//! 进程内 e2e:DPoP AS 侧签发(spec 010 §5.2/5.3,C8.7b,RFC 9449)。
//!
//! 覆盖(三轮/两轮双评审收敛的设计不变量):
//! - 带 DPoP proof 的 code flow /token → access token 含 cnf.jkt == RFC 7638 thumbprint of proof.jwk。
//! - 无 DPoP 头 → bearer(不带 cnf,opt-in)。
//! - 非法 proof(错 htu / 错 typ / 过旧 iat)→ invalid_dpop_proof 拒,不降级 bearer。
//! - jti 重放(同 proof 复用)→ 拒(B2)。
//! - refresh 绑定延续(B1):DPoP-bound family 的 refresh 缺/错 proof 拒,匹配 proof 续绑。
//! - require_dpop client 缺 proof 拒(M1)。
//! - discovery 宣告 dpop_signing_alg_values_supported=["ES256"](P3)。

use agent_auth_http::{build_router, AppState, Phase};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use tower::ServiceExt;

const HOST: &str = "localhost";
const CLIENT: &str = "dpop-app";
const REDIRECT: &str = "https://app.example.com/cb";
const TOKEN_HTU: &str = "https://localhost/token";

// P3 state(DPoP 签发能力上线;replay_store dev 已开)。
fn p3_state() -> AppState {
    let mut s = AppState::dev(HOST);
    s.phase = Phase::P3;
    s
}

// 造一个固定 EC P-256 keypair + 其公钥 jwk(x/y base64url)。
fn dpop_keypair(seed: u8) -> (SigningKey, serde_json::Value) {
    let sk = SigningKey::from_bytes(&[seed; 32].into()).unwrap();
    let vk = sk.verifying_key();
    let ep = vk.to_encoded_point(false);
    let x = B64.encode(ep.x().unwrap());
    let y = B64.encode(ep.y().unwrap());
    let jwk = serde_json::json!({ "kty": "EC", "crv": "P-256", "x": x, "y": y });
    (sk, jwk)
}

// 签一个 DPoP proof(header/claims 可注入以测各失败模式)。
fn make_proof(
    sk: &SigningKey,
    jwk: &serde_json::Value,
    typ: &str,
    htu: &str,
    htm: &str,
    jti: &str,
    iat: i64,
) -> String {
    let header = serde_json::json!({ "typ": typ, "alg": "ES256", "jwk": jwk });
    let claims = serde_json::json!({ "htu": htu, "htm": htm, "iat": iat, "jti": jti });
    let h = B64.encode(serde_json::to_vec(&header).unwrap());
    let c = B64.encode(serde_json::to_vec(&claims).unwrap());
    let si = format!("{h}.{c}");
    let sig: Signature = sk.sign(si.as_bytes());
    format!("{si}.{}", B64.encode(sig.to_bytes()))
}

// 期望的 jkt(与 AS 内部 ec_thumbprint 一致)。
fn expected_jkt(jwk: &serde_json::Value) -> String {
    let x = jwk["x"].as_str().unwrap();
    let y = jwk["y"].as_str().unwrap();
    B64.encode(agent_auth_infra_core::jwks::ec_thumbprint("P-256", x, y))
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

async fn get_redirect(router: &axum::Router, uri: &str) -> String {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "authorize 应 303");
    resp.headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

// 走 authorize 拿 code。
async fn get_code(router: &axum::Router) -> (String, String) {
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = agent_auth_client::s256_challenge(verifier);
    let uri = format!(
        "/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice"
    );
    let loc = get_redirect(router, &uri).await;
    let code = loc
        .split('?')
        .nth(1)
        .unwrap()
        .split('&')
        .find_map(|kv| kv.strip_prefix("code="))
        .unwrap()
        .to_string();
    (code, verifier.to_string())
}

// POST /token,可选带 DPoP 头。
async fn post_token(
    router: &axum::Router,
    form: &str,
    dpop: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut b = Request::builder()
        .method("POST")
        .uri("/token")
        .header("host", HOST)
        .header("content-type", "application/x-www-form-urlencoded");
    if let Some(p) = dpop {
        b = b.header("dpop", p);
    }
    let resp = router
        .clone()
        .oneshot(b.body(Body::from(form.to_string())).unwrap())
        .await
        .unwrap();
    let st = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        st,
        serde_json::from_slice(&body).unwrap_or(serde_json::json!({})),
    )
}

// 解 JWT payload 的 cnf。
fn token_cnf(access_token: &str) -> Option<serde_json::Value> {
    let payload = access_token.split('.').nth(1)?;
    let c: serde_json::Value = serde_json::from_slice(&B64.decode(payload).ok()?).ok()?;
    c.get("cnf").cloned()
}

fn assert_access_token_es256(access_token: &str) {
    let header: serde_json::Value =
        serde_json::from_slice(&B64.decode(access_token.split('.').next().unwrap()).unwrap())
            .unwrap();
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["typ"], "at+jwt");
}

async fn app() -> axum::Router {
    let state = p3_state();
    state.seed_dev_client(CLIENT, REDIRECT, None).await;
    build_router(state).0
}

// 带合法 DPoP proof 的 code flow → access token 含 cnf.jkt == thumbprint。
#[tokio::test]
async fn code_flow_with_dpop_binds_cnf_jkt() {
    let router = app().await;
    let (code, verifier) = get_code(&router).await;
    let (sk, jwk) = dpop_keypair(11);
    let proof = make_proof(&sk, &jwk, "dpop+jwt", TOKEN_HTU, "POST", "jti-1", now());
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}&redirect_uri={REDIRECT}&client_id={CLIENT}"
    );
    let (st, body) = post_token(&router, &form, Some(&proof)).await;
    assert_eq!(st, StatusCode::OK, "带 DPoP 的 code flow 应成功: {body}");
    let at = body["access_token"].as_str().unwrap();
    assert_access_token_es256(at);
    let cnf = token_cnf(at).expect("access token 应含 cnf");
    assert_eq!(
        cnf["jkt"],
        expected_jkt(&jwk),
        "cnf.jkt == RFC 7638 thumbprint"
    );
    // RFC 9449 §5:DPoP-bound token 响应 token_type MUST = "DPoP"(评审 codex M:否则 client 按 Bearer 用被 RS 拒)。
    assert_eq!(
        body["token_type"], "DPoP",
        "DPoP-bound token 的 token_type 应为 DPoP"
    );
}

// 无 DPoP 头 → bearer(不带 cnf)。
#[tokio::test]
async fn code_flow_without_dpop_is_bearer() {
    let router = app().await;
    let (code, verifier) = get_code(&router).await;
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}&redirect_uri={REDIRECT}&client_id={CLIENT}"
    );
    let (st, body) = post_token(&router, &form, None).await;
    assert_eq!(st, StatusCode::OK);
    let at = body["access_token"].as_str().unwrap();
    assert!(token_cnf(at).is_none(), "无 DPoP → bearer,不带 cnf");
    assert_eq!(body["token_type"], "Bearer", "无 DPoP → token_type=Bearer");
}

// 非法 proof(错 htu / 错 typ / 过旧 iat)→ invalid_dpop_proof 拒,不降级 bearer。
#[tokio::test]
async fn code_flow_bad_dpop_rejected_no_downgrade() {
    let router = app().await;
    let (sk, jwk) = dpop_keypair(12);
    // 每个坏 proof 用独立 code(避免 code 被前一次消费)。
    for (label, proof) in [
        (
            "wrong_htu",
            make_proof(
                &sk,
                &jwk,
                "dpop+jwt",
                "https://evil.example.com/token",
                "POST",
                "j-a",
                now(),
            ),
        ),
        (
            "wrong_typ",
            make_proof(&sk, &jwk, "jwt", TOKEN_HTU, "POST", "j-b", now()),
        ),
        (
            "stale_iat",
            make_proof(&sk, &jwk, "dpop+jwt", TOKEN_HTU, "POST", "j-c", now() - 999),
        ),
    ] {
        let (code, verifier) = get_code(&router).await;
        let form = format!(
            "grant_type=authorization_code&code={code}&code_verifier={verifier}&redirect_uri={REDIRECT}&client_id={CLIENT}"
        );
        let (st, body) = post_token(&router, &form, Some(&proof)).await;
        assert_eq!(
            st,
            StatusCode::BAD_REQUEST,
            "{label}: 非法 proof 应拒: {body}"
        );
        assert_eq!(body["error"], "invalid_dpop_proof", "{label}");
    }
}

// jti 重放(同 proof 复用)→ 第二次拒(B2)。用两个 code + 同一 proof(同 jti)。
#[tokio::test]
async fn dpop_jti_replay_rejected() {
    let router = app().await;
    let (sk, jwk) = dpop_keypair(13);
    let proof = make_proof(
        &sk,
        &jwk,
        "dpop+jwt",
        TOKEN_HTU,
        "POST",
        "jti-replay",
        now(),
    );
    // 第一次:成功。
    let (code1, v1) = get_code(&router).await;
    let form1 = format!(
        "grant_type=authorization_code&code={code1}&code_verifier={v1}&redirect_uri={REDIRECT}&client_id={CLIENT}"
    );
    let (st1, _) = post_token(&router, &form1, Some(&proof)).await;
    assert_eq!(st1, StatusCode::OK, "首次 proof 应成功");
    // 第二次:同 proof(同 jti)→ 重放拒。
    let (code2, v2) = get_code(&router).await;
    let form2 = format!(
        "grant_type=authorization_code&code={code2}&code_verifier={v2}&redirect_uri={REDIRECT}&client_id={CLIENT}"
    );
    let (st2, body2) = post_token(&router, &form2, Some(&proof)).await;
    assert_eq!(
        st2,
        StatusCode::BAD_REQUEST,
        "重放同 jti proof 应拒: {body2}"
    );
    assert_eq!(body2["error"], "invalid_dpop_proof");
}

// B1:DPoP-bound family 的 refresh MUST 出示匹配 proof;缺/错 proof 拒不降级;匹配则续绑 cnf.jkt。
#[tokio::test]
async fn refresh_dpop_binding_continuity() {
    let router = app().await;
    let (sk, jwk) = dpop_keypair(14);
    let jkt = expected_jkt(&jwk);
    // 1. DPoP-bound code flow 拿 refresh_token(family 存 jkt)。
    let (code, verifier) = get_code(&router).await;
    let proof0 = make_proof(&sk, &jwk, "dpop+jwt", TOKEN_HTU, "POST", "j-r0", now());
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}&redirect_uri={REDIRECT}&client_id={CLIENT}"
    );
    let (st, body) = post_token(&router, &form, Some(&proof0)).await;
    assert_eq!(st, StatusCode::OK, "DPoP code flow: {body}");
    let refresh = body["refresh_token"]
        .as_str()
        .expect("含 refresh_token")
        .to_string();

    // 2. refresh **不带** proof → 拒(不降级 bearer)。
    let rform = format!("grant_type=refresh_token&refresh_token={refresh}&client_id={CLIENT}");
    let (st_no, b_no) = post_token(&router, &rform, None).await;
    assert_eq!(
        st_no,
        StatusCode::BAD_REQUEST,
        "DPoP-bound refresh 缺 proof 应拒: {b_no}"
    );
    assert_eq!(b_no["error"], "invalid_dpop_proof");

    // 3. refresh 带**错 key** 的 proof(jkt 不匹配)→ 拒。
    let (sk_wrong, jwk_wrong) = dpop_keypair(99);
    let proof_wrong = make_proof(
        &sk_wrong,
        &jwk_wrong,
        "dpop+jwt",
        TOKEN_HTU,
        "POST",
        "j-rw",
        now(),
    );
    let (st_w, _) = post_token(&router, &rform, Some(&proof_wrong)).await;
    assert_eq!(
        st_w,
        StatusCode::BAD_REQUEST,
        "错 key proof 应拒(jkt 不匹配)"
    );

    // 4. refresh 带**匹配** proof → 成功,新 access token 续绑同 cnf.jkt。
    let proof_ok = make_proof(&sk, &jwk, "dpop+jwt", TOKEN_HTU, "POST", "j-r1", now());
    let (st_ok, b_ok) = post_token(&router, &rform, Some(&proof_ok)).await;
    assert_eq!(
        st_ok,
        StatusCode::OK,
        "匹配 proof 的 refresh 应成功: {b_ok}"
    );
    assert_eq!(
        b_ok["token_type"], "DPoP",
        "DPoP-bound refresh 的 token_type 必须保持 DPoP"
    );
    let at = b_ok["access_token"].as_str().unwrap();
    assert_access_token_es256(at);
    assert_eq!(token_cnf(at).unwrap()["jkt"], jkt, "refresh 续绑同 cnf.jkt");
}

// C3.2:已轮换的 DPoP-bound refresh 在 grace 内只能由同一 key 重放。
// 不同 key 的旧 token 重放按 reuse 处理,拒绝响应不得泄出 token,且 rotated family 必须失效。
#[tokio::test]
async fn grace_window_dpop_identity_mismatch_revokes_family() {
    let router = app().await;
    let (sk, jwk) = dpop_keypair(21);

    let (code, verifier) = get_code(&router).await;
    let code_proof = make_proof(
        &sk,
        &jwk,
        "dpop+jwt",
        TOKEN_HTU,
        "POST",
        "grace-code",
        now(),
    );
    let code_form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}\
         &redirect_uri={REDIRECT}&client_id={CLIENT}"
    );
    let (code_status, code_tokens) = post_token(&router, &code_form, Some(&code_proof)).await;
    assert_eq!(code_status, StatusCode::OK);
    let refresh_r0 = code_tokens["refresh_token"]
        .as_str()
        .expect("DPoP code flow 应返回 refresh");
    let refresh_form =
        format!("grant_type=refresh_token&refresh_token={refresh_r0}&client_id={CLIENT}");

    let (wrong_sk, wrong_jwk) = dpop_keypair(22);
    let current_wrong_proof = make_proof(
        &wrong_sk,
        &wrong_jwk,
        "dpop+jwt",
        TOKEN_HTU,
        "POST",
        "grace-current-wrong-key",
        now(),
    );
    let (current_wrong_status, current_wrong_body) =
        post_token(&router, &refresh_form, Some(&current_wrong_proof)).await;
    assert_eq!(current_wrong_status, StatusCode::BAD_REQUEST);
    assert_eq!(current_wrong_body["error"], "invalid_dpop_proof");
    assert!(current_wrong_body.get("access_token").is_none());
    assert!(current_wrong_body.get("refresh_token").is_none());
    assert!(current_wrong_body.get("id_token").is_none());

    let first_proof = make_proof(
        &sk,
        &jwk,
        "dpop+jwt",
        TOKEN_HTU,
        "POST",
        "grace-first",
        now(),
    );
    let (first_status, first_tokens) = post_token(&router, &refresh_form, Some(&first_proof)).await;
    assert_eq!(first_status, StatusCode::OK);
    let refresh_r1 = first_tokens["refresh_token"]
        .as_str()
        .expect("DPoP rotation 应返回新 refresh");

    let cached_proof = make_proof(
        &sk,
        &jwk,
        "dpop+jwt",
        TOKEN_HTU,
        "POST",
        "grace-same-key-cache",
        now(),
    );
    let (cached_status, cached_tokens) =
        post_token(&router, &refresh_form, Some(&cached_proof)).await;
    assert_eq!(cached_status, StatusCode::OK);
    assert_eq!(cached_tokens["access_token"], first_tokens["access_token"]);
    assert_eq!(
        cached_tokens["refresh_token"],
        first_tokens["refresh_token"]
    );
    assert_eq!(cached_tokens["token_type"], "DPoP");

    let wrong_proof = make_proof(
        &wrong_sk,
        &wrong_jwk,
        "dpop+jwt",
        TOKEN_HTU,
        "POST",
        "grace-wrong-key",
        now(),
    );
    let (replay_status, replay_body) = post_token(&router, &refresh_form, Some(&wrong_proof)).await;
    assert_eq!(replay_status, StatusCode::BAD_REQUEST);
    assert_eq!(replay_body["error"], "invalid_grant");
    assert!(replay_body.get("access_token").is_none());
    assert!(replay_body.get("refresh_token").is_none());
    assert!(replay_body.get("id_token").is_none());

    let rotated_form =
        format!("grant_type=refresh_token&refresh_token={refresh_r1}&client_id={CLIENT}");
    let rotated_proof = make_proof(
        &sk,
        &jwk,
        "dpop+jwt",
        TOKEN_HTU,
        "POST",
        "grace-rotated",
        now(),
    );
    let (rotated_status, rotated_body) =
        post_token(&router, &rotated_form, Some(&rotated_proof)).await;
    assert_eq!(
        rotated_status,
        StatusCode::BAD_REQUEST,
        "错误 DPoP key 重放旧 refresh 必须吊销 rotated family: {rotated_body}"
    );
    assert_eq!(rotated_body["error"], "invalid_grant");
}

// M1:require_dpop=true 的 client 缺 proof → 拒(防中间件丢头/漏配静默降级 bearer)。
#[tokio::test]
async fn require_dpop_client_rejects_missing_proof() {
    use agent_auth_http::ports::{ClientRecord, ClientStore};
    let state = p3_state();
    // 直接 put 一个 require_dpop=true 的 public client(PKCE)。
    ClientStore::put(
        state.clients.as_ref(),
        "",
        ClientRecord {
            client_id: "rd-app".into(),
            redirect_uris: vec![REDIRECT.into()],
            token_endpoint_auth_method: "none".into(),
            require_dpop: true,
            prm_domains: vec![],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let router = build_router(state).0;
    // authorize + /token 缺 DPoP → 拒。
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = agent_auth_client::s256_challenge(verifier);
    let uri = format!(
        "/authorize?response_type=code&client_id=rd-app&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice"
    );
    let loc = get_redirect(&router, &uri).await;
    let code = loc
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap()
        .to_string();
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}&redirect_uri={REDIRECT}&client_id=rd-app"
    );
    let (st, body) = post_token(&router, &form, None).await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "require_dpop client 缺 proof 应拒: {body}"
    );
    assert_eq!(body["error"], "invalid_dpop_proof");
}

// discovery 宣告 dpop_signing_alg_values_supported=["ES256"](P3)。
#[tokio::test]
async fn discovery_announces_dpop_alg_at_p3() {
    let router = app().await;
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        doc["dpop_signing_alg_values_supported"],
        serde_json::json!(["ES256"]),
        "P3 discovery 宣告 DPoP ES256"
    );
}
