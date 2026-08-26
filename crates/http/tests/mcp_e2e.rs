//! 进程内 e2e:MCP 集成 P1a AS 侧(spec 010)—— PRM 生成 + /introspect(aud 隔离 + 回带命名空间)。
//!
//! 覆盖:
//! - C8.1:`GET /rs/{resource_id}/prm` 为已注册 RS 生成 PRM JSON(resource/authorization_servers 匹配);
//!   未注册 resource_id → 404(不为任意 URL 生成)。
//! - C8.6:`/introspect` 调用方认证 + introspect 权限门;aud ∈ caller.resource_ids 才 active;
//!   RS-A 凭证查 aud=RS-B 的 token → active:false;无权限 client → 401。
//! - C8.7a:active 响应回带命名空间 sub_type/auth_grant/actor_types 与 act(if present)。

use agent_auth_client::s256_challenge;
use agent_auth_http::ports::{ClientRecord, ClientStore};
use agent_auth_http::{build_router, AppState};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use tower::ServiceExt;

const HOST: &str = "localhost";
const RS_A: &str = "https://mcp.kb.example.com";
const RS_PATH: &str = "https://mcp.kb.example.com:8443/api/v1/";
const RS_B: &str = "https://mcp.mail.example.com";
const RS_C: &str = "https://mcp.calendar.example.com";
const RS_OTHER: &str = "https://mcp.other.example.com";

struct MintedResourceToken {
    access_token: String,
    replay_form: String,
}

async fn mint_resource_token_with_replay(
    router: &axum::Router,
    client: &str,
    redirect: &str,
) -> MintedResourceToken {
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let authz = format!(
        "/authorize?response_type=code&client_id={client}&redirect_uri={redirect}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&state=s&login_user=alice"
    );
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&authz)
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let code = loc
        .split('?')
        .nth(1)
        .unwrap()
        .split('&')
        .find_map(|kv| kv.strip_prefix("code="))
        .unwrap()
        .to_string();
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}\
         &redirect_uri={redirect}&client_id={client}"
    );
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let tok: serde_json::Value = serde_json::from_slice(&body).unwrap();
    MintedResourceToken {
        access_token: tok["access_token"].as_str().unwrap().to_string(),
        replay_form: form,
    }
}

// 用绑定 default_resource=rs 的 client 换一枚 aud=rs 的 access token。
async fn mint_token_for_resource(router: &axum::Router, client: &str, redirect: &str) -> String {
    mint_resource_token_with_replay(router, client, redirect)
        .await
        .access_token
}

fn basic(client_id: &str, secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}")))
}

async fn introspect(
    router: &axum::Router,
    caller_id: &str,
    caller_secret: &str,
    token: &str,
) -> (StatusCode, serde_json::Value) {
    let form = format!("token={token}&client_id={caller_id}");
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/introspect")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .header("authorization", basic(caller_id, caller_secret))
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    (status, json)
}

async fn post_token_form(
    router: &axum::Router,
    form: impl Into<String>,
) -> (StatusCode, serde_json::Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form.into()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

fn assert_oauth_error_without_tokens(
    status: StatusCode,
    body: &serde_json::Value,
    expected_status: StatusCode,
    expected_error: &str,
) {
    assert_eq!(status, expected_status, "unexpected OAuth error: {body}");
    assert_eq!(body["error"], expected_error);
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
    assert!(body.get("token_type").is_none());
}

// PRM 生成:认证的 RS 取回自己的 PRM(字段匹配);未认证 / 非本 caller 资源 → 401。
#[tokio::test]
async fn prm_generated_for_authenticated_owner_only() {
    let state = AppState::dev(HOST);
    state
        .seed_rs_introspect_client("rs-a-introspect", "sekret-a", &[RS_A, RS_PATH])
        .await;
    ClientStore::put(
        state.clients.as_ref(),
        "",
        ClientRecord {
            client_id: "malformed-confidential-none".into(),
            token_endpoint_auth_method: "none".into(),
            client_type: Some("confidential".into()),
            introspect_enabled: true,
            resource_ids: vec![RS_A.into()],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let (router, _) = build_router(state);

    for resource in [RS_A, RS_PATH] {
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/rs/prm?resource={}&client_id=rs-a-introspect",
                        urlencoding(resource)
                    ))
                    .header("host", HOST)
                    .header("authorization", basic("rs-a-introspect", "sekret-a"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "认证的 owner 应取回 PRM");
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let prm: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            prm["resource"], resource,
            "resource 必须逐字等于已绑定 RS 标识，保留端口、路径和尾斜杠"
        );
        assert_eq!(
            prm["authorization_servers"],
            serde_json::json!([format!("https://{HOST}")])
        );
        assert_ne!(
            prm["resource"], prm["authorization_servers"][0],
            "PRM 描述 RS，不能把 AS issuer 当 resource"
        );
        assert!(prm["bearer_methods_supported"].is_array());
    }

    // 未认证(无凭证)→ 401。
    let enc = urlencoding(RS_A);
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/rs/prm?resource={enc}"))
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "未认证取 PRM 应 401"
    );

    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/rs/prm?resource={enc}&client_id=malformed-confidential-none"
                ))
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "confidential+none 脏记录不得无凭证读取 PRM"
    );

    // RS-A 认证但请求非自己绑定的 RS_B → 401(不泄露 RS_B 是否注册)。
    let enc_b = urlencoding(RS_B);
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/rs/prm?resource={enc_b}&client_id=rs-a-introspect"
                ))
                .header("host", HOST)
                .header("authorization", basic("rs-a-introspect", "sekret-a"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "非本 caller 资源应 401(防枚举)"
    );

    // 近似 URL 不得匹配：尾斜杠是 resource identifier 的一部分。
    let close_variant = urlencoding("https://mcp.kb.example.com:8443/api/v1");
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/rs/prm?resource={close_variant}&client_id=rs-a-introspect"
                ))
                .header("host", HOST)
                .header("authorization", basic("rs-a-introspect", "sekret-a"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "resource identifier 必须逐字匹配，不得归一或前缀匹配"
    );

    // P1 默认只生成 PRM 供 RS 自挂；AS issuer origin 的 well-known 路径不得发布它。
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/.well-known/oauth-protected-resource")
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "BYOD 未启用时 AS origin 不得发布全局 PRM"
    );
}

// /introspect:授权 RS 查自己 aud 的 token → active + 回带命名空间;RS-A 查 RS-B token → active:false。
#[tokio::test]
async fn introspect_aud_isolation_and_namespace() {
    let state = AppState::dev(HOST);
    // 一个 client 绑 default_resource=RS_A,用来签出 aud=RS_A 的 token。
    state
        .seed_dev_client("app-a", "https://app.example.com/cb", Some(RS_A))
        .await;
    state
        .seed_dev_client("app-b", "https://app-b.example.com/cb", Some(RS_B))
        .await;
    state
        .seed_dev_client("app-c", "https://app-c.example.com/cb", Some(RS_C))
        .await;
    // 同一 caller 绑定三个 resource,并逐一验证首/中/尾位置都按集合 membership 放行。
    state
        .seed_rs_introspect_client("rs-all-introspect", "sekret-all", &[RS_A, RS_B, RS_C])
        .await;
    state
        .seed_rs_introspect_client("rs-other-introspect", "sekret-other", &[RS_OTHER])
        .await;
    let (router, _) = build_router(state);

    let token_a = mint_token_for_resource(&router, "app-a", "https://app.example.com/cb").await;
    let token_b = mint_token_for_resource(&router, "app-b", "https://app-b.example.com/cb").await;
    let token_c = mint_token_for_resource(&router, "app-c", "https://app-c.example.com/cb").await;
    for (token, expected_aud) in [(&token_a, RS_A), (&token_b, RS_B), (&token_c, RS_C)] {
        let (status, body) = introspect(&router, "rs-all-introspect", "sekret-all", token).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["active"], true,
            "caller resource set 的任意位置都应按 membership 放行"
        );
        assert_eq!(body["aud"], serde_json::json!([expected_aud]));
    }

    let token_claims: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(token_a.split('.').nth(1).expect("access token payload"))
            .expect("access token payload base64url"),
    )
    .expect("access token claims JSON");

    // 复查首项 token 的命名空间回带。
    let (st, j) = introspect(&router, "rs-all-introspect", "sekret-all", &token_a).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(j["active"], true, "授权 RS 查自己 aud 的 token 应 active");
    assert_eq!(j["aud"], serde_json::json!([RS_A]));
    // spec 011 增量 A:access token 带 jti,introspect 回带(RFC 7662 标准字段)。
    assert!(
        j["jti"].as_str().map(|s| !s.is_empty()).unwrap_or(false),
        "introspect 应回带非空 jti"
    );
    // C8.7a:回带命名空间对象 sub_type/auth_grant。
    let ns = &j["https://a-auth.com/c"];
    assert_eq!(
        ns, &token_claims["https://a-auth.com/c"],
        "非委托 introspection 必须逐值回带签名 token namespace"
    );
    assert_eq!(
        ns.as_object()
            .expect("namespace object")
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from(["auth_grant", "sub_type"]),
        "非委托 token 的 introspection namespace 不得编造 actor_types"
    );
    assert_eq!(ns["sub_type"], "user", "回带命名空间 sub_type");
    assert!(
        ns["auth_grant"]
            .as_str()
            .map(|grant| !grant.is_empty())
            .unwrap_or(false),
        "回带非空命名空间 auth_grant"
    );
    // P1 非委托 token 无 act(不编造)。
    assert!(j.get("act").is_none(), "非委托 token 不编造 act");
    assert!(
        j.get("authorization_details").is_none(),
        "无 RAR 的 token 不得由 introspection 编造 authorization_details"
    );

    // 不含 RS_A 的 caller 查 aud=RS_A token → active:false(aud 隔离,不泄露)。
    let (st, j) = introspect(&router, "rs-other-introspect", "sekret-other", &token_a).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        j["active"], false,
        "RS-B 查 aud=RS-A 的 token 应 active:false"
    );
    assert_eq!(
        j,
        serde_json::json!({"active": false}),
        "跨 RS introspection 只返回 inactive,不得泄露任何其它字段"
    );
}

// C7.6b / spec 011 §5.1(P2):Grant 吊销即时反映于 introspect —— 签名仍有效的 token,其源 Grant 被吊销
// 后 introspect MUST 返回 active:false(否则 RS 靠 introspection 查不出吊销 = 吊销不生效)。
#[tokio::test]
async fn introspect_reflects_grant_revocation() {
    let state = AppState::dev(HOST);
    state
        .seed_dev_client("app-a", "https://app.example.com/cb", Some(RS_A))
        .await;
    state
        .seed_rs_introspect_client("rs-a-introspect", "sekret-a", &[RS_A])
        .await;
    let grants = state.grants.clone(); // 捕获 handle 供吊销
    let (router, _) = build_router(state);

    let token = mint_token_for_resource(&router, "app-a", "https://app.example.com/cb").await;
    // 先确认 active。
    let (_, j) = introspect(&router, "rs-a-introspect", "sekret-a", &token).await;
    assert_eq!(j["active"], true, "吊销前应 active");
    // token 命名空间 auth_grant = 源 Grant id(=family_id)。
    let ns = &j["https://a-auth.com/c"];
    let gid = ns["auth_grant"].as_str().expect("auth_grant").to_string();

    // 吊销该 Grant(模拟 /grants DELETE 的 status=Revoked)。
    let mut g = agent_auth_http::ports::GrantStore::get(grants.as_ref(), "", &gid)
        .await
        .unwrap()
        .expect("code flow 应已建 Grant");
    g.status = agent_auth_grant::GrantStatus::Revoked;
    agent_auth_http::ports::GrantStore::put(grants.as_ref(), "", g)
        .await
        .unwrap();

    // 吊销后:同一 token(签名/exp 仍有效)introspect → active:false(即时反映吊销)。
    let (st, j2) = introspect(&router, "rs-a-introspect", "sekret-a", &token).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        j2["active"], false,
        "Grant 吊销后 introspect MUST active:false(C7.6b 吊销即时反映)"
    );
    assert!(j2.get("sub").is_none(), "inactive 不泄露其它字段");
}

// 双源 AND 第②源(评审 MEDIUM 收敛):**family-only 吊销**(/revoke RFC7009 / 复用检测 / 批量吊销 只吊
// refresh family、不吊 Grant)也 MUST 被 introspect 反映——单查 Grant 会漏此路径。
#[tokio::test]
async fn introspect_reflects_family_only_revocation() {
    let state = AppState::dev(HOST);
    state
        .seed_dev_client("app-a", "https://app.example.com/cb", Some(RS_A))
        .await;
    state
        .seed_rs_introspect_client("rs-a-introspect", "sekret-a", &[RS_A])
        .await;
    let grants = state.grants.clone();
    let refresh = state.refresh.clone(); // 捕获 handle 供 family 吊销(不动 Grant)
    let (router, _) = build_router(state);

    let token = mint_token_for_resource(&router, "app-a", "https://app.example.com/cb").await;
    let (_, j) = introspect(&router, "rs-a-introspect", "sekret-a", &token).await;
    assert_eq!(j["active"], true, "吊销前应 active");
    let gid = j["https://a-auth.com/c"]["auth_grant"]
        .as_str()
        .unwrap()
        .to_string();

    // **只吊 family,不动 Grant**——模拟 /revoke / 复用检测路径。
    agent_auth_http::ports::RefreshStore::revoke(refresh.as_ref(), "", &gid)
        .await
        .unwrap();
    assert_eq!(
        agent_auth_http::ports::GrantStore::get(grants.as_ref(), "", &gid)
            .await
            .unwrap()
            .expect("code flow should retain the source Grant")
            .status,
        agent_auth_grant::GrantStatus::Active,
        "family-only revocation must leave the Grant authority active"
    );

    // introspect 双源 ② 应命中 family.revoked → active:false(Grant 仍 Active,单查 Grant 会漏)。
    let (st, j2) = introspect(&router, "rs-a-introspect", "sekret-a", &token).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        j2["active"], false,
        "family-only 吊销 MUST 被 introspect 反映(双源 AND 第②源)"
    );
}

#[tokio::test]
async fn introspect_reflects_authorization_code_replay_revocation() {
    let state = AppState::dev(HOST);
    state
        .seed_dev_client("app-a", "https://app.example.com/cb", Some(RS_A))
        .await;
    state
        .seed_rs_introspect_client("rs-a-introspect", "sekret-a", &[RS_A])
        .await;
    let router = build_router(state).0;

    let minted =
        mint_resource_token_with_replay(&router, "app-a", "https://app.example.com/cb").await;
    let (_, before) =
        introspect(&router, "rs-a-introspect", "sekret-a", &minted.access_token).await;
    assert_eq!(before["active"], true);

    let replay = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(minted.replay_form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);

    let (_, after) = introspect(&router, "rs-a-introspect", "sekret-a", &minted.access_token).await;
    assert_eq!(
        after["active"], false,
        "authorization code replay must invalidate introspection online"
    );
}

// C8.7a'(spec 010 §4.3):introspection 回带 `authorization_details`(RAR 绑 Grant,P2)——RAR-bearing
// token 经 introspect,响应 MUST 含 authorization_details(供走 introspection 的 RS 与离线校验能力对等)。
#[tokio::test]
async fn introspect_returns_authorization_details() {
    let mut state = AppState::dev(HOST);
    state.phase = agent_auth_http::Phase::P2; // RAR 发行属 P2
    state
        .seed_dev_client("app-a", "https://app.example.com/cb", Some(RS_A))
        .await;
    state
        .seed_rs_introspect_client("rs-a-introspect", "sekret-a", &[RS_A])
        .await;
    let (router, _) = build_router(state);

    // authorize 带内建词汇表 RAR(locations 指向 RS_A)→ code → token(顶层带 authorization_details)。
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let rar_value = serde_json::json!([
        {
            "type": "agent_auth_rar_v1",
            "locations": [RS_A],
            "max_records": 42
        },
        {
            "type": "agent_auth_rar_v1",
            "locations": [RS_A],
            "valid_from": 1_000,
            "valid_to": 4_000_000_000_i64
        }
    ]);
    let rar = serde_json::to_string(&rar_value).unwrap();
    let rar_enc: String = rar
        .replace('{', "%7B")
        .replace('}', "%7D")
        .replace('[', "%5B")
        .replace(']', "%5D")
        .replace('"', "%22")
        .replace(':', "%3A")
        .replace(',', "%2C")
        .replace('/', "%2F");
    let authz = format!(
        "/authorize?response_type=code&client_id=app-a&redirect_uri=https://app.example.com/cb\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice\
         &resource={RS_A}&authorization_details={rar_enc}"
    );
    let loc = {
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&authz)
                    .header("host", HOST)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        resp.headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string()
    };
    let code = loc
        .split('?')
        .nth(1)
        .unwrap()
        .split('&')
        .find_map(|kv| kv.strip_prefix("code="))
        .unwrap()
        .to_string();
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}\
         &redirect_uri=https://app.example.com/cb&client_id=app-a&resource={RS_A}"
    );
    let tok: serde_json::Value = {
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header("host", HOST)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form))
                    .unwrap(),
            )
            .await
            .unwrap();
        let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&b).unwrap()
    };
    let at = tok["access_token"].as_str().expect("access_token");
    let token_claims: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(at.split('.').nth(1).expect("access token payload"))
            .expect("access token payload base64url"),
    )
    .expect("access token claims JSON");

    // introspect 该 token → 响应 MUST 回带 authorization_details(C8.7a')。
    let (st, j) = introspect(&router, "rs-a-introspect", "sekret-a", at).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(j["active"], true);
    assert_eq!(
        j["authorization_details"], token_claims["authorization_details"],
        "introspection 必须逐值回带 access token 的 authorization_details"
    );
    let ad = j["authorization_details"]
        .as_array()
        .expect("introspect 响应 MUST 回带 authorization_details(C8.7a')");
    assert_eq!(ad.len(), 2);
    assert_eq!(ad[0]["type"], "agent_auth_rar_v1");
    assert_eq!(ad[0]["max_records"], 42, "RAR 约束值经 introspect 透出");
    assert_eq!(
        ad,
        rar_value.as_array().expect("RAR fixture array"),
        "非委托 introspection 必须回带全部有序 RAR"
    );
}

// C8.10b: P3 large RAR uses a bounded signed summary while authenticated
// introspection returns the complete Grant-backed authorization details.
#[tokio::test]
async fn large_rar_uses_bounded_summary_and_grant_backed_introspection() {
    let mut state = AppState::dev(HOST);
    state.phase = agent_auth_http::Phase::P3;
    state
        .seed_dev_client("app-a", "https://app.example.com/cb", Some(RS_A))
        .await;
    state
        .seed_rs_introspect_client("rs-a-introspect", "sekret-a", &[RS_A])
        .await;
    let grants = state.grants.clone();
    let (router, _) = build_router(state);

    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let padding = "policy-segment-".repeat(100);
    let rar_value = serde_json::Value::Array(
        (0..4)
            .map(|index| {
                serde_json::json!({
                    "type": "agent_auth_rar_v1",
                    "locations": [RS_A],
                    "identifier": format!("policy-{index}-{padding}"),
                    "max_records": index + 1
                })
            })
            .collect(),
    );
    let rar = serde_json::to_string(&rar_value).unwrap();
    let rar_enc = rar
        .replace('%', "%25")
        .replace('{', "%7B")
        .replace('}', "%7D")
        .replace('[', "%5B")
        .replace(']', "%5D")
        .replace('"', "%22")
        .replace(':', "%3A")
        .replace(',', "%2C")
        .replace('/', "%2F");
    let authz = format!(
        "/authorize?response_type=code&client_id=app-a&redirect_uri=https://app.example.com/cb\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice\
         &resource={RS_A}&authorization_details={rar_enc}"
    );
    let location = {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&authz)
                    .header("host", HOST)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string()
    };
    let code = location
        .split('?')
        .nth(1)
        .unwrap()
        .split('&')
        .find_map(|part| part.strip_prefix("code="))
        .expect("authorization code");
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}\
         &redirect_uri=https://app.example.com/cb&client_id=app-a&resource={RS_A}"
    );
    let (status, token_response) = {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header("host", HOST)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        )
    };
    assert_eq!(
        status,
        StatusCode::OK,
        "P3 large RAR must use Grant-backed offload instead of rejecting the token: {token_response}"
    );
    let access_token = token_response["access_token"]
        .as_str()
        .expect("access token");
    assert!(
        access_token.len() < agent_auth_token::JWT_SOFT_TARGET_BYTES,
        "Grant-backed summary token must remain below the 4 KiB target"
    );

    let header: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(access_token.split('.').next().unwrap())
            .unwrap(),
    )
    .unwrap();
    let jwks_response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/jwks.json")
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let jwks_body = axum::body::to_bytes(jwks_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let jwks: serde_json::Value = serde_json::from_slice(&jwks_body).unwrap();
    let kid = header["kid"].as_str().expect("access token kid");
    let ec_jwk = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["kty"] == "EC" && key["kid"] == kid)
        .expect("access token signing key");
    let verified = agent_auth_workload::verify_es256(
        access_token,
        ec_jwk["x"].as_str().unwrap(),
        ec_jwk["y"].as_str().unwrap(),
        Some(kid),
    )
    .expect("large-RAR summary token must be verifiably signed");
    let summary = verified.claims["authorization_details"]
        .as_array()
        .and_then(|details| details.first())
        .expect("signed token must carry one bounded RAR summary");
    assert_eq!(summary["type"], "agent_auth_grant_summary_v1");
    assert_eq!(summary["locations"], serde_json::json!([RS_A]));
    assert_eq!(summary["authorization_details_count"], 4);
    assert_eq!(summary["introspection_required"], true);
    assert_eq!(
        summary["authorization_details_sha256"]
            .as_str()
            .expect("summary digest")
            .len(),
        43,
        "SHA-256 must use fixed-width base64url without padding"
    );
    assert!(
        !serde_json::to_string(&verified.claims)
            .unwrap()
            .contains(&padding),
        "signed summary must not inline the large Grant details"
    );

    let (introspection_status, introspection) =
        introspect(&router, "rs-a-introspect", "sekret-a", access_token).await;
    assert_eq!(introspection_status, StatusCode::OK);
    assert_eq!(introspection["active"], true);
    assert_eq!(
        introspection["authorization_details"], rar_value,
        "authenticated introspection must return the complete ordered Grant details"
    );

    let refresh_token = token_response["refresh_token"]
        .as_str()
        .expect("code flow refresh token");
    let refresh_form = format!(
        "grant_type=refresh_token&refresh_token={refresh_token}&client_id=app-a&resource={RS_A}"
    );
    let (refresh_status, refresh_response) = {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header("host", HOST)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(refresh_form))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        )
    };
    assert_eq!(
        refresh_status,
        StatusCode::OK,
        "refresh must preserve Grant-backed delivery instead of rejecting the large RAR: {refresh_response}"
    );
    let refreshed_access_token = refresh_response["access_token"]
        .as_str()
        .expect("refreshed access token");
    assert!(
        refreshed_access_token.len() < agent_auth_token::JWT_SOFT_TARGET_BYTES,
        "refreshed Grant-backed summary token must remain below the 4 KiB target"
    );
    let refreshed = agent_auth_workload::verify_es256(
        refreshed_access_token,
        ec_jwk["x"].as_str().unwrap(),
        ec_jwk["y"].as_str().unwrap(),
        Some(kid),
    )
    .expect("refreshed large-RAR summary token must be verifiably signed");
    assert_eq!(
        refreshed.claims["authorization_details"][0]["type"],
        "agent_auth_grant_summary_v1"
    );
    let (refreshed_introspection_status, refreshed_introspection) = introspect(
        &router,
        "rs-a-introspect",
        "sekret-a",
        refreshed_access_token,
    )
    .await;
    assert_eq!(refreshed_introspection_status, StatusCode::OK);
    assert_eq!(refreshed_introspection["active"], true);
    assert_eq!(
        refreshed_introspection["authorization_details"], rar_value,
        "refreshed token introspection must return the complete ordered Grant details"
    );

    let grant_id = verified.claims["https://a-auth.com/c"]["auth_grant"]
        .as_str()
        .expect("summary token auth_grant");
    let original_grant = agent_auth_http::ports::GrantStore::get(grants.as_ref(), "", grant_id)
        .await
        .unwrap()
        .expect("summary token Grant");
    let mut changed_grant = original_grant.clone();
    changed_grant.per_resource[0].authorization_details[0]["max_records"] =
        serde_json::json!(9_999);
    agent_auth_http::ports::GrantStore::put(grants.as_ref(), "", changed_grant)
        .await
        .unwrap();

    let (changed_status, changed_introspection) =
        introspect(&router, "rs-a-introspect", "sekret-a", access_token).await;
    assert_eq!(changed_status, StatusCode::OK);
    assert_eq!(
        changed_introspection,
        serde_json::json!({"active": false}),
        "a signed summary must fail closed when the authoritative Grant no longer matches its digest"
    );

    agent_auth_http::ports::GrantStore::put(grants.as_ref(), "", original_grant.clone())
        .await
        .unwrap();
    let mut current_refresh_token = refresh_response["refresh_token"]
        .as_str()
        .expect("rotated refresh token")
        .to_string();
    let refresh_form_for = |refresh_token: &str| {
        format!(
            "grant_type=refresh_token&refresh_token={refresh_token}&client_id=app-a&resource={RS_A}"
        )
    };

    let mut revoked_grant = original_grant.clone();
    revoked_grant.status = agent_auth_grant::GrantStatus::Revoked;
    agent_auth_http::ports::GrantStore::put(grants.as_ref(), "", revoked_grant)
        .await
        .unwrap();
    let revoked_form = refresh_form_for(&current_refresh_token);
    let (status, revoked_error) = post_token_form(&router, revoked_form.clone()).await;
    assert_oauth_error_without_tokens(
        status,
        &revoked_error,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
    );
    agent_auth_http::ports::GrantStore::put(grants.as_ref(), "", original_grant.clone())
        .await
        .unwrap();
    let (status, recovered) = post_token_form(&router, revoked_form).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the same refresh token must remain usable after the revoked-Grant read gate is restored: {recovered}"
    );
    current_refresh_token = recovered["refresh_token"]
        .as_str()
        .expect("refresh after revoked-Grant recovery")
        .to_string();

    let mut expired_grant = original_grant.clone();
    expired_grant.constraints.expires_at = 0;
    agent_auth_http::ports::GrantStore::put(grants.as_ref(), "", expired_grant)
        .await
        .unwrap();
    let expired_form = refresh_form_for(&current_refresh_token);
    let (status, expired_error) = post_token_form(&router, expired_form.clone()).await;
    assert_oauth_error_without_tokens(
        status,
        &expired_error,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
    );
    agent_auth_http::ports::GrantStore::put(grants.as_ref(), "", original_grant.clone())
        .await
        .unwrap();
    let (status, recovered) = post_token_form(&router, expired_form).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the same refresh token must remain usable after the expired-Grant read gate is restored: {recovered}"
    );
    current_refresh_token = recovered["refresh_token"]
        .as_str()
        .expect("refresh after expired-Grant recovery")
        .to_string();

    match grants.as_ref() {
        agent_auth_http::state::GrantStoreImpl::Memory(store) => store.fail_next_get_permanent(),
        #[cfg(feature = "aws")]
        agent_auth_http::state::GrantStoreImpl::Dynamo(_) => {
            panic!("test requires memory Grant store")
        }
    }
    let read_error_form = refresh_form_for(&current_refresh_token);
    let (status, read_error) = post_token_form(&router, read_error_form.clone()).await;
    assert_oauth_error_without_tokens(
        status,
        &read_error,
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
    );
    let (status, recovered) = post_token_form(&router, read_error_form).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the same refresh token must remain usable after the permanent Grant read error clears: {recovered}"
    );
    current_refresh_token = recovered["refresh_token"]
        .as_str()
        .expect("refresh after Grant read recovery")
        .to_string();

    let mut wrong_resource_grant = original_grant.clone();
    wrong_resource_grant.per_resource.clear();
    agent_auth_http::ports::GrantStore::put(grants.as_ref(), "", wrong_resource_grant)
        .await
        .unwrap();
    let wrong_resource_form = refresh_form_for(&current_refresh_token);
    let (status, wrong_resource_error) =
        post_token_form(&router, wrong_resource_form.clone()).await;
    assert_oauth_error_without_tokens(
        status,
        &wrong_resource_error,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
    );
    agent_auth_http::ports::GrantStore::put(grants.as_ref(), "", original_grant.clone())
        .await
        .unwrap();
    let (status, recovered) = post_token_form(&router, wrong_resource_form).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the same refresh token must remain usable after exact-resource authority is restored: {recovered}"
    );
    current_refresh_token = recovered["refresh_token"]
        .as_str()
        .expect("refresh after exact-resource recovery")
        .to_string();

    assert_eq!(
        agent_auth_http::ports::GrantStore::delete_all_by_tenant(grants.as_ref(), "")
            .await
            .unwrap(),
        1,
        "test setup must remove the authoritative Grant"
    );
    let missing_grant_form = refresh_form_for(&current_refresh_token);
    let (status, missing_grant_error) = post_token_form(&router, missing_grant_form.clone()).await;
    assert_oauth_error_without_tokens(
        status,
        &missing_grant_error,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
    );
    agent_auth_http::ports::GrantStore::put(grants.as_ref(), "", original_grant.clone())
        .await
        .unwrap();
    let (status, recovered) = post_token_form(&router, missing_grant_form).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the same refresh token must remain usable after the missing Grant is restored: {recovered}"
    );

    let persistence_verifier = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
    let persistence_challenge = s256_challenge(persistence_verifier);
    let persistence_authz = format!(
        "/authorize?response_type=code&client_id=app-a&redirect_uri=https://app.example.com/cb\
         &code_challenge={persistence_challenge}&code_challenge_method=S256&scope=openid&login_user=alice\
         &resource={RS_A}&authorization_details={rar_enc}"
    );
    let persistence_location = {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&persistence_authz)
                    .header("host", HOST)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string()
    };
    let persistence_code = persistence_location
        .split('?')
        .nth(1)
        .unwrap()
        .split('&')
        .find_map(|part| part.strip_prefix("code="))
        .expect("authorization code");
    match grants.as_ref() {
        agent_auth_http::state::GrantStoreImpl::Memory(store) => store.fail_next_put(),
        #[cfg(feature = "aws")]
        agent_auth_http::state::GrantStoreImpl::Dynamo(_) => {
            panic!("test requires memory Grant store")
        }
    }
    let persistence_form = format!(
        "grant_type=authorization_code&code={persistence_code}&code_verifier={persistence_verifier}\
         &redirect_uri=https://app.example.com/cb&client_id=app-a&resource={RS_A}"
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(persistence_form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "a bounded summary token must never be returned when its authoritative Grant cannot be persisted"
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let persistence_error: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(persistence_error["error"], "server_error");
    assert!(persistence_error.get("access_token").is_none());
    assert!(persistence_error.get("refresh_token").is_none());
    assert!(persistence_error.get("token_type").is_none());
    assert!(persistence_error.get("id_token").is_none());

    let small_rar_value = serde_json::json!([{
        "type": "agent_auth_rar_v1",
        "locations": [RS_A],
        "identifier": "policy-small",
        "max_records": 3
    }]);
    let small_rar = serde_json::to_string(&small_rar_value).unwrap();
    let small_rar_enc = small_rar
        .replace('%', "%25")
        .replace('{', "%7B")
        .replace('}', "%7D")
        .replace('[', "%5B")
        .replace(']', "%5D")
        .replace('"', "%22")
        .replace(':', "%3A")
        .replace(',', "%2C")
        .replace('/', "%2F");
    let small_verifier = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg";
    let small_challenge = s256_challenge(small_verifier);
    let small_authz = format!(
        "/authorize?response_type=code&client_id=app-a&redirect_uri=https://app.example.com/cb\
         &code_challenge={small_challenge}&code_challenge_method=S256&scope=openid&login_user=alice\
         &resource={RS_A}&authorization_details={small_rar_enc}"
    );
    let small_location = {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&small_authz)
                    .header("host", HOST)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string()
    };
    let small_code = small_location
        .split('?')
        .nth(1)
        .unwrap()
        .split('&')
        .find_map(|part| part.strip_prefix("code="))
        .expect("authorization code");
    match grants.as_ref() {
        agent_auth_http::state::GrantStoreImpl::Memory(store) => store.fail_next_put(),
        #[cfg(feature = "aws")]
        agent_auth_http::state::GrantStoreImpl::Dynamo(_) => {
            panic!("test requires memory Grant store")
        }
    }
    let small_form = format!(
        "grant_type=authorization_code&code={small_code}&code_verifier={small_verifier}\
         &redirect_uri=https://app.example.com/cb&client_id=app-a&resource={RS_A}"
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(small_form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "an inline small-RAR access token may retain the existing single-authority fallback"
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let small_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        small_response.get("refresh_token").is_none(),
        "a marked family without a Grant must not return an unusable refresh credential"
    );
    let small_access_token = small_response["access_token"]
        .as_str()
        .expect("inline small-RAR access token");
    let small_claims: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(
                small_access_token
                    .split('.')
                    .nth(1)
                    .expect("access token payload"),
            )
            .expect("access token payload base64url"),
    )
    .expect("access token claims JSON");
    assert_eq!(
        small_claims["authorization_details"], small_rar_value,
        "small RAR must remain inline when no bounded summary was needed"
    );
}

// /introspect:垃圾/无效 token 经端点 → active:false,与 aud 不匹配的响应字节等价(不可区分)。
#[tokio::test]
async fn introspect_invalid_token_indistinguishable_inactive() {
    let state = AppState::dev(HOST);
    state
        .seed_dev_client("app-a", "https://app.example.com/cb", Some(RS_A))
        .await;
    state
        .seed_rs_introspect_client("rs-a-introspect", "sekret-a", &[RS_A])
        .await;
    state
        .seed_rs_introspect_client("rs-b-introspect", "sekret-b", &[RS_B])
        .await;
    let (router, _) = build_router(state);
    let token = mint_token_for_resource(&router, "app-a", "https://app.example.com/cb").await;

    // 垃圾 token(验签失败)→ active:false。
    let (st, garbage) = introspect(&router, "rs-a-introspect", "sekret-a", "not.a.jwt").await;
    assert_eq!(st, StatusCode::OK);
    // aud 不匹配(RS-B 查 RS-A token)→ active:false。
    let (_, wrong_aud) = introspect(&router, "rs-b-introspect", "sekret-b", &token).await;
    // 两者响应字节等价(都只 {"active":false},不泄露"token 无效"vs"aud 不匹配")。
    assert_eq!(
        garbage, wrong_aud,
        "无效 token 与 aud 不匹配的 inactive 响应应不可区分"
    );
    assert_eq!(garbage, serde_json::json!({"active": false}));
}

// /introspect:普通机密 client(无 introspect 权限)→ 401;认证失败 → 401。
#[tokio::test]
async fn introspect_requires_permission_and_auth() {
    let state = AppState::dev(HOST);
    state
        .seed_dev_client("app-a", "https://app.example.com/cb", Some(RS_A))
        .await;
    state
        .seed_rs_introspect_client("rs-a-introspect", "sekret-a", &[RS_A])
        .await;
    let (router, _) = build_router(state);
    let token = mint_token_for_resource(&router, "app-a", "https://app.example.com/cb").await;

    // 完全匿名(无 client_id、无 Authorization)→ 401(C8.6:MUST NOT 匿名可达)。
    let form = format!("token={token}");
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/introspect")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "匿名 introspect 应 401"
    );

    // 未知调用方 → 401。
    let (st, _) = introspect(&router, "nobody", "x", &token).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "未知调用方应 401");

    // 认证方式对但 secret 错 → 401。
    let (st, _) = introspect(&router, "rs-a-introspect", "WRONG", &token).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "错 secret 应 401");

    // public client(app-a,无 introspect 权限)即便认证"通过"也无权限 → 401。
    let form = format!("token={token}&client_id=app-a");
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/introspect")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "无 introspect 权限的 client 应 401"
    );
}

// 评审 codex HIGH:introspect_enabled 但认证方式=none 的 client → 仍 401(无凭证不可 introspect)。
#[tokio::test]
async fn introspect_none_auth_method_rejected_even_if_enabled() {
    use agent_auth_http::ports::{ClientRecord, ClientStore};
    let state = AppState::dev(HOST);
    state
        .seed_dev_client("app-a", "https://app.example.com/cb", Some(RS_A))
        .await;
    // 故意配置一个 introspect_enabled=true 但 token_endpoint_auth_method=none 的坏记录。
    let _ = ClientStore::put(
        &*state.clients,
        "",
        ClientRecord {
            client_id: "bad-none-introspect".into(),
            redirect_uris: vec![],
            application_type: None,
            token_endpoint_auth_method: "none".into(),
            client_secret: None,
            client_secret_credentials: Default::default(),
            jwks: None,
            jwks_uri: None,
            token_endpoint_auth_signing_alg: None,
            default_resource: None,
            introspect_enabled: true,
            resource_ids: vec![RS_A.into()],
            post_logout_redirect_uris: vec![],
            reg_token_hash: None,
            registration_token_credentials: Default::default(),
            client_type: Some("confidential".into()),
            id_token_signed_response_alg: None,
            oidc_sector_identifier: None,
            allowed_resources: vec![],
            allowed_scopes: vec![],
            redirect_mode: None,
            created_at: 0,
            last_used_day: None,
            authority_revision: 0,
            tombstoned_at: None,
            backchannel_token_delivery_mode: None,
            backchannel_client_notification_endpoint: None,
            require_dpop: false,
            prm_domains: vec![],
        },
    )
    .await;
    let (router, _) = build_router(state.clone());
    let token = mint_token_for_resource(&router, "app-a", "https://app.example.com/cb").await;

    // 无 Authorization 头、仅 form client_id → none 方法即便 enabled 也 MUST 401。
    let form = format!("token={token}&client_id=bad-none-introspect");
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/introspect")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "none 认证方式的 introspect client 应 401(fail-closed,评审 codex HIGH)"
    );
}

// 最小 URL 编码(只处理测试里用到的 : 和 /)。
fn urlencoding(s: &str) -> String {
    s.replace(':', "%3A").replace('/', "%2F")
}
