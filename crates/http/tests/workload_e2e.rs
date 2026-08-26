//! 进程内 e2e:workload 客户端认证的纯逻辑切片(spec 012,P2)。
//!
//! 覆盖(不依赖真实 STS/JWKS):
//! - C5.6:`client_type=workload` 的 client 发起 `GET /authorize` → 拒(unauthorized_client)。
//!   非 workload(public)client 不受影响。
//! - C5.5:DCR `POST /register` 无法铸造 workload——三条 workload auth method 被拒(未知方法),
//!   且 DCR 产出的 client 恒非 workload(client_type 由 auth_method 推 public/confidential)。

use agent_auth_client::s256_challenge;
use agent_auth_http::{build_router, AppState};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

const HOST: &str = "localhost";

// C5.6:workload client 发起 /authorize 被拒。
#[tokio::test]
async fn authorize_rejects_workload_client() {
    let state = AppState::dev(HOST);
    state.seed_workload_client("wl-agent").await;
    let (router, _) = build_router(state);

    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let authz = format!(
        "/authorize?response_type=code&client_id=wl-agent&redirect_uri=https://x/cb\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice"
    );
    let resp = router
        .oneshot(
            Request::builder()
                .uri(&authz)
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "workload 走 /authorize 应拒"
    );
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("unauthorized_client"),
        "错误应含 unauthorized_client: {text}"
    );
    assert!(text.contains("workload"), "错误应说明 workload 限制");
}

// C5.6 对照:非 workload(public)client 走 /authorize 正常(有 login_user 占位 → 303 签 code)。
#[tokio::test]
async fn authorize_allows_public_client() {
    let state = AppState::dev(HOST);
    state
        .seed_dev_client("pub-app", "https://app.example.com/cb", None)
        .await;
    let (router, _) = build_router(state);

    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let authz = format!(
        "/authorize?response_type=code&client_id=pub-app&redirect_uri=https://app.example.com/cb\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice"
    );
    let resp = router
        .oneshot(
            Request::builder()
                .uri(&authz)
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "public client 应正常签 code(303)"
    );
}

// C5.5:DCR 无法铸造 workload——workload auth method 被拒。
#[tokio::test]
async fn dcr_cannot_mint_workload_auth_method() {
    let state = AppState::dev(HOST); // dcr_mode=Open
    let (router, _) = build_router(state);

    for method in [
        "aws_sigv4_caller_identity",
        "workload_oidc_jwt",
        "spiffe_jwt_svid",
        "spiffe_svid_mtls",
    ] {
        let body = serde_json::json!({
            "redirect_uris": ["https://x/cb"],
            "token_endpoint_auth_method": method
        });
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/register")
                    .header("host", HOST)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "DCR 用 workload auth method {method} 应拒(不铸 workload 信任锚)"
        );
    }
}

// C5.5 admin API:登记 OIDC workload 信任绑定(admin 认证)+ 目标须为 workload client + 列表。
#[tokio::test]
async fn admin_workload_trust_register_and_list() {
    const ADMIN: &str = "dev-admin-token-not-for-prod";
    let admin_auth = format!("Bearer {ADMIN}");
    let state = AppState::dev(HOST);
    state.seed_workload_client("wl-gha").await; // 目标 workload client
    state
        .seed_dev_client("pub-app", "https://app.example.com/cb", None)
        .await; // 普通 client(对照)
    let (router, _) = build_router(state);

    let mk_body = |cid: &str| {
        serde_json::json!({
            "binding_id": "b1",
            "tenant_id": "default",
            "platform_issuer": "https://token.actions.githubusercontent.com",
            "jwks_uri": "https://token.actions.githubusercontent.com/.well-known/jwks",
            "subject_pattern": "repo:acme/agent:*",
            "mapped_client_id": cid
        })
        .to_string()
    };

    // 无 admin token → 401。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/workload-trust")
                .header("host", HOST)
                .header("content-type", "application/json")
                .body(Body::from(mk_body("wl-gha")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "无 admin token 应 401"
    );

    // 绑到不存在的 client → 400。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/workload-trust")
                .header("host", HOST)
                .header("authorization", &admin_auth)
                .header("content-type", "application/json")
                .body(Body::from(mk_body("nonexistent")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "绑不存在 client 应 400"
    );

    // 绑到非 workload(普通 public)client → 400。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/workload-trust")
                .header("host", HOST)
                .header("authorization", &admin_auth)
                .header("content-type", "application/json")
                .body(Body::from(mk_body("pub-app")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "绑非 workload client 应 400"
    );

    // 评审 M1:过宽 subject_pattern(纯 `*`)→ 400(纵深防御,防信任边界绕过)。
    let wide = serde_json::json!({
        "binding_id": "bwide", "tenant_id": "default",
        "platform_issuer": "https://token.actions.githubusercontent.com",
        "jwks_uri": "https://x/jwks", "subject_pattern": "*", "mapped_client_id": "wl-gha"
    });
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/workload-trust")
                .header("host", HOST)
                .header("authorization", &admin_auth)
                .header("content-type", "application/json")
                .body(Body::from(wide.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "纯 * subject_pattern 应拒(M1)"
    );

    // 绑到 workload client → 201。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/workload-trust")
                .header("host", HOST)
                .header("authorization", &admin_auth)
                .header("content-type", "application/json")
                .body(Body::from(mk_body("wl-gha")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "绑 workload client 应 201"
    );

    // 列出该租户绑定 → 含刚登记的。
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/admin/workload-trust/default")
                .header("host", HOST)
                .header("authorization", &admin_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let j: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(j["total"], 1);
    assert_eq!(j["bindings"][0]["mechanism"], "oidc");
    assert_eq!(j["bindings"][0]["mapped_client_id"], "wl-gha");
}

// spec 012 §1.4:admin 登记 SpiffeJwt 绑定 round-trip + 校验(评审 Kiro Q5:枚举扩展序列化兼容 + 整域通配拒)。
#[tokio::test]
async fn admin_workload_trust_spiffe_register_and_list() {
    const ADMIN: &str = "dev-admin-token-not-for-prod";
    let admin_auth = format!("Bearer {ADMIN}");
    let state = AppState::dev(HOST);
    state.seed_workload_client("wl-spiffe").await;
    let (router, _) = build_router(state);

    let post = |body: String| {
        let router = router.clone();
        let auth = admin_auth.clone();
        async move {
            router
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/admin/workload-trust")
                        .header("host", HOST)
                        .header("authorization", &auth)
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap()
        }
    };

    // 整域通配 spiffe://<td>/* → 400(过宽,吞整个 trust domain)。
    let wide = serde_json::json!({
        "binding_id": "bs-wide", "tenant_id": "default", "mechanism": "spiffe_jwt",
        "trust_domain": "acme.example", "jwks_uri": "https://spire.acme.example/bundle",
        "subject_pattern": "spiffe://acme.example/*", "mapped_client_id": "wl-spiffe"
    });
    assert_eq!(
        post(wide.to_string()).await.status(),
        StatusCode::BAD_REQUEST,
        "整域通配 spiffe://<td>/* 应拒"
    );

    // pattern 非 SPIFFE ID → 400。
    let notspiffe = serde_json::json!({
        "binding_id": "bs-ns", "tenant_id": "default", "mechanism": "spiffe_jwt",
        "trust_domain": "acme.example", "jwks_uri": "https://spire.acme.example/bundle",
        "subject_pattern": "agent/*", "mapped_client_id": "wl-spiffe"
    });
    assert_eq!(
        post(notspiffe.to_string()).await.status(),
        StatusCode::BAD_REQUEST,
        "pattern 非完整 SPIFFE ID 应拒"
    );

    // pattern trust domain 与独立信任锚不一致 → 400。
    let mismatch = serde_json::json!({
        "binding_id": "bs-mm", "tenant_id": "default", "mechanism": "spiffe_jwt",
        "trust_domain": "acme.example", "jwks_uri": "https://spire.acme.example/bundle",
        "subject_pattern": "spiffe://evil.example/agent/*", "mapped_client_id": "wl-spiffe"
    });
    assert_eq!(
        post(mismatch.to_string()).await.status(),
        StatusCode::BAD_REQUEST,
        "pattern trust domain 与 trust_domain 字段不一致应拒"
    );

    // SPIFFE bundle 不得复用本 AS JWKS；大小写、query、fragment 都不能绕过。
    let as_jwks = serde_json::json!({
        "binding_id": "bs-as-jwks", "tenant_id": "default", "mechanism": "spiffe_jwt",
        "trust_domain": "acme.example",
        "jwks_uri": format!("HTTPS://{HOST}/jwks.json?cache=1#fragment"),
        "subject_pattern": "spiffe://acme.example/agent/*", "mapped_client_id": "wl-spiffe"
    });
    assert_eq!(
        post(as_jwks.to_string()).await.status(),
        StatusCode::BAD_REQUEST,
        "SPIFFE trust bundle 不得复用本 AS JWKS"
    );

    // 合法 SPIFFE 绑定 → 201。
    let ok = serde_json::json!({
        "binding_id": "bs1", "tenant_id": "default", "mechanism": "spiffe_jwt",
        "trust_domain": "acme.example", "jwks_uri": "https://spire.acme.example/bundle",
        "subject_pattern": "spiffe://acme.example/agent/*", "mapped_client_id": "wl-spiffe"
    });
    assert_eq!(
        post(ok.to_string()).await.status(),
        StatusCode::CREATED,
        "合法 SPIFFE 绑定应 201"
    );

    // list 回显 mechanism=spiffe_jwt + trust_anchor=trust_domain。
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/admin/workload-trust/default")
                .header("host", HOST)
                .header("authorization", &admin_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let j: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(j["total"], 1);
    assert_eq!(j["bindings"][0]["mechanism"], "spiffe_jwt");
    assert_eq!(j["bindings"][0]["trust_anchor"], "acme.example");
    assert_eq!(
        j["bindings"][0]["subject_pattern"],
        "spiffe://acme.example/agent/*"
    );
}

// spec 012 §1.4 / C5.7:admin 登记 SpiffeX509(mTLS)round-trip + 校验(无 jwks_uri;评审 M1)。
#[tokio::test]
async fn admin_workload_trust_spiffe_x509_register_and_list() {
    const ADMIN: &str = "dev-admin-token-not-for-prod";
    let admin_auth = format!("Bearer {ADMIN}");
    let state = AppState::dev(HOST);
    state.seed_workload_client("wl-x509").await;
    let (router, _) = build_router(state);

    let post = |body: String| {
        let router = router.clone();
        let auth = admin_auth.clone();
        async move {
            router
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/admin/workload-trust")
                        .header("host", HOST)
                        .header("authorization", &auth)
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap()
        }
    };

    // 整域通配拒。
    let wide = serde_json::json!({
        "binding_id": "x-wide", "tenant_id": "default", "mechanism": "spiffe_x509",
        "trust_domain": "acme.example",
        "subject_pattern": "spiffe://acme.example/*", "mapped_client_id": "wl-x509"
    });
    assert_eq!(
        post(wide.to_string()).await.status(),
        StatusCode::BAD_REQUEST
    );

    // pattern td 与 trust_domain 不一致拒。
    let mismatch = serde_json::json!({
        "binding_id": "x-mm", "tenant_id": "default", "mechanism": "spiffe_x509",
        "trust_domain": "acme.example",
        "subject_pattern": "spiffe://evil.example/agent/*", "mapped_client_id": "wl-x509"
    });
    assert_eq!(
        post(mismatch.to_string()).await.status(),
        StatusCode::BAD_REQUEST
    );

    // 合法 SpiffeX509 绑定(**无 jwks_uri**)→ 201。
    let ok = serde_json::json!({
        "binding_id": "x1", "tenant_id": "default", "mechanism": "spiffe_x509",
        "trust_domain": "acme.example",
        "subject_pattern": "spiffe://acme.example/agent/*", "mapped_client_id": "wl-x509"
    });
    assert_eq!(
        post(ok.to_string()).await.status(),
        StatusCode::CREATED,
        "合法 SpiffeX509 绑定(无 jwks_uri)应 201"
    );

    // list 回显 mechanism=spiffe_x509 + trust_anchor。
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/admin/workload-trust/default")
                .header("host", HOST)
                .header("authorization", &admin_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let j: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(j["total"], 1);
    assert_eq!(j["bindings"][0]["mechanism"], "spiffe_x509");
    assert_eq!(j["bindings"][0]["trust_anchor"], "acme.example");
}

// C5.5:DCR 产出的 client 恒非 workload(client_type 由 auth_method 推 public/confidential)。
#[tokio::test]
async fn dcr_client_is_never_workload() {
    use agent_auth_http::ports::{ClientStore, ClientType};
    let state = AppState::dev(HOST);
    let (router, _) = build_router(state.clone());

    // 注册一个 public client(none)。
    let body = serde_json::json!({ "redirect_uris": ["https://x/cb"] });
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("host", HOST)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let j: serde_json::Value = serde_json::from_slice(&b).unwrap();
    let cid = j["client_id"].as_str().unwrap();
    let rec = ClientStore::get(&*state.clients, "", cid)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(
        rec.client_type(),
        ClientType::Workload,
        "DCR 产出的 client 绝不是 workload"
    );
    assert_eq!(
        rec.client_type(),
        ClientType::Public,
        "none 方法应推 public"
    );
}

// ---- spec 012 C5.1/C5.6:workload_oidc_jwt 认证 + client_credentials(2LO)接线(P2)----

use agent_auth_http::ports::{
    ClientRecord, ClientStore, PlatformJwk, RateLimitStore, RegisteredClientJwk,
    RegisteredClientJwks, WorkloadTrustStore,
};
use agent_auth_http::security_event::{
    SecurityEventCategory, SecurityEventOutcome, SecurityEventStore,
};
use agent_auth_http::state::JwksFetcherImpl;
use agent_auth_http::Phase;
use agent_auth_workload::{TrustBinding, TrustMechanism};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD as B64};
use base64::Engine as _;
use std::sync::Arc;

const PLATFORM_ISS: &str = "https://token.actions.githubusercontent.com";
const JWKS_URI: &str = "https://token.actions.githubusercontent.com/jwks";
const RS: &str = "https://mcp.rs.example.com";

// 造一把确定性 RSA key、一枚平台 OIDC JWT(RS256)、以及对应 PlatformJwk。
// 返回 (jwt, platform_jwk)。`claims` 由调用方给(iss/sub/aud/exp/iat 等)。
fn make_platform_jwt(kid: &str, claims: serde_json::Value) -> (String, PlatformJwk) {
    use rsa::pkcs1v15::SigningKey;
    use rsa::rand_core::SeedableRng;
    use rsa::signature::{SignatureEncoding, Signer};
    use rsa::traits::PublicKeyParts;
    // 确定性 key(测试可复现)。
    let mut rng = rand::rngs::StdRng::from_seed([7u8; 32]);
    let sk = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let pk = sk.to_public_key();
    let n = B64.encode(pk.n().to_bytes_be());
    let e = B64.encode(pk.e().to_bytes_be());

    let header = serde_json::json!({ "alg": "RS256", "typ": "JWT", "kid": kid });
    let h = B64.encode(serde_json::to_vec(&header).unwrap());
    let p = B64.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{h}.{p}");
    let signer = SigningKey::<sha2::Sha256>::new(sk);
    let sig = signer.sign(signing_input.as_bytes());
    let jwt = format!("{signing_input}.{}", B64.encode(sig.to_bytes()));
    (
        jwt,
        PlatformJwk {
            kid: Some(kid.to_string()),
            kty: Some("RSA".into()),
            n,
            e,
            alg: Some("RS256".into()),
            ..Default::default()
        },
    )
}

// 装配 P2 AppState:workload client(带 allowed_resources)+ OIDC 信任绑定 + JwksFetcher 预置 key。
async fn setup_2lo_with_state(claims_kid: &str, jwk: PlatformJwk) -> (axum::Router, AppState) {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P2; // client_credentials 阶段门控(006)
                             // workload client + 2LO 策略(allowed_resources=RS)。
    state
        .seed_workload_client_with_policy("wl-gha", vec![RS.to_string()], vec!["kb:read".into()])
        .await;
    // OIDC 信任绑定(tenant=default,与 tenant_from_issuer 一致;iss+sub 匹配 → wl-gha)。
    let _ = state
        .workload_trust
        .put(
            "",
            "b1".into(),
            TrustBinding {
                tenant_id: "default".into(),
                mechanism: TrustMechanism::Oidc {
                    platform_issuer: PLATFORM_ISS.into(),
                    jwks_uri: JWKS_URI.into(),
                    subject_pattern: "repo:acme/agent:*".into(),
                },
                mapped_client_id: "wl-gha".into(),
            },
        )
        .await;
    // JwksFetcher 预置该 jwks_uri 的 key。
    let fetcher = agent_auth_http::adapters::memory::MemoryJwksFetcher::default();
    fetcher.set(JWKS_URI, vec![jwk]).await;
    let _ = claims_kid;
    state.jwks_fetcher = Arc::new(JwksFetcherImpl::Memory(fetcher));
    let (router, _) = build_router(state.clone());
    (router, state)
}

async fn setup_2lo(claims_kid: &str, jwk: PlatformJwk) -> axum::Router {
    setup_2lo_with_state(claims_kid, jwk).await.0
}

/// 同 setup_2lo,但 allowed_scopes 由参数给(供体积上限测试:超大白名单 scope 全授进 token)。
async fn setup_2lo_with_scopes(
    claims_kid: &str,
    jwk: PlatformJwk,
    allowed_scopes: Vec<String>,
) -> axum::Router {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P2;
    state
        .seed_workload_client_with_policy("wl-gha", vec![RS.to_string()], allowed_scopes)
        .await;
    let _ = state
        .workload_trust
        .put(
            "",
            "b1".into(),
            TrustBinding {
                tenant_id: "default".into(),
                mechanism: TrustMechanism::Oidc {
                    platform_issuer: PLATFORM_ISS.into(),
                    jwks_uri: JWKS_URI.into(),
                    subject_pattern: "repo:acme/agent:*".into(),
                },
                mapped_client_id: "wl-gha".into(),
            },
        )
        .await;
    let fetcher = agent_auth_http::adapters::memory::MemoryJwksFetcher::default();
    fetcher.set(JWKS_URI, vec![jwk]).await;
    let _ = claims_kid;
    state.jwks_fetcher = Arc::new(JwksFetcherImpl::Memory(fetcher));
    let (router, _) = build_router(state);
    router
}

async fn post_2lo_response(router: &axum::Router, form: String) -> axum::response::Response {
    router
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
        .unwrap()
}

async fn post_2lo(router: &axum::Router, form: String) -> (StatusCode, serde_json::Value) {
    let resp = post_2lo_response(router, form).await;
    let st = resp.status();
    let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        st,
        serde_json::from_slice(&b).unwrap_or(serde_json::json!({})),
    )
}

async fn setup_service_2lo(subject_type: agent_auth_http::SubjectType) -> (axum::Router, AppState) {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P2;
    state.subject_type = subject_type;
    for (client_id, secret, auth_method, allowed_resources) in [
        (
            "svc-backend",
            "svc-secret",
            "client_secret_basic",
            vec![RS.into(), RS2.into()],
        ),
        (
            "svc-post",
            "post-secret",
            "client_secret_post",
            vec![RS.into()],
        ),
        ("ordinary-web", "web-secret", "client_secret_basic", vec![]),
        (
            "malformed-public",
            "public-secret",
            "client_secret_basic",
            vec![RS.into()],
        ),
        (
            "malformed-workload",
            "workload-secret",
            "client_secret_basic",
            vec![RS.into()],
        ),
    ] {
        let client_type = match client_id {
            "malformed-public" => "public",
            "malformed-workload" => "workload",
            _ => "confidential",
        };
        state
            .clients
            .put(
                "",
                ClientRecord {
                    client_id: client_id.into(),
                    token_endpoint_auth_method: auth_method.into(),
                    client_secret: Some(secret.into()),
                    client_type: Some(client_type.into()),
                    allowed_resources,
                    allowed_scopes: vec!["kb:read".into()],
                    ..Default::default()
                },
            )
            .await
            .unwrap();
    }
    state
        .clients
        .put(
            "",
            ClientRecord {
                client_id: "misconfigured-service".into(),
                token_endpoint_auth_method: "none".into(),
                client_type: Some("confidential".into()),
                allowed_resources: vec![RS.into()],
                allowed_scopes: vec!["kb:read".into()],
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let (_, service_jwk) = service_private_key_material();
    state
        .clients
        .put(
            "",
            ClientRecord {
                client_id: "svc-jwt".into(),
                token_endpoint_auth_method: "private_key_jwt".into(),
                token_endpoint_auth_signing_alg: Some("ES256".into()),
                jwks: Some(RegisteredClientJwks {
                    keys: vec![service_jwk],
                }),
                client_type: Some("confidential".into()),
                allowed_resources: vec![RS.into()],
                allowed_scopes: vec!["kb:read".into()],
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let (router, _) = build_router(state.clone());
    (router, state)
}

fn service_private_key_material() -> (SigningKey, RegisteredClientJwk) {
    let signing_key = SigningKey::from_bytes(&[91u8; 32].into()).unwrap();
    let point = signing_key.verifying_key().to_encoded_point(false);
    (
        signing_key,
        RegisteredClientJwk {
            kid: "svc-jwt-key".into(),
            kty: "EC".into(),
            alg: "ES256".into(),
            public_key_use: Some("sig".into()),
            crv: Some("P-256".into()),
            n: None,
            e: None,
            x: Some(B64.encode(point.x().unwrap())),
            y: Some(B64.encode(point.y().unwrap())),
        },
    )
}

fn service_private_key_assertion(client_id: &str, jti: &str) -> String {
    let (signing_key, _) = service_private_key_material();
    let now = te_now();
    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "JWT",
        "kid": "svc-jwt-key"
    });
    let claims = serde_json::json!({
        "iss": client_id,
        "sub": client_id,
        "aud": TE_HTU,
        "iat": now,
        "nbf": now,
        "exp": now + 120,
        "jti": jti
    });
    let encoded_header = B64.encode(serde_json::to_vec(&header).unwrap());
    let encoded_claims = B64.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{encoded_header}.{encoded_claims}");
    let signature: P256Sig = signing_key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", B64.encode(signature.to_bytes()))
}

async fn post_service_2lo(
    router: &axum::Router,
    client_id: &str,
    secret: &str,
    resource: &str,
) -> axum::response::Response {
    post_service_2lo_request(router, client_id, secret, resource, "kb:read", None).await
}

async fn post_service_2lo_request(
    router: &axum::Router,
    client_id: &str,
    secret: &str,
    resource: &str,
    scope: &str,
    dpop: Option<&str>,
) -> axum::response::Response {
    let basic = STANDARD.encode(format!("{client_id}:{secret}"));
    let mut request = Request::builder()
        .method("POST")
        .uri("/token")
        .header("host", HOST)
        .header("authorization", format!("Basic {basic}"))
        .header("content-type", "application/x-www-form-urlencoded");
    if let Some(proof) = dpop {
        request = request.header("dpop", proof);
    }
    router
        .clone()
        .oneshot(
            request
                .body(Body::from(format!(
                    "grant_type=client_credentials&resource={resource}&scope={scope}"
                )))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn post_service_2lo_form(
    router: &axum::Router,
    values: &[(&str, &str)],
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(serde_urlencoded::to_string(values).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn post_service_2lo_form_with_basic(
    router: &axum::Router,
    client_id: &str,
    secret: &str,
    values: &[(&str, &str)],
) -> axum::response::Response {
    let basic = STANDARD.encode(format!("{client_id}:{secret}"));
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("authorization", format!("Basic {basic}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(serde_urlencoded::to_string(values).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn post_service_2lo_without_auth(
    router: &axum::Router,
    client_id: &str,
    resource: &str,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=client_credentials&client_id={client_id}\
                     &resource={resource}&scope=kb:read"
                )))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn exhaust_client_rate_limit(state: &AppState, client_id: &str) {
    let rate_limit = state.rate_limit.as_ref().expect("dev rate-limit store");
    rate_limit.delete(client_id).await.unwrap();
    assert!(
        rate_limit
            .try_consume(client_id, i64::MAX / 4, 1.0, 0.0, 1.0)
            .await
            .unwrap()
            .allowed,
        "test setup must consume the only token in a future-dated bucket"
    );
    assert!(
        agent_auth_http::ratelimit_gate::check(state, "", client_id)
            .await
            .is_some(),
        "the production client gate must observe the exhausted bucket"
    );
}

async fn assert_client_rate_limited(response: axum::response::Response) {
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|value| value > 0),
        "per-client throttling must advertise a positive Retry-After"
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"], "temporarily_unavailable");
}

const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

fn assert_access_token_es256(access_token: &str) {
    let header: serde_json::Value =
        serde_json::from_slice(&B64.decode(access_token.split('.').next().unwrap()).unwrap())
            .unwrap();
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["typ"], "at+jwt");
}

async fn service_jwks(router: &axum::Router) -> serde_json::Value {
    let response = router
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
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

fn verify_service_token(token: &str, jwks: &serde_json::Value) -> serde_json::Value {
    let header: serde_json::Value =
        serde_json::from_slice(&B64.decode(token.split('.').next().unwrap()).unwrap()).unwrap();
    let kid = header["kid"].as_str().expect("service token kid");
    let key = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["kty"] == "EC" && key["kid"] == kid)
        .expect("service token signing key");
    agent_auth_workload::verify_es256(
        token,
        key["x"].as_str().unwrap(),
        key["y"].as_str().unwrap(),
        Some(kid),
    )
    .expect("service token must be verifiably signed")
    .claims
}

// C2.3/C2.3a:预注册纯服务后端用标准 client auth 走 client_credentials,
// 签出 service 主体且 sub=client_id、跨 RS 恒定。
#[tokio::test]
async fn client_credentials_confidential_service_uses_registered_auth_and_service_subject() {
    let (router, state) = setup_service_2lo(agent_auth_http::SubjectType::Public).await;

    let rejected = post_service_2lo(&router, "svc-backend", "wrong-secret", RS).await;
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        rejected
            .headers()
            .get("www-authenticate")
            .and_then(|value| value.to_str().ok()),
        Some("Basic realm=\"token\"")
    );
    let rejected_body = axum::body::to_bytes(rejected.into_body(), usize::MAX)
        .await
        .unwrap();
    let rejected_body: serde_json::Value = serde_json::from_slice(&rejected_body).unwrap();
    assert_eq!(rejected_body["error"], "invalid_client");
    assert!(rejected_body.get("access_token").is_none());

    let ordinary = post_service_2lo(&router, "ordinary-web", "web-secret", RS).await;
    assert_eq!(ordinary.status(), StatusCode::BAD_REQUEST);
    let ordinary_body = axum::body::to_bytes(ordinary.into_body(), usize::MAX)
        .await
        .unwrap();
    let ordinary_body: serde_json::Value = serde_json::from_slice(&ordinary_body).unwrap();
    assert_eq!(ordinary_body["error"], "unauthorized_client");
    assert!(ordinary_body.get("access_token").is_none());

    let no_auth = post_service_2lo_without_auth(&router, "misconfigured-service", RS).await;
    assert_eq!(no_auth.status(), StatusCode::UNAUTHORIZED);
    let no_auth_body = axum::body::to_bytes(no_auth.into_body(), usize::MAX)
        .await
        .unwrap();
    let no_auth_body: serde_json::Value = serde_json::from_slice(&no_auth_body).unwrap();
    assert_eq!(no_auth_body["error"], "invalid_client");
    assert!(no_auth_body.get("access_token").is_none());

    let post_response = post_service_2lo_form(
        &router,
        &[
            ("grant_type", "client_credentials"),
            ("client_id", "svc-post"),
            ("client_secret", "post-secret"),
            ("resource", RS),
            ("scope", "kb:read"),
        ],
    )
    .await;
    assert_eq!(post_response.status(), StatusCode::OK);
    let post_body = axum::body::to_bytes(post_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let post_body: serde_json::Value = serde_json::from_slice(&post_body).unwrap();
    assert_eq!(
        verify_service_token(
            post_body["access_token"].as_str().unwrap(),
            &service_jwks(&router).await
        )["https://a-auth.com/c"]["sub_type"],
        "service"
    );

    let assertion = service_private_key_assertion("svc-jwt", "service-private-key-success");
    let private_key_response = post_service_2lo_form(
        &router,
        &[
            ("grant_type", "client_credentials"),
            ("client_id", "svc-jwt"),
            ("client_assertion_type", JWT_BEARER),
            ("client_assertion", assertion.as_str()),
            ("resource", RS),
            ("scope", "kb:read"),
        ],
    )
    .await;
    assert_eq!(private_key_response.status(), StatusCode::OK);
    let private_key_body = axum::body::to_bytes(private_key_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let private_key_body: serde_json::Value = serde_json::from_slice(&private_key_body).unwrap();
    assert_eq!(
        verify_service_token(
            private_key_body["access_token"].as_str().unwrap(),
            &service_jwks(&router).await
        )["https://a-auth.com/c"]["sub_type"],
        "service"
    );

    let malformed_assertion = post_service_2lo_form(
        &router,
        &[
            ("grant_type", "client_credentials"),
            ("client_id", "svc-jwt"),
            ("client_assertion_type", JWT_BEARER),
            ("client_assertion", "not-a-jwt"),
            ("resource", RS),
            ("scope", "kb:read"),
        ],
    )
    .await;
    assert_eq!(malformed_assertion.status(), StatusCode::BAD_REQUEST);
    let malformed_body = axum::body::to_bytes(malformed_assertion.into_body(), usize::MAX)
        .await
        .unwrap();
    let malformed_body: serde_json::Value = serde_json::from_slice(&malformed_body).unwrap();
    assert_eq!(malformed_body["error"], "invalid_request");
    assert!(malformed_body.get("access_token").is_none());

    let denied_before_mixed_credentials = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 100)
        .await
        .unwrap()
        .iter()
        .filter(|stored| {
            stored.event.action == "authentication.client"
                && stored.event.outcome == SecurityEventOutcome::Denied
                && stored.event.correlation.client_id.as_deref() == Some("svc-jwt")
        })
        .count();
    let mixed_credentials = post_service_2lo_form(
        &router,
        &[
            ("grant_type", "client_credentials"),
            ("client_id", "svc-jwt"),
            ("client_secret", "dummy-secret"),
            ("client_assertion_type", JWT_BEARER),
            ("client_assertion", "not-a-jwt"),
            ("resource", RS),
            ("scope", "kb:read"),
        ],
    )
    .await;
    assert_eq!(mixed_credentials.status(), StatusCode::BAD_REQUEST);
    let mixed_body = axum::body::to_bytes(mixed_credentials.into_body(), usize::MAX)
        .await
        .unwrap();
    let mixed_body: serde_json::Value = serde_json::from_slice(&mixed_body).unwrap();
    assert_eq!(mixed_body["error"], "invalid_request");
    assert!(mixed_body.get("access_token").is_none());
    let events_after_mixed_credentials = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 100)
        .await
        .unwrap();
    assert_eq!(
        events_after_mixed_credentials
            .iter()
            .filter(|stored| {
                stored.event.action == "authentication.client"
                    && stored.event.outcome == SecurityEventOutcome::Denied
                    && stored.event.correlation.client_id.as_deref() == Some("svc-jwt")
            })
            .count(),
        denied_before_mixed_credentials + 1,
        "mixed registered service credentials must remain attributed to service authentication"
    );
    assert!(!events_after_mixed_credentials.iter().any(|stored| {
        stored.event.action == "authentication.workload"
            && stored.event.outcome == SecurityEventOutcome::Denied
            && stored.event.correlation.client_id.as_deref() == Some("svc-jwt")
    }));

    let mixed_basic = post_service_2lo_form_with_basic(
        &router,
        "svc-jwt",
        "dummy-secret",
        &[
            ("grant_type", "client_credentials"),
            ("client_assertion_type", JWT_BEARER),
            ("client_assertion", "not-a-jwt"),
            ("resource", RS),
            ("scope", "kb:read"),
        ],
    )
    .await;
    assert_eq!(mixed_basic.status(), StatusCode::BAD_REQUEST);
    let mixed_basic_body = axum::body::to_bytes(mixed_basic.into_body(), usize::MAX)
        .await
        .unwrap();
    let mixed_basic_body: serde_json::Value = serde_json::from_slice(&mixed_basic_body).unwrap();
    assert_eq!(mixed_basic_body["error"], "invalid_request");
    assert!(mixed_basic_body.get("access_token").is_none());
    let events_after_mixed_basic = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 100)
        .await
        .unwrap();
    assert_eq!(
        events_after_mixed_basic
            .iter()
            .filter(|stored| {
                stored.event.action == "authentication.client"
                    && stored.event.outcome == SecurityEventOutcome::Denied
                    && stored.event.correlation.client_id.as_deref() == Some("svc-jwt")
            })
            .count(),
        denied_before_mixed_credentials + 2,
        "Basic-only service identity fallback must retain service audit attribution"
    );

    let workload_denials_before_malformed = events_after_mixed_basic
        .iter()
        .filter(|stored| {
            stored.event.action == "authentication.workload"
                && stored.event.outcome == SecurityEventOutcome::Denied
        })
        .count();
    let malformed_workload_assertion = post_service_2lo_form(
        &router,
        &[
            ("grant_type", "client_credentials"),
            ("client_id", "malformed-workload"),
            ("client_assertion_type", JWT_BEARER),
            ("client_assertion", "not-a-jwt"),
            ("resource", RS),
            ("scope", "kb:read"),
        ],
    )
    .await;
    assert_eq!(
        malformed_workload_assertion.status(),
        StatusCode::BAD_REQUEST
    );
    let malformed_workload_body =
        axum::body::to_bytes(malformed_workload_assertion.into_body(), usize::MAX)
            .await
            .unwrap();
    let malformed_workload_body: serde_json::Value =
        serde_json::from_slice(&malformed_workload_body).unwrap();
    assert_eq!(malformed_workload_body["error"], "invalid_client");
    assert!(malformed_workload_body.get("access_token").is_none());
    let events_after_malformed_workload = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 100)
        .await
        .unwrap();
    assert_eq!(
        events_after_malformed_workload
            .iter()
            .filter(|stored| {
                stored.event.action == "authentication.workload"
                    && stored.event.outcome == SecurityEventOutcome::Denied
            })
            .count(),
        workload_denials_before_malformed + 1,
        "known workload assertions must remain on the workload audit path"
    );
    assert!(!events_after_malformed_workload.iter().any(|stored| {
        stored.event.action == "authentication.client"
            && stored.event.correlation.client_id.as_deref() == Some("malformed-workload")
    }));

    for (client_id, secret) in [
        ("malformed-public", "public-secret"),
        ("malformed-workload", "workload-secret"),
    ] {
        let response = post_service_2lo(&router, client_id, secret, RS).await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{client_id} must not enter registered confidential service issuance"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"], "invalid_client");
        assert!(body.get("access_token").is_none());
    }

    for (resource, scope, expected_error) in [
        (
            "https://not-allowed.example.com",
            "kb:read",
            "invalid_target",
        ),
        (RS, "kb:write", "invalid_scope"),
    ] {
        let response =
            post_service_2lo_request(&router, "svc-backend", "svc-secret", resource, scope, None)
                .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"], expected_error);
        assert!(body.get("access_token").is_none());
    }

    let mut tokens = Vec::new();
    for resource in [RS, RS2] {
        let response = post_service_2lo(&router, "svc-backend", "svc-secret", resource).await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "registered confidential service must obtain a 2LO token for {resource}"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(body.get("refresh_token").is_none());
        assert!(body.get("id_token").is_none());
        tokens.push((
            resource,
            body["access_token"]
                .as_str()
                .expect("service access token")
                .to_string(),
        ));
    }

    let jwks = service_jwks(&router).await;

    let mut subjects = Vec::new();
    for (resource, token) in tokens {
        let claims = verify_service_token(&token, &jwks);
        assert_eq!(claims["aud"], serde_json::json!([resource]));
        assert_eq!(claims["sub"], "svc-backend");
        assert_eq!(claims["client_id"], "svc-backend");
        assert_eq!(claims["scope"], "kb:read");
        assert_eq!(claims["https://a-auth.com/c"]["sub_type"], "service");
        assert_eq!(
            claims["https://a-auth.com/c"]["auth_grant"],
            "client_credentials"
        );
        subjects.push(claims["sub"].clone());
    }
    assert_eq!(
        subjects[0], subjects[1],
        "service sub must be stable across RS"
    );

    let (pairwise_router, _) = setup_service_2lo(agent_auth_http::SubjectType::Pairwise).await;
    let pairwise_jwks = service_jwks(&pairwise_router).await;
    let mut pairwise_subjects = Vec::new();
    for resource in [RS, RS2] {
        let response =
            post_service_2lo(&pairwise_router, "svc-backend", "svc-secret", resource).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let claims = verify_service_token(body["access_token"].as_str().unwrap(), &pairwise_jwks);
        assert_eq!(claims["aud"], serde_json::json!([resource]));
        assert_eq!(claims["sub"], "svc-backend");
        assert_eq!(claims["https://a-auth.com/c"]["sub_type"], "service");
        pairwise_subjects.push(claims["sub"].clone());
    }
    assert_eq!(pairwise_subjects[0], pairwise_subjects[1]);
    assert_eq!(
        subjects[0], pairwise_subjects[0],
        "service sub must ignore user Public/Pairwise subject mode"
    );

    let mut service = state.clients.get("", "svc-backend").await.unwrap().unwrap();
    service.require_dpop = true;
    state.clients.put("", service.clone()).await.unwrap();
    let missing_dpop = post_service_2lo(&router, "svc-backend", "svc-secret", RS).await;
    assert_eq!(missing_dpop.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(missing_dpop.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"], "invalid_dpop_proof");

    let malformed_dpop = post_service_2lo_request(
        &router,
        "svc-backend",
        "svc-secret",
        RS,
        "kb:read",
        Some("not-a-dpop-jwt"),
    )
    .await;
    assert_eq!(malformed_dpop.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(malformed_dpop.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"], "invalid_dpop_proof");

    let (dpop_key, dpop_jwk) = te_dpop_keypair(71);
    let dpop_proof = te_make_proof(&dpop_key, &dpop_jwk, "service-dpop");
    let dpop_response = post_service_2lo_request(
        &router,
        "svc-backend",
        "svc-secret",
        RS,
        "kb:read",
        Some(&dpop_proof),
    )
    .await;
    assert_eq!(dpop_response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(dpop_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["token_type"], "DPoP");
    assert_eq!(
        te_token_cnf(body["access_token"].as_str().unwrap()).unwrap()["jkt"],
        te_jkt(&dpop_jwk)
    );

    service.tombstoned_at = Some(te_now());
    state.clients.put("", service).await.unwrap();
    let tombstoned = post_service_2lo_request(
        &router,
        "svc-backend",
        "svc-secret",
        RS,
        "kb:read",
        Some(&te_make_proof(&dpop_key, &dpop_jwk, "service-tombstoned")),
    )
    .await;
    assert_eq!(tombstoned.status(), StatusCode::UNAUTHORIZED);
    let body = axum::body::to_bytes(tombstoned.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"], "invalid_client");

    assert!(
        state
            .clients
            .get("", "svc-backend")
            .await
            .unwrap()
            .unwrap()
            .last_used_day
            .is_some(),
        "successful service issuance must advance client activity"
    );
    let events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 100)
        .await
        .unwrap();
    assert!(events.iter().any(|stored| {
        stored.event.action == "authentication.client"
            && stored.event.outcome == SecurityEventOutcome::Denied
            && stored.event.correlation.client_id.as_deref() == Some("svc-backend")
    }));
    assert!(events.iter().any(|stored| {
        stored.event.action == "authentication.client"
            && stored.event.outcome == SecurityEventOutcome::Denied
            && stored.event.correlation.client_id.as_deref() == Some("misconfigured-service")
    }));
    assert!(events.iter().any(|stored| {
        stored.event.action == "authentication.client"
            && stored.event.outcome == SecurityEventOutcome::Success
            && stored.event.correlation.client_id.as_deref() == Some("ordinary-web")
    }));
    assert!(events.iter().any(|stored| {
        stored.event.action == "grant.service_token.issue"
            && stored.event.outcome == SecurityEventOutcome::Denied
            && stored.event.correlation.client_id.as_deref() == Some("ordinary-web")
    }));
    assert!(events.iter().any(|stored| {
        stored.event.action == "authentication.client"
            && stored.event.outcome == SecurityEventOutcome::Success
            && stored.event.correlation.client_id.as_deref() == Some("svc-backend")
    }));
    assert!(events.iter().any(|stored| {
        stored.event.action == "grant.service_token.issue"
            && stored.event.outcome == SecurityEventOutcome::Success
            && stored.event.correlation.client_id.as_deref() == Some("svc-backend")
    }));
    assert!(events.iter().any(|stored| {
        stored.event.action == "authentication.client"
            && stored.event.outcome == SecurityEventOutcome::Denied
            && stored.event.correlation.client_id.as_deref() == Some("svc-jwt")
    }));
    assert!(!events.iter().any(|stored| {
        stored.event.action == "authentication.workload"
            && stored.event.outcome == SecurityEventOutcome::Denied
            && stored.event.correlation.client_id.as_deref() == Some("svc-jwt")
    }));
}

#[tokio::test]
async fn client_credentials_workload_oidc_iss_equal_sub_is_not_misrouted_to_service() {
    let real_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = serde_json::json!({
        "iss": PLATFORM_ISS,
        "sub": PLATFORM_ISS,
        "aud": format!("https://{HOST}"),
        "iat": real_now,
        "exp": real_now + 300,
    });
    let (jwt, jwk) = make_platform_jwt("equal-iss-sub", claims);
    let (router, state) = setup_2lo_with_state("equal-iss-sub", jwk).await;
    state
        .workload_trust
        .put(
            "",
            "b1".into(),
            TrustBinding {
                tenant_id: "default".into(),
                mechanism: TrustMechanism::Oidc {
                    platform_issuer: PLATFORM_ISS.into(),
                    jwks_uri: JWKS_URI.into(),
                    subject_pattern: PLATFORM_ISS.into(),
                },
                mapped_client_id: "wl-gha".into(),
            },
        )
        .await
        .unwrap();

    let form = format!(
        "grant_type=client_credentials&client_assertion_type={JWT_BEARER}\
         &client_assertion={jwt}&resource={RS}"
    );
    let (status, body) = post_2lo(&router, form).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "iss == sub workload assertion must still reach trust-binding verification: {body}"
    );
    let payload = body["access_token"]
        .as_str()
        .unwrap()
        .split('.')
        .nth(1)
        .unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&B64.decode(payload).unwrap()).unwrap();
    assert_eq!(claims["sub"], "wl-gha");
    assert_eq!(claims["https://a-auth.com/c"]["sub_type"], "agent");
}

// C5.1:有效平台 OIDC JWT(aud=本AS/iss+sub 匹配)→ 签出 2LO token(sub=client_id、sub_type=agent、无 refresh)。
#[tokio::test]
async fn client_credentials_workload_oidc_jwt_succeeds() {
    let now = 100_000i64; // 固定;下方 claims 用真实 now 以过 exp。实际用系统 now。
    let _ = now;
    let real_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = serde_json::json!({
        "iss": PLATFORM_ISS,
        "sub": "repo:acme/agent:ref:main",
        "aud": format!("https://{HOST}"),
        "iat": real_now,
        "exp": real_now + 300,
    });
    let (jwt, jwk) = make_platform_jwt("k1", claims);
    let (router, state) = setup_2lo_with_state("k1", jwk).await;
    assert_eq!(
        state
            .clients
            .get("", "wl-gha")
            .await
            .unwrap()
            .unwrap()
            .last_used_day,
        None
    );

    let rejected_form = format!(
        "grant_type=client_credentials&client_assertion_type={JWT_BEARER}&client_assertion={jwt}&resource=https://not-allowed.example.com"
    );
    let (rejected_status, rejected_body) = post_2lo(&router, rejected_form).await;
    assert_eq!(
        rejected_status,
        StatusCode::BAD_REQUEST,
        "不在 client policy 的 resource 必须拒绝: {rejected_body}"
    );
    assert_eq!(
        state
            .clients
            .get("", "wl-gha")
            .await
            .unwrap()
            .unwrap()
            .last_used_day,
        None,
        "client_credentials 签发失败不得推进 client 活动"
    );

    let form = format!(
        "grant_type=client_credentials&client_id=wl-gha&client_assertion_type={JWT_BEARER}&client_assertion={jwt}&resource={RS}"
    );
    let (st, body) = post_2lo(&router, form).await;
    assert_eq!(
        st,
        StatusCode::OK,
        "有效 workload OIDC JWT 应签出 2LO: {body}"
    );
    let at = body["access_token"].as_str().expect("含 access_token");
    assert!(
        body.get("refresh_token").is_none(),
        "2LO 不发 refresh(RFC 6749 §4.4.3)"
    );
    // 解 access token claims:sub=client_id、aud=RS、sub_type=agent、auth_grant=client_credentials。
    let payload = at.split('.').nth(1).unwrap();
    let c: serde_json::Value = serde_json::from_slice(&B64.decode(payload).unwrap()).unwrap();
    assert_eq!(c["sub"], "wl-gha", "2LO sub=client_id");
    assert_eq!(c["aud"], serde_json::json!([RS]));
    assert_eq!(
        c["scope"], "kb:read",
        "省略 scope 时只能签出 client 注册的 allowed_scopes"
    );
    // 私有 claim 收在命名空间对象(NAMESPACE = "https://a-auth.com/c",见 token::claims)。
    let ns_obj = &c["https://a-auth.com/c"];
    assert_eq!(
        ns_obj["sub_type"], "agent",
        "workload 2LO sub_type=agent(非 service/user)"
    );
    assert_eq!(ns_obj["auth_grant"], "client_credentials");
    // C2.10:2LO token 省略 auth_time(无用户登录)/grant_id(2LO 不挂 Grant,C7.5)/act(无委托链)。
    assert!(
        c.get("auth_time").is_none(),
        "C2.10:2LO 无 auth_time(无用户登录)"
    );
    assert!(
        c.get("grant_id").is_none(),
        "C2.10:2LO 无 grant_id(不挂 Grant)"
    );
    assert!(c.get("act").is_none(), "C2.10:2LO 无 act(非委托)");
    assert!(
        ns_obj.get("actor_types").is_none(),
        "C2.10:2LO 命名空间无 actor_types(非委托)"
    );
    assert!(
        state
            .clients
            .get("", "wl-gha")
            .await
            .unwrap()
            .unwrap()
            .last_used_day
            .is_some(),
        "成功 client_credentials 签发必须推进 client 活动"
    );
    let events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 100)
        .await
        .unwrap();
    assert!(events.iter().any(|stored| {
        let event = serde_json::to_value(&stored.event).unwrap();
        stored.event.category == SecurityEventCategory::Authentication
            && stored.event.action == "authentication.workload"
            && stored.event.outcome == SecurityEventOutcome::Success
            && event["actor"]["kind"] == "client"
            && event["actor"]["id"] == "wl-gha"
            && event["subject"]["id"] == "wl-gha"
    }));
}

#[tokio::test]
async fn workload_rate_limit_uses_authenticated_client() {
    let real_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = serde_json::json!({
        "iss": PLATFORM_ISS,
        "sub": "repo:acme/agent:ref:main",
        "aud": format!("https://{HOST}"),
        "iat": real_now,
        "exp": real_now + 300,
    });
    let (jwt, jwk) = make_platform_jwt("rate-limit-workload", claims);
    let (router, state) = setup_2lo_with_state("rate-limit-workload", jwk).await;
    let form = format!(
        "grant_type=client_credentials&client_assertion_type={JWT_BEARER}\
         &client_assertion={jwt}&resource={RS}"
    );

    exhaust_client_rate_limit(&state, "wl-gha").await;
    let limited = router
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
    assert_client_rate_limited(limited).await;

    state
        .rate_limit
        .as_ref()
        .unwrap()
        .delete("wl-gha")
        .await
        .unwrap();
    assert_eq!(
        post_2lo(&router, form).await.0,
        StatusCode::OK,
        "a throttled workload assertion must remain retryable"
    );
}

#[tokio::test]
async fn client_credentials_kms_transient_returns_retry_after_without_token() {
    use agent_auth_http::state::SignerImpl;

    let real_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = serde_json::json!({
        "iss": PLATFORM_ISS,
        "sub": "repo:acme/agent:ref:main",
        "aud": format!("https://{HOST}"),
        "iat": real_now,
        "exp": real_now + 300,
    });
    let (jwt, jwk) = make_platform_jwt("kms-transient-2lo", claims);
    let (router, state) = setup_2lo_with_state("kms-transient-2lo", jwk).await;
    let SignerImpl::Memory(signer) = state.signer.as_ref() else {
        panic!("dev state must use MemorySigner");
    };
    signer.fail_next_es256(true);

    let response = post_2lo_response(
        &router,
        format!(
            "grant_type=client_credentials&client_assertion_type={JWT_BEARER}\
             &client_assertion={jwt}&resource={RS}"
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()["retry-after"], "1");
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["error"], "temporarily_unavailable");
    for field in ["access_token", "refresh_token", "id_token", "token_type"] {
        assert!(
            body.get(field).is_none(),
            "transient signing failure must not return {field}: {body}"
        );
    }
}

// C8.7b:workload client_credentials 也走与其它 /token grant 相同的 DPoP opt-in seam。
#[tokio::test]
async fn workload_client_credentials_dpop_and_bearer_binding() {
    let real_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let dpop_claims = serde_json::json!({
        "iss": PLATFORM_ISS,
        "sub": "repo:acme/agent:ref:dpop",
        "aud": format!("https://{HOST}"),
        "iat": real_now,
        "exp": real_now + 300,
    });
    let bearer_claims = serde_json::json!({
        "iss": PLATFORM_ISS,
        "sub": "repo:acme/agent:ref:bearer",
        "aud": format!("https://{HOST}"),
        "iat": real_now,
        "exp": real_now + 300,
    });
    let (dpop_assertion, jwk) = make_platform_jwt("k-dpop", dpop_claims);
    let (bearer_assertion, _) = make_platform_jwt("k-dpop", bearer_claims);

    let mut state = AppState::dev(HOST);
    state.phase = Phase::P3;
    state
        .seed_workload_client_with_policy("wl-gha", vec![RS.to_string()], vec!["kb:read".into()])
        .await;
    let _ = state
        .workload_trust
        .put(
            "",
            "b-dpop".into(),
            TrustBinding {
                tenant_id: "default".into(),
                mechanism: TrustMechanism::Oidc {
                    platform_issuer: PLATFORM_ISS.into(),
                    jwks_uri: JWKS_URI.into(),
                    subject_pattern: "repo:acme/agent:*".into(),
                },
                mapped_client_id: "wl-gha".into(),
            },
        )
        .await;
    let fetcher = agent_auth_http::adapters::memory::MemoryJwksFetcher::default();
    fetcher.set(JWKS_URI, vec![jwk]).await;
    state.jwks_fetcher = Arc::new(JwksFetcherImpl::Memory(fetcher));
    let (router, _) = build_router(state);

    let (dpop_key, dpop_jwk) = te_dpop_keypair(40);
    let proof = te_make_proof(&dpop_key, &dpop_jwk, "workload-dpop");
    let dpop_form = format!(
        "grant_type=client_credentials&client_assertion_type={JWT_BEARER}\
         &client_assertion={dpop_assertion}&resource={RS}"
    );
    let (dpop_status, dpop_body) = post_token_dpop(&router, &dpop_form, Some(&proof)).await;
    assert_eq!(
        dpop_status,
        StatusCode::OK,
        "workload DPoP issuance should succeed: {dpop_body}"
    );
    assert_eq!(dpop_body["token_type"], "DPoP");
    assert_access_token_es256(dpop_body["access_token"].as_str().unwrap());
    assert_eq!(
        te_token_cnf(dpop_body["access_token"].as_str().unwrap()).unwrap()["jkt"],
        te_jkt(&dpop_jwk)
    );

    let bearer_form = format!(
        "grant_type=client_credentials&client_assertion_type={JWT_BEARER}\
         &client_assertion={bearer_assertion}&resource={RS}"
    );
    let (bearer_status, bearer_body) = post_token_dpop(&router, &bearer_form, None).await;
    assert_eq!(
        bearer_status,
        StatusCode::OK,
        "workload bearer issuance should remain available: {bearer_body}"
    );
    assert_eq!(bearer_body["token_type"], "Bearer");
    assert_access_token_es256(bearer_body["access_token"].as_str().unwrap());
    assert!(
        te_token_cnf(bearer_body["access_token"].as_str().unwrap()).is_none(),
        "a proof-free workload token must not receive an invented cnf"
    );
}

// C2.3a(§2.8):2LO sub = client_id、跨 RS 恒定，且不受 public/pairwise 用户主体形态影响。
#[tokio::test]
async fn client_credentials_sub_is_client_id_cross_rs_no_pairwise() {
    for (mode, subject_type, kid) in [
        (
            "public",
            agent_auth_http::SubjectType::Public,
            "c2-3a-public",
        ),
        (
            "pairwise",
            agent_auth_http::SubjectType::Pairwise,
            "c2-3a-pairwise",
        ),
    ] {
        let real_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let claims = serde_json::json!({
            "iss": PLATFORM_ISS, "sub": "repo:acme/agent:ref:main",
            "aud": format!("https://{HOST}"), "iat": real_now, "exp": real_now + 300,
        });
        let (jwt, jwk) = make_platform_jwt(kid, claims);

        let mut state = AppState::dev(HOST);
        state.phase = Phase::P2;
        state.subject_type = subject_type;
        state
            .seed_workload_client_with_policy(
                "wl-gha",
                vec![RS.to_string(), RS2.to_string()],
                vec!["kb:read".into()],
            )
            .await;
        let _ = state
            .workload_trust
            .put(
                "",
                "b1".into(),
                TrustBinding {
                    tenant_id: "default".into(),
                    mechanism: TrustMechanism::Oidc {
                        platform_issuer: PLATFORM_ISS.into(),
                        jwks_uri: JWKS_URI.into(),
                        subject_pattern: "repo:acme/agent:*".into(),
                    },
                    mapped_client_id: "wl-gha".into(),
                },
            )
            .await;
        let fetcher = agent_auth_http::adapters::memory::MemoryJwksFetcher::default();
        fetcher.set(JWKS_URI, vec![jwk]).await;
        state.jwks_fetcher = Arc::new(JwksFetcherImpl::Memory(fetcher));
        let (router, _) = build_router(state);

        let claims_of = |body: &serde_json::Value| -> serde_json::Value {
            let at = body["access_token"].as_str().unwrap();
            serde_json::from_slice(&B64.decode(at.split('.').nth(1).unwrap()).unwrap()).unwrap()
        };

        let form1 = format!(
            "grant_type=client_credentials&client_assertion_type={JWT_BEARER}&client_assertion={jwt}&resource={RS}"
        );
        let (st1, b1) = post_2lo(&router, form1).await;
        assert_eq!(st1, StatusCode::OK, "{mode}:为 RS 签 2LO: {b1}");
        let form2 = format!(
            "grant_type=client_credentials&client_assertion_type={JWT_BEARER}&client_assertion={jwt}&resource={RS2}"
        );
        let (st2, b2) = post_2lo(&router, form2).await;
        assert_eq!(st2, StatusCode::OK, "{mode}:为 RS2 签 2LO: {b2}");

        let (claims_rs, claims_rs2) = (claims_of(&b1), claims_of(&b2));
        assert_eq!(
            claims_rs["aud"],
            serde_json::json!([RS]),
            "{mode}:第一枚 token 必须绑定 RS"
        );
        assert_eq!(
            claims_rs2["aud"],
            serde_json::json!([RS2]),
            "{mode}:第二枚 token 必须绑定 RS2"
        );
        for claims in [&claims_rs, &claims_rs2] {
            assert_eq!(claims["sub"], "wl-gha", "{mode}:2LO sub = client_id");
            assert_eq!(
                claims["client_id"], "wl-gha",
                "{mode}:client_id 必须与 workload 身份一致"
            );
            assert_eq!(
                claims["https://a-auth.com/c"]["sub_type"], "agent",
                "{mode}:workload client_credentials 必须保持 agent 主体类型"
            );
        }
        assert_eq!(
            claims_rs["sub"], claims_rs2["sub"],
            "{mode}:2LO sub 必须跨 RS 恒定且不分 sector"
        );
    }
}

// C5.1:aud 非本 AS 的平台 token → 拒(绝不放宽 aud)。
#[tokio::test]
async fn client_credentials_wrong_aud_rejected() {
    let real_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = serde_json::json!({
        "iss": PLATFORM_ISS, "sub": "repo:acme/agent:ref:main",
        "aud": "https://sts.amazonaws.com", // 非本 AS
        "iat": real_now, "exp": real_now + 300,
    });
    let (jwt, jwk) = make_platform_jwt("k1", claims);
    let (router, state) = setup_2lo_with_state("k1", jwk).await;
    let form = format!("grant_type=client_credentials&client_assertion_type={JWT_BEARER}&client_assertion={jwt}&resource={RS}");
    let (st, body) = post_2lo(&router, form).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "aud 非本 AS 应拒");
    assert_eq!(body["error"], "invalid_client");
    assert_eq!(
        body["error_description"],
        "platform token audience must equal this authorization server; configure the platform audience or use SigV4",
        "C5.1 拒绝必须明确说明 audience 不能放宽"
    );
    let events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 100)
        .await
        .unwrap();
    let denied = events
        .iter()
        .find(|stored| {
            stored.event.action == "authentication.workload"
                && stored.event.outcome == SecurityEventOutcome::Denied
        })
        .expect("rejected workload authentication must remain auditable");
    let event = serde_json::to_value(&denied.event).unwrap();
    assert_eq!(denied.event.category, SecurityEventCategory::Authentication);
    assert_eq!(event["actor"]["kind"], "system");
    assert_eq!(
        denied.event.subject,
        agent_auth_http::security_event::SecuritySubject::unknown("anonymous")
    );
    assert!(denied.event.correlation.client_id.is_none());
}

// 无匹配信任绑定(iss 未登记)→ 拒。
#[tokio::test]
async fn client_credentials_unknown_iss_rejected() {
    let real_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = serde_json::json!({
        "iss": "https://evil.example.com", "sub": "repo:acme/agent:ref:main",
        "aud": format!("https://{HOST}"), "iat": real_now, "exp": real_now + 300,
    });
    let (jwt, jwk) = make_platform_jwt("k1", claims);
    let router = setup_2lo("k1", jwk).await;
    let form = format!("grant_type=client_credentials&client_assertion_type={JWT_BEARER}&client_assertion={jwt}&resource={RS}");
    let (st, _) = post_2lo(&router, form).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "未登记 iss 应拒(无信任锚)");
}

// sub 不匹配 subject_pattern → 拒。
#[tokio::test]
async fn client_credentials_sub_mismatch_rejected() {
    let real_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = serde_json::json!({
        "iss": PLATFORM_ISS, "sub": "repo:OTHER/x:ref:main", // 不匹配 repo:acme/agent:*
        "aud": format!("https://{HOST}"), "iat": real_now, "exp": real_now + 300,
    });
    let (jwt, jwk) = make_platform_jwt("k1", claims);
    let router = setup_2lo("k1", jwk).await;
    let form = format!("grant_type=client_credentials&client_assertion_type={JWT_BEARER}&client_assertion={jwt}&resource={RS}");
    let (st, _) = post_2lo(&router, form).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "sub 不匹配 pattern 应拒");
}

// resource 不在 allowed_resources → invalid_target。
#[tokio::test]
async fn client_credentials_resource_not_allowed_rejected() {
    let real_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = serde_json::json!({
        "iss": PLATFORM_ISS, "sub": "repo:acme/agent:ref:main",
        "aud": format!("https://{HOST}"), "iat": real_now, "exp": real_now + 300,
    });
    let (jwt, jwk) = make_platform_jwt("k1", claims);
    let (router, state) = setup_2lo_with_state("k1", jwk).await;
    let form = format!("grant_type=client_credentials&client_assertion_type={JWT_BEARER}&client_assertion={jwt}&resource=https://other.rs.example.com");
    let (st, body) = post_2lo(&router, form).await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "resource 不在 allowed_resources 应拒: {body}"
    );
    assert_eq!(body["error"], "invalid_target");
    let events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 100)
        .await
        .unwrap();
    let denied = events
        .iter()
        .find(|stored| {
            stored.event.action == "grant.workload_token.issue"
                && stored.event.outcome == SecurityEventOutcome::Denied
        })
        .expect("post-auth workload token denial must remain attributable");
    let event = serde_json::to_value(&denied.event).unwrap();
    assert_eq!(denied.event.category, SecurityEventCategory::Grant);
    assert_eq!(event["actor"]["kind"], "client");
    assert_eq!(event["actor"]["id"], "wl-gha");
    assert_eq!(event["subject"]["id"], "wl-gha");
    assert_eq!(
        denied.event.correlation.client_id.as_deref(),
        Some("wl-gha")
    );
    assert!(!events.iter().any(|stored| {
        stored.event.action == "authentication.workload"
            && stored.event.outcome == SecurityEventOutcome::Denied
    }));
}

// P1 阶段 client_credentials 不受理(grant 阶段门控)。
#[tokio::test]
async fn client_credentials_rejected_at_p1() {
    let state = AppState::dev(HOST); // 默认 phase=P1
    let (router, _) = build_router(state);
    let form = format!("grant_type=client_credentials&client_assertion_type={JWT_BEARER}&client_assertion=x.y.z&resource={RS}");
    let (st, _) = post_2lo(&router, form).await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "P1 阶段 client_credentials 应 unsupported_grant_type"
    );
}

// 评审 codex HIGH:scope 超出 allowed_scopes → 拒(fail-closed;空 allowed_scopes 不再"不限")。
#[tokio::test]
async fn client_credentials_scope_beyond_allowed_rejected() {
    let real_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = serde_json::json!({
        "iss": PLATFORM_ISS, "sub": "repo:acme/agent:ref:main",
        "aud": format!("https://{HOST}"), "iat": real_now, "exp": real_now + 300,
    });
    let (jwt, jwk) = make_platform_jwt("k1", claims);
    // setup_2lo 里 allowed_scopes=["kb:read"];请求 kb:write(不在) → invalid_scope。
    let router = setup_2lo("k1", jwk).await;
    let form = format!("grant_type=client_credentials&client_assertion_type={JWT_BEARER}&client_assertion={jwt}&resource={RS}&scope=kb:write");
    let (st, body) = post_2lo(&router, form).await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "scope 超出 allowed_scopes 应拒: {body}"
    );
    assert_eq!(body["error"], "invalid_scope");
}

// C8.10:JWT 体积硬上限——2LO 用**超大白名单 scope**(allowed_scopes 全带上,请求全要),使签出
// token > 7KB 硬上限 → 拒签(server_error),不静默发超大 token,并指导客户端收窄授权或走 introspection。
#[tokio::test]
async fn client_credentials_oversized_token_rejected() {
    let real_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = serde_json::json!({
        "iss": PLATFORM_ISS, "sub": "repo:acme/agent:ref:main",
        "aud": format!("https://{HOST}"), "iat": real_now, "exp": real_now + 300,
    });
    let (jwt, jwk) = make_platform_jwt("k1", claims);
    // 1600 段 scope 全进 allowed_scopes(scope 串 ~10KB → base64 payload 远超 7KB),请求全要 → 拒签。
    let scopes: Vec<String> = (0..1600).map(|i| format!("scope{i}")).collect();
    let router = setup_2lo_with_scopes("k1", jwk, scopes.clone()).await;
    let big_scope = scopes.join("+"); // + = url-encoded 空格
    let form = format!("grant_type=client_credentials&client_assertion_type={JWT_BEARER}&client_assertion={jwt}&resource={RS}&scope={big_scope}");
    let (st, body) = post_2lo(&router, form).await;
    assert_eq!(
        st,
        StatusCode::INTERNAL_SERVER_ERROR,
        "超硬上限 token 应拒签(server_error),不静默发超大: {body}"
    );
    assert_eq!(body["error"], "server_error");
    assert!(
        body.get("access_token").is_none() && body.get("refresh_token").is_none(),
        "超硬上限响应不得同时返回任何 token: {body}"
    );
    let description = body["error_description"]
        .as_str()
        .expect("超硬上限响应必须带客户端可执行的收窄指导");
    assert_eq!(
        description,
        "access token exceeds the 7 KiB size limit; narrow scope or authorization_details; use token introspection only when the Grant-backed introspection profile is enabled",
        "超硬上限响应必须逐字给出 scope/RAR 收窄与 introspection 指导"
    );
}

// 评审 codex HIGH:平台 token 缺 iat → 拒(最长寿命上限不可被"省略 iat"绕过)。
#[tokio::test]
async fn client_credentials_missing_iat_rejected() {
    let real_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // 无 iat,exp 很远 → 若不强制 iat,寿命上限被绕过。
    let claims = serde_json::json!({
        "iss": PLATFORM_ISS, "sub": "repo:acme/agent:ref:main",
        "aud": format!("https://{HOST}"), "exp": real_now + 100_000,
    });
    let (jwt, jwk) = make_platform_jwt("k1", claims);
    let router = setup_2lo("k1", jwk).await;
    let form = format!("grant_type=client_credentials&client_assertion_type={JWT_BEARER}&client_assertion={jwt}&resource={RS}");
    let (st, _) = post_2lo(&router, form).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "缺 iat 应拒(无从界定寿命)");
}

// ---- spec 011 token-exchange(RFC 8693 委托,P2)----

use agent_auth_http::ports::{
    CodeRecord, CodeStore, JtiStore, PolicyArtifactStore, RefreshFamilyRecord, RefreshStore,
    StoreError, UsersStore,
};
use agent_auth_http::state::{JtiStoreImpl, PolicyArtifactStoreImpl};

const TE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const TT_ACCESS: &str = "urn:ietf:params:oauth:token-type:access_token";
const TT_ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";
const RS2: &str = "https://mcp.rs2.example.com";

// 装配 P2 AppState:workload actor(wl-actor,OIDC 可认证)+ 一条 Grant 前身 family(actor_allowlist=[wl-actor],
// resources=[RS2],user=alice)+ jti 映射(jti→{alice, family})。返回 (router, subject_jti, actor_jwt)。
async fn setup_token_exchange() -> (
    axum::Router,
    String,
    String,
    Arc<agent_auth_http::state::RefreshStoreImpl>,
    Arc<agent_auth_http::state::GrantStoreImpl>,
    String,
) {
    setup_token_exchange_with(agent_auth_http::SubjectType::Public).await
}

/// setup_token_exchange 的形态可配版(C7.8 pairwise 断言用):subject_type=Pairwise 时 code flow 签的
/// subject_token sub 与委托 token sub 均按 sector pairwise 派生(非 user_id)。默认 Public 见无参版。
async fn setup_token_exchange_with(
    subject_type: agent_auth_http::SubjectType,
) -> (
    axum::Router,
    String,
    String,
    Arc<agent_auth_http::state::RefreshStoreImpl>,
    Arc<agent_auth_http::state::GrantStoreImpl>,
    String,
) {
    let (router, subject, actor, refresh, grants, id_token, _jti_store) =
        setup_token_exchange_with_jti(subject_type).await;
    (router, subject, actor, refresh, grants, id_token)
}

async fn setup_token_exchange_with_jti(
    subject_type: agent_auth_http::SubjectType,
) -> (
    axum::Router,
    String,
    String,
    Arc<agent_auth_http::state::RefreshStoreImpl>,
    Arc<agent_auth_http::state::GrantStoreImpl>,
    String,
    agent_auth_http::adapters::memory::MemoryJtiStore,
) {
    let (
        router,
        subject,
        actor,
        refresh,
        grants,
        id_token,
        jti_store,
        _clients,
        _policy_artifacts,
        _rate_limit,
        _state,
    ) = setup_token_exchange_with_jti_phase(subject_type, Phase::P2, false).await;
    (router, subject, actor, refresh, grants, id_token, jti_store)
}

async fn setup_token_exchange_p3() -> (
    axum::Router,
    String,
    String,
    Arc<agent_auth_http::state::RefreshStoreImpl>,
    Arc<agent_auth_http::state::GrantStoreImpl>,
    String,
) {
    let (
        router,
        subject,
        actor,
        refresh,
        grants,
        id_token,
        _jti_store,
        _clients,
        _policy_artifacts,
        _rate_limit,
        _state,
    ) = setup_token_exchange_with_jti_phase(agent_auth_http::SubjectType::Public, Phase::P3, false)
        .await;
    (router, subject, actor, refresh, grants, id_token)
}

async fn setup_token_exchange_activity() -> (
    axum::Router,
    String,
    String,
    Arc<agent_auth_http::state::ClientStoreImpl>,
    Arc<PolicyArtifactStoreImpl>,
) {
    let (
        router,
        subject,
        actor,
        _refresh,
        _grants,
        _id_token,
        _jti_store,
        clients,
        policy_artifacts,
        _rate_limit,
        _state,
    ) = setup_token_exchange_with_jti_phase(agent_auth_http::SubjectType::Public, Phase::P2, true)
        .await;
    (router, subject, actor, clients, policy_artifacts)
}

async fn setup_token_exchange_with_jti_phase(
    subject_type: agent_auth_http::SubjectType,
    phase: Phase,
    authz_enabled: bool,
) -> (
    axum::Router,
    String,
    String,
    Arc<agent_auth_http::state::RefreshStoreImpl>,
    Arc<agent_auth_http::state::GrantStoreImpl>,
    String,
    agent_auth_http::adapters::memory::MemoryJtiStore,
    Arc<agent_auth_http::state::ClientStoreImpl>,
    Arc<PolicyArtifactStoreImpl>,
    Arc<agent_auth_http::state::RateLimitStoreImpl>,
    AppState,
) {
    setup_token_exchange_with_jti_phase_and_region(subject_type, phase, authz_enabled, None).await
}

async fn setup_token_exchange_with_jti_phase_and_region(
    subject_type: agent_auth_http::SubjectType,
    phase: Phase,
    authz_enabled: bool,
    region: Option<agent_auth_http::region::RegionRuntime>,
) -> (
    axum::Router,
    String,
    String,
    Arc<agent_auth_http::state::RefreshStoreImpl>,
    Arc<agent_auth_http::state::GrantStoreImpl>,
    String,
    agent_auth_http::adapters::memory::MemoryJtiStore,
    Arc<agent_auth_http::state::ClientStoreImpl>,
    Arc<PolicyArtifactStoreImpl>,
    Arc<agent_auth_http::state::RateLimitStoreImpl>,
    AppState,
) {
    let mut state = AppState::dev(HOST);
    state.phase = phase;
    state.subject_type = subject_type;
    state.authz_enabled = authz_enabled;
    if let Some(region) = region {
        state.region = region;
        assert_eq!(
            state
                .region
                .admit(agent_auth_http::current_unix_secs())
                .await
                .unwrap(),
            agent_auth_http::region::RegionAdmission::Active
        );
    }
    if authz_enabled {
        assert_eq!(
            agent_auth_http::recompute::publish_policy_from_env(
                &state,
                "",
                r#"permit(principal, action, resource);"#,
            )
            .await
            .unwrap(),
            1,
            "the activity fixture must exercise the authz-enabled current-policy hot path"
        );
    }
    // 1. workload actor client + OIDC 信任绑定 + JWKS。
    state
        .seed_workload_client_with_policy("wl-actor", vec![RS2.to_string()], vec![])
        .await;
    state
        .seed_workload_client_with_policy("wl-other", vec![RS2.to_string()], vec![])
        .await;
    let _ = state
        .workload_trust
        .put(
            "",
            "b-te".into(),
            TrustBinding {
                tenant_id: "default".into(),
                mechanism: TrustMechanism::Oidc {
                    platform_issuer: PLATFORM_ISS.into(),
                    jwks_uri: JWKS_URI.into(),
                    subject_pattern: "repo:acme/actor:*".into(),
                },
                mapped_client_id: "wl-actor".into(),
            },
        )
        .await;
    let _ = state
        .workload_trust
        .put(
            "",
            "b-te-other".into(),
            TrustBinding {
                tenant_id: "default".into(),
                mechanism: TrustMechanism::Oidc {
                    platform_issuer: PLATFORM_ISS.into(),
                    jwks_uri: JWKS_URI.into(),
                    subject_pattern: "repo:acme/other:*".into(),
                },
                mapped_client_id: "wl-other".into(),
            },
        )
        .await;
    // actor 的平台 OIDC JWT。
    let real_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let (actor_jwt, jwk) = make_platform_jwt(
        "ka",
        serde_json::json!({
            "iss": PLATFORM_ISS, "sub": "repo:acme/actor:ref:main",
            "aud": format!("https://{HOST}"), "iat": real_now, "exp": real_now + 300,
        }),
    );
    let (_other_actor_jwt, other_jwk) = make_platform_jwt(
        "kb",
        serde_json::json!({
            "iss": PLATFORM_ISS, "sub": "repo:acme/other:ref:main",
            "aud": format!("https://{HOST}"), "iat": real_now, "exp": real_now + 300,
        }),
    );
    let fetcher = agent_auth_http::adapters::memory::MemoryJwksFetcher::default();
    fetcher.set(JWKS_URI, vec![jwk, other_jwk]).await;
    state.jwks_fetcher = Arc::new(JwksFetcherImpl::Memory(fetcher));

    // 2. Grant 前身 family:actor_allowlist=[wl-actor],max_act_chain=1,resources=[RS2],user=alice。
    let _ = state
        .refresh
        .create(
            "",
            RefreshFamilyRecord {
                family_id: "fam-te".into(),
                current_version: 0,
                revoked: false,
                client_id: "app-3lo".into(), // 3LO OAuth 客户端(≠actor,故必须靠 allowlist 显式授权)
                cimd_snapshot: None,
                user_id: "alice".into(),
                credential_epoch: 0,
                resources: vec![RS2.to_string()],
                scope: vec!["kb:read".into()],
                actor_allowlist: vec!["wl-actor".into()],
                max_act_chain: 1,
                dpop_jkt: None,
                pkce_code_challenge: None,
                auth_time: None,
                acr: None,
                password_credential_version: None,
            },
        )
        .await;

    // 2b. **Grant 正式化对象**(spec 011 §5.1;P2 权威源):与 fam-te 同 id,授 RS2/kb:read,委托约束
    //     actor_allowlist=[wl-actor]、max_act_chain=1。token-exchange 优先按 Grant 校验(见 jti.grant_id)。
    let selected_resource = agent_auth_grant::ResourceGrant {
        resource: RS2.to_string(),
        scopes: vec!["kb:read".into(), "kb:metadata".into()],
        authorization_details: vec![],
    };
    let _ = agent_auth_http::ports::GrantStore::put(
        state.grants.as_ref(),
        "",
        agent_auth_grant::Grant {
            grant_id: "fam-te".into(),
            user_id: "alice".into(),
            client_id: "app-3lo".into(),
            per_resource: vec![selected_resource.clone()],
            effective_per_resource: if authz_enabled {
                vec![selected_resource]
            } else {
                vec![]
            },
            effective_pv: u64::from(authz_enabled),
            allowed_ip_cidrs: vec![],
            allowed_vpce: vec![],
            credential_epoch: 0,
            revision: 0,
            constraints: agent_auth_grant::GrantConstraints {
                max_act_chain: 1,
                actor_allowlist: vec!["wl-actor".into()],
                expires_at: 4_000_000_000,
            },
            status: agent_auth_grant::GrantStatus::Active,
        },
    )
    .await;

    // 3. Put a short-lived code carrying a verified strong authentication
    // event, then exchange it through the real /token path. The resulting
    // access/id tokens carry signed jti/acr/auth_time claims.
    let jti_store = new_shared_jti_store();
    state.jti_store = Some(Arc::new(JtiStoreImpl::Memory(jti_store.clone())));
    state.seed_dev_client("app-3lo", REDIRECT_TE, None).await;
    let authentication_time = real_now - 30;
    state
        .users
        .create_or_get_by_id("", "alice", authentication_time)
        .await
        .unwrap();
    let verifier = "0123456789012345678901234567890123456789abc";
    let authorization_code = state.region.issue_id("strong-te-code");
    state
        .codes
        .put(
            "",
            CodeRecord {
                code: authorization_code.clone(),
                client_id: "app-3lo".into(),
                cimd_snapshot: None,
                redirect_uri: REDIRECT_TE.into(),
                code_challenge: agent_auth_client::s256_challenge(verifier),
                // Keep the subject token in the OIDC/userinfo sector. The
                // mapped fam-te Grant below independently authorizes RS2.
                resources: vec![],
                user_id: "alice".into(),
                scope: vec!["openid".into(), "kb:read".into()],
                expires_at: real_now + 300,
                authz_session_id: None,
                nonce: None,
                auth_time: authentication_time,
                authorization_details: vec![],
                acr: Some(agent_auth_authn::assurance::STRONG_ACR.into()),
                amr: vec!["webauthn".into(), "hwk".into()],
                credential_epoch: Some(0),
                password_credential_version: None,
            },
        )
        .await
        .unwrap();
    // RS2 的 introspection 凭证(供委托 token introspect 断言,C8.7a P2:委托 token 经 introspect 含 act)。
    state
        .seed_rs_introspect_client("rs2-introspect", "sekret-rs2", &[RS2])
        .await;
    // 捕获 refresh + grants handle(共享 Arc),供 revoked 测试在装配后吊销。
    let refresh = state.refresh.clone();
    let grants = state.grants.clone();
    let clients = state.clients.clone();
    let policy_artifacts = state.policy_artifacts.clone();
    let rate_limit = state.rate_limit.clone().expect("dev rate-limit store");
    let returned_state = state.clone();
    let (router, _) = build_router(state);

    // Code exchange produces access_token + id_token with distinct jti values
    // and the same strong authentication event. Point both at fam-te.
    let (subject_token, id_subject_token) =
        mint_3lo_access_and_id_token(&router, &authorization_code).await;
    let jti_of = |tok: &str| -> String {
        let payload = tok.split('.').nth(1).unwrap();
        let c: serde_json::Value = serde_json::from_slice(&B64.decode(payload).unwrap()).unwrap();
        c["jti"].as_str().unwrap().to_string()
    };
    let real_now2 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // 覆盖 access_token + id_token 两个 jti 映射:jti→{alice, fam-te, grant=fam-te}。
    for jti in [jti_of(&subject_token), jti_of(&id_subject_token)] {
        jti_store
            .put(agent_auth_http::ports::JtiRecord {
                jti,
                tenant_id: "default".into(),
                user_id: "alice".into(),
                family_id: Some("fam-te".into()),
                grant_id: Some("fam-te".into()), // 指向 Grant → token-exchange 走 Grant 权威源
                expires_at: real_now2 + 900,
            })
            .await
            .unwrap();
    }
    (
        router,
        subject_token,
        actor_jwt,
        refresh,
        grants,
        id_subject_token,
        jti_store,
        clients,
        policy_artifacts,
        rate_limit,
        returned_state,
    )
}

async fn setup_token_exchange_rate_limit() -> (axum::Router, String, String, AppState) {
    let (
        router,
        subject,
        actor,
        _refresh,
        _grants,
        _id_token,
        _jti_store,
        _clients,
        _policy_artifacts,
        _rate_limit,
        state,
    ) = setup_token_exchange_with_jti_phase(agent_auth_http::SubjectType::Public, Phase::P2, false)
        .await;
    (router, subject, actor, state)
}

const REDIRECT_TE: &str = "https://app3lo.example.com/cb";

// 造一个共享的 MemoryJtiStore(测试要在装配后仍能写它)。
fn new_shared_jti_store() -> agent_auth_http::adapters::memory::MemoryJtiStore {
    agent_auth_http::adapters::memory::MemoryJtiStore::default()
}

// Exchange the pre-seeded strong authorization code for access and ID tokens.
async fn mint_3lo_access_and_id_token(
    router: &axum::Router,
    authorization_code: &str,
) -> (String, String) {
    let verifier = "0123456789012345678901234567890123456789abc";
    let form = format!(
        "grant_type=authorization_code&code={authorization_code}&code_verifier={verifier}\
         &redirect_uri={REDIRECT_TE}&client_id=app-3lo"
    );
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
    let t: serde_json::Value = serde_json::from_slice(&b).unwrap();
    let access = t["access_token"].as_str().unwrap().to_string();
    let id = t["id_token"]
        .as_str()
        .expect("scope=openid 应返回 id_token")
        .to_string();
    (access, id)
}

async fn post_te_response(router: &axum::Router, form: String) -> axum::response::Response {
    router
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
        .unwrap()
}

async fn post_te(router: &axum::Router, form: String) -> (StatusCode, serde_json::Value) {
    let resp = post_te_response(router, form).await;
    let st = resp.status();
    let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        st,
        serde_json::from_slice(&b).unwrap_or(serde_json::json!({})),
    )
}

async fn introspect_rs2(router: &axum::Router, token: &str) -> serde_json::Value {
    let basic = base64::engine::general_purpose::STANDARD.encode("rs2-introspect:sekret-rs2");
    let form = format!("token={token}&client_id=rs2-introspect");
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/introspect")
                .header("host", HOST)
                .header("authorization", format!("Basic {basic}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&body).expect("introspection response JSON")
}

// C7.1/C7.2/C7.3:合法委托 → 委托 token(sub=用户 RS2 sector、act.sub=actor、aud=RS2、scope⊆family)。
#[tokio::test]
async fn token_exchange_happy_path() {
    let (router, subject, actor, clients, policy_artifacts) = setup_token_exchange_activity().await;
    assert_eq!(
        clients
            .get("", "wl-actor")
            .await
            .unwrap()
            .unwrap()
            .last_used_day,
        None
    );
    let rejected_form = format!(
        "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource=https://not-authorized.example.com&scope=kb:read"
    );
    let (rejected_status, rejected_body) = post_te(&router, rejected_form).await;
    assert_eq!(
        rejected_status,
        StatusCode::BAD_REQUEST,
        "越出 Grant resource 的 token-exchange 必须拒绝: {rejected_body}"
    );
    assert_eq!(
        clients
            .get("", "wl-actor")
            .await
            .unwrap()
            .unwrap()
            .last_used_day,
        None,
        "token-exchange 签发失败不得推进 actor client 活动"
    );

    let PolicyArtifactStoreImpl::Memory(artifacts) = policy_artifacts.as_ref() else {
        panic!("dev state must use MemoryPolicyArtifactStore");
    };
    let artifact_reads_before_hot_path = artifacts.get_count();
    artifacts.fail_next_get();
    let form = format!(
        "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource={RS2}&scope=kb:read"
    );
    let (st, body) = post_te(&router, form).await;
    assert_eq!(st, StatusCode::OK, "合法委托应签出委托 token: {body}");
    assert_eq!(
        artifacts.get_count(),
        artifact_reads_before_hot_path,
        "token-exchange /token MUST NOT synchronously read a policy artifact"
    );
    assert!(
        matches!(
            policy_artifacts.get("", 1).await,
            Err(StoreError::Transient(_))
        ),
        "the armed policy-artifact read failure must remain pending until an explicit cold read"
    );
    let at = body["access_token"].as_str().expect("含委托 access_token");
    assert_access_token_es256(at);
    assert!(
        body.get("refresh_token").is_none(),
        "委托 token 不发 refresh"
    );
    let payload = at.split('.').nth(1).unwrap();
    let c: serde_json::Value = serde_json::from_slice(&B64.decode(payload).unwrap()).unwrap();
    let subject_claims: serde_json::Value = serde_json::from_slice(
        &B64.decode(subject.split('.').nth(1).expect("subject payload"))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(c["aud"], serde_json::json!([RS2]), "委托 token aud=目标 RS");
    assert_eq!(
        c["scope"], "kb:read",
        "委托 token scope 必须精确等于 Grant 允许的请求子集"
    );
    assert_eq!(
        c["acr"], subject_claims["acr"],
        "delegated token preserves the subject authentication class"
    );
    assert_eq!(
        c["auth_time"], subject_claims["auth_time"],
        "delegated token preserves the subject authentication time"
    );
    assert_eq!(
        c["act"]["sub"], "wl-actor",
        "act.sub=发起 agent(纯 RFC 8693)"
    );
    // dev 默认 public 形态 → 委托 token sub = 用户 user_id(alice);pairwise 形态则为 RS2 sector 派生 sub。
    assert_eq!(
        c["sub"].as_str().unwrap(),
        "alice",
        "public 下委托 token sub=用户 user_id"
    );
    // 命名空间 actor_types 含 agent 类型。
    let ns = &c["https://a-auth.com/c"];
    assert_eq!(ns["sub_type"], "user", "委托 token 代表用户 sub_type=user");
    assert_eq!(
        ns["auth_grant"], "fam-te",
        "委托 token 必须绑定被选中的源 Grant"
    );
    assert!(ns["actor_types"].is_object(), "命名空间含 actor_types");
    assert!(
        c.get("may_act").is_none(),
        "Grant actor_allowlist 只做服务端准入,不得塞入输出 token 的 may_act"
    );
    assert!(
        clients
            .get("", "wl-actor")
            .await
            .unwrap()
            .unwrap()
            .last_used_day
            .is_some(),
        "成功 token-exchange 必须推进 actor client 活动"
    );
}

#[tokio::test]
async fn token_exchange_rejects_subject_jti_from_previous_regional_activation() {
    use agent_auth_http::region::{
        MemoryRegionControlStore, RegionControlRecord, RegionControlStoreImpl, RegionRuntime,
    };

    let control = MemoryRegionControlStore::with_record(RegionControlRecord {
        active: true,
        activation_not_before: 0,
        revision: 1,
    });
    let region =
        RegionRuntime::controlled("us-east-1", RegionControlStoreImpl::Memory(control.clone()))
            .unwrap();
    let (
        router,
        subject,
        actor,
        _refresh,
        _grants,
        _id_token,
        _jti_store,
        _clients,
        _policy_artifacts,
        _rate_limit,
        _state,
    ) = setup_token_exchange_with_jti_phase_and_region(
        agent_auth_http::SubjectType::Public,
        Phase::P2,
        false,
        Some(region),
    )
    .await;
    assert!(
        te_jti_of(&subject).starts_with("r1_us-east-1_1_"),
        "the subject JTI must be bound to the issuing activation"
    );

    control
        .set(Some(RegionControlRecord {
            active: true,
            activation_not_before: agent_auth_http::current_unix_secs() + 330,
            revision: 2,
        }))
        .await;
    let form = format!(
        "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource={RS2}&scope=kb:read"
    );
    let (quiescing_status, quiescing_body) = post_te(&router, form.clone()).await;
    assert_eq!(
        quiescing_status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{quiescing_body}"
    );
    assert_eq!(quiescing_body["error"], "region_inactive");
    assert!(quiescing_body.get("access_token").is_none());

    control
        .set(Some(RegionControlRecord {
            active: true,
            activation_not_before: 0,
            revision: 3,
        }))
        .await;
    let (status, body) = post_te(&router, form).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(
        body["error_description"],
        "subject_token belongs to another Region"
    );
}

#[tokio::test]
async fn token_exchange_kms_transient_returns_retry_after_without_token() {
    use agent_auth_http::state::SignerImpl;

    let (
        router,
        subject,
        actor,
        _refresh,
        _grants,
        _id_token,
        _jti_store,
        _clients,
        _policy_artifacts,
        _rate_limit,
        state,
    ) = setup_token_exchange_with_jti_phase(agent_auth_http::SubjectType::Public, Phase::P2, false)
        .await;
    let SignerImpl::Memory(signer) = state.signer.as_ref() else {
        panic!("dev state must use MemorySigner");
    };
    signer.fail_next_es256(true);

    let response = post_te_response(
        &router,
        format!(
            "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
             &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
             &resource={RS2}&scope=kb:read"
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()["retry-after"], "1");
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["error"], "temporarily_unavailable");
    for field in ["access_token", "refresh_token", "id_token", "token_type"] {
        assert!(
            body.get(field).is_none(),
            "transient delegation signing failure must not return {field}: {body}"
        );
    }
}

#[tokio::test]
async fn token_exchange_rate_limit_uses_authenticated_actor() {
    let (router, subject, actor, state) = setup_token_exchange_rate_limit().await;
    exhaust_client_rate_limit(&state, "wl-actor").await;
    let form = format!(
        "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource={RS2}&scope=kb:read"
    );
    let limited = router
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
    assert_client_rate_limited(limited).await;

    state
        .rate_limit
        .as_ref()
        .unwrap()
        .delete("wl-actor")
        .await
        .unwrap();
    assert_eq!(
        post_te(&router, form).await.0,
        StatusCode::OK,
        "a throttled token-exchange request must remain retryable"
    );
}

// C7.1:subject/actor 必须使用各自参数槽和显式 token type,不得缺项、换槽或把用户 token 当 actor。
#[tokio::test]
async fn token_exchange_parameter_contract_rejects_missing_wrong_and_swapped_slots() {
    let (router, subject, actor, _refresh, _grants, id_token) = setup_token_exchange().await;
    let jwt_bearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    let invalid_request_forms = [
        (
            "missing subject_token",
            format!(
                "grant_type={TE_GRANT}&subject_token_type={TT_ACCESS}\
                 &actor_token={actor}&actor_token_type={jwt_bearer}&resource={RS2}"
            ),
        ),
        (
            "missing subject_token_type",
            format!(
                "grant_type={TE_GRANT}&subject_token={subject}\
                 &actor_token={actor}&actor_token_type={jwt_bearer}&resource={RS2}"
            ),
        ),
        (
            "unsupported subject_token_type",
            format!(
                "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type=urn:ietf:params:oauth:token-type:refresh_token\
                 &actor_token={actor}&actor_token_type={jwt_bearer}&resource={RS2}"
            ),
        ),
        (
            "missing actor_token",
            format!(
                "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
                 &actor_token_type={jwt_bearer}&resource={RS2}"
            ),
        ),
        (
            "missing actor_token_type",
            format!(
                "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
                 &actor_token={actor}&resource={RS2}"
            ),
        ),
        (
            "actor declared as access token",
            format!(
                "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
                 &actor_token={actor}&actor_token_type={TT_ACCESS}&resource={RS2}"
            ),
        ),
    ];
    for (name, form) in invalid_request_forms {
        let (status, body) = post_te(&router, form).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{name}: {body}");
        assert_eq!(body["error"], "invalid_request", "{name}: {body}");
    }

    let actor_in_subject_slot = format!(
        "grant_type={TE_GRANT}&subject_token={actor}&subject_token_type={TT_ACCESS}\
         &actor_token={actor}&actor_token_type={jwt_bearer}&resource={RS2}"
    );
    let (status, body) = post_te(&router, actor_in_subject_slot).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["error"], "invalid_grant",
        "平台 actor JWT 不得冒充用户 subject access token"
    );

    let id_token_declared_as_access = format!(
        "grant_type={TE_GRANT}&subject_token={id_token}&subject_token_type={TT_ACCESS}\
         &actor_token={actor}&actor_token_type={jwt_bearer}&resource={RS2}"
    );
    let (status, body) = post_te(&router, id_token_declared_as_access).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["error"], "invalid_grant",
        "RS256 ID token 不得冒充 ES256 at+jwt subject"
    );

    let subject_in_actor_slot = format!(
        "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
         &actor_token={subject}&actor_token_type={jwt_bearer}&resource={RS2}"
    );
    let (status, body) = post_te(&router, subject_in_actor_slot).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(
        body["error"], "invalid_client",
        "用户 access token 不得冒充已认证 workload actor"
    );
}

async fn sign_subject_token_with_extra_claims(
    jti: &str,
    extra_claims: serde_json::Value,
) -> String {
    use agent_auth_http::adapters::memory::MemorySigner;
    use agent_auth_http::ports::Signer;

    let signer = MemorySigner::dev();
    let kid = signer.active_kid().await.unwrap();
    let now = agent_auth_http::current_unix_secs();
    let header = serde_json::json!({ "alg": "ES256", "typ": "at+jwt", "kid": kid });
    let mut claims = serde_json::json!({
        "iss": format!("https://{HOST}"),
        "sub": "alice",
        "aud": [RS2],
        "client_id": "app-3lo",
        "jti": jti,
        "iat": now,
        "exp": now + 300,
        "https://a-auth.com/c": {
            "sub_type": "user",
            "auth_grant": "authorization_code"
        }
    });
    claims
        .as_object_mut()
        .expect("subject claims object")
        .extend(
            extra_claims
                .as_object()
                .expect("extra subject claims object")
                .clone(),
        );
    let signing_input = format!(
        "{}.{}",
        B64.encode(serde_json::to_vec(&header).unwrap()),
        B64.encode(serde_json::to_vec(&claims).unwrap())
    );
    let sig = signer.sign_es256(signing_input.as_bytes()).await.unwrap();
    format!("{signing_input}.{}", B64.encode(sig))
}

async fn sign_id_subject_token(jti: &str) -> String {
    use agent_auth_http::adapters::memory::MemorySigner;
    use agent_auth_http::ports::Signer;

    let signer = MemorySigner::dev();
    let (kid, _) = signer.sign_rs256(b"probe").await.unwrap();
    let now = agent_auth_http::current_unix_secs();
    let header = serde_json::json!({ "alg": "RS256", "typ": "JWT", "kid": kid });
    let claims = serde_json::json!({
        "iss": format!("https://{HOST}"),
        "sub": "alice",
        "aud": "app-3lo",
        "jti": jti,
        "iat": now,
        "exp": now + 300
    });
    let signing_input = format!(
        "{}.{}",
        B64.encode(serde_json::to_vec(&header).unwrap()),
        B64.encode(serde_json::to_vec(&claims).unwrap())
    );
    let (signed_kid, sig) = signer.sign_rs256(signing_input.as_bytes()).await.unwrap();
    assert_eq!(signed_kid, kid);
    format!("{signing_input}.{}", B64.encode(sig))
}

async fn sign_subject_token_with_prior_actor(jti: &str) -> String {
    sign_subject_token_with_extra_claims(
        jti,
        serde_json::json!({
            "act": {
                "sub": "middle-actor",
                "act": { "sub": "earliest-actor" }
            },
            "https://a-auth.com/c": {
                "sub_type": "user",
                "auth_grant": "authorization_code",
                "actor_types": {
                    "middle-actor": "agent",
                    "earliest-actor": "agent"
                }
            }
        }),
    )
    .await
}

async fn map_exchange_subject_jti(
    jti_store: &agent_auth_http::adapters::memory::MemoryJtiStore,
    jti: &str,
) {
    jti_store
        .put(agent_auth_http::ports::JtiRecord {
            jti: jti.into(),
            tenant_id: "default".into(),
            user_id: "alice".into(),
            family_id: Some("fam-te".into()),
            grant_id: Some("fam-te".into()),
            expires_at: agent_auth_http::current_unix_secs() + 300,
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn token_exchange_nests_prior_actor_inside_current_actor() {
    use agent_auth_http::ports::GrantStore;

    let (router, _subject, actor, _refresh, grants, _id, jti_store) =
        setup_token_exchange_with_jti(agent_auth_http::SubjectType::Public).await;
    let mut grant = grants
        .get("", "fam-te")
        .await
        .unwrap()
        .expect("setup must seed fam-te");
    grant.constraints.max_act_chain = 3;
    grants.put("", grant).await.unwrap();

    let jti = "jti-with-prior-actor";
    let subject = sign_subject_token_with_prior_actor(jti).await;
    map_exchange_subject_jti(&jti_store, jti).await;

    let form = format!(
        "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource={RS2}&scope=kb:read"
    );
    let (status, body) = post_te(&router, form).await;
    assert_eq!(status, StatusCode::OK, "multi-hop exchange failed: {body}");
    let delegated = body["access_token"]
        .as_str()
        .expect("multi-hop exchange must issue an access token");
    let claims: serde_json::Value = serde_json::from_slice(
        &B64.decode(delegated.split('.').nth(1).expect("delegated payload"))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        claims["act"],
        serde_json::json!({
            "sub": "wl-actor",
            "act": {
                "sub": "middle-actor",
                "act": { "sub": "earliest-actor" }
            }
        }),
        "RFC 8693 requires the current actor outside and the prior chain inside"
    );
    assert_eq!(
        claims["https://a-auth.com/c"]["actor_types"],
        serde_json::json!({
            "earliest-actor": "agent",
            "middle-actor": "agent",
            "wl-actor": "agent"
        }),
        "the actor type view must retain prior actors and add the current actor"
    );
    let introspection = introspect_rs2(&router, delegated).await;
    assert_eq!(introspection["active"], true);
    assert_eq!(
        introspection["act"], claims["act"],
        "introspection must preserve the complete nested RFC 8693 actor chain"
    );
    assert_eq!(
        introspection["https://a-auth.com/c"], claims["https://a-auth.com/c"],
        "introspection must preserve the complete nested actor type namespace"
    );
}

// C7.2:may_act 是对 Grant allowlist 的附加收紧闸。仅精确单对象命中可放行,数组/错 actor/通配均拒。
#[tokio::test]
async fn token_exchange_may_act_is_wired_as_exact_single_actor_gate() {
    let (router, _subject, actor, _refresh, _grants, _id, jti_store) =
        setup_token_exchange_with_jti(agent_auth_http::SubjectType::Public).await;
    let cases = [
        (
            "match",
            serde_json::json!({"sub": "wl-actor"}),
            StatusCode::OK,
            None,
        ),
        (
            "wrong actor",
            serde_json::json!({"sub": "wl-other"}),
            StatusCode::FORBIDDEN,
            Some("access_denied"),
        ),
        (
            "wildcard",
            serde_json::json!({"sub": "wl-*"}),
            StatusCode::FORBIDDEN,
            Some("access_denied"),
        ),
        (
            "array",
            serde_json::json!([{"sub": "wl-actor"}, {"sub": "wl-other"}]),
            StatusCode::FORBIDDEN,
            Some("access_denied"),
        ),
        (
            "missing sub",
            serde_json::json!({}),
            StatusCode::FORBIDDEN,
            Some("access_denied"),
        ),
        (
            "nonstring sub",
            serde_json::json!({"sub": 123}),
            StatusCode::FORBIDDEN,
            Some("access_denied"),
        ),
        (
            "scalar",
            serde_json::json!("wl-actor"),
            StatusCode::FORBIDDEN,
            Some("access_denied"),
        ),
    ];

    for (suffix, may_act, expected_status, expected_error) in cases {
        let jti = format!("jti-may-act-{}", suffix.replace(' ', "-"));
        let subject =
            sign_subject_token_with_extra_claims(&jti, serde_json::json!({"may_act": may_act}))
                .await;
        map_exchange_subject_jti(&jti_store, &jti).await;
        let form = format!(
            "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
             &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
             &resource={RS2}&scope=kb:read"
        );
        let (status, body) = post_te(&router, form).await;
        assert_eq!(status, expected_status, "{suffix}: {body}");
        if let Some(error) = expected_error {
            assert_eq!(body["error"], error, "{suffix}: {body}");
        } else {
            let delegated = body["access_token"]
                .as_str()
                .expect("matching may_act should issue a delegated token");
            let claims: serde_json::Value = serde_json::from_slice(
                &B64.decode(
                    delegated
                        .split('.')
                        .nth(1)
                        .expect("delegated access-token payload"),
                )
                .unwrap(),
            )
            .unwrap();
            assert!(
                claims.get("may_act").is_none(),
                "validated upstream may_act is an admission constraint, not an output authorization claim"
            );
        }
    }

    // Matching may_act must not replace the independent Grant actor_allowlist gate.
    let real_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let (other_actor, _jwk) = make_platform_jwt(
        "kb",
        serde_json::json!({
            "iss": PLATFORM_ISS, "sub": "repo:acme/other:ref:main",
            "aud": format!("https://{HOST}"), "iat": real_now, "exp": real_now + 300,
        }),
    );
    let other_jti = "jti-may-act-cannot-bypass-allowlist";
    let other_subject = sign_subject_token_with_extra_claims(
        other_jti,
        serde_json::json!({"may_act": {"sub": "wl-other"}}),
    )
    .await;
    map_exchange_subject_jti(&jti_store, other_jti).await;
    let form = format!(
        "grant_type={TE_GRANT}&subject_token={other_subject}&subject_token_type={TT_ACCESS}\
         &actor_token={other_actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource={RS2}&scope=kb:read"
    );
    let (status, body) = post_te(&router, form).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        body["error"], "access_denied",
        "matching may_act must not bypass Grant actor_allowlist"
    );

    // Matching may_act must not replace the independent max_act_chain gate.
    let deep_jti = "jti-may-act-cannot-bypass-depth";
    let deep_subject = sign_subject_token_with_extra_claims(
        deep_jti,
        serde_json::json!({
            "may_act": {"sub": "wl-actor"},
            "act": {"sub": "prior-actor"}
        }),
    )
    .await;
    map_exchange_subject_jti(&jti_store, deep_jti).await;
    let form = format!(
        "grant_type={TE_GRANT}&subject_token={deep_subject}&subject_token_type={TT_ACCESS}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource={RS2}&scope=kb:read"
    );
    let (status, body) = post_te(&router, form).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["error"], "invalid_grant",
        "matching may_act must not bypass Grant max_act_chain"
    );
}

// spec 010 §4 / DESIGN §5.2:510(委托 ⊆ 源 Grant):token-exchange 换发的委托 token **MUST 带源 Grant
// 该 resource 的 authorization_details(RAR)**——否则静默剥离 → RS enforce_rar 遇缺失回退 scope 放行
// = 委托 token 比源 Grant 更宽 = 扩权洞(评审设计阶段 BLOCKER)。此测试装配后把 Grant 重置为带 RAR,
// 再换发,断言委托 token 顶层 authorization_details == 源 Grant 该 resource 的 RAR。
#[tokio::test]
async fn token_exchange_propagates_source_grant_rar() {
    let (router, subject, actor, _refresh, grants, _id) = setup_token_exchange().await;
    // 把 Grant fam-te 重置为带 RAR(RS2 的内建词汇表约束)。
    let rar_count = serde_json::json!({
        "type": "agent_auth_rar_v1",
        "locations": [RS2],
        "resource_subset": [format!("{RS2}/2026/")],
        "max_records": 50
    });
    let rar_time = serde_json::json!({
        "type": "agent_auth_rar_v1",
        "locations": [RS2],
        "valid_from": 1_000,
        "valid_to": 4_000_000_000_i64
    });
    agent_auth_http::ports::GrantStore::put(
        grants.as_ref(),
        "",
        agent_auth_grant::Grant {
            grant_id: "fam-te".into(),
            user_id: "alice".into(),
            client_id: "app-3lo".into(),
            per_resource: vec![agent_auth_grant::ResourceGrant {
                resource: RS2.to_string(),
                scopes: vec!["kb:read".into()],
                authorization_details: vec![rar_count.clone(), rar_time.clone()],
            }],
            effective_per_resource: vec![],
            effective_pv: 0,
            allowed_ip_cidrs: vec![],
            allowed_vpce: vec![],
            credential_epoch: 0,
            revision: 0,
            constraints: agent_auth_grant::GrantConstraints {
                max_act_chain: 1,
                actor_allowlist: vec!["wl-actor".into()],
                expires_at: 4_000_000_000,
            },
            status: agent_auth_grant::GrantStatus::Active,
        },
    )
    .await
    .unwrap();

    let form = format!(
        "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource={RS2}&scope=kb:read"
    );
    let (st, body) = post_te(&router, form).await;
    assert_eq!(st, StatusCode::OK, "带 RAR 的委托应签出: {body}");
    let at = body["access_token"].as_str().expect("含委托 access_token");
    let c: serde_json::Value =
        serde_json::from_slice(&B64.decode(at.split('.').nth(1).unwrap()).unwrap()).unwrap();
    // **关键断言:委托 token 顶层带源 Grant 的 RAR(不静默剥离)。**
    let ad = c["authorization_details"]
        .as_array()
        .expect("委托 token MUST 带源 Grant 的 authorization_details(防剥离扩权)");
    assert_eq!(ad.len(), 2, "透传源 Grant RS2 的全部 RAR");
    assert_eq!(ad[0]["type"], "agent_auth_rar_v1");
    assert_eq!(ad[0]["max_records"], 50, "RAR 约束值透传");
    assert_eq!(
        ad,
        &[rar_count.clone(), rar_time.clone()],
        "委托 token RAR == 源 Grant 该 resource 的完整有序 RAR"
    );
    let introspection = introspect_rs2(&router, at).await;
    assert_eq!(introspection["active"], true);
    assert_eq!(
        introspection["authorization_details"],
        serde_json::json!([rar_count, rar_time]),
        "委托 token introspection 必须回带全部 RAR,不得截断或因 act 存在而省略"
    );
}

#[tokio::test]
async fn token_exchange_large_rar_uses_grant_backed_introspection() {
    let (router, subject, actor, _refresh, grants, _id) = setup_token_exchange_p3().await;
    let padding = "delegated-policy-segment-".repeat(80);
    let authorization_details: Vec<serde_json::Value> = (0..4)
        .map(|index| {
            serde_json::json!({
                "type": "agent_auth_rar_v1",
                "locations": [RS2],
                "identifier": format!("delegated-policy-{index}-{padding}"),
                "max_records": index + 1,
            })
        })
        .collect();
    agent_auth_http::ports::GrantStore::put(
        grants.as_ref(),
        "",
        agent_auth_grant::Grant {
            grant_id: "fam-te".into(),
            user_id: "alice".into(),
            client_id: "app-3lo".into(),
            per_resource: vec![agent_auth_grant::ResourceGrant {
                resource: RS2.to_string(),
                scopes: vec!["kb:read".into()],
                authorization_details: authorization_details.clone(),
            }],
            effective_per_resource: vec![],
            effective_pv: 0,
            allowed_ip_cidrs: vec![],
            allowed_vpce: vec![],
            credential_epoch: 0,
            revision: 0,
            constraints: agent_auth_grant::GrantConstraints {
                max_act_chain: 1,
                actor_allowlist: vec!["wl-actor".into()],
                expires_at: 4_000_000_000,
            },
            status: agent_auth_grant::GrantStatus::Active,
        },
    )
    .await
    .unwrap();

    let form = format!(
        "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource={RS2}&scope=kb:read"
    );
    let (status, body) = post_te(&router, form).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "large delegated RAR must use Grant-backed delivery: {body}"
    );
    let access_token = body["access_token"]
        .as_str()
        .expect("delegated access token");
    assert!(
        access_token.len() < agent_auth_token::JWT_SOFT_TARGET_BYTES,
        "delegated Grant-backed token must remain below the 4 KiB target"
    );
    let header: serde_json::Value =
        serde_json::from_slice(&B64.decode(access_token.split('.').next().unwrap()).unwrap())
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
    let kid = header["kid"].as_str().expect("delegated access token kid");
    let ec_jwk = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["kty"] == "EC" && key["kid"] == kid)
        .expect("delegated access token signing key");
    let verified = agent_auth_workload::verify_es256(
        access_token,
        ec_jwk["x"].as_str().unwrap(),
        ec_jwk["y"].as_str().unwrap(),
        Some(kid),
    )
    .expect("large-RAR delegated token must be verifiably signed");
    let claims = verified.claims;
    assert_eq!(
        claims["authorization_details"].as_array().unwrap().len(),
        1,
        "delegated token must contain exactly one bounded Grant summary"
    );
    assert_eq!(
        claims["authorization_details"][0]["type"],
        "agent_auth_grant_summary_v1"
    );
    assert!(
        !serde_json::to_string(&claims).unwrap().contains(&padding),
        "delegated token must not inline the large Grant details"
    );

    let introspection = introspect_rs2(&router, access_token).await;
    assert_eq!(introspection["active"], true);
    assert_eq!(
        introspection["authorization_details"],
        serde_json::Value::Array(authorization_details),
        "target RS introspection must return the complete ordered source Grant details"
    );
}

// C7.8a(spec 011 §3.4/§3.5):**id_token 作 subject_token**——RS256 验签 + jti→grant_id 单指针消歧
// (与 access_token 路径同口径)+ id_token.aud==源 Grant client_id 纵深防御。合法 id_token → 委托 token。
#[tokio::test]
async fn token_exchange_id_token_subject_happy_path() {
    // setup 返回的 id_subject_token 已把其 jti 映射覆写指向 fam-te(user=alice,client=app-3lo)。
    let (router, _access_subject, actor, _refresh, _grants, id_token) =
        setup_token_exchange().await;
    let form = format!(
        "grant_type={TE_GRANT}&subject_token={id_token}&subject_token_type={TT_ID_TOKEN}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource={RS2}&scope=kb:read"
    );
    let (st, body) = post_te(&router, form).await;
    assert_eq!(
        st,
        StatusCode::OK,
        "id_token 作 subject_token 合法委托应签出: {body}"
    );
    let at = body["access_token"].as_str().expect("含委托 access_token");
    let c: serde_json::Value =
        serde_json::from_slice(&B64.decode(at.split('.').nth(1).unwrap()).unwrap()).unwrap();
    assert_eq!(c["aud"], serde_json::json!([RS2]), "委托 token aud=目标 RS");
    assert_eq!(c["act"]["sub"], "wl-actor", "act.sub=发起 agent");
    assert_eq!(c["sub"].as_str().unwrap(), "alice", "public 下 sub=user_id");
}

// C7.8a:正确签名且带 jti 的 ID token，如果没有 jti 映射也必须拒绝；不能回退 token.sub。
#[tokio::test]
async fn token_exchange_id_token_unknown_jti_mapping_rejected() {
    let (router, _access_subject, actor, _refresh, _grants, _id_token) =
        setup_token_exchange().await;
    let id_token = sign_id_subject_token("id-jti-not-mapped").await;
    let form = format!(
        "grant_type={TE_GRANT}&subject_token={id_token}&subject_token_type={TT_ID_TOKEN}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource={RS2}&scope=kb:read"
    );
    let (status, body) = post_te(&router, form).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["error"], "invalid_grant",
        "合法 ID token 的未知 jti 必须在映射闸 fail-closed"
    );
}

// C7.8a:ID token 的 jti 映射必须带唯一 grant_id 指针；不得用过渡期 family 回退替代 Grant 消歧。
#[tokio::test]
async fn token_exchange_id_token_without_grant_pointer_rejected() {
    let (router, _access_subject, actor, _refresh, _grants, id_token, jti_store) =
        setup_token_exchange_with_jti(agent_auth_http::SubjectType::Public).await;
    jti_store
        .put(agent_auth_http::ports::JtiRecord {
            jti: te_jti_of(&id_token),
            tenant_id: "default".into(),
            user_id: "alice".into(),
            family_id: Some("fam-te".into()),
            grant_id: None,
            expires_at: agent_auth_http::current_unix_secs() + 300,
        })
        .await
        .unwrap();

    let form = format!(
        "grant_type={TE_GRANT}&subject_token={id_token}&subject_token_type={TT_ID_TOKEN}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource={RS2}&scope=kb:read"
    );
    let (status, body) = post_te(&router, form).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["error"], "invalid_grant",
        "ID token 缺 grant_id 单指针必须 fail-closed，不得回退 family"
    );
}

// C7.8a:access token 与 ID token 同口径；旧映射即使保留 family 也不能缺 Grant 单指针。
#[tokio::test]
async fn token_exchange_access_token_without_grant_pointer_rejected() {
    let (router, access_subject, actor, _refresh, _grants, _id_token, jti_store) =
        setup_token_exchange_with_jti(agent_auth_http::SubjectType::Public).await;
    jti_store
        .put(agent_auth_http::ports::JtiRecord {
            jti: te_jti_of(&access_subject),
            tenant_id: "default".into(),
            user_id: "alice".into(),
            family_id: Some("fam-te".into()),
            grant_id: None,
            expires_at: agent_auth_http::current_unix_secs() + 300,
        })
        .await
        .unwrap();

    let form = format!(
        "grant_type={TE_GRANT}&subject_token={access_subject}&subject_token_type={TT_ACCESS}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource={RS2}&scope=kb:read"
    );
    let (status, body) = post_te(&router, form).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant");
}

// C7.8a:同一用户存在另一 Grant 也不得按 resource 猜选；跨 Grant 必须显式出示 grant-ref。
#[tokio::test]
async fn token_exchange_id_token_cross_grant_without_ref_rejected() {
    let (router, _access_subject, actor, _refresh, grants, id_token) = setup_token_exchange().await;
    seed_grant_b(&grants).await;
    let form = format!(
        "grant_type={TE_GRANT}&subject_token={id_token}&subject_token_type={TT_ID_TOKEN}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource={RS_B}&scope=kb:read"
    );
    let (status, body) = post_te(&router, form).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["error"], "invalid_target",
        "无 grant-ref 时只能使用 jti 指向的源 Grant，不得按 resource 回退另一 Grant"
    );
}

// C7.8a:同一 ID token 只有显式携带绑定当前 actor 的 grant-ref，才能跨到另一 Grant 的 resource。
#[tokio::test]
async fn token_exchange_id_token_cross_grant_with_ref_succeeds() {
    let (router, _access_subject, actor, _refresh, grants, id_token) = setup_token_exchange().await;
    seed_grant_b(&grants).await;
    let grant_ref = sign_grant_ref_test("grant-b", "wl-actor", "grant-ref+jwt", far_exp()).await;
    let form = format!(
        "grant_type={TE_GRANT}&subject_token={id_token}&subject_token_type={TT_ID_TOKEN}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &grant_ref={grant_ref}&resource={RS_B}&scope=kb:read"
    );
    let (status, body) = post_te(&router, form).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let access = body["access_token"]
        .as_str()
        .expect("delegated access token");
    let claims: serde_json::Value = serde_json::from_slice(
        &B64.decode(access.split('.').nth(1).expect("token payload"))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(claims["aud"], serde_json::json!([RS_B]));
    assert_eq!(claims["https://a-auth.com/c"]["auth_grant"], "grant-b");
}

// C7.8a:jti 单指针命中的源 Grant 必须仍 active；ID token 未过期也不能绕过在线吊销。
#[tokio::test]
async fn token_exchange_id_token_revoked_grant_rejected() {
    use agent_auth_http::ports::GrantStore;

    let (router, _access_subject, actor, _refresh, grants, id_token) = setup_token_exchange().await;
    assert!(grants.revoke("", "fam-te").await.unwrap());
    let form = format!(
        "grant_type={TE_GRANT}&subject_token={id_token}&subject_token_type={TT_ID_TOKEN}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource={RS2}&scope=kb:read"
    );
    let (status, body) = post_te(&router, form).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant");
}

// C7.8a:jti 指针值必须真正选择其签发时源 Grant，不能只检查指针存在后固定加载 fam-te。
#[tokio::test]
async fn token_exchange_id_token_pointer_selects_distinct_source_grant() {
    let (router, _access_subject, actor, refresh, grants, _id_token, jti_store) =
        setup_token_exchange_with_jti(agent_auth_http::SubjectType::Public).await;
    seed_grant_b(&grants).await;
    refresh
        .create(
            "",
            RefreshFamilyRecord {
                family_id: "grant-b".into(),
                current_version: 0,
                revoked: false,
                client_id: "app-3lo".into(),
                cimd_snapshot: None,
                user_id: "alice".into(),
                credential_epoch: 0,
                resources: vec![RS_B.to_string()],
                scope: vec!["kb:read".into()],
                actor_allowlist: vec!["wl-actor".into()],
                max_act_chain: 1,
                dpop_jkt: None,
                pkce_code_challenge: None,
                auth_time: None,
                acr: None,
                password_credential_version: None,
            },
        )
        .await
        .unwrap();
    let jti = "id-jti-source-grant-b";
    let id_token = sign_id_subject_token(jti).await;
    jti_store
        .put(agent_auth_http::ports::JtiRecord {
            jti: jti.into(),
            tenant_id: "default".into(),
            user_id: "alice".into(),
            family_id: Some("grant-b".into()),
            grant_id: Some("grant-b".into()),
            expires_at: agent_auth_http::current_unix_secs() + 300,
        })
        .await
        .unwrap();

    let form = format!(
        "grant_type={TE_GRANT}&subject_token={id_token}&subject_token_type={TT_ID_TOKEN}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource={RS_B}&scope=kb:read"
    );
    let (status, body) = post_te(&router, form).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let access = body["access_token"]
        .as_str()
        .expect("delegated access token");
    let claims: serde_json::Value = serde_json::from_slice(
        &B64.decode(access.split('.').nth(1).expect("token payload"))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(claims["aud"], serde_json::json!([RS_B]));
    assert_eq!(claims["https://a-auth.com/c"]["auth_grant"], "grant-b");

    let wrong_source = format!(
        "grant_type={TE_GRANT}&subject_token={id_token}&subject_token_type={TT_ID_TOKEN}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource={RS2}&scope=kb:read"
    );
    let (status, body) = post_te(&router, wrong_source).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_target");
}

// C7.8a 红线:access_token 冒充 id_token(subject_token_type=id_token 但传的是 ES256 at+jwt)→ 拒
//(RS256 验签器拒 ES256/at+jwt,alg/typ 混淆防御)。
#[tokio::test]
async fn token_exchange_id_token_type_rejects_access_token() {
    let (router, access_subject, actor, _refresh, _grants, _id) = setup_token_exchange().await;
    // 传 access_token(ES256/at+jwt)却声明 subject_token_type=id_token → verify_id_token 拒。
    let form = format!(
        "grant_type={TE_GRANT}&subject_token={access_subject}&subject_token_type={TT_ID_TOKEN}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource={RS2}&scope=kb:read"
    );
    let (st, body) = post_te(&router, form).await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "access_token 冒充 id_token(type=id_token 传 at+jwt)MUST 拒: {body}"
    );
}

// 🔴 C7.8(§10 点名易漏 P2 MUST)8.7:**pairwise 租户**下 token-exchange——委托 token 的 sub 是**目标
// RS2 sector 派生的新 pairwise sub**(非 user_id、非 subject_token 的 sub),定位同一 user_id+Grant 靠
// jti→user_id 映射(**不解 subject_token 的 pairwise sub**,HMAC 单向不可反解)。act.sub 仍 = 发起 agent。
#[tokio::test]
async fn token_exchange_pairwise_delegated_sub_is_rs2_sector() {
    let (router, subject, actor, _refresh, _grants, _id) =
        setup_token_exchange_with(agent_auth_http::SubjectType::Pairwise).await;

    // subject_token(pairwise,aud=<issuer>/userinfo 的 OIDC sector)的 sub —— 用于断言"未依赖 sub 反解"
    // (委托 token sub 由 RS2 sector 独立派生,与 subject_token sub 不同)。
    let subj_sub = {
        let p = subject.split('.').nth(1).unwrap();
        let c: serde_json::Value = serde_json::from_slice(&B64.decode(p).unwrap()).unwrap();
        c["sub"].as_str().unwrap().to_string()
    };
    assert_ne!(
        subj_sub, "alice",
        "pairwise:subject_token sub 应为派生值,非 user_id"
    );

    let form = format!(
        "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource={RS2}&scope=kb:read"
    );
    let (st, body) = post_te(&router, form).await;
    assert_eq!(st, StatusCode::OK, "pairwise 合法委托应签出: {body}");
    let at = body["access_token"].as_str().unwrap();
    let c: serde_json::Value =
        serde_json::from_slice(&B64.decode(at.split('.').nth(1).unwrap()).unwrap()).unwrap();

    assert_eq!(c["aud"], serde_json::json!([RS2]), "委托 token aud=RS2");
    assert_eq!(c["act"]["sub"], "wl-actor", "act.sub=发起 agent");
    let deleg_sub = c["sub"].as_str().unwrap();
    let expected_rs2_sub =
        agent_auth_token::pairwise_sub(b"dev-server-secret-not-for-prod", "alice", RS2);
    // C7.8 核心:委托 token sub 精确等于内部 user_id × RS2 sector 派生值。
    assert_eq!(
        deleg_sub, expected_rs2_sub,
        "必须经 jti 还原内部 user_id，再按目标 RS2 sector 派生"
    );
    assert_ne!(
        deleg_sub, "alice",
        "pairwise:委托 sub 非 user_id(靠 jti 映射定位,不暴露 user_id)"
    );
    assert_ne!(
        deleg_sub, subj_sub,
        "委托 sub(RS2 sector)!= subject_token sub(OIDC sector)——不同 sector 不同 sub,未依赖 sub 反解"
    );
    // 确定性:同 user 同 RS2 sector 再换发得同一 sub(pairwise 派生是 user_id×sector 的确定函数)。
    let form2 = format!(
        "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource={RS2}&scope=kb:read"
    );
    let (st2, body2) = post_te(&router, form2).await;
    assert_eq!(st2, StatusCode::OK, "二次换发: {body2}");
    let c2: serde_json::Value = serde_json::from_slice(
        &B64.decode(
            body2["access_token"]
                .as_str()
                .unwrap()
                .split('.')
                .nth(1)
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        c2["sub"].as_str().unwrap(),
        deleg_sub,
        "同 user+RS2 sector 委托 sub 确定(pairwise 派生稳定)"
    );
}

// C7.8:即使 token 的 sub 看起来是可直接使用的内部 user_id，未知 jti 也必须拒绝，不得回退信任 sub。
#[tokio::test]
async fn token_exchange_unknown_jti_never_falls_back_to_subject_claim() {
    let (router, _subject, actor, _refresh, _grants, _id) =
        setup_token_exchange_with(agent_auth_http::SubjectType::Pairwise).await;
    let pairwise_sub =
        agent_auth_token::pairwise_sub(b"dev-server-secret-not-for-prod", "alice", RS2);
    let subject = sign_subject_token_with_extra_claims(
        "jti-not-mapped",
        serde_json::json!({
            "sub": pairwise_sub
        }),
    )
    .await;
    let form = format!(
        "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource={RS2}&scope=kb:read"
    );
    let (status, body) = post_te(&router, form).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["error"], "invalid_grant",
        "未知 jti 必须 fail-closed，即使 sub 是真实可枚举用户的合法 pairwise 派生值"
    );
}

// C8.7a(spec 010 Task 6.7,P2 委托 token 部分):委托 token(token-exchange 产,aud=RS2)经 /introspect
// (RS2 凭证)→ active + 回带 `act`(发起 agent)+ 命名空间 `actor_types`。补 introspect 委托 token 断言
// (此前 mcp_e2e 只测非委托 token 无 act;此处测委托 token **含** act)。
#[tokio::test]
async fn introspect_delegated_token_carries_act_and_actor_types() {
    let (router, subject, actor, _refresh, _grants, _id) = setup_token_exchange().await;
    // 1. 换发委托 token(aud=RS2,含 act.sub=wl-actor + actor_types)。
    let form = format!(
        "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource={RS2}&scope=kb:read"
    );
    let (st, body) = post_te(&router, form).await;
    assert_eq!(st, StatusCode::OK, "换发委托 token: {body}");
    let delegated = body["access_token"].as_str().expect("委托 token");

    // 2. RS2 凭证 introspect 该委托 token → active + act + actor_types。
    let j = introspect_rs2(&router, delegated).await;
    assert_eq!(
        j["active"], true,
        "RS2 查 aud=RS2 的委托 token 应 active: {j}"
    );
    // C8.7a:委托 token 经 introspect **回带 act**(发起 agent,纯 RFC 8693)。
    assert_eq!(
        j["act"],
        serde_json::json!({"sub": "wl-actor"}),
        "introspect 委托 token 应逐值回带纯 RFC 8693 act(C8.7a P2)"
    );
    let delegated_claims: serde_json::Value = serde_json::from_slice(
        &B64.decode(delegated.split('.').nth(1).expect("delegated payload"))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        j["https://a-auth.com/c"], delegated_claims["https://a-auth.com/c"],
        "introspection 必须逐键保留 signer 的 sub_type/auth_grant/actor_types 命名空间"
    );
    let namespace = j["https://a-auth.com/c"]
        .as_object()
        .expect("delegated introspection namespace");
    assert_eq!(
        namespace
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from(["actor_types", "auth_grant", "sub_type"]),
        "委托 introspection namespace 必须恰含三项规范键"
    );
    assert_eq!(namespace["sub_type"], "user");
    assert!(
        namespace["auth_grant"]
            .as_str()
            .map(|grant| !grant.is_empty())
            .unwrap_or(false),
        "委托 introspection 必须回带非空 auth_grant"
    );
    assert_eq!(
        namespace["actor_types"]["wl-actor"], "agent",
        "委托 introspection 必须回带当前 actor 的类型"
    );
    let subject_claims: serde_json::Value = serde_json::from_slice(
        &B64.decode(subject.split('.').nth(1).expect("subject payload"))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        j["acr"], subject_claims["acr"],
        "introspection returns the delegated authentication class"
    );
    assert_eq!(
        j["auth_time"], subject_claims["auth_time"],
        "introspection returns the delegated authentication time"
    );
}

// C7.2 身份闸:第二个 actor 已通过独立 workload trust + client 认证,但不在 Grant allowlist → 拒。
#[tokio::test]
async fn token_exchange_actor_not_in_allowlist_rejected() {
    let (router, subject, _actor, _refresh, _grants, _id) = setup_token_exchange().await;
    let real_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let (other_actor, _jwk) = make_platform_jwt(
        "kb",
        serde_json::json!({
            "iss": PLATFORM_ISS, "sub": "repo:acme/other:ref:main",
            "aud": format!("https://{HOST}"), "iat": real_now, "exp": real_now + 300,
        }),
    );
    let form = format!(
        "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
         &actor_token={other_actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource={RS2}&scope=kb:read"
    );
    let (st, body) = post_te(&router, form).await;
    assert_eq!(
        st,
        StatusCode::FORBIDDEN,
        "已认证 wl-other 不在 Grant allowlist,必须在委托身份闸拒绝: {body}"
    );
    assert_eq!(body["error"], "access_denied");
}

// C7.3:请求超白名单 scope → 拒。
#[tokio::test]
async fn token_exchange_scope_beyond_grant_rejected() {
    let (router, subject, actor, _refresh, _grants, _id) = setup_token_exchange().await;
    let form = format!(
        "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource={RS2}&scope=kb:write"
    );
    let (st, body) = post_te(&router, form).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "超白名单 scope 应拒");
    assert_eq!(body["error"], "invalid_scope");
}

// C7.3:scope 必须属于目标 resource 自己的 ResourceGrant,不得从同一 Grant 的其他 resource 借用。
#[tokio::test]
async fn token_exchange_scope_cannot_cross_resource_boundary() {
    use agent_auth_http::ports::GrantStore;

    let (router, subject, actor, _refresh, grants, _id) = setup_token_exchange().await;
    let mut grant = grants
        .get("", "fam-te")
        .await
        .unwrap()
        .expect("setup must seed fam-te");
    grant.per_resource.push(agent_auth_grant::ResourceGrant {
        resource: RS_B.to_string(),
        scopes: vec!["kb:write".into()],
        authorization_details: vec![],
    });
    let expected_grant = grant.clone();
    grants.put("", grant).await.unwrap();

    let form = format!(
        "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource={RS_B}&scope=kb:read"
    );
    let (st, body) = post_te(&router, form).await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "RS2 授予的 kb:read 不得被 RS_B 借用: {body}"
    );
    assert_eq!(body["error"], "invalid_scope");
    assert_eq!(
        grants.get("", "fam-te").await.unwrap(),
        Some(expected_grant),
        "越界请求必须直接拒绝,不得内联修改 Grant 补授权"
    );
}

// C7.3:目标 resource 不在源授权集合 → 拒。
#[tokio::test]
async fn token_exchange_resource_not_in_grant_rejected() {
    let (router, subject, actor, _refresh, _grants, _id) = setup_token_exchange().await;
    let form = format!(
        "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource=https://other.rs.example.com&scope=kb:read"
    );
    let (st, body) = post_te(&router, form).await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "目标 resource 不在源授权集合应拒"
    );
    assert_eq!(body["error"], "invalid_target");
}

// P1 阶段 token-exchange 不受理。
#[tokio::test]
async fn token_exchange_rejected_at_p1() {
    let state = AppState::dev(HOST); // phase=P1
    let (router, _) = build_router(state);
    let form = format!(
        "grant_type={TE_GRANT}&subject_token=x.y.z&subject_token_type={TT_ACCESS}\
         &actor_token=a.b.c&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&resource={RS2}"
    );
    let (st, _) = post_te(&router, form).await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "P1 阶段 token-exchange 应 unsupported_grant_type"
    );
}

// C7.8a:**畸形/伪造** id_token 作 subject_token → invalid_grant(验签失败,非误导性放行)。
// (合法 id_token 换发见 token_exchange_id_token_subject_happy_path;此处专测非法 id_token 被拒)。
#[tokio::test]
async fn token_exchange_malformed_id_token_rejected() {
    let (router, _subject, actor, _refresh, _grants, _id) = setup_token_exchange().await;
    let form = format!(
        "grant_type={TE_GRANT}&subject_token=x.y.z&subject_token_type=urn:ietf:params:oauth:token-type:id_token\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource={RS2}&scope=kb:read"
    );
    let (st, body) = post_te(&router, form).await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "畸形 id_token 作 subject_token 应拒"
    );
    assert_eq!(body["error"], "invalid_grant", "验签失败归 invalid_grant");
}

// C7.8 / 评审 M4(Task 2.8):token-exchange 是 AS **在线**操作,MUST 复核源 refresh-family/Grant
// 仍 active——即便 subject_token 表面签名有效/未过期,源授权已吊销即拒 invalid_grant(不因离线 RS
// 的 TTL 让步而延伸到在线换发)。
#[tokio::test]
async fn token_exchange_revoked_source_family_rejected() {
    let (router, subject, actor, refresh, _grants, _id) = setup_token_exchange().await;
    // 先确认 happy path 前提成立:吊销前同一请求应能换发(隔离"是不是别的原因拒")。
    // 这里不重复签发(一次性 jti 未消费),直接吊销源 family 再换发。
    refresh.revoke("", "fam-te").await.expect("吊销源 family");

    let form = format!(
        "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource={RS2}&scope=kb:read"
    );
    let (st, body) = post_te(&router, form).await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "源授权已吊销,在线换发 MUST 拒: {body}"
    );
    assert_eq!(
        body["error"], "invalid_grant",
        "源 family 吊销 → invalid_grant"
    );
}

// C7.6b / §5.1:吊销 **Grant**(status=Revoked)→ token-exchange 按 Grant 权威源拒(即便 family 仍 active)。
#[tokio::test]
async fn token_exchange_revoked_grant_rejected() {
    let (router, subject, actor, _refresh, grants, _id) = setup_token_exchange().await;
    // 只吊销 Grant(不动 family),验证 Grant 是权威源。
    use agent_auth_http::ports::GrantStore;
    assert!(
        grants.revoke("", "fam-te").await.unwrap(),
        "Grant 应存在并吊销"
    );
    let form = format!(
        "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource={RS2}&scope=kb:read"
    );
    let (st, body) = post_te(&router, form).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "Grant 吊销后换发应拒: {body}");
    assert_eq!(body["error"], "invalid_grant", "Grant 吊销 → invalid_grant");
}

// C7.2 深度闸(max_act_chain):为带两层 act 的合法签名 subject 建立真实 jti/Grant 映射,
// 确保请求到达 authorize_delegation 后因 2+1 > 1 被拒,而不是更早因缺 jti 映射失败。
#[tokio::test]
async fn token_exchange_depth_chain_exceeded_rejected() {
    let (router, _subject, actor, _refresh, _grants, _id, jti_store) =
        setup_token_exchange_with_jti(agent_auth_http::SubjectType::Public).await;
    let jti = "jti-depth-over-limit";
    let subject = sign_subject_token_with_prior_actor(jti).await;
    map_exchange_subject_jti(&jti_store, jti).await;
    let form = format!(
        "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource={RS2}&scope=kb:read"
    );
    let (status, body) = post_te(&router, form).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "入站 act 深度 2 + 本跳 1 超过 Grant max_act_chain=1,必须由深度闸拒绝: {body}"
    );
    assert_eq!(body["error"], "invalid_grant");
}

// ---- spec 012 C5.2/C5.3/C5.4:SigV4/STS 兜底路径接线(mock STS)----

use agent_auth_http::state::StsCallerImpl;
use agent_auth_workload::{SigV4Assertion, StsCallerIdentity};
use std::collections::BTreeMap;

const SIGV4_ASSERTION_TYPE: &str = "urn:agent-auth:params:oauth:client-assertion-type:aws-sigv4";
const SIGV4_ACCOUNT: &str = "123456789012";
const SIGV4_ARN: &str = "arn:aws:sts::123456789012:assumed-role/AgentRuntime-kb/sess-1";

/// 把 unix 秒格式化为 SigV4 `X-Amz-Date`(`YYYYMMDDTHHMMSSZ`)。纯整数换算(Howard Hinnant 逆),
/// 供测试造"当前时刻"的合法 amz-date(handler 读真实时钟,须用接近 now 的值过 TTL 门)。
fn amz_date(unix: i64) -> String {
    let days = unix.div_euclid(86400);
    let secs = unix.rem_euclid(86400);
    let (h, mi, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    // days → civil(逆 days_from_civil)。
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}{m:02}{d:02}T{h:02}{mi:02}{s:02}Z")
}

/// 造一枚 SigV4Assertion:audience 头**在 SignedHeaders 内**且值=本 AS issuer,X-Amz-Date=now,
/// Signature=给定值(mock STS 据此返身份)。url=真 STS host。
fn make_sigv4_assertion(issuer: &str, signature: &str, now: i64) -> SigV4Assertion {
    let authz = format!(
        "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20260101/us-east-1/sts/aws4_request,\
         SignedHeaders=host;x-amz-date;x-agent-auth-audience,Signature={signature}"
    );
    let mut headers = BTreeMap::new();
    headers.insert("authorization".into(), authz);
    headers.insert("x-amz-date".into(), amz_date(now));
    headers.insert("x-agent-auth-audience".into(), issuer.to_string());
    headers.insert("host".into(), "sts.amazonaws.com".into());
    SigV4Assertion {
        method: "POST".into(),
        url: "https://sts.amazonaws.com/".into(),
        headers,
        body: "Action=GetCallerIdentity&Version=2011-06-15".into(),
    }
}

/// 装配 P2 state:workload client(SigV4 信任绑定 caller ARN→wl-sigv4)+ mock STS 预置该 signature 身份。
async fn setup_sigv4(
    signature: &str,
) -> (
    axum::Router,
    i64,
    agent_auth_http::adapters::memory::MemoryStsCaller,
) {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P2;
    state
        .seed_workload_client_with_policy("wl-sigv4", vec![RS.to_string()], vec!["kb:read".into()])
        .await;
    let _ = state
        .workload_trust
        .put(
            "",
            "b-sigv4".into(),
            TrustBinding {
                tenant_id: "default".into(),
                mechanism: TrustMechanism::Sigv4 {
                    aws_account_id: SIGV4_ACCOUNT.into(),
                    role_arn_pattern: "arn:aws:sts::123456789012:assumed-role/AgentRuntime-*"
                        .into(),
                },
                mapped_client_id: "wl-sigv4".into(),
            },
        )
        .await;
    // mock STS:该 signature 转发后返回 caller 身份(STS 200)。
    let sts = agent_auth_http::adapters::memory::MemoryStsCaller::default();
    sts.set(
        signature,
        StsCallerIdentity {
            account: SIGV4_ACCOUNT.into(),
            arn: SIGV4_ARN.into(),
            user_id: "AROAEXAMPLE:sess-1".into(),
        },
    )
    .await;
    state.sts_caller = Some(Arc::new(StsCallerImpl::Memory(sts.clone())));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let (router, _) = build_router(state);
    (router, now, sts)
}

// C5.2/C5.3:合法 SigV4 断言(audience 被签名+值符 / TTL 内 / STS host 合法)→ STS 验证 → 映射
// client_id → 签 2LO agent token(sub=wl-sigv4、sub_type=agent、无 refresh)。
#[tokio::test]
async fn sigv4_happy_path_issues_2lo_token() {
    let sig = "goodsig123";
    let (router, now, sts) = setup_sigv4(sig).await;
    let issuer = format!("https://{HOST}");
    let assertion = make_sigv4_assertion(&issuer, sig, now);
    let assertion_json = serde_json::to_string(&assertion).unwrap();
    let enc = urlencoding_lite(&assertion_json);
    let form = format!("grant_type=client_credentials&client_assertion_type={SIGV4_ASSERTION_TYPE}&client_assertion={enc}&resource={RS}&scope=kb:read");
    let (st, body) = post_2lo(&router, form).await;
    assert_eq!(st, StatusCode::OK, "合法 SigV4 应签出 2LO token: {body}");
    let at = body["access_token"].as_str().expect("access_token");
    let payload = at.split('.').nth(1).unwrap();
    let c: serde_json::Value = serde_json::from_slice(&B64.decode(payload).unwrap()).unwrap();
    assert_eq!(c["sub"], "wl-sigv4", "SigV4 2LO sub=映射 client_id");
    assert_eq!(c["https://a-auth.com/c"]["sub_type"], "agent");
    assert!(body.get("refresh_token").is_none(), "2LO 不发 refresh");
    assert_eq!(sts.call_count(), 1, "合法 SigV4 请求恰好调用一次 STS");
}

// C5.2:audience 头不在 SignedHeaders 内(转发前塞的未签名头)→ 前校拒(不转发 STS)。
#[tokio::test]
async fn sigv4_unsigned_audience_rejected() {
    let sig = "goodsig123";
    let (router, now, sts) = setup_sigv4(sig).await;
    let issuer = format!("https://{HOST}");
    let mut assertion = make_sigv4_assertion(&issuer, sig, now);
    // 把 audience 从 SignedHeaders 摘掉(值仍在,但未签名)。
    assertion.headers.insert(
        "authorization".into(),
        format!("AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/x,SignedHeaders=host;x-amz-date,Signature={sig}"),
    );
    let enc = urlencoding_lite(&serde_json::to_string(&assertion).unwrap());
    let form = format!("grant_type=client_credentials&client_assertion_type={SIGV4_ASSERTION_TYPE}&client_assertion={enc}&resource={RS}&scope=kb:read");
    let (st, body) = post_2lo(&router, form).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "未签名 audience 应拒: {body}");
    assert_eq!(body["error"], "invalid_client");
    assert_eq!(sts.call_count(), 0, "未签名 audience MUST 在 STS 前拒绝");
}

// C5.2:audience 已在 SignedHeaders 内、但值不是本 AS issuer → 前校拒(不转发 STS)。
#[tokio::test]
async fn sigv4_signed_wrong_audience_rejected_before_sts() {
    let sig = "goodsig123";
    let (router, now, sts) = setup_sigv4(sig).await;
    let issuer = format!("https://{HOST}");
    let mut assertion = make_sigv4_assertion(&issuer, sig, now);
    assertion.headers.insert(
        "x-agent-auth-audience".into(),
        "https://other-as.example.com".into(),
    );
    let enc = urlencoding_lite(&serde_json::to_string(&assertion).unwrap());
    let form = format!("grant_type=client_credentials&client_assertion_type={SIGV4_ASSERTION_TYPE}&client_assertion={enc}&resource={RS}&scope=kb:read");
    let (st, body) = post_2lo(&router, form).await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "已签但 issuer 错误的 audience 应拒: {body}"
    );
    assert_eq!(body["error"], "invalid_client");
    assert_eq!(
        sts.call_count(),
        0,
        "已签但 issuer 错误的 audience MUST 在 STS 前拒绝"
    );
}

// C5.3②:同一预签名请求重放第二次 → 一次性 replay 缓存命中 → invalid_grant。
#[tokio::test]
async fn sigv4_replay_second_use_rejected() {
    use agent_auth_workload::{validate_sigv4_pre_sts, SigV4RejectReason};

    let sig = "replaysig";
    let (router, now, sts) = setup_sigv4(sig).await;
    let issuer = format!("https://{HOST}");
    let assertion = make_sigv4_assertion(&issuer, sig, now);

    let stale = make_sigv4_assertion(&issuer, "stalesig", now - 91);
    assert_eq!(
        validate_sigv4_pre_sts(&stale, "x-agent-auth-audience", &issuer, now),
        Err(SigV4RejectReason::OutsideTtl),
        "SigV4 预签名超过短 TTL+skew MUST 在 STS 前拒绝"
    );
    let mut forged_host = make_sigv4_assertion(&issuer, "forgedhostsig", now);
    forged_host.url = "https://evil.example.com/".into();
    assert_eq!(
        validate_sigv4_pre_sts(&forged_host, "x-agent-auth-audience", &issuer, now),
        Err(SigV4RejectReason::StsHostNotAllowed),
        "非 allowlist STS host MUST 在转发前拒绝"
    );

    let enc = urlencoding_lite(&serde_json::to_string(&assertion).unwrap());
    let form = format!("grant_type=client_credentials&client_assertion_type={SIGV4_ASSERTION_TYPE}&client_assertion={enc}&resource={RS}&scope=kb:read");
    // 第一次:成功签出 token。
    let (st1, body1) = post_2lo(&router, form.clone()).await;
    assert_eq!(st1, StatusCode::OK, "首次应签出 token: {body1}");
    assert_eq!(sts.call_count(), 1, "首次请求调用一次 STS");
    // 第二次(同一预签名)→ replay 缓存命中 → invalid_grant(不转发 STS)。
    let (st2, body2) = post_2lo(&router, form).await;
    assert_eq!(st2, StatusCode::BAD_REQUEST, "重放应拒: {body2}");
    assert_eq!(body2["error"], "invalid_grant");
    assert_eq!(sts.call_count(), 1, "重放 MUST 在 STS 前拒绝");
}

// C5.3:STS 拒(签名无效,mock 未预置该 signature)→ 认证失败 invalid_client。
#[tokio::test]
async fn sigv4_sts_rejects_invalid_signature() {
    let (router, now, sts) = setup_sigv4("goodsig123").await;
    let issuer = format!("https://{HOST}");
    // 用未预置的 signature(mock STS 返 Ok(None) = 拒)。
    let assertion = make_sigv4_assertion(&issuer, "unknownsig", now);
    let enc = urlencoding_lite(&serde_json::to_string(&assertion).unwrap());
    let form = format!("grant_type=client_credentials&client_assertion_type={SIGV4_ASSERTION_TYPE}&client_assertion={enc}&resource={RS}&scope=kb:read");
    let (st, body) = post_2lo(&router, form).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "STS 拒应 401: {body}");
    assert_eq!(body["error"], "invalid_client");
    assert_eq!(sts.call_count(), 1, "STS 拒绝路径应调用一次 STS");
}

// C5.4:STS 瞬时失败达阈值 → 熔断打开 → 后续请求快速失败 503(不再外呼)。验 handler 熔断接线。
#[tokio::test]
async fn sigv4_sts_transient_trips_circuit_breaker() {
    let sig = "transientsig";
    // 装配:mock STS 对该 signature 恒瞬时失败(模拟 STS 超时/5xx)。
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P2;
    state
        .seed_workload_client_with_policy("wl-sigv4", vec![RS.to_string()], vec!["kb:read".into()])
        .await;
    let _ = state
        .workload_trust
        .put(
            "",
            "b-sigv4".into(),
            TrustBinding {
                tenant_id: "default".into(),
                mechanism: TrustMechanism::Sigv4 {
                    aws_account_id: SIGV4_ACCOUNT.into(),
                    role_arn_pattern: "arn:aws:sts::123456789012:assumed-role/AgentRuntime-*"
                        .into(),
                },
                mapped_client_id: "wl-sigv4".into(),
            },
        )
        .await;
    let sts = agent_auth_http::adapters::memory::MemoryStsCaller::default();
    let _ = sig; // 用**各不相同**的签名(真客户端重试会重新签名,replay 缓存不会误拦重试)。
    let sigs: Vec<String> = (0..6).map(|i| format!("transientsig{i}")).collect();
    for s in sigs.iter().take(5) {
        sts.set_transient(s).await;
    }
    let sts_probe = sts.clone();
    state.sts_caller = Some(Arc::new(StsCallerImpl::Memory(sts)));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let oidc_claims = serde_json::json!({
        "iss": PLATFORM_ISS,
        "sub": "repo:acme/agent:ref:main",
        "aud": format!("https://{HOST}"),
        "iat": now,
        "exp": now + 300,
    });
    let (oidc_jwt, oidc_jwk) = make_platform_jwt("c5-4-oidc", oidc_claims);
    state
        .seed_workload_client_with_policy("wl-gha", vec![RS.to_string()], vec!["kb:read".into()])
        .await;
    let _ = state
        .workload_trust
        .put(
            "",
            "b-c5-4-oidc".into(),
            TrustBinding {
                tenant_id: "default".into(),
                mechanism: TrustMechanism::Oidc {
                    platform_issuer: PLATFORM_ISS.into(),
                    jwks_uri: JWKS_URI.into(),
                    subject_pattern: "repo:acme/agent:*".into(),
                },
                mapped_client_id: "wl-gha".into(),
            },
        )
        .await;
    let fetcher = agent_auth_http::adapters::memory::MemoryJwksFetcher::default();
    fetcher.set(JWKS_URI, vec![oidc_jwk]).await;
    state.jwks_fetcher = Arc::new(JwksFetcherImpl::Memory(fetcher));
    let (router, _) = build_router(state);
    let issuer = format!("https://{HOST}");
    let mk_form = |s: &str| {
        let assertion = make_sigv4_assertion(&issuer, s, now);
        let enc = urlencoding_lite(&serde_json::to_string(&assertion).unwrap());
        format!("grant_type=client_credentials&client_assertion_type={SIGV4_ASSERTION_TYPE}&client_assertion={enc}&resource={RS}&scope=kb:read")
    };

    // 前 5 次(各不同签名,过 replay):STS 瞬时失败 → 503(每次真外呼 + 计熔断失败)。
    for (i, s) in sigs.iter().take(5).enumerate() {
        let (st, body) = post_2lo(&router, mk_form(s)).await;
        assert_eq!(
            st,
            StatusCode::SERVICE_UNAVAILABLE,
            "第{i}次瞬时失败应 503: {body}"
        );
        assert_eq!(body["error"], "temporarily_unavailable");
    }
    assert_eq!(sts_probe.call_count(), 5, "前5次请求必须都外呼STS");
    // 第 6 次(新签名,过 replay):熔断已打开 → 快速失败 503,不再外呼。
    let (st, body) = post_2lo(&router, mk_form(&sigs[5])).await;
    assert_eq!(
        st,
        StatusCode::SERVICE_UNAVAILABLE,
        "熔断打开后应快速 503: {body}"
    );
    assert_eq!(body["error"], "temporarily_unavailable");
    assert_eq!(sts_probe.call_count(), 5, "熔断打开后第6次请求不得外呼STS");
    for field in ["access_token", "refresh_token", "id_token", "token_type"] {
        assert!(
            body.get(field).is_none(),
            "熔断错误响应不得泄出{field}: {body}"
        );
    }

    let oidc_form = format!(
        "grant_type=client_credentials&client_assertion_type={JWT_BEARER}&client_assertion={oidc_jwt}&resource={RS}"
    );
    let (oidc_status, oidc_body) = post_2lo(&router, oidc_form).await;
    assert_eq!(
        oidc_status,
        StatusCode::OK,
        "STS circuit Open不得影响同一/token上的OIDC自校验路径: {oidc_body}"
    );
    assert!(oidc_body["access_token"].is_string());
    assert_eq!(
        sts_probe.call_count(),
        5,
        "OIDC自校验路径不得触碰STS circuit或外呼STS"
    );
}

// 最小 url-encode(仅编码会破坏 form 的字符:& = % 空格 +);测试够用。
fn urlencoding_lite(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '%' => "%25".to_string(),
            '&' => "%26".to_string(),
            '+' => "%2B".to_string(),
            ' ' => "%20".to_string(),
            '=' => "%3D".to_string(),
            other => other.to_string(),
        })
        .collect()
}

// spec 011 Task 6.2 / 8.4(C7.5/C2):2LO token 形态断言 —— **不带** grant_id/auth_time/act/actor_types
// (2LO 无自然人、无委托链、无 Grant),且签发前后 Grant 物理记录数不变。这些私有 claim 收在命名空间
// 对象下,断言它们均缺席;顶层 auth_time(OIDC)亦缺席。防回归:未来若误给 2LO 塞这些字段,RS 会误判为委托/用户流。
#[tokio::test]
async fn client_credentials_2lo_token_omits_delegation_claims() {
    let real_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = serde_json::json!({
        "iss": PLATFORM_ISS,
        "sub": "repo:acme/agent:ref:main",
        "aud": format!("https://{HOST}"),
        "iat": real_now,
        "exp": real_now + 300,
    });
    let (jwt, jwk) = make_platform_jwt("k1", claims);
    let (router, state) = setup_2lo_with_state("k1", jwk).await;
    let grants_before = match state.grants.as_ref() {
        agent_auth_http::state::GrantStoreImpl::Memory(grants) => grants.record_count().await,
        #[cfg(feature = "aws")]
        agent_auth_http::state::GrantStoreImpl::Dynamo(_) => {
            panic!("setup_2lo_with_state must use the memory Grant store")
        }
    };

    let form = format!(
        "grant_type=client_credentials&client_assertion_type={JWT_BEARER}&client_assertion={jwt}&resource={RS}"
    );
    let (st, body) = post_2lo(&router, form).await;
    assert_eq!(st, StatusCode::OK, "2LO 应签出: {body}");
    let at = body["access_token"].as_str().expect("含 access_token");
    let payload = at.split('.').nth(1).unwrap();
    let c: serde_json::Value = serde_json::from_slice(&B64.decode(payload).unwrap()).unwrap();

    // 顶层:无 OIDC auth_time(2LO 无自然人认证时刻)。
    assert!(
        c.get("auth_time").is_none(),
        "2LO token 不得带顶层 auth_time(无自然人认证)"
    );
    // 命名空间私有 claim 对象:sub_type=agent 应在;grant_id/act/actor_types/auth_time 均不得在。
    let ns = &c["https://a-auth.com/c"];
    assert_eq!(ns["sub_type"], "agent", "2LO sub_type=agent");
    for absent in ["grant_id", "act", "actor_types", "auth_time"] {
        assert!(
            ns.get(absent).is_none(),
            "2LO token 命名空间不得带 {absent}(无 Grant/委托链/自然人):实际 {ns}"
        );
    }
    // 顶层也不得混入这些(防实现从别处塞顶层)。
    for absent in ["grant_id", "act", "actor_types"] {
        assert!(
            c.get(absent).is_none(),
            "2LO token 顶层不得带 {absent}:实际有 {}",
            c.get(absent).unwrap()
        );
    }
    let grants_after = match state.grants.as_ref() {
        agent_auth_http::state::GrantStoreImpl::Memory(grants) => grants.record_count().await,
        #[cfg(feature = "aws")]
        agent_auth_http::state::GrantStoreImpl::Dynamo(_) => {
            panic!("setup_2lo_with_state must use the memory Grant store")
        }
    };
    assert_eq!(grants_after, grants_before, "2LO 签发不得持久化任何 Grant");
}

// ============ grant-ref 跨 Grant 换发(spec 011 §4,C7.1/C7.7)============

const RS_B: &str = "https://mcp.rsB.example.com";

/// 用 dev MemorySigner(与 AppState::dev 同一缓存单例 key/kid)签一枚 grant-ref JWT。
/// typ 可注入(测 typ 混淆);exp 可注入(测过期)。iss=https://{HOST}(与 SelfHosted issuer 一致)。
async fn sign_grant_ref_test(grant_id: &str, bound_agent: &str, typ: &str, exp: i64) -> String {
    sign_grant_ref_test_with_extra_claims(grant_id, bound_agent, typ, exp, serde_json::json!({}))
        .await
}

async fn sign_grant_ref_test_with_extra_claims(
    grant_id: &str,
    bound_agent: &str,
    typ: &str,
    exp: i64,
    extra_claims: serde_json::Value,
) -> String {
    use agent_auth_http::adapters::memory::MemorySigner;
    use agent_auth_http::ports::Signer;
    let signer = MemorySigner::dev();
    let kid = signer.active_kid().await.unwrap();
    let now = agent_auth_http::current_unix_secs();
    let header = serde_json::json!({ "alg": "ES256", "typ": typ, "kid": kid });
    let mut claims = serde_json::json!({
        "grant_id": grant_id, "bound_agent": bound_agent,
        "iss": format!("https://{HOST}"), "iat": now, "exp": exp,
    });
    claims
        .as_object_mut()
        .expect("grant-ref claims object")
        .extend(
            extra_claims
                .as_object()
                .expect("extra grant-ref claims object")
                .clone(),
        );
    let signing_input = format!(
        "{}.{}",
        B64.encode(serde_json::to_vec(&header).unwrap()),
        B64.encode(serde_json::to_vec(&claims).unwrap())
    );
    let sig = signer.sign_es256(signing_input.as_bytes()).await.unwrap();
    format!("{signing_input}.{}", B64.encode(sig))
}

/// 在 setup_token_exchange 的 grants 上加一个**Grant B**(同 user alice,资源 RS_B,actor_allowlist=[wl-actor])。
async fn seed_grant_b(grants: &Arc<agent_auth_http::state::GrantStoreImpl>) {
    use agent_auth_http::ports::GrantStore;
    GrantStore::put(
        grants.as_ref(),
        "",
        agent_auth_grant::Grant {
            grant_id: "grant-b".into(),
            user_id: "alice".into(),
            client_id: "app-3lo".into(),
            per_resource: vec![agent_auth_grant::ResourceGrant {
                resource: RS_B.to_string(),
                scopes: vec!["kb:read".into(), "kb:metadata".into()],
                authorization_details: vec![],
            }],
            effective_per_resource: vec![],
            effective_pv: 0,
            allowed_ip_cidrs: vec![],
            allowed_vpce: vec![],
            credential_epoch: 0,
            revision: 0,
            constraints: agent_auth_grant::GrantConstraints {
                max_act_chain: 1,
                actor_allowlist: vec!["wl-actor".into()],
                expires_at: 4_000_000_000,
            },
            status: agent_auth_grant::GrantStatus::Active,
        },
    )
    .await
    .unwrap();
}

fn far_exp() -> i64 {
    agent_auth_http::current_unix_secs() + 300
}

/// 用 dev signer 签一枚**带 cnf** 的 ES256 access token(typ=at+jwt + client_id + iss=本AS + jti),
/// 用于测"入站 sender-constrained subject_token 不静默降级"(C7.9 / §7.1)。
async fn sign_access_token_with_cnf(jkt: &str) -> String {
    sign_access_token_with_raw_cnf(serde_json::json!({ "jkt": jkt })).await
}

/// 同上,但 cnf 值任意注入(测畸形 cnf:无 jkt / 非对象等 fail-closed 兜底,§7.2 ⑧)。
async fn sign_access_token_with_raw_cnf(cnf: serde_json::Value) -> String {
    use agent_auth_http::adapters::memory::MemorySigner;
    use agent_auth_http::ports::Signer;
    let signer = MemorySigner::dev();
    let kid = signer.active_kid().await.unwrap();
    let now = agent_auth_http::current_unix_secs();
    let header = serde_json::json!({ "alg": "ES256", "typ": "at+jwt", "kid": kid });
    let claims = serde_json::json!({
        "iss": format!("https://{HOST}"), "sub": "u-sc", "aud": [RS2],
        "client_id": "app-3lo", "jti": "jti-sender-constrained",
        "iat": now, "exp": now + 300,
        "cnf": cnf, // ← 入站已 sender-constrained(值由调用方给)
    });
    let signing_input = format!(
        "{}.{}",
        B64.encode(serde_json::to_vec(&header).unwrap()),
        B64.encode(serde_json::to_vec(&claims).unwrap())
    );
    let sig = signer.sign_es256(signing_input.as_bytes()).await.unwrap();
    format!("{signing_input}.{}", B64.encode(sig))
}

// C7.9 / §7.1 不静默降级(§7.2 演进):入站 subject_token 已 sender-constrained(带 cnf)且发起 actor
// **无 DPoP proof** → MUST 拒(invalid_dpop_proof)——绝不签出丢 cnf 的 bearer 悄悄降级整条链。
// §7.2 前此处返 invalid_request(彼时委托 cnf 传播未实现,一律拒);现由 DPoP holder-of-key 闸接管
// (缺 proof / 跨 key 均拒;同 key 重绑才放行,见 te_dpop_* 测试)。
#[tokio::test]
async fn token_exchange_sender_constrained_subject_not_silently_downgraded() {
    let (router, _subject, actor, _refresh, _grants, _id) = setup_token_exchange().await;
    // 自造一枚带 cnf 的合法 AS 签发 access token 作 subject_token(验签必过 → 到达 3b holder-of-key 闸)。
    // jkt 用真 RFC 7638 EC P-256 JWK thumbprint(SHA-256 of {"crv","kty","x","y"} 规范化,base64url),
    // 使测试贴近真实 DPoP-bound subject token(评审 codex Low:勿用非 thumbprint 占位串)。
    let subject_sc =
        sign_access_token_with_cnf("oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U").await;
    // actor 不带 DPoP 头 → 缺 proof。
    let form = format!(
        "grant_type={TE_GRANT}&subject_token={subject_sc}&subject_token_type={TT_ACCESS}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource={RS2}&scope=kb:read"
    );
    let (st, body) = post_te(&router, form).await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "入站带 cnf 的 subject_token + actor 无 proof MUST 拒(不静默降级为 bearer): {body}"
    );
    assert_eq!(body["error"], "invalid_dpop_proof");
}

// 快乐路径:subject_token(源 Grant fam-te,资源 RS2)+ grant_ref(Grant B,资源 RS_B)→ 换发 RS_B 的委托 token。
#[tokio::test]
async fn grant_ref_cross_grant_exchange_happy_path() {
    let (router, subject, actor, _refresh, grants, _id) = setup_token_exchange().await;
    seed_grant_b(&grants).await;
    let gref = sign_grant_ref_test("grant-b", "wl-actor", "grant-ref+jwt", far_exp()).await;
    // 目标 resource=RS_B(Grant B 的资源,不在源 Grant fam-te 的 RS2 里)——靠 grant_ref 跨 Grant 换发。
    let form = format!(
        "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &grant_ref={gref}&resource={RS_B}&scope=kb:read"
    );
    let (st, body) = post_te(&router, form).await;
    assert_eq!(st, StatusCode::OK, "grant_ref 跨 Grant 换发应成功: {body}");
    let at = body["access_token"].as_str().expect("含委托 token");
    let c: serde_json::Value =
        serde_json::from_slice(&B64.decode(at.split('.').nth(1).unwrap()).unwrap()).unwrap();
    assert_eq!(
        c["aud"],
        serde_json::json!([RS_B]),
        "aud=grant_ref 选中 Grant B 的资源 RS_B"
    );
    assert_eq!(
        c["scope"], "kb:read",
        "scope 必须是 Grant B 允许集合的请求子集"
    );
    // Q5:auth_grant 指向选中 Grant B(非源 family fam-te)。
    let ns = &c["https://a-auth.com/c"];
    assert_eq!(
        ns["auth_grant"], "grant-b",
        "Q5:auth_grant 指向 grant_ref 选中 Grant(非源 family)"
    );
}

#[tokio::test]
async fn grant_ref_stale_selected_grant_epoch_rejected() {
    use agent_auth_http::ports::GrantStore;

    let (router, subject, actor, _refresh, grants, _id) = setup_token_exchange().await;
    seed_grant_b(&grants).await;
    let mut stale = grants.get("", "grant-b").await.unwrap().unwrap();
    stale.credential_epoch = 1;
    grants.put("", stale).await.unwrap();

    let gref = sign_grant_ref_test("grant-b", "wl-actor", "grant-ref+jwt", far_exp()).await;
    let form = format!(
        "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &grant_ref={gref}&resource={RS_B}&scope=kb:read"
    );
    let (status, body) = post_te(&router, form).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant");
}

// 攻击①:grant_ref 泄露被他人兑换 —— bound_agent=别的 agent,出示者=wl-actor → 绑定闸拒。
#[tokio::test]
async fn grant_ref_leaked_wrong_actor_rejected() {
    let (router, subject, actor, _refresh, grants, _id) = setup_token_exchange().await;
    seed_grant_b(&grants).await;
    // grant_ref 绑给 "other-agent",但出示者(actor_token)是 wl-actor。
    let gref = sign_grant_ref_test("grant-b", "other-agent", "grant-ref+jwt", far_exp()).await;
    let form = format!(
        "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &grant_ref={gref}&resource={RS_B}&scope=kb:read"
    );
    let (st, body) = post_te(&router, form).await;
    assert_eq!(
        st,
        StatusCode::FORBIDDEN,
        "泄露 grant_ref 被他人兑换应拒(绑定闸): {body}"
    );
    assert_eq!(body["error"], "access_denied");
}

// 攻击②:过期 grant_ref → 验签时效拒(短时自焚)。
#[tokio::test]
async fn grant_ref_expired_rejected() {
    let (router, subject, actor, _refresh, grants, _id) = setup_token_exchange().await;
    seed_grant_b(&grants).await;
    let past = agent_auth_http::current_unix_secs() - 120; // 超 30s 时钟偏移容忍(DEFAULT_CLOCK_SKEW_SECS)
    let gref = sign_grant_ref_test("grant-b", "wl-actor", "grant-ref+jwt", past).await;
    let form = format!(
        "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &grant_ref={gref}&resource={RS_B}&scope=kb:read"
    );
    let (st, _body) = post_te(&router, form).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "过期 grant_ref 应拒");
}

// 攻击③:typ 混淆 —— 用 at+jwt(access token typ)冒充 grant-ref → 专用 verifier 拒。
#[tokio::test]
async fn grant_ref_wrong_typ_rejected() {
    let (router, subject, actor, _refresh, grants, _id) = setup_token_exchange().await;
    seed_grant_b(&grants).await;
    let gref = sign_grant_ref_test("grant-b", "wl-actor", "at+jwt", far_exp()).await; // 错 typ
    let form = format!(
        "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &grant_ref={gref}&resource={RS_B}&scope=kb:read"
    );
    let (st, _body) = post_te(&router, form).await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "typ 混淆(at+jwt 冒充 grant-ref)应拒"
    );
}

// C7.7:合法 grant-ref 只能放在独立 grant_ref 槽,不能作为 subject access token 或 actor JWT 泛用。
#[tokio::test]
async fn grant_ref_cannot_be_reused_as_subject_or_actor_bearer() {
    let (router, subject, actor, _refresh, grants, _id) = setup_token_exchange().await;
    seed_grant_b(&grants).await;
    let gref = sign_grant_ref_test("grant-b", "wl-actor", "grant-ref+jwt", far_exp()).await;

    let as_subject = format!(
        "grant_type={TE_GRANT}&subject_token={gref}&subject_token_type={TT_ACCESS}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource={RS_B}&scope=kb:read"
    );
    let (status, body) = post_te(&router, as_subject).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["error"], "invalid_grant",
        "grant-ref+jwt 不得通过 at+jwt subject verifier"
    );

    let as_actor = format!(
        "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
         &actor_token={gref}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource={RS_B}&scope=kb:read"
    );
    let (status, body) = post_te(&router, as_actor).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(
        body["error"], "invalid_client",
        "grant-ref+jwt 不得通过 workload actor verifier"
    );

    // Use access-shaped claims so typ is the only remaining discriminator at a real Bearer endpoint.
    let userinfo_ref = sign_grant_ref_test_with_extra_claims(
        "grant-b",
        "wl-actor",
        "grant-ref+jwt",
        far_exp(),
        serde_json::json!({
            "sub": "alice",
            "aud": [format!("https://{HOST}/userinfo")],
            "client_id": "app-3lo",
            "scope": "openid",
            "https://a-auth.com/c": {
                "sub_type": "user",
                "auth_grant": "grant-b"
            }
        }),
    )
    .await;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/userinfo")
                .header("host", HOST)
                .header("authorization", format!("Bearer {userinfo_ref}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "access-shaped grant-ref+jwt must be rejected by a real Bearer consumer on typ"
    );

    let introspection_ref = sign_grant_ref_test_with_extra_claims(
        "grant-b",
        "wl-actor",
        "grant-ref+jwt",
        far_exp(),
        serde_json::json!({
            "sub": "alice",
            "aud": [RS2],
            "client_id": "app-3lo",
            "scope": "kb:read",
            "https://a-auth.com/c": {
                "sub_type": "user",
                "auth_grant": "grant-b"
            }
        }),
    )
    .await;
    assert_eq!(
        introspect_rs2(&router, &introspection_ref).await,
        serde_json::json!({"active": false}),
        "introspection must reject access-shaped grant-ref+jwt on typ"
    );
}

// 攻击④:归属闸 —— grant_ref 指向他人 Grant(user=mallory),subject_token 证明的是 alice → 拒。
#[tokio::test]
async fn grant_ref_cross_user_stitch_rejected() {
    use agent_auth_http::ports::GrantStore;
    let (router, subject, actor, _refresh, grants, _id) = setup_token_exchange().await;
    // Grant C 属 mallory(非 subject_token 的 alice)。
    GrantStore::put(
        grants.as_ref(),
        "",
        agent_auth_grant::Grant {
            grant_id: "grant-c-mallory".into(),
            user_id: "mallory".into(),
            client_id: "app-3lo".into(),
            per_resource: vec![agent_auth_grant::ResourceGrant {
                resource: RS_B.to_string(),
                scopes: vec!["kb:read".into()],
                authorization_details: vec![],
            }],
            effective_per_resource: vec![],
            effective_pv: 0,
            allowed_ip_cidrs: vec![],
            allowed_vpce: vec![],
            credential_epoch: 0,
            revision: 0,
            constraints: agent_auth_grant::GrantConstraints {
                max_act_chain: 1,
                actor_allowlist: vec!["wl-actor".into()],
                expires_at: 4_000_000_000,
            },
            status: agent_auth_grant::GrantStatus::Active,
        },
    )
    .await
    .unwrap();
    let gref = sign_grant_ref_test("grant-c-mallory", "wl-actor", "grant-ref+jwt", far_exp()).await;
    let form = format!(
        "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &grant_ref={gref}&resource={RS_B}&scope=kb:read"
    );
    let (st, body) = post_te(&router, form).await;
    assert_eq!(
        st,
        StatusCode::FORBIDDEN,
        "他人 id_token + 自己 grant_ref 拼接应拒(归属闸): {body}"
    );
    assert_eq!(body["error"], "access_denied");
}

// 攻击⑤(评审 Kiro M-1):选中 Grant 覆盖后,scope MUST 恒 ⊆ **选中 Grant**——grant_ref 指向 Grant B
// (仅授 kb:read),请求 kb:write → 拒(挡"grant_ref 换发时用源 family scope 校验"的扩权错位)。
#[tokio::test]
async fn grant_ref_exceeds_selected_grant_scope_rejected() {
    let (router, subject, actor, _refresh, grants, _id) = setup_token_exchange().await;
    seed_grant_b(&grants).await; // Grant B 仅授 RS_B 的 kb:read
    let gref = sign_grant_ref_test("grant-b", "wl-actor", "grant-ref+jwt", far_exp()).await;
    let form = format!(
        "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &grant_ref={gref}&resource={RS_B}&scope=kb:write"
    );
    let (st, body) = post_te(&router, form).await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "请求 scope 超出**选中 Grant B** 应拒(scope⊆选中Grant,非源family): {body}"
    );
    assert_eq!(body["error"], "invalid_scope");
}

// 攻击⑥(评审 Kiro M-2):选中 Grant 覆盖后,resource MUST ∈ **选中 Grant**——grant_ref 指向 Grant B
// (仅授 RS_B),却请求源 Grant fam-te 的 RS2 → 拒(否则借 grant_ref 触及选中 Grant 未授权的 resource)。
#[tokio::test]
async fn grant_ref_wrong_resource_rejected() {
    let (router, subject, actor, _refresh, grants, _id) = setup_token_exchange().await;
    seed_grant_b(&grants).await; // Grant B 仅授 RS_B
    let gref = sign_grant_ref_test("grant-b", "wl-actor", "grant-ref+jwt", far_exp()).await;
    let form = format!(
        "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &grant_ref={gref}&resource={RS2}&scope=kb:read"
    );
    let (st, body) = post_te(&router, form).await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "请求**选中 Grant B** 未授权的 resource(RS2 仅在源 family)应拒: {body}"
    );
    assert_eq!(body["error"], "invalid_target");
}

// ============================================================================
// spec 011 §7.2:DPoP 委托 token cnf 继承(RFC 9449 §5,C7.9,P3;双评审收敛)
// ----------------------------------------------------------------------------
// 核心口径:委托 token 的 cnf.jkt **重绑到发起 actor 自己出示的 DPoP proof key**(非双绑、不含入站
// subject_token 的 user key)。入站 subject_token 带 cnf 时 **MUST holder-of-key**:actor_jkt == 入站
// cnf.jkt(评审 codex High——否则窃到 DPoP-bound 入站 token 但**不持有其 key**者,可用自己 key 把它洗成
// 新委托 token = holder-of-key 降级)。require_dpop 的 actor:MUST 出示 proof(能力解锁,非一律拒;M4)。
// ============================================================================

use p256::ecdsa::{signature::Signer as _, Signature as P256Sig, SigningKey};

const TE_HTU: &str = "https://localhost/token"; // token-exchange 也是 POST /token,htu = <issuer>/token

fn te_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

// EC P-256 keypair + 其公钥 jwk(x/y base64url)。
fn te_dpop_keypair(seed: u8) -> (SigningKey, serde_json::Value) {
    let sk = SigningKey::from_bytes(&[seed; 32].into()).unwrap();
    let vk = sk.verifying_key();
    let ep = vk.to_encoded_point(false);
    let x = B64.encode(ep.x().unwrap());
    let y = B64.encode(ep.y().unwrap());
    (
        sk,
        serde_json::json!({ "kty": "EC", "crv": "P-256", "x": x, "y": y }),
    )
}

// 签一枚 DPoP proof(htm=POST,htu=token endpoint)。
fn te_make_proof(sk: &SigningKey, jwk: &serde_json::Value, jti: &str) -> String {
    let header = serde_json::json!({ "typ": "dpop+jwt", "alg": "ES256", "jwk": jwk });
    let claims = serde_json::json!({ "htu": TE_HTU, "htm": "POST", "iat": te_now(), "jti": jti });
    let h = B64.encode(serde_json::to_vec(&header).unwrap());
    let c = B64.encode(serde_json::to_vec(&claims).unwrap());
    let si = format!("{h}.{c}");
    let sig: P256Sig = sk.sign(si.as_bytes());
    format!("{si}.{}", B64.encode(sig.to_bytes()))
}

// jwk 的 RFC 7638 thumbprint(与 AS 内部 ec_thumbprint 一致)。
fn te_jkt(jwk: &serde_json::Value) -> String {
    B64.encode(agent_auth_infra_core::jwks::ec_thumbprint(
        "P-256",
        jwk["x"].as_str().unwrap(),
        jwk["y"].as_str().unwrap(),
    ))
}

// POST /token(token-exchange 或 code flow),可带 DPoP 头。
async fn post_token_dpop(
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

fn te_token_cnf(token: &str) -> Option<serde_json::Value> {
    let payload = token.split('.').nth(1)?;
    let c: serde_json::Value = serde_json::from_slice(&B64.decode(payload).ok()?).ok()?;
    c.get("cnf").cloned()
}

fn te_jti_of(tok: &str) -> String {
    let payload = tok.split('.').nth(1).unwrap();
    let c: serde_json::Value = serde_json::from_slice(&B64.decode(payload).unwrap()).unwrap();
    c["jti"].as_str().unwrap().to_string()
}

// 自成一体的 §7.2 装配(不动既有 20+ setup_token_exchange 调用方):
// - actor `wl-actor`(可配 require_dpop)+ OIDC 信任绑定 + JWKS;
// - Grant 前身 family `fam-te`(actor_allowlist=[wl-actor],resources=[RS2],user=alice)+ 正式 Grant;
// - subject_token 走 code flow 铸,`subject_dpop=Some((sk,jwk))` 时**带 DPoP proof** → 入站带 cnf.jkt。
// 返回 (router, subject_token, actor_jwt)。
async fn setup_te_dpop(
    actor_require_dpop: bool,
    subject_dpop: Option<(&SigningKey, &serde_json::Value)>,
) -> (axum::Router, String, String) {
    use agent_auth_http::ports::ClientStore;

    // Phase::P3:DPoP 是 P3 能力(discovery 宣告 + 启动守卫强制 replay_store 均 P3;dpop_e2e 亦 P3)。
    // token-exchange 自 P2 起受理,P3 仍受理,故 §7.2 DPoP 委托测试跑 P3 与真实部署对齐(评审 Kiro M)。
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P3;
    // 1. workload actor + OIDC 信任 + JWKS。
    state
        .seed_workload_client_with_policy("wl-actor", vec![RS2.to_string()], vec![])
        .await;
    // actor require_dpop:回读 record 改写 require_dpop 再 put(seed 默认 false)。
    if actor_require_dpop {
        let mut rec = ClientStore::get(state.clients.as_ref(), "", "wl-actor")
            .await
            .unwrap()
            .unwrap();
        rec.require_dpop = true;
        ClientStore::put(state.clients.as_ref(), "", rec)
            .await
            .unwrap();
    }
    let _ = state
        .workload_trust
        .put(
            "",
            "b-te".into(),
            TrustBinding {
                tenant_id: "default".into(),
                mechanism: TrustMechanism::Oidc {
                    platform_issuer: PLATFORM_ISS.into(),
                    jwks_uri: JWKS_URI.into(),
                    subject_pattern: "repo:acme/actor:*".into(),
                },
                mapped_client_id: "wl-actor".into(),
            },
        )
        .await;
    let real_now = te_now();
    let (actor_jwt, jwk) = make_platform_jwt(
        "ka",
        serde_json::json!({
            "iss": PLATFORM_ISS, "sub": "repo:acme/actor:ref:main",
            "aud": format!("https://{HOST}"), "iat": real_now, "exp": real_now + 300,
        }),
    );
    let fetcher = agent_auth_http::adapters::memory::MemoryJwksFetcher::default();
    fetcher.set(JWKS_URI, vec![jwk]).await;
    state.jwks_fetcher = Arc::new(JwksFetcherImpl::Memory(fetcher));

    // 2. Grant 前身 family + 正式 Grant(actor_allowlist=[wl-actor],RS2/kb:read,user=alice)。
    let _ = state
        .refresh
        .create(
            "",
            RefreshFamilyRecord {
                family_id: "fam-te".into(),
                current_version: 0,
                revoked: false,
                client_id: "app-3lo".into(),
                cimd_snapshot: None,
                user_id: "alice".into(),
                credential_epoch: 0,
                resources: vec![RS2.to_string()],
                scope: vec!["kb:read".into()],
                actor_allowlist: vec!["wl-actor".into()],
                max_act_chain: 1,
                dpop_jkt: None,
                pkce_code_challenge: None,
                auth_time: None,
                acr: None,
                password_credential_version: None,
            },
        )
        .await;
    let _ = agent_auth_http::ports::GrantStore::put(
        state.grants.as_ref(),
        "",
        agent_auth_grant::Grant {
            grant_id: "fam-te".into(),
            user_id: "alice".into(),
            client_id: "app-3lo".into(),
            per_resource: vec![agent_auth_grant::ResourceGrant {
                resource: RS2.to_string(),
                scopes: vec!["kb:read".into()],
                authorization_details: vec![],
            }],
            effective_per_resource: vec![],
            effective_pv: 0,
            allowed_ip_cidrs: vec![],
            allowed_vpce: vec![],
            credential_epoch: 0,
            revision: 0,
            constraints: agent_auth_grant::GrantConstraints {
                max_act_chain: 1,
                actor_allowlist: vec!["wl-actor".into()],
                expires_at: 4_000_000_000,
            },
            status: agent_auth_grant::GrantStatus::Active,
        },
    )
    .await;

    // 3. jti store + 3LO client(subject 走 code flow 铸)+ RS2 introspect 凭证(供 §5.4 cnf.jkt introspect 断言)。
    let jti_store = new_shared_jti_store();
    state.jti_store = Some(Arc::new(JtiStoreImpl::Memory(jti_store.clone())));
    state.seed_dev_client("app-3lo", REDIRECT_TE, None).await;
    state
        .seed_rs_introspect_client("rs2-introspect", "sekret-rs2", &[RS2])
        .await;
    let (router, _) = build_router(state);

    // 4. code flow 铸 subject_token(subject_dpop=Some → 带 DPoP proof,入站带 cnf.jkt)。
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = agent_auth_client::s256_challenge(verifier);
    let authz = format!(
        "/authorize?response_type=code&client_id=app-3lo&redirect_uri={REDIRECT_TE}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&login_user=alice"
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
    let loc = resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let code = loc
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap()
        .to_string();
    let tform = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}&redirect_uri={REDIRECT_TE}&client_id=app-3lo"
    );
    let subject_proof = subject_dpop.map(|(sk, jwk)| te_make_proof(sk, jwk, "sub-mint-jti"));
    let (st, body) = post_token_dpop(&router, &tform, subject_proof.as_deref()).await;
    assert_eq!(st, StatusCode::OK, "铸 subject_token 应成功: {body}");
    let subject_token = body["access_token"].as_str().unwrap().to_string();
    if subject_dpop.is_some() {
        assert!(
            te_token_cnf(&subject_token).is_some(),
            "DPoP subject_token 应带 cnf"
        );
    }

    // 5. subject 的 jti 映射改指 fam-te(user=alice,grant=fam-te)。
    let real_now2 = te_now();
    jti_store
        .put(agent_auth_http::ports::JtiRecord {
            jti: te_jti_of(&subject_token),
            tenant_id: "default".into(),
            user_id: "alice".into(),
            family_id: Some("fam-te".into()),
            grant_id: Some("fam-te".into()),
            expires_at: real_now2 + 900,
        })
        .await
        .unwrap();

    (router, subject_token, actor_jwt)
}

// 组 token-exchange form(可带 grant_ref 之外的标准委托参数)。
fn te_form(subject: &str, actor: &str) -> String {
    format!(
        "grant_type={TE_GRANT}&subject_token={subject}&subject_token_type={TT_ACCESS}\
         &actor_token={actor}&actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &resource={RS2}&scope=kb:read"
    )
}

// §7.2 ①:入站 DPoP-bound subject + actor 出示**同 key** proof → 委托 token 重绑该 key(holder-of-key
// 保持),token_type=DPoP。
#[tokio::test]
async fn te_dpop_rebind_same_key_succeeds() {
    let (sk, jwk) = te_dpop_keypair(21);
    let (router, subject, actor) = setup_te_dpop(false, Some((&sk, &jwk))).await;
    // actor 用**同一 key**(持有入站 token 的 key)出示 proof,jti 与铸 subject 时不同(防重放)。
    let proof = te_make_proof(&sk, &jwk, "act-same-key");
    let (st, body) = post_token_dpop(&router, &te_form(&subject, &actor), Some(&proof)).await;
    assert_eq!(
        st,
        StatusCode::OK,
        "入站 cnf + actor 同 key proof 应签出委托 token: {body}"
    );
    let at = body["access_token"].as_str().unwrap();
    assert_eq!(
        te_token_cnf(at).unwrap()["jkt"],
        te_jkt(&jwk),
        "委托 token cnf.jkt 重绑 actor(= 入站同一)key"
    );
    assert_eq!(
        body["token_type"], "DPoP",
        "DPoP 重绑委托 token 的 token_type=DPoP"
    );
}

// §7.2 ②(评审 codex High,holder-of-key):入站 DPoP-bound subject + actor 用**不同 key** proof → 拒。
// 挡"窃到入站 DPoP-bound token 但不持有其 key"者用自己 key 洗成新委托 token。
#[tokio::test]
async fn te_dpop_cross_key_rejected() {
    let (sk, jwk) = te_dpop_keypair(22);
    let (router, subject, actor) = setup_te_dpop(false, Some((&sk, &jwk))).await;
    // actor 用**另一把 key**(未持有入站 token 的 key)。
    let (sk2, jwk2) = te_dpop_keypair(23);
    let proof = te_make_proof(&sk2, &jwk2, "act-cross-key");
    let (st, body) = post_token_dpop(&router, &te_form(&subject, &actor), Some(&proof)).await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "入站 cnf + actor 跨 key(不持有入站 key)应拒: {body}"
    );
    assert_eq!(body["error"], "invalid_dpop_proof");
}

// §7.2 ③:入站 DPoP-bound subject + actor **无 proof** → 拒(不把 sender-constrained 链静默降级 bearer)。
#[tokio::test]
async fn te_dpop_inbound_cnf_no_proof_rejected() {
    let (sk, jwk) = te_dpop_keypair(24);
    let (router, subject, actor) = setup_te_dpop(false, Some((&sk, &jwk))).await;
    let (st, body) = post_token_dpop(&router, &te_form(&subject, &actor), None).await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "入站 cnf + actor 无 proof 应拒(不降级 bearer): {body}"
    );
    assert_eq!(body["error"], "invalid_dpop_proof");
}

// §7.2 ④:入站**无 cnf**(bearer subject)+ actor 出示 proof → opt-in sender-constrained,委托 token 绑
// actor key,token_type=DPoP。
#[tokio::test]
async fn te_no_inbound_cnf_actor_proof_opt_in_dpop() {
    let (router, subject, actor) = setup_te_dpop(false, None).await;
    let (sk, jwk) = te_dpop_keypair(25);
    let proof = te_make_proof(&sk, &jwk, "act-opt-in");
    let (st, body) = post_token_dpop(&router, &te_form(&subject, &actor), Some(&proof)).await;
    assert_eq!(
        st,
        StatusCode::OK,
        "bearer subject + actor proof 应 opt-in 绑 actor key: {body}"
    );
    let at = body["access_token"].as_str().unwrap();
    assert_eq!(
        te_token_cnf(at).unwrap()["jkt"],
        te_jkt(&jwk),
        "委托 token cnf.jkt = actor 自己 proof key"
    );
    assert_eq!(body["token_type"], "DPoP");
}

// §7.2 ⑤(回归):入站无 cnf + actor 无 proof → bearer 委托 token(现状,不变)。
#[tokio::test]
async fn te_no_cnf_no_proof_stays_bearer() {
    let (router, subject, actor) = setup_te_dpop(false, None).await;
    let (st, body) = post_token_dpop(&router, &te_form(&subject, &actor), None).await;
    assert_eq!(st, StatusCode::OK, "bearer 委托应成功: {body}");
    let at = body["access_token"].as_str().unwrap();
    assert!(te_token_cnf(at).is_none(), "无 cnf(bearer 委托 token)");
    assert_eq!(body["token_type"], "Bearer");
}

// §7.2 ⑥(M4/H2):require_dpop 的 actor **无 proof** → 拒(fail-closed,不换出无约束委托 token)。
#[tokio::test]
async fn te_require_dpop_actor_no_proof_rejected() {
    let (router, subject, actor) = setup_te_dpop(true, None).await;
    let (st, body) = post_token_dpop(&router, &te_form(&subject, &actor), None).await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "require_dpop actor 无 proof 应拒: {body}"
    );
    assert_eq!(body["error"], "invalid_dpop_proof");
}

#[tokio::test]
async fn te_require_dpop_constrained_subject_no_proof_rejected() {
    let (sk, jwk) = te_dpop_keypair(31);
    let (router, subject, actor) = setup_te_dpop(true, Some((&sk, &jwk))).await;
    let (st, body) = post_token_dpop(&router, &te_form(&subject, &actor), None).await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "require_dpop + 入站 cnf + actor 无 proof 必须拒且不得降级 bearer: {body}"
    );
    assert_eq!(body["error"], "invalid_dpop_proof");
    assert!(body.get("access_token").is_none());
}

// §7.2 ⑦(M4:require_dpop 义为"要求约束"非"禁止换发"):require_dpop actor **带 proof** →
// 换发解锁,委托 token 绑 actor key(bearer subject 无 holder-of-key 约束)。
#[tokio::test]
async fn te_require_dpop_actor_with_proof_succeeds() {
    let (router, subject, actor) = setup_te_dpop(true, None).await;
    let (sk, jwk) = te_dpop_keypair(26);
    let proof = te_make_proof(&sk, &jwk, "act-require");
    let (st, body) = post_token_dpop(&router, &te_form(&subject, &actor), Some(&proof)).await;
    assert_eq!(
        st,
        StatusCode::OK,
        "require_dpop actor 带 proof 应换发(能力解锁): {body}"
    );
    let at = body["access_token"].as_str().unwrap();
    assert_eq!(
        te_token_cnf(at).unwrap()["jkt"],
        te_jkt(&jwk),
        "委托 token 绑 actor key"
    );
    assert_eq!(body["token_type"], "DPoP");
}

// §7.2 ⑧(评审 Kiro Low,fail-closed 兜底):入站 cnf **无 jkt**(非 DPoP holder-of-key 约束结构)+
// actor 出示合法 proof → 仍拒(cnf.get("jkt").as_str()==None 落拒绝臂,不当作可重绑)。3b holder-of-key
// 闸在 jti 解析(step 4)**之前**,故 subject 无需 jti 映射即在 3b 拒;现实不可达(本 AS 只写规范
// cnf.jkt),锁死"cnf 存在即触发 holder-of-key,jkt 缺失一律拒"兜底。
#[tokio::test]
async fn te_dpop_inbound_cnf_without_jkt_rejected() {
    // 自造带**畸形 cnf**(无 jkt)的合法 AS 签发 access token 作 subject_token(验签必过 → 到 3b)。
    let (router, _subject, actor) = setup_te_dpop(false, None).await;
    let subject_bad_cnf = sign_access_token_with_raw_cnf(serde_json::json!({ "foo": "bar" })).await;
    let (sk, jwk) = te_dpop_keypair(27);
    let proof = te_make_proof(&sk, &jwk, "act-badcnf");
    let (st, body) =
        post_token_dpop(&router, &te_form(&subject_bad_cnf, &actor), Some(&proof)).await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "入站 cnf 无 jkt + actor proof 应拒(cnf 存在即须 holder-of-key,jkt 缺失一律拒): {body}"
    );
    assert_eq!(body["error"], "invalid_dpop_proof");
}

// §7.2 ⑨(评审 Kiro Low):**require_dpop=true + 入站 DPoP-bound cnf + actor 跨 key** → 拒。holder-of-key
// 闸与 require_dpop 正交;此交叉组合(有意义的"错 key"场景)显式锁定。
#[tokio::test]
async fn te_require_dpop_inbound_cnf_cross_key_rejected() {
    let (sk, jwk) = te_dpop_keypair(28);
    let (router, subject, actor) = setup_te_dpop(true, Some((&sk, &jwk))).await;
    // actor(require_dpop)出示**另一把 key** 的合法 proof(不持有入站 token 的 key)。
    let (sk2, jwk2) = te_dpop_keypair(29);
    let proof = te_make_proof(&sk2, &jwk2, "act-req-cross");
    let (st, body) = post_token_dpop(&router, &te_form(&subject, &actor), Some(&proof)).await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "require_dpop + 入站 cnf + actor 跨 key 应拒(holder-of-key): {body}"
    );
    assert_eq!(body["error"], "invalid_dpop_proof");
}

// spec 010 §5.4 / Task 6.7 收尾(C8.7b,P3):**DPoP 委托 token 经 /introspect 回带 cnf.jkt**——RS 走
// introspection(非离线校验)时也能拿到 cnf.jkt 校 DPoP proof(SDK verify_dpop_proof,C8.9),与离线
// RS 能力对等。此前 6.7 的 cnf.jkt 部分被"DPoP 上线"阻塞;010 §5.2 直接 grant + 011 §7.2 委托 cnf 继承
// 落地后解除,补此 e2e 坐实 introspect if-present 回带对委托 token 的 cnf 也生效。
#[tokio::test]
async fn introspect_dpop_delegation_token_reflects_cnf_jkt() {
    let (sk, jwk) = te_dpop_keypair(30);
    let (router, subject, actor) = setup_te_dpop(false, Some((&sk, &jwk))).await;
    // 1. 换发 DPoP 委托 token(actor 同 key proof → cnf.jkt 重绑该 key)。
    let proof = te_make_proof(&sk, &jwk, "act-introspect");
    let (st, body) = post_token_dpop(&router, &te_form(&subject, &actor), Some(&proof)).await;
    assert_eq!(st, StatusCode::OK, "换发 DPoP 委托 token: {body}");
    let delegated = body["access_token"].as_str().expect("委托 token");
    assert_access_token_es256(delegated);
    assert_eq!(body["token_type"], "DPoP");
    let expected_jkt = te_jkt(&jwk);
    let issued_cnf = te_token_cnf(delegated).expect("已发行委托 token 必须含 cnf");
    assert_eq!(
        issued_cnf["jkt"], expected_jkt,
        "已发行委托 token 的 cnf.jkt 必须等于 actor proof key thumbprint"
    );

    // 2. RS2 凭证 introspect 该委托 token → active + 逐值回带已签 token 的 cnf。
    let basic = base64::engine::general_purpose::STANDARD.encode("rs2-introspect:sekret-rs2");
    let iform = format!("token={delegated}&client_id=rs2-introspect");
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/introspect")
                .header("host", HOST)
                .header("authorization", format!("Basic {basic}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(iform))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ibody = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let j: serde_json::Value = serde_json::from_slice(&ibody).unwrap();
    assert_eq!(j["active"], true, "DPoP 委托 token 应 active: {j}");
    assert_eq!(
        j["cnf"], issued_cnf,
        "introspect 必须逐值反射已签委托 token 的 cnf(C8.7b;RS 走 introspection 校 DPoP): {j}"
    );
}

// ============================================================================
// spec 012 §1.4:SPIFFE JWT-SVID via client_assertion(C5.7,双评审收敛)
// ----------------------------------------------------------------------------
// JWT-SVID 由 trust domain 签名 key 签(ES256,SPIRE 默认);sub=SPIFFE ID、aud=本 AS。信任锚 = 从 sub
// 解出的 trust domain(**绝不用 iss**)→ 该 trust bundle JWKS 本地验签 → 完整 SPIFFE ID 匹配绑定 → 签 2LO。
// 进程内 e2e:p256 铸 ES256 SVID + MemoryJwksFetcher 注入 EC bundle,无需真 SPIRE。
// ============================================================================

const SPIFFE_TD: &str = "acme.example";
const SPIFFE_SUB: &str = "spiffe://acme.example/agent/kb";
const SPIFFE_BUNDLE_URI: &str = "https://spire.acme.example/bundle";
const SPIRE_ISS: &str = "https://spire.acme.example"; // SPIRE server URL(≠trust domain,验证不以 iss 作锚)

// 用 EC P-256 keypair 签一枚 ES256 JWT-SVID,返回 (jwt, PlatformJwk[EC])。claims 由调用方给。
fn make_spiffe_svid(
    kid: &str,
    sk: &SigningKey,
    claims: serde_json::Value,
) -> (String, agent_auth_http::ports::PlatformJwk) {
    make_spiffe_svid_with_header(
        kid,
        sk,
        claims,
        serde_json::json!({ "alg": "ES256", "typ": "JWT", "kid": kid }),
    )
}

fn make_spiffe_svid_with_header(
    kid: &str,
    sk: &SigningKey,
    claims: serde_json::Value,
    header: serde_json::Value,
) -> (String, agent_auth_http::ports::PlatformJwk) {
    let vk = sk.verifying_key();
    let ep = vk.to_encoded_point(false);
    let x = B64.encode(ep.x().unwrap());
    let y = B64.encode(ep.y().unwrap());
    let h = B64.encode(serde_json::to_vec(&header).unwrap());
    let p = B64.encode(serde_json::to_vec(&claims).unwrap());
    let si = format!("{h}.{p}");
    let sig: P256Sig = sk.sign(si.as_bytes());
    let jwt = format!("{si}.{}", B64.encode(sig.to_bytes()));
    (
        jwt,
        agent_auth_http::ports::PlatformJwk {
            kid: Some(kid.to_string()),
            kty: Some("EC".into()),
            crv: Some("P-256".into()),
            x: Some(x),
            y: Some(y),
            alg: Some("ES256".into()),
            ..Default::default()
        },
    )
}

fn spiffe_claims(sub: &str, aud: serde_json::Value) -> serde_json::Value {
    let now = te_now();
    serde_json::json!({ "iss": SPIRE_ISS, "sub": sub, "aud": aud, "iat": now, "exp": now + 300 })
}

// 装配 P2 AppState:workload client(SPIFFE)+ SpiffeJwt 信任绑定 + bundle JWKS。返回 router。
// `bundle_jwk`=注入 SPIFFE_BUNDLE_URI 的 EC 公钥(SVID 验签锚);`pattern`=绑定的完整 SPIFFE ID pattern。
async fn setup_spiffe(
    bundle_jwk: agent_auth_http::ports::PlatformJwk,
    pattern: &str,
) -> axum::Router {
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P2;
    state
        .seed_workload_client_with_policy(
            "wl-spiffe",
            vec![RS2.to_string()],
            vec!["kb:read".into()],
        )
        .await;
    let _ = state
        .workload_trust
        .put(
            "",
            "b-spiffe".into(),
            TrustBinding {
                tenant_id: "default".into(),
                mechanism: TrustMechanism::SpiffeJwt {
                    trust_domain: SPIFFE_TD.into(),
                    jwks_uri: SPIFFE_BUNDLE_URI.into(),
                    spiffe_id_pattern: pattern.into(),
                },
                mapped_client_id: "wl-spiffe".into(),
            },
        )
        .await;
    let fetcher = agent_auth_http::adapters::memory::MemoryJwksFetcher::default();
    fetcher.set(SPIFFE_BUNDLE_URI, vec![bundle_jwk]).await;
    state.jwks_fetcher = Arc::new(JwksFetcherImpl::Memory(fetcher));
    build_router(state).0
}

fn spiffe_form(svid: &str) -> String {
    format!(
        "grant_type=client_credentials&client_assertion_type={JWT_BEARER}&client_assertion={svid}&resource={RS2}"
    )
}

// §1.4 ①:合法 ES256 JWT-SVID(sub=SPIFFE ID、aud=本 AS)→ 签 2LO(sub=映射 client_id、sub_type=agent、无 refresh)。
#[tokio::test]
async fn spiffe_jwt_svid_happy_path_es256() {
    let sk = SigningKey::from_bytes(&[41u8; 32].into()).unwrap();
    let (svid, bundle) = make_spiffe_svid(
        "sk1",
        &sk,
        spiffe_claims(SPIFFE_SUB, serde_json::json!(format!("https://{HOST}"))),
    );
    let router = setup_spiffe(bundle, "spiffe://acme.example/agent/*").await;
    let (st, body) = post_2lo(&router, spiffe_form(&svid)).await;
    assert_eq!(st, StatusCode::OK, "合法 ES256 SVID 应签出 2LO: {body}");
    let at = body["access_token"].as_str().expect("含 access_token");
    assert!(body.get("refresh_token").is_none(), "2LO 不发 refresh");
    let payload = at.split('.').nth(1).unwrap();
    let c: serde_json::Value = serde_json::from_slice(&B64.decode(payload).unwrap()).unwrap();
    assert_eq!(c["sub"], "wl-spiffe", "2LO sub=映射 client_id");
    assert_eq!(c["aud"], serde_json::json!([RS2]));
    assert_eq!(
        c["https://a-auth.com/c"]["sub_type"], "agent",
        "workload=agent"
    );
}

#[tokio::test]
async fn spiffe_jwt_svid_jose_typ_happy_path() {
    let sk = SigningKey::from_bytes(&[41u8; 32].into()).unwrap();
    let claims = spiffe_claims(SPIFFE_SUB, serde_json::json!(format!("https://{HOST}")));
    let (svid, bundle) = make_spiffe_svid_with_header(
        "sk1",
        &sk,
        claims,
        serde_json::json!({ "alg": "ES256", "typ": "JOSE", "kid": "sk1" }),
    );
    let router = setup_spiffe(bundle, "spiffe://acme.example/agent/*").await;
    let (st, body) = post_2lo(&router, spiffe_form(&svid)).await;
    assert_eq!(
        st,
        StatusCode::OK,
        "SPIFFE JWT-SVID typ=JOSE is permitted: {body}"
    );
    assert!(body.get("access_token").is_some());
}

// §1.4 ②(PoP 根本断言):非 bundle key 签的 SVID → 验签失败拒。
#[tokio::test]
async fn spiffe_jwt_svid_wrong_key_rejected() {
    // 绑定注入的 bundle 是 key A 的公钥;SVID 用 key B 签 → 验签失败。
    let sk_a = SigningKey::from_bytes(&[41u8; 32].into()).unwrap();
    let (_svid_a, bundle_a) = make_spiffe_svid(
        "sk1",
        &sk_a,
        spiffe_claims(SPIFFE_SUB, serde_json::json!(format!("https://{HOST}"))),
    );
    let sk_b = SigningKey::from_bytes(&[42u8; 32].into()).unwrap();
    // key B 的 SVID 但 kid 冒充 sk1(选中 bundle 的 key A 公钥)→ 验签失败。
    let claims = spiffe_claims(SPIFFE_SUB, serde_json::json!(format!("https://{HOST}")));
    let (svid_b, _bundle_b) = make_spiffe_svid_with_header(
        "sk1",
        &sk_b,
        claims,
        serde_json::json!({
            "alg": "ES256",
            "typ": "JWT",
            "kid": "sk1",
            "jku": "https://attacker.example/jwks.json",
            "x5u": "https://attacker.example/cert.pem"
        }),
    );
    let router = setup_spiffe(bundle_a, "spiffe://acme.example/agent/*").await;
    let (st, body) = post_2lo(&router, spiffe_form(&svid_b)).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "非 bundle key 签应拒: {body}");
    assert_eq!(body["error"], "invalid_client");
}

// §1.4 ③:aud 非本 AS → 拒(绝不放宽)。
#[tokio::test]
async fn spiffe_jwt_svid_aud_not_this_as_rejected() {
    let sk = SigningKey::from_bytes(&[41u8; 32].into()).unwrap();
    let (svid, bundle) = make_spiffe_svid(
        "sk1",
        &sk,
        spiffe_claims(SPIFFE_SUB, serde_json::json!("https://other.example")),
    );
    let router = setup_spiffe(bundle, "spiffe://acme.example/agent/*").await;
    let (st, body) = post_2lo(&router, spiffe_form(&svid)).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "aud 非本 AS 应拒: {body}");
    assert_eq!(body["error"], "invalid_client");
}

// C5.7:SPIFFE JWT-SVID 的信任锚来自 sub 中的 trust domain，iss 不参与绑定选择。
#[tokio::test]
async fn spiffe_jwt_svid_issuer_is_not_the_trust_anchor() {
    let sk = SigningKey::from_bytes(&[41u8; 32].into()).unwrap();
    let now = te_now();
    let claims = serde_json::json!({
        "iss": "https://unrelated-issuer.example",
        "sub": SPIFFE_SUB,
        "aud": format!("https://{HOST}"),
        "iat": now,
        "exp": now + 300,
    });
    let (svid, bundle) = make_spiffe_svid("sk1", &sk, claims);
    let router = setup_spiffe(bundle, "spiffe://acme.example/agent/*").await;
    let (st, body) = post_2lo(&router, spiffe_form(&svid)).await;
    assert_eq!(
        st,
        StatusCode::OK,
        "unrelated iss must not replace the sub-derived SPIFFE trust anchor: {body}"
    );
    assert_eq!(
        body["access_token"]
            .as_str()
            .expect("successful SPIFFE exchange returns an access token")
            .split('.')
            .count(),
        3
    );
}

#[tokio::test]
async fn spiffe_jwt_svid_ambiguous_bindings_rejected() {
    let sk = SigningKey::from_bytes(&[41u8; 32].into()).unwrap();
    let (svid, bundle) = make_spiffe_svid(
        "sk1",
        &sk,
        spiffe_claims(SPIFFE_SUB, serde_json::json!(format!("https://{HOST}"))),
    );
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P2;
    for client_id in ["wl-spiffe-a", "wl-spiffe-b"] {
        state
            .seed_workload_client_with_policy(
                client_id,
                vec![RS2.to_string()],
                vec!["kb:read".into()],
            )
            .await;
    }
    for (binding_id, pattern, client_id) in [
        (
            "b-spiffe-prefix",
            "spiffe://acme.example/agent/*",
            "wl-spiffe-a",
        ),
        ("b-spiffe-exact", SPIFFE_SUB, "wl-spiffe-b"),
    ] {
        state
            .workload_trust
            .put(
                "",
                binding_id.to_string(),
                TrustBinding {
                    tenant_id: "default".into(),
                    mechanism: TrustMechanism::SpiffeJwt {
                        trust_domain: SPIFFE_TD.into(),
                        jwks_uri: SPIFFE_BUNDLE_URI.into(),
                        spiffe_id_pattern: pattern.into(),
                    },
                    mapped_client_id: client_id.into(),
                },
            )
            .await
            .unwrap();
    }
    let fetcher = agent_auth_http::adapters::memory::MemoryJwksFetcher::default();
    fetcher.set(SPIFFE_BUNDLE_URI, vec![bundle]).await;
    state.jwks_fetcher = Arc::new(JwksFetcherImpl::Memory(fetcher));
    let router = build_router(state).0;

    let (status, body) = post_2lo(&router, spiffe_form(&svid)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "overlapping SPIFFE bindings must fail closed: {body}"
    );
    assert_eq!(body["error"], "invalid_client");
    assert!(body.get("access_token").is_none());
}

// §1.4 ④:跨 trust domain(sub 的 td ≠ 绑定 td)→ 拒(无信任锚)。
#[tokio::test]
async fn spiffe_jwt_svid_cross_trust_domain_rejected() {
    let sk = SigningKey::from_bytes(&[41u8; 32].into()).unwrap();
    // SVID sub 是 evil.example 域;绑定只认 acme.example → 选不到绑定。
    let (svid, bundle) = make_spiffe_svid(
        "sk1",
        &sk,
        spiffe_claims(
            "spiffe://evil.example/agent/kb",
            serde_json::json!(format!("https://{HOST}")),
        ),
    );
    let router = setup_spiffe(bundle, "spiffe://acme.example/agent/*").await;
    let (st, body) = post_2lo(&router, spiffe_form(&svid)).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "跨 trust domain 应拒: {body}");
    assert_eq!(body["error"], "invalid_client");
}

// §1.4 ⑤:SPIFFE ID 不匹配绑定 pattern → 拒。
#[tokio::test]
async fn spiffe_jwt_svid_pattern_miss_rejected() {
    let sk = SigningKey::from_bytes(&[41u8; 32].into()).unwrap();
    // sub 是 /svc/db,绑定 pattern 只认 /agent/*。
    let (svid, bundle) = make_spiffe_svid(
        "sk1",
        &sk,
        spiffe_claims(
            "spiffe://acme.example/svc/db",
            serde_json::json!(format!("https://{HOST}")),
        ),
    );
    let router = setup_spiffe(bundle, "spiffe://acme.example/agent/*").await;
    let (st, body) = post_2lo(&router, spiffe_form(&svid)).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "pattern 不符应拒: {body}");
    assert_eq!(body["error"], "invalid_client");
}

// §1.4 ⑥:多段深路径 sub 命中 /agent/* pattern(固化"任意深度前缀"预期)。
#[tokio::test]
async fn spiffe_jwt_svid_deep_path_matches() {
    let sk = SigningKey::from_bytes(&[41u8; 32].into()).unwrap();
    let (svid, bundle) = make_spiffe_svid(
        "sk1",
        &sk,
        spiffe_claims(
            "spiffe://acme.example/agent/kb/sess-1",
            serde_json::json!(format!("https://{HOST}")),
        ),
    );
    let router = setup_spiffe(bundle, "spiffe://acme.example/agent/*").await;
    let (st, body) = post_2lo(&router, spiffe_form(&svid)).await;
    assert_eq!(st, StatusCode::OK, "多段深路径应命中 /agent/*: {body}");
}

// §1.4 ⑦(typ/iss 混淆):typ=at+jwt(本 AS access token 形态)→ ES256 验签器拒(spec 012:MUST NOT 接受 at+jwt)。
// 注:本 AS access token 的 typ=at+jwt;此处造一个 typ=at+jwt 的 SVID-ish token,断言不被当作合法 SVID。
#[tokio::test]
async fn spiffe_jwt_svid_at_jwt_typ_rejected() {
    let sk = SigningKey::from_bytes(&[41u8; 32].into()).unwrap();
    let (_ok_svid, bundle) = make_spiffe_svid(
        "sk1",
        &sk,
        spiffe_claims(SPIFFE_SUB, serde_json::json!(format!("https://{HOST}"))),
    );
    // 手造 typ=at+jwt 的 token(sub 仍是 SPIFFE ID,过分派;但 typ 冒充 access token)。
    let now = te_now();
    let header = serde_json::json!({ "alg": "ES256", "typ": "at+jwt", "kid": "sk1" });
    let claims = serde_json::json!({ "iss": SPIRE_ISS, "sub": SPIFFE_SUB, "aud": format!("https://{HOST}"), "iat": now, "exp": now + 300 });
    let h = B64.encode(serde_json::to_vec(&header).unwrap());
    let p = B64.encode(serde_json::to_vec(&claims).unwrap());
    let si = format!("{h}.{p}");
    let sig: P256Sig = sk.sign(si.as_bytes());
    let at_jwt_token = format!("{si}.{}", B64.encode(sig.to_bytes()));
    let router = setup_spiffe(bundle, "spiffe://acme.example/agent/*").await;
    let (st, body) = post_2lo(&router, spiffe_form(&at_jwt_token)).await;
    // verify_access_token 侧不涉;此处 SVID 路径应拒 at+jwt(与本 AS token typ 隔离)。
    assert_eq!(st, StatusCode::UNAUTHORIZED, "at+jwt typ 冒充应拒: {body}");
    assert_eq!(body["error"], "invalid_client");
}

// §1.4 ⑧:SVID 过期 → 拒(共享时间前置)。
#[tokio::test]
async fn spiffe_jwt_svid_expired_rejected() {
    let sk = SigningKey::from_bytes(&[41u8; 32].into()).unwrap();
    let now = te_now();
    let claims = serde_json::json!({ "iss": SPIRE_ISS, "sub": SPIFFE_SUB, "aud": format!("https://{HOST}"), "iat": now - 1000, "exp": now - 500 });
    let (svid, bundle) = make_spiffe_svid("sk1", &sk, claims);
    let router = setup_spiffe(bundle, "spiffe://acme.example/agent/*").await;
    let (st, body) = post_2lo(&router, spiffe_form(&svid)).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "过期 SVID 应拒: {body}");
    assert_eq!(body["error"], "invalid_client");
}

// §1.4 补(评审 codex/Kiro H1):typ=`AT+JWT`(大写变体)也应拒(typ 大小写不敏感,防绕过)。
#[tokio::test]
async fn spiffe_jwt_svid_uppercase_at_jwt_typ_rejected() {
    let sk = SigningKey::from_bytes(&[41u8; 32].into()).unwrap();
    let (_ok, bundle) = make_spiffe_svid(
        "sk1",
        &sk,
        spiffe_claims(SPIFFE_SUB, serde_json::json!(format!("https://{HOST}"))),
    );
    let now = te_now();
    // 大写 typ=AT+JWT(RFC 7515 typ 大小写不敏感 → 应等同 at+jwt 被拒)。
    let header = serde_json::json!({ "alg": "ES256", "typ": "AT+JWT", "kid": "sk1" });
    let claims = serde_json::json!({ "iss": SPIRE_ISS, "sub": SPIFFE_SUB, "aud": format!("https://{HOST}"), "iat": now, "exp": now + 300 });
    let h = B64.encode(serde_json::to_vec(&header).unwrap());
    let p = B64.encode(serde_json::to_vec(&claims).unwrap());
    let si = format!("{h}.{p}");
    let sig: P256Sig = sk.sign(si.as_bytes());
    let tok = format!("{si}.{}", B64.encode(sig.to_bytes()));
    let router = setup_spiffe(bundle, "spiffe://acme.example/agent/*").await;
    let (st, body) = post_2lo(&router, spiffe_form(&tok)).await;
    assert_eq!(
        st,
        StatusCode::UNAUTHORIZED,
        "AT+JWT(大写)typ 也应拒: {body}"
    );
    assert_eq!(body["error"], "invalid_client");
}

// §1.4 补(评审 codex M1):bundle JWK **同时带 RSA(n/e)与 EC(x/y)字段** → 畸形歧义,验签器 fail-closed 拒
//(不猜验签器,防 alg/kty 混淆诱导)。
#[tokio::test]
async fn spiffe_jwt_svid_mixed_field_jwk_rejected() {
    let sk = SigningKey::from_bytes(&[41u8; 32].into()).unwrap();
    let (svid, ec_bundle) = make_spiffe_svid(
        "sk1",
        &sk,
        spiffe_claims(SPIFFE_SUB, serde_json::json!(format!("https://{HOST}"))),
    );
    // 污染 bundle:在合法 EC key 上再塞 RSA n/e(混合字段)。
    let mut mixed = ec_bundle;
    mixed.n = "AQAB".into();
    mixed.e = "AQAB".into();
    let router = setup_spiffe(mixed, "spiffe://acme.example/agent/*").await;
    let (st, body) = post_2lo(&router, spiffe_form(&svid)).await;
    assert_eq!(
        st,
        StatusCode::UNAUTHORIZED,
        "混合 RSA+EC 字段 JWK 应 fail-closed 拒: {body}"
    );
    assert_eq!(body["error"], "invalid_client");
}

// §1.4 ⑨(评审 Kiro High):SVID nbf 未生效 → 拒(共享时间前置的 nbf 分支端到端验证)。
#[tokio::test]
async fn spiffe_jwt_svid_nbf_not_yet_valid_rejected() {
    let sk = SigningKey::from_bytes(&[41u8; 32].into()).unwrap();
    let now = te_now();
    // nbf 远超 now + skew(30s)→ 未生效拒。
    let claims = serde_json::json!({ "iss": SPIRE_ISS, "sub": SPIFFE_SUB, "aud": format!("https://{HOST}"), "iat": now, "nbf": now + 600, "exp": now + 900 });
    let (svid, bundle) = make_spiffe_svid("sk1", &sk, claims);
    let router = setup_spiffe(bundle, "spiffe://acme.example/agent/*").await;
    let (st, body) = post_2lo(&router, spiffe_form(&svid)).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "nbf 未生效 SVID 应拒: {body}");
    assert_eq!(body["error"], "invalid_client");
}

#[tokio::test]
async fn spiffe_jwt_svid_missing_iat_rejected() {
    let sk = SigningKey::from_bytes(&[41u8; 32].into()).unwrap();
    let now = te_now();
    let claims = serde_json::json!({
        "iss": SPIRE_ISS,
        "sub": SPIFFE_SUB,
        "aud": format!("https://{HOST}"),
        "exp": now + 300,
    });
    let (svid, bundle) = make_spiffe_svid("sk1", &sk, claims);
    let router = setup_spiffe(bundle, "spiffe://acme.example/agent/*").await;
    let (st, body) = post_2lo(&router, spiffe_form(&svid)).await;
    assert_eq!(
        st,
        StatusCode::UNAUTHORIZED,
        "SPIFFE JWT-SVID without iat must fail the shared lifetime gate: {body}"
    );
    assert_eq!(body["error"], "invalid_client");
    assert!(body.get("access_token").is_none());
}

// C5.7:SPIFFE JWT-SVID 复用平台断言的 1h 最长寿命闸，不能靠有效签名绕过。
#[tokio::test]
async fn spiffe_jwt_svid_overlong_lifetime_rejected() {
    let sk = SigningKey::from_bytes(&[41u8; 32].into()).unwrap();
    let now = te_now();
    let claims = serde_json::json!({
        "iss": SPIRE_ISS,
        "sub": SPIFFE_SUB,
        "aud": format!("https://{HOST}"),
        "iat": now,
        "exp": now + 3601,
    });
    let (svid, bundle) = make_spiffe_svid("sk1", &sk, claims);
    let router = setup_spiffe(bundle, "spiffe://acme.example/agent/*").await;
    let (st, body) = post_2lo(&router, spiffe_form(&svid)).await;
    assert_eq!(
        st,
        StatusCode::UNAUTHORIZED,
        "SPIFFE assertions longer than the shared one-hour limit must fail: {body}"
    );
    assert_eq!(body["error"], "invalid_client");
    assert!(body.get("access_token").is_none());
}

// §1.4 ⑩(评审 Kiro High):**RS256** JWT-SVID happy path(SPIRE 也支持 RS256;验 verify_with_platform_key
// 的 RSA 分支在 SPIFFE 路径生效)。用 make_platform_jwt 造 RSA key,但 claims 用 SPIFFE 形态。
#[tokio::test]
async fn spiffe_jwt_svid_rs256_happy_path() {
    let now = te_now();
    let claims = serde_json::json!({ "iss": SPIRE_ISS, "sub": SPIFFE_SUB, "aud": format!("https://{HOST}"), "iat": now, "exp": now + 300 });
    // make_platform_jwt 造 RS256 JWT + RSA PlatformJwk(kty=RSA)。
    let (svid, bundle) = make_platform_jwt("rsk1", claims);
    let router = setup_spiffe(bundle, "spiffe://acme.example/agent/*").await;
    let (st, body) = post_2lo(&router, spiffe_form(&svid)).await;
    assert_eq!(st, StatusCode::OK, "RS256 SVID 应签出 2LO: {body}");
    let at = body["access_token"].as_str().expect("含 access_token");
    let payload = at.split('.').nth(1).unwrap();
    let c: serde_json::Value = serde_json::from_slice(&B64.decode(payload).unwrap()).unwrap();
    assert_eq!(c["sub"], "wl-spiffe", "RS256 SVID 也映射到 client_id");
}

// §1.4 ⑪(评审 Kiro High,OIDC 重构回归):**EC(ES256)平台 OIDC token** 走 workload_oidc_jwt 路径 →
// 验 verify_with_platform_key 的 EC 分支在 OIDC(非 SPIFFE)路径生效(重构后新支持,防回归)。
#[tokio::test]
async fn client_credentials_ec_platform_token_happy() {
    // EC 平台:iss=PLATFORM_ISS(OIDC 按 iss 选绑定),sub=repo:acme/agent:*(非 SPIFFE,走 OIDC 路径)。
    let sk = SigningKey::from_bytes(&[55u8; 32].into()).unwrap();
    let now = te_now();
    let claims = serde_json::json!({
        "iss": PLATFORM_ISS, "sub": "repo:acme/agent:ref:main",
        "aud": format!("https://{HOST}"), "iat": now, "exp": now + 300,
    });
    // 复用 make_spiffe_svid 的 EC 签名机制(它只是 ES256 JWT 铸造器,claims 任意)。
    let (jwt, ec_jwk) = make_spiffe_svid("eck1", &sk, claims);
    // 装配 OIDC 绑定(iss=PLATFORM_ISS)+ 注入 EC bundle 到 JWKS_URI。
    let mut state = AppState::dev(HOST);
    state.phase = Phase::P2;
    state
        .seed_workload_client_with_policy("wl-gha", vec![RS.to_string()], vec!["kb:read".into()])
        .await;
    let _ = state
        .workload_trust
        .put(
            "",
            "b-ec".into(),
            TrustBinding {
                tenant_id: "default".into(),
                mechanism: TrustMechanism::Oidc {
                    platform_issuer: PLATFORM_ISS.into(),
                    jwks_uri: JWKS_URI.into(),
                    subject_pattern: "repo:acme/agent:*".into(),
                },
                mapped_client_id: "wl-gha".into(),
            },
        )
        .await;
    let fetcher = agent_auth_http::adapters::memory::MemoryJwksFetcher::default();
    fetcher.set(JWKS_URI, vec![ec_jwk]).await;
    state.jwks_fetcher = Arc::new(JwksFetcherImpl::Memory(fetcher));
    let router = build_router(state).0;
    let form = format!(
        "grant_type=client_credentials&client_assertion_type={JWT_BEARER}&client_assertion={jwt}&resource={RS}"
    );
    let (st, body) = post_2lo(&router, form).await;
    assert_eq!(
        st,
        StatusCode::OK,
        "EC(ES256)平台 OIDC token 应签出 2LO(重构后 EC 分支): {body}"
    );
    let at = body["access_token"].as_str().expect("含 access_token");
    let c: serde_json::Value =
        serde_json::from_slice(&B64.decode(at.split('.').nth(1).unwrap()).unwrap()).unwrap();
    assert_eq!(c["sub"], "wl-gha");
}
