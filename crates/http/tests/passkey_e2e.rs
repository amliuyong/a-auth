//! 进程内 e2e:WebAuthn passkey 登录仪式(spec 003 §3,C9.4)。**无需真/虚拟 authenticator**:
//! 测试内用 P-256 key 扮 authenticator——CBOR encode fmt=none attestation(注册)+ 签 assertion(认证),
//! 类比 federation_e2e 的 MemorySigner 造 JWT。
//!
//! 全链:passkey_enabled → magic-link 登录建会话 → register/begin → 造 attestation → register/finish 存凭证
//! → authenticate/begin(login_hint) → 造 assertion → authenticate/finish → 建 passkey 会话(amr=webauthn)。
//! + fail-closed:功能关 404、UV 缺拒、challenge 重放拒。

use agent_auth_authn::assurance::STRONG_ACR;
use agent_auth_http::ports::{
    CredentialChangeStart, PasskeyStore, PasswordStore, SessionRecord, SessionStore, UsersStore,
};
use agent_auth_http::security_event::{SecurityEventOutcome, SecurityEventStore};
use agent_auth_http::{build_router, AppState};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

const HOST: &str = "localhost";
const RP_ID: &str = "localhost";
const ORIGIN: &str = "https://localhost";
const SAAS_ZONE: &str = "aws.example.com";
const SAAS_CONTROL: &str = "c.aws.example.com";
const SAAS_T1: &str = "t1.aws.example.com";
const SAAS_T2: &str = "t2.aws.example.com";
const SAAS_EMAIL: &str = "shared-passkey@example.com";
const SAAS_ORIGIN_SECRET: &str = "test-cloudfront-origin-secret-32-bytes";

async fn app() -> (axum::Router, AppState) {
    let mut state = AppState::dev(HOST);
    state.passkey_enabled = true;
    for email in [
        "pk-user@example.com",
        "pk-uv@example.com",
        "pk-replay@example.com",
        "pk-reset@example.com",
        "pk-fence@example.com",
        "pk-register-race@example.com",
    ] {
        state.seed_dev_user(email).await;
    }
    let (r, _) = build_router(state.clone());
    (r, state)
}

async fn saas_app(tenant_partitioning: bool) -> (axum::Router, AppState) {
    let mut state = AppState::dev("unused.example.com");
    state.form = agent_auth_discovery::Form::Saas {
        zone: SAAS_ZONE.to_string(),
        control_host: SAAS_CONTROL.to_string(),
    };
    state.saas_tenants = std::sync::Arc::new(vec!["t1".to_string(), "t2".to_string()]);
    state.tenant_partitioning = tenant_partitioning;
    state.passkey_enabled = true;
    state.saas_origin_auth = std::sync::Arc::new(
        agent_auth_http::origin_auth::SaasOriginAuth::required(
            SAAS_ORIGIN_SECRET.to_string(),
            "test-cloudfront-secondary-origin-secret".to_string(),
        )
        .unwrap(),
    );
    state.web_base_url = format!("https://{SAAS_CONTROL}");
    state.seed_dev_user_in_tenant("t1", SAAS_EMAIL).await;
    state.seed_dev_user_in_tenant("t2", SAAS_EMAIL).await;
    let (router, _) = build_router(state.clone());
    (router, state)
}

fn set_cookie_val(resp: &axum::http::Response<Body>, name: &str) -> Option<String> {
    for hv in resp.headers().get_all(axum::http::header::SET_COOKIE) {
        let s = hv.to_str().ok()?;
        if let Some(rest) = s.strip_prefix(&format!("{name}=")) {
            return Some(rest.split(';').next().unwrap_or("").to_string());
        }
    }
    None
}

async fn body_json(resp: axum::http::Response<Body>) -> serde_json::Value {
    let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&b).unwrap_or(serde_json::Value::Null)
}

// magic-link 登录建会话(amr=email),返回 session cookie。
async fn login_session(router: &axum::Router, host: &str, email: &str) -> String {
    let body = serde_json::json!({ "email": email, "authorize_query": "" });
    let mut builder = Request::builder()
        .method("POST")
        .uri("/login/magic-link")
        .header("host", host)
        .header("content-type", "application/json");
    if host.ends_with(SAAS_ZONE) {
        builder = builder.header("x-agent-auth-origin-auth", SAAS_ORIGIN_SECRET);
    }
    let resp = router
        .clone()
        .oneshot(
            builder
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let nonce = set_cookie_val(&resp, "__Host-agent_auth_login_nonce").unwrap();
    let rbody = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let link = serde_json::from_slice::<serde_json::Value>(&rbody).unwrap()["dev_link"]
        .as_str()
        .unwrap()
        .to_string();
    let pq = link.split_once("/login/callback").unwrap().1.to_string();
    let mut builder = Request::builder()
        .uri(format!("/login/callback{pq}"))
        .header("host", host)
        .header("cookie", format!("__Host-agent_auth_login_nonce={nonce}"));
    if host.ends_with(SAAS_ZONE) {
        builder = builder.header("x-agent-auth-origin-auth", SAAS_ORIGIN_SECRET);
    }
    let resp = router
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    set_cookie_val(&resp, "__Host-agent_auth_session").unwrap()
}

// ---- mock authenticator(P-256)----

struct MockAuthenticator {
    key: SigningKey,
    pubkey_sec1: Vec<u8>, // 0x04‖X‖Y
}
impl MockAuthenticator {
    fn new() -> Self {
        let key = SigningKey::from_bytes(&[42u8; 32].into()).unwrap();
        let pubkey_sec1 = key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        Self { key, pubkey_sec1 }
    }
    fn cose(&self) -> Vec<u8> {
        let x = &self.pubkey_sec1[1..33];
        let y = &self.pubkey_sec1[33..65];
        let v = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Integer(1.into()),
                ciborium::value::Value::Integer(2.into()),
            ),
            (
                ciborium::value::Value::Integer(3.into()),
                ciborium::value::Value::Integer((-7).into()),
            ),
            (
                ciborium::value::Value::Integer((-1).into()),
                ciborium::value::Value::Integer(1.into()),
            ),
            (
                ciborium::value::Value::Integer((-2).into()),
                ciborium::value::Value::Bytes(x.to_vec()),
            ),
            (
                ciborium::value::Value::Integer((-3).into()),
                ciborium::value::Value::Bytes(y.to_vec()),
            ),
        ]);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&v, &mut out).unwrap();
        out
    }
    // authData:rpIdHash(32)+flags+signCount(4)[+AAGUID(16)+credIdLen(2)+credId+COSE(注册时)]。
    fn auth_data(&self, flags: u8, count: u32, cred_id: Option<&[u8]>) -> Vec<u8> {
        self.auth_data_for(RP_ID, flags, count, cred_id)
    }
    fn auth_data_for(&self, rp_id: &str, flags: u8, count: u32, cred_id: Option<&[u8]>) -> Vec<u8> {
        let mut ad = Vec::new();
        ad.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
        ad.push(flags);
        ad.extend_from_slice(&count.to_be_bytes());
        if let Some(cid) = cred_id {
            ad.extend_from_slice(&[0u8; 16]); // AAGUID
            ad.extend_from_slice(&(cid.len() as u16).to_be_bytes());
            ad.extend_from_slice(cid);
            ad.extend_from_slice(&self.cose());
        }
        ad
    }
    // fmt=none attestationObject(注册)。
    fn attestation(&self, flags: u8, count: u32, cred_id: &[u8]) -> Vec<u8> {
        self.attestation_for(RP_ID, flags, count, cred_id)
    }
    fn attestation_for(&self, rp_id: &str, flags: u8, count: u32, cred_id: &[u8]) -> Vec<u8> {
        let ad = self.auth_data_for(rp_id, flags, count, Some(cred_id));
        let v = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Text("fmt".into()),
                ciborium::value::Value::Text("none".into()),
            ),
            (
                ciborium::value::Value::Text("attStmt".into()),
                ciborium::value::Value::Map(vec![]),
            ),
            (
                ciborium::value::Value::Text("authData".into()),
                ciborium::value::Value::Bytes(ad),
            ),
        ]);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&v, &mut out).unwrap();
        out
    }
    // 签 assertion:sig over authData ‖ SHA256(clientDataJSON)。
    fn sign(&self, ad: &[u8], cdj: &[u8]) -> Vec<u8> {
        let mut signed = ad.to_vec();
        signed.extend_from_slice(&Sha256::digest(cdj));
        let sig: Signature = self.key.sign(&signed);
        sig.to_der().as_bytes().to_vec()
    }
}

fn cdj(typ: &str, challenge: &str) -> Vec<u8> {
    cdj_for(typ, challenge, ORIGIN)
}

fn cdj_for(typ: &str, challenge: &str, origin: &str) -> Vec<u8> {
    format!(r#"{{"type":"{typ}","challenge":"{challenge}","origin":"{origin}"}}"#).into_bytes()
}

async fn post_json(
    router: &axum::Router,
    uri: &str,
    cookie: Option<&str>,
    body: serde_json::Value,
) -> axum::http::Response<Body> {
    post_json_at_host(router, HOST, uri, cookie, body).await
}

async fn post_json_at_host(
    router: &axum::Router,
    host: &str,
    uri: &str,
    cookie: Option<&str>,
    body: serde_json::Value,
) -> axum::http::Response<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header("host", host)
        .header("x-agent-auth-origin-auth", SAAS_ORIGIN_SECRET)
        .header("content-type", "application/json");
    if let Some(c) = cookie {
        b = b.header("cookie", format!("__Host-agent_auth_session={c}"));
    }
    router
        .clone()
        .oneshot(
            b.body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn authenticate_begin(
    router: &axum::Router,
    host: &str,
    email: &str,
) -> axum::http::Response<Body> {
    router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/passkey/authenticate/begin?login_hint={email}"))
                .header("host", host)
                .header("x-agent-auth-origin-auth", SAAS_ORIGIN_SECRET)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn get_status(router: &axum::Router, cookie: Option<&str>) -> axum::http::Response<Body> {
    let mut b = Request::builder()
        .uri("/passkey/status")
        .header("host", HOST);
    if let Some(c) = cookie {
        b = b.header("cookie", format!("__Host-agent_auth_session={c}"));
    }
    router
        .clone()
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

// SelfHosted 的 API 与浏览器 SPA 分域时,WebAuthn 必须绑定浏览器 origin。
#[tokio::test]
async fn self_hosted_passkey_uses_browser_origin_behind_cloudfront() {
    const API_HOST: &str = "api-id.execute-api.us-east-1.amazonaws.com";
    const WEB_HOST: &str = "example.cloudfront.net";

    let mut state = AppState::dev(API_HOST);
    state.web_base_url = format!("https://{WEB_HOST}");
    state.passkey_enabled = true;
    state.seed_dev_user("pk-cloudfront@example.com").await;
    let (router, _) = build_router(state);
    let session = login_session(&router, API_HOST, "pk-cloudfront@example.com").await;

    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/passkey/register/begin")
                .header("host", API_HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["rp_id"], WEB_HOST);
}

#[tokio::test]
async fn saas_passkey_isolated_by_exact_tenant_rp_origin_challenge_and_store() {
    let (router, state) = saas_app(true).await;
    let auth = MockAuthenticator::new();
    let credential_bytes = b"saas-t1-passkey";
    let credential_id = B64.encode(credential_bytes);
    let session = login_session(&router, SAAS_T1, SAAS_EMAIL).await;

    let begin = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/passkey/register/begin")
                .header("host", SAAS_T1)
                .header("x-agent-auth-origin-auth", SAAS_ORIGIN_SECRET)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(begin.status(), StatusCode::OK);
    let begin_body = body_json(begin).await;
    assert_eq!(begin_body["rp_id"], SAAS_T1);
    let registration_challenge = begin_body["challenge"].as_str().unwrap().to_string();
    let registration_client_data = cdj_for(
        "webauthn.create",
        &registration_challenge,
        &format!("https://{SAAS_T1}"),
    );
    let registration = post_json_at_host(
        &router,
        SAAS_T1,
        "/passkey/register/finish",
        Some(&session),
        serde_json::json!({
            "challenge": registration_challenge,
            "client_data_json": B64.encode(registration_client_data),
            "attestation_object": B64.encode(
                auth.attestation_for(SAAS_T1, 0x45, 0, credential_bytes)
            ),
        }),
    )
    .await;
    assert_eq!(registration.status(), StatusCode::OK);
    assert!(state
        .passkeys
        .get("t1", &credential_id)
        .await
        .unwrap()
        .is_some());
    assert!(state
        .passkeys
        .get("t2", &credential_id)
        .await
        .unwrap()
        .is_none());

    let t2_begin = authenticate_begin(&router, SAAS_T2, SAAS_EMAIL).await;
    assert_eq!(t2_begin.status(), StatusCode::OK);
    let t2_begin_body = body_json(t2_begin).await;
    assert_eq!(t2_begin_body["rp_id"], SAAS_T2);
    assert_eq!(
        t2_begin_body["allow_credentials"],
        serde_json::json!([]),
        "tenant B must not enumerate tenant A credentials"
    );
    let t2_challenge = t2_begin_body["challenge"].as_str().unwrap().to_string();
    let forged_t2_authenticator_data = auth.auth_data_for(SAAS_T2, 0x05, 1, None);
    let forged_t2_client_data =
        cdj_for("webauthn.get", &t2_challenge, &format!("https://{SAAS_T2}"));
    let forged_t2_signature = auth.sign(&forged_t2_authenticator_data, &forged_t2_client_data);
    let cross_tenant = post_json_at_host(
        &router,
        SAAS_T2,
        "/passkey/authenticate/finish",
        None,
        serde_json::json!({
            "challenge": t2_challenge,
            "credential_id": credential_id,
            "client_data_json": B64.encode(forged_t2_client_data),
            "authenticator_data": B64.encode(forged_t2_authenticator_data),
            "signature": B64.encode(forged_t2_signature),
        }),
    )
    .await;
    assert_eq!(cross_tenant.status(), StatusCode::BAD_REQUEST);
    assert!(set_cookie_val(&cross_tenant, "__Host-agent_auth_session").is_none());
    assert_eq!(
        state
            .passkeys
            .get("t1", &credential_id)
            .await
            .unwrap()
            .unwrap()
            .sign_count,
        0,
        "tenant B denial must not update tenant A counter"
    );

    for invalid_host in [SAAS_ZONE, SAAS_CONTROL] {
        assert_eq!(
            authenticate_begin(&router, invalid_host, SAAS_EMAIL)
                .await
                .status(),
            StatusCode::BAD_REQUEST,
            "{invalid_host} must not become a WebAuthn RP"
        );
    }
    let direct_valid_tenant_spoof = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/passkey/authenticate/begin?login_hint={SAAS_EMAIL}"
                ))
                .header("host", SAAS_T1)
                .header("x-forwarded-host", SAAS_T2)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        direct_valid_tenant_spoof.status(),
        StatusCode::FORBIDDEN,
        "a valid tenant forwarded host without the CloudFront origin credential must fail"
    );
    let forged_forwarded_host = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/passkey/authenticate/begin?login_hint={SAAS_EMAIL}"
                ))
                .header("host", SAAS_T1)
                .header("x-forwarded-host", SAAS_ZONE)
                .header("x-agent-auth-origin-auth", SAAS_ORIGIN_SECRET)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(forged_forwarded_host.status(), StatusCode::BAD_REQUEST);

    let wrong_origin_begin = authenticate_begin(&router, SAAS_T1, SAAS_EMAIL).await;
    let wrong_origin_challenge = body_json(wrong_origin_begin).await["challenge"]
        .as_str()
        .unwrap()
        .to_string();
    let wrong_origin_authenticator_data = auth.auth_data_for(SAAS_T1, 0x05, 1, None);
    let wrong_origin_client_data = cdj_for(
        "webauthn.get",
        &wrong_origin_challenge,
        &format!("https://{SAAS_T2}"),
    );
    let wrong_origin_signature =
        auth.sign(&wrong_origin_authenticator_data, &wrong_origin_client_data);
    assert_eq!(
        post_json_at_host(
            &router,
            SAAS_T1,
            "/passkey/authenticate/finish",
            None,
            serde_json::json!({
                "challenge": wrong_origin_challenge,
                "credential_id": credential_id,
                "client_data_json": B64.encode(wrong_origin_client_data),
                "authenticator_data": B64.encode(wrong_origin_authenticator_data),
                "signature": B64.encode(wrong_origin_signature),
            }),
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );

    let registration_begin = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/passkey/register/begin")
                .header("host", SAAS_T1)
                .header("x-agent-auth-origin-auth", SAAS_ORIGIN_SECRET)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let registration_only_challenge = body_json(registration_begin).await["challenge"]
        .as_str()
        .unwrap()
        .to_string();
    let cross_ceremony_authenticator_data = auth.auth_data_for(SAAS_T1, 0x05, 1, None);
    let cross_ceremony_client_data = cdj_for(
        "webauthn.get",
        &registration_only_challenge,
        &format!("https://{SAAS_T1}"),
    );
    let cross_ceremony_signature = auth.sign(
        &cross_ceremony_authenticator_data,
        &cross_ceremony_client_data,
    );
    assert_eq!(
        post_json_at_host(
            &router,
            SAAS_T1,
            "/passkey/authenticate/finish",
            None,
            serde_json::json!({
                "challenge": registration_only_challenge,
                "credential_id": credential_id,
                "client_data_json": B64.encode(cross_ceremony_client_data),
                "authenticator_data": B64.encode(cross_ceremony_authenticator_data),
                "signature": B64.encode(cross_ceremony_signature),
            }),
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST,
        "registration challenge must not authorize authentication"
    );

    let t1_begin = authenticate_begin(&router, SAAS_T1, SAAS_EMAIL).await;
    let t1_challenge = body_json(t1_begin).await["challenge"]
        .as_str()
        .unwrap()
        .to_string();
    let t1_authenticator_data = auth.auth_data_for(SAAS_T1, 0x05, 1, None);
    let t1_client_data = cdj_for("webauthn.get", &t1_challenge, &format!("https://{SAAS_T1}"));
    let t1_signature = auth.sign(&t1_authenticator_data, &t1_client_data);
    let t1_payload = serde_json::json!({
        "challenge": t1_challenge,
        "credential_id": credential_id,
        "client_data_json": B64.encode(t1_client_data),
        "authenticator_data": B64.encode(t1_authenticator_data),
        "signature": B64.encode(t1_signature),
    });
    assert_eq!(
        post_json_at_host(
            &router,
            SAAS_T2,
            "/passkey/authenticate/finish",
            None,
            t1_payload.clone(),
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST,
        "tenant B must not consume tenant A challenge"
    );
    let successful_t1 = post_json_at_host(
        &router,
        SAAS_T1,
        "/passkey/authenticate/finish",
        None,
        t1_payload,
    )
    .await;
    assert_eq!(successful_t1.status(), StatusCode::OK);
    assert!(set_cookie_val(&successful_t1, "__Host-agent_auth_session").is_some());
}

#[tokio::test]
async fn saas_passkey_fails_closed_without_tenant_partitioning() {
    let (router, _) = saas_app(false).await;
    assert_eq!(
        authenticate_begin(&router, SAAS_T1, SAAS_EMAIL)
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

// 快乐路径全链:baseline magic-link → register → authenticate → canonical strong passkey 会话。
#[tokio::test]
async fn passkey_register_then_authenticate_end_to_end() {
    let (router, state) = app().await;
    let auth = MockAuthenticator::new();
    let cred_id = b"passkey-cred-e2e-1";
    let session = login_session(&router, HOST, "pk-user@example.com").await;
    let baseline_session = state
        .sessions
        .get("", &session)
        .await
        .unwrap()
        .expect("magic-link session");
    assert_eq!(
        baseline_session.acr, None,
        "magic-link uses the canonical missing-ACR baseline representation"
    );
    assert_eq!(baseline_session.amr, vec!["email"]);

    // 1. 注册前状态只返回最小配置摘要。
    let resp = get_status(&router, Some(&session)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        body_json(resp).await,
        serde_json::json!({ "configured": false, "count": 0 })
    );

    // 2. register/begin → challenge。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/passkey/register/begin")
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "已登录 register/begin 应 200"
    );
    let bj = body_json(resp).await;
    let reg_challenge = bj["challenge"].as_str().unwrap().to_string();
    assert_eq!(bj["user_verification"], "required", "MUST require UV");

    // 3. 造 fmt=none attestation(UP|UV|AT = 0x45)+ register/finish。
    let att = auth.attestation(0x45, 0, cred_id);
    let cdj_reg = cdj("webauthn.create", &reg_challenge);
    let resp = post_json(
        &router,
        "/passkey/register/finish",
        Some(&session),
        serde_json::json!({
            "challenge": reg_challenge,
            "client_data_json": B64.encode(&cdj_reg),
            "attestation_object": B64.encode(&att),
        }),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "register/finish 应成功存凭证"
    );
    assert_eq!(
        resp.headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json"),
        "openapi-fetch 要求成功响应为 JSON"
    );
    assert_eq!(body_json(resp).await["registered"], true);
    assert!(state
        .credential_audit
        .snapshot()
        .join("\n")
        .contains("action=register tenant= actor=user:pk-user@example.com kind=passkey target=new result=success"));

    // 4. 注册后状态更新,但不泄露 credential id 或公钥。
    let resp = get_status(&router, Some(&session)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        body_json(resp).await,
        serde_json::json!({ "configured": true, "count": 1 })
    );
    let last_login_before_passkey = state
        .users
        .get_by_id("", "user:pk-user@example.com")
        .await
        .unwrap()
        .unwrap()
        .last_login_at
        .expect("注册 passkey 前的 magic-link 登录应已有时间");

    // 5. authenticate/begin(login_hint)→ challenge + allowCredentials 含刚注册的。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/passkey/authenticate/begin?login_hint=pk-user@example.com")
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let aj = body_json(resp).await;
    let auth_challenge = aj["challenge"].as_str().unwrap().to_string();
    let cred_id_b64 = B64.encode(cred_id);
    assert!(
        aj["allow_credentials"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c.as_str() == Some(&cred_id_b64)),
        "allowCredentials 应含刚注册凭证"
    );

    // 6. 造 assertion(UP|UV=0x05,signCount 递增到 1)+ authenticate/finish。
    let ad = auth.auth_data(0x05, 1, None);
    let cdj_auth = cdj("webauthn.get", &auth_challenge);
    let sig = auth.sign(&ad, &cdj_auth);
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    let auth_payload = serde_json::json!({
        "challenge": auth_challenge,
        "credential_id": cred_id_b64,
        "client_data_json": B64.encode(&cdj_auth),
        "authenticator_data": B64.encode(&ad),
        "signature": B64.encode(&sig),
    });
    let resp = post_json(
        &router,
        "/passkey/authenticate/finish",
        None,
        auth_payload.clone(),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "authenticate/finish 应成功登入"
    );
    let passkey_session_id =
        set_cookie_val(&resp, "__Host-agent_auth_session").expect("应建 passkey 会话 cookie");
    let passkey_session = state
        .sessions
        .get("", &passkey_session_id)
        .await
        .unwrap()
        .expect("passkey session");
    assert_eq!(passkey_session.acr.as_deref(), Some(STRONG_ACR));
    assert_eq!(passkey_session.amr, vec!["webauthn", "hwk"]);
    assert_eq!(body_json(resp).await["authenticated"], true);
    assert!(
        state
            .users
            .get_by_id("", "user:pk-user@example.com")
            .await
            .unwrap()
            .unwrap()
            .last_login_at
            .is_some_and(|timestamp| timestamp > last_login_before_passkey),
        "passkey 成功建立会话后应推进最后登录时间"
    );
    assert_eq!(
        post_json(&router, "/passkey/authenticate/finish", None, auth_payload,)
            .await
            .status(),
        StatusCode::BAD_REQUEST,
        "consumed challenge replay must be denied"
    );
    let events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 500)
        .await
        .unwrap();
    assert!(events.iter().any(|stored| {
        stored.event.action == "authentication.passkey"
            && stored.event.outcome == SecurityEventOutcome::Success
    }));
    assert!(events.iter().any(|stored| {
        stored.event.action == "authentication.passkey"
            && stored.event.outcome == SecurityEventOutcome::Denied
    }));
    assert!(events.iter().any(|stored| {
        stored.event.action == "authentication.magic_link"
            && stored.event.outcome == SecurityEventOutcome::Success
    }));
}

#[tokio::test]
async fn passkey_registration_cannot_commit_after_user_epoch_changes() {
    let (router, state) = app().await;
    let auth = MockAuthenticator::new();
    let email = "pk-register-race@example.com";
    let user_id = format!("user:{email}");
    let session = login_session(&router, HOST, email).await;

    let begin = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/passkey/register/begin")
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(begin.status(), StatusCode::OK);
    let challenge = body_json(begin).await["challenge"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        state
            .users
            .begin_credential_change(
                "",
                &user_id,
                0,
                "registration-race-owner",
                agent_auth_http::current_unix_secs(),
            )
            .await
            .unwrap(),
        CredentialChangeStart::Started { epoch: 1 }
    );

    let credential_id = b"passkey-register-race";
    let response = post_json(
        &router,
        "/passkey/register/finish",
        Some(&session),
        serde_json::json!({
            "challenge": challenge,
            "client_data_json": B64.encode(cdj("webauthn.create", &challenge)),
            "attestation_object": B64.encode(auth.attestation(0x45, 0, credential_id)),
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(state
        .passkeys
        .get("", &B64.encode(credential_id))
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn passkey_cannot_create_session_while_admin_reset_is_pending() {
    let (router, state) = app().await;
    let auth = MockAuthenticator::new();
    let email = "pk-reset@example.com";
    let user_id = format!("user:{email}");
    let credential_id = B64.encode(b"passkey-reset-pending");
    assert!(state
        .passkeys
        .put_new(
            "",
            agent_auth_authn::passkey::PasskeyCredential {
                credential_id: credential_id.clone(),
                user_id: user_id.clone(),
                rp_id: RP_ID.to_string(),
                public_key_sec1: auth.pubkey_sec1.clone(),
                sign_count: 0,
                name: "Passkey".into(),
                created_at: 0,
            },
        )
        .await
        .unwrap());
    assert_eq!(
        state
            .passwords
            .reset_temporary(
                "",
                &user_id,
                agent_auth_authn::password::hash_password("Temporary reset password 123!").unwrap(),
                None,
                1,
            )
            .await
            .unwrap(),
        Some(1)
    );

    let begin = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/passkey/authenticate/begin?login_hint={email}"))
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(begin.status(), StatusCode::OK);
    let challenge = body_json(begin).await["challenge"]
        .as_str()
        .unwrap()
        .to_string();
    let authenticator_data = auth.auth_data(0x05, 1, None);
    let client_data_json = cdj("webauthn.get", &challenge);
    let signature = auth.sign(&authenticator_data, &client_data_json);
    let response = post_json(
        &router,
        "/passkey/authenticate/finish",
        None,
        serde_json::json!({
            "challenge": challenge,
            "credential_id": credential_id,
            "client_data_json": B64.encode(client_data_json),
            "authenticator_data": B64.encode(authenticator_data),
            "signature": B64.encode(signature),
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(set_cookie_val(&response, "__Host-agent_auth_session").is_none());
    assert_eq!(
        state
            .users
            .get_by_id("", &user_id)
            .await
            .unwrap()
            .unwrap()
            .last_login_at,
        None,
        "authority 回滚的 passkey 会话不得记录最后登录时间"
    );
    assert_eq!(
        state
            .sessions
            .count_by_user(
                "",
                &user_id,
                agent_auth_http::token::current_unix_secs_pub()
            )
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn passkey_cannot_create_session_while_credential_fence_is_pending() {
    let (router, state) = app().await;
    let auth = MockAuthenticator::new();
    let email = "pk-fence@example.com";
    let user_id = format!("user:{email}");
    let credential_id = B64.encode(b"passkey-user-fence");
    assert!(state
        .passkeys
        .put_new(
            "",
            agent_auth_authn::passkey::PasskeyCredential {
                credential_id: credential_id.clone(),
                user_id: user_id.clone(),
                rp_id: RP_ID.to_string(),
                public_key_sec1: auth.pubkey_sec1.clone(),
                sign_count: 0,
                name: "Passkey".into(),
                created_at: 0,
            },
        )
        .await
        .unwrap());
    let begin = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/passkey/authenticate/begin?login_hint={email}"))
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let challenge = body_json(begin).await["challenge"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        state
            .users
            .begin_credential_change(
                "",
                &user_id,
                0,
                "authentication-race-owner",
                agent_auth_http::current_unix_secs(),
            )
            .await
            .unwrap(),
        CredentialChangeStart::Started { epoch: 1 }
    );
    let authenticator_data = auth.auth_data(0x05, 1, None);
    let client_data_json = cdj("webauthn.get", &challenge);
    let signature = auth.sign(&authenticator_data, &client_data_json);

    let response = post_json(
        &router,
        "/passkey/authenticate/finish",
        None,
        serde_json::json!({
            "challenge": challenge,
            "credential_id": credential_id,
            "client_data_json": B64.encode(client_data_json),
            "authenticator_data": B64.encode(authenticator_data),
            "signature": B64.encode(signature),
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(set_cookie_val(&response, "__Host-agent_auth_session").is_none());
    assert_eq!(
        state
            .sessions
            .count_by_user(
                "",
                &user_id,
                agent_auth_http::token::current_unix_secs_pub()
            )
            .await
            .unwrap(),
        0
    );
}

// 功能关:所有 /passkey/* → 404(F10,不暴露不完整主认证面)。
#[tokio::test]
async fn passkey_endpoints_404_when_disabled() {
    let state = AppState::dev(HOST); // passkey_enabled=false 默认
    let (router, _) = build_router(state);
    // 用**格式合法**的 body(带各端点必填字段),使 axum 提取器通过 → 打到 handler 的 feature-gate
    // → 404(证 F10 门控本身,而非提取器 422)。
    for (m, uri, body) in [
        ("GET", "/passkey/status", ""),
        ("POST", "/passkey/register/begin", "{}"),
        (
            "POST",
            "/passkey/register/finish",
            r#"{"challenge":"c","client_data_json":"","attestation_object":""}"#,
        ),
        ("GET", "/passkey/authenticate/begin?login_hint=x@y.com", ""),
        (
            "POST",
            "/passkey/authenticate/finish",
            r#"{"challenge":"c","credential_id":"c","client_data_json":"","authenticator_data":"","signature":""}"#,
        ),
    ] {
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(m)
                    .uri(uri)
                    .header("host", HOST)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{uri} 功能关应 404");
    }
}

// status 是会话鉴权的账户接口,不能匿名枚举用户 passkey 配置。
#[tokio::test]
async fn passkey_status_requires_login() {
    let (router, _) = app().await;
    let resp = get_status(&router, None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// register/begin 未登录 → 401(不能匿名注册他人 passkey)。
#[tokio::test]
async fn passkey_register_requires_login() {
    let (router, _) = app().await;
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/passkey/register/begin")
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "未登录 register 应 401"
    );
}

#[tokio::test]
async fn passkey_registration_begin_and_finish_require_recent_reauthentication() {
    let (router, state) = app().await;
    let now = agent_auth_http::current_unix_secs();
    let user_id = "user:pk-user@example.com";
    let stale_session = "stale-passkey-registration";
    let credential_epoch = state
        .users
        .get_by_id("", user_id)
        .await
        .unwrap()
        .unwrap()
        .credential_epoch;
    state
        .sessions
        .create(
            "",
            SessionRecord {
                session_id: stale_session.to_string(),
                user_id: user_id.to_string(),
                credential_epoch,
                auth_time: now - 301,
                created_at: now - 301,
                last_used_at: now - 301,
                device: "Stale browser".to_string(),
                expires_at: now + 3_600,
                acr: None,
                amr: vec!["email".to_string()],
            },
        )
        .await
        .unwrap();

    let stale_begin = post_json(
        &router,
        "/passkey/register/begin",
        Some(stale_session),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(stale_begin.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(stale_begin).await["error"],
        "reauthentication_required"
    );

    let fresh_session = login_session(&router, HOST, "pk-user@example.com").await;
    let begin = post_json(
        &router,
        "/passkey/register/begin",
        Some(&fresh_session),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(begin.status(), StatusCode::OK);
    let challenge = body_json(begin).await["challenge"]
        .as_str()
        .unwrap()
        .to_string();
    let auth = MockAuthenticator::new();
    let body = serde_json::json!({
        "challenge": challenge,
        "client_data_json": B64.encode(cdj("webauthn.create", &challenge)),
        "attestation_object": B64.encode(auth.attestation(0x45, 0, b"reauth-passkey")),
    });

    let stale_finish = post_json(
        &router,
        "/passkey/register/finish",
        Some(stale_session),
        body.clone(),
    )
    .await;
    assert_eq!(stale_finish.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(stale_finish).await["error"],
        "reauthentication_required"
    );
    assert!(state
        .passkeys
        .list_by_user("", user_id)
        .await
        .unwrap()
        .is_empty());

    let fresh_finish = post_json(
        &router,
        "/passkey/register/finish",
        Some(&fresh_session),
        body,
    )
    .await;
    assert_eq!(
        fresh_finish.status(),
        StatusCode::OK,
        "stale finish must not consume the registration challenge"
    );
    assert_eq!(
        state
            .passkeys
            .list_by_user("", user_id)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn unknown_user_cannot_jit_through_passkey_endpoints() {
    let (router, state) = app().await;
    let auth = MockAuthenticator::new();
    for (email, user_id, credential_bytes) in [
        (
            "unknown-passkey@example.com",
            "user:unknown-passkey@example.com",
            b"unknown-passkey-credential".as_slice(),
        ),
        (
            "unknown-passkey-owner@example.com",
            "orphan-canonical-id",
            b"unknown-passkey-owner-credential".as_slice(),
        ),
    ] {
        let credential_id = B64.encode(credential_bytes);
        assert!(state
            .passkeys
            .put_new(
                "",
                agent_auth_authn::passkey::PasskeyCredential {
                    credential_id: credential_id.clone(),
                    user_id: user_id.to_string(),
                    rp_id: RP_ID.to_string(),
                    public_key_sec1: auth.pubkey_sec1.clone(),
                    sign_count: 0,
                    name: "Orphaned passkey".into(),
                    created_at: 0,
                },
            )
            .await
            .unwrap());

        let begin = authenticate_begin(&router, HOST, email).await;
        assert_eq!(begin.status(), StatusCode::OK);
        let begin = body_json(begin).await;
        assert_eq!(begin["allow_credentials"], serde_json::json!([]));
        let challenge = begin["challenge"].as_str().unwrap();
        let authenticator_data = auth.auth_data(0x05, 1, None);
        let client_data_json = cdj("webauthn.get", challenge);
        let signature = auth.sign(&authenticator_data, &client_data_json);

        let finish = post_json(
            &router,
            "/passkey/authenticate/finish",
            None,
            serde_json::json!({
                "challenge": challenge,
                "credential_id": credential_id,
                "client_data_json": B64.encode(client_data_json),
                "authenticator_data": B64.encode(authenticator_data),
                "signature": B64.encode(signature),
            }),
        )
        .await;
        assert_eq!(finish.status(), StatusCode::FORBIDDEN, "{user_id}");

        assert!(state.users.get_by_email("", email).await.unwrap().is_none());
        assert!(state.users.get_by_id("", user_id).await.unwrap().is_none());
        let passkeys = state.passkeys.list_by_user("", user_id).await.unwrap();
        assert_eq!(
            passkeys.len(),
            1,
            "authentication must not create a passkey"
        );
        assert_eq!(passkeys[0].credential_id, credential_id);
        assert_eq!(
            state
                .sessions
                .count_by_user("", user_id, agent_auth_http::token::current_unix_secs_pub())
                .await
                .unwrap(),
            0
        );
    }

    let active_email = "active-arbitrary-passkey@example.com";
    let active_user_id = "active-scim-canonical-id";
    let active_credential_bytes = b"active-arbitrary-owner-credential";
    let active_credential_id = B64.encode(active_credential_bytes);
    let now = agent_auth_http::current_unix_secs();
    state
        .users
        .create_or_get_by_email("", active_email, active_user_id, now)
        .await
        .unwrap();
    assert_eq!(
        state
            .users
            .begin_credential_change("", active_user_id, 0, "active-arbitrary-owner", now)
            .await
            .unwrap(),
        CredentialChangeStart::Started { epoch: 1 }
    );
    assert!(state
        .users
        .complete_credential_change(
            "",
            active_user_id,
            agent_auth_http::ports::CredentialChangeOwner {
                epoch: 1,
                operation_id: "active-arbitrary-owner",
            },
            now + 1,
        )
        .await
        .unwrap());
    assert!(state
        .passkeys
        .put_new(
            "",
            agent_auth_authn::passkey::PasskeyCredential {
                credential_id: active_credential_id.clone(),
                user_id: active_user_id.to_string(),
                rp_id: RP_ID.to_string(),
                public_key_sec1: auth.pubkey_sec1.clone(),
                sign_count: 0,
                name: "Active arbitrary owner passkey".into(),
                created_at: now,
            },
        )
        .await
        .unwrap());
    let begin = authenticate_begin(&router, HOST, active_email).await;
    assert_eq!(begin.status(), StatusCode::OK);
    let begin = body_json(begin).await;
    assert_eq!(
        begin["allow_credentials"],
        serde_json::json!([active_credential_id])
    );
    let challenge = begin["challenge"].as_str().unwrap();
    let authenticator_data = auth.auth_data(0x05, 1, None);
    let client_data_json = cdj("webauthn.get", challenge);
    let signature = auth.sign(&authenticator_data, &client_data_json);
    let finish = post_json(
        &router,
        "/passkey/authenticate/finish",
        None,
        serde_json::json!({
            "challenge": challenge,
            "credential_id": active_credential_id,
            "client_data_json": B64.encode(client_data_json),
            "authenticator_data": B64.encode(authenticator_data),
            "signature": B64.encode(signature),
        }),
    )
    .await;
    assert_eq!(
        finish.status(),
        StatusCode::OK,
        "an active arbitrary canonical ID must preserve its nonzero epoch"
    );
    assert!(set_cookie_val(&finish, "__Host-agent_auth_session").is_some());

    let register = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/passkey/register/begin")
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(register.status(), StatusCode::UNAUTHORIZED);
}

// UV 缺(register/finish 用 UP|AT=0x41 无 UV)→ 400(无密码主因子 MUST UV)。
#[tokio::test]
async fn passkey_register_uv_required() {
    let (router, state) = app().await;
    let auth = MockAuthenticator::new();
    let session = login_session(&router, HOST, "pk-uv@example.com").await;
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/passkey/register/begin")
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let challenge = body_json(resp).await["challenge"]
        .as_str()
        .unwrap()
        .to_string();
    let att = auth.attestation(0x41, 0, b"c-uv"); // UP|AT 无 UV
    let resp = post_json(
        &router,
        "/passkey/register/finish",
        Some(&session),
        serde_json::json!({
            "challenge": challenge,
            "client_data_json": B64.encode(cdj("webauthn.create", &challenge)),
            "attestation_object": B64.encode(&att),
        }),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "UV 缺应拒(无密码主因子 MUST UV)"
    );
    assert!(state
        .credential_audit
        .snapshot()
        .join("\n")
        .contains("action=register tenant= actor=user:pk-uv@example.com kind=passkey target=new result=denied"));
}

// challenge 重放:同 challenge 二次 register/finish → 400(一次性 consume)。
#[tokio::test]
async fn passkey_challenge_one_shot() {
    let (router, state) = app().await;
    let auth = MockAuthenticator::new();
    let session = login_session(&router, HOST, "pk-replay@example.com").await;
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/passkey/register/begin")
                .header("host", HOST)
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let challenge = body_json(resp).await["challenge"]
        .as_str()
        .unwrap()
        .to_string();
    let body = serde_json::json!({
        "challenge": challenge,
        "client_data_json": B64.encode(cdj("webauthn.create", &challenge)),
        "attestation_object": B64.encode(auth.attestation(0x45, 0, b"c-replay")),
    });
    let r1 = post_json(
        &router,
        "/passkey/register/finish",
        Some(&session),
        body.clone(),
    )
    .await;
    assert_eq!(r1.status(), StatusCode::OK, "首次注册成功");
    let r2 = post_json(&router, "/passkey/register/finish", Some(&session), body).await;
    assert_eq!(
        r2.status(),
        StatusCode::BAD_REQUEST,
        "同 challenge 二次 → 400(一次性 consume 防重放)"
    );
    assert!(state
        .credential_audit
        .snapshot()
        .join("\n")
        .contains("action=register tenant= actor=user:pk-replay@example.com kind=passkey target=new result=denied"));
}
