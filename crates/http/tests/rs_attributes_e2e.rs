//! 进程内 e2e:spec 007 RS 命名空间用户属性(§6.1,C8.11/C8.12)。
//!
//! 覆盖:
//! - 写(admin)→ 读(RS token,aud=namespace):读到属性 + sub 逐字节一致 + revision。
//! - 跨命名空间隔离:aud=RS-A 的 token 读不到 RS-B 命名空间(返空)。
//! - 反向隔离:aud=<issuer>/userinfo 的 token 调 /rs/attributes → 拒;非 admin 写 → 拒。
//! - 乐观锁:stale If-Match 写 → 409;正确 revision → 200。
//! - 体积/URI/生命周期:超 4KB → 413;非 URI namespace → 400;Tombstoned 用户读 fail-closed。
//! - C2.11 未破坏:aud=<RS> 的 token 调 /userinfo 仍拒。

use agent_auth_client::s256_challenge;
use agent_auth_http::{
    adapters::memory::MemorySigner,
    attribute_namespace::{
        AttributeNamespaceStore, NamespaceMigrationPhase, NamespaceOperationCheckpoint,
    },
    build_router,
    federation_attributes::{
        FederationAttributeMappingsStore, FederationAttributeReconciliationOutcome,
        FederationAttributeReconciliationRequest, MappingChange, MappingChangeOutcome, MappingMode,
        MappingSpec,
    },
    ports::{JtiRecord, JtiStore, Signer, UserStatus, UsersStore},
    security_event::{SecurityEventOutcome, SecurityEventStore},
    state::{AttributeNamespaceStoreImpl, JtiStoreImpl},
    AppState,
};
use agent_auth_token::claims::NAMESPACE;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use std::sync::Arc;
use tower::ServiceExt;

const HOST: &str = "localhost";
const RS_A: &str = "https://mcp.a.example.com/";
const RS_B: &str = "https://mcp.b.example.com/";
const CANONICAL: &str = "https://resources.example.com/shared";
const ADMIN: &str = "dev-admin-token-not-for-prod";
const USER_ID: &str = "alice"; // login_user 占位 → code.user_id = "alice"

fn admin_auth() -> String {
    format!("Bearer {ADMIN}")
}

async fn sign_test_access_token(typ: &str, claims: serde_json::Value) -> String {
    let signer = MemorySigner::dev();
    let header = serde_json::json!({
        "alg": "ES256",
        "typ": typ,
        "kid": signer.active_kid().await.unwrap(),
    });
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap()),
    );
    let signature = signer.sign_es256(signing_input.as_bytes()).await.unwrap();
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn tamper_signature(token: &str) -> String {
    let mut parts = token.split('.').map(str::to_string).collect::<Vec<_>>();
    let mut signature = URL_SAFE_NO_PAD.decode(&parts[2]).unwrap();
    signature[0] ^= 1;
    parts[2] = URL_SAFE_NO_PAD.encode(signature);
    parts.join(".")
}

fn test_access_claims(
    now: i64,
    aud: serde_json::Value,
    sub_type: &str,
    issuer: &str,
    jti: &str,
) -> serde_json::Value {
    let mut claims = serde_json::json!({
        "iss": issuer,
        "sub": "pairwise-looking-sub",
        "aud": aud,
        "client_id": "client-a",
        "jti": jti,
        "iat": now,
        "exp": now + 300,
    });
    claims.as_object_mut().unwrap().insert(
        NAMESPACE.to_string(),
        serde_json::json!({
            "sub_type": sub_type,
            "auth_grant": "authorization_code",
        }),
    );
    claims
}

/// 用绑定 default_resource=resource 的 public client 走 code flow 换一枚 aud=resource 的 access token。
async fn mint_token(router: &axum::Router, client: &str, redirect: &str) -> String {
    let verifier = "0123456789012345678901234567890123456789abc";
    let challenge = s256_challenge(verifier);
    let authz = format!(
        "/authorize?response_type=code&client_id={client}&redirect_uri={redirect}\
         &code_challenge={challenge}&code_challenge_method=S256&scope=openid&state=s&login_user={USER_ID}"
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
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "authorize 应发码");
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
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let tok: serde_json::Value = serde_json::from_slice(&body).unwrap();
    tok["access_token"].as_str().unwrap().to_string()
}

/// admin PUT 属性。返回 (status, json)。
async fn put_attrs(
    router: &axum::Router,
    user_id: &str,
    namespace: &str,
    body: &str,
    if_match: Option<u64>,
    auth: &str,
) -> (StatusCode, serde_json::Value) {
    let enc_ns = urlencoding(namespace);
    let mut req = Request::builder()
        .method("PUT")
        .uri(format!(
            "/admin/users/{user_id}/attributes?namespace={enc_ns}"
        ))
        .header("host", HOST)
        .header("authorization", auth)
        .header("content-type", "application/json");
    if let Some(m) = if_match {
        req = req.header("if-match", m.to_string());
    }
    let resp = router
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&b).unwrap_or(serde_json::Value::Null),
    )
}

/// RS 读属性(带 access token)。返回 (status, json)。
async fn get_rs_attrs(router: &axum::Router, token: &str) -> (StatusCode, serde_json::Value) {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/rs/attributes")
                .header("host", HOST)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&b).unwrap_or(serde_json::Value::Null),
    )
}

async fn get_rs_attrs_with_cache(
    router: &axum::Router,
    token: &str,
) -> (StatusCode, Option<String>, serde_json::Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/rs/attributes")
                .header("host", HOST)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let cache_control = response
        .headers()
        .get("cache-control")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        cache_control,
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
    )
}

async fn begin_namespace_change(
    router: &axum::Router,
    canonical_namespace: &str,
    exact_audiences: &[&str],
    expected_revision: u64,
    operation_id: &str,
) -> serde_json::Value {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/admin/attribute-namespaces")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "canonical_namespace": canonical_namespace,
                        "exact_audiences": exact_audiences,
                        "expected_revision": expected_revision,
                        "operation_id": operation_id,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap()
}

async fn advance_namespace_change(
    router: &axum::Router,
    canonical_namespace: &str,
    operation_id: &str,
    expected_operation_revision: u64,
) -> (StatusCode, serde_json::Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/attribute-namespaces/advance")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "canonical_namespace": canonical_namespace,
                        "operation_id": operation_id,
                        "expected_operation_revision": expected_operation_revision,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let json = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    (status, json)
}

async fn finish_namespace_change(
    router: &axum::Router,
    canonical_namespace: &str,
    operation_id: &str,
    mut registration: serde_json::Value,
) -> serde_json::Value {
    for _ in 0..5 {
        let Some(revision) = registration["operation"]["revision"].as_u64() else {
            return registration;
        };
        let (status, next) =
            advance_namespace_change(router, canonical_namespace, operation_id, revision).await;
        assert_eq!(status, StatusCode::OK, "advance failed: {next:?}");
        registration = next;
    }
    panic!("namespace change did not converge: {registration:?}");
}

async fn cancel_namespace_change(
    router: &axum::Router,
    canonical_namespace: &str,
    operation_id: &str,
    expected_operation_revision: u64,
) -> (StatusCode, serde_json::Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/attribute-namespaces/cancel")
                .header("host", HOST)
                .header("authorization", admin_auth())
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "canonical_namespace": canonical_namespace,
                        "operation_id": operation_id,
                        "expected_operation_revision": expected_operation_revision,
                    })
                    .to_string(),
                ))
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
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
    )
}

async fn delete_namespace_registration(
    router: &axum::Router,
    canonical_namespace: &str,
    expected_revision: u64,
    operation_id: &str,
) -> (StatusCode, serde_json::Value) {
    let uri = format!(
        "/admin/attribute-namespaces?canonical_namespace={}&expected_revision={expected_revision}&operation_id={operation_id}",
        urlencoding(canonical_namespace)
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(uri)
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
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
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
    )
}

fn urlencoding(s: &str) -> String {
    // 最小 percent-encode(路径段):只编码本测试 namespace 里出现的 ':' '/' 。
    s.replace(':', "%3A").replace('/', "%2F")
}

async fn seed_state() -> AppState {
    let state = AppState::dev(HOST);
    // 两个 client:各绑一个 default_resource → 换出的 token aud = 对应 RS。
    state
        .seed_dev_client("client-a", "https://app.a/cb", Some(RS_A))
        .await;
    state
        .seed_dev_client("client-b", "https://app.b/cb", Some(RS_B))
        .await;
    // 纯 OIDC client(无 default_resource)→ token aud = <issuer>/userinfo。
    state
        .seed_dev_client("client-oidc", "https://app.o/cb", None)
        .await;
    // 预置用户(user_id="alice",与 login_user 占位一致)——active-user gate 需其存在。
    {
        use agent_auth_http::ports::UsersStore;
        let _ = state
            .users
            .create_or_get_by_email("", "alice@example.com", USER_ID, 1000)
            .await;
    }
    state
}

#[tokio::test]
async fn write_then_read_roundtrip_and_isolation() {
    let state = seed_state().await;
    let (router, _) = build_router(state);

    // admin 写 RS-A 属性(首写 If-Match 缺省=0)。
    let (st, j) = put_attrs(
        &router,
        USER_ID,
        RS_A,
        r#"{"role":"admin","team":"x"}"#,
        None,
        &admin_auth(),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "首写应成功: {j:?}");
    assert_eq!(j["revision"], 1);

    // RS-A token 读到该属性 + sub 逐字节一致 + revision。
    let tok_a = mint_token(&router, "client-a", "https://app.a/cb").await;
    let (st, j) = get_rs_attrs(&router, &tok_a).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(j["attributes"]["role"], "admin");
    assert_eq!(j["revision"], 1);
    let token_payload = tok_a.split('.').nth(1).unwrap();
    let token_claims: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(token_payload).unwrap()).unwrap();
    assert_eq!(j["sub"], token_claims["sub"]);

    // 跨命名空间隔离:RS-B token 读不到 RS-A 属性(RS-B 命名空间为空)。
    let tok_b = mint_token(&router, "client-b", "https://app.b/cb").await;
    let (st, j) = get_rs_attrs(&router, &tok_b).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        j["attributes"].as_object().unwrap().len(),
        0,
        "RS-B 命名空间应为空(隔离)"
    );
}

#[tokio::test]
async fn rs_attributes_strict_token_jti_and_user_gates_fail_closed() {
    let state = seed_state().await;
    let observed_state = state.clone();
    let now = agent_auth_http::current_unix_secs();
    for (jti, user_id) in [("rs-valid-jti", USER_ID), ("rs-missing-user-jti", "ghost")] {
        observed_state
            .jti_store
            .as_ref()
            .unwrap()
            .put(JtiRecord {
                jti: jti.to_string(),
                tenant_id: "default".to_string(),
                user_id: user_id.to_string(),
                family_id: None,
                grant_id: None,
                expires_at: now + 300,
            })
            .await
            .unwrap();
    }
    observed_state
        .jti_store
        .as_ref()
        .unwrap()
        .put(JtiRecord {
            jti: "rs-expired-jti".to_string(),
            tenant_id: "default".to_string(),
            user_id: USER_ID.to_string(),
            family_id: None,
            grant_id: None,
            expires_at: now,
        })
        .await
        .unwrap();
    let (router, _) = build_router(state);
    assert_eq!(
        put_attrs(
            &router,
            USER_ID,
            RS_A,
            r#"{"role":"admin"}"#,
            None,
            &admin_auth(),
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        put_attrs(
            &router,
            USER_ID,
            RS_B,
            r#"{"role":"viewer"}"#,
            None,
            &admin_auth(),
        )
        .await
        .0,
        StatusCode::OK
    );

    let valid_claims = test_access_claims(
        now,
        serde_json::json!([RS_A]),
        "user",
        "https://localhost",
        "rs-valid-jti",
    );
    let valid_token = sign_test_access_token("at+jwt", valid_claims.clone()).await;
    assert_eq!(
        get_rs_attrs(&router, &tamper_signature(&valid_token))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/rs/attributes?namespace={}", urlencoding(RS_B)))
                .header("host", HOST)
                .header("authorization", format!("Bearer {valid_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["attributes"]["role"], "admin");
    assert_eq!(body["sub"], "pairwise-looking-sub");

    let mut wrong_typ = valid_claims.clone();
    wrong_typ["jti"] = serde_json::json!("rs-valid-jti");
    assert_eq!(
        get_rs_attrs(&router, &sign_test_access_token("JWT", wrong_typ).await)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let mut missing_aud = valid_claims.clone();
    missing_aud.as_object_mut().unwrap().remove("aud");
    let mut missing_jti = valid_claims.clone();
    missing_jti.as_object_mut().unwrap().remove("jti");
    assert_eq!(
        get_rs_attrs(
            &router,
            &sign_test_access_token("at+jwt", missing_jti).await
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    for claims in [
        missing_aud,
        test_access_claims(
            now,
            serde_json::json!([]),
            "user",
            "https://localhost",
            "rs-valid-jti",
        ),
        test_access_claims(
            now,
            serde_json::json!([123]),
            "user",
            "https://localhost",
            "rs-valid-jti",
        ),
        test_access_claims(
            now,
            serde_json::json!(RS_A),
            "user",
            "https://localhost",
            "rs-valid-jti",
        ),
        test_access_claims(
            now,
            serde_json::json!([RS_A, RS_B]),
            "user",
            "https://localhost",
            "rs-valid-jti",
        ),
        test_access_claims(
            now,
            serde_json::json!([RS_A]),
            "agent",
            "https://localhost",
            "rs-valid-jti",
        ),
        test_access_claims(
            now,
            serde_json::json!([RS_A]),
            "user",
            "https://other.example.com",
            "rs-valid-jti",
        ),
    ] {
        assert_eq!(
            get_rs_attrs(&router, &sign_test_access_token("at+jwt", claims).await)
                .await
                .0,
            StatusCode::FORBIDDEN
        );
    }
    for jti in ["rs-unknown-jti", "rs-missing-user-jti"] {
        let token = sign_test_access_token(
            "at+jwt",
            test_access_claims(
                now,
                serde_json::json!([RS_A]),
                "user",
                "https://localhost",
                jti,
            ),
        )
        .await;
        assert_eq!(
            get_rs_attrs(&router, &token).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    let expired_jti_token = sign_test_access_token(
        "at+jwt",
        test_access_claims(
            now,
            serde_json::json!([RS_A]),
            "user",
            "https://localhost",
            "rs-expired-jti",
        ),
    )
    .await;
    assert_eq!(
        get_rs_attrs(&router, &expired_jti_token).await.0,
        StatusCode::UNAUTHORIZED,
        "a physically present JTI mapping is invalid at now == expires_at"
    );

    match observed_state.jti_store.as_ref().unwrap().as_ref() {
        JtiStoreImpl::Memory(store) => store.fail_next_get(),
        #[cfg(feature = "aws")]
        JtiStoreImpl::Dynamo(_) => panic!("expected memory JTI store"),
    }
    assert_eq!(
        get_rs_attrs(&router, &valid_token).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );

    observed_state
        .users
        .set_status("", USER_ID, UserStatus::Disabled, now)
        .await
        .unwrap();
    assert_eq!(
        get_rs_attrs(&router, &valid_token).await.0,
        StatusCode::UNAUTHORIZED
    );
    observed_state
        .users
        .set_status("", USER_ID, UserStatus::Tombstoned, now + 1)
        .await
        .unwrap();
    assert_eq!(
        get_rs_attrs(&router, &valid_token).await.0,
        StatusCode::UNAUTHORIZED
    );

    let missing_jti_state = seed_state().await;
    let mut missing_jti_state = missing_jti_state;
    missing_jti_state.jti_store = None;
    let (missing_jti_router, _) = build_router(missing_jti_state);
    assert_eq!(
        get_rs_attrs(&missing_jti_router, &valid_token).await.0,
        StatusCode::UNAUTHORIZED
    );

    let namespace_failure_state = seed_state().await;
    namespace_failure_state
        .jti_store
        .as_ref()
        .unwrap()
        .put(JtiRecord {
            jti: "rs-valid-jti".to_string(),
            tenant_id: "default".to_string(),
            user_id: USER_ID.to_string(),
            family_id: None,
            grant_id: None,
            expires_at: now + 300,
        })
        .await
        .unwrap();
    let mut namespace_failure_state = namespace_failure_state;
    namespace_failure_state.attribute_namespaces = Arc::new(AttributeNamespaceStoreImpl::Disabled);
    let (namespace_failure_router, _) = build_router(namespace_failure_state);
    assert_eq!(
        get_rs_attrs(&namespace_failure_router, &valid_token)
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

const FEDERATED_IDP: &str = "corp";
const FEDERATED_ISSUER: &str = "https://idp.example.com";

async fn setup_federation_rs_read(router: &axum::Router) -> String {
    let pending = begin_namespace_change(router, CANONICAL, &[RS_A], 0, "federation-rs-read").await;
    finish_namespace_change(router, CANONICAL, "federation-rs-read", pending).await;
    let token = mint_token(router, "client-a", "https://app.a/cb").await;

    let (status, body) = put_attrs(
        router,
        USER_ID,
        CANONICAL,
        r#"{"note":"local"}"#,
        None,
        &admin_auth(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    token
}

async fn create_federated_role(state: &AppState) {
    let created = state
        .federation_attribute_mappings
        .change(
            "default",
            FEDERATED_IDP,
            FEDERATED_ISSUER,
            MappingChange::Create {
                mapping_id: "fm_finance_role".to_string(),
                expected_registry_revision: 0,
                spec: MappingSpec {
                    source_claim: "groups".to_string(),
                    target_namespace: CANONICAL.to_string(),
                    target_key: "role".to_string(),
                    mode: MappingMode::ExactMembership {
                        source_value: "finance-admin".to_string(),
                        target_value: "admin".to_string(),
                    },
                },
            },
        )
        .await
        .unwrap();
    assert!(matches!(created, MappingChangeOutcome::Applied(_)));
    let reconciled = state
        .reconcile_federated_attributes(FederationAttributeReconciliationRequest {
            operation_id: "flow-rs-immediate-invalidation".to_string(),
            logical_tenant_id: "default".to_string(),
            storage_tenant_id: String::new(),
            upstream_idp_id: FEDERATED_IDP.to_string(),
            upstream_issuer: FEDERATED_ISSUER.to_string(),
            user_id: USER_ID.to_string(),
            verified_claims: serde_json::json!({"groups": ["finance-admin"]}),
        })
        .await
        .unwrap();
    assert!(matches!(
        reconciled,
        FederationAttributeReconciliationOutcome::Applied { changed: true, .. }
    ));
}

async fn assert_federated_role_visible(router: &axum::Router, token: &str) {
    let (status, cache_control, body) = get_rs_attrs_with_cache(router, token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cache_control.as_deref(), Some("no-store"));
    assert_eq!(body["attributes"]["note"], "local");
    assert_eq!(body["attributes"]["role"], "admin");
    assert_eq!(
        put_attrs(
            router,
            USER_ID,
            CANONICAL,
            r#"{"note":"local","role":"viewer"}"#,
            Some(2),
            &admin_auth(),
        )
        .await
        .0,
        StatusCode::CONFLICT,
        "admin writes must not take over a federation-owned key"
    );
}

async fn update_federated_role(state: &AppState, router: &axum::Router, token: &str) {
    let updated = state
        .federation_attribute_mappings
        .change(
            "default",
            FEDERATED_IDP,
            FEDERATED_ISSUER,
            MappingChange::Update {
                mapping_id: "fm_finance_role".to_string(),
                expected_registry_revision: 1,
                expected_mapping_revision: 1,
                enabled: true,
                spec: MappingSpec {
                    source_claim: "groups".to_string(),
                    target_namespace: CANONICAL.to_string(),
                    target_key: "role".to_string(),
                    mode: MappingMode::ExactMembership {
                        source_value: "finance-admin".to_string(),
                        target_value: "owner".to_string(),
                    },
                },
            },
        )
        .await
        .unwrap();
    assert!(matches!(updated, MappingChangeOutcome::Applied(_)));

    let (status, cache_control, body) = get_rs_attrs_with_cache(router, token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cache_control.as_deref(), Some("no-store"));
    assert_eq!(body["attributes"]["note"], "local");
    assert!(body["attributes"].get("role").is_none());
}

async fn reconcile_updated_federated_role(state: &AppState, router: &axum::Router, token: &str) {
    state
        .reconcile_federated_attributes(FederationAttributeReconciliationRequest {
            operation_id: "flow-rs-updated-mapping".to_string(),
            logical_tenant_id: "default".to_string(),
            storage_tenant_id: String::new(),
            upstream_idp_id: FEDERATED_IDP.to_string(),
            upstream_issuer: FEDERATED_ISSUER.to_string(),
            user_id: USER_ID.to_string(),
            verified_claims: serde_json::json!({"groups": ["finance-admin"]}),
        })
        .await
        .unwrap();
    let (status, _, body) = get_rs_attrs_with_cache(router, token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["attributes"]["role"], "owner");
}

async fn disable_federated_role(state: &AppState, router: &axum::Router, token: &str) {
    let disabled = state
        .federation_attribute_mappings
        .change(
            "default",
            FEDERATED_IDP,
            FEDERATED_ISSUER,
            MappingChange::SetEnabled {
                mapping_id: "fm_finance_role".to_string(),
                expected_registry_revision: 2,
                expected_mapping_revision: 2,
                enabled: false,
            },
        )
        .await
        .unwrap();
    assert!(matches!(disabled, MappingChangeOutcome::Applied(_)));
    let (status, _, body) = get_rs_attrs_with_cache(router, token).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["attributes"].get("role").is_none());
}

async fn reenable_federated_role(state: &AppState, router: &axum::Router, token: &str) {
    let enabled = state
        .federation_attribute_mappings
        .change(
            "default",
            FEDERATED_IDP,
            FEDERATED_ISSUER,
            MappingChange::SetEnabled {
                mapping_id: "fm_finance_role".to_string(),
                expected_registry_revision: 3,
                expected_mapping_revision: 3,
                enabled: true,
            },
        )
        .await
        .unwrap();
    assert!(matches!(enabled, MappingChangeOutcome::Applied(_)));
    state
        .reconcile_federated_attributes(FederationAttributeReconciliationRequest {
            operation_id: "flow-rs-reenabled-mapping".to_string(),
            logical_tenant_id: "default".to_string(),
            storage_tenant_id: String::new(),
            upstream_idp_id: FEDERATED_IDP.to_string(),
            upstream_issuer: FEDERATED_ISSUER.to_string(),
            user_id: USER_ID.to_string(),
            verified_claims: serde_json::json!({"groups": ["finance-admin"]}),
        })
        .await
        .unwrap();
    let (status, _, body) = get_rs_attrs_with_cache(router, token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["attributes"]["role"], "owner");
}

async fn delete_federated_role(state: &AppState, router: &axum::Router, token: &str) {
    let deleted = state
        .federation_attribute_mappings
        .change(
            "default",
            FEDERATED_IDP,
            FEDERATED_ISSUER,
            MappingChange::Delete {
                mapping_id: "fm_finance_role".to_string(),
                expected_registry_revision: 4,
                expected_mapping_revision: 4,
            },
        )
        .await
        .unwrap();
    assert!(matches!(deleted, MappingChangeOutcome::Applied(_)));
    let (status, cache_control, body) = get_rs_attrs_with_cache(router, token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cache_control.as_deref(), Some("no-store"));
    assert_eq!(body["attributes"]["note"], "local");
    assert!(body["attributes"].get("role").is_none());
}

#[tokio::test]
async fn mapping_update_disable_and_delete_are_immediately_hidden_from_rs_reads() {
    let state = seed_state().await;
    let observed_state = state.clone();
    let (router, _) = build_router(state);
    let token = setup_federation_rs_read(&router).await;

    create_federated_role(&observed_state).await;
    assert_federated_role_visible(&router, &token).await;
    update_federated_role(&observed_state, &router, &token).await;
    reconcile_updated_federated_role(&observed_state, &router, &token).await;
    disable_federated_role(&observed_state, &router, &token).await;
    reenable_federated_role(&observed_state, &router, &token).await;
    delete_federated_role(&observed_state, &router, &token).await;
}

#[tokio::test]
async fn userinfo_token_and_non_admin_rejected() {
    let state = seed_state().await;
    let (router, _) = build_router(state);

    // aud=<issuer>/userinfo 的 token 调 /rs/attributes → 拒(反向隔离)。
    let tok_oidc = mint_token(&router, "client-oidc", "https://app.o/cb").await;
    let (st, _) = get_rs_attrs(&router, &tok_oidc).await;
    assert_eq!(
        st,
        StatusCode::FORBIDDEN,
        "userinfo token 不得当属性 namespace"
    );

    // 非 admin(用 RS access token 冒充)写属性 → 拒。
    let tok_a = mint_token(&router, "client-a", "https://app.a/cb").await;
    let (st, _) = put_attrs(
        &router,
        USER_ID,
        RS_A,
        r#"{"role":"admin"}"#,
        None,
        &format!("Bearer {tok_a}"),
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "非 admin token 写属性应拒");
}

#[tokio::test]
async fn optimistic_lock_conflict() {
    let state = seed_state().await;
    let observed_state = state.clone();
    let (router, _) = build_router(state);

    // 首写 → revision 1。
    let (st, _) = put_attrs(
        &router,
        USER_ID,
        RS_A,
        r#"{"role":"admin"}"#,
        None,
        &admin_auth(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    // stale If-Match(用 0 再写)→ 409。
    let (st, j) = put_attrs(
        &router,
        USER_ID,
        RS_A,
        r#"{"role":"editor"}"#,
        Some(0),
        &admin_auth(),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT, "stale If-Match 应 409: {j:?}");
    // 正确 revision 1 → 200,revision→2。
    let (st, j) = put_attrs(
        &router,
        USER_ID,
        RS_A,
        r#"{"role":"editor"}"#,
        Some(1),
        &admin_auth(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(j["revision"], 2);

    let events = observed_state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 1_000)
        .await
        .unwrap();
    assert!(events.iter().any(|stored| {
        stored.event.action == "user.attributes.write"
            && stored.event.outcome == SecurityEventOutcome::Success
    }));
    assert!(events.iter().any(|stored| {
        stored.event.action == "user.attributes.write"
            && stored.event.outcome == SecurityEventOutcome::Denied
    }));
}

#[tokio::test]
async fn malformed_attribute_payloads_are_denied_and_audited() {
    let state = seed_state().await;
    let observed_state = state.clone();
    let (router, _) = build_router(state);

    for body in ["{", "[]"] {
        assert_eq!(
            put_attrs(&router, USER_ID, RS_A, body, None, &admin_auth())
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
    }

    let denied = observed_state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 1_000)
        .await
        .unwrap()
        .into_iter()
        .filter(|stored| {
            stored.event.action == "user.attributes.write"
                && stored.event.outcome == SecurityEventOutcome::Denied
        })
        .count();
    assert_eq!(denied, 2, "each authenticated rejected write is audited");
}

#[tokio::test]
async fn migration_page_read_failure_remains_cancellable() {
    let state = seed_state().await;
    let observed_state = state.clone();
    let (router, _) = build_router(state);
    let operation_id = "alias-page-read-failure";

    begin_namespace_change(&router, CANONICAL, &[RS_A], 0, operation_id).await;
    observed_state
        .attribute_namespaces
        .checkpoint(
            "",
            CANONICAL,
            operation_id,
            NamespaceOperationCheckpoint {
                expected_revision: 1,
                phase: NamespaceMigrationPhase::Migrating,
                cursor: Some("not-a-memory-user-cursor".into()),
                scan_complete: false,
                started_mutation: false,
                inflight_user_id: None,
                users_scanned: 0,
                users_completed: 0,
                conflict_count: 0,
                conflict_user_ids: vec![],
            },
        )
        .await
        .unwrap();

    assert_eq!(
        advance_namespace_change(&router, CANONICAL, operation_id, 2)
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        cancel_namespace_change(&router, CANONICAL, operation_id, 2)
            .await
            .0,
        StatusCode::OK,
        "a page read failure must not cross the irreversible mutation boundary"
    );
}

#[tokio::test]
async fn migration_recovery_completes_a_committed_inflight_user_exactly_once() {
    let state = seed_state().await;
    let observed_state = state.clone();
    let (router, _) = build_router(state);
    let operation_id = "alias-inflight-recovery";

    assert_eq!(
        put_attrs(
            &router,
            USER_ID,
            RS_A,
            r#"{"role":"admin"}"#,
            None,
            &admin_auth(),
        )
        .await
        .0,
        StatusCode::OK
    );
    begin_namespace_change(&router, CANONICAL, &[RS_A, RS_B], 0, operation_id).await;
    observed_state
        .attribute_namespaces
        .checkpoint(
            "",
            CANONICAL,
            operation_id,
            NamespaceOperationCheckpoint {
                expected_revision: 1,
                phase: NamespaceMigrationPhase::Migrating,
                cursor: Some("not-a-memory-user-cursor".into()),
                scan_complete: false,
                started_mutation: true,
                inflight_user_id: None,
                users_scanned: 0,
                users_completed: 0,
                conflict_count: 0,
                conflict_user_ids: vec![],
            },
        )
        .await
        .unwrap();
    observed_state
        .attribute_namespaces
        .checkpoint(
            "",
            CANONICAL,
            operation_id,
            NamespaceOperationCheckpoint {
                expected_revision: 2,
                phase: NamespaceMigrationPhase::Migrating,
                cursor: Some("not-a-memory-user-cursor".into()),
                scan_complete: false,
                started_mutation: true,
                inflight_user_id: Some(USER_ID.into()),
                users_scanned: 0,
                users_completed: 0,
                conflict_count: 0,
                conflict_user_ids: vec![],
            },
        )
        .await
        .unwrap();
    let registration = observed_state
        .attribute_namespaces
        .get("", CANONICAL)
        .await
        .unwrap()
        .unwrap();
    let sources = registration
        .operation
        .as_ref()
        .unwrap()
        .source_namespaces
        .clone();
    assert!(matches!(
        observed_state
            .users
            .migrate_attributes("", USER_ID, CANONICAL, &sources)
            .await
            .unwrap(),
        agent_auth_http::ports::AttributeMigrationOutcome::Migrated { .. }
    ));

    assert_eq!(
        advance_namespace_change(&router, CANONICAL, operation_id, 3)
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    let recovered = observed_state
        .attribute_namespaces
        .get("", CANONICAL)
        .await
        .unwrap()
        .unwrap();
    let operation = recovered.operation.unwrap();
    assert_eq!(operation.users_completed, 1);
    assert_eq!(operation.inflight_user_id, None);
    assert_eq!(operation.revision, 4);

    assert_eq!(
        advance_namespace_change(&router, CANONICAL, operation_id, 4)
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        observed_state
            .attribute_namespaces
            .get("", CANONICAL)
            .await
            .unwrap()
            .unwrap()
            .operation
            .unwrap()
            .users_completed,
        1
    );
}

#[tokio::test]
async fn migration_recovery_completes_a_tombstoned_inflight_user_exactly_once() {
    let state = seed_state().await;
    let observed_state = state.clone();
    let (router, _) = build_router(state);
    let operation_id = "alias-inflight-tombstone";

    begin_namespace_change(&router, CANONICAL, &[RS_A, RS_B], 0, operation_id).await;
    observed_state
        .attribute_namespaces
        .checkpoint(
            "",
            CANONICAL,
            operation_id,
            NamespaceOperationCheckpoint {
                expected_revision: 1,
                phase: NamespaceMigrationPhase::Migrating,
                cursor: Some("not-a-memory-user-cursor".into()),
                scan_complete: false,
                started_mutation: true,
                inflight_user_id: None,
                users_scanned: 0,
                users_completed: 0,
                conflict_count: 0,
                conflict_user_ids: vec![],
            },
        )
        .await
        .unwrap();
    observed_state
        .attribute_namespaces
        .checkpoint(
            "",
            CANONICAL,
            operation_id,
            NamespaceOperationCheckpoint {
                expected_revision: 2,
                phase: NamespaceMigrationPhase::Migrating,
                cursor: Some("not-a-memory-user-cursor".into()),
                scan_complete: false,
                started_mutation: true,
                inflight_user_id: Some(USER_ID.into()),
                users_scanned: 0,
                users_completed: 0,
                conflict_count: 0,
                conflict_user_ids: vec![],
            },
        )
        .await
        .unwrap();
    assert!(observed_state
        .users
        .set_status("", USER_ID, UserStatus::Tombstoned, 1)
        .await
        .unwrap());

    assert_eq!(
        advance_namespace_change(&router, CANONICAL, operation_id, 3)
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    let recovered = observed_state
        .attribute_namespaces
        .get("", CANONICAL)
        .await
        .unwrap()
        .unwrap();
    let operation = recovered.operation.unwrap();
    assert_eq!(operation.users_completed, 1);
    assert_eq!(operation.inflight_user_id, None);
    assert_eq!(operation.revision, 4);

    assert_eq!(
        advance_namespace_change(&router, CANONICAL, operation_id, 4)
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        observed_state
            .attribute_namespaces
            .get("", CANONICAL)
            .await
            .unwrap()
            .unwrap()
            .operation
            .unwrap()
            .users_completed,
        1
    );
}

#[tokio::test]
async fn oversized_and_non_uri_and_empty_body_rejected() {
    let state = seed_state().await;
    let (router, _) = build_router(state);

    // 超 4KB → 413。
    let big = format!(r#"{{"blob":"{}"}}"#, "x".repeat(5000));
    let (st, _) = put_attrs(&router, USER_ID, RS_A, &big, None, &admin_auth()).await;
    assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE);

    // 非 URI namespace → 400。
    let (st, _) = put_attrs(
        &router,
        USER_ID,
        "not-a-uri",
        r#"{"k":"v"}"#,
        None,
        &admin_auth(),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);

    // 值非字符串 → 400。
    let (st, _) = put_attrs(&router, USER_ID, RS_A, r#"{"k":123}"#, None, &admin_auth()).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);

    // 零长 body → 400(区别于 {})。
    let (st, _) = put_attrs(&router, USER_ID, RS_A, "", None, &admin_auth()).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn userinfo_c211_not_broken_by_rs_attributes() {
    let state = seed_state().await;
    let (router, _) = build_router(state);

    // aud=<RS> 的 token 调 /userinfo → 仍按 C2.11 拒(本能力未破坏 userinfo 隔离)。
    let tok_a = mint_token(&router, "client-a", "https://app.a/cb").await;
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/userinfo")
                .header("host", HOST)
                .header("authorization", format!("Bearer {tok_a}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "aud=RS 的 token 调 /userinfo 仍应 C2.11 拒"
    );
}

/// admin GET /admin/users/{id} 返回 UserDetail JSON。
async fn get_user_detail(router: &axum::Router, uid: &str) -> serde_json::Value {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/admin/users/{uid}"))
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&b).unwrap()
}

// H2:管理面 UserDetail 回带**全部** namespace 属性(超级权限全局视图,区别于 RS 侧只见自身 aud)。
#[tokio::test]
async fn admin_user_detail_shows_all_namespaces() {
    let state = seed_state().await;
    let (router, _) = build_router(state);
    // 写两个 namespace。
    let (st, _) = put_attrs(
        &router,
        USER_ID,
        RS_A,
        r#"{"role":"admin"}"#,
        None,
        &admin_auth(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (st, _) = put_attrs(
        &router,
        USER_ID,
        RS_B,
        r#"{"tier":"gold"}"#,
        None,
        &admin_auth(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    // admin 详情同时见到两个 namespace（全局视图）。
    let d = get_user_detail(&router, USER_ID).await;
    let attrs = d["attributes"].as_object().unwrap();
    assert_eq!(attrs[RS_A]["kv"]["role"], "admin", "详情应含 RS_A: {d:?}");
    assert_eq!(attrs[RS_B]["kv"]["tier"], "gold", "详情应含 RS_B: {d:?}");
    assert_eq!(attrs[RS_A]["revision"], 1);
    assert_eq!(attrs[RS_A]["canonical_namespace"], RS_A);
    assert_eq!(attrs[RS_A]["registration_state"], "unbound");
    assert_eq!(attrs[RS_A]["exact_audiences"].as_array().unwrap().len(), 0);
}

// H4:删用户(tombstone)级联清空 attributes(GDPR),不留孤儿。
#[tokio::test]
async fn delete_user_cascades_attributes_gdpr() {
    let state = seed_state().await;
    let (router, _) = build_router(state);
    let (st, _) = put_attrs(
        &router,
        USER_ID,
        RS_A,
        r#"{"role":"admin"}"#,
        None,
        &admin_auth(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    // DELETE 用户(tombstone)。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/users/{USER_ID}"))
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // 详情:attributes 已清空(GDPR),status=tombstoned。
    let d = get_user_detail(&router, USER_ID).await;
    assert_eq!(
        d["attributes"].as_object().unwrap().len(),
        0,
        "tombstone 应级联清属性: {d:?}"
    );
}

// M2:Disabled 用户允许 admin 预置属性(spec §6.1:Disabled 默认允许写,区别于 Tombstoned 拒)。
#[tokio::test]
async fn disabled_user_allows_admin_write() {
    let state = seed_state().await;
    let (router, _) = build_router(state);
    // 先在 active 时签一枚 token(供后面验证禁用后读 fail-closed)。
    let tok = mint_token(&router, "client-a", "https://app.a/cb").await;
    // 再禁用。
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/users/{USER_ID}/disable"))
                .header("host", HOST)
                .header("authorization", admin_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // Disabled 用户 admin 仍可写属性(预配置合法)。
    let (st, _) = put_attrs(
        &router,
        USER_ID,
        RS_A,
        r#"{"role":"admin"}"#,
        None,
        &admin_auth(),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "Disabled 用户应允许 admin 预置属性");
    // 该用户禁用前签的 token 读属性 → active-user gate fail-closed(读时强一致读 status=Disabled → 拒)。
    let (st, _) = get_rs_attrs(&router, &tok).await;
    assert_eq!(
        st,
        StatusCode::UNAUTHORIZED,
        "Disabled 用户 RS 读应 fail-closed"
    );
}

#[tokio::test]
async fn exact_audience_aliases_migrate_share_and_retire_without_fallback() {
    let state = seed_state().await;
    let (router, _) = build_router(state);
    let token_a = mint_token(&router, "client-a", "https://app.a/cb").await;
    let token_b = mint_token(&router, "client-b", "https://app.b/cb").await;

    let (status, _) = put_attrs(
        &router,
        USER_ID,
        RS_A,
        r#"{"role":"admin"}"#,
        None,
        &admin_auth(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let pending =
        begin_namespace_change(&router, CANONICAL, &[RS_A, RS_B], 0, "alias-operation-1").await;
    assert_eq!(pending["state"], "pending");
    assert_eq!(
        get_rs_attrs(&router, &token_a).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        get_rs_attrs(&router, &token_b).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        put_attrs(
            &router,
            USER_ID,
            RS_A,
            r#"{"role":"viewer"}"#,
            Some(1),
            &admin_auth(),
        )
        .await
        .0,
        StatusCode::CONFLICT,
        "admin writes through a blocked alias must fail closed"
    );

    let active = finish_namespace_change(&router, CANONICAL, "alias-operation-1", pending).await;
    assert_eq!(active["state"], "active");
    assert!(active["operation"].is_null());
    for token in [&token_a, &token_b] {
        let (status, attributes) = get_rs_attrs(&router, token).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(attributes["attributes"]["role"], "admin");
    }
    let detail = get_user_detail(&router, USER_ID).await;
    let attrs = detail["attributes"].as_object().unwrap();
    assert_eq!(attrs.len(), 1, "migration must leave one canonical key");
    assert_eq!(attrs[CANONICAL]["canonical_namespace"], CANONICAL);
    assert_eq!(attrs[CANONICAL]["registration_state"], "active");
    assert_eq!(
        attrs[CANONICAL]["exact_audiences"],
        serde_json::json!([RS_A, RS_B])
    );

    let replacement =
        begin_namespace_change(&router, CANONICAL, &[RS_B], 1, "alias-operation-2").await;
    assert_eq!(
        get_rs_attrs(&router, &token_a).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        get_rs_attrs(&router, &token_b).await.0,
        StatusCode::FORBIDDEN
    );
    let active =
        finish_namespace_change(&router, CANONICAL, "alias-operation-2", replacement).await;
    assert_eq!(active["revision"], 2);
    assert_eq!(
        get_rs_attrs(&router, &token_a).await.0,
        StatusCode::FORBIDDEN,
        "removed alias must stay retired instead of falling back to its raw namespace"
    );
    let (status, attributes) = get_rs_attrs(&router, &token_b).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(attributes["attributes"]["role"], "admin");
    let detail = get_user_detail(&router, USER_ID).await;
    assert_eq!(
        detail["attributes"][CANONICAL]["exact_audiences"],
        serde_json::json!([RS_B])
    );
}

#[tokio::test]
async fn conflicting_alias_values_block_without_mutation_and_cancel_restores_fallback() {
    let state = seed_state().await;
    let (router, _) = build_router(state);
    let token_a = mint_token(&router, "client-a", "https://app.a/cb").await;
    let token_b = mint_token(&router, "client-b", "https://app.b/cb").await;

    assert_eq!(
        put_attrs(
            &router,
            USER_ID,
            RS_A,
            r#"{"role":"admin"}"#,
            None,
            &admin_auth(),
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        put_attrs(
            &router,
            USER_ID,
            RS_B,
            r#"{"role":"viewer"}"#,
            None,
            &admin_auth(),
        )
        .await
        .0,
        StatusCode::OK
    );

    let pending =
        begin_namespace_change(&router, CANONICAL, &[RS_A, RS_B], 0, "alias-conflict").await;
    let (status, conflicted) = advance_namespace_change(
        &router,
        CANONICAL,
        "alias-conflict",
        pending["operation"]["revision"].as_u64().unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(conflicted["operation"]["scan_complete"], true);
    assert_eq!(conflicted["operation"]["conflict_count"], 1);
    assert_eq!(
        get_rs_attrs(&router, &token_a).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        get_rs_attrs(&router, &token_b).await.0,
        StatusCode::FORBIDDEN
    );

    let detail = get_user_detail(&router, USER_ID).await;
    assert_eq!(detail["attributes"][RS_A]["kv"]["role"], "admin");
    assert_eq!(detail["attributes"][RS_B]["kv"]["role"], "viewer");
    assert_eq!(detail["attributes"][RS_A]["registration_state"], "pending");

    let (status, _) = cancel_namespace_change(
        &router,
        CANONICAL,
        "alias-conflict",
        conflicted["operation"]["revision"].as_u64().unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, attributes) = get_rs_attrs(&router, &token_a).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(attributes["attributes"]["role"], "admin");
    let (status, attributes) = get_rs_attrs(&router, &token_b).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(attributes["attributes"]["role"], "viewer");
}

#[tokio::test]
async fn deleted_alias_can_rebind_without_old_canonical_fallback_and_stale_delete_is_audited() {
    const REBOUND_CANONICAL: &str = "https://resources.example.com/rebound";

    let state = seed_state().await;
    let observed_state = state.clone();
    let (router, _) = build_router(state);
    let token_a = mint_token(&router, "client-a", "https://app.a/cb").await;

    assert_eq!(
        put_attrs(
            &router,
            USER_ID,
            RS_A,
            r#"{"role":"old-canonical"}"#,
            None,
            &admin_auth(),
        )
        .await
        .0,
        StatusCode::OK
    );
    let pending =
        begin_namespace_change(&router, CANONICAL, &[RS_A], 0, "alias-delete-create").await;
    let active = finish_namespace_change(&router, CANONICAL, "alias-delete-create", pending).await;
    assert_eq!(active["revision"], 1);

    let (status, _) =
        delete_namespace_registration(&router, CANONICAL, 0, "alias-delete-stale").await;
    assert_eq!(status, StatusCode::CONFLICT);
    let events = observed_state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 1_000)
        .await
        .unwrap();
    assert!(events.iter().any(|stored| {
        stored.event.action == "attribute_namespace.delete"
            && stored.event.outcome == SecurityEventOutcome::Denied
    }));

    let (status, retired) =
        delete_namespace_registration(&router, CANONICAL, 1, "alias-delete").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(retired["state"], "retired");
    assert_eq!(
        get_rs_attrs(&router, &token_a).await.0,
        StatusCode::FORBIDDEN,
        "deleted aliases must remain retired"
    );

    let pending =
        begin_namespace_change(&router, REBOUND_CANONICAL, &[RS_A], 0, "alias-rebind").await;
    assert_eq!(
        get_rs_attrs(&router, &token_a).await.0,
        StatusCode::FORBIDDEN,
        "rebind must remain blocked until activation"
    );
    let rebound =
        finish_namespace_change(&router, REBOUND_CANONICAL, "alias-rebind", pending).await;
    assert_eq!(rebound["state"], "active");

    let (status, attributes) = get_rs_attrs(&router, &token_a).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        attributes["attributes"].as_object().unwrap().is_empty(),
        "rebind must not expose attributes retained under the old canonical"
    );
    assert_eq!(
        put_attrs(
            &router,
            USER_ID,
            REBOUND_CANONICAL,
            r#"{"role":"new-canonical"}"#,
            None,
            &admin_auth(),
        )
        .await
        .0,
        StatusCode::OK
    );
    let (status, attributes) = get_rs_attrs(&router, &token_a).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(attributes["attributes"]["role"], "new-canonical");
}

#[tokio::test]
async fn saas_attribute_surfaces_return_not_found_before_authentication() {
    let mut state = AppState::dev(HOST);
    state.form = agent_auth_discovery::Form::Saas {
        zone: "example.test".into(),
        control_host: "control.example.test".into(),
    };
    let (router, _) = build_router(state);

    for (method, uri) in [
        ("GET", "/rs/attributes"),
        ("GET", "/admin/attribute-namespaces"),
        ("PUT", "/admin/attribute-namespaces"),
        ("DELETE", "/admin/attribute-namespaces"),
        ("POST", "/admin/attribute-namespaces/advance"),
        ("POST", "/admin/attribute-namespaces/cancel"),
        ("PUT", "/admin/users/user%3Aone@example.com/attributes"),
        (
            "DELETE",
            "/admin/users/user%3Aone@example.com/attributes/federation-owner",
        ),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("host", HOST)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
