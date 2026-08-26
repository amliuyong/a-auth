//! 进程内 e2e:X.509-SVID / mTLS 认证(spec 012 §1.4 / C5.7,P3)。
//!
//! 覆盖(对齐设计 Scenario):
//! - 合法 X.509-SVID(SAN=spiffe://,ClientCertPem 扩展)+ SpiffeX509 绑定 → 换 2LO(sub=映射 client/agent/无 refresh)
//! - 无证书扩展 → X.509 不激活(回落普通 client_credentials,SVID 未实现拒)
//! - 连接层身份排他(H1):cert=A 建连 + body 塞 client_assertion → 以证书判定(忽略 assertion)
//! - 跨 trust domain / pattern 不符 / 无匹配绑定 → 拒
//! - feature 关(mtls_svid_enabled=false)→ 即便有证书也不走 X.509
//! - SAN 无 spiffe URI / 多 URI → 拒(x509 纯逻辑已细测,这里过 HTTP 面再确认)
//!
//! 证书注入:真机由 lambda 中间件从 requestContext 注入 `ClientCertPem`;进程内测试直接把扩展塞进请求
//! (本地 server 无该中间件,故 X.509 路径靠显式注入激活——与设计"仅 clientCert 存在才触发"一致)。

use agent_auth_http::mtls::ClientCertPem;
use agent_auth_http::ports::WorkloadTrustStore;
use agent_auth_http::{build_router, AppState};
use agent_auth_workload::{TrustBinding, TrustMechanism};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tower::ServiceExt;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::asn1::Ia5String;
use x509_cert::der::{pem::LineEnding, EncodePem};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::{Time, Validity};

use p256::ecdsa::{DerSignature, SigningKey};

const HOST: &str = "auth.customer.example"; // SelfHosted configured_host = issuer origin
const TD: &str = "acme.example";
const RS: &str = "https://mcp.rs.example.com";

/// 造一张带指定 SAN URI 的叶子证书 PEM(测试样本;真机是 SPIRE 签的 SVID)。
fn make_svid_pem(san_uris: &[&str]) -> String {
    make_svid_pem_with_validity(
        san_uris,
        Validity::from_now(Duration::from_secs(3600)).unwrap(),
    )
}

fn make_svid_pem_with_validity(san_uris: &[&str], validity: Validity) -> String {
    let signer = SigningKey::from_slice(&[9u8; 32]).unwrap();
    let vk = signer.verifying_key();
    let spki = SubjectPublicKeyInfoOwned::from_key(*vk).unwrap();
    let profile = Profile::Leaf {
        issuer: Name::from_str("CN=test-ca").unwrap(),
        enable_key_agreement: false,
        enable_key_encipherment: false,
    };
    let mut builder = CertificateBuilder::new(
        profile,
        SerialNumber::from(1u32),
        validity,
        Name::from_str("CN=svid").unwrap(),
        spki,
        &signer,
    )
    .unwrap();
    let sans: Vec<GeneralName> = san_uris
        .iter()
        .map(|u| GeneralName::UniformResourceIdentifier(Ia5String::new(*u).unwrap()))
        .collect();
    builder.add_extension(&SubjectAltName(sans)).unwrap();
    let cert: x509_cert::Certificate =
        <CertificateBuilder<_> as Builder>::build::<DerSignature>(builder).unwrap();
    cert.to_pem(LineEnding::LF).unwrap()
}

/// SelfHosted state,开 X.509-mTLS,phase P3;seed workload client + SpiffeX509 绑定。
async fn state_with_x509(pattern: &str) -> AppState {
    let mut state = AppState::dev(HOST);
    state.mtls_svid_enabled = true;
    state.phase = agent_auth_http::Phase::P3;
    state
        .seed_workload_client_with_policy("wl-x509", vec![RS.to_string()], vec!["kb:read".into()])
        .await;
    state
        .workload_trust
        .put(
            "",
            "b-x509".to_string(),
            TrustBinding {
                tenant_id: "default".into(),
                mechanism: TrustMechanism::SpiffeX509 {
                    trust_domain: TD.into(),
                    spiffe_id_pattern: pattern.into(),
                },
                mapped_client_id: "wl-x509".into(),
            },
        )
        .await
        .unwrap();
    state
}

/// POST /token client_credentials,可选注入 ClientCertPem 扩展 + 可选 body client_assertion。
async fn post_token(
    router: &axum::Router,
    cert_pem: Option<String>,
    extra_form: &str,
) -> (StatusCode, serde_json::Value) {
    let form = format!("grant_type=client_credentials&resource={RS}&scope=kb:read{extra_form}");
    let request_host = if cert_pem.is_some() {
        format!("mtls.{HOST}")
    } else {
        HOST.to_string()
    };
    let mut req = Request::builder()
        .method("POST")
        .uri("/token")
        .header("host", request_host)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(form))
        .unwrap();
    if let Some(pem) = cert_pem {
        req.extensions_mut().insert(ClientCertPem(pem));
    }
    let resp = router.clone().oneshot(req).await.unwrap();
    let st = resp.status();
    let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        st,
        serde_json::from_slice(&b).unwrap_or(serde_json::json!({})),
    )
}

// ---- 合法 X.509-SVID 换 2LO ----
#[tokio::test]
async fn valid_x509_svid_mints_2lo() {
    let state = state_with_x509("spiffe://acme.example/agent/*").await;
    let (router, _) = build_router(state);
    let pem = make_svid_pem(&["spiffe://acme.example/agent/kb"]);
    let (st, body) = post_token(&router, Some(pem), "").await;
    assert_eq!(st, StatusCode::OK, "合法 SVID 应换 2LO(got {body:?})");
    let at = body["access_token"].as_str().unwrap();
    let claims: serde_json::Value = {
        use base64::Engine;
        let p: Vec<&str> = at.split('.').collect();
        let d = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(p[1])
            .unwrap();
        serde_json::from_slice(&d).unwrap()
    };
    assert_eq!(
        claims["iss"],
        format!("https://{HOST}"),
        "mTLS request Host stays dedicated while token issuer remains the configured AS host"
    );
    assert_eq!(claims["sub"], "wl-x509");
    assert_eq!(claims["aud"], serde_json::json!([RS]));
    assert!(body["refresh_token"].is_null(), "2LO 无 refresh");
}

#[tokio::test]
async fn expired_and_not_yet_valid_x509_svids_rejected() {
    let state = state_with_x509("spiffe://acme.example/agent/*").await;
    let (router, _) = build_router(state);
    let now = SystemTime::now();
    let expired = make_svid_pem_with_validity(
        &["spiffe://acme.example/agent/kb"],
        Validity {
            not_before: Time::try_from(now - Duration::from_secs(7200)).unwrap(),
            not_after: Time::try_from(now - Duration::from_secs(3600)).unwrap(),
        },
    );
    let (expired_status, expired_body) = post_token(&router, Some(expired), "").await;
    assert_eq!(expired_status, StatusCode::UNAUTHORIZED);
    assert_eq!(expired_body["error"], "invalid_client");
    assert!(expired_body.get("access_token").is_none());

    let future = make_svid_pem_with_validity(
        &["spiffe://acme.example/agent/kb"],
        Validity {
            not_before: Time::try_from(now + Duration::from_secs(3600)).unwrap(),
            not_after: Time::try_from(now + Duration::from_secs(7200)).unwrap(),
        },
    );
    let (future_status, future_body) = post_token(&router, Some(future), "").await;
    assert_eq!(future_status, StatusCode::UNAUTHORIZED);
    assert_eq!(future_body["error"], "invalid_client");
    assert!(future_body.get("access_token").is_none());
}

// ---- 无证书扩展 → X.509 不激活(回落普通 client_credentials → SVID 未实现拒)----
#[tokio::test]
async fn no_client_cert_does_not_activate_x509() {
    let state = state_with_x509("spiffe://acme.example/agent/*").await;
    let (router, _) = build_router(state);
    // 无 ClientCertPem 扩展、无 client_assertion → 落普通 client_credentials 分派 → 拒(无凭证)。
    let (st, _) = post_token(&router, None, "").await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "无证书 + 无 assertion 应被普通 2LO 分派拒(X.509 路径未激活)"
    );
}

#[tokio::test]
async fn x509_svid_pem_client_assertion_does_not_activate_mtls() {
    let state = state_with_x509("spiffe://acme.example/agent/*").await;
    let (router, _) = build_router(state);
    let pem = make_svid_pem(&["spiffe://acme.example/agent/kb"]);
    let assertion = url::form_urlencoded::Serializer::new(String::new())
        .append_pair(
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        )
        .append_pair("client_assertion", &pem)
        .finish();
    let (status, body) = post_token(&router, None, &format!("&{assertion}")).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a copied certificate must not become a bearer assertion: {body}"
    );
    assert_eq!(body["error"], "invalid_client");
    assert!(body.get("access_token").is_none());
}

// ---- 连接层身份排他(H1):cert 存在时忽略 body client_assertion ----
#[tokio::test]
async fn client_cert_identity_is_exclusive_over_body_assertion() {
    let state = state_with_x509("spiffe://acme.example/agent/*").await;
    let (router, _) = build_router(state);
    // 合法证书 + body 塞一个(格式合法但内容无关的)client_assertion → 仍以证书判定 → 200。
    let pem = make_svid_pem(&["spiffe://acme.example/agent/kb"]);
    let extra = "&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=ey.fake.fake";
    let (st, body) = post_token(&router, Some(pem), extra).await;
    assert_eq!(
        st,
        StatusCode::OK,
        "证书存在时以连接层身份判定、忽略 body assertion(got {body:?})"
    );
    // sub 在签出的 2LO token 里(= 证书映射的 wl-x509),证明用证书身份而非 body assertion。
    let at = body["access_token"].as_str().unwrap();
    let claims: serde_json::Value = {
        use base64::Engine;
        let p: Vec<&str> = at.split('.').collect();
        let d = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(p[1])
            .unwrap();
        serde_json::from_slice(&d).unwrap()
    };
    assert_eq!(
        claims["sub"], "wl-x509",
        "以连接层证书身份签发(非 body assertion)"
    );
}

// ---- 跨 trust domain / pattern 不符 → 拒 ----
#[tokio::test]
async fn cross_trust_domain_and_pattern_miss_rejected() {
    let state = state_with_x509("spiffe://acme.example/agent/*").await;
    let (router, _) = build_router(state);
    // 跨 trust domain(evil.example)→ 无匹配绑定拒。
    let cross = make_svid_pem(&["spiffe://evil.example/agent/kb"]);
    assert_eq!(
        post_token(&router, Some(cross), "").await.0,
        StatusCode::UNAUTHORIZED
    );
    // pattern 不符(svc 而非 agent)→ 拒。
    let miss = make_svid_pem(&["spiffe://acme.example/svc/db"]);
    assert_eq!(
        post_token(&router, Some(miss), "").await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn ambiguous_x509_svid_bindings_rejected() {
    let state = state_with_x509("spiffe://acme.example/agent/*").await;
    state
        .seed_workload_client_with_policy(
            "wl-x509-exact",
            vec![RS.to_string()],
            vec!["kb:read".into()],
        )
        .await;
    state
        .workload_trust
        .put(
            "",
            "b-x509-exact".to_string(),
            TrustBinding {
                tenant_id: "default".into(),
                mechanism: TrustMechanism::SpiffeX509 {
                    trust_domain: TD.into(),
                    spiffe_id_pattern: "spiffe://acme.example/agent/kb".into(),
                },
                mapped_client_id: "wl-x509-exact".into(),
            },
        )
        .await
        .unwrap();
    let (router, _) = build_router(state);
    let pem = make_svid_pem(&["spiffe://acme.example/agent/kb"]);
    let (status, body) = post_token(&router, Some(pem), "").await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "overlapping X.509-SVID bindings must fail closed: {body}"
    );
    assert_eq!(body["error"], "invalid_client");
    assert!(body.get("access_token").is_none());
}

// ---- SAN 无 spiffe URI / 多 URI → 拒 ----
#[tokio::test]
async fn bad_san_rejected() {
    let state = state_with_x509("spiffe://acme.example/agent/*").await;
    let (router, _) = build_router(state);
    // 非 spiffe URI。
    let http = make_svid_pem(&["https://acme.example/agent"]);
    assert_eq!(
        post_token(&router, Some(http), "").await.0,
        StatusCode::UNAUTHORIZED
    );
    // 多 URI(冒充歧义)。
    let multi = make_svid_pem(&["spiffe://acme.example/agent/kb", "https://x.example/"]);
    assert_eq!(
        post_token(&router, Some(multi), "").await.0,
        StatusCode::UNAUTHORIZED
    );
}

// ---- feature 关:即便有证书也不走 X.509(回落普通 2LO 拒)----
#[tokio::test]
async fn feature_off_does_not_activate_x509() {
    let mut state = AppState::dev(HOST);
    state.mtls_svid_enabled = false; // 关
    state.phase = agent_auth_http::Phase::P3;
    state
        .seed_workload_client_with_policy("wl-x509", vec![RS.to_string()], vec!["kb:read".into()])
        .await;
    let (router, _) = build_router(state);
    let pem = make_svid_pem(&["spiffe://acme.example/agent/kb"]);
    // 证书在,但 flag 关 → 落普通 client_credentials → 拒(未激活 X.509)。
    let (st, _) = post_token(&router, Some(pem), "").await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "flag 关时证书不触发 X.509 路径"
    );
}

// ---- SaaS 形态即便 flag 想开也不生效(B1;直接构造 mtls_svid_enabled=true + Saas → handle_x509 fail-closed)----
#[tokio::test]
async fn saas_form_x509_fail_closed() {
    let mut state = AppState::dev(HOST);
    state.form = agent_auth_discovery::Form::Saas {
        zone: "aws.example.com".into(),
        control_host: "c.aws.example.com".into(),
    };
    state.saas_tenants = std::sync::Arc::new(vec!["t1".to_string()]);
    // 模拟"误开"(from_env_aws 会挡,但直接构造绕过 → handle_x509 里 self_hosted_issuer 返 None fail-closed)。
    state.mtls_svid_enabled = true;
    state.phase = agent_auth_http::Phase::P3;
    let _ = Arc::clone(&state.workload_trust);
    let (router, _) = build_router(state);
    let pem = make_svid_pem(&["spiffe://acme.example/agent/kb"]);
    // SaaS host 请求 + 证书 → handle_x509 因 Saas 无 self_hosted_issuer fail-closed 拒。
    let form = format!("grant_type=client_credentials&resource={RS}&scope=kb:read");
    let mut req = Request::builder()
        .method("POST")
        .uri("/token")
        .header("host", "t1.aws.example.com")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(form))
        .unwrap();
    req.extensions_mut().insert(ClientCertPem(pem));
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "SaaS 形态 X.509 fail-closed(仅 SelfHosted,B1)"
    );
}
