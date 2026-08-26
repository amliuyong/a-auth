//! 进程内 e2e:BYOD 数据面 PRM 托管(投放方式 b,spec 010 §5.4 / C8.1b,P3)。
//!
//! 覆盖(对齐 spec 010 §5.4 Scenarios):
//! - 登记的 BYOD 域名 Host 命中 → 返回该 RS 的 PRM(issuer 从**存储绑定 tenant_id + form 重建**,非请求 Host)。
//! - 未登记 / 伪造 Host → 404(公开数据无枚举顾虑,防的是 misdirection 非泄露)。
//! - 注册期拒 issuer-origin host 作 BYOD 域名(SelfHosted configured_host / SaaS control_host / zone 子域)。
//! - 全局唯一:他人已登记同域名 → 409(conditional put attribute_not_exists 失败)。
//! - BYOD 未启用 → well-known 短路 404 + admin bind 拒。
//! - issuer origin 命中该路径仍 404(C8.1 不破)。
//! - 删 client 级联清 domain map 行(悬空防护)。

use std::{collections::HashMap, sync::Arc, time::Duration};

use agent_auth_discovery::Form;
use agent_auth_http::{
    admin_credentials::{
        AdminCredentialOwner, AdminCredentialRecord, AdminCredentialResolver, AdminCredentialSet,
        MemoryAdminCredentialStore,
    },
    build_router, current_unix_secs,
    origin_auth::{SaasOriginAuth, PRIMARY_ORIGIN_AUTH_HEADER},
    AppState,
};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

const HOST: &str = "auth.customer.example"; // SelfHosted configured_host(= issuer origin)
const ADMIN: &str = "Bearer dev-admin-token-not-for-prod";
const T1_ADMIN: &str = "Bearer t1-admin-secret-v1";
const T2_ADMIN: &str = "Bearer t2-admin-secret-v1";
const BYOD_DOMAIN: &str = "mcp.acme.example"; // RS 自带域名(非 issuer origin)
const RS_RESOURCE: &str = "https://mcp.acme.example";
const T2_BYOD_DOMAIN: &str = "mcp.beta.example";
const T2_RS_RESOURCE: &str = "https://mcp.beta.example";
const API_HOST: &str = "api-gw.execute-api.local";
const ORIGIN_PRIMARY: &str = "primary-origin-secret-at-least-32-bytes";
const ORIGIN_SECONDARY: &str = "secondary-origin-secret-at-least-32-bytes";

fn selfhosted_state(byod: bool) -> AppState {
    let mut s = AppState::dev(HOST);
    s.byod_enabled = byod;
    s
}

fn saas_state(byod: bool) -> AppState {
    let mut s = AppState::dev("c.aws.example.com");
    s.form = Form::Saas {
        zone: "aws.example.com".to_string(),
        control_host: "c.aws.example.com".to_string(),
    };
    s.saas_tenants = Arc::new(vec!["t1".to_string(), "t2".to_string()]);
    s.tenant_partitioning = true;
    let now = current_unix_secs();
    let store = MemoryAdminCredentialStore::default();
    store.put_set(
        "memory:platform",
        &AdminCredentialSet::single(
            AdminCredentialOwner::platform(),
            AdminCredentialRecord::explicit(
                "platform-v1",
                "dev-admin-token-not-for-prod",
                now - 60,
                now - 60,
                now + 86_400,
            ),
        ),
        now,
    );
    let mut tenant_refs = HashMap::new();
    for (tenant, token) in [("t1", "t1-admin-secret-v1"), ("t2", "t2-admin-secret-v1")] {
        let secret_ref = format!("memory:tenant:{tenant}");
        tenant_refs.insert(tenant.to_string(), secret_ref.clone());
        store.put_set(
            secret_ref,
            &AdminCredentialSet::single(
                AdminCredentialOwner::tenant(tenant),
                AdminCredentialRecord::explicit(
                    format!("{tenant}-v1"),
                    token,
                    now - 60,
                    now - 60,
                    now + 86_400,
                ),
            ),
            now,
        );
    }
    s.admin_credentials = Arc::new(AdminCredentialResolver::memory(
        Some("memory:platform".to_string()),
        tenant_refs,
        store,
        Duration::ZERO,
    ));
    s.saas_origin_auth = Arc::new(
        SaasOriginAuth::required(ORIGIN_PRIMARY.to_string(), ORIGIN_SECONDARY.to_string()).unwrap(),
    );
    s.byod_enabled = byod;
    s
}

fn admin_auth_for_host(host: &str) -> &'static str {
    match host {
        "t1.aws.example.com" => T1_ADMIN,
        "t2.aws.example.com" => T2_ADMIN,
        _ => ADMIN,
    }
}

fn request_from_viewer_host(
    method: &str,
    uri: &str,
    viewer_host: &str,
) -> axum::http::request::Builder {
    let builder = Request::builder().method(method).uri(uri);
    if viewer_host == "aws.example.com" || viewer_host.ends_with(".aws.example.com") {
        builder
            .header("host", API_HOST)
            .header("x-forwarded-host", viewer_host)
            .header(PRIMARY_ORIGIN_AUTH_HEADER, ORIGIN_PRIMARY)
    } else {
        builder.header("host", viewer_host)
    }
}

/// admin 建一个带 resource_ids 的 client(introspect 无关,只要 resource_ids 含目标)。
async fn admin_create_client(router: &axum::Router, host: &str, resource_id: &str) -> String {
    let body = serde_json::json!({
        "redirect_uris": ["https://rs.example/cb"],
        "introspect_enabled": true,
        "resource_ids": [resource_id],
    });
    let resp = router
        .clone()
        .oneshot(
            request_from_viewer_host("POST", "/admin/clients", host)
                .header("authorization", admin_auth_for_host(host))
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
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    v["client_id"].as_str().unwrap().to_string()
}

async fn bind_domain(
    router: &axum::Router,
    host: &str,
    domain: &str,
    resource_id: &str,
    client_id: &str,
    tenant_id: Option<&str>,
) -> StatusCode {
    let mut body = serde_json::json!({
        "domain": domain,
        "resource_id": resource_id,
        "client_id": client_id,
    });
    if let Some(t) = tenant_id {
        body["tenant_id"] = serde_json::json!(t);
    }
    let resp = router
        .clone()
        .oneshot(
            request_from_viewer_host("POST", "/admin/domains", host)
                .header("authorization", admin_auth_for_host(host))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    resp.status()
}

async fn unbind_domain(router: &axum::Router, host: &str, domain: &str) -> StatusCode {
    let path = format!("/admin/domains/{domain}");
    router
        .clone()
        .oneshot(
            request_from_viewer_host("DELETE", &path, host)
                .header("authorization", admin_auth_for_host(host))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

async fn delete_client(router: &axum::Router, host: &str, client_id: &str) -> StatusCode {
    let path = format!("/admin/clients/{client_id}");
    router
        .clone()
        .oneshot(
            request_from_viewer_host("DELETE", &path, host)
                .header("authorization", admin_auth_for_host(host))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

/// GET well-known PRM,以 x-forwarded-host 模拟 BYOD 入站 Host。返回 (status, body_json)。
async fn get_prm(router: &axum::Router, xfh: &str) -> (StatusCode, Option<serde_json::Value>) {
    get_prm_with_origin(router, xfh, Some(ORIGIN_PRIMARY)).await
}

async fn get_prm_with_origin(
    router: &axum::Router,
    xfh: &str,
    origin_credential: Option<&str>,
) -> (StatusCode, Option<serde_json::Value>) {
    let mut request = Request::builder()
        .uri("/.well-known/oauth-protected-resource")
        // host = API Gateway 自身域名(CloudFront→APIGW);x-forwarded-host = viewer BYOD 域名。
        .header("host", API_HOST)
        .header("x-forwarded-host", xfh);
    if let Some(credential) = origin_credential {
        request = request.header(PRIMARY_ORIGIN_AUTH_HEADER, credential);
    }
    let resp = router
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json = serde_json::from_slice::<serde_json::Value>(&b).ok();
    (status, json)
}

// ---- Scenario:登记的 BYOD 域名命中 → PRM(issuer 从存储绑定重建,SelfHosted)----
#[tokio::test]
async fn registered_byod_host_returns_prm_with_reconstructed_issuer() {
    let (router, _) = build_router(selfhosted_state(true));
    let cid = admin_create_client(&router, HOST, RS_RESOURCE).await;
    assert_eq!(
        bind_domain(&router, HOST, BYOD_DOMAIN, RS_RESOURCE, &cid, None).await,
        StatusCode::CREATED
    );

    let (status, json) = get_prm(&router, BYOD_DOMAIN).await;
    assert_eq!(status, StatusCode::OK, "登记的 BYOD 域名应返 PRM");
    let json = json.unwrap();
    assert_eq!(json["resource"], RS_RESOURCE);
    // ★ issuer 从存储 tenant_id(SelfHosted→default→configured_host)重建,**非**请求 Host(mcp.acme.example)。
    assert_eq!(
        json["authorization_servers"][0],
        format!("https://{HOST}"),
        "authorization_servers MUST 从存储绑定重建的 issuer,绝不用请求 Host 派生"
    );
    assert_ne!(
        json["authorization_servers"][0],
        format!("https://{BYOD_DOMAIN}"),
        "绝不把 authorization_servers 指向 RS 自己域名(misdirection)"
    );
}

// ---- Scenario:SaaS 下 issuer 从 tenant_id 重建为 https://{tenant}.{zone} ----
#[tokio::test]
async fn saas_byod_reconstructs_tenant_issuer() {
    let (router, _) = build_router(saas_state(true));
    // SaaS 下 admin 用租户子域 host 建 client(tenant_partitioning 默认关,tenant 空串,不影响本用例)。
    let cid = admin_create_client(&router, "t1.aws.example.com", RS_RESOURCE).await;
    assert_eq!(
        bind_domain(
            &router,
            "t1.aws.example.com",
            BYOD_DOMAIN,
            RS_RESOURCE,
            &cid,
            Some("t1")
        )
        .await,
        StatusCode::CREATED
    );
    let (status, json) = get_prm(&router, BYOD_DOMAIN).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        json.unwrap()["authorization_servers"][0],
        "https://t1.aws.example.com",
        "SaaS BYOD issuer = https://{{tenant_id}}.{{zone}}(从存储 tenant_id 重建)"
    );
}

#[tokio::test]
async fn saas_registered_hosts_resolve_only_their_stored_tenant_binding() {
    let (router, _) = build_router(saas_state(true));
    let t1_client = admin_create_client(&router, "t1.aws.example.com", RS_RESOURCE).await;
    let t2_client = admin_create_client(&router, "t2.aws.example.com", T2_RS_RESOURCE).await;

    assert_eq!(
        bind_domain(
            &router,
            "t1.aws.example.com",
            BYOD_DOMAIN,
            RS_RESOURCE,
            &t1_client,
            Some("t1")
        )
        .await,
        StatusCode::CREATED
    );
    assert_eq!(
        bind_domain(
            &router,
            "t2.aws.example.com",
            T2_BYOD_DOMAIN,
            T2_RS_RESOURCE,
            &t2_client,
            Some("t2")
        )
        .await,
        StatusCode::CREATED
    );

    let (t1_status, t1_prm) = get_prm(&router, BYOD_DOMAIN).await;
    assert_eq!(t1_status, StatusCode::OK);
    let t1_prm = t1_prm.unwrap();
    assert_eq!(t1_prm["resource"], RS_RESOURCE);
    assert_eq!(
        t1_prm["authorization_servers"][0],
        "https://t1.aws.example.com"
    );

    let (t2_status, t2_prm) = get_prm(&router, T2_BYOD_DOMAIN).await;
    assert_eq!(t2_status, StatusCode::OK);
    let t2_prm = t2_prm.unwrap();
    assert_eq!(t2_prm["resource"], T2_RS_RESOURCE);
    assert_eq!(
        t2_prm["authorization_servers"][0],
        "https://t2.aws.example.com"
    );

    assert_eq!(
        bind_domain(
            &router,
            "t2.aws.example.com",
            BYOD_DOMAIN,
            T2_RS_RESOURCE,
            &t2_client,
            Some("t2")
        )
        .await,
        StatusCode::CONFLICT,
        "a second tenant must not replace an existing global Host binding"
    );
    let (_, t1_after_conflict) = get_prm(&router, BYOD_DOMAIN).await;
    assert_eq!(t1_after_conflict.unwrap(), t1_prm);

    let (forged_status, forged_body) = get_prm(&router, "unregistered.attacker.example").await;
    assert_eq!(forged_status, StatusCode::NOT_FOUND);
    if let Some(body) = forged_body {
        assert!(body.get("resource").is_none());
        assert!(body.get("authorization_servers").is_none());
    }
}

// ---- Scenario(评审 B1/M1):SaaS 下 owner tenant 从认证 Host 派生,body.tenant_id 不一致 → 拒 ----
#[tokio::test]
async fn saas_bind_rejects_body_tenant_mismatch() {
    let (router, _) = build_router(saas_state(true));
    let cid = admin_create_client(&router, "t1.aws.example.com", RS_RESOURCE).await;
    // admin 在 t1 上下文,却声明 t2 或显式空 tenant_id → 403。
    for claimed in ["t2", ""] {
        assert_eq!(
            bind_domain(
                &router,
                "t1.aws.example.com",
                BYOD_DOMAIN,
                RS_RESOURCE,
                &cid,
                Some(claimed)
            )
            .await,
            StatusCode::FORBIDDEN,
            "body.tenant_id={claimed:?} 与认证 Host 派生租户不一致 MUST 拒"
        );
    }
}

#[tokio::test]
async fn saas_unbind_rejects_another_tenants_domain() {
    let (router, _) = build_router(saas_state(true));
    let cid = admin_create_client(&router, "t2.aws.example.com", RS_RESOURCE).await;
    assert_eq!(
        bind_domain(
            &router,
            "t2.aws.example.com",
            BYOD_DOMAIN,
            RS_RESOURCE,
            &cid,
            Some("t2")
        )
        .await,
        StatusCode::CREATED
    );

    assert_eq!(
        unbind_domain(&router, "t1.aws.example.com", BYOD_DOMAIN).await,
        StatusCode::FORBIDDEN,
        "t1 admin must not delete t2's global domain binding"
    );
    assert_eq!(
        get_prm(&router, BYOD_DOMAIN).await.0,
        StatusCode::OK,
        "forbidden cross-tenant unbind must leave the binding intact"
    );
    assert_eq!(
        unbind_domain(&router, "t2.aws.example.com", BYOD_DOMAIN).await,
        StatusCode::OK
    );
}

// ---- Scenario(评审 B1):SaaS 控制面 Host 上下文绑定 → 拒(无从确定 owner 租户)----
#[tokio::test]
async fn saas_bind_from_control_host_rejected() {
    let (router, _) = build_router(saas_state(true));
    // 先在 t1 建 client;平台 token 从控制 Host 调租户绑定 API 在鉴权域边界即拒。
    let cid = admin_create_client(&router, "t1.aws.example.com", RS_RESOURCE).await;
    assert_eq!(
        bind_domain(
            &router,
            "c.aws.example.com",
            BYOD_DOMAIN,
            RS_RESOURCE,
            &cid,
            Some("t1")
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "平台控制 token 不得从控制 Host 调租户绑定 API"
    );
}

// ---- Scenario:未登记 / 伪造 Host → 404 ----
#[tokio::test]
async fn saas_untrusted_edge_rejected_and_unregistered_host_404() {
    let (router, _) = build_router(saas_state(true));
    for credential in [None, Some("wrong-origin-credential")] {
        let (status, _) = get_prm_with_origin(&router, "evil.example", credential).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "缺失或错误 edge credential 时伪造 X-Forwarded-Host MUST 先拒"
        );
    }

    let (status, body) = get_prm(&router, "evil.example").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "可信边缘下未登记 Host MUST 404"
    );
    if let Some(body) = body {
        assert!(body.get("resource").is_none());
        assert!(body.get("authorization_servers").is_none());
    }
}

// ---- Scenario:issuer origin 命中该路径仍 404(C8.1 不破)----
#[tokio::test]
async fn issuer_origin_host_on_wellknown_404() {
    let (router, _) = build_router(selfhosted_state(true));
    // 即便有别的登记域名,issuer origin(configured_host)本身永无全局 PRM。
    let cid = admin_create_client(&router, HOST, RS_RESOURCE).await;
    let _ = bind_domain(&router, HOST, BYOD_DOMAIN, RS_RESOURCE, &cid, None).await;
    let (status, _) = get_prm(&router, HOST).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "issuer origin 上该路径 MUST 404"
    );
}

// ---- Scenario:注册期拒 issuer-origin host 作 BYOD 域名 ----
#[tokio::test]
async fn registration_rejects_issuer_origin_hosts_selfhosted() {
    let (router, _) = build_router(selfhosted_state(true));
    let cid = admin_create_client(&router, HOST, RS_RESOURCE).await;
    // configured_host 本身 = issuer origin → 拒。
    assert_eq!(
        bind_domain(&router, HOST, HOST, RS_RESOURCE, &cid, None).await,
        StatusCode::BAD_REQUEST,
        "SelfHosted configured_host 不可登记为 BYOD 域名"
    );
}

#[tokio::test]
async fn registration_rejects_issuer_origin_hosts_saas() {
    let (router, _) = build_router(saas_state(true));
    let cid = admin_create_client(&router, "t1.aws.example.com", RS_RESOURCE).await;
    // 各种 issuer-origin host:control_host / zone apex / 租户子域 / 嵌套子域 → 全拒。
    for bad in [
        "c.aws.example.com",    // control_host
        "aws.example.com",      // zone apex
        "t2.aws.example.com",   // 租户子域
        "a.t2.aws.example.com", // 嵌套子域
    ] {
        assert_eq!(
            bind_domain(
                &router,
                "t1.aws.example.com",
                bad,
                RS_RESOURCE,
                &cid,
                Some("t1")
            )
            .await,
            StatusCode::BAD_REQUEST,
            "SaaS issuer-origin host {bad} 不可登记"
        );
    }
}

// ---- Scenario:全局唯一——不能抢注他人已登记域名 ----
#[tokio::test]
async fn global_uniqueness_rejects_reregister() {
    let (router, _) = build_router(selfhosted_state(true));
    let cid1 = admin_create_client(&router, HOST, RS_RESOURCE).await;
    let cid2 = admin_create_client(&router, HOST, RS_RESOURCE).await;
    assert_eq!(
        bind_domain(&router, HOST, BYOD_DOMAIN, RS_RESOURCE, &cid1, None).await,
        StatusCode::CREATED
    );
    // 另一 client 抢注同域名 → 409(conditional put attribute_not_exists 失败)。
    assert_eq!(
        bind_domain(&router, HOST, BYOD_DOMAIN, RS_RESOURCE, &cid2, None).await,
        StatusCode::CONFLICT,
        "已登记域名不能被他人抢注(fleet 全局唯一)"
    );
}

// ---- Scenario:resource_id 必须 ∈ client.resource_ids ----
#[tokio::test]
async fn bind_rejects_resource_not_owned_by_client() {
    let (router, _) = build_router(saas_state(true));
    let cid = admin_create_client(&router, "t1.aws.example.com", RS_RESOURCE).await;
    assert_eq!(
        bind_domain(
            &router,
            "t1.aws.example.com",
            BYOD_DOMAIN,
            "https://other.rs",
            &cid,
            Some("t1")
        )
        .await,
        StatusCode::BAD_REQUEST,
        "resource_id 不在 client.resource_ids 内应拒"
    );
}

// ---- Scenario:BYOD 未启用 → well-known 短路 404 + admin bind 拒 ----
#[tokio::test]
async fn byod_disabled_shortcircuits() {
    let (router, _) = build_router(selfhosted_state(false));
    // well-known 短路 404(触 store 前)。
    let (status, _) = get_prm(&router, BYOD_DOMAIN).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // admin bind 拒(BYOD not enabled)。
    let cid = admin_create_client(&router, HOST, RS_RESOURCE).await;
    assert_eq!(
        bind_domain(&router, HOST, BYOD_DOMAIN, RS_RESOURCE, &cid, None).await,
        StatusCode::BAD_REQUEST
    );
}

// ---- Scenario:删 client 级联清 domain map 行 ----
#[tokio::test]
async fn delete_client_cascades_domain_unbind() {
    let (router, _) = build_router(saas_state(true));
    let cid = admin_create_client(&router, "t1.aws.example.com", RS_RESOURCE).await;
    assert_eq!(
        bind_domain(
            &router,
            "t1.aws.example.com",
            BYOD_DOMAIN,
            RS_RESOURCE,
            &cid,
            Some("t1")
        )
        .await,
        StatusCode::CREATED
    );
    // 命中确认。
    assert_eq!(get_prm(&router, BYOD_DOMAIN).await.0, StatusCode::OK);
    // 删 client。
    assert_eq!(
        delete_client(&router, "t1.aws.example.com", &cid).await,
        StatusCode::OK
    );
    // 级联清后 well-known 不再命中 → 404。
    assert_eq!(
        get_prm(&router, BYOD_DOMAIN).await.0,
        StatusCode::NOT_FOUND,
        "删 client 后其 BYOD 域名 map 行应级联清除"
    );
    // 且该域名可被重新登记(map 行已释放)。
    let cid2 = admin_create_client(&router, "t1.aws.example.com", RS_RESOURCE).await;
    assert_eq!(
        bind_domain(
            &router,
            "t1.aws.example.com",
            BYOD_DOMAIN,
            RS_RESOURCE,
            &cid2,
            Some("t1")
        )
        .await,
        StatusCode::CREATED,
        "级联释放后域名可重新登记"
    );
}

// ---- Scenario:unbind 后可重新登记 + 幂等 ----
#[tokio::test]
async fn unbind_releases_and_is_idempotent() {
    let (router, _) = build_router(selfhosted_state(true));
    let cid = admin_create_client(&router, HOST, RS_RESOURCE).await;
    let _ = bind_domain(&router, HOST, BYOD_DOMAIN, RS_RESOURCE, &cid, None).await;
    let unbind = |domain: String| {
        let router = router.clone();
        async move {
            router
                .oneshot(
                    Request::builder()
                        .method("DELETE")
                        .uri(format!("/admin/domains/{domain}"))
                        .header("host", HOST)
                        .header("authorization", ADMIN)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
        }
    };
    assert_eq!(unbind(BYOD_DOMAIN.to_string()).await, StatusCode::OK);
    // 幂等:再删仍 200。
    assert_eq!(unbind(BYOD_DOMAIN.to_string()).await, StatusCode::OK);
    // 释放后不再命中。
    assert_eq!(get_prm(&router, BYOD_DOMAIN).await.0, StatusCode::NOT_FOUND);
}
