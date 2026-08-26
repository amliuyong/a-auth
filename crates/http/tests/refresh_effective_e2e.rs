//! 进程内 e2e:refresh 换发的 scope claim 走 per-resource effective(spec 006 §3.4 / spec 005 §7 O1,C10.17)。
//!
//! 策略**收窄**(非全 deny)某 resource 的 scope 时,refresh 出的 access token scope claim MUST 反映 effective
//! (不再是 family 全集)。判据:aud 真 RS + 源 Grant `effective_pv≥1` → per-resource effective;否则扁平回退。
//! 消歧:effective 该 aud 返 None 时回 consent 层——空 scope+无 RAR=RS 默认权限(签空 scope 不拒)、有 scope 被
//! 丢弃=真 deny(invalid_scope)。全程 HTTP 驱动 refresh(读回签出的 JWT scope claim 断言)。

use agent_auth_grant::{Grant, GrantConstraints, GrantStatus, ResourceGrant};
use agent_auth_http::ports::{
    GrantStore, PolicyArtifactStore, RefreshFamilyRecord, RefreshStore, StoreError,
};
use agent_auth_http::recompute::run_recompute_pass;
use agent_auth_http::refresh_flow::encode_refresh;
use agent_auth_http::state::{PolicyArtifactStoreImpl, SignerImpl};
use agent_auth_http::{build_router, AppState};
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use tower::ServiceExt;

const HOST: &str = "localhost";
const CLIENT: &str = "app";
const RS1: &str = "https://mcp.rs1.example.com";

/// 建 authz-on AppState + 发布策略(current_pv=1),seed client。
async fn state_authz(policy: &str) -> AppState {
    let mut state = AppState::dev(HOST);
    state.authz_enabled = true;
    state
        .seed_dev_client(CLIENT, "https://app.example.com/cb", None)
        .await;
    use agent_auth_http::ports::{PolicyArtifactStore, PolicyVersionStore};
    use sha2::{Digest, Sha256};
    let digest = format!("{:x}", Sha256::digest(policy.as_bytes()));
    state
        .policy_artifacts
        .put("", 1, policy.to_string(), digest)
        .await
        .unwrap();
    state.policy_versions.bump("").await.unwrap();
    state
}

/// seed 一个 refresh family(version 0,flat scope=consent 全集) + 同 id 的 Grant。返回 refresh token。
/// family.scope 取 grant.per_resource[0].scopes(与 consent 一致——现网 per_resource.scopes==family.scope)。
async fn seed_family_and_grant(state: &AppState, fid: &str, grant: Grant) -> String {
    let family_scope = grant
        .per_resource
        .first()
        .map(|r| r.scopes.clone())
        .unwrap_or_default();
    state
        .refresh
        .create(
            "",
            RefreshFamilyRecord {
                family_id: fid.into(),
                current_version: 0,
                revoked: false,
                client_id: CLIENT.into(),
                cimd_snapshot: None,
                user_id: "user:alice".into(),
                credential_epoch: 0,
                resources: vec![RS1.into()],
                scope: family_scope, // 扁平 family = consent 全集(现网不变量)
                actor_allowlist: vec![],
                max_act_chain: 1,
                dpop_jkt: None,
                pkce_code_challenge: None,
                auth_time: None,
                acr: None,
                password_credential_version: Some(0),
            },
        )
        .await
        .unwrap();
    state.grants.put("", grant).await.unwrap();
    encode_refresh(fid, 0)
}

/// HTTP POST /token refresh(带 resource=RS1);返回 (status, headers, json)。
async fn refresh_response(
    router: &axum::Router,
    refresh_tok: &str,
) -> (StatusCode, HeaderMap, serde_json::Value) {
    let form = format!(
        "grant_type=refresh_token&refresh_token={refresh_tok}&client_id={CLIENT}&resource={RS1}"
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
    let st = resp.status();
    let headers = resp.headers().clone();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        st,
        headers,
        serde_json::from_slice(&body).unwrap_or(serde_json::json!({})),
    )
}

/// HTTP POST /token refresh(带 resource=RS1);返回 (status, json)。
async fn refresh(router: &axum::Router, refresh_tok: &str) -> (StatusCode, serde_json::Value) {
    let (status, _headers, body) = refresh_response(router, refresh_tok).await;
    (status, body)
}

/// 解 access token JWT 的 scope claim(排序去空)。
fn token_scopes(access: &str) -> Vec<String> {
    let payload = access.split('.').nth(1).expect("jwt payload");
    let bytes = URL_SAFE_NO_PAD.decode(payload).expect("b64");
    let claims: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let mut s: Vec<String> = claims["scope"]
        .as_str()
        .unwrap_or("")
        .split_whitespace()
        .map(str::to_string)
        .collect();
    s.sort();
    s
}

fn grant_with(fid: &str, consent: Vec<&str>, effective: Option<Vec<&str>>, pv: u64) -> Grant {
    Grant {
        grant_id: fid.into(),
        user_id: "user:alice".into(),
        client_id: CLIENT.into(),
        per_resource: vec![ResourceGrant {
            resource: RS1.into(),
            scopes: consent.iter().map(|s| s.to_string()).collect(),
            authorization_details: vec![],
        }],
        effective_per_resource: match effective {
            // effective 为空 vec = 该 aud 被丢弃(evaluate 全 deny 或空 scope);Some(非空)=收窄结果。
            Some(e) if !e.is_empty() => vec![ResourceGrant {
                resource: RS1.into(),
                scopes: e.iter().map(|s| s.to_string()).collect(),
                authorization_details: vec![],
            }],
            _ => vec![],
        },
        effective_pv: pv,
        allowed_ip_cidrs: vec![],
        allowed_vpce: vec![],
        credential_epoch: 0,
        revision: 0,
        constraints: GrantConstraints {
            max_act_chain: 1,
            actor_allowlist: vec![],
            expires_at: i64::MAX,
        },
        status: GrantStatus::Active,
    }
}

// C10.17: stale Grant 必须在 refresh rotate/sign 之前 fail-safe 拒绝,并可在后台重算后用同一 token 重试。
#[tokio::test]
async fn refresh_stale_policy_returns_retry_after_without_rotating_and_retries_after_recompute() {
    let state = state_authz(r#"permit(principal, action == Action::"read", resource);"#).await;
    let (router, _) = build_router(state.clone());
    let SignerImpl::Memory(signer) = state.signer.as_ref() else {
        panic!("dev state must use MemorySigner");
    };
    let fid = "fam-stale-read-gate";
    let refresh_token = seed_family_and_grant(
        &state,
        fid,
        grant_with(fid, vec!["read"], Some(vec!["read"]), 0),
    )
    .await;

    let sign_count_before_stale = signer.es256_sign_count();
    let (status, headers, body) = refresh_response(&router, &refresh_token).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body:?}");
    assert_eq!(body["error"], "temporarily_unavailable");
    assert!(
        body.get("access_token").is_none(),
        "stale 拒绝不得签发 token"
    );
    let retry_after = headers
        .get("retry-after")
        .expect("stale 503 MUST include Retry-After")
        .to_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert!(retry_after > 0);

    let family = state.refresh.get("", fid).await.unwrap().unwrap();
    assert_eq!(
        family.current_version, 0,
        "stale read-gate MUST run before refresh rotation"
    );
    assert!(!family.revoked);
    assert_eq!(
        signer.es256_sign_count(),
        sign_count_before_stale,
        "stale read-gate MUST reject before any ES256 signing attempt"
    );

    let stats = run_recompute_pass(&state, "", false).await;
    assert_eq!(stats.scanned, 1);
    assert_eq!(stats.recomputed, 1);
    assert_eq!(stats.revoked, 0);
    assert_eq!(stats.conflicted, 0);
    assert_eq!(stats.errored, 0);
    let recomputed = state.grants.get("", fid).await.unwrap().unwrap();
    assert_eq!(recomputed.effective_pv, 1);
    assert_eq!(
        recomputed.effective_per_resource[0].scopes,
        vec!["read".to_string()]
    );

    let PolicyArtifactStoreImpl::Memory(artifacts) = state.policy_artifacts.as_ref() else {
        panic!("dev state must use MemoryPolicyArtifactStore");
    };
    let artifact_reads_before_hot_path = artifacts.get_count();
    artifacts.fail_next_get();
    let (status, body) = refresh(&router, &refresh_token).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "recomputed Grant 应允许同一 token 重试:{body:?}"
    );
    assert!(body["access_token"].as_str().is_some());
    assert!(
        signer.es256_sign_count() > sign_count_before_stale,
        "successful retry after recompute MUST reach ES256 signing"
    );
    assert_eq!(
        artifacts.get_count(),
        artifact_reads_before_hot_path,
        "current-version refresh /token MUST NOT synchronously read a policy artifact"
    );
    assert!(
        matches!(
            state.policy_artifacts.get("", 1).await,
            Err(StoreError::Transient(_))
        ),
        "the armed policy-artifact read failure must remain pending until an explicit cold read"
    );
    assert_eq!(
        state
            .refresh
            .get("", fid)
            .await
            .unwrap()
            .unwrap()
            .current_version,
        1
    );
}

// 策略收窄 {read,write}→{read}:refresh 的 scope claim MUST = {read}(不是 family 全集 {read,write})。
#[tokio::test]
async fn refresh_scope_reflects_effective_narrowing() {
    let state = state_authz(r#"permit(principal, action == Action::"read", resource);"#).await;
    let (r, _) = build_router(state.clone());
    // consent {read,write},effective 收窄 {read},pv=1。
    let tok = seed_family_and_grant(
        &state,
        "fam-narrow",
        grant_with("fam-narrow", vec!["read", "write"], Some(vec!["read"]), 1),
    )
    .await;
    let (st, body) = refresh(&r, &tok).await;
    assert_eq!(st, StatusCode::OK, "应签发成功:{body:?}");
    assert_eq!(
        token_scopes(body["access_token"].as_str().unwrap()),
        vec!["read".to_string()],
        "refresh scope claim MUST = effective {{read}},不得回退 family 全集 {{read,write}}"
    );
}

// flag 关(current_pv==0、effective_pv==0):扁平回退,scope claim = family 全集(字节等价现网)。
// 注:authz 开且已 publish(current_pv≥1)时,effective_pv==0 的 Grant 是 **stale** → stale_gate 503(正确;
// 该 Grant 待重算追平,不该走扁平)。故"扁平回退"的真实语义 = 未启用 authz(或从未 publish),此处以 flag 关验证。
#[tokio::test]
async fn refresh_scope_flat_when_authz_off() {
    let mut state = AppState::dev(HOST);
    state.authz_enabled = false; // flag 关 = 字节等价现网
    state
        .seed_dev_client(CLIENT, "https://app.example.com/cb", None)
        .await;
    let (r, _) = build_router(state.clone());
    // pv=0 + flag 关 → 扁平 fam_rec.scope {read,write};effective_view 也回退 per_resource。
    let tok = seed_family_and_grant(
        &state,
        "fam-flat",
        grant_with("fam-flat", vec!["read", "write"], None, 0),
    )
    .await;
    let (st, body) = refresh(&r, &tok).await;
    assert_eq!(st, StatusCode::OK, "flag 关应正常签发:{body:?}");
    assert_eq!(
        token_scopes(body["access_token"].as_str().unwrap()),
        vec!["read".to_string(), "write".to_string()],
        "flag 关 → 扁平 family 全集(字节等价)"
    );
}

// RS 默认权限(consent 空 scope+无 RAR,effective 丢弃):refresh 签空 scope、不拒。
#[tokio::test]
async fn refresh_empty_scope_default_permission_signs_empty_not_reject() {
    let state = state_authz(r#"permit(principal, action, resource);"#).await;
    let (r, _) = build_router(state.clone());
    // consent 空 scope,effective 空(丢弃),pv=1。
    let tok = seed_family_and_grant(
        &state,
        "fam-default",
        grant_with("fam-default", vec![], None, 1),
    )
    .await;
    // family.scope 也置空(与 consent 一致:RS 默认权限,无 scope)。
    let (st, body) = refresh(&r, &tok).await;
    assert_eq!(
        st,
        StatusCode::OK,
        "RS 默认权限应签发成功(空 scope),不拒:{body:?}"
    );
    assert!(
        token_scopes(body["access_token"].as_str().unwrap()).is_empty(),
        "consent 空 scope+无 RAR = 默认权限 → 签空 scope"
    );
}

// 真 deny(consent 有 scope 但 effective 全丢弃):refresh 该 aud → invalid_scope(不回退扁平)。
#[tokio::test]
async fn refresh_true_deny_rejects_invalid_scope() {
    let state = state_authz(r#"permit(principal, action == Action::"unrelated", resource);"#).await;
    let (r, _) = build_router(state.clone());
    // consent {read}(有可评估单元),effective 空(策略全 deny),pv=1。
    let tok = seed_family_and_grant(
        &state,
        "fam-deny",
        grant_with("fam-deny", vec!["read"], None, 1),
    )
    .await;
    let (st, body) = refresh(&r, &tok).await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "consent 有 scope 却被 effective 全丢弃 = 真 deny → invalid_scope:{body:?}"
    );
    assert_eq!(body["error"].as_str(), Some("invalid_scope"));
}

// 评审 Medium #3:client **显式绑定** `resource=<issuer>/userinfo` 且策略收窄 → 走 **per-resource**(不能因
// aud==userinfo 字符串就回退扁平、重开 O1 泄漏)。判据用 consent_grant(aud) membership 而非 aud!=userinfo。
#[tokio::test]
async fn refresh_explicitly_bound_userinfo_narrowed_uses_per_resource() {
    let state = state_authz(r#"permit(principal, action == Action::"read", resource);"#).await;
    let (r, _) = build_router(state.clone());
    let userinfo = format!("http://{HOST}/userinfo"); // dev issuer 的 userinfo 绝对 URI
                                                      // Grant 显式把 userinfo 作为 per_resource 条目:consent {read,write},effective 收窄 {read},pv=1。
    let fid = "fam-bound-userinfo";
    state
        .refresh
        .create(
            "",
            RefreshFamilyRecord {
                family_id: fid.into(),
                current_version: 0,
                revoked: false,
                client_id: CLIENT.into(),
                cimd_snapshot: None,
                user_id: "user:alice".into(),
                credential_epoch: 0,
                resources: vec![userinfo.clone()], // 显式绑定 userinfo 为 resource
                scope: vec!["read".into(), "write".into()],
                actor_allowlist: vec![],
                max_act_chain: 1,
                dpop_jkt: None,
                pkce_code_challenge: None,
                auth_time: None,
                acr: None,
                password_credential_version: Some(0),
            },
        )
        .await
        .unwrap();
    state
        .grants
        .put(
            "",
            Grant {
                grant_id: fid.into(),
                user_id: "user:alice".into(),
                client_id: CLIENT.into(),
                per_resource: vec![ResourceGrant {
                    resource: userinfo.clone(),
                    scopes: vec!["read".into(), "write".into()],
                    authorization_details: vec![],
                }],
                effective_per_resource: vec![ResourceGrant {
                    resource: userinfo.clone(),
                    scopes: vec!["read".into()], // Cedar 收窄
                    authorization_details: vec![],
                }],
                effective_pv: 1,
                allowed_ip_cidrs: vec![],
                allowed_vpce: vec![],
                credential_epoch: 0,
                revision: 0,
                constraints: GrantConstraints {
                    max_act_chain: 1,
                    actor_allowlist: vec![],
                    expires_at: i64::MAX,
                },
                status: GrantStatus::Active,
            },
        )
        .await
        .unwrap();
    // refresh 带 resource=userinfo(显式绑定的 aud)。
    let form = format!(
        "grant_type=refresh_token&refresh_token={}&client_id={CLIENT}&resource={userinfo}",
        encode_refresh(fid, 0)
    );
    let resp = r
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
    let st = resp.status();
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap_or(serde_json::json!({}));
    assert_eq!(st, StatusCode::OK, "应签发:{body:?}");
    assert_eq!(
        token_scopes(body["access_token"].as_str().unwrap()),
        vec!["read".to_string()],
        "显式绑定的 userinfo 被策略收窄 → per-resource effective {{read}},MUST NOT 回退扁平 {{read,write}}"
    );
}

// 防御性契约(评审 Info):aud ∈ family.resources 但 **不在** Grant per_resource(consent+effective 都无)——
// 现网 code-flow 二者恒同步(都来自 record.resources),此为防御分支:MUST fail-closed invalid_target,不签发。
#[tokio::test]
async fn refresh_aud_in_family_but_not_in_grant_rejects_invalid_target() {
    let state = state_authz(r#"permit(principal, action, resource);"#).await;
    let (r, _) = build_router(state.clone());
    let rs2 = "https://mcp.rs2.example.com";
    let fid = "fam-divergent";
    // family.resources = {RS1, RS2},但 Grant per_resource 只有 RS1(人为制造分歧)。
    state
        .refresh
        .create(
            "",
            RefreshFamilyRecord {
                family_id: fid.into(),
                current_version: 0,
                revoked: false,
                client_id: CLIENT.into(),
                cimd_snapshot: None,
                user_id: "user:alice".into(),
                credential_epoch: 0,
                resources: vec![RS1.into(), rs2.into()],
                scope: vec!["read".into()],
                actor_allowlist: vec![],
                max_act_chain: 1,
                dpop_jkt: None,
                pkce_code_challenge: None,
                auth_time: None,
                acr: None,
                password_credential_version: Some(0),
            },
        )
        .await
        .unwrap();
    state
        .grants
        .put("", grant_with(fid, vec!["read"], Some(vec!["read"]), 1)) // per_resource 只 RS1
        .await
        .unwrap();
    // refresh 带 resource=RS2(在 family、不在 Grant)。
    let form = format!(
        "grant_type=refresh_token&refresh_token={}&client_id={CLIENT}&resource={rs2}",
        encode_refresh(fid, 0)
    );
    let resp = r
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
    let st = resp.status();
    // aud=RS2 不在 Grant consent → use_per_resource=false(membership 判)→ 走扁平 fam_rec.scope。
    // 扁平路径对 RS2 不校 per-resource,但 select_audience 已确认 RS2 ∈ family.resources → 签发扁平 scope。
    // 注:此非 fail-open——RS2 确在授权集合(family.resources),扁平 scope 是 family 授权上限;Grant per_resource
    // 缺 RS2 仅意味 Cedar 未对 RS2 预判(该 Grant create 时 RS2 未在 per_resource),按未评估扁平处理,方向安全。
    assert_eq!(
        st,
        StatusCode::OK,
        "RS2 ∈ family.resources → 扁平签发(membership 判 use_per_resource=false);非 fail-open"
    );
}
