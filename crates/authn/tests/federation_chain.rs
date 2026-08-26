//! 集成测试:联邦 callback **决策链**端到端(spec 003 §4)——组合已落地的纯逻辑件,证明它们
//! **正确串起来**(在 IO 编排 handler [4.8b] 写之前先锁住组合正确性;handler 只是按此序调 IO+这些纯函数)。
//!
//! 覆盖的链(callback 验签后的判定序,全 fail-closed):
//!   已验签 id_token claims
//!     → verify_upstream_id_token_claims(iss/aud/azp/nonce/exp/nbf/iat 全过 → 返 sub)
//!     → resolve_upstream_context(config 信任锚 tenant+issuer 一致 → 提取 acr/amr/auth_time)
//!     → federated_user_id(复合键 (tenant,issuer,sub) 派生本地 user_id)
//!     → inject_into_claims(acr/amr/auth_time 透传进待签 token claims)
//!
//! 这些件各自已有单元测试;本测试锁**组合**:同一份上游 claims 走完全链,产出自洽(sub 一致、
//! user_id 复合键、透传值原样)。真实 HTTP 往返(exchange_code/JwksFetcher)属 IO,走 4.9 mock-IdP e2e。

use agent_auth_authn::federation::{
    federated_user_id, inject_into_claims, resolve_upstream_context,
    verify_upstream_id_token_claims, FederationConfig, IdTokenExpectations, OidcRpParams,
    UpstreamProtocol,
};
use serde_json::json;

const SECRET: &[u8] = b"integration-test-server-secret";
const TENANT: &str = "default";
const ISSUER: &str = "https://idp.example.com";
const CLIENT_ID: &str = "as-rp-client";
const FLOW_NONCE: &str = "flow-nonce-abc";

fn config() -> FederationConfig {
    FederationConfig {
        tenant_id: TENANT.into(),
        upstream_idp_id: "okta".into(),
        protocol: UpstreamProtocol::Oidc,
        upstream_issuer: ISSUER.into(),
        strong_acr_values: vec!["urn:okta:loa:2fa".into()],
        oidc: Some(OidcRpParams {
            client_id: CLIENT_ID.into(),
            client_secret_ref: "secretsmanager:fed/okta".into(),
            authorization_endpoint: format!("{ISSUER}/authorize"),
            token_endpoint: format!("{ISSUER}/token"),
            jwks_uri: format!("{ISSUER}/jwks"),
            scopes: vec!["openid".into()],
        }),
    }
}

fn expectations(now: i64) -> IdTokenExpectations<'static> {
    IdTokenExpectations {
        upstream_issuer: ISSUER,
        client_id: CLIENT_ID,
        nonce: FLOW_NONCE,
        now,
        clock_skew_secs: 60,
    }
}

// 快乐路径:合法上游 id_token 走完整决策链,产出自洽的本地身份 + canonical assurance。
#[test]
fn full_callback_decision_chain_happy_path() {
    let now = 1_000_000_000;
    let claims = json!({
        "iss": ISSUER,
        "sub": "upstream-user-42",
        "aud": CLIENT_ID,
        "exp": now + 300,
        "iat": now,
        "nonce": FLOW_NONCE,
        "acr": "urn:okta:loa:2fa",
        "amr": ["pwd", "otp"],
        "auth_time": now - 30
    });

    // ① id_token claims 校验 → 返 sub。
    let sub = verify_upstream_id_token_claims(&claims, &expectations(now))
        .expect("合法 id_token 应过校验");
    assert_eq!(sub, "upstream-user-42");

    // ② 信任锚 + tenant 一致 → 提取上游认证上下文。
    let ctx = resolve_upstream_context(&claims, &config(), TENANT).expect("信任锚一致应放行");
    assert_eq!(
        ctx.acr.as_deref(),
        Some(agent_auth_authn::assurance::STRONG_ACR)
    );
    assert_eq!(ctx.amr, vec!["pwd".to_string(), "otp".to_string()]);
    assert_eq!(ctx.auth_time, Some(now - 30));

    // ③ 复合键派生本地 user_id(确定性 + 带联邦命名空间)。
    let uid = federated_user_id(SECRET, TENANT, ISSUER, sub);
    assert!(uid.starts_with("user:fed:v1:"));
    // 同输入可重现(handler 幂等:同一上游用户每次登录得同一本地 id)。
    assert_eq!(uid, federated_user_id(SECRET, TENANT, ISSUER, sub));

    // ④ canonical acr 与观测证据进入待签本 AS token claims。
    let mut out = serde_json::Map::new();
    inject_into_claims(&ctx, &mut out);
    assert_eq!(out["acr"], json!(agent_auth_authn::assurance::STRONG_ACR));
    assert_eq!(out["amr"], json!(["pwd", "otp"]));
    assert_eq!(out["auth_time"], json!(now - 30));
}

// 链在**第①步**(claims 校验)即 fail-closed:nonce 不符 → 整链不继续(防 id_token 重放)。
#[test]
fn chain_stops_at_nonce_mismatch() {
    let now = 1_000_000_000;
    let claims = json!({
        "iss": ISSUER, "sub": "u", "aud": CLIENT_ID,
        "exp": now + 300, "nonce": "attacker-supplied-nonce"
    });
    assert!(
        verify_upstream_id_token_claims(&claims, &expectations(now)).is_err(),
        "nonce 不符必须在链首拒(不进入 resolve/派生)"
    );
}

// 链在**第②步**(信任锚)fail-closed:claims 验过但 config 属别的租户 → 拒(纵深隔离 C10.19)。
#[test]
fn chain_stops_at_cross_tenant_config() {
    let now = 1_000_000_000;
    let claims = json!({
        "iss": ISSUER, "sub": "u", "aud": CLIENT_ID,
        "exp": now + 300, "nonce": FLOW_NONCE
    });
    // claims 校验过。
    assert!(verify_upstream_id_token_claims(&claims, &expectations(now)).is_ok());
    // 但请求租户 "t-other" != config.tenant_id "default" → resolve 拒。
    assert!(
        resolve_upstream_context(&claims, &config(), "t-other").is_err(),
        "跨租户 config 命中必须拒(C10.19 纵深)"
    );
}

// 同一 sub 跨不同上游 issuer 派生不同本地 user_id(链末防账户串号,F2)。
#[test]
fn chain_user_id_no_cross_issuer_collision() {
    let a = federated_user_id(SECRET, TENANT, "https://okta.example.com", "shared-sub");
    let b = federated_user_id(SECRET, TENANT, "https://entra.example.com", "shared-sub");
    assert_ne!(a, b, "同 sub 跨 IdP 必须派生不同本地身份(防串号)");
}
