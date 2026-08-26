//! `GET /rs/attributes`(spec 007 §6.1,C8.11)—— RS 侧读取"自己命名空间(=token aud)下当前用户的属性"。
//!
//! **决策真相源:docs/DESIGN §6.1。** RS 把自身授权语义(如 EK 的 `role=admin`)托管到 AS,经本端点用
//! 自己已有的 access token 读回。AS **语义无知**,只按命名空间隔离下发。
//!
//! 契约(spec 007 收敛后,双评审硬化):
//! - **严格准入**:`typ==at+jwt`(verify_access_token 已校)+ `aud` 单元素数组(single_aud_strict,拒裸串/多元素)
//!   + `sub_type==user`(拒 2LO agent/service)+ `iss == 当前 Host 派生 issuer`(拒跨租户 token)
//!   + **拒 `aud==<issuer>/userinfo`**(userinfo token 不当属性 namespace,闭合与 /userinfo 的双向隔离,C2.11)。
//! - **命名空间键恒取自已验签 token 的 `aud`**,绝不接受请求参数指定 → RS-A token 读不到 RS-B 命名空间。
//! - **user 主体经 `jti`→`JtiStore` 反查 `user_id`**,绝不反解/直接用 pairwise `sub`(HMAC 单向)。映射缺失/
//!   过期/故障一律 **fail-closed**(不回退 sub)。
//! - **active-user gate**:解出 user 后强一致读 UserStatus,Disabled/Tombstoned/不存在/故障 fail-closed。
//! - 返回 `{sub, revision, attributes}`:`sub` 与入站 token 逐字节一致(展示用);`revision` 供前端 RMW If-Match。

use agent_auth_discovery::{derive_issuer, Form};
use agent_auth_token::claims::NAMESPACE;
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::attribute_namespace::{AttributeNamespaceStore, AudienceResolution};
use crate::federation_attributes::FederationAttributeMappingsStore;
use crate::ports::{Signer, UserStatus, UsersStore};
use crate::state::AppState;
use crate::verify::{single_aud_strict, verify_access_token};

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    raw.strip_prefix("Bearer ").map(|s| s.trim().to_string())
}

async fn visible_attributes(
    state: &AppState,
    logical_tenant: &str,
    canonical_namespace: &str,
    attributes: &crate::ports::NamespaceAttrs,
) -> Result<std::collections::BTreeMap<String, String>, crate::ports::StoreError> {
    let mut registries = std::collections::BTreeMap::new();
    for owner in attributes.federation_owners.values() {
        if !registries.contains_key(&owner.upstream_idp_id) {
            registries.insert(
                owner.upstream_idp_id.clone(),
                state
                    .federation_attribute_mappings
                    .get_registry(logical_tenant, &owner.upstream_idp_id)
                    .await?,
            );
        }
    }

    let mut visible = attributes.kv.clone();
    for (key, owner) in &attributes.federation_owners {
        let current = registries
            .get(&owner.upstream_idp_id)
            .and_then(Option::as_ref)
            .is_some_and(|registry| {
                registry.tenant_id == logical_tenant
                    && registry.upstream_idp_id == owner.upstream_idp_id
                    && registry.upstream_issuer == owner.upstream_issuer
                    && registry.mappings.iter().any(|mapping| {
                        mapping.mapping_id == owner.mapping_id
                            && mapping.revision == owner.mapping_revision
                            && mapping.enabled
                            && mapping.target_namespace == canonical_namespace
                            && mapping.target_key == *key
                    })
            });
        if !current {
            visible.remove(key);
        }
    }
    Ok(visible)
}

/// `GET /rs/attributes` 端点(C8.11)。
#[utoipa::path(
    get,
    path = "/rs/attributes",
    tag = "mcp",
    responses(
        (status = 200, description = "该 RS(=token aud)命名空间下当前用户的属性 {sub, revision, attributes}"),
        (status = 400, description = "Host/tenant 上下文无效"),
        (status = 401, description = "缺/无效 Bearer token / jti 映射缺失 / 被禁用户(fail-closed)"),
        (status = 403, description = "sub_type≠user / aud 非单元素 / aud=<issuer>/userinfo / 跨租户 iss / namespace 被阻断"),
        (status = 404, description = "SaaS 形态不可用"),
        (status = 503, description = "签名密钥、namespace registry 或用户存储不可用")
    )
)]
pub async fn rs_attributes_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    if matches!(state.form, Form::Saas { .. }) {
        return Err(StatusCode::NOT_FOUND);
    }
    let token = bearer_token(&headers).ok_or(StatusCode::UNAUTHORIZED)?;

    // tenant 分区(spec 020 §2.3):jti / users 查询按本 Host 对应 tenant 隔离。flag 关→空串透传。
    let tenant =
        crate::tenant::tenant_or_400(&state, &headers).map_err(|_| StatusCode::BAD_REQUEST)?;

    // 用自己的 JWKS 公钥验签(含 typ==at+jwt + client_id 存在,verify_access_token)。
    let signer = state
        .tenant_keys
        .resolve(&tenant)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let jwks_keys = signer
        .public_jwks()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let jwks: Vec<crate::jwks::Jwk> = jwks_keys.iter().map(crate::jwks::to_jwk).collect();
    let now = crate::token::current_unix_secs_pub();
    let verified = verify_access_token(&token, &jwks, now).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let claims = &verified.claims;

    // ── 严格准入 ──
    // (a) sub_type == user(拒 2LO agent/service:无用户身份、无 jti→user_id 映射)。
    let sub_type = claims
        .get(NAMESPACE)
        .and_then(|ns| ns.get("sub_type"))
        .and_then(|v| v.as_str());
    if sub_type != Some("user") {
        return Err(StatusCode::FORBIDDEN);
    }
    // (b) aud 单元素数组(拒裸字符串/多元素,C2.5a)。
    let aud = single_aud_strict(claims).ok_or(StatusCode::FORBIDDEN)?;
    // (c) iss == 当前 Host 派生 issuer(拒跨租户 token:A 租户签的 token 打到 B 租户 Host)。
    let issuer = crate::hostutil::issuer_host(&headers)
        .and_then(|h| derive_issuer(&h, &state.form).ok())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let token_iss = claims.get("iss").and_then(|v| v.as_str());
    if token_iss != Some(issuer.as_str()) {
        return Err(StatusCode::FORBIDDEN);
    }
    // (d) 拒 aud==<issuer>/userinfo(userinfo token 不当属性 namespace;闭合双向隔离,不破坏 C2.11)。
    let userinfo_resource = format!("{}/userinfo", issuer.as_str());
    if aud == userinfo_resource {
        return Err(StatusCode::FORBIDDEN);
    }

    // ── user 主体经 jti 反查(绝不解 pairwise sub)──
    let jti = claims
        .get("jti")
        .and_then(|v| v.as_str())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if !state.region.owns_id(jti) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    // jti tenant 分区键:与 token.rs 落映射口径一致(空 tenant → "default")。
    let jti_tenant = if tenant.is_empty() {
        "default"
    } else {
        tenant.as_str()
    };
    let Some(jti_store) = &state.jti_store else {
        // 未配 jti 映射存储 → 无法安全解析 user_id → fail-closed。
        return Err(StatusCode::UNAUTHORIZED);
    };
    let user_id = match crate::jti_authority::read_current_jti(
        jti_store.as_ref(),
        jti_tenant,
        jti,
        crate::token::current_unix_secs_pub,
    )
    .await
    {
        Ok(crate::jti_authority::JtiAuthority::Current(rec)) => rec.user_id,
        Ok(crate::jti_authority::JtiAuthority::Expired)
        | Ok(crate::jti_authority::JtiAuthority::Missing) => return Err(StatusCode::UNAUTHORIZED), // 映射缺失/过期 → fail-closed(不回退 sub)
        Err(_) => return Err(StatusCode::SERVICE_UNAVAILABLE), // 存储故障 → fail-closed
    };

    // ── active-user gate(强一致读 status;非 Active 一律 fail-closed)──
    let user = match state.users.get_by_id(&tenant, &user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return Err(StatusCode::UNAUTHORIZED),
        Err(_) => return Err(StatusCode::SERVICE_UNAVAILABLE),
    };
    if user.status != UserStatus::Active {
        return Err(StatusCode::UNAUTHORIZED); // Disabled / Tombstoned fail-closed
    }

    let canonical_namespace = match state.attribute_namespaces.resolve(&tenant, &aud).await {
        Ok(AudienceResolution::Active {
            canonical_namespace,
        }) => canonical_namespace,
        Ok(AudienceResolution::Unbound) => aud.clone(),
        Ok(AudienceResolution::Blocked) => return Err(StatusCode::FORBIDDEN),
        Err(_) => return Err(StatusCode::SERVICE_UNAVAILABLE),
    };

    // ── 返回解析后 canonical 命名空间下的属性(无 → 空 object;revision 供 RMW If-Match)──
    let sub = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let logical_tenant = if tenant.is_empty() {
        "default"
    } else {
        tenant.as_str()
    };
    let (revision, kv) = match user.attributes.get(&canonical_namespace) {
        Some(n) => (
            n.revision,
            visible_attributes(&state, logical_tenant, &canonical_namespace, n)
                .await
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
        ),
        None => (0, Default::default()),
    };
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({
            "sub": sub,
            "revision": revision,
            "attributes": kv,
        })),
    ))
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(rs_attributes_handler))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        federation_attributes::{
            FederationAttributeMappingsStore, MappingChange, MappingChangeOutcome, MappingMode,
            MappingSpec,
        },
        ports::{FederatedAttributeOwner, NamespaceAttrs},
    };

    #[tokio::test]
    async fn federation_owned_attributes_require_exact_current_mapping_target() {
        const TENANT: &str = "default";
        const IDP: &str = "corp";
        const ISSUER: &str = "https://idp.example.com";
        const NAMESPACE: &str = "https://resources.example.com/finance";

        let state = AppState::dev("localhost");
        let created = state
            .federation_attribute_mappings
            .change(
                TENANT,
                IDP,
                ISSUER,
                MappingChange::Create {
                    mapping_id: "fm_role".into(),
                    expected_registry_revision: 0,
                    spec: MappingSpec {
                        source_claim: "department".into(),
                        target_namespace: NAMESPACE.into(),
                        target_key: "role".into(),
                        mode: MappingMode::CopyString,
                    },
                },
            )
            .await
            .unwrap();
        let MappingChangeOutcome::Applied(registry) = created else {
            panic!("mapping fixture must be valid");
        };
        let mapping_revision = registry.mappings[0].revision;
        let owner = FederatedAttributeOwner {
            upstream_idp_id: IDP.into(),
            upstream_issuer: ISSUER.into(),
            mapping_id: "fm_role".into(),
            mapping_revision,
        };
        let current = NamespaceAttrs {
            revision: 1,
            kv: std::collections::BTreeMap::from([("role".into(), "admin".into())]),
            federation_owners: std::collections::BTreeMap::from([("role".into(), owner.clone())]),
        };
        assert_eq!(
            visible_attributes(&state, TENANT, NAMESPACE, &current)
                .await
                .unwrap(),
            current.kv
        );
        assert!(
            visible_attributes(
                &state,
                TENANT,
                "https://resources.example.com/other",
                &current,
            )
            .await
            .unwrap()
            .is_empty(),
            "a current mapping revision for another namespace must stay hidden"
        );

        let wrong_key = NamespaceAttrs {
            revision: 1,
            kv: std::collections::BTreeMap::from([("tier".into(), "admin".into())]),
            federation_owners: std::collections::BTreeMap::from([("tier".into(), owner)]),
        };
        assert!(
            visible_attributes(&state, TENANT, NAMESPACE, &wrong_key)
                .await
                .unwrap()
                .is_empty(),
            "a current mapping revision for another target key must stay hidden"
        );
    }
}
