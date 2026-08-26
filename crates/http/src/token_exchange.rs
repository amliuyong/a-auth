//! `POST /token` 的 `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`(RFC 8693 委托,spec 011)。
//!
//! agent 代表用户拿下游 RS 的委托 token。**双闸**(C7.2)+ 权限 ⊆ Grant(C7.3/4)+ subject 解析(C7.8)。
//! P1 载体 = **refresh-family 前身**(Task 1.4/§5.1):family 提供 user_id/resources/scope;
//! 前身退化的委托约束(评审收敛):`actor_allowlist = {family.client_id}`、`max_act_chain = 1`。
//!
//! 编排(不重述规则):
//! 1. **actor 身份** = 已认证 workload(复用 workload_flow 的 workload_oidc_jwt 认证,`actor_token` 承载平台
//!    OIDC JWT)。actor **不是**客户端自称(C7.2);裸 RS-bound access token **不可**作 actor(token 转用面)。
//! 2. **subject_token 先验签再信 jti**(评审真缺口):本 AS 签 + iss=本AS + 未过期,通过才取 jti → JtiStore
//!    反查 {user_id, family_id}(**绝不解 pairwise sub**,C7.8;HMAC 单向)。
//! 3. **双闸**:深度 ≤ max_act_chain(前身=1,即入站不得已带 act)+ 发起 actor ∈ actor_allowlist(前身=
//!    {family owning client})。
//! 4. **权限 ⊆ family**:换发 resource ∈ family.resources、scope ⊆ family.scope;超出拒(不内联补授权,C7.3)。
//! 5. **复核 family active**(C7.8/评审 M4:AS 在线操作,不因 subject_token 表面未过期就换发)。
//! 6. 签**委托 token**:sub = 用户在**目标 resource sector** 的 pairwise sub;`act.sub` = 发起 agent;
//!    命名空间 actor_types 记 agent 类型。**按 tenant 分区**查 jti(SaaS 隔离)。
//!
//! 决策真相源 docs §5.1/§5.2/§2.8 + spec 011 C7.1–C7.8 + CONFORMANCE C7。

use axum::{
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::ports::{ClientStore, GrantStore, RefreshStore, Signer};
use crate::state::AppState;
use crate::token::{err, TokenRequest, TokenResponse};
use agent_auth_discovery::derive_issuer;

/// RFC 8693 token-exchange grant type。
pub(crate) const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// subject_token_type:入站被代表用户身份(access_token / id_token)。
const TT_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
const TT_ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";

/// 处理 token-exchange(委托)。actor 身份复用 workload 认证(actor_token=平台 OIDC JWT)。
pub async fn handle(
    state: &AppState,
    headers: &HeaderMap,
    req: &TokenRequest,
) -> axum::response::Response {
    // 0. issuer + tenant(与其它路径同口径;tenant 从 issuer 派生,绝不客户端提供)。
    let Some(issuer) =
        crate::hostutil::issuer_host(headers).and_then(|h| derive_issuer(&h, &state.form).ok())
    else {
        return err(StatusCode::BAD_REQUEST, "invalid_request", "Host 非法").into_response();
    };
    // C10.22a 跨租户防伪造闸(spec 020;纵深 + 回归护栏,当前结构恒成立)。见 token.rs 同注。
    if !crate::tenant::issuer_belongs_to_request_tenant(
        state,
        headers,
        issuer.as_str(),
        crate::security_event::SecurityActor::system("token-exchange"),
    )
    .await
    {
        return err(StatusCode::BAD_REQUEST, "invalid_request", "iss 不属本租户").into_response();
    }
    let as_issuer = issuer.as_str();
    // tenant 分区(spec 020 §2.3,codex M1):从入站 Host 派生一次,贯穿 jti/refresh/grant/client 全链。
    // jti 反查一贯用 "default"(空 tenant 时保持后向兼容);store 物理键用 `tenant`(空=透传)。
    let tenant = match crate::tenant::tenant_or_400(state, headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let tenant_id = if tenant.is_empty() {
        "default".to_string()
    } else {
        tenant.clone()
    };

    // 1. 必需参数(RFC 8693)。subject_token(被代表用户)+ actor_token(发起 agent workload 身份)。
    let (Some(subject_token), Some(subject_token_type)) = (
        req.subject_token.as_deref(),
        req.subject_token_type.as_deref(),
    ) else {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "缺 subject_token / subject_token_type",
        )
        .into_response();
    };
    // subject_token 支持 access_token(ES256,typ=at+jwt)与 **id_token**(RS256,C7.8a)。
    // 两者验签路径分离(防 alg/typ 混淆),但**消歧口径统一**:都经 jti→grant_id 单指针定位源 Grant
    // (评审 Kiro M3:消歧与 subject_token 类型无关,jti 已唯一指向源 Grant;不做类型二分)。
    // id_token 路径的 grant.client_id==id_token.aud 纵深防御在 jrec 取得后校(防跨 client 转用)。
    if subject_token_type != TT_ACCESS_TOKEN && subject_token_type != TT_ID_TOKEN {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "subject_token_type 仅支持 access_token / id_token",
        )
        .into_response();
    }
    let subject_is_id_token = subject_token_type == TT_ID_TOKEN;

    // 2. **actor 身份 = 已认证 workload**(复用 workload_oidc_jwt 认证;actor_token 承载平台 OIDC JWT)。
    //    绝不把客户端自称/裸 RS-bound access token 当 actor(C7.2 / 评审:token 转用面)。
    let actor =
        match crate::workload_flow::authenticate_actor(state, headers, req, as_issuer, &tenant_id)
            .await
        {
            Ok(a) => a,
            Err(resp) => return resp,
        };

    // tombstone + require_dpop 闸(spec 005 §9.3 / spec 011 §7.2):token-exchange 的 actor 由 workload 认证
    // 得,`client_id` 来自信任绑定的 `mapped_client_id`——而信任绑定注册时 **MUST** 该 client 存在且为
    // workload(admin.rs),故**不变式:workload actor 恒有 ClientRecord**。补一次 actor client 读:
    //   · tombstoned → 拒(回收中不许发起委托);
    //   · 存在 → 取其 `require_dpop`(=true 的 actor **MUST** 出示 DPoP proof,下方 resolve_dpop_binding 传此
    //     标志缺 proof fail-closed 拒;出示则委托 token 绑其 jkt——能力解锁,非一律拒;委托准入真正的闸是
    //     Grant actor_allowlist,require_dpop 义为"要求 DPoP 约束"非"禁止换发");
    //   · **不存在(Ok(None))→ 拒 invalid_client(评审 codex Medium,fail-closed)**:client 被物理删除但
    //     信任绑定 + Grant actor_allowlist 残留时,`Ok(None)` **绝不**降级为 require_dpop=false——否则删 client
    //     即静默丢失其 client 级 DPoP 硬化策略。与上方 tombstone 拒同向(client 记录缺失/回收一律不发起委托)。
    let actor_require_dpop = match state.clients.get(&tenant, &actor.client_id).await {
        Ok(Some(c)) if c.is_tombstoned() => {
            return err(
                StatusCode::BAD_REQUEST,
                "invalid_client",
                "actor client 已回收",
            )
            .into_response()
        }
        Ok(Some(c)) => c.require_dpop,
        Ok(None) => {
            return err(
                StatusCode::BAD_REQUEST,
                "invalid_client",
                "actor client 记录不存在(信任绑定残留但 client 已删;fail-closed 拒,不丢失 require_dpop 策略)",
            )
            .into_response()
        }
        Err(_) => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "存储瞬时不可用",
            )
            .into_response()
        }
    };

    // per-client 限流(C10.7 / spec 005 §3.1):**认证后**按 `actor.client_id`(发起 agent 已过 workload
    // 认证,不可伪造;评审 HIGH#2 键为认证后主体)。token-exchange 无两阶段 lease,无 lease 交互。fail-open。
    if let Some(resp) = crate::ratelimit_gate::check(state, &tenant, &actor.client_id).await {
        return resp;
    }
    // 逐租户 ECC Sign 公平闸(spec 020 §3.1 / C10.14):全局闸之前(默认关字节等价)。
    if let Some(resp) = crate::ratelimit_gate::kms_sign_tenant_gate(state, &tenant).await {
        return resp;
    }
    // 全局 KMS Sign 前置并发闸(spec 005 §1.4 / C10.2;默认关)。token-exchange 无 code lease,超额直接 503 退避。
    if let Some(resp) = crate::ratelimit_gate::kms_sign_gate(state).await {
        return resp;
    }

    // 3. **subject_token 先验签再信 jti**(评审真缺口):本 AS 公钥验签 + iss=本AS + 未过期 + jti 提取。
    //    按类型分派验签器:access_token→ES256+typ=at+jwt;id_token→RS256+typ≠at+jwt+aud 单值。
    let now = crate::token::current_unix_secs_pub();
    let tenant_signer = match crate::tenant_keys::signer_or_503(state, &tenant).await {
        Ok(signer) => signer,
        Err(response) => return response,
    };
    let (jti, id_token_aud) = match verify_subject_and_extract_jti(
        tenant_signer.as_ref(),
        subject_token,
        subject_is_id_token,
        as_issuer,
        now,
    )
    .await
    {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if !state.region.owns_id(&jti) {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "subject_token belongs to another Region",
        )
        .into_response();
    }

    // 3a. **解析发起 actor 自己出示的 DPoP proof**(spec 011 §7.2,RFC 9449 §5,C7.9)。resolve_dpop_binding
    //     内部 htu 用**本 AS 已派生可信 issuer** 的 `<issuer>/token`(绝不用 proof 自称 htu 当权威;评审
    //     Kiro M1)、jti 重放 key 按可信 issuer 分区(M2),token-exchange 也是 `POST /token` 故天然正确。
    //     `actor_require_dpop`=true 的 actor 缺 proof → fail-closed 拒(不静默换出无约束委托 token)。
    let actor_jkt: Option<String> = match crate::dpop::resolve_dpop_binding(
        state,
        headers,
        &tenant,
        as_issuer,
        actor_require_dpop,
    )
    .await
    {
        Ok(j) => j,
        Err(resp) => return resp,
    };

    // 3b. **入站 sender-constraint 处理(spec 011 §7.2,C7.9;不静默降级 + holder-of-key 校验)**:
    //  - 入站 subject_token **带 cnf**(已 sender-constrained):委托 token 的 sender-constraint 是**重绑到
    //    下一持有者(发起 actor)**,不是双绑、不含入站 user key。但 **MUST** 先校 actor 持有入站 token 的
    //    同一 key(评审 codex High):
    //      · actor 出示 proof 且 `actor_jkt == 入站 cnf.jkt` → 允许(同 key 重绑,holder-of-key 保持)。
    //      · 否则(无 proof / key 不符 / 入站 cnf 无 jkt[非 DPoP 约束])→ 拒 `invalid_dpop_proof`:
    //        无 proof=不把 sender-constrained 链静默降级为 bearer;跨 key=挡"窃到入站 DPoP-bound token 但
    //        **不持有其 key**"者用自己 key 把它洗成新委托 token(holder-of-key 降级)。
    //  - 入站 **无 cnf**:actor 出示 proof → 委托 token 绑 actor jkt(opt-in sender-constrained);无 proof
    //    → bearer(现状,不变)。
    //  **覆盖范围(评审 Kiro Low)**:本闸只覆盖 subject_token 的降级面;actor_token 是认证凭据(不进输出
    //  token)、grant_ref 是 AS 短时自签(非 sender-constrained access token),均非降级向量。
    let delegation_cnf_jkt: Option<String> = match subject_token_claim(subject_token, "cnf") {
        Some(cnf) => {
            let inbound_jkt = cnf.get("jkt").and_then(|v| v.as_str());
            match (inbound_jkt, actor_jkt.as_deref()) {
                (Some(inb), Some(aj)) if aj == inb => Some(aj.to_string()),
                _ => {
                    return err(
                        StatusCode::BAD_REQUEST,
                        "invalid_dpop_proof",
                        "subject_token 已 sender-constrained(带 cnf):发起 actor MUST 出示持有同一 key 的 DPoP proof(actor_jkt==cnf.jkt);缺 proof / key 不符 / 非 DPoP 约束一律拒——不降级为 bearer、不允许跨 key 换绑(C7.9)",
                    )
                    .into_response();
                }
            }
        }
        None => actor_jkt, // 入站无 cnf:有 proof 绑 actor(opt-in),无为 bearer
    };

    // 4. subject 解析(C7.8):jti → {user_id, family_id}(按 tenant 分区)。绝不解 pairwise sub。
    // jti_store 未配 = 本部署未启用 token-exchange 主体解析(fail-closed)。
    let Some(jti_store) = state.jti_store.as_ref() else {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "本部署未启用 token-exchange(缺 jti 映射存储)",
        )
        .into_response();
    };
    let jrec = match crate::jti_authority::read_current_jti(
        jti_store.as_ref(),
        &tenant_id,
        &jti,
        crate::token::current_unix_secs_pub,
    )
    .await
    {
        Ok(crate::jti_authority::JtiAuthority::Current(r)) => r,
        Ok(crate::jti_authority::JtiAuthority::Missing) => {
            return err(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "subject_token 无对应 jti 映射(无法解析主体)",
            )
            .into_response()
        }
        Ok(crate::jti_authority::JtiAuthority::Expired) => {
            return err(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "subject_token 映射已过期",
            )
            .into_response()
        }
        Err(crate::ports::StoreError::Transient(_)) => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "存储瞬时不可用",
            )
            .into_response()
        }
        Err(_) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "存储错误",
            )
            .into_response()
        }
    };
    // C7.8a:access/ID token 同口径，必须由签发时落下的 jti→grant_id 单指针消歧。
    // 缺指针时绝不能按 family/resource 猜选 Grant。
    if jrec.grant_id.is_none() {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "subject_token 的 jti 映射缺少 Grant 指针",
        )
        .into_response();
    }

    // 5. Grant 前身 = refresh-family。无 family_id → 前身无授权载体,拒(P1 消歧退化不支持无 family 换发)。
    let Some(family_id) = jrec.family_id.as_deref() else {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "subject_token 无 Grant 前身(family),P1 不支持无 family 委托换发",
        )
        .into_response();
    };
    let fam = match state.refresh.get(&tenant, family_id).await {
        Ok(Some(f)) => f,
        Ok(None) => {
            return err(StatusCode::BAD_REQUEST, "invalid_grant", "Grant 前身不存在")
                .into_response()
        }
        Err(crate::ports::StoreError::Transient(_)) => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "存储瞬时不可用",
            )
            .into_response()
        }
        Err(_) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "存储错误",
            )
            .into_response()
        }
    };
    // 6. **复核 family active**(C7.8/评审 M4:AS 在线操作,不因 subject_token 未过期就换发)。
    if fam.revoked {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "源授权(Grant 前身)已吊销",
        )
        .into_response();
    }
    // 一致性:jti 映射的 user_id 应与 family 的 user_id 一致(纵深防御)。
    if fam.user_id != jrec.user_id {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "主体与 Grant 前身不一致",
        )
        .into_response();
    }
    match crate::user_gate::require_password_authority_version(
        state,
        &tenant,
        &jrec.user_id,
        fam.password_credential_version,
    )
    .await
    {
        crate::user_gate::PasswordGate::Allowed => {}
        crate::user_gate::PasswordGate::ChangeRequired => {
            return err(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "password authority changed after source authorization",
            )
            .into_response()
        }
        crate::user_gate::PasswordGate::Unavailable => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "password authority 查询失败",
            )
            .into_response()
        }
    }
    // **active-user gate(评审 codex High,spec 003 §1.4)**:委托换发签出的是**代表该用户**的 token
    // (deleg_sub 从 jrec.user_id 派生)——被代表用户 disable/tombstone 后 MUST 拒换发(否则 agent 仍能
    // 用旧 subject_token 换出代表已禁用户的委托 token)。read-gate,置签发前:Blocked→invalid_grant、
    // 查询失败→503(不 downgrade,与 family/Grant 联查同口径)。人类 user:* 均 gate,含联邦用户。
    match crate::user_gate::require_active_user_epoch(
        state,
        &tenant,
        &jrec.user_id,
        fam.credential_epoch,
    )
    .await
    {
        Ok(()) => {}
        Err(crate::user_gate::UserGate::Blocked) => {
            return err(StatusCode::BAD_REQUEST, "invalid_grant", "被代表用户已禁用")
                .into_response()
        }
        Err(crate::user_gate::UserGate::Unavailable) => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "user status 查询失败",
            )
            .into_response()
        }
        Err(crate::user_gate::UserGate::Allowed) => unreachable!(),
    }
    // **id_token 纵深防御(评审 codex/Kiro)**:id_token 的 aud 是签发给的 client_id;MUST 与源 Grant
    // (前身 family)的 client_id 一致——防 agent-A 拿 agent-B 的 id_token 发起委托(跨 client 转用)。
    // access_token 路径无此校验(其 jti→family 单指针已隐含归属;id_token 显式多校一层归属更稳)。
    if let Some(aud) = id_token_aud.as_deref() {
        if aud != fam.client_id {
            return err(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "id_token aud 与源 Grant 的 client 不一致(跨 client 转用)",
            )
            .into_response();
        }
    }

    // 6.5 **Grant 正式化权威源**(spec 011 §5.1,P2):access/ID token 的 jti 单指针加载 Grant，
    // 深度/身份/resource/scope 闸一律以 Grant 为准；Grant 缺失或不可用均 fail-closed。
    let gid = jrec.grant_id.as_deref().expect("grant_id checked above");
    // **迁移不变式**:当前 family 与 Grant 共用 id。若映射损坏成不一致，拒绝使用另一 Grant。
    if gid != family_id {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "jti 映射 grant_id 与 family_id 不一致(迁移不变式破坏,fail-closed)",
        )
        .into_response();
    }
    let mut grant = match state.grants.get(&tenant, gid).await {
        Ok(Some(g)) => g,
        Ok(None) => {
            return err(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "jti 指向的 Grant 不存在(权威源丢失,fail-closed)",
            )
            .into_response();
        }
        Err(crate::ports::StoreError::Transient(_)) => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "存储瞬时不可用",
            )
            .into_response();
        }
        Err(_) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "存储错误",
            )
            .into_response();
        }
    };
    if grant.user_id != jrec.user_id {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "主体与 Grant 不一致",
        )
        .into_response();
    }
    if grant.credential_epoch != fam.credential_epoch {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Grant lifecycle generation mismatch",
        )
        .into_response();
    }
    if grant.is_usable(now).is_err() {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "源 Grant 已吊销或过期",
        )
        .into_response();
    }

    // 6.6 **grant-ref 跨 Grant 换发**(spec 011 §4,C7.7):带 `grant_ref` 时**改用** grant_ref 指向的 Grant
    // (而非 jti 单指针的源 Grant),用于"用 Grant A 的 subject_token 换 Grant B 的 resource"。仍走下方双闸。
    // 闸链:①验签 grant-ref(ES256 + typ=grant-ref+jwt + iss=本AS + 未过期)→ ②**绑定闸** actor.client_id
    // (已认证 workload,不可伪造)== grant_ref.bound_agent(泄露被他人兑换即拒)→ ③加载 grant_ref.grant_id
    // 的 Grant + is_usable → ④**归属闸** grant.user_id == jrec.user_id(subject_token 证明的用户;挡"他人
    // id_token + 自己 grant_ref"拼接)。选中 Grant 覆盖上面的 grant,`effective_auth_grant` 指向它(Q5 修正)。
    // 不带 grant_ref 时:effective_auth_grant = family_id(维持 jti 单指针路径)。
    let mut effective_auth_grant = grant.grant_id.clone();
    if let Some(gref) = req.grant_ref.as_deref().filter(|s| !s.is_empty()) {
        // ① 验签 grant-ref(EC JWKS;专用 verifier 强制 typ=grant-ref+jwt)。
        let ec_keys = match tenant_signer.public_jwks().await {
            Ok(k) => k,
            Err(_) => {
                return err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "存储瞬时不可用",
                )
                .into_response()
            }
        };
        let jwks: Vec<crate::jwks::Jwk> = ec_keys.iter().map(crate::jwks::to_jwk).collect();
        let verified = match crate::verify::verify_grant_ref(gref, &jwks, now) {
            Ok(v) => v,
            Err(_) => {
                return err(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "grant_ref 验签/时效/typ 失败",
                )
                .into_response()
            }
        };
        // iss=本AS(不接受他方签发的 grant-ref)。
        if verified.claims.get("iss").and_then(|v| v.as_str()) != Some(as_issuer) {
            return err(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "grant_ref iss 非本 AS",
            )
            .into_response();
        }
        let (Some(ref_grant_id), Some(bound_agent)) = (
            verified.claims.get("grant_id").and_then(|v| v.as_str()),
            verified.claims.get("bound_agent").and_then(|v| v.as_str()),
        ) else {
            return err(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "grant_ref 缺 grant_id/bound_agent",
            )
            .into_response();
        };
        // ② 绑定闸:出示者(已认证 actor)MUST == grant-ref 绑定的 agent(泄露被他人兑换即拒,C7.7)。
        if actor.client_id != bound_agent {
            return err(
                StatusCode::FORBIDDEN,
                "access_denied",
                "grant_ref 绑定的 agent 与出示者不符(不可当泛用 bearer)",
            )
            .into_response();
        }
        // ③ 加载 grant_ref 选中的 Grant。
        let selected = match state.grants.get(&tenant, ref_grant_id).await {
            Ok(Some(g)) => g,
            Ok(None) => {
                return err(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "grant_ref 指向的 Grant 不存在",
                )
                .into_response()
            }
            Err(crate::ports::StoreError::Transient(_)) => {
                return err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "存储瞬时不可用",
                )
                .into_response()
            }
            Err(_) => {
                return err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "存储错误",
                )
                .into_response()
            }
        };
        if selected.is_usable(now).is_err() {
            return err(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "grant_ref 指向的 Grant 已吊销或过期",
            )
            .into_response();
        }
        // ④ 归属闸:选中 Grant 的属主 MUST == subject_token 证明的用户(挡他人 id_token + 自己 grant_ref 拼接)。
        if selected.user_id != jrec.user_id {
            return err(
                StatusCode::FORBIDDEN,
                "access_denied",
                "grant_ref 指向的 Grant 属主与 subject_token 用户不符",
            )
            .into_response();
        }
        if selected.credential_epoch != fam.credential_epoch {
            return err(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "grant_ref points to a stale lifecycle generation",
            )
            .into_response();
        }
        // 选中 Grant 覆盖(下方双闸 authorize_delegation/authorize_target 据它);auth_grant 指向它(Q5)。
        effective_auth_grant = selected.grant_id.clone();
        grant = selected;
    }

    // 7. **双闸**(C7.2):
    //    ① 深度闸 + ② 身份闸:Grant.authorize_delegation(actor∈allowlist +
    //       入站链深+本跳≤max_act_chain)。入站链深按真实嵌套计
    //       (act_chain_depth,RFC 8693 nested;u32::MAX 哨兵表解码失败 fail-closed)。
    let inbound_depth = subject_token_act_depth(subject_token);
    if let Err(e) = grant.authorize_delegation(&actor.client_id, inbound_depth) {
        return match e {
            agent_auth_grant::GrantError::ActorNotAllowed => err(
                StatusCode::FORBIDDEN,
                "access_denied",
                "发起 actor 不在 Grant actor_allowlist(委托身份闸)",
            ),
            _ => err(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "委托链深度超限(超过 Grant max_act_chain)",
            ),
        }
        .into_response();
    }
    //    ③ 叠加校验入站 `may_act`(C7.2,评审 MED#3):若 subject_token 带标准 RFC 8693 `may_act`,
    //       MUST 严格为**单对象** `{"sub":X}`(无数组/通配)且 X == 发起 actor,否则拒。多候选只走 allowlist。
    //       Grant/前身两路径都叠加此校验(与授权源正交)。
    if !may_act_permits(
        subject_token_may_act(subject_token).as_ref(),
        &actor.client_id,
    ) {
        return err(
            StatusCode::FORBIDDEN,
            "access_denied",
            "入站 may_act 未命中发起 actor 或非单对象(多候选须走 actor_allowlist)",
        )
        .into_response();
    }

    // 8. 目标 resource + scope ⊆ 授权源(C7.3/4)。resource 必带(委托 token 面向具体 RS)。
    let Some(target_resource) = req.resource.as_deref() else {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "token-exchange 须指定 resource(委托 token 面向具体下游 RS)",
        )
        .into_response();
    };
    let requested_scopes: Vec<String> = req
        .scope
        .as_deref()
        .map(|s| s.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default();
    // T7.4 热路径 fail-safe 闸(C10.17):选中 Grant 若 policy stale → 503 拒(不签超策略 token);
    // ip/vpc 不匹配 → access_denied。flag 关 no-op。零 Cedar(只 u64 比较 + CIDR)。
    if let Err(resp) =
        crate::policy_freshness::stale_gate(state, &tenant, &grant, headers, now).await
    {
        return resp;
    }
    let granted_scope: Vec<String> = match grant.authorize_target(
        target_resource,
        &requested_scopes,
        now,
    ) {
        Ok(scopes) => scopes,
        Err(agent_auth_grant::GrantError::ResourceNotGranted) => {
            return err(
                StatusCode::BAD_REQUEST,
                "invalid_target",
                "目标 resource 不在 Grant per_resource(委托权限恒 ⊆ Grant)。扩权须改走异步 consent(CIBA /bc-authorize 或 device /device_authorization,端点见 discovery)重新征得用户同意、生成新 Grant 后再换发",
            )
            .into_response();
        }
        Err(agent_auth_grant::GrantError::ScopeExceedsGrant) => {
            return err(
                StatusCode::BAD_REQUEST,
                "invalid_scope",
                "请求 scope 超出 Grant 该 resource 授权(不内联补授权)。扩权须改走异步 consent(CIBA /bc-authorize 或 device /device_authorization,端点见 discovery)重新征得用户同意、生成新 Grant 后再换发",
            )
            .into_response();
        }
        Err(_) => {
            return err(StatusCode::BAD_REQUEST, "invalid_grant", "Grant 不可用").into_response();
        }
    };

    // 9. 委托 token 的 sub:用户在**目标 resource sector** 的派生 sub(pairwise 下按 aud 派生;public=user_id)。
    let mode = crate::token::subject_mode(state.subject_type_for_tenant(&tenant_id));
    let deleg_sub = agent_auth_token::derive_user_sub(
        mode,
        &state.server_secret,
        &jrec.user_id,
        target_resource,
    );

    // 10. 签委托 token:sub=用户、act.sub=发起 agent、actor_types 命名空间(agent 类型)。恒 ES256 access。
    //     多级委托(P2):把入站 subject_token 的 act 链 + actor_types 嵌套进本跳(评审 codex MEDIUM:
    //     否则多跳丢 prior actor 且链深不增)。P1 前身入站恒无 act,二者 None,退化单层。
    let inbound_act = subject_token_claim(subject_token, "act");
    let inbound_actor_types = subject_token_claim(subject_token, agent_auth_token::NAMESPACE)
        .and_then(|ns| ns.get("actor_types").cloned());
    let inherited_auth_time =
        subject_token_claim(subject_token, "auth_time").and_then(|value| value.as_i64());
    let inherited_acr = subject_token_claim(subject_token, "acr")
        .and_then(|value| value.as_str().map(str::to_string));
    // RAR 透传(spec 010 §4 / DESIGN §5.2:510):委托 token MUST 带源 Grant 该 target_resource 的
    // authorization_details——否则委托换发会静默剥离 RAR = 委托 token 比源 Grant 宽 = 扩权洞(评审 Q6)。
    let rar_for_target: Vec<serde_json::Value> = grant
        .resource_grant(target_resource)
        .map(|rg| rg.authorization_details.clone())
        .unwrap_or_default();
    let scope_str = granted_scope.join(" ");
    let delegated_jti = crate::token::new_jti(state);
    let jwt = match crate::token::sign_tenant_delegation_token_with_delivery(
        state,
        headers,
        tenant_signer.as_ref(),
        as_issuer,
        &deleg_sub,
        target_resource,
        &actor.client_id, // client_id claim = 发起 agent
        &scope_str,
        &effective_auth_grant, // auth_grant 引用(Q5:grant_ref 时=选中 Grant,否则=源 family;审计/归属/吊销对齐)
        &actor.client_id,      // act.sub
        inbound_act,
        inbound_actor_types,
        &rar_for_target,
        delegation_cnf_jkt.as_deref(), // DPoP 重绑 actor jkt(§7.2;None=bearer)
        inherited_auth_time,
        inherited_acr.as_deref(),
        &delegated_jti,
        now,
        state.phase.at_least(agent_auth_discovery::Phase::P3),
        crate::security_event::SecurityActor::system("token-exchange"),
    )
    .await
    {
        Ok(signed) => signed.token,
        Err(crate::token::TokenSignError::Transient) => {
            // 签名瞬时失败(KMS throttle)→ 503 + Retry-After(C10.2 退避重试)。
            return crate::token::err_retry_after(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "签名瞬时失败(KMS throttle),请退避重试",
                1,
            )
            .into_response();
        }
        Err(crate::token::TokenSignError::TooLarge) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                crate::token::TOKEN_TOO_LARGE_ERROR_DESCRIPTION,
            )
            .into_response()
        }
        Err(crate::token::TokenSignError::IssuerMismatch) => {
            return err(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "issuer does not belong to tenant",
            )
            .into_response()
        }
        Err(crate::token::TokenSignError::Permanent) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "签名失败",
            )
            .into_response()
        }
    };

    // 记 actor client 最后使用日(spec 005 §9.2,C10.5;发起委托也算 actor client 的"使用")。
    crate::token::touch_client_last_used(state, &tenant, &actor.client_id, now).await;

    // Recheck after signing so a password reset that completes during policy or
    // KMS work suppresses the newly minted delegated token. Keep this as the
    // final awaited operation on the successful response path.
    match crate::user_gate::require_password_authority_version(
        state,
        &tenant,
        &jrec.user_id,
        fam.password_credential_version,
    )
    .await
    {
        crate::user_gate::PasswordGate::Allowed => {}
        crate::user_gate::PasswordGate::ChangeRequired => {
            return err(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "password authority changed during token exchange",
            )
            .into_response()
        }
        crate::user_gate::PasswordGate::Unavailable => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "password authority verification failed",
            )
            .into_response()
        }
    }
    if crate::user_gate::require_active_user_epoch(
        state,
        &tenant,
        &jrec.user_id,
        fam.credential_epoch,
    )
    .await
    .is_err()
    {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "user lifecycle changed during token exchange",
        )
        .into_response();
    }

    // 注(评审 LOW#5):委托 token **不落 jti 映射**——它已带 act,再作 subject_token 会被深度闸拒
    // (前身 max_act_chain=1),故落映射无消费者;放开深链(P2 Grant)时再按需补委托 token 的映射写。

    Json(TokenResponse {
        access_token: jwt,
        // 带 cnf(DPoP 重绑)→ `DPoP`,否则 `Bearer`(RFC 9449 §5;评审 Kiro L2,复用 token_type_for)。
        token_type: crate::token::token_type_for(delegation_cnf_jkt.as_deref()),
        expires_in: crate::token::ACCESS_TTL,
        scope: (!scope_str.is_empty()).then_some(scope_str),
        refresh_token: None, // 委托 token 不发 refresh(P1;委托是短时下游访问)
        id_token: None,
        resource: None,
    })
    .into_response()
}

/// 验 subject_token 是本 AS 签发、iss=本AS、未过期,返回 `(jti, id_token_aud)`(先验签再信 jti)。
/// 按类型分派验签器(**严格分离防 alg/typ 混淆**):
/// - **access_token**:`verify_access_token`(ES256 + 强制 typ=at+jwt + 顶层 client_id);返回 aud=None。
/// - **id_token**(C7.8a):`verify_id_token`(RS256 + typ≠at+jwt + iss + aud 单值 + jti 必在);
///   返回该 id_token 的 aud(= 签发给的 client_id),供上层纵深防御(aud==源 Grant client_id)。
///
/// 两条路径都强制 jti 存在(经 jti→user_id 映射还原主体,MUST NOT 解 pairwise sub,C7.8)。
async fn verify_subject_and_extract_jti(
    signer: &crate::state::SignerImpl,
    token: &str,
    is_id_token: bool,
    as_issuer: &str,
    now: i64,
) -> Result<(String, Option<String>), axum::response::Response> {
    let unavailable = || {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "JWKS 暂不可用",
        )
        .into_response()
    };

    if is_id_token {
        // id_token 路径(RS256):用 **RSA** JWKS(id_token 默认 RS256;access token 的 EC JWKS 无 n/e)。
        // expected_client_id=None(client_id 未知,验签阶段不校 aud 归属;上层取得源 Grant 后校
        // aud==grant.client_id 纵深防御)。verify_id_token 已校 typ≠at+jwt/iss/jti。
        let rsa_keys = signer.public_rsa_jwks().await.map_err(|_| unavailable())?;
        let jwks: Vec<crate::jwks::Jwk> = rsa_keys.iter().map(crate::jwks::rsa_to_jwk).collect();
        let verified =
            crate::verify::verify_id_token(token, &jwks, as_issuer, None, now).map_err(|_| {
                err(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "subject_token 非有效 id_token(RS256 验签/时效/typ/iss/jti 失败)",
                )
                .into_response()
            })?;
        // 取 aud(单值 client_id;数组取单元素)供上层纵深防御。
        let aud = match verified.claims.get("aud") {
            Some(serde_json::Value::String(s)) => Some(s.clone()),
            Some(serde_json::Value::Array(a)) if a.len() == 1 => a[0].as_str().map(str::to_string),
            _ => None,
        };
        let jti = verified
            .claims
            .get("jti")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| {
                err(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "id_token 缺 jti(无法解析主体)",
                )
                .into_response()
            })?;
        return Ok((jti, aud));
    }

    // access_token 路径(ES256 + typ=at+jwt + client_id):用 **EC** JWKS。
    let ec_keys = signer.public_jwks().await.map_err(|_| unavailable())?;
    let jwks: Vec<crate::jwks::Jwk> = ec_keys.iter().map(crate::jwks::to_jwk).collect();
    let verified = crate::verify::verify_access_token(token, &jwks, now).map_err(|_| {
        err(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "subject_token 非有效 access token(验签/时效/typ 失败)",
        )
        .into_response()
    })?;
    // iss=本AS(不接受他方签发的 token 作 subject)。
    if verified.claims.get("iss").and_then(|v| v.as_str()) != Some(as_issuer) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "subject_token iss 非本 AS",
        )
        .into_response());
    }
    let jti = verified
        .claims
        .get("jti")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| {
            err(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "subject_token 缺 jti(无法解析主体)",
            )
            .into_response()
        })?;
    Ok((jti, None))
}

/// subject_token 的委托链**真实嵌套深度**(深度闸,C7.2):0=无 act、N=N 层嵌套 act。
/// 只解 payload(已在上一步验签,这里只读 claim);深度计数复用纯逻辑 `act_chain_depth`。
/// **解码失败 fail-closed 返 u32::MAX**(评审 codex LOW:虽已验签故不可达,但若未来调用顺序重排,
/// 返 0 会 fail-open 漏放行;返 MAX 使 `depth+1 > max_act_chain` 恒成立 → 拒,安全侧)。
fn subject_token_act_depth(token: &str) -> u32 {
    let Some(payload) = token.split('.').nth(1) else {
        return u32::MAX;
    };
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(payload) else {
        return u32::MAX;
    };
    match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(claims) => agent_auth_token::act_chain_depth(&claims),
        Err(_) => u32::MAX,
    }
}

/// 取 subject_token 的 `may_act` claim(C7.2 叠加校验用)。返回原始 Value(可能是对象/数组/其它);
/// 上层据"是否单对象且 sub 命中"判定。已验签,只读 payload。
fn subject_token_may_act(token: &str) -> Option<serde_json::Value> {
    subject_token_claim(token, "may_act")
}

/// 入站 `may_act` 是否**允许** `actor_id` 代理(C7.2 叠加校验,RFC 8693 §4.4)。纯逻辑,可测。
///
/// 规则(fail-closed 严格):
/// - **无 `may_act`**(`None`)→ 放行(此闸只在带 `may_act` 时收紧;身份准入另由 actor_allowlist 管);
/// - **单对象 `{"sub": X}`** 且 `X == actor_id` → 放行;
/// - 其余一律**拒**:sub 不命中、`sub` 非字符串、缺 `sub`、**数组**(多候选须走 actor_allowlist 而非
///   subject_token 内联多主体)、其它类型。RFC 8693 的 `may_act` 是单一「谁可代理」断言,本系统不接受
///   数组/通配把它变成开放代理面。
fn may_act_permits(may_act: Option<&serde_json::Value>, actor_id: &str) -> bool {
    match may_act {
        None => true, // 无 may_act:此闸不适用(准入靠 allowlist)
        Some(v) => {
            // 数组/非对象一律拒(get("sub") 对数组返 None,但显式拒更清晰、防未来 serde 变化)。
            if !v.is_object() {
                return false;
            }
            matches!(v.get("sub").and_then(|s| s.as_str()), Some(s) if s == actor_id)
        }
    }
}

/// 读 subject_token payload 的某 claim(已验签;仅解码 payload 段)。
fn subject_token_claim(token: &str, key: &str) -> Option<serde_json::Value> {
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()?
        .get(key)
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::may_act_permits;
    use serde_json::json;

    // C7.2 may_act 叠加校验(RFC 8693 §4.4):严格单对象 {"sub":actor} 命中才放行。
    #[test]
    fn may_act_none_permits() {
        // 无 may_act:此闸不适用(准入靠 actor_allowlist),放行。
        assert!(may_act_permits(None, "agent-a"));
    }

    #[test]
    fn may_act_single_object_matching_actor_permits() {
        let ma = json!({"sub": "agent-a"});
        assert!(may_act_permits(Some(&ma), "agent-a"));
    }

    #[test]
    fn may_act_single_object_wrong_actor_rejected() {
        let ma = json!({"sub": "agent-b"});
        assert!(
            !may_act_permits(Some(&ma), "agent-a"),
            "sub 不命中发起 actor 应拒"
        );
    }

    #[test]
    fn may_act_array_rejected() {
        // 数组(多候选)MUST 拒——多主体须走 actor_allowlist,不接受 subject_token 内联多代理。
        let ma = json!([{"sub": "agent-a"}, {"sub": "agent-b"}]);
        assert!(!may_act_permits(Some(&ma), "agent-a"), "数组 may_act 应拒");
    }

    #[test]
    fn may_act_missing_or_nonstring_sub_rejected() {
        assert!(!may_act_permits(Some(&json!({})), "agent-a"), "缺 sub 应拒");
        assert!(
            !may_act_permits(Some(&json!({"sub": 123})), "agent-a"),
            "sub 非字符串应拒"
        );
        assert!(
            !may_act_permits(Some(&json!({"sub": {"nested": "x"}})), "agent-a"),
            "sub 为对象应拒"
        );
    }

    #[test]
    fn may_act_nonobject_scalar_rejected() {
        // 字符串/数字/bool/null 等非对象一律拒(不是合法 may_act 结构)。
        for v in [json!("agent-a"), json!(42), json!(true), json!(null)] {
            assert!(!may_act_permits(Some(&v), "agent-a"), "非对象 {v} 应拒");
        }
    }

    #[test]
    fn may_act_empty_actor_id_still_needs_exact_match() {
        // 边界:actor_id 为空时,仅当 sub 也恰为空串才命中(不放宽)。
        assert!(may_act_permits(Some(&json!({"sub": ""})), ""));
        assert!(!may_act_permits(Some(&json!({"sub": "agent-a"})), ""));
    }
}
