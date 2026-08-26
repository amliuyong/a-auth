//! 上游 IdP 联邦纯逻辑(spec 003 C9.5b,P1b 后端契约)。零 IO、零 AWS。
//!
//! **关注点**:从上游 IdP 断言(OIDC id_token claims / SAML attributes,已解析为 JSON)提取
//! `acr`/`amr`/`auth_time`,供签发侧透传进本 AS token(claim 结构见 spec 001,OIDC 标准顶层字段)。
//! P1 **原样透传**上游值(不做 NIST AAL 标准化映射,留 post-P1)。真实上游对接(HTTP 回调、
//! JWKS 验签、SAML 解析)属 IO 层,不在此;本模块只做"从已验证断言提取要透传的值"的纯契约。
//!
//! **【SaaS】逐租户隔离**:联邦配置按 tenant 存(FederationConfig,存储端口在 http 层),信任
//! MUST NOT 跨租户共享(隔离机制见 spec 020 / C10.19)。本模块的 FederationConfig 是配置形状定义。
//!
//! 决策真相源:docs/DESIGN §7(联邦)/ §11 #10;CONFORMANCE C9.5b。

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// 上游 IdP 联邦配置(逐租户;存储/查询在 http 层 FederationConfigStore)。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationConfig {
    /// 逻辑租户 id(【SaaS】隔离键;自部署单租户可固定)。
    pub tenant_id: String,
    /// 上游 IdP 标识(一个租户可配多个上游)。
    pub upstream_idp_id: String,
    /// 上游协议类型。
    pub protocol: UpstreamProtocol,
    /// 上游 issuer(OIDC)/ entity_id(SAML)。
    pub upstream_issuer: String,
    /// Upstream `acr` values explicitly trusted to satisfy Agent Auth `strong`.
    /// Unknown values and `amr` strings never elevate assurance.
    #[serde(default)]
    pub strong_acr_values: Vec<String>,
    /// OIDC RP 往返参数(spec 003 §4 ADDED,Task 4.6):`protocol==Oidc` 时 MUST `Some`;SAML 时 `None`。
    /// 往返编排(重定向/换 token/验签)属 IO 层(http 联邦回调),本 crate 只持配置形状 + 校验。
    pub oidc: Option<OidcRpParams>,
}

/// OIDC RP(依赖方)往返参数(Task 4.6)。AS 作上游 IdP 的 RP 时,发起授权重定向 + code 换 token +
/// 验签 id_token 所需的登记数据。**endpoints 仅取自本结构(登记 config),不接受请求参数里的任意 URL**
/// (SSRF 防线,spec 003 §4 安全不变量)。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcRpParams {
    /// 本 AS 在上游注册的 client_id。
    pub client_id: String,
    /// 本 AS 在上游的 client_secret 的**引用名**(Secrets Manager/SSM;**绝不存明文**,SecretResolver 解析)。
    pub client_secret_ref: String,
    /// 上游授权端点(重定向用户去此;MUST https 绝对 URL)。
    pub authorization_endpoint: String,
    /// 上游 token 端点(code 换 token;MUST https)。
    pub token_endpoint: String,
    /// 上游 JWKS(验 id_token 签名;信任锚绑此,不接受 token 自带 jku;MUST https)。
    pub jwks_uri: String,
    /// 请求 scope(至少含 `openid`)。
    pub scopes: Vec<String>,
}

/// OIDC RP config 校验失败(登记时 fail-closed,防 SSRF / 误配)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OidcRpConfigError {
    /// `protocol==Oidc` 但 `oidc` 为 None(或反之 SAML 带了 oidc)。
    ProtocolParamsMismatch,
    /// 某必填字段为空(client_id / client_secret_ref / 三个 endpoint)。
    EmptyField(&'static str),
    /// endpoint 不是 https 绝对 URL(防 SSRF 到内网/非 TLS/任意 scheme)。
    EndpointNotHttps(&'static str),
    /// scopes 未含 `openid`。
    MissingOpenidScope,
    /// Strong ACR allowlist entries must be unique non-empty tokens.
    InvalidStrongAcrValue,
}

impl FederationConfig {
    /// 登记时校验(Task 4.6,fail-closed):OIDC 须带完整合法 oidc 参数;endpoint MUST https 绝对 URL
    /// (SSRF 防线);scopes 含 openid。SAML 暂只校"不带 oidc"。**secret 只校引用名非空,绝不解析明文**。
    pub fn validate(&self) -> Result<(), OidcRpConfigError> {
        let mut seen = std::collections::BTreeSet::new();
        if self.strong_acr_values.iter().any(|value| {
            value.is_empty()
                || value.len() > 256
                || value.chars().any(char::is_whitespace)
                || !seen.insert(value)
        }) {
            return Err(OidcRpConfigError::InvalidStrongAcrValue);
        }
        match (self.protocol, &self.oidc) {
            (UpstreamProtocol::Oidc, Some(p)) => p.validate(),
            // SAML 目前不带 oidc(SAML 参数留后);OIDC 缺 oidc = 误配。
            (UpstreamProtocol::Saml, None) => Ok(()),
            _ => Err(OidcRpConfigError::ProtocolParamsMismatch),
        }
    }
}

impl OidcRpParams {
    fn validate(&self) -> Result<(), OidcRpConfigError> {
        if self.client_id.trim().is_empty() {
            return Err(OidcRpConfigError::EmptyField("client_id"));
        }
        if self.client_secret_ref.trim().is_empty() {
            return Err(OidcRpConfigError::EmptyField("client_secret_ref"));
        }
        // 三个 endpoint MUST https 绝对 URL(SSRF 防线:不接受 http/内网 scheme/相对)。
        for (name, url) in [
            ("authorization_endpoint", &self.authorization_endpoint),
            ("token_endpoint", &self.token_endpoint),
            ("jwks_uri", &self.jwks_uri),
        ] {
            if url.trim().is_empty() {
                return Err(OidcRpConfigError::EmptyField(name));
            }
            // MUST 以 https:// 开头(小写 scheme,绝对 URL);排除 http/file/其它 scheme 与相对路径。
            if !url.starts_with("https://") {
                return Err(OidcRpConfigError::EndpointNotHttps(name));
            }
        }
        if !self.scopes.iter().any(|s| s == "openid") {
            return Err(OidcRpConfigError::MissingOpenidScope);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpstreamProtocol {
    Oidc,
    Saml,
}

/// 从上游断言提取、要透传进本 AS token 的认证强度信息(C9.5b)。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UpstreamAuthContext {
    /// Upstream `acr` before tenant-specific assurance mapping.
    pub acr: Option<String>,
    /// 上游 `amr`(认证方法引用列表,原样透传)。
    pub amr: Vec<String>,
    /// 上游 `auth_time`(Unix 秒)。
    pub auth_time: Option<i64>,
}

/// 联邦断言处理失败(纯逻辑判定;IO 侧验签/JWKS 失败不在此)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FederationError {
    /// 上游断言缺 `iss`(无法核对信任锚)。
    MissingIssuer,
    /// 上游断言 `iss` != config.upstream_issuer(**接受了未登记 IdP 的断言**,fail-closed)。
    IssuerMismatch { expected: String, actual: String },
    /// config.tenant_id != 请求 tenant_id(**跨租户配置命中**;隔离缺陷/误配,fail-closed 纵深防御)。
    TenantMismatch { expected: String, actual: String },
}

/// **联邦 callback 处理纯逻辑(C9.5b + C10.19 隔离,P1b 后端契约核心)**:给定**已验签**的上游
/// OIDC 断言 claims + 一条 `FederationConfig` + 请求租户 → 校信任锚后产出 `UpstreamAuthContext`。
///
/// 判定链(全 fail-closed):
/// ① **tenant 一致**(纵深防御 C10.19):`config.tenant_id == request_tenant_id`——即便 IO 层 adapter
///    误把跨租户 config 取回来(bug/误配),此断言在纯逻辑侧再拦一道,不依赖 adapter 自觉;
/// ② **issuer 匹配**(信任锚,防接受未登记 IdP):上游 `iss` MUST == `config.upstream_issuer`;
/// ③ Extract acr/amr/auth_time, then map verified upstream evidence to canonical assurance.
///
/// ⚠️ **验签前提**:`verified_claims` MUST 是**用该 config 指定的上游信任(jwks_uri/upstream_issuer)
/// 验过签 + 时效**的断言(IO 层保证);本函数不验签,只做信任锚一致性 + 提取。绝不能"先随便验签
/// 再补校 iss"——验签用的 JWKS 必须来自同一条 config(顺序耦合,写进 e2e 契约)。
pub fn resolve_upstream_context(
    verified_claims: &Value,
    config: &FederationConfig,
    request_tenant_id: &str,
) -> Result<UpstreamAuthContext, FederationError> {
    // ① tenant 一致(C10.19 纵深:不依赖 adapter,纯逻辑再断一次)。
    if config.tenant_id != request_tenant_id {
        return Err(FederationError::TenantMismatch {
            expected: request_tenant_id.to_string(),
            actual: config.tenant_id.clone(),
        });
    }
    // ② issuer 匹配(信任锚:上游 iss MUST == 登记的 upstream_issuer)。
    let iss = verified_claims
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or(FederationError::MissingIssuer)?;
    if iss != config.upstream_issuer {
        return Err(FederationError::IssuerMismatch {
            expected: config.upstream_issuer.clone(),
            actual: iss.to_string(),
        });
    }
    // ③ Extract evidence, then map only an explicitly trusted upstream ACR
    // into the stable internal assurance vocabulary. `amr` is observational.
    let mut context = extract_from_oidc_claims(verified_claims);
    let class = crate::assurance::classify_upstream(
        context.acr.as_deref(),
        &context.amr,
        &config.strong_acr_values,
    );
    context.acr = Some(class.acr().to_string());
    Ok(context)
}

/// 上游 id_token claims 校验失败(评审 F9 完整校验清单,spec 003 §4 callback)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdTokenClaimError {
    /// 缺必需 claim(iss/aud/exp/sub/nonce 任一缺)。
    MissingClaim(&'static str),
    /// iss != config.upstream_issuer(信任锚不符,防接受未登记 IdP)。
    IssuerMismatch,
    /// aud 不含本 AS 在上游的 client_id(token 转用/confused-deputy 防线)。
    AudienceMismatch,
    /// azp(有则)!= client_id(multi-aud 时 authorized party 必须是自己)。
    AzpMismatch,
    /// nonce != flow 绑定的 nonce(防 id_token 重放到别的登录会话)。
    NonceMismatch,
    /// 已过期(exp + skew ≤ now)。
    Expired,
    /// nbf 未生效(nbf - skew > now)。
    NotYetValid,
    /// iat 不合理(iat - skew > now,签发在未来)。
    IatInFuture,
}

/// 上游 id_token claims 校验的期望值(callback 从 flow-state + config 提供)。
pub struct IdTokenExpectations<'a> {
    /// config.upstream_issuer(信任锚)。
    pub upstream_issuer: &'a str,
    /// 本 AS 在上游注册的 client_id(= aud MUST 含 / azp MUST 等[若present])。
    pub client_id: &'a str,
    /// flow-state 绑定的 nonce(MUST == id_token.nonce)。
    pub nonce: &'a str,
    /// 现在(Unix 秒)。
    pub now: i64,
    /// 允许时钟偏移(秒)。
    pub clock_skew_secs: i64,
}

/// `aud` 是否**包含** `expected`(aud 可为字符串或字符串数组,RFC 7519)。
fn aud_contains(claims: &Value, expected: &str) -> bool {
    match claims.get("aud") {
        Some(Value::String(s)) => s == expected,
        Some(Value::Array(arr)) => arr.iter().any(|v| v.as_str() == Some(expected)),
        _ => false,
    }
}

/// **上游 id_token claims 完整校验(评审 F9,spec 003 §4 callback 核心)**。前提:claims 已用
/// config.jwks_uri 的 key **验过签**(IO 层保证,信任锚绑 config);本函数做**验签后的语义校验**,全 fail-closed。
///
/// 校验清单(RFC 9207 iss / OIDC Core §3.1.3.7 id_token validation):
/// ① iss == config.upstream_issuer(信任锚);② aud **含** client_id(confused-deputy 防线);
/// ③ azp(present 时)== client_id(multi-aud authorized party);④ nonce == flow.nonce(防重放);
/// ⑤ exp + skew > now(未过期);⑥ nbf(present 时)- skew ≤ now;⑦ iat(present 时)- skew ≤ now(非未来签发)。
/// 成功返回 `sub`(供 `federated_user_id` 派生本地身份键)。
pub fn verify_upstream_id_token_claims<'a>(
    claims: &'a Value,
    expect: &IdTokenExpectations<'_>,
) -> Result<&'a str, IdTokenClaimError> {
    // 必需 claim。
    let iss = claims
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or(IdTokenClaimError::MissingClaim("iss"))?;
    let sub = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or(IdTokenClaimError::MissingClaim("sub"))?;
    let exp = claims
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or(IdTokenClaimError::MissingClaim("exp"))?;
    let nonce = claims
        .get("nonce")
        .and_then(|v| v.as_str())
        .ok_or(IdTokenClaimError::MissingClaim("nonce"))?;
    if claims.get("aud").is_none() {
        return Err(IdTokenClaimError::MissingClaim("aud"));
    }
    // ① iss 信任锚。
    if iss != expect.upstream_issuer {
        return Err(IdTokenClaimError::IssuerMismatch);
    }
    // ② aud 含 client_id(绝不放宽)。
    if !aud_contains(claims, expect.client_id) {
        return Err(IdTokenClaimError::AudienceMismatch);
    }
    // ③ azp(present 时)MUST == client_id(multi-aud 场景的 authorized party;OIDC Core)。
    if let Some(azp) = claims.get("azp").and_then(|v| v.as_str()) {
        if azp != expect.client_id {
            return Err(IdTokenClaimError::AzpMismatch);
        }
    }
    // ④ nonce 绑定(防 id_token 重放到别的登录会话)。
    if nonce != expect.nonce {
        return Err(IdTokenClaimError::NonceMismatch);
    }
    // ⑤ exp(fail-closed:exp + skew ≤ now 即过期)。
    if exp + expect.clock_skew_secs <= expect.now {
        return Err(IdTokenClaimError::Expired);
    }
    // ⑥ nbf(present 时):nbf - skew > now → 未生效。
    if let Some(nbf) = claims.get("nbf").and_then(|v| v.as_i64()) {
        if nbf - expect.clock_skew_secs > expect.now {
            return Err(IdTokenClaimError::NotYetValid);
        }
    }
    // ⑦ iat(present 时):iat - skew > now → 未来签发(拒)。
    if let Some(iat) = claims.get("iat").and_then(|v| v.as_i64()) {
        if iat - expect.clock_skew_secs > expect.now {
            return Err(IdTokenClaimError::IatInFuture);
        }
    }
    Ok(sub)
}

/// Extract acr/amr/auth_time from verified upstream OIDC ID-token claims (C9.5b).
/// 上游断言的**验签/时效**由 IO 层(联邦回调)保证,本函数只提取值。
pub fn extract_from_oidc_claims(claims: &Value) -> UpstreamAuthContext {
    let acr = claims.get("acr").and_then(|v| v.as_str()).map(String::from);
    // amr:OIDC 是字符串数组;宽容接受单字符串。
    let amr = match claims.get("amr") {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => vec![],
    };
    let auth_time = claims.get("auth_time").and_then(|v| v.as_i64());
    UpstreamAuthContext {
        acr,
        amr,
        auth_time,
    }
}

/// 联邦本地 user_id 派生(**评审 F2 Blocker 的核心决策落地**,spec 003 §4 ADDED)。
///
/// **身份键 = `(tenant_id, upstream_issuer, sub)` 复合**,绝不用裸 `sub`:上游 `sub` 只在**单个 issuer
/// 内**唯一,跨 IdP / 跨租户裸 `sub` 会撞号 → 账户串号/接管。三元组与 `resolve_upstream_context` 的信任锚
/// 判定(tenant + upstream_issuer)一脉相承。
///
/// **确定性派生**(P1 选型,免 `FederationIdentityStore` 端口;牺牲可重绑/改名——若后续需要再引映射表):
/// `user:fed:v1:base64url(HMAC-SHA256(server_secret, "fed-uid:v1"‖len‖tenant‖len‖issuer‖len‖sub))`。
/// - **长度前缀框定**(各字段 8 字节大端长度前缀):任意字节内容都无拼接歧义(如 issuer 尾含分隔符也不与 sub 混)。
/// - **域分离** `"fed-uid:v1"`:与 pairwise `sub`(`"sub:v1"`)、magic-link tag、recovery code_hash 等 HMAC 输出隔离,
///   防跨用途混用。**v1** 预留派生方案版本。
/// - 输出带 `user:fed:` 前缀:与 magic-link 的 `user:{email}` 派生同命名空间但可区分来源(联邦 vs 本地邮箱)。
///
/// ⚠️ **email 绝不参与派生 / 绝不按 email 自动 link 既有本地账户**(评审 F2):上游 email 未必已验证、且可被
/// 上游侧改写 → 经典账户接管向量。要跨因子 link 须显式流程 + 上游 `email_verified` + 额外确认(post-P1)。
pub fn federated_user_id(
    server_secret: &[u8],
    tenant_id: &str,
    upstream_issuer: &str,
    sub: &str,
) -> String {
    let mut mac = HmacSha256::new_from_slice(server_secret).expect("HMAC accepts any key length");
    mac.update(b"fed-uid:v1");
    mac.update(&(tenant_id.len() as u64).to_be_bytes());
    mac.update(tenant_id.as_bytes());
    mac.update(&(upstream_issuer.len() as u64).to_be_bytes());
    mac.update(upstream_issuer.as_bytes());
    mac.update(&(sub.len() as u64).to_be_bytes());
    mac.update(sub.as_bytes());
    format!(
        "user:fed:v1:{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

/// 把上游认证上下文注入到**要签发的 token claims**(spec 001:acr/amr/auth_time 是 OIDC 顶层标准字段)。
/// 原样透传(P1);仅在有值时写入(不覆盖成 null)。
pub fn inject_into_claims(ctx: &UpstreamAuthContext, claims: &mut serde_json::Map<String, Value>) {
    if let Some(acr) = &ctx.acr {
        claims.insert("acr".into(), Value::String(acr.clone()));
    }
    if !ctx.amr.is_empty() {
        claims.insert(
            "amr".into(),
            Value::Array(ctx.amr.iter().map(|s| Value::String(s.clone())).collect()),
        );
    }
    if let Some(at) = ctx.auth_time {
        claims.insert("auth_time".into(), Value::Number(at.into()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extract_oidc_acr_amr_auth_time() {
        let claims = json!({
            "sub": "u1",
            "acr": "urn:mace:incommon:iap:silver",
            "amr": ["pwd", "mfa"],
            "auth_time": 1_700_000_000i64
        });
        let ctx = extract_from_oidc_claims(&claims);
        assert_eq!(ctx.acr.as_deref(), Some("urn:mace:incommon:iap:silver"));
        assert_eq!(ctx.amr, vec!["pwd".to_string(), "mfa".to_string()]);
        assert_eq!(ctx.auth_time, Some(1_700_000_000));
    }

    #[test]
    fn amr_single_string_tolerated() {
        let ctx = extract_from_oidc_claims(&json!({ "amr": "pwd" }));
        assert_eq!(ctx.amr, vec!["pwd".to_string()]);
    }

    #[test]
    fn missing_fields_default_empty() {
        let ctx = extract_from_oidc_claims(&json!({ "sub": "u1" }));
        assert_eq!(ctx.acr, None);
        assert!(ctx.amr.is_empty());
        assert_eq!(ctx.auth_time, None);
    }

    #[test]
    fn inject_passes_through_verbatim() {
        // 上游值原样进 token(不做 AAL 映射,P1)。
        let ctx = UpstreamAuthContext {
            acr: Some("phr".into()),
            amr: vec!["webauthn".into(), "hwk".into()],
            auth_time: Some(1234),
        };
        let mut claims = serde_json::Map::new();
        inject_into_claims(&ctx, &mut claims);
        assert_eq!(claims["acr"], json!("phr"));
        assert_eq!(claims["amr"], json!(["webauthn", "hwk"]));
        assert_eq!(claims["auth_time"], json!(1234));
    }

    #[test]
    fn inject_skips_absent() {
        // 空 ctx 不写入任何键(不覆盖成 null)。
        let ctx = UpstreamAuthContext::default();
        let mut claims = serde_json::Map::new();
        claims.insert("sub".into(), json!("u1"));
        inject_into_claims(&ctx, &mut claims);
        assert_eq!(claims.len(), 1, "空 ctx 不注入");
        assert!(!claims.contains_key("acr"));
    }

    // roundtrip:上游 claims → 提取 → 注入,值不变(原样透传契约)。
    #[test]
    fn roundtrip_verbatim() {
        let upstream = json!({ "acr": "level2", "amr": ["otp"], "auth_time": 999 });
        let ctx = extract_from_oidc_claims(&upstream);
        let mut out = serde_json::Map::new();
        inject_into_claims(&ctx, &mut out);
        assert_eq!(out["acr"], upstream["acr"]);
        assert_eq!(out["amr"], upstream["amr"]);
        assert_eq!(out["auth_time"], upstream["auth_time"]);
    }

    fn cfg(tenant: &str, iss: &str) -> FederationConfig {
        FederationConfig {
            tenant_id: tenant.into(),
            upstream_idp_id: "okta".into(),
            protocol: UpstreamProtocol::Oidc,
            upstream_issuer: iss.into(),
            strong_acr_values: vec![],
            oidc: None,
        }
    }

    fn oidc_params() -> OidcRpParams {
        OidcRpParams {
            client_id: "as-rp-client".into(),
            client_secret_ref: "secretsmanager:fed/okta/secret".into(),
            authorization_endpoint: "https://idp.example.com/authorize".into(),
            token_endpoint: "https://idp.example.com/token".into(),
            jwks_uri: "https://idp.example.com/jwks".into(),
            scopes: vec!["openid".into(), "profile".into()],
        }
    }

    // 合法 OIDC RP config → 校验通过。
    #[test]
    fn oidc_config_valid() {
        let mut c = cfg("t1", "https://idp.example.com");
        c.oidc = Some(oidc_params());
        assert_eq!(c.validate(), Ok(()));
    }

    // protocol/params 不匹配:OIDC 缺 oidc、或 SAML 带 oidc → 拒。
    #[test]
    fn oidc_config_protocol_mismatch_rejected() {
        let c = cfg("t1", "https://idp.example.com"); // Oidc 但 oidc=None
        assert_eq!(c.validate(), Err(OidcRpConfigError::ProtocolParamsMismatch));
        let mut saml = cfg("t1", "https://idp.example.com");
        saml.protocol = UpstreamProtocol::Saml;
        saml.oidc = Some(oidc_params());
        assert_eq!(
            saml.validate(),
            Err(OidcRpConfigError::ProtocolParamsMismatch)
        );
    }

    // SSRF 防线:endpoint 非 https(http/内网/任意 scheme/相对)→ 拒。
    #[test]
    fn oidc_config_non_https_endpoint_rejected() {
        let mut c = cfg("t1", "https://idp.example.com");
        let mut p = oidc_params();
        p.token_endpoint = "http://169.254.169.254/latest/meta-data".into(); // http + 内网元数据
        c.oidc = Some(p);
        assert_eq!(
            c.validate(),
            Err(OidcRpConfigError::EndpointNotHttps("token_endpoint"))
        );
    }

    // secret 引用名为空 → 拒(绝不接受空引用/隐式明文)。
    #[test]
    fn oidc_config_empty_secret_ref_rejected() {
        let mut c = cfg("t1", "https://idp.example.com");
        let mut p = oidc_params();
        p.client_secret_ref = "  ".into();
        c.oidc = Some(p);
        assert_eq!(
            c.validate(),
            Err(OidcRpConfigError::EmptyField("client_secret_ref"))
        );
    }

    // scopes 缺 openid → 拒。
    #[test]
    fn oidc_config_missing_openid_rejected() {
        let mut c = cfg("t1", "https://idp.example.com");
        let mut p = oidc_params();
        p.scopes = vec!["profile".into()];
        c.oidc = Some(p);
        assert_eq!(c.validate(), Err(OidcRpConfigError::MissingOpenidScope));
    }

    // C9.5b + C10.19:合法上游断言仍须经过显式 ACR 映射。
    #[test]
    fn resolve_ok_when_issuer_and_tenant_match() {
        let mut config = cfg("t1", "https://idp.example.com");
        let claims = json!({
            "iss": "https://idp.example.com",
            "acr": "phr", "amr": ["webauthn"], "auth_time": 100
        });
        let ctx = resolve_upstream_context(&claims, &config, "t1").unwrap();
        assert_eq!(
            ctx.acr.as_deref(),
            Some(crate::assurance::BASELINE_ACR),
            "unknown upstream acr and amr must not elevate"
        );
        assert_eq!(ctx.amr, vec!["webauthn".to_string()]);

        config.strong_acr_values = vec!["phr".into()];
        let ctx = resolve_upstream_context(&claims, &config, "t1").unwrap();
        assert_eq!(ctx.acr.as_deref(), Some(crate::assurance::STRONG_ACR));
    }

    #[test]
    fn invalid_strong_acr_allowlist_is_rejected() {
        let mut config = cfg("t1", "https://idp.example.com");
        config.oidc = Some(oidc_params());
        config.strong_acr_values = vec!["".into()];
        assert_eq!(
            config.validate(),
            Err(OidcRpConfigError::InvalidStrongAcrValue)
        );
    }

    // 红线②:上游 iss != config.upstream_issuer → 拒(接受未登记 IdP 断言)。
    #[test]
    fn resolve_rejects_issuer_mismatch() {
        let config = cfg("t1", "https://idp.example.com");
        // 攻击者拿**另一个 IdP** 签的合法断言。
        let claims = json!({ "iss": "https://evil-idp.example.com", "acr": "phr" });
        assert_eq!(
            resolve_upstream_context(&claims, &config, "t1"),
            Err(FederationError::IssuerMismatch {
                expected: "https://idp.example.com".into(),
                actual: "https://evil-idp.example.com".into()
            })
        );
    }

    // 红线①(C10.19 纵深):config.tenant_id != 请求 tenant → 拒(跨租户配置命中)。
    // 即便 iss 匹配,tenant 不符也 fail-closed(不依赖 adapter 隔离)。
    #[test]
    fn resolve_rejects_cross_tenant_config() {
        // adapter 误把 t2 的 config 取回来(模拟隔离缺陷)。
        let t2_config = cfg("t2", "https://idp.example.com");
        let claims = json!({ "iss": "https://idp.example.com", "acr": "phr" });
        // 请求租户是 t1,但 config 属 t2 → 拒。
        assert_eq!(
            resolve_upstream_context(&claims, &t2_config, "t1"),
            Err(FederationError::TenantMismatch {
                expected: "t1".into(),
                actual: "t2".into()
            })
        );
    }

    // 上游断言缺 iss → 拒(无法核对信任锚)。
    #[test]
    fn resolve_rejects_missing_issuer() {
        let config = cfg("t1", "https://idp.example.com");
        let claims = json!({ "acr": "phr" }); // 无 iss
        assert_eq!(
            resolve_upstream_context(&claims, &config, "t1"),
            Err(FederationError::MissingIssuer)
        );
    }

    // ---- federated_user_id 派生(评审 F2 Blocker:防账户串号/接管)----
    const FSEC: &[u8] = b"federation-derivation-test-secret";

    // 确定性:同 (tenant, issuer, sub) → 同 user_id(可重现,免存映射表)。
    #[test]
    fn federated_user_id_deterministic() {
        let a = federated_user_id(FSEC, "t1", "https://idp.example.com", "sub-123");
        let b = federated_user_id(FSEC, "t1", "https://idp.example.com", "sub-123");
        assert_eq!(a, b, "同三元组必须派生同一 user_id");
        assert!(a.starts_with("user:fed:v1:"), "带联邦命名空间前缀:{a}");
    }

    // **核心防线**:同一 sub 值在**不同 upstream_issuer** 下 → 不同 user_id(裸 sub 跨 IdP 会串账)。
    #[test]
    fn federated_user_id_no_collision_across_issuers() {
        let idp_a = federated_user_id(FSEC, "t1", "https://okta.example.com", "42");
        let idp_b = federated_user_id(FSEC, "t1", "https://entra.example.com", "42");
        assert_ne!(
            idp_a, idp_b,
            "同 sub 跨不同 issuer MUST 不同 user_id(防跨 IdP 账户串号)"
        );
    }

    // **核心防线**:同一 (issuer, sub) 在**不同 tenant** 下 → 不同 user_id(跨租户隔离)。
    #[test]
    fn federated_user_id_no_collision_across_tenants() {
        let t1 = federated_user_id(FSEC, "t1", "https://idp.example.com", "same-sub");
        let t2 = federated_user_id(FSEC, "t2", "https://idp.example.com", "same-sub");
        assert_ne!(t1, t2, "同 (issuer,sub) 跨租户 MUST 不同(C10.19 隔离)");
    }

    // 长度前缀框定:字段边界移动(issuer 尾字符挪到 sub 首)不产生同一输出(防拼接歧义)。
    #[test]
    fn federated_user_id_length_prefix_framing() {
        // ("iss/","sub") vs ("iss","/sub"):裸拼接会撞,长度前缀框定不撞。
        let a = federated_user_id(FSEC, "t1", "https://idp.example.com/", "sub");
        let b = federated_user_id(FSEC, "t1", "https://idp.example.com", "/sub");
        assert_ne!(a, b, "长度前缀框定:字段边界移动 MUST 不产生同一 user_id");
    }

    // 域分离:与 pairwise sub 的 "sub:v1" HMAC 不会碰撞(不同域前缀);输出不含明文 sub。
    #[test]
    fn federated_user_id_domain_separated_and_opaque() {
        let uid = federated_user_id(FSEC, "t1", "https://idp.example.com", "alice@corp.com");
        // 不泄露明文 sub(即便 sub 是 email 形状也不回显)。
        assert!(!uid.contains("alice@corp.com"), "user_id 不含明文 sub");
        // 秘密不同 → 输出不同(HMAC 绑 server_secret)。
        let other = federated_user_id(
            b"different-secret",
            "t1",
            "https://idp.example.com",
            "alice@corp.com",
        );
        assert_ne!(uid, other, "换 server_secret → 派生变(HMAC 绑密钥)");
    }

    // ---- verify_upstream_id_token_claims(评审 F9 完整校验清单)----
    fn idtok_expect<'a>(now: i64) -> IdTokenExpectations<'a> {
        IdTokenExpectations {
            upstream_issuer: "https://idp.example.com",
            client_id: "as-rp",
            nonce: "flow-nonce-xyz",
            now,
            clock_skew_secs: 60,
        }
    }

    fn idtok(overrides: serde_json::Value) -> serde_json::Value {
        // 合法基线 + 覆盖字段。
        let mut base = json!({
            "iss": "https://idp.example.com",
            "sub": "upstream-sub-1",
            "aud": "as-rp",
            "exp": 2_000_000_000i64,
            "nonce": "flow-nonce-xyz"
        });
        if let (Some(b), Some(o)) = (base.as_object_mut(), overrides.as_object()) {
            for (k, v) in o {
                if v.is_null() {
                    b.remove(k);
                } else {
                    b.insert(k.clone(), v.clone());
                }
            }
        }
        base
    }

    #[test]
    fn idtoken_valid_returns_sub() {
        let c = idtok(json!({}));
        let sub = verify_upstream_id_token_claims(&c, &idtok_expect(1_000_000_000)).unwrap();
        assert_eq!(sub, "upstream-sub-1");
    }

    #[test]
    fn idtoken_aud_array_containing_client_id_ok() {
        let c = idtok(json!({ "aud": ["other", "as-rp"] }));
        assert!(verify_upstream_id_token_claims(&c, &idtok_expect(1_000_000_000)).is_ok());
    }

    #[test]
    fn idtoken_missing_required_claims_rejected() {
        for (k, name) in [
            ("iss", "iss"),
            ("sub", "sub"),
            ("exp", "exp"),
            ("nonce", "nonce"),
            ("aud", "aud"),
        ] {
            let c = idtok(json!({ k: null }));
            assert_eq!(
                verify_upstream_id_token_claims(&c, &idtok_expect(1_000_000_000)),
                Err(IdTokenClaimError::MissingClaim(name)),
                "缺 {k} 应拒"
            );
        }
    }

    #[test]
    fn idtoken_issuer_mismatch_rejected() {
        let c = idtok(json!({ "iss": "https://evil.example.com" }));
        assert_eq!(
            verify_upstream_id_token_claims(&c, &idtok_expect(1_000_000_000)),
            Err(IdTokenClaimError::IssuerMismatch)
        );
    }

    #[test]
    fn idtoken_audience_mismatch_rejected() {
        // aud 不含本 AS client_id(confused-deputy 防线)。
        let c = idtok(json!({ "aud": ["someone-else"] }));
        assert_eq!(
            verify_upstream_id_token_claims(&c, &idtok_expect(1_000_000_000)),
            Err(IdTokenClaimError::AudienceMismatch)
        );
    }

    #[test]
    fn idtoken_azp_mismatch_rejected() {
        // multi-aud + azp 指向别人 → 拒。
        let c = idtok(json!({ "aud": ["as-rp","other"], "azp": "other" }));
        assert_eq!(
            verify_upstream_id_token_claims(&c, &idtok_expect(1_000_000_000)),
            Err(IdTokenClaimError::AzpMismatch)
        );
    }

    #[test]
    fn idtoken_nonce_mismatch_rejected() {
        let c = idtok(json!({ "nonce": "attacker-nonce" }));
        assert_eq!(
            verify_upstream_id_token_claims(&c, &idtok_expect(1_000_000_000)),
            Err(IdTokenClaimError::NonceMismatch)
        );
    }

    #[test]
    fn idtoken_expired_rejected() {
        let c = idtok(json!({ "exp": 100i64 }));
        // now 远超 exp+skew → 过期。
        assert_eq!(
            verify_upstream_id_token_claims(&c, &idtok_expect(1_000_000_000)),
            Err(IdTokenClaimError::Expired)
        );
    }

    #[test]
    fn idtoken_nbf_future_and_iat_future_rejected() {
        // nbf 在未来(超 skew)→ 未生效。
        let c = idtok(json!({ "nbf": 1_000_001_000i64 }));
        assert_eq!(
            verify_upstream_id_token_claims(&c, &idtok_expect(1_000_000_000)),
            Err(IdTokenClaimError::NotYetValid)
        );
        // iat 在未来(超 skew)→ 拒。
        let c = idtok(json!({ "iat": 1_000_001_000i64 }));
        assert_eq!(
            verify_upstream_id_token_claims(&c, &idtok_expect(1_000_000_000)),
            Err(IdTokenClaimError::IatInFuture)
        );
    }

    #[test]
    fn idtoken_within_clock_skew_ok() {
        // exp 刚过但在 skew 窗内 → 放行(now=exp+30,skew=60)。
        let c = idtok(json!({ "exp": 999_999_970i64 }));
        assert!(verify_upstream_id_token_claims(&c, &idtok_expect(1_000_000_000)).is_ok());
    }
}
