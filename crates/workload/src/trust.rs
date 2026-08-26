//! workload 信任绑定数据模型 + 匹配(spec 012 H2/M5/L2)。
//!
//! 信任策略把平台侧主体(OIDC `iss`+`sub` / SigV4 caller ARN)映射到本 AS 的 `client_id`。
//! 匹配语义:①**精确**(逐字节);②**glob 前缀**(`*` 通配**单段**,如 `role/agent-*`;**不支持 `**`/正则**)。
//! 认证成功产出 `WorkloadIdentity`,供 2LO 签发 + spec 011 身份闸消费。

use serde::{Deserialize, Serialize};

/// 信任机制(与三条自定义 auth method 对应)。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustMechanism {
    /// OIDC-JWT:平台签发的 OIDC token(本地验签)。
    Oidc {
        /// 平台 issuer(`iss` 精确匹配)。
        platform_issuer: String,
        /// 平台 JWKS 取处(IO 层用;本纯逻辑不取)。
        jwks_uri: String,
        /// `sub` 匹配模式(精确或 glob 前缀单段)。
        subject_pattern: String,
    },
    /// SigV4:STS 返回的 caller ARN 匹配。
    Sigv4 {
        /// 可信 AWS 账号(caller ARN 须属此账号)。
        aws_account_id: String,
        /// role ARN 匹配模式(精确或 glob 前缀单段)。
        role_arn_pattern: String,
    },
    /// SPIFFE JWT-SVID(spec 012 §1.4):trust domain 签发的 JWT-SVID 作 client_assertion。
    SpiffeJwt {
        /// **信任锚 = trust domain**(从 SVID `sub` 的 `spiffe://<authority>` authority 段解出、精确匹配;
        /// **绝不以 `iss` 作锚**——SPIRE `iss` 常是 server URL、非 trust domain)。
        trust_domain: String,
        /// 该 trust domain 的 trust bundle JWKS 取处(IO 层用;**MUST 独立于 AS 自身 JWKS**)。
        jwks_uri: String,
        /// **完整 SPIFFE ID** 匹配模式(`spiffe://<td>/<path>`;精确或 `.../*` 任意深度前缀,复用
        /// `spiffe_id_matches` 的 `/*` 边界语义;裸 `*`/空/整域 `spiffe://<td>/*` 之外不放宽)。
        spiffe_id_pattern: String,
    },
    /// SPIFFE X.509-SVID / mTLS(spec 012 §1.4,C5.7,P3):连接层客户端证书(SAN URI=SPIFFE ID)。
    /// **无 `jwks_uri`**——链验证由 API Gateway mTLS truststore(CA bundle)承载,不本地取 bundle;
    /// 本 AS 只从**已验链的叶子证书** SAN 取唯一 SPIFFE ID(`crates/workload/src/x509.rs`)后匹配本绑定。
    SpiffeX509 {
        /// **信任锚 = trust domain**(从证书 SAN SPIFFE ID 的 authority 解出、精确匹配;同 SpiffeJwt,绝不以证书 issuer DN 作锚)。
        trust_domain: String,
        /// **完整 SPIFFE ID** 匹配模式(同 SpiffeJwt 语义:精确或 `.../*` 任意深度前缀;裸 `*`/空/整域拒)。
        spiffe_id_pattern: String,
    },
}

/// 从 SPIFFE ID(`spiffe://<trust-domain>/<path>`)解出 trust domain(authority 段)。
/// 合法性(SPIFFE-ID 规范):MUST `spiffe://` scheme + **非空 trust domain**,且 authority **MUST NOT** 含
/// 端口(`:`)/ userinfo(`@`)/ query(`?`)/ fragment(`#`)——SPIFFE trust domain 是纯 DNS-like 名。
/// 含这些即**畸形 SPIFFE ID**,返 None(调用方 fail-closed 拒;评审 Kiro:不静默把 `td:8443` 当 trust
/// domain,也不 strip 后放行 malformed id——直接拒最安全)。trust domain = scheme 后到第一个 `/` 或串尾。
pub fn spiffe_trust_domain(spiffe_id: &str) -> Option<&str> {
    let rest = spiffe_id.strip_prefix("spiffe://")?;
    // authority 到第一个 `/`(path 起点)或串尾。
    let td = rest.split('/').next().unwrap_or("");
    // 非空 + 不含端口/userinfo/query/fragment(畸形 SPIFFE ID 一律拒,fail-closed)。
    if td.is_empty() || td.contains([':', '@', '?', '#']) {
        return None;
    }
    Some(td)
}

/// SPIFFE ID 匹配(spec 012 §1.4):对**完整 SPIFFE ID** 跑,与 grant `actor_matches` **同 `/*` 边界语义**——
/// `.../*` 匹配该前缀下**任意深度**子路径(prefix 须以 `/` 结尾 + candidate 须严格更长有子段);无 `*` 精确;
/// **裸 `*`/空 pattern fail-closed 拒**(绝不放行整域/一切)。措辞:非"单段",是任意深度前缀。
pub fn spiffe_id_matches(pattern: &str, spiffe_id: &str) -> bool {
    if pattern.is_empty() || pattern == "*" {
        return false; // 空/纯通配绝不放行
    }
    if let Some(prefix_slash) = pattern.strip_suffix('*') {
        // `.../*` 前缀通配:prefix 须以 `/` 结尾(防裸 `*`/段边界逃逸)、candidate 须以 prefix 开头且严格更长。
        prefix_slash.ends_with('/')
            && prefix_slash.len() > 1
            && spiffe_id.starts_with(prefix_slash)
            && spiffe_id.len() > prefix_slash.len()
    } else {
        pattern == spiffe_id
    }
}

/// SPIFFE JWT-SVID 匹配:找 trust_domain == sub 解出的 trust domain 且完整 SPIFFE ID 命中 pattern 的绑定。
/// principal = 实际 SPIFFE ID(sub),供审计 + 011 actor_allowlist 前缀通配。tenant 隔离。
pub fn match_spiffe(
    bindings: &[TrustBinding],
    tenant_id: &str,
    spiffe_id: &str,
) -> Result<WorkloadIdentity, MatchError> {
    // sub 须为合法 SPIFFE ID(spiffe:// + 非空 trust domain);否则无信任锚 fail-closed。
    let td = match spiffe_trust_domain(spiffe_id) {
        Some(td) => td,
        None => return Err(MatchError::NoBinding),
    };
    let mut matched = None;
    for b in bindings {
        if b.tenant_id != tenant_id {
            continue;
        }
        if let TrustMechanism::SpiffeJwt {
            trust_domain,
            spiffe_id_pattern,
            ..
        } = &b.mechanism
        {
            if trust_domain == td && spiffe_id_matches(spiffe_id_pattern, spiffe_id) {
                let identity = WorkloadIdentity {
                    client_id: b.mapped_client_id.clone(),
                    principal_kind: PrincipalKind::SpiffeId,
                    principal: spiffe_id.to_string(),
                };
                if matched.is_some() {
                    return Err(MatchError::AmbiguousBinding);
                }
                matched = Some(identity);
            }
        }
    }
    matched.ok_or(MatchError::NoBinding)
}

/// SPIFFE X.509-SVID 匹配(spec 012 §1.4 / C5.7):找 `SpiffeX509` 绑定,trust_domain == sub 解出的
/// trust domain 且完整 SPIFFE ID 命中 pattern。与 `match_spiffe` 同锚/同 `/*` 边界语义,仅机制变体不同
/// (X.509 无 jwks_uri——链验证在 API Gateway truststore,本处只对**已验链叶子证书的 SAN SPIFFE ID** 匹配)。
/// tenant 隔离(SelfHosted 恒 "default")。principal = 实际 SPIFFE ID(审计 + 011 actor_allowlist 前缀通配)。
pub fn match_spiffe_x509(
    bindings: &[TrustBinding],
    tenant_id: &str,
    spiffe_id: &str,
) -> Result<WorkloadIdentity, MatchError> {
    // sub(SAN)须为合法 SPIFFE ID(spiffe:// + 非空 trust domain,无端口/userinfo);否则无信任锚 fail-closed。
    let td = match spiffe_trust_domain(spiffe_id) {
        Some(td) => td,
        None => return Err(MatchError::NoBinding),
    };
    let mut matched = None;
    for b in bindings {
        if b.tenant_id != tenant_id {
            continue;
        }
        if let TrustMechanism::SpiffeX509 {
            trust_domain,
            spiffe_id_pattern,
        } = &b.mechanism
        {
            if trust_domain == td && spiffe_id_matches(spiffe_id_pattern, spiffe_id) {
                let identity = WorkloadIdentity {
                    client_id: b.mapped_client_id.clone(),
                    principal_kind: PrincipalKind::SpiffeId,
                    principal: spiffe_id.to_string(),
                };
                if matched.is_some() {
                    return Err(MatchError::AmbiguousBinding);
                }
                matched = Some(identity);
            }
        }
    }
    matched.ok_or(MatchError::NoBinding)
}

/// 一条 workload 信任绑定。**MUST** 经管理面登记(C5.5);【SaaS】按 tenant_id 分区(L3)。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustBinding {
    /// 逻辑租户 id(【SaaS】隔离键;自部署单租户可固定)。
    pub tenant_id: String,
    pub mechanism: TrustMechanism,
    /// 命中后映射到的本 AS client_id(供 2LO 签发)。
    pub mapped_client_id: String,
}

/// workload 认证成功的规范化身份输出(供 2LO 签发 + spec 011 身份闸,M5)。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadIdentity {
    /// 信任策略映射结果(2LO token 的 sub / 011 actor_allowlist 精确匹配)。
    pub client_id: String,
    pub principal_kind: PrincipalKind,
    /// 平台侧原始主体(ARN/sub/SPIFFE ID;审计 + 011 前缀通配匹配)。
    pub principal: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    OidcSubject,
    CallerArn,
    SpiffeId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchError {
    /// 无匹配的信任绑定(fail-closed:无信任锚不可认证)。
    NoBinding,
    /// 多条信任绑定同时命中同一主体,无法确定唯一 client 映射。
    AmbiguousBinding,
}

/// glob 前缀匹配(单段 `*`):`*` 只在**模式末尾**、匹配任意后缀(不跨已由调用方切好的"段")。
/// 本实现约定 `*` 仅支持"末尾单个",匹配 = candidate 以 `*` 前的字面前缀开头;无 `*` 则要求逐字节相等。
/// **拒绝** `**`、中间 `*`、多 `*`(不支持,返回 false——避免过宽匹配)。
pub fn pattern_match(pattern: &str, candidate: &str) -> bool {
    match pattern.split('*').count() {
        // 无 `*`:精确匹配。
        1 => pattern == candidate,
        // 恰一个 `*`:必须在末尾(split 后第二段为空)且**前缀非空**(评审 M1:空前缀 `*` 匹配一切
        // = 绕过信任边界,fail-closed 拒);前缀匹配。
        2 => {
            let (prefix, suffix) = pattern.split_once('*').unwrap();
            !prefix.is_empty() && suffix.is_empty() && candidate.starts_with(prefix)
        }
        // 多个 `*`(含 `**`):不支持,一律不匹配(fail-closed,防过宽)。
        _ => false,
    }
}

/// OIDC 匹配:找 `iss` == platform_issuer 且 `sub` 命中 subject_pattern 的绑定。
/// principal 记为**实际的 sub**(非模式),供审计/011 通配匹配。
pub fn match_oidc(
    bindings: &[TrustBinding],
    tenant_id: &str,
    iss: &str,
    sub: &str,
) -> Result<WorkloadIdentity, MatchError> {
    for b in bindings {
        if b.tenant_id != tenant_id {
            continue;
        }
        if let TrustMechanism::Oidc {
            platform_issuer,
            subject_pattern,
            ..
        } = &b.mechanism
        {
            if platform_issuer == iss && pattern_match(subject_pattern, sub) {
                return Ok(WorkloadIdentity {
                    client_id: b.mapped_client_id.clone(),
                    principal_kind: PrincipalKind::OidcSubject,
                    principal: sub.to_string(),
                });
            }
        }
    }
    Err(MatchError::NoBinding)
}

/// SigV4 匹配便捷式:caller ARN 属可信账号 + 命中 role_arn_pattern。principal = 实际 caller ARN。
pub fn match_sigv4(
    bindings: &[TrustBinding],
    tenant_id: &str,
    caller_account: &str,
    caller_arn: &str,
) -> Result<WorkloadIdentity, MatchError> {
    for b in bindings {
        if b.tenant_id != tenant_id {
            continue;
        }
        if let TrustMechanism::Sigv4 {
            aws_account_id,
            role_arn_pattern,
        } = &b.mechanism
        {
            if aws_account_id == caller_account && pattern_match(role_arn_pattern, caller_arn) {
                return Ok(WorkloadIdentity {
                    client_id: b.mapped_client_id.clone(),
                    principal_kind: PrincipalKind::CallerArn,
                    principal: caller_arn.to_string(),
                });
            }
        }
    }
    Err(MatchError::NoBinding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_match_exact_and_prefix() {
        // 精确。
        assert!(pattern_match("system:sa:ns:agent", "system:sa:ns:agent"));
        assert!(!pattern_match("system:sa:ns:agent", "system:sa:ns:other"));
        // 末尾 glob 前缀。
        assert!(pattern_match(
            "arn:aws:iam::123:role/agent-*",
            "arn:aws:iam::123:role/agent-kb"
        ));
        assert!(!pattern_match(
            "arn:aws:iam::123:role/agent-*",
            "arn:aws:iam::123:role/admin"
        ));
        // 中间 `*` / `**` / 多 `*`:不支持,不匹配(fail-closed 防过宽)。
        assert!(!pattern_match("a*c", "abc"));
        assert!(!pattern_match("role/**", "role/x"));
        assert!(!pattern_match("a*b*c", "abc"));
        // 评审 M1:空前缀 `*` 匹配一切 = 绕过信任边界,MUST 拒。
        assert!(!pattern_match("*", "anything"));
        assert!(!pattern_match("*", ""));
    }

    fn oidc_binding() -> TrustBinding {
        TrustBinding {
            tenant_id: "t1".into(),
            mechanism: TrustMechanism::Oidc {
                platform_issuer: "https://token.actions.githubusercontent.com".into(),
                jwks_uri: "https://token.actions.githubusercontent.com/.well-known/jwks".into(),
                subject_pattern: "repo:acme/agent:*".into(),
            },
            mapped_client_id: "wl-gha".into(),
        }
    }

    #[test]
    fn match_oidc_hits_and_records_actual_sub() {
        let bs = [oidc_binding()];
        let id = match_oidc(
            &bs,
            "t1",
            "https://token.actions.githubusercontent.com",
            "repo:acme/agent:ref:refs/heads/main",
        )
        .unwrap();
        assert_eq!(id.client_id, "wl-gha");
        assert_eq!(id.principal_kind, PrincipalKind::OidcSubject);
        assert_eq!(id.principal, "repo:acme/agent:ref:refs/heads/main"); // 实际 sub,非模式
    }

    #[test]
    fn match_oidc_wrong_iss_or_sub_no_binding() {
        let bs = [oidc_binding()];
        // iss 不符。
        assert_eq!(
            match_oidc(&bs, "t1", "https://evil.example", "repo:acme/agent:x"),
            Err(MatchError::NoBinding)
        );
        // sub 不在模式内。
        assert_eq!(
            match_oidc(
                &bs,
                "t1",
                "https://token.actions.githubusercontent.com",
                "repo:other/x:y"
            ),
            Err(MatchError::NoBinding)
        );
    }

    #[test]
    fn cross_tenant_binding_not_read() {
        let bs = [oidc_binding()]; // tenant t1
                                   // 用 t2 查 → 不读 t1 的绑定(SaaS 隔离,L3)。
        assert_eq!(
            match_oidc(
                &bs,
                "t2",
                "https://token.actions.githubusercontent.com",
                "repo:acme/agent:x"
            ),
            Err(MatchError::NoBinding)
        );
    }

    #[test]
    fn match_sigv4_account_and_arn() {
        let bs = [TrustBinding {
            tenant_id: "t1".into(),
            mechanism: TrustMechanism::Sigv4 {
                aws_account_id: "111122223333".into(),
                role_arn_pattern: "arn:aws:sts::111122223333:assumed-role/agent-*".into(),
            },
            mapped_client_id: "wl-lambda".into(),
        }];
        let id = match_sigv4(
            &bs,
            "t1",
            "111122223333",
            "arn:aws:sts::111122223333:assumed-role/agent-kb/session",
        )
        .unwrap();
        assert_eq!(id.client_id, "wl-lambda");
        assert_eq!(id.principal_kind, PrincipalKind::CallerArn);
        // 错账号 → 无绑定。
        assert_eq!(
            match_sigv4(
                &bs,
                "t1",
                "999988887777",
                "arn:aws:sts::999988887777:assumed-role/agent-kb/s"
            ),
            Err(MatchError::NoBinding)
        );
    }

    #[test]
    fn empty_bindings_fail_closed() {
        assert_eq!(
            match_oidc(&[], "t1", "iss", "sub"),
            Err(MatchError::NoBinding)
        );
    }

    // ---- spec 012 §1.4 SPIFFE JWT-SVID ----

    #[test]
    fn spiffe_trust_domain_parsing() {
        assert_eq!(
            spiffe_trust_domain("spiffe://acme.example/agent/kb"),
            Some("acme.example")
        );
        // 无 path 也合法(trust domain 自身)。
        assert_eq!(
            spiffe_trust_domain("spiffe://acme.example"),
            Some("acme.example")
        );
        // 非 spiffe:// scheme / 空 trust domain → None(fail-closed)。
        assert_eq!(spiffe_trust_domain("https://acme.example/x"), None);
        assert_eq!(spiffe_trust_domain("spiffe:///agent/kb"), None); // 空 authority
        assert_eq!(spiffe_trust_domain("acme.example/agent"), None);
        // 无 path 也合法。
        assert_eq!(
            spiffe_trust_domain("spiffe://acme.example/"),
            Some("acme.example")
        ); // 空 path 段
           // 畸形:authority 含端口/userinfo/query/fragment → None(SPIFFE trust domain 不含这些,fail-closed)。
        assert_eq!(
            spiffe_trust_domain("spiffe://acme.example:8443/agent/kb"),
            None
        );
        assert_eq!(
            spiffe_trust_domain("spiffe://user@acme.example/agent"),
            None
        );
        assert_eq!(spiffe_trust_domain("spiffe://acme.example?x=1"), None);
        assert_eq!(spiffe_trust_domain("spiffe://acme.example#f"), None);
    }

    #[test]
    fn spiffe_id_matches_prefix_and_exact() {
        // 精确。
        assert!(spiffe_id_matches(
            "spiffe://acme/agent/kb",
            "spiffe://acme/agent/kb"
        ));
        assert!(!spiffe_id_matches(
            "spiffe://acme/agent/kb",
            "spiffe://acme/agent/other"
        ));
        // `.../*` 任意深度前缀:匹配 kb 与 kb/x(深路径)。
        assert!(spiffe_id_matches(
            "spiffe://acme/agent/*",
            "spiffe://acme/agent/kb"
        ));
        assert!(spiffe_id_matches(
            "spiffe://acme/agent/*",
            "spiffe://acme/agent/kb/x"
        ));
        // 段边界:prefix 须以 `/` 结尾,`spiffe://acme/agent*`(无斜杠)不放行 agentEVIL(防越界)。
        assert!(!spiffe_id_matches(
            "spiffe://acme/agent*",
            "spiffe://acme/agentEVIL"
        ));
        // 前缀不符。
        assert!(!spiffe_id_matches(
            "spiffe://acme/agent/*",
            "spiffe://acme/other/kb"
        ));
        // 裸 `*` / 空 → fail-closed 拒。
        assert!(!spiffe_id_matches("*", "spiffe://acme/agent/kb"));
        assert!(!spiffe_id_matches("", "spiffe://acme/agent/kb"));
        // candidate == prefix(无子段)不匹配(`*` 须吃至少一段)。
        assert!(!spiffe_id_matches(
            "spiffe://acme/agent/*",
            "spiffe://acme/agent/"
        ));
    }

    fn spiffe_binding() -> TrustBinding {
        TrustBinding {
            tenant_id: "t1".into(),
            mechanism: TrustMechanism::SpiffeJwt {
                trust_domain: "acme.example".into(),
                jwks_uri: "https://spire.acme.example/bundle".into(),
                spiffe_id_pattern: "spiffe://acme.example/agent/*".into(),
            },
            mapped_client_id: "wl-spiffe".into(),
        }
    }

    #[test]
    fn match_spiffe_hits_and_records_spiffe_id() {
        let bs = [spiffe_binding()];
        let id = match_spiffe(&bs, "t1", "spiffe://acme.example/agent/kb").unwrap();
        assert_eq!(id.client_id, "wl-spiffe");
        assert_eq!(id.principal_kind, PrincipalKind::SpiffeId);
        assert_eq!(id.principal, "spiffe://acme.example/agent/kb");
        // 深路径也命中。
        assert!(match_spiffe(&bs, "t1", "spiffe://acme.example/agent/kb/sess").is_ok());
    }

    #[test]
    fn match_spiffe_cross_trust_domain_rejected() {
        let bs = [spiffe_binding()]; // trust_domain=acme.example
                                     // 另一 trust domain 的 SVID(即便 path 像)→ 无绑定(跨域拒)。
        assert_eq!(
            match_spiffe(&bs, "t1", "spiffe://evil.example/agent/kb"),
            Err(MatchError::NoBinding)
        );
    }

    #[test]
    fn match_spiffe_pattern_miss_and_bad_sub_rejected() {
        let bs = [spiffe_binding()];
        // pattern 不符(非 agent 路径)。
        assert_eq!(
            match_spiffe(&bs, "t1", "spiffe://acme.example/svc/db"),
            Err(MatchError::NoBinding)
        );
        // 非 SPIFFE ID sub(无 spiffe:// scheme)→ fail-closed。
        assert_eq!(
            match_spiffe(&bs, "t1", "not-a-spiffe-id"),
            Err(MatchError::NoBinding)
        );
        // 空 trust domain → fail-closed。
        assert_eq!(
            match_spiffe(&bs, "t1", "spiffe:///agent/kb"),
            Err(MatchError::NoBinding)
        );
    }

    #[test]
    fn match_spiffe_cross_tenant_rejected() {
        let bs = [spiffe_binding()]; // tenant t1
        assert_eq!(
            match_spiffe(&bs, "t2", "spiffe://acme.example/agent/kb"),
            Err(MatchError::NoBinding)
        );
    }

    #[test]
    fn match_spiffe_empty_bindings_fail_closed() {
        assert_eq!(
            match_spiffe(&[], "t1", "spiffe://acme.example/agent/kb"),
            Err(MatchError::NoBinding)
        );
    }

    // ── SpiffeX509 匹配(spec 012 §1.4 / C5.7)──
    fn spiffe_x509_binding() -> TrustBinding {
        TrustBinding {
            tenant_id: "default".into(),
            mechanism: TrustMechanism::SpiffeX509 {
                trust_domain: "acme.example".into(),
                spiffe_id_pattern: "spiffe://acme.example/agent/*".into(),
            },
            mapped_client_id: "wl-x509".into(),
        }
    }

    #[test]
    fn match_spiffe_x509_hits() {
        let bs = [spiffe_x509_binding()];
        let id = match_spiffe_x509(&bs, "default", "spiffe://acme.example/agent/kb").unwrap();
        assert_eq!(id.client_id, "wl-x509");
        assert_eq!(id.principal_kind, PrincipalKind::SpiffeId);
        assert_eq!(id.principal, "spiffe://acme.example/agent/kb");
        // 深路径命中。
        assert!(match_spiffe_x509(&bs, "default", "spiffe://acme.example/agent/kb/s").is_ok());
    }

    #[test]
    fn match_spiffe_x509_cross_domain_pattern_tenant_bad_sub_rejected() {
        let bs = [spiffe_x509_binding()];
        // 跨 trust domain 拒。
        assert_eq!(
            match_spiffe_x509(&bs, "default", "spiffe://evil.example/agent/kb"),
            Err(MatchError::NoBinding)
        );
        // pattern 不符拒。
        assert_eq!(
            match_spiffe_x509(&bs, "default", "spiffe://acme.example/svc/db"),
            Err(MatchError::NoBinding)
        );
        // 跨租户拒。
        assert_eq!(
            match_spiffe_x509(&bs, "t2", "spiffe://acme.example/agent/kb"),
            Err(MatchError::NoBinding)
        );
        // 非 SPIFFE / 空 trust domain fail-closed。
        assert_eq!(
            match_spiffe_x509(&bs, "default", "not-spiffe"),
            Err(MatchError::NoBinding)
        );
        assert_eq!(
            match_spiffe_x509(&bs, "default", "spiffe:///agent/kb"),
            Err(MatchError::NoBinding)
        );
        // 空绑定 fail-closed。
        assert_eq!(
            match_spiffe_x509(&[], "default", "spiffe://acme.example/agent/kb"),
            Err(MatchError::NoBinding)
        );
    }

    // SpiffeX509 与 SpiffeJwt 机制不串:X.509 匹配器不命中 JWT 绑定,反之亦然。
    #[test]
    fn spiffe_x509_and_jwt_mechanisms_do_not_cross() {
        let jwt = [spiffe_binding()]; // SpiffeJwt, tenant t1
        assert_eq!(
            match_spiffe_x509(&jwt, "t1", "spiffe://acme.example/agent/kb"),
            Err(MatchError::NoBinding),
            "X.509 匹配器 MUST NOT 命中 SpiffeJwt 绑定"
        );
        let x509 = [spiffe_x509_binding()]; // SpiffeX509, default
        assert_eq!(
            match_spiffe(&x509, "default", "spiffe://acme.example/agent/kb"),
            Err(MatchError::NoBinding),
            "JWT 匹配器 MUST NOT 命中 SpiffeX509 绑定"
        );
    }
}
