//! C1.2 — metadata 分阶段如实宣告(DESIGN §0 公理 1;golden 基线 = DESIGN §1 阶段列)。
//!
//! 每个发布阶段只宣告**本阶段及更早**真正落地的 grant type / 端点。路线图未到的能力
//! (P1 `end_session_endpoint`、P2 device/CIBA、P3 PAR)MUST NOT 提前出现在 discovery。
//!
//! 决策真相源:DESIGN §1 端点表 + grant 矩阵的阶段列、§10 路线图。本模块把该阶段列
//! 编码成"每阶段期望能力集"的 golden 基线,供 metadata 生成与快照比对共用。

/// 分阶段字段的取值形态(端点 URL 或布尔开关)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointValue {
    /// 端点 URL:最终值 = `issuer + 此路径`。
    Url(&'static str),
    /// 布尔开关字段:最终值 = `true`(如 PAR 强制标记)。
    BoolTrue,
}

/// 发布阶段(对齐 DESIGN §10:P-1 spike 不产 metadata,故从 P0 起)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    P0,
    P0_5,
    P1,
    P2,
    P3,
}

impl Phase {
    /// 从环境变量字符串解析发布阶段(部署期 `AGENT_AUTH_PHASE`)。大小写/下划线不敏感:
    /// `p0`/`p0.5`/`p0_5`/`p1`/`p2`/`p3`。无法识别返回 None(上层 fail-safe 回落 P1)。
    pub fn from_env_str(s: &str) -> Option<Phase> {
        match s
            .trim()
            .to_ascii_lowercase()
            .replace(['.', '-'], "_")
            .as_str()
        {
            "p0" => Some(Phase::P0),
            "p0_5" => Some(Phase::P0_5),
            "p1" => Some(Phase::P1),
            "p2" => Some(Phase::P2),
            "p3" => Some(Phase::P3),
            _ => None,
        }
    }

    fn rank(self) -> u8 {
        match self {
            Phase::P0 => 0,
            Phase::P0_5 => 1,
            Phase::P1 => 2,
            Phase::P2 => 3,
            Phase::P3 => 4,
        }
    }

    /// 某能力在 `min` 阶段落地,则本阶段(self)是否应宣告它。
    fn has(self, min: Phase) -> bool {
        self.rank() >= min.rank()
    }

    /// 本阶段是否 ≥ `min`(公开的阶段比较,供 handler 判定阶段门控——如多 resource 属 P1+)。
    pub fn at_least(self, min: Phase) -> bool {
        self.has(min)
    }

    /// 本阶段应宣告的 **grant_types_supported**(DESIGN §1 grant 矩阵阶段列)。
    /// 永久排除 implicit/hybrid/ROPC(C1.2b)——它们根本不出现在任何阶段的返回里。
    pub fn grant_types_supported(self) -> Vec<&'static str> {
        let mut v = vec![
            "authorization_code", // P0
            "refresh_token",      // P0
        ];
        if self.has(Phase::P2) {
            v.push("client_credentials"); // P2:2LO/workload
            v.push("urn:ietf:params:oauth:grant-type:token-exchange"); // P2:委托
            v.push("urn:ietf:params:oauth:grant-type:device_code"); // P2:device
            v.push("urn:openid:params:grant-type:ciba"); // P2:CIBA
        }
        v
    }

    /// 本阶段应宣告的 **token_endpoint_auth_methods_supported**(spec 012 M6:workload_oidc_jwt 随 P2 落地)。
    /// 只宣告落地的(公理 1):P2 才加自定义 workload auth method。`mtls_svid_enabled`(spec 012 §1.4/C5.7)=
    /// **P3 且 X.509-mTLS feature 开 + SelfHosted** 时才宣告 `spiffe_svid_mtls`(经独立 mTLS 端点,文档点明);默认关不宣告。
    pub fn token_endpoint_auth_methods_supported(
        self,
        private_key_jwt_enabled: bool,
        mtls_svid_enabled: bool,
    ) -> Vec<&'static str> {
        let mut v =
            agent_auth_client::enabled_registered_client_auth_method_names(private_key_jwt_enabled);
        if self.has(Phase::P2) {
            v.push("workload_oidc_jwt"); // P2:workload 平台 OIDC-JWT 认证(spec 012 C5.1)
            v.push("aws_sigv4_caller_identity"); // P2:SigV4/STS 兜底(spec 012 C5.2,已落地转发+熔断)
            v.push("spiffe_jwt_svid"); // P2:SPIFFE JWT-SVID via client_assertion(spec 012 §1.4/C5.7)
        }
        if self.has(Phase::P3) && mtls_svid_enabled {
            v.push("spiffe_svid_mtls"); // P3+flag:X.509-SVID via 独立 mTLS 端点(spec 012 §1.4/C5.7)
        }
        v
    }

    /// 分阶段端点的 **golden 基线**(C1.2 单一真相源):metadata 生成与快照比对**都消费它**,
    /// 二者不再各写各的(消除 Kiro 评审的双真相源漂移风险)。
    /// 返回 `(metadata 字段名, URL 路径或布尔标记, 该字段最早落地阶段)`。
    /// - `EndpointValue::Url(path)`:该字段是端点 URL,值 = `issuer + path`。
    /// - `EndpointValue::BoolTrue`:该字段是布尔开关(如 PAR 强制标记),值 = `true`。
    ///
    /// 核心 P0 端点(authorize/token/jwks 等)在集合① shared_map 里恒在,不在此列。
    pub fn phased_fields() -> &'static [(&'static str, EndpointValue, Phase)] {
        use EndpointValue::*;
        &[
            ("userinfo_endpoint", Url("/userinfo"), Phase::P0), // §1:/userinfo 提到 P0
            ("introspection_endpoint", Url("/introspect"), Phase::P1),
            ("revocation_endpoint", Url("/revoke"), Phase::P1),
            ("end_session_endpoint", Url("/end-session"), Phase::P1), // RP-initiated logout
            (
                "device_authorization_endpoint",
                Url("/device_authorization"),
                Phase::P2,
            ),
            (
                "backchannel_authentication_endpoint",
                Url("/bc-authorize"),
                Phase::P2,
            ), // CIBA
            (
                "pushed_authorization_request_endpoint",
                Url("/par"),
                Phase::P3,
            ), // PAR
               // 评审 Kiro M2:**不宣告全局 `require_pushed_authorization_requests=true`**——PAR "默认可选、
               // 逐客户端 opt-in 强制"(DESIGN §1);AS 级全局强制会逼所有直连 authorize 客户端必走 PAR,与设计矛盾。
               // 强制落逐客户端策略(post-freeze);此处仅宣告端点。
        ]
    }

    /// 本阶段应出现的分阶段字段(golden 端点集)——metadata 生成据此上架端点。
    pub fn active_fields(self) -> Vec<(&'static str, EndpointValue)> {
        Self::phased_fields()
            .iter()
            .filter(|(_, _, min)| self.has(*min))
            .map(|(name, val, _)| (*name, *val))
            .collect()
    }

    /// 给定字段名,若它是分阶段端点且本阶段**不应**出现,返回 true(用于断言 MUST NOT)。
    pub fn must_not_advertise(self, field: &str) -> bool {
        Self::phased_fields()
            .iter()
            .any(|(name, _, min)| *name == field && !self.has(*min))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // C1.2:P0 的 grant_types 只含 code + refresh,不含 P2 的 device/CIBA/exchange/cc。
    #[test]
    fn p0_grants_minimal() {
        let g = Phase::P0.grant_types_supported();
        assert_eq!(g, vec!["authorization_code", "refresh_token"]);
    }

    #[test]
    fn p2_adds_delegation_grants() {
        let g = Phase::P2.grant_types_supported();
        assert!(g.contains(&"client_credentials"));
        assert!(g.contains(&"urn:ietf:params:oauth:grant-type:token-exchange"));
        assert!(g.contains(&"urn:openid:params:grant-type:ciba"));
    }

    #[test]
    fn from_env_str_parses_all_forms() {
        assert_eq!(Phase::from_env_str("P0"), Some(Phase::P0));
        assert_eq!(Phase::from_env_str("p0.5"), Some(Phase::P0_5));
        assert_eq!(Phase::from_env_str("P0_5"), Some(Phase::P0_5));
        assert_eq!(Phase::from_env_str(" p1 "), Some(Phase::P1));
        assert_eq!(Phase::from_env_str("P2"), Some(Phase::P2));
        assert_eq!(Phase::from_env_str("p3"), Some(Phase::P3));
        assert_eq!(Phase::from_env_str("garbage"), None);
        assert_eq!(Phase::from_env_str(""), None);
    }

    // C1.2b:任何阶段都不含 implicit/hybrid/ROPC。
    #[test]
    fn no_phase_has_implicit_or_ropc() {
        for p in [Phase::P0, Phase::P0_5, Phase::P1, Phase::P2, Phase::P3] {
            let g = p.grant_types_supported();
            for banned in ["token", "id_token", "password", "implicit"] {
                assert!(!g.contains(&banned), "阶段 {p:?} 不得含 {banned}");
            }
        }
    }

    // C1.2:P0 不得宣告 P1 的 end_session、P2 device/CIBA、P3 PAR。
    #[test]
    fn p0_must_not_advertise_later_endpoints() {
        assert!(Phase::P0.must_not_advertise("end_session_endpoint"));
        assert!(Phase::P0.must_not_advertise("device_authorization_endpoint"));
        assert!(Phase::P0.must_not_advertise("pushed_authorization_request_endpoint"));
        // userinfo 提到 P0,不应被禁。
        assert!(!Phase::P0.must_not_advertise("userinfo_endpoint"));
    }

    #[test]
    fn p1_allows_end_session_but_not_par() {
        assert!(!Phase::P1.must_not_advertise("end_session_endpoint"));
        assert!(Phase::P1.must_not_advertise("device_authorization_endpoint"));
        assert!(Phase::P1.must_not_advertise("pushed_authorization_request_endpoint"));
    }

    #[test]
    fn p3_allows_par() {
        assert!(!Phase::P3.must_not_advertise("pushed_authorization_request_endpoint"));
        assert!(!Phase::P3.must_not_advertise("device_authorization_endpoint"));
    }
}
