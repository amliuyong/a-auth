//! C1.1 / C1.2 / C1.2b / C1.3 / C1.4 / C1.5 / C1.6 — 两份 discovery metadata 生成。
//!
//! 生成 OIDC(`/.well-known/openid-configuration`)与 OAuth(RFC 8414
//! `/.well-known/oauth-authorization-server`)两份**独立**文档,按 spec 000 的
//! **三个闭合字段集**处理:
//! - 集合① 共享且逐值相等:两份都含、取值相同。
//! - 集合② OIDC 专有:仅 OIDC 份含。
//! - 集合③ OIDC REQUIRED 闭列:OIDC 份必填(= ①∩OIDC + ②)。
//!
//! 决策真相源:docs/DESIGN §1(端点/字段)、§0.1(永久非目标)、§2.8(subject_types 语义,本处只宣告)。
//! 本模块只做"发现面如实宣告",不实现签名/流程。

use crate::issuer::Issuer;
use crate::phase::Phase;
use agent_auth_ema::{GRANT_PROFILE as EMA_GRANT_PROFILE, JWT_BEARER_GRANT};
use serde::Serialize;
use serde_json::{Map, Value};

/// subject_types 形态(C1.1b:宣告值 = 实际签发口径)。派生规则在 §2.8 / spec 001,此处只宣告。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectType {
    Pairwise,
    Public,
}

impl SubjectType {
    fn as_str(self) -> &'static str {
        match self {
            SubjectType::Pairwise => "pairwise",
            SubjectType::Public => "public",
        }
    }
}

/// 生成 metadata 所需的部署配置(由上游按 issuer + 部署选定值提供)。
#[derive(Debug, Clone)]
pub struct MetadataConfig {
    /// C1.6a 派生出的 issuer(所有端点都拼它,保证 C1.6 同 origin)。
    pub issuer: Issuer,
    /// C1.1b:该租户/部署**实际选定**的 subject_type(宣告值必须 = 签发口径)。
    pub subject_type: SubjectType,
    /// 当前发布阶段(C1.2:只宣告本阶段及更早落地的端点/grant)。
    pub phase: Phase,
    /// CIBA ping/push 是否**实际启用**(spec 013 §4,C7b.5:Phase≥P3 且 feature gate 开;由 HTTP 层
    /// 从 `AppState::ciba_ping_push_active()` 注入)。true → discovery 宣告 poll/ping/push;false → 仅 poll。
    /// **不写死"P3=三模式"**:宣告值 MUST 反映运行时实际可用能力(评审 M3)。默认 false(后向兼容)。
    pub ciba_ping_push_active: bool,
    /// X.509-SVID / mTLS 是否**实际启用**(spec 012 §1.4/C5.7:P3 且 feature 开 + SelfHosted;HTTP 层从
    /// `AppState::mtls_svid_enabled` 注入)。true → `token_endpoint_auth_methods_supported` 含 `spiffe_svid_mtls`。默认 false。
    pub mtls_svid_enabled: bool,
    /// private_key_jwt 的 replay store 是否可用。false 时准入与 metadata 均隐藏该方法。
    pub private_key_jwt_enabled: bool,
    /// Stable MCP EMA profile 是否已完整启用。上游只可在 feature gate 与全部运行时依赖
    /// 启动校验通过后置 true；本层再做 P2 阶段门控，避免提前宣告未落地能力。
    pub ema_enabled: bool,
    /// 当前 issuer/tenant 是否已完整启用 Client ID Metadata Document resolution。
    /// false 时字段必须缺失，而不是宣告 false，避免客户端误判 capability。
    pub client_id_metadata_document_supported: bool,
}

/// 一份 discovery 文档(键序稳定,便于快照比对)。
#[derive(Debug, Clone, PartialEq)]
pub struct Metadata(Map<String, Value>);

impl Metadata {
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.get(key)
    }
    pub fn contains(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }
    pub fn to_json(&self) -> Value {
        Value::Object(self.0.clone())
    }
}

impl Serialize for Metadata {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

/// 集合①:两份共享且必须逐值相等的字段名(spec 000 C1.1)。
pub const SHARED_FIELDS: &[&str] = &[
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "registration_endpoint",
    "jwks_uri",
    "code_challenge_methods_supported",
    "grant_types_supported",
    "response_types_supported",
    "authorization_response_iss_parameter_supported",
    "token_endpoint_auth_methods_supported",
    "client_id_metadata_document_supported",
];

/// 集合②:OIDC 专有字段(仅 OIDC 份含)。
pub const OIDC_ONLY_FIELDS: &[&str] = &[
    "subject_types_supported",
    "id_token_signing_alg_values_supported",
    "userinfo_endpoint",
    "claims_supported", // OIDC-only:不进 OAuth AS metadata
    "acr_values_supported",
    "request_parameter_supported",
    "request_uri_parameter_supported",
];

/// 集合③:OIDC REQUIRED 闭列(OIDC 份必填)。
pub const OIDC_REQUIRED_FIELDS: &[&str] = &[
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "jwks_uri",
    "response_types_supported",
    "subject_types_supported",
    "id_token_signing_alg_values_supported",
];

fn ep(issuer: &Issuer, path: &str) -> Value {
    // 端点一律拼在 issuer origin 上 → C1.6 同 origin 天然成立。
    Value::String(format!("{}{}", issuer.as_str(), path))
}

/// 共享字段(集合①)——两份都用同一份,保证逐值相等。
fn shared_map(cfg: &MetadataConfig) -> Map<String, Value> {
    let iss = &cfg.issuer;
    let mut m = Map::new();
    m.insert("issuer".into(), Value::String(iss.as_str().to_string()));
    m.insert("authorization_endpoint".into(), ep(iss, "/authorize"));
    m.insert("token_endpoint".into(), ep(iss, "/token"));
    m.insert("registration_endpoint".into(), ep(iss, "/register"));
    m.insert("jwks_uri".into(), ep(iss, "/jwks.json"));
    // C1.3:PKCE S256。
    m.insert(
        "code_challenge_methods_supported".into(),
        json_str_array(&["S256"]),
    );
    // C1.2b:永久排除 implicit/hybrid/ROPC —— response_types 恒 ["code"];
    //        grant_types 只列受支持且按阶段落地的(C1.2),绝不含 implicit/password。
    m.insert("response_types_supported".into(), json_str_array(&["code"]));
    let mut grant_types = cfg.phase.grant_types_supported();
    let ema_active = cfg.ema_enabled && cfg.phase.at_least(Phase::P2);
    if ema_active {
        grant_types.push(JWT_BEARER_GRANT);
    }
    m.insert("grant_types_supported".into(), json_str_array(&grant_types));
    if ema_active {
        m.insert(
            "authorization_grant_profiles_supported".into(),
            json_str_array(&[EMA_GRANT_PROFILE]),
        );
    }
    // C1.4:宣告 iss 参数支持。
    m.insert(
        "authorization_response_iss_parameter_supported".into(),
        Value::Bool(true),
    );
    if cfg.client_id_metadata_document_supported {
        m.insert(
            "client_id_metadata_document_supported".into(),
            Value::Bool(true),
        );
    }
    // 分阶段(spec 012 M6):workload_oidc_jwt 随 P2 落地才宣告(公理 1)。
    m.insert(
        "token_endpoint_auth_methods_supported".into(),
        json_str_array(&cfg.phase.token_endpoint_auth_methods_supported(
            cfg.private_key_jwt_enabled,
            cfg.mtls_svid_enabled,
        )),
    );
    let private_key_jwt_algs =
        agent_auth_client::enabled_private_key_jwt_signing_alg_names(cfg.private_key_jwt_enabled);
    if !private_key_jwt_algs.is_empty() {
        m.insert(
            "token_endpoint_auth_signing_alg_values_supported".into(),
            json_str_array(&private_key_jwt_algs),
        );
    }
    m
}

fn json_str_array(items: &[&str]) -> Value {
    Value::Array(items.iter().map(|s| Value::String((*s).into())).collect())
}

fn insert_revocation_metadata(cfg: &MetadataConfig, metadata: &mut Map<String, Value>) {
    if cfg.phase.must_not_advertise("revocation_endpoint") {
        return;
    }
    metadata.insert("revocation_endpoint".into(), ep(&cfg.issuer, "/revoke"));
    metadata.insert(
        "revocation_endpoint_auth_methods_supported".into(),
        json_str_array(
            &agent_auth_client::enabled_registered_client_auth_method_names(
                cfg.private_key_jwt_enabled,
            ),
        ),
    );
    let private_key_jwt_algs =
        agent_auth_client::enabled_private_key_jwt_signing_alg_names(cfg.private_key_jwt_enabled);
    if !private_key_jwt_algs.is_empty() {
        metadata.insert(
            "revocation_endpoint_auth_signing_alg_values_supported".into(),
            json_str_array(&private_key_jwt_algs),
        );
    }
}

/// 生成 OIDC discovery(`/.well-known/openid-configuration`):共享① + OIDC 专有② + 分阶段端点。
pub fn openid_configuration(cfg: &MetadataConfig) -> Metadata {
    let iss = &cfg.issuer;
    let mut m = shared_map(cfg);
    // 集合②:OIDC 专有(subject_types 宣告选定值;ID token alg 含 RS256+ES256,C1.5)。
    m.insert(
        "subject_types_supported".into(),
        json_str_array(&[cfg.subject_type.as_str()]),
    );
    m.insert(
        "id_token_signing_alg_values_supported".into(),
        json_str_array(&["RS256", "ES256"]),
    );
    // OIDC Discovery §3:by-value Request Object 不支持。request_uri 缺省为 true，P3
    // 前必须显式 false；P3 起仅通过 PAR 产生的同源 URN request_uri 可用。
    m.insert("request_parameter_supported".into(), Value::Bool(false));
    m.insert(
        "request_uri_parameter_supported".into(),
        Value::Bool(cfg.phase.at_least(Phase::P3)),
    );
    // claims_supported(OIDC Discovery §3,RECOMMENDED):宣告 **id_token 实际签发**的标准 claim(公理 1:
    // 只宣告真发的)。acr/amr 随 C9.5b acr/amr 透传链落地(联邦透传上游、本地登录带 email/recovery_code)才纳入。
    // 非标准命名空间 claim(`https://…/c`)不列入(仅标准 claim)。
    m.insert(
        "claims_supported".into(),
        json_str_array(&[
            "iss",
            "sub",
            "aud",
            "exp",
            "iat",
            "auth_time",
            "nonce",
            "acr",
            "amr",
        ]),
    );
    m.insert(
        "acr_values_supported".into(),
        json_str_array(&[
            "urn:agent-auth:assurance:baseline",
            "urn:agent-auth:assurance:strong",
        ]),
    );
    // C1.2:分阶段端点**一律从 phase golden 单一真相源上架**(userinfo/introspect/revoke/
    // end-session/device/CIBA/PAR……),避免"生成"与"快照基线"两处漂移(Kiro 评审)。
    // 未到阶段的端点不出现(C1.2 MUST NOT)。
    let active = cfg.phase.active_fields();
    for (field, val) in &active {
        let v = match val {
            crate::phase::EndpointValue::Url(path) => ep(iss, path),
            crate::phase::EndpointValue::BoolTrue => Value::Bool(true),
        };
        m.insert((*field).into(), v);
    }
    // RFC 8414:两份 metadata 复用同一 revocation endpoint/auth-method 投影。
    insert_revocation_metadata(cfg, &mut m);
    // DPoP 宣告(spec 010 §5.2,C8.7b,RFC 9449 §5.1):P3 起 AS 支持 token endpoint 的 DPoP proof 校验 +
    // cnf.jkt 签发(v1 仅 ES256)。宣告让 client 知道可用 DPoP + 算法;P3 前不宣告(能力未上线)。
    if cfg.phase.at_least(Phase::P3) {
        m.insert(
            "dpop_signing_alg_values_supported".into(),
            json_str_array(&["ES256"]),
        );
    }
    // CIBA 投递模式宣告(spec 013 §4,C7b.5,OIDC CIBA §4):仅当 backchannel_authentication_endpoint 已上架
    // (P2+)才宣告 backchannel_token_delivery_modes_supported。值反映**运行时实际能力**(评审 M3):
    // ping/push 已启用(Phase≥P3+gate)→ ["poll","ping","push"];否则仅 ["poll"](不写死 P3=三模式)。
    if active
        .iter()
        .any(|(f, _)| *f == "backchannel_authentication_endpoint")
    {
        let modes: &[&str] = if cfg.ciba_ping_push_active {
            &["poll", "ping", "push"]
        } else {
            &["poll"]
        };
        m.insert(
            "backchannel_token_delivery_modes_supported".into(),
            json_str_array(modes),
        );
    }
    Metadata(m)
}

/// 生成 OAuth AS metadata(RFC 8414 `/.well-known/oauth-authorization-server`)。
pub fn oauth_authorization_server(cfg: &MetadataConfig) -> Metadata {
    let mut metadata = shared_map(cfg);
    insert_revocation_metadata(cfg, &mut metadata);
    Metadata(metadata)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issuer::{derive, Form};

    fn cfg(phase: Phase, st: SubjectType) -> MetadataConfig {
        let form = Form::Saas {
            zone: "aws.example.com".into(),
            control_host: "c.aws.example.com".into(),
        };
        MetadataConfig {
            issuer: derive("t1.aws.example.com", &form).unwrap(),
            subject_type: st,
            phase,
            ciba_ping_push_active: false, // 默认关;测 ping/push 宣告的用例单独置 true
            mtls_svid_enabled: false,     // 默认关;测 spiffe_svid_mtls 宣告的用例单独置 true
            private_key_jwt_enabled: true,
            ema_enabled: false,
            client_id_metadata_document_supported: false,
        }
    }

    // spec 013 §4 / C7b.5:backchannel_token_delivery_modes_supported 宣告随阶段 + 运行时能力。
    #[test]
    fn ciba_delivery_modes_announcement() {
        // P0/P1:无 backchannel_authentication_endpoint(CIBA 未上架)→ 不宣告 delivery modes。
        let p0 = openid_configuration(&cfg(Phase::P0, SubjectType::Pairwise));
        assert!(!p0.contains("backchannel_token_delivery_modes_supported"));
        // P2:CIBA 端点上架但 ping/push 未启用 → 仅宣告 ["poll"]。
        let p2 = openid_configuration(&cfg(Phase::P2, SubjectType::Pairwise));
        assert!(p2.contains("backchannel_authentication_endpoint"));
        assert_eq!(
            p2.get("backchannel_token_delivery_modes_supported")
                .unwrap(),
            &json_str_array(&["poll"]),
            "P2(ping/push 未启用)仅宣告 poll"
        );
        // P3 + ping/push 启用 → 宣告 poll/ping/push(反映实际能力)。
        let mut p3_active = cfg(Phase::P3, SubjectType::Pairwise);
        p3_active.ciba_ping_push_active = true;
        let m = openid_configuration(&p3_active);
        assert_eq!(
            m.get("backchannel_token_delivery_modes_supported").unwrap(),
            &json_str_array(&["poll", "ping", "push"]),
            "P3+gate 开宣告三模式"
        );
        // P3 但 gate 关(ciba_ping_push_active=false)→ 仍仅 poll(不写死 P3=三模式)。
        let p3_off = openid_configuration(&cfg(Phase::P3, SubjectType::Pairwise));
        assert_eq!(
            p3_off
                .get("backchannel_token_delivery_modes_supported")
                .unwrap(),
            &json_str_array(&["poll"]),
            "P3 但 gate 关仍仅 poll(宣告反映运行时能力,非阶段)"
        );
    }

    // spec 012 §1.4 / C5.7:spiffe_svid_mtls 宣告随 P3 + feature 开(反映运行时能力,公理 1)。
    #[test]
    fn spiffe_svid_mtls_announcement_gated() {
        let has_mtls = |c: &MetadataConfig| {
            openid_configuration(c)
                .get("token_endpoint_auth_methods_supported")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "spiffe_svid_mtls")
        };
        // P2(flag 关):不宣告 X.509-mTLS(spiffe_jwt_svid 走 P2 已在,X.509 是 P3)。
        assert!(!has_mtls(&cfg(Phase::P2, SubjectType::Pairwise)));
        // P3 但 flag 关:仍不宣告(默认关 = 字节等价)。
        assert!(!has_mtls(&cfg(Phase::P3, SubjectType::Pairwise)));
        // P3 + flag 开:宣告 spiffe_svid_mtls。
        let mut p3_on = cfg(Phase::P3, SubjectType::Pairwise);
        p3_on.mtls_svid_enabled = true;
        assert!(has_mtls(&p3_on), "P3+flag 开宣告 spiffe_svid_mtls");
        // flag 开但阶段 P2:不宣告(X.509-mTLS 是 P3 能力)。
        let mut p2_on = cfg(Phase::P2, SubjectType::Pairwise);
        p2_on.mtls_svid_enabled = true;
        assert!(!has_mtls(&p2_on), "P2 即便 flag 开也不宣告(未到 P3)");
    }

    // spec 010 §5.2 / C8.7b:dpop_signing_alg_values_supported 随 P3 宣告(RFC 9449 §5.1)。
    #[test]
    fn dpop_alg_announced_at_p3() {
        // P0–P2:不宣告(DPoP AS 签发未上线)。
        for ph in [Phase::P0, Phase::P1, Phase::P2] {
            let m = openid_configuration(&cfg(ph, SubjectType::Pairwise));
            assert!(
                !m.contains("dpop_signing_alg_values_supported"),
                "{ph:?} 不应宣告 DPoP alg"
            );
        }
        // P3:宣告 ["ES256"]。
        let m = openid_configuration(&cfg(Phase::P3, SubjectType::Pairwise));
        assert_eq!(
            m.get("dpop_signing_alg_values_supported").unwrap(),
            &json_str_array(&["ES256"]),
            "P3 宣告 DPoP ES256"
        );
    }

    // C1.1 Scenario:两份独立、共享字段逐值相等、OIDC 专有仅 OIDC 份含。
    #[test]
    fn shared_fields_byte_equal_across_docs() {
        let mut c = cfg(Phase::P0, SubjectType::Pairwise);
        c.client_id_metadata_document_supported = true;
        let oidc = openid_configuration(&c);
        let oauth = oauth_authorization_server(&c);
        for f in SHARED_FIELDS {
            assert_eq!(oidc.get(f), oauth.get(f), "共享字段 {f} 必须两份逐值相等");
            assert!(oidc.contains(f) && oauth.contains(f), "{f} 两份都须含");
        }
    }

    #[test]
    fn cimd_capability_is_gated_and_shared() {
        let mut c = cfg(Phase::P1, SubjectType::Pairwise);
        for enabled in [false, true] {
            c.client_id_metadata_document_supported = enabled;
            let oidc = openid_configuration(&c);
            let oauth = oauth_authorization_server(&c);
            let expected = enabled.then_some(Value::Bool(true));
            assert_eq!(
                oidc.get("client_id_metadata_document_supported"),
                expected.as_ref()
            );
            assert_eq!(
                oauth.get("client_id_metadata_document_supported"),
                expected.as_ref()
            );
        }
    }

    #[test]
    fn dynamic_client_registration_is_discoverable_in_both_docs() {
        let c = cfg(Phase::P0, SubjectType::Public);
        let expected = Value::String(format!("{}/register", c.issuer.as_str()));
        for metadata in [openid_configuration(&c), oauth_authorization_server(&c)] {
            assert_eq!(
                metadata.get("registration_endpoint"),
                Some(&expected),
                "DCR 客户端必须能从 discovery 找到同源 /register"
            );
        }
    }

    #[test]
    fn oidc_only_fields_absent_from_oauth() {
        let c = cfg(Phase::P0, SubjectType::Pairwise);
        let oidc = openid_configuration(&c);
        let oauth = oauth_authorization_server(&c);
        for f in OIDC_ONLY_FIELDS {
            assert!(oidc.contains(f), "OIDC 份须含 {f}");
            assert!(!oauth.contains(f), "OAuth 份 MUST NOT 含 OIDC 专有 {f}");
        }
    }

    #[test]
    fn oidc_discovery_explicitly_disables_request_objects() {
        let metadata = openid_configuration(&cfg(Phase::P0, SubjectType::Public));
        assert_eq!(
            metadata.get("request_parameter_supported"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            metadata.get("request_uri_parameter_supported"),
            Some(&Value::Bool(false))
        );
        assert!(!metadata.contains("request_object_signing_alg_values_supported"));

        let p3 = openid_configuration(&cfg(Phase::P3, SubjectType::Public));
        assert_eq!(
            p3.get("request_uri_parameter_supported"),
            Some(&Value::Bool(true)),
            "P3 PAR request_uri support must remain discoverable"
        );
    }

    #[test]
    fn oidc_required_closed_list_present() {
        let c = cfg(Phase::P0, SubjectType::Public);
        let oidc = openid_configuration(&c);
        for f in OIDC_REQUIRED_FIELDS {
            assert!(oidc.contains(f), "OIDC REQUIRED 闭列缺 {f}");
        }
    }

    // claims_supported 宣告 id_token 实际签发的标准 claim,含 acr/amr(C9.5b 透传链已落 → 公理 1 可宣告)。
    #[test]
    fn claims_supported_includes_acr_amr() {
        let c = cfg(Phase::P0, SubjectType::Public);
        let m = openid_configuration(&c);
        let cs = m
            .get("claims_supported")
            .expect("OIDC 份应含 claims_supported");
        let arr = cs.as_array().expect("claims_supported 应为数组");
        let vals: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
        for want in ["sub", "aud", "iss", "auth_time", "nonce", "acr", "amr"] {
            assert!(
                vals.contains(&want),
                "claims_supported 应含 {want}:{vals:?}"
            );
        }
    }

    #[test]
    fn oidc_discovery_publishes_internal_assurance_classes() {
        let metadata = openid_configuration(&cfg(Phase::P0, SubjectType::Public));
        assert_eq!(
            metadata.get("acr_values_supported"),
            Some(&json_str_array(&[
                "urn:agent-auth:assurance:baseline",
                "urn:agent-auth:assurance:strong",
            ]))
        );
    }

    // C1.3:code_challenge_methods 含 S256。
    #[test]
    fn code_challenge_methods_has_s256() {
        for phase in [Phase::P0, Phase::P0_5, Phase::P1, Phase::P2, Phase::P3] {
            let config = cfg(phase, SubjectType::Pairwise);
            for metadata in [
                openid_configuration(&config),
                oauth_authorization_server(&config),
            ] {
                assert_eq!(
                    metadata.get("code_challenge_methods_supported").unwrap(),
                    &json_str_array(&["S256"])
                );
            }
        }
    }

    // C1.4:宣告 authorization_response_iss_parameter_supported === true。
    #[test]
    fn iss_param_supported_true() {
        let c = cfg(Phase::P0, SubjectType::Pairwise);
        let m = openid_configuration(&c);
        assert_eq!(
            m.get("authorization_response_iss_parameter_supported")
                .unwrap(),
            &Value::Bool(true)
        );
    }

    // C1.5:id_token alg 含 RS256 + ES256。
    #[test]
    fn id_token_alg_has_rs256_and_es256() {
        for phase in [Phase::P0, Phase::P0_5, Phase::P1, Phase::P2, Phase::P3] {
            let metadata = openid_configuration(&cfg(phase, SubjectType::Pairwise));
            assert_eq!(
                metadata
                    .get("id_token_signing_alg_values_supported")
                    .unwrap(),
                &json_str_array(&["RS256", "ES256"])
            );
        }
    }

    // C1.1b:subject_types 宣告 = 选定值。
    #[test]
    fn subject_types_reflects_config() {
        let p = openid_configuration(&cfg(Phase::P0, SubjectType::Pairwise));
        assert_eq!(
            p.get("subject_types_supported").unwrap(),
            &json_str_array(&["pairwise"])
        );
        let pub_ = openid_configuration(&cfg(Phase::P0, SubjectType::Public));
        assert_eq!(
            pub_.get("subject_types_supported").unwrap(),
            &json_str_array(&["public"])
        );
    }

    // C1.6:所有 AS 端点与 issuer 同 origin。
    #[test]
    fn all_endpoints_same_origin_as_issuer() {
        for phase in [Phase::P0, Phase::P0_5, Phase::P1, Phase::P2, Phase::P3] {
            let config = cfg(phase, SubjectType::Pairwise);
            let origin = config.issuer.origin();
            for (document, metadata) in [
                ("oidc", openid_configuration(&config)),
                ("oauth", oauth_authorization_server(&config)),
            ] {
                let object = metadata.to_json();
                for (field, value) in object.as_object().unwrap() {
                    if field != "issuer" && field != "jwks_uri" && !field.ends_with("_endpoint") {
                        continue;
                    }
                    let url = value.as_str().unwrap();
                    let suffix = url.strip_prefix(origin).unwrap_or_else(|| {
                        panic!(
                            "{document} {phase:?} {field}={url} 必须与 issuer origin {origin} 同源"
                        )
                    });
                    assert!(
                        suffix.is_empty() || suffix.starts_with('/'),
                        "{document} {phase:?} {field}={url} 不能仅以 issuer 字符串为前缀"
                    );
                }
            }
        }
    }

    // C1.2b:response_types 恒 ["code"]、grant_types 不含 implicit/hybrid/ROPC。
    #[test]
    fn permanent_non_goals_excluded() {
        for phase in [Phase::P0, Phase::P0_5, Phase::P1, Phase::P2, Phase::P3] {
            let config = cfg(phase, SubjectType::Pairwise);
            for metadata in [
                openid_configuration(&config),
                oauth_authorization_server(&config),
            ] {
                assert_eq!(
                    metadata.get("response_types_supported").unwrap(),
                    &json_str_array(&["code"]),
                    "response_types 恒 [code]"
                );
                let grants = metadata.get("grant_types_supported").unwrap();
                let banned = ["token", "id_token", "token id_token", "password"];
                for banned_grant in banned {
                    assert!(
                        !grants
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|grant| grant == banned_grant),
                        "grant_types 阶段 {phase:?} MUST NOT 含 {banned_grant}"
                    );
                }
            }
        }
    }

    #[test]
    fn private_key_jwt_metadata_requires_runtime_replay_capability() {
        let mut config = cfg(Phase::P1, SubjectType::Pairwise);
        config.private_key_jwt_enabled = false;
        for metadata in [
            openid_configuration(&config),
            oauth_authorization_server(&config),
        ] {
            assert!(!metadata
                .get("token_endpoint_auth_methods_supported")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .any(|method| method == "private_key_jwt"));
            assert!(!metadata.contains("token_endpoint_auth_signing_alg_values_supported"));
            assert!(!metadata.contains("revocation_endpoint_auth_signing_alg_values_supported"));
        }
    }

    // C1.1b「租户间独立」(Kiro 评审补):两个不同 config 各自生成、互不影响。
    #[test]
    fn tenant_configs_are_independent() {
        let form = Form::Saas {
            zone: "aws.example.com".into(),
            control_host: "c.aws.example.com".into(),
        };
        let t1 = MetadataConfig {
            issuer: derive("t1.aws.example.com", &form).unwrap(),
            subject_type: SubjectType::Public, // 企业租户 opt-in public
            phase: Phase::P0,
            ciba_ping_push_active: false,
            mtls_svid_enabled: false,
            private_key_jwt_enabled: true,
            ema_enabled: false,
            client_id_metadata_document_supported: false,
        };
        let t2 = MetadataConfig {
            issuer: derive("t2.aws.example.com", &form).unwrap(),
            subject_type: SubjectType::Pairwise, // 默认 pairwise
            phase: Phase::P0,
            ciba_ping_push_active: false,
            mtls_svid_enabled: false,
            private_key_jwt_enabled: true,
            ema_enabled: false,
            client_id_metadata_document_supported: false,
        };
        let m1 = openid_configuration(&t1);
        let m2 = openid_configuration(&t2);
        // t1 opt-in public 不影响 t2 仍宣告 pairwise。
        assert_eq!(
            m1.get("subject_types_supported").unwrap(),
            &json_str_array(&["public"])
        );
        assert_eq!(
            m2.get("subject_types_supported").unwrap(),
            &json_str_array(&["pairwise"])
        );
        // issuer 各自独立。
        assert_ne!(m1.get("issuer"), m2.get("issuer"));
    }

    // C1.2:用独立于 `Phase::active_fields()` 的显式矩阵钉死两份 metadata 在全部阶段
    // 实际宣告的 grant 与端点。若实现新增字段却未同步 DESIGN 阶段表,精确集合比较会失败。
    #[test]
    fn metadata_grants_and_endpoints_match_complete_phase_matrix() {
        use std::collections::BTreeMap;

        const BASE_GRANTS: &[&str] = &["authorization_code", "refresh_token"];
        const P2_GRANTS: &[&str] = &[
            "authorization_code",
            "refresh_token",
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:token-exchange",
            "urn:ietf:params:oauth:grant-type:device_code",
            "urn:openid:params:grant-type:ciba",
        ];
        const P2_EMA_GRANTS: &[&str] = &[
            "authorization_code",
            "refresh_token",
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:token-exchange",
            "urn:ietf:params:oauth:grant-type:device_code",
            "urn:openid:params:grant-type:ciba",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
        ];
        const OIDC_P0_ENDPOINTS: &[(&str, &str)] = &[
            ("authorization_endpoint", "/authorize"),
            ("jwks_uri", "/jwks.json"),
            ("registration_endpoint", "/register"),
            ("token_endpoint", "/token"),
            ("userinfo_endpoint", "/userinfo"),
        ];
        const OIDC_P1_ENDPOINTS: &[(&str, &str)] = &[
            ("authorization_endpoint", "/authorize"),
            ("end_session_endpoint", "/end-session"),
            ("introspection_endpoint", "/introspect"),
            ("jwks_uri", "/jwks.json"),
            ("registration_endpoint", "/register"),
            ("revocation_endpoint", "/revoke"),
            ("token_endpoint", "/token"),
            ("userinfo_endpoint", "/userinfo"),
        ];
        const OIDC_P2_ENDPOINTS: &[(&str, &str)] = &[
            ("authorization_endpoint", "/authorize"),
            ("backchannel_authentication_endpoint", "/bc-authorize"),
            ("device_authorization_endpoint", "/device_authorization"),
            ("end_session_endpoint", "/end-session"),
            ("introspection_endpoint", "/introspect"),
            ("jwks_uri", "/jwks.json"),
            ("registration_endpoint", "/register"),
            ("revocation_endpoint", "/revoke"),
            ("token_endpoint", "/token"),
            ("userinfo_endpoint", "/userinfo"),
        ];
        const OIDC_P3_ENDPOINTS: &[(&str, &str)] = &[
            ("authorization_endpoint", "/authorize"),
            ("backchannel_authentication_endpoint", "/bc-authorize"),
            ("device_authorization_endpoint", "/device_authorization"),
            ("end_session_endpoint", "/end-session"),
            ("introspection_endpoint", "/introspect"),
            ("jwks_uri", "/jwks.json"),
            ("pushed_authorization_request_endpoint", "/par"),
            ("registration_endpoint", "/register"),
            ("revocation_endpoint", "/revoke"),
            ("token_endpoint", "/token"),
            ("userinfo_endpoint", "/userinfo"),
        ];
        const OAUTH_P0_ENDPOINTS: &[(&str, &str)] = &[
            ("authorization_endpoint", "/authorize"),
            ("jwks_uri", "/jwks.json"),
            ("registration_endpoint", "/register"),
            ("token_endpoint", "/token"),
        ];
        const OAUTH_P1_ENDPOINTS: &[(&str, &str)] = &[
            ("authorization_endpoint", "/authorize"),
            ("jwks_uri", "/jwks.json"),
            ("registration_endpoint", "/register"),
            ("revocation_endpoint", "/revoke"),
            ("token_endpoint", "/token"),
        ];

        let matrix = [
            (
                Phase::P0,
                BASE_GRANTS,
                BASE_GRANTS,
                OIDC_P0_ENDPOINTS,
                OAUTH_P0_ENDPOINTS,
            ),
            (
                Phase::P0_5,
                BASE_GRANTS,
                BASE_GRANTS,
                OIDC_P0_ENDPOINTS,
                OAUTH_P0_ENDPOINTS,
            ),
            (
                Phase::P1,
                BASE_GRANTS,
                BASE_GRANTS,
                OIDC_P1_ENDPOINTS,
                OAUTH_P1_ENDPOINTS,
            ),
            (
                Phase::P2,
                P2_GRANTS,
                P2_EMA_GRANTS,
                OIDC_P2_ENDPOINTS,
                OAUTH_P1_ENDPOINTS,
            ),
            (
                Phase::P3,
                P2_GRANTS,
                P2_EMA_GRANTS,
                OIDC_P3_ENDPOINTS,
                OAUTH_P1_ENDPOINTS,
            ),
        ];

        for (phase, expected_grants, expected_ema_grants, expected_oidc, expected_oauth) in matrix {
            for (ema_enabled, expected_feature_grants) in
                [(false, expected_grants), (true, expected_ema_grants)]
            {
                let mut config = cfg(phase, SubjectType::Pairwise);
                config.ema_enabled = ema_enabled;
                for (document, metadata, expected_endpoints) in [
                    ("oidc", openid_configuration(&config), expected_oidc),
                    ("oauth", oauth_authorization_server(&config), expected_oauth),
                ] {
                    assert_eq!(
                        metadata.get("grant_types_supported"),
                        Some(&json_str_array(expected_feature_grants)),
                        "{document} {phase:?} ema={ema_enabled} grant matrix drifted"
                    );
                    assert!(
                        !metadata.contains("require_pushed_authorization_requests"),
                        "{document} {phase:?} must not require PAR AS-wide"
                    );

                    let actual = metadata
                        .to_json()
                        .as_object()
                        .unwrap()
                        .iter()
                        .filter(|(field, _)| {
                            field.as_str() == "jwks_uri" || field.ends_with("_endpoint")
                        })
                        .map(|(field, value)| {
                            (
                                field.clone(),
                                value
                                    .as_str()
                                    .unwrap_or_else(|| {
                                        panic!("{document} {phase:?} {field} must be a URL string")
                                    })
                                    .to_string(),
                            )
                        })
                        .collect::<BTreeMap<_, _>>();
                    let expected = expected_endpoints
                        .iter()
                        .map(|(field, path)| {
                            (
                                (*field).to_string(),
                                format!("{}{}", config.issuer.as_str(), path),
                            )
                        })
                        .collect::<BTreeMap<_, _>>();
                    assert_eq!(
                        actual, expected,
                        "{document} {phase:?} ema={ema_enabled} endpoint matrix drifted"
                    );
                }
            }
        }
    }

    // determinism(codex+Kiro):同 config 多次生成的 JSON 字节完全一致(固定插入顺序)。
    #[test]
    fn metadata_json_deterministic() {
        let c = cfg(Phase::P0, SubjectType::Pairwise);
        let a = serde_json::to_string(&openid_configuration(&c)).unwrap();
        let b = serde_json::to_string(&openid_configuration(&c)).unwrap();
        assert_eq!(a, b, "同 config 两次序列化必须逐字节一致(便于快照/ETag)");
    }

    // C13.1:EMA 默认关闭时，两份 P2 metadata 必须与引入 EMA 前逐字节兼容。
    #[test]
    fn ema_feature_off_full_metadata_json_golden() {
        let c = cfg(Phase::P2, SubjectType::Pairwise);
        assert_eq!(
            serde_json::to_string(&openid_configuration(&c)).unwrap(),
            r#"{"issuer":"https://t1.aws.example.com","authorization_endpoint":"https://t1.aws.example.com/authorize","token_endpoint":"https://t1.aws.example.com/token","registration_endpoint":"https://t1.aws.example.com/register","jwks_uri":"https://t1.aws.example.com/jwks.json","code_challenge_methods_supported":["S256"],"response_types_supported":["code"],"grant_types_supported":["authorization_code","refresh_token","client_credentials","urn:ietf:params:oauth:grant-type:token-exchange","urn:ietf:params:oauth:grant-type:device_code","urn:openid:params:grant-type:ciba"],"authorization_response_iss_parameter_supported":true,"token_endpoint_auth_methods_supported":["none","client_secret_basic","client_secret_post","private_key_jwt","workload_oidc_jwt","aws_sigv4_caller_identity","spiffe_jwt_svid"],"token_endpoint_auth_signing_alg_values_supported":["RS256","ES256"],"subject_types_supported":["pairwise"],"id_token_signing_alg_values_supported":["RS256","ES256"],"request_parameter_supported":false,"request_uri_parameter_supported":false,"claims_supported":["iss","sub","aud","exp","iat","auth_time","nonce","acr","amr"],"acr_values_supported":["urn:agent-auth:assurance:baseline","urn:agent-auth:assurance:strong"],"userinfo_endpoint":"https://t1.aws.example.com/userinfo","introspection_endpoint":"https://t1.aws.example.com/introspect","revocation_endpoint":"https://t1.aws.example.com/revoke","end_session_endpoint":"https://t1.aws.example.com/end-session","device_authorization_endpoint":"https://t1.aws.example.com/device_authorization","backchannel_authentication_endpoint":"https://t1.aws.example.com/bc-authorize","revocation_endpoint_auth_methods_supported":["none","client_secret_basic","client_secret_post","private_key_jwt"],"revocation_endpoint_auth_signing_alg_values_supported":["RS256","ES256"],"backchannel_token_delivery_modes_supported":["poll"]}"#,
            "EMA-off OIDC metadata changed"
        );
        assert_eq!(
            serde_json::to_string(&oauth_authorization_server(&c)).unwrap(),
            r#"{"issuer":"https://t1.aws.example.com","authorization_endpoint":"https://t1.aws.example.com/authorize","token_endpoint":"https://t1.aws.example.com/token","registration_endpoint":"https://t1.aws.example.com/register","jwks_uri":"https://t1.aws.example.com/jwks.json","code_challenge_methods_supported":["S256"],"response_types_supported":["code"],"grant_types_supported":["authorization_code","refresh_token","client_credentials","urn:ietf:params:oauth:grant-type:token-exchange","urn:ietf:params:oauth:grant-type:device_code","urn:openid:params:grant-type:ciba"],"authorization_response_iss_parameter_supported":true,"token_endpoint_auth_methods_supported":["none","client_secret_basic","client_secret_post","private_key_jwt","workload_oidc_jwt","aws_sigv4_caller_identity","spiffe_jwt_svid"],"token_endpoint_auth_signing_alg_values_supported":["RS256","ES256"],"revocation_endpoint":"https://t1.aws.example.com/revoke","revocation_endpoint_auth_methods_supported":["none","client_secret_basic","client_secret_post","private_key_jwt"],"revocation_endpoint_auth_signing_alg_values_supported":["RS256","ES256"]}"#,
            "EMA-off OAuth metadata changed"
        );
    }

    #[test]
    fn ema_feature_on_is_announced_consistently_at_p2() {
        const PROFILE: &str = "urn:ietf:params:oauth:grant-profile:id-jag";
        const GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

        let mut enabled = cfg(Phase::P2, SubjectType::Pairwise);
        enabled.ema_enabled = true;
        for metadata in [
            openid_configuration(&enabled),
            oauth_authorization_server(&enabled),
        ] {
            assert_eq!(
                metadata.get("authorization_grant_profiles_supported"),
                Some(&json_str_array(&[PROFILE]))
            );
            assert!(metadata
                .get("grant_types_supported")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == GRANT));
        }

        let mut too_early = cfg(Phase::P1, SubjectType::Pairwise);
        too_early.ema_enabled = true;
        for metadata in [
            openid_configuration(&too_early),
            oauth_authorization_server(&too_early),
        ] {
            assert!(!metadata.contains("authorization_grant_profiles_supported"));
            assert!(!metadata
                .get("grant_types_supported")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == GRANT));
        }
    }
}
