//! C3.2 — 宽限窗请求指纹(构成钉死,见 spec 001)。
//!
//! 指纹 = `HMAC-SHA256(server_secret, canonical)`,`canonical` 由规范化字段按固定顺序拼成:
//! `grant_type`、`scope`(字典序集合)、`resource`(下采样目标单值)、`code_challenge`。
//! 规范化:HTTP 层恰好 URL-decode 一次后传入本模块;本模块按 `key=value` 用 `\n`
//! 连接、缺失字段用空串占位,不得再次 decode。
//! `client_id` 与 DPoP `jkt` 是**独立比较维度**(不进指纹 hash)。
//!
//! 决策真相源:docs/DESIGN §2/§2.1;本模块把 spec 001 C3.2 钉死的构成实现为确定性函数。

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// 宽限窗比较所需的续期请求要素。
#[derive(Debug, Clone, Default)]
pub struct GraceRequest {
    pub grant_type: String,
    /// scope 集合(内部会排序规范化;传入顺序无关)。
    pub scopes: Vec<String>,
    /// 下采样目标 resource(单值);无则空串。
    pub resource: String,
    /// PKCE code_challenge(源自 PKCE 流时带);无则空串。
    pub code_challenge: String,
}

/// 规范化 canonical 串(确定性:同输入同输出,scope 排序去顺序影响)。
fn canonical(req: &GraceRequest) -> String {
    let gt = &req.grant_type;
    let mut scopes = req.scopes.clone();
    scopes.sort();
    let scope = scopes.join(" ");
    let resource = &req.resource;
    let cc = &req.code_challenge;
    // 固定顺序 + 固定 key,缺失用空串占位(由上面各字段本就可空保证)。
    format!("grant_type={gt}\nscope={scope}\nresource={resource}\ncode_challenge={cc}")
}

/// 计算请求指纹(HMAC-SHA256 → 32 字节)。`server_secret` 走密钥管理(不进 repo)。
pub fn fingerprint(server_secret: &[u8], req: &GraceRequest) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(server_secret).expect("HMAC 接受任意长度 key");
    mac.update(canonical(req).as_bytes());
    mac.finalize().into_bytes().into()
}

/// 宽限窗**独立比较维度**(不进指纹 hash):client_id 与 DPoP jkt。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraceIdentity {
    pub client_id: String,
    /// DPoP key thumbprint(有 `cnf.jkt` 时);无 DPoP 为 None。
    pub dpop_jkt: Option<String>,
}

/// 宽限窗判定结果(C3.2)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraceDecision {
    /// 全维度一致 → 返回缓存的同一结果。
    ReturnCached,
    /// 任一维度不符 → 按复用检测处理(全链吊销)。
    TreatAsReuse,
}

/// 判定:缓存项(指纹 + 身份)与本次请求是否全维度一致(C3.2)。
/// 指纹用**常量时间比较**(防时序侧信道)。身份维度逐字节比较。
pub fn decide(
    cached_fp: &[u8; 32],
    cached_id: &GraceIdentity,
    req_fp: &[u8; 32],
    req_id: &GraceIdentity,
) -> GraceDecision {
    let fp_eq: bool = cached_fp.ct_eq(req_fp).into();
    let id_eq = cached_id == req_id;
    if fp_eq && id_eq {
        GraceDecision::ReturnCached
    } else {
        GraceDecision::TreatAsReuse
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> GraceRequest {
        GraceRequest {
            grant_type: "refresh_token".into(),
            scopes: vec!["kb:read".into(), "kb:search".into()],
            resource: "https://mcp.example.com".into(),
            code_challenge: String::new(),
        }
    }

    fn id() -> GraceIdentity {
        GraceIdentity {
            client_id: "cli_1".into(),
            dpop_jkt: Some("jkt_abc".into()),
        }
    }

    const SECRET: &[u8] = b"test-server-secret-not-a-real-key";

    // 确定性:同输入同指纹。
    #[test]
    fn fingerprint_deterministic() {
        assert_eq!(fingerprint(SECRET, &req()), fingerprint(SECRET, &req()));
    }

    // scope 顺序无关(规范化排序)。
    #[test]
    fn scope_order_irrelevant() {
        let mut r2 = req();
        r2.scopes = vec!["kb:search".into(), "kb:read".into()];
        assert_eq!(fingerprint(SECRET, &req()), fingerprint(SECRET, &r2));
    }

    // C3.2:全维度一致 → 返回缓存。
    #[test]
    fn all_match_returns_cached() {
        let fp = fingerprint(SECRET, &req());
        assert_eq!(decide(&fp, &id(), &fp, &id()), GraceDecision::ReturnCached);
    }

    // C3.2:改 scope → 指纹变 → 按复用处理。
    #[test]
    fn changed_scope_treated_as_reuse() {
        let cached = fingerprint(SECRET, &req());
        let mut r2 = req();
        r2.scopes = vec!["kb:read".into()]; // 少一个 scope
        let now = fingerprint(SECRET, &r2);
        assert_eq!(
            decide(&cached, &id(), &now, &id()),
            GraceDecision::TreatAsReuse
        );
    }

    // C3.2:改 resource → 按复用。
    #[test]
    fn changed_resource_treated_as_reuse() {
        let cached = fingerprint(SECRET, &req());
        let mut r2 = req();
        r2.resource = "https://other.example.com".into();
        let now = fingerprint(SECRET, &r2);
        assert_eq!(
            decide(&cached, &id(), &now, &id()),
            GraceDecision::TreatAsReuse
        );
    }

    // C3.2:独立维度换 DPoP key → 指纹相同但身份不符 → 按复用。
    #[test]
    fn changed_dpop_key_treated_as_reuse() {
        let fp = fingerprint(SECRET, &req());
        let other_id = GraceIdentity {
            client_id: "cli_1".into(),
            dpop_jkt: Some("jkt_DIFFERENT".into()),
        };
        assert_eq!(
            decide(&fp, &id(), &fp, &other_id),
            GraceDecision::TreatAsReuse
        );
    }

    // 独立维度换 client_id → 按复用。
    #[test]
    fn changed_client_id_treated_as_reuse() {
        let fp = fingerprint(SECRET, &req());
        let other_id = GraceIdentity {
            client_id: "cli_2".into(),
            dpop_jkt: Some("jkt_abc".into()),
        };
        assert_eq!(
            decide(&fp, &id(), &fp, &other_id),
            GraceDecision::TreatAsReuse
        );
    }

    // HTTP/Form 已解码的值不得在 fingerprint 层再次解码。
    #[test]
    fn parsed_values_are_not_decoded_again() {
        let mut encoded_literal = req();
        encoded_literal.scopes = vec!["a%20b".into()];
        let mut decoded_values = req();
        decoded_values.scopes = vec!["a".into(), "b".into()];
        assert_ne!(
            fingerprint(SECRET, &encoded_literal),
            fingerprint(SECRET, &decoded_values)
        );
    }

    // 边界(Kiro):超长 scope + unicode(emoji URL-encode)确定性、不 panic。
    #[test]
    fn overlong_and_unicode_scope_deterministic() {
        let mut r = req();
        r.scopes = vec!["s".repeat(10_000), "读%F0%9F%98%80书".into()];
        let a = fingerprint(SECRET, &r);
        let b = fingerprint(SECRET, &r);
        assert_eq!(a, b, "超长/unicode scope 仍须确定性");
    }

    // 边界:已解析值含百分号字面量时不 panic、保持确定性。
    #[test]
    fn malformed_percent_no_panic() {
        let mut r = req();
        r.resource = "%C0%80%ZZ".into();
        let a = fingerprint(SECRET, &r);
        let b = fingerprint(SECRET, &r);
        assert_eq!(a, b);
    }
}
