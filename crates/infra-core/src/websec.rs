//! C10.9 / C10.9b / C10.10 — Web 交互安全:CSRF token、clickjacking 头、CORS 按端点分类。
//!
//! - **C10.9**:consent 表单 POST MUST 由 AS 下发 **per-request anti-CSRF token** 校验(consent 走
//!   cookie 会话,PAR 保护不到这一跳)。`GET /authorize` 的跨站防护靠客户端的 `state`(C1.7 echo,
//!   不在此)。
//! - **C10.9b**:所有交互页(consent/登录)MUST 下发 `Content-Security-Policy: frame-ancestors 'none'`
//!   (并 SHOULD 附 `X-Frame-Options: DENY`)防 clickjacking。
//! - **C10.10**:CORS 按端点性质分三类:公开 GET(discovery/JWKS/PRM)`*`;`open` 档 `/register` `*`
//!   (无 cookie,不与 `Allow-Credentials: true` 并用);带凭证端点(`/token` 等)按注册的 origin
//!   allowlist、MUST NOT 用 `*`;preflight `OPTIONS` 正确处理。
//!
//! 本模块纯逻辑、零 AWS 依赖:CSRF token = HMAC(session_secret, session_id‖nonce) + 常量时间比较;
//! 头构造为纯映射。`now`/随机 nonce 由上层注入(不读墙上时钟、不自取随机)。
//! 决策真相源:docs/DESIGN §8;docs/CONFORMANCE C10.9·C10.9b·C10.10。

use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

// ---------- C10.9 CSRF ----------

/// 生成 per-request anti-CSRF token = base64url(HMAC-SHA256(secret, session_id‖":"‖nonce))。
/// `session_id` 绑定 cookie 会话,`nonce` 是本次表单的一次性随机(由上层生成、随表单下发)。
pub fn csrf_token(secret: &[u8], session_id: &str, nonce: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(session_id.as_bytes());
    mac.update(b":");
    mac.update(nonce.as_bytes());
    b64url(&mac.finalize().into_bytes())
}

/// 校验 consent POST 带回的 CSRF token(常量时间比较,防时序侧信道)。
/// 会话/ nonce 不符或 token 缺失(空串)一律拒。
pub fn csrf_verify(secret: &[u8], session_id: &str, nonce: &str, presented: &str) -> bool {
    if presented.is_empty() {
        return false;
    }
    let expected = csrf_token(secret, session_id, nonce);
    // 长度不同直接不等;等长走常量时间比较。
    expected.as_bytes().ct_eq(presented.as_bytes()).into()
}

// ---------- C10.9b clickjacking / 安全响应头 ----------

/// 交互页(consent/登录)MUST/SHOULD 下发的防点击劫持头(C10.9b)。
/// 返回 (header_name, value) 列表:CSP frame-ancestors 'none'(MUST)+ X-Frame-Options DENY(SHOULD)。
pub fn interactive_page_security_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        ("Content-Security-Policy", "frame-ancestors 'none'"),
        ("X-Frame-Options", "DENY"),
    ]
}

// ---------- C10.10 CORS 按端点分类 ----------

/// 端点的 CORS 类别(C10.10 三分类)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorsClass {
    /// 公开 GET(discovery/JWKS/PRM):放开 `*`,无凭证。
    PublicGet,
    /// `open` 档 `POST /register`:允许 `*`,无 cookie(不与 Allow-Credentials 并用)。
    OpenRegister,
    /// 带凭证/敏感端点(`/token` 等):按 origin allowlist,MUST NOT `*`。
    Credentialed,
}

/// CORS 决策结果——上层据此下发响应头(preflight 与实际请求共用)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorsDecision {
    /// 允许:`Access-Control-Allow-Origin` 的值 + 是否带 `Allow-Credentials: true`。
    Allow {
        allow_origin: String,
        allow_credentials: bool,
    },
    /// 拒绝(origin 不在 allowlist / 敏感端点收到未授权 origin):不下发 ACAO。
    Deny,
}

/// 按端点类别 + 请求 origin + 注册 allowlist 决策 CORS(C10.10)。
/// - PublicGet / OpenRegister:恒 `*`、无凭证(即便带 origin 也回 `*`,因本就公开无 cookie)。
/// - Credentialed:origin 必须 ∈ allowlist 才回显该 origin + `Allow-Credentials: true`;否则 Deny。
///   MUST NOT 对带凭证端点回 `*`(浏览器也会因 `*`+credentials 组合报错)。
pub fn cors_decision(
    class: CorsClass,
    request_origin: Option<&str>,
    allowlist: &[String],
) -> CorsDecision {
    match class {
        CorsClass::PublicGet | CorsClass::OpenRegister => CorsDecision::Allow {
            allow_origin: "*".to_string(),
            allow_credentials: false, // 无 cookie,MUST NOT 与 credentials 并用
        },
        CorsClass::Credentialed => match request_origin {
            Some(origin) if allowlist.iter().any(|o| o == origin) => CorsDecision::Allow {
                allow_origin: origin.to_string(), // 回显具体 origin,不用 *
                allow_credentials: true,
            },
            _ => CorsDecision::Deny,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"test-session-secret-key";

    // C10.9:合法 CSRF token 校验通过。
    #[test]
    fn csrf_roundtrip_ok() {
        let t = csrf_token(SECRET, "sess-abc", "nonce-1");
        assert!(csrf_verify(SECRET, "sess-abc", "nonce-1", &t));
    }

    // C10.9:缺 token(空)→ 拒。
    #[test]
    fn csrf_missing_rejected() {
        assert!(!csrf_verify(SECRET, "sess-abc", "nonce-1", ""));
    }

    // C10.9:token 不匹配(改一位)→ 拒。
    #[test]
    fn csrf_tampered_rejected() {
        let mut t = csrf_token(SECRET, "sess-abc", "nonce-1");
        // 翻转最后一个字符。
        let last = t.pop().unwrap();
        t.push(if last == 'A' { 'B' } else { 'A' });
        assert!(!csrf_verify(SECRET, "sess-abc", "nonce-1", &t));
    }

    // C10.9:换了 session 或 nonce → 拒(per-request 绑定)。
    #[test]
    fn csrf_wrong_session_or_nonce_rejected() {
        let t = csrf_token(SECRET, "sess-abc", "nonce-1");
        assert!(!csrf_verify(SECRET, "sess-OTHER", "nonce-1", &t));
        assert!(!csrf_verify(SECRET, "sess-abc", "nonce-2", &t));
    }

    // 不同 nonce → 不同 token(per-request)。
    #[test]
    fn csrf_per_request_distinct() {
        let a = csrf_token(SECRET, "s", "n1");
        let b = csrf_token(SECRET, "s", "n2");
        assert_ne!(a, b);
    }

    // C10.9b:交互页头含 frame-ancestors 'none' 与 X-Frame-Options DENY。
    #[test]
    fn clickjacking_headers_present() {
        let headers = interactive_page_security_headers();
        assert!(headers
            .iter()
            .any(|(k, v)| *k == "Content-Security-Policy" && v.contains("frame-ancestors 'none'")));
        assert!(headers
            .iter()
            .any(|(k, v)| *k == "X-Frame-Options" && *v == "DENY"));
    }

    // C10.10:公开 GET → `*`、无凭证。
    #[test]
    fn cors_public_get_star() {
        let d = cors_decision(CorsClass::PublicGet, Some("https://evil.example"), &[]);
        assert_eq!(
            d,
            CorsDecision::Allow {
                allow_origin: "*".into(),
                allow_credentials: false
            }
        );
    }

    // C10.10:open 档 register → `*`、无 cookie。
    #[test]
    fn cors_open_register_star_no_creds() {
        let d = cors_decision(CorsClass::OpenRegister, None, &[]);
        match d {
            CorsDecision::Allow {
                allow_origin,
                allow_credentials,
            } => {
                assert_eq!(allow_origin, "*");
                assert!(!allow_credentials, "MUST NOT 与 Allow-Credentials 并用");
            }
            _ => panic!("open register 应放行 *"),
        }
    }

    // C10.10:带凭证端点 + origin ∈ allowlist → 回显 origin + credentials,不用 `*`。
    #[test]
    fn cors_credentialed_allowlisted() {
        let allow = vec!["https://app.example.com".to_string()];
        let d = cors_decision(
            CorsClass::Credentialed,
            Some("https://app.example.com"),
            &allow,
        );
        assert_eq!(
            d,
            CorsDecision::Allow {
                allow_origin: "https://app.example.com".into(),
                allow_credentials: true
            }
        );
    }

    // C10.10:带凭证端点回显具体 origin(绝不 `*`)。
    #[test]
    fn cors_credentialed_never_star() {
        let allow = vec!["https://app.example.com".to_string()];
        if let CorsDecision::Allow { allow_origin, .. } = cors_decision(
            CorsClass::Credentialed,
            Some("https://app.example.com"),
            &allow,
        ) {
            assert_ne!(allow_origin, "*", "带凭证端点 MUST NOT 用 *");
        } else {
            panic!("应放行");
        }
    }

    // C10.10:带凭证端点 + origin ∉ allowlist → 拒。
    #[test]
    fn cors_credentialed_not_allowlisted_denied() {
        let allow = vec!["https://app.example.com".to_string()];
        assert_eq!(
            cors_decision(
                CorsClass::Credentialed,
                Some("https://evil.example"),
                &allow
            ),
            CorsDecision::Deny
        );
    }

    // C10.10:带凭证端点 + 无 origin → 拒(不能默认放行)。
    #[test]
    fn cors_credentialed_no_origin_denied() {
        assert_eq!(
            cors_decision(CorsClass::Credentialed, None, &[]),
            CorsDecision::Deny
        );
    }
}
