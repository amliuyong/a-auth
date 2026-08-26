//! C9.2 / C9.1 — magic-link ↔ session 绑定(防 login-CSRF)+ 短命一次性。
//!
//! - **C9.2 login-CSRF 防护**:magic-link MUST 与**发起浏览器会话**绑定(link ↔ session nonce)。
//!   发起登录时生成随机 `session_nonce`、存入发起浏览器的 AS 会话 cookie 并带入 magic-link;
//!   打开时校验"链接携带的 session_nonce"与"打开浏览器 cookie 里的 session_nonce"一致——
//!   异浏览器(cookie 不同)打开 MUST 被拒,防诱导受害者点链接登进攻击者账号。
//! - **C9.1 短命一次性**:magic-link MUST 短命(≤10min,§2.1)且一次性(消费即作废、不可重放);
//!   过期判定走 `expires_at` 读写校验(fail-closed,复用 `infra_core::lifecycle`),不靠 TTL 删除。
//!
//! 本模块纯逻辑、零 AWS 依赖:HMAC 密钥、随机 nonce、`now`、"是否已消费"的持久状态均由上层注入
//! (不读墙上时钟、不自取随机、不落库)。login-CSRF 的 nonce 比对用常量时间(防时序侧信道)。
//! 决策真相源:docs/DESIGN §7·§8(login-CSRF)·§2.1(短命一次性);docs/CONFORMANCE C9.1·C9.2。

use agent_auth_infra_core::lifecycle::shortlived_is_expired;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// magic-link 的绑定材料(随链接下发、也回存服务端签发记录)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagicLink {
    /// 一次性标记的键(服务端据此记"是否已消费")。
    pub link_id: String,
    /// 绑定到发起浏览器会话的 nonce(同时写入发起浏览器 cookie)。
    pub session_nonce: String,
    /// 过期时刻(Unix 秒)。MUST ≤ 签发时刻 + 10min。
    pub expires_at: i64,
}

/// magic-link 有效期上限(秒):§2.1 短命项 ≤ 10min。
/// 这是 **authn 层的签发策略常量**(供上层算 `expires_at = issued_at + TTL` 与 `validate_ttl` 引用),
/// **不是** infra/协议层的共享常量(`infra_core::lifecycle` 只按传入 `expires_at` 判过期、不管业务 TTL 上限)。
/// 调整此值只需改此处;若跨层引用它,应意识到它随 authn 策略而非协议契约变动。
pub const MAX_MAGIC_LINK_TTL_SECS: i64 = 600;

/// 对 magic-link 的绑定材料计算完整性 tag(HMAC),防 URL 参数被篡改。
/// tag = base64url(HMAC(secret, link_id‖":"‖session_nonce‖":"‖expires_at))。
pub fn compute_tag(secret: &[u8], link: &MagicLink) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(link.link_id.as_bytes());
    mac.update(b":");
    mac.update(link.session_nonce.as_bytes());
    mac.update(b":");
    mac.update(link.expires_at.to_string().as_bytes());
    b64url(&mac.finalize().into_bytes())
}

/// 校验 magic-link 打开请求的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenError {
    /// 完整性 tag 不匹配(链接被篡改 / 非本系统签发)。
    BadTag,
    /// 链接已过期(> expires_at,fail-closed)。
    Expired,
    /// 已被消费过(一次性,二次打开)——重放。
    AlreadyUsed,
    /// login-CSRF:链接携带的 session_nonce 与打开浏览器 cookie 的 session_nonce 不一致。
    SessionMismatch,
}

/// 签发校验:确保将要签发的 magic-link 有效期不超过 10min 上限(C9.1)。
/// `issued_at`/`expires_at` = Unix 秒。超限即拒(防误签长效 link)。
pub fn validate_ttl(issued_at: i64, expires_at: i64) -> Result<(), OpenError> {
    // 复用短命项语义:expires_at 必须在 issued_at 之后、且不超过 10min。
    if expires_at <= issued_at || expires_at.saturating_sub(issued_at) > MAX_MAGIC_LINK_TTL_SECS {
        // 用 Expired 表达"时效非法";签发路径据此拒签。
        return Err(OpenError::Expired);
    }
    Ok(())
}

/// 打开 magic-link 的完整校验(C9.1 短命一次性 + C9.2 login-CSRF),顺序固定、fail-closed:
/// 1. 完整性 tag(防篡改)→ 2. 过期(fail-closed)→ 3. 一次性(已消费即拒)→ 4. session 绑定。
///
/// - `secret`:HMAC 密钥;`link`:链接携带并回解析出的绑定材料;`presented_tag`:链接上的 tag。
/// - `now`:当前 Unix 秒。
/// - `already_used`:该 `link_id` 是否已被消费(上层从库读)。
/// - `cookie_session_nonce`:打开请求所在浏览器 cookie 里的 session_nonce(`None` = 无会话 cookie)。
///
/// 全部通过返回 `Ok(())`,上层随后 MUST 原子标记该 link_id 已消费(一次性)再建立登录态。
pub fn open(
    secret: &[u8],
    link: &MagicLink,
    presented_tag: &str,
    now: i64,
    already_used: bool,
    cookie_session_nonce: Option<&str>,
) -> Result<(), OpenError> {
    // 1. 完整性:tag 必须匹配(常量时间比较)。
    let expected = compute_tag(secret, link);
    if presented_tag.is_empty() || !bool::from(expected.as_bytes().ct_eq(presented_tag.as_bytes()))
    {
        return Err(OpenError::BadTag);
    }
    // 2. 过期:fail-closed 精确判过期(复用 infra-core 短命项判定,不套时钟宽限)。
    if shortlived_is_expired(now, link.expires_at) {
        return Err(OpenError::Expired);
    }
    // 3. 一次性:已消费即拒(防重放)。
    if already_used {
        return Err(OpenError::AlreadyUsed);
    }
    // 4. login-CSRF:链接绑定的 session_nonce 必须与打开浏览器 cookie 的一致(常量时间比较)。
    // 两侧都必须非空:空 cookie 已被 `!cookie_nonce.is_empty()` 拦(短路在 ct_eq 前);
    // 额外要求 `!link.session_nonce.is_empty()` 作纵深防御——即便签发侧误发空 nonce 的 link,
    // 也不会与恰好为空的 cookie 比中(杜绝 "两空相等" 的理论绕过口)。
    match cookie_session_nonce {
        Some(cookie_nonce)
            if !cookie_nonce.is_empty()
                && !link.session_nonce.is_empty()
                && bool::from(link.session_nonce.as_bytes().ct_eq(cookie_nonce.as_bytes())) =>
        {
            Ok(())
        }
        _ => Err(OpenError::SessionMismatch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"authn-magic-link-secret";

    fn link(exp: i64) -> MagicLink {
        MagicLink {
            link_id: "lid-123".into(),
            session_nonce: "sess-nonce-abc".into(),
            expires_at: exp,
        }
    }

    // 正常路径:tag 对、未过期、未用、同会话 → 通过。
    #[test]
    fn open_happy_path() {
        let l = link(2000);
        let tag = compute_tag(SECRET, &l);
        assert_eq!(
            open(SECRET, &l, &tag, 1000, false, Some("sess-nonce-abc")),
            Ok(())
        );
    }

    // C9.2:异浏览器(cookie nonce 不同)打开 → SessionMismatch。
    #[test]
    fn different_browser_rejected() {
        let l = link(2000);
        let tag = compute_tag(SECRET, &l);
        assert_eq!(
            open(SECRET, &l, &tag, 1000, false, Some("OTHER-browser-nonce")),
            Err(OpenError::SessionMismatch)
        );
    }

    // C9.2:无会话 cookie(直接点链接、无发起会话)→ SessionMismatch。
    #[test]
    fn no_cookie_rejected() {
        let l = link(2000);
        let tag = compute_tag(SECRET, &l);
        assert_eq!(
            open(SECRET, &l, &tag, 1000, false, None),
            Err(OpenError::SessionMismatch)
        );
    }

    // C9.1:超过有效期打开 → Expired(fail-closed)。
    #[test]
    fn expired_rejected() {
        let l = link(1000);
        let tag = compute_tag(SECRET, &l);
        // now=1000 == expires_at → 已过期(短命项 fail-closed 精确判定)。
        assert_eq!(
            open(SECRET, &l, &tag, 1000, false, Some("sess-nonce-abc")),
            Err(OpenError::Expired)
        );
    }

    // C9.1:已消费的 link 二次打开 → AlreadyUsed(不可重放)。
    #[test]
    fn already_used_rejected() {
        let l = link(2000);
        let tag = compute_tag(SECRET, &l);
        assert_eq!(
            open(SECRET, &l, &tag, 1000, true, Some("sess-nonce-abc")),
            Err(OpenError::AlreadyUsed)
        );
    }

    // 篡改:改了 expires_at 但 tag 没变 → BadTag(完整性防篡改)。
    #[test]
    fn tampered_expiry_bad_tag() {
        let l = link(2000);
        let tag = compute_tag(SECRET, &l);
        let mut tampered = l.clone();
        tampered.expires_at = 9_999_999; // 想延长有效期
        assert_eq!(
            open(SECRET, &tampered, &tag, 1000, false, Some("sess-nonce-abc")),
            Err(OpenError::BadTag)
        );
    }

    // 篡改:换了 session_nonce 想绕过绑定 → tag 也不匹配(BadTag),tag 覆盖 nonce。
    #[test]
    fn tampered_nonce_bad_tag() {
        let l = link(2000);
        let tag = compute_tag(SECRET, &l);
        let mut tampered = l.clone();
        tampered.session_nonce = "attacker-nonce".into();
        // 用篡改后的 nonce 当 cookie 也无济于事:tag 是按原 nonce 算的,先被 BadTag 拦。
        assert_eq!(
            open(SECRET, &tampered, &tag, 1000, false, Some("attacker-nonce")),
            Err(OpenError::BadTag)
        );
    }

    // 空 tag → BadTag。
    #[test]
    fn empty_tag_rejected() {
        let l = link(2000);
        assert_eq!(
            open(SECRET, &l, "", 1000, false, Some("sess-nonce-abc")),
            Err(OpenError::BadTag)
        );
    }

    // 校验顺序:过期优先于一次性——过期且已用应报 Expired(先到的检查),稳定归因。
    #[test]
    fn check_order_expiry_before_used() {
        let l = link(1000);
        let tag = compute_tag(SECRET, &l);
        assert_eq!(
            open(SECRET, &l, &tag, 5000, true, Some("sess-nonce-abc")),
            Err(OpenError::Expired)
        );
    }

    // C9.1:签发时效校验——正常 10min 内通过。
    #[test]
    fn validate_ttl_ok() {
        assert_eq!(validate_ttl(1000, 1000 + 600), Ok(()));
        assert_eq!(validate_ttl(1000, 1000 + 300), Ok(()));
    }

    // C9.1:签发时效超过 10min → 拒(防误签长效 link)。
    #[test]
    fn validate_ttl_too_long_rejected() {
        assert_eq!(validate_ttl(1000, 1000 + 601), Err(OpenError::Expired));
    }

    // 签发时效非正(expires <= issued)→ 拒。
    #[test]
    fn validate_ttl_non_positive_rejected() {
        assert_eq!(validate_ttl(1000, 1000), Err(OpenError::Expired));
        assert_eq!(validate_ttl(1000, 999), Err(OpenError::Expired));
    }

    // C9.2 纵深防御:链接 session_nonce 为空 + cookie 也为空 → 仍 SessionMismatch(不"两空相等"绕过)。
    // 用与空 nonce 匹配的 tag,确保不是被 BadTag 拦、而是被 session 绑定拦。
    #[test]
    fn empty_session_nonce_not_bypassed() {
        let l = MagicLink {
            link_id: "lid-x".into(),
            session_nonce: "".into(), // 签发侧误发空 nonce
            expires_at: 2000,
        };
        let tag = compute_tag(SECRET, &l); // tag 对空 nonce 合法
                                           // 空 cookie:被 !cookie_nonce.is_empty() 短路;空 link nonce:被新增守卫拦。
        assert_eq!(
            open(SECRET, &l, &tag, 1000, false, Some("")),
            Err(OpenError::SessionMismatch)
        );
        assert_eq!(
            open(SECRET, &l, &tag, 1000, false, None),
            Err(OpenError::SessionMismatch)
        );
    }

    // 校验顺序(verify-MAC-before-use):tag **有效**的过期 link → 报 Expired(非 BadTag),
    // 证明 tag-first 顺序不会把合法签发的过期 link 误报成篡改;过期在 tag 通过后被正确拦。
    #[test]
    fn valid_tag_expired_reports_expired_not_badtag() {
        let l = link(1000);
        let tag = compute_tag(SECRET, &l); // 有效 tag
        assert_eq!(
            open(SECRET, &l, &tag, 5000, false, Some("sess-nonce-abc")),
            Err(OpenError::Expired),
            "tag 有效的过期 link 应报 Expired,tag-first 顺序不会误报 BadTag"
        );
    }

    // tag 确定性:同输入同 tag,不同 link_id 不同 tag。
    #[test]
    fn tag_deterministic_and_bound() {
        let a = compute_tag(SECRET, &link(2000));
        let b = compute_tag(SECRET, &link(2000));
        assert_eq!(a, b);
        let mut other = link(2000);
        other.link_id = "different".into();
        assert_ne!(a, compute_tag(SECRET, &other));
    }
}
