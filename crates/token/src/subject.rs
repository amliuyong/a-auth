//! pairwise / sector `sub` 派生(spec 001 C2.11;DESIGN §2.8 唯一权威源的实现)。纯逻辑,零 IO。
//!
//! 公式(§2.8):`sub = base64url(HMAC-SHA256(server_secret, "sub:v1" ‖ len(user_id) ‖ user_id ‖ len(sector) ‖ sector))`
//! ——可复现、单向不可逆推 `user_id`(用户级关联靠内部 `user_id`,非 `sub`)。
//! **域前缀 `"sub:v1"`**:server_secret 复用于 magic-link tag / CSRF / reg_token,加域前缀做**域分离**
//! (防跨用途的 HMAC 输出被混用);`v1` 预留派生方案版本。**长度前缀框定**(各字段 8 字节大端长度前缀)
//! 消除 `user_id‖sector` 的拼接歧义——即便 `user_id`/`sector` 含任意字节(含 0x1f 等控制字符)也无碰撞
//! (评审 codex/Kiro:比单一分隔符更强,不依赖上游校验输入)。
//!
//! **sector 键两路径**(§2.8):
//! - MCP 路径(access token,`aud`=某 RS):sector = **resource 标识**(每 RS 不同 `sub`,不可跨 RS 关联)。
//! - 纯 OIDC / `/userinfo` 路径(id_token 及 aud=`<issuer>/userinfo` 的 token):sector = **OIDC sector
//!   identifier**(客户端 redirect_uri 同 host → 该 host;多 host 须 DCR `sector_identifier_uri`)。
//!   ⚠️ 同一 client 的 id_token 与其 `/userinfo` token MUST 用**同一 OIDC sector**,故两者 `sub` 一致(C2.11)。
//!
//! **仅 `sub_type=user` 做 pairwise**;2LO(`sub_type=agent/service`)的 `sub`=client_id、不派生(§2 line 222)。
//! public 形态:`sub` 直接 = `user_id`(跨 RS 可关联,首方 RS 场景)。

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// 部署/租户的 subject 形态(与 discovery `subject_types_supported` 对齐)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectMode {
    /// public:`sub` = `user_id`,跨 RS 可关联(自部署首方 RS 默认)。
    Public,
    /// pairwise:`sub` = HMAC 派生、随 sector 变(SaaS 防跨 RS 关联,默认)。
    Pairwise,
}

/// pairwise `sub` 派生(§2.8):`base64url(HMAC-SHA256(secret, "sub:v1"‖len‖user_id‖len‖sector))`。
/// 直接暴露供需要显式 sector 的场景;一般走 `derive_user_sub`(按 mode 分派)。
pub fn pairwise_sub(server_secret: &[u8], user_id: &str, sector: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(server_secret).expect("HMAC any key len");
    // 域分离(与 magic-link tag / CSRF / reg_token 隔离)+ 方案版本 v1。
    mac.update(b"sub:v1");
    // 长度前缀框定:len(user_id)‖user_id‖len(sector)‖sector,任意字节内容都无拼接歧义。
    mac.update(&(user_id.len() as u64).to_be_bytes());
    mac.update(user_id.as_bytes());
    mac.update(&(sector.len() as u64).to_be_bytes());
    mac.update(sector.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

/// 按形态派生 **user 主体** 的 `sub`(sub_type=user 专用):
/// - Public → 原样 `user_id`;
/// - Pairwise → `pairwise_sub(secret, user_id, sector)`。
///
/// `sector` 由调用方按路径给:MCP access = resource 标识;OIDC id_token / userinfo = OIDC sector identifier。
pub fn derive_user_sub(
    mode: SubjectMode,
    server_secret: &[u8],
    user_id: &str,
    sector: &str,
) -> String {
    match mode {
        SubjectMode::Public => user_id.to_string(),
        SubjectMode::Pairwise => pairwise_sub(server_secret, user_id, sector),
    }
}

/// OIDC sector identifier(§2.8 纯 OIDC 路径,P0 中间态):客户端所有 redirect_uri **同 host** → 该 host;
/// **多 host 或含无法归一 host 的 URI**(如自定义 scheme 原生回调 `com.example.app:/cb`)且未配
/// `sector_identifier_uri` → None(上层据此拒注册 / 拒签,避免 `sub` 不确定)。
/// **fail-closed**:任一 redirect_uri 取不出 host → 返回 None(不能只按能归一的那部分猜一个 sector)。
/// `sector_identifier_uri` 存在时上层直接用其 host 集(此处只处理 P0 的 redirect_uri host 归一)。
pub fn oidc_sector_from_redirect_hosts(redirect_uris: &[String]) -> Option<String> {
    if redirect_uris.is_empty() {
        return None;
    }
    let mut agreed: Option<String> = None;
    for uri in redirect_uris {
        // fail-closed:任一 URI 无法归一 host(自定义 scheme / 非法)→ 整体 None。
        let h = host_of(uri)?;
        match &agreed {
            None => agreed = Some(h),
            Some(prev) if *prev == h => {}
            Some(_) => return None, // 出现不同 host → 须 sector_identifier_uri
        }
    }
    agreed
}

/// 取 URL 的 host(小写;去 scheme、port、path;正确处理 IPv6 字面量 `[::1]`)。
/// 极简解析(redirect_uri 已在 client crate canonicalize);无 `scheme://` 权威部分(如自定义
/// scheme `com.example.app:/cb`)→ None。
fn host_of(url: &str) -> Option<String> {
    let after_scheme = url.split("://").nth(1)?;
    let authority = after_scheme.split(['/', '?', '#']).next()?;
    // 去 userinfo@ 段。
    let host = authority.split('@').next_back()?;
    // IPv6 字面量:`[::1]` / `[::1]:8443` → 取方括号内(含括号,保持与 URL host 一致的可比形式)。
    let host = if let Some(rest) = host.strip_prefix('[') {
        let inside = rest.split(']').next()?; // 括号内的地址
        return (!inside.is_empty()).then(|| format!("[{}]", inside.to_lowercase()));
    } else {
        host.split(':').next()? // 普通 host:去 port
    };
    (!host.is_empty()).then(|| host.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"test-server-secret";

    #[test]
    fn pairwise_reproducible_and_sector_scoped() {
        let a = pairwise_sub(SECRET, "user:alice", "https://rs1.example.com");
        let a2 = pairwise_sub(SECRET, "user:alice", "https://rs1.example.com");
        assert_eq!(a, a2, "同 (user,sector) 可复现");
        // 不同 sector → 不同 sub(不可跨 RS 关联)。
        let b = pairwise_sub(SECRET, "user:alice", "https://rs2.example.com");
        assert_ne!(a, b, "不同 sector 得不同 sub");
        // 不同 user 同 sector → 不同 sub。
        let c = pairwise_sub(SECRET, "user:bob", "https://rs1.example.com");
        assert_ne!(a, c);
    }

    #[test]
    fn not_reversible_and_not_raw_user_id() {
        let s = pairwise_sub(SECRET, "user:alice", "sec");
        assert!(!s.contains("alice"), "sub 不得含 user_id 明文");
        assert_ne!(s, "user:alice");
    }

    #[test]
    fn domain_separation_from_plain_hmac() {
        // 加了 "sub:v1" 域前缀 → 与不加前缀的裸 HMAC 不同(防跨用途混用)。
        let mut mac = HmacSha256::new_from_slice(SECRET).unwrap();
        mac.update(b"user:alice");
        mac.update(b"sec");
        let plain = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        assert_ne!(pairwise_sub(SECRET, "user:alice", "sec"), plain);
    }

    #[test]
    fn length_framing_prevents_collision() {
        // ("ab","c") 与 ("a","bc") 不得撞(长度前缀框定)。
        assert_ne!(
            pairwise_sub(SECRET, "ab", "c"),
            pairwise_sub(SECRET, "a", "bc")
        );
        // 即便含 0x1f 控制字符也无歧义(不依赖上游校验)。
        assert_ne!(
            pairwise_sub(SECRET, "a\u{1f}b", "c"),
            pairwise_sub(SECRET, "a", "b\u{1f}c")
        );
        // 空串边界:("", "x") 与 ("x", "") 不得撞。
        assert_ne!(pairwise_sub(SECRET, "", "x"), pairwise_sub(SECRET, "x", ""));
    }

    #[test]
    fn public_mode_returns_user_id() {
        assert_eq!(
            derive_user_sub(SubjectMode::Public, SECRET, "user:alice", "sec"),
            "user:alice"
        );
    }

    #[test]
    fn pairwise_mode_derives() {
        let s = derive_user_sub(SubjectMode::Pairwise, SECRET, "user:alice", "sec");
        assert_eq!(s, pairwise_sub(SECRET, "user:alice", "sec"));
        assert_ne!(s, "user:alice");
    }

    #[test]
    fn oidc_sector_single_host() {
        let uris = vec![
            "https://app.example.com/cb".to_string(),
            "https://app.example.com/cb2".to_string(),
        ];
        assert_eq!(
            oidc_sector_from_redirect_hosts(&uris).as_deref(),
            Some("app.example.com")
        );
    }

    #[test]
    fn oidc_sector_multi_host_none() {
        let uris = vec![
            "https://a.example.com/cb".to_string(),
            "https://b.example.com/cb".to_string(),
        ];
        assert_eq!(
            oidc_sector_from_redirect_hosts(&uris),
            None,
            "多 host 须 sector_identifier_uri"
        );
    }

    #[test]
    fn host_of_variants() {
        assert_eq!(
            host_of("https://App.Example.com:8443/cb?x=1"),
            Some("app.example.com".into())
        );
        assert_eq!(host_of("http://127.0.0.1/cb"), Some("127.0.0.1".into()));
        assert_eq!(host_of("not-a-url"), None);
        // 自定义 scheme 原生回调(无 `://` 权威)→ None(fail-closed)。
        assert_eq!(host_of("com.example.app:/oauth/cb"), None);
        // 去 userinfo@。
        assert_eq!(
            host_of("https://user:pw@host.example.com/cb"),
            Some("host.example.com".into())
        );
    }

    #[test]
    fn host_of_ipv6_literal() {
        // IPv6 字面量:内部冒号不得被当端口分隔(F3/codex#2)。
        assert_eq!(
            host_of("https://[2001:db8::1]/cb"),
            Some("[2001:db8::1]".into())
        );
        assert_eq!(host_of("https://[::1]:8443/cb"), Some("[::1]".into()));
        // 不同 IPv6 host 必须判为不同(不再坍缩成 "[")。
        assert_ne!(
            host_of("https://[2001:db8::1]/cb"),
            host_of("https://[2001:db8::2]/cb")
        );
    }

    #[test]
    fn ipv6_multi_host_returns_none() {
        // 两个不同 IPv6 host → None(多 host 拒绝不被旁路)。
        let uris = vec![
            "https://[2001:db8::1]/cb".to_string(),
            "https://[2001:db8::2]/cb".to_string(),
        ];
        assert_eq!(oidc_sector_from_redirect_hosts(&uris), None);
    }

    #[test]
    fn custom_scheme_uri_fails_closed() {
        // 含无法归一 host 的自定义 scheme → 整体 None(不按能归一的那个猜 sector,F4)。
        let uris = vec![
            "https://app.example.com/cb".to_string(),
            "com.example.app:/oauth/cb".to_string(),
        ];
        assert_eq!(
            oidc_sector_from_redirect_hosts(&uris),
            None,
            "任一 URI 无法归一 host → fail-closed None"
        );
    }

    #[test]
    fn empty_redirect_uris_none() {
        assert_eq!(oidc_sector_from_redirect_hosts(&[]), None);
    }
}
