//! device flow `user_code` 字符集/规范化(spec 013 C7b.4;RFC 8628 §6.1)。纯逻辑。
//!
//! `user_code` 是用户在另一设备手输的短码,MUST 用**防混淆字符集**(去掉易混的 0/O/1/I 等)。
//! 规范化:输入时去空白/连字符、转大写,便于"WDJB-MJHT"这类带分隔展示的码匹配。生成(随机)属 IO 层。

/// RFC 8628 §6.1 推荐字符集:base20,去掉易混淆的 `0 1 O I` 等(只留清晰可辨大写字母)。
pub const USER_CODE_CHARSET: &str = "BCDFGHJKLMNPQRSTVWXZ";

/// 规范化用户输入的 user_code:去空白与连字符、转大写(展示可带 `WDJB-MJHT`,匹配时归一)。
/// **仅 ASCII 大写**(评审 L2:`to_uppercase()` 对 `ß`→`SS` 会扩展字符、把非法输入洗成合法集内字符;
/// 用 `to_ascii_uppercase` 不扩展,非 ASCII 字符原样保留 → 后续 charset 校验会拒)。
pub fn canonicalize_user_code(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// 校验规范化后的 user_code 是否全在允许字符集内(防注入/非法字符;长度由调用方另定)。
pub fn is_valid_user_code_charset(canonical: &str) -> bool {
    !canonical.is_empty() && canonical.chars().all(|c| USER_CODE_CHARSET.contains(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charset_excludes_confusable() {
        for c in ['0', '1', 'O', 'I', 'U'] {
            assert!(!USER_CODE_CHARSET.contains(c), "字符集不应含易混字符 {c}");
        }
    }

    #[test]
    fn canonicalize_strips_and_uppercases() {
        assert_eq!(canonicalize_user_code("wdjb-mjht"), "WDJBMJHT");
        assert_eq!(canonicalize_user_code(" WDJB MJHT "), "WDJBMJHT");
        assert_eq!(canonicalize_user_code("WDJB-MJHT"), "WDJBMJHT");
    }

    #[test]
    fn valid_charset_check() {
        assert!(is_valid_user_code_charset("WDJBMJHT"));
        // 含易混字符(规范化后仍非法)→ false。
        assert!(!is_valid_user_code_charset("WDJB0MJHT")); // 含 0
        assert!(!is_valid_user_code_charset("")); // 空
        assert!(!is_valid_user_code_charset("wdjb")); // 小写(应先 canonicalize)
    }

    #[test]
    fn canonicalize_then_validate_roundtrip() {
        let c = canonicalize_user_code("wdjb-mjht");
        assert!(is_valid_user_code_charset(&c));
    }

    #[test]
    fn non_ascii_not_expanded_to_valid() {
        // 评审 L2:ß 不得被 to_uppercase 洗成 SS(合法集内);ASCII-only 大写 → 原样非 ASCII → charset 拒。
        let c = canonicalize_user_code("ßdjb");
        assert!(
            !is_valid_user_code_charset(&c),
            "非 ASCII 输入不得规范化成合法码: {c:?}"
        );
    }
}
