//! login_hint 三型归一(spec 013 C7b.1)——**分类 + 键推导的纯逻辑意图**。
//!
//! 实际验签(id_token_hint)/ 解密(login_hint_token)/ 注册查库(login_hint)属 IO 层;此处只定义
//! 三型分类 + 「归一后节流键」的构造规则(键 = `tenant_id + user_id`,**不用 raw hint**,防换标识绕过)。

/// 三种用户标识类型(CIBA `/bc-authorize` 三选一,C7b.1)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HintKind {
    /// `login_hint`:email/phone/opaque——须校验属本租户注册用户。
    LoginHint,
    /// `login_hint_token`:AS 自签 opaque——验签/解密提取 user_id。
    LoginHintToken,
    /// `id_token_hint`:OIDC id_token——验签 + sub→user_id(经 jti 映射,复用 011 C7.8)。
    IdTokenHint,
}

impl HintKind {
    /// 从三个可选参数判定用了哪种(三选一;0 个或 >1 个都非法 → None)。
    pub fn classify(
        login_hint: Option<&str>,
        login_hint_token: Option<&str>,
        id_token_hint: Option<&str>,
    ) -> Option<HintKind> {
        let present: Vec<HintKind> = [
            login_hint
                .filter(|s| !s.is_empty())
                .map(|_| HintKind::LoginHint),
            login_hint_token
                .filter(|s| !s.is_empty())
                .map(|_| HintKind::LoginHintToken),
            id_token_hint
                .filter(|s| !s.is_empty())
                .map(|_| HintKind::IdTokenHint),
        ]
        .into_iter()
        .flatten()
        .collect();
        // 严格三选一:恰好一个。
        match present.as_slice() {
            [k] => Some(*k),
            _ => None,
        }
    }
}

/// 归一后的节流/推送键:`tenant_id + user_id`(**MUST NOT** 用 raw hint 串,防换标识绕过 per-user 冷却)。
/// `user_id` 由 IO 层按 HintKind 归一解析得到(校注册 / 验签 / jti 映射)后传入。
///
/// **长度前缀编码(评审 M2)**:`"{tenant_len}:{tenant}{user_len}:{user}"`——避免分隔符注入导致键碰撞
/// (如 `("t1","u\x1fv")` 与 `("t1\x1fu","v")` 用裸分隔符会撞同键 → 互相限流/绕过冷却)。
pub fn normalize_key(tenant_id: &str, user_id: &str) -> String {
    format!("{}:{tenant_id}{}:{user_id}", tenant_id.len(), user_id.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_exactly_one() {
        assert_eq!(
            HintKind::classify(Some("a@x"), None, None),
            Some(HintKind::LoginHint)
        );
        assert_eq!(
            HintKind::classify(None, Some("tok"), None),
            Some(HintKind::LoginHintToken)
        );
        assert_eq!(
            HintKind::classify(None, None, Some("jwt")),
            Some(HintKind::IdTokenHint)
        );
    }

    #[test]
    fn classify_none_or_multiple_rejected() {
        // 一个都不带 → None(C7b.1 拒)。
        assert_eq!(HintKind::classify(None, None, None), None);
        assert_eq!(HintKind::classify(Some(""), None, None), None); // 空串不算
                                                                    // 多于一个 → None(歧义,拒)。
        assert_eq!(HintKind::classify(Some("a"), Some("b"), None), None);
        assert_eq!(HintKind::classify(Some("a"), None, Some("c")), None);
    }

    #[test]
    fn key_uses_tenant_and_user_not_raw_hint() {
        // 同一 user_id、不同原始 hint(email vs 从 id_token 提取)→ 同键(不能换标识绕过)。
        let k1 = normalize_key("t1", "user:alice");
        let k2 = normalize_key("t1", "user:alice");
        assert_eq!(k1, k2);
        // 不同 tenant 隔离。
        assert_ne!(
            normalize_key("t1", "user:alice"),
            normalize_key("t2", "user:alice")
        );
        // 不同 user 不同键。
        assert_ne!(
            normalize_key("t1", "user:alice"),
            normalize_key("t1", "user:bob")
        );
    }

    #[test]
    fn key_no_separator_injection_collision() {
        // 评审 M2:含控制字符/分隔符的 id 不得撞键(长度前缀编码防歧义)。
        assert_ne!(
            normalize_key("t1", "u\u{1f}v"),
            normalize_key("t1\u{1f}u", "v")
        );
        assert_ne!(normalize_key("a", "bc"), normalize_key("ab", "c"));
        assert_ne!(normalize_key("t", "1:x"), normalize_key("t1", "x")); // 冒号也不撞
    }
}
