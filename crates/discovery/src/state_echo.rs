//! C1.7 — 授权响应原样回填 `state`(对称于 `nonce` 的 MUST echo,见 DESIGN §8 CSRF)。
//!
//! AS 不生成、不校验 `state` 语义(那是客户端侧 CSRF 职责),但一旦客户端传入 `state`,
//! 授权响应 **MUST** 逐字节原样 echo;客户端未传则响应 **MUST NOT** 出现 `state`。

/// 给定请求传入的 `state`(None = 未传),返回授权响应应携带的 `state`。
/// 逐字节透传:不截断、不重编码、不改写。
pub fn echo_state(request_state: Option<&str>) -> Option<String> {
    request_state.map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // C1.7 Scenario:带 state 逐字节相等。
    #[test]
    fn echoes_state_byte_for_byte() {
        let s = "aB3-_~.高熵值%20+&=";
        assert_eq!(echo_state(Some(s)).as_deref(), Some(s));
    }

    // C1.7 Scenario:不传 state 则响应也无。
    #[test]
    fn no_state_when_absent() {
        assert_eq!(echo_state(None), None);
    }

    // 空字符串 state 也原样回(客户端传了空串≠没传;这里如实透传)。
    #[test]
    fn empty_string_preserved() {
        assert_eq!(echo_state(Some("")).as_deref(), Some(""));
    }
}
