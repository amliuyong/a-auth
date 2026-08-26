pub(crate) fn normalize_email(raw: &str) -> String {
    raw.trim().to_lowercase()
}

pub(crate) fn is_valid_email(email: &str) -> bool {
    !email.is_empty()
        && email.matches('@').count() == 1
        && !email.starts_with('@')
        && !email.ends_with('@')
        && !email.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
}

pub(crate) fn is_password_capable_user_id(user_id: &str) -> bool {
    user_id.starts_with("user:") && !user_id.starts_with("user:fed:")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_and_validates_local_email_identifiers() {
        assert_eq!(normalize_email(" Alice@Example.COM "), "alice@example.com");
        assert!(is_valid_email("alice@example.com"));
        for invalid in [
            "",
            "alice",
            "@example.com",
            "alice@",
            "a@@example.com",
            "a\u{1f}@x",
        ] {
            assert!(!is_valid_email(invalid), "{invalid:?}");
        }
        assert!(is_password_capable_user_id("user:alice@example.com"));
        assert!(is_password_capable_user_id("user:scim:opaque"));
        assert!(!is_password_capable_user_id("user:fed:alice"));
        assert!(!is_password_capable_user_id("agent:alice@example.com"));
    }
}
