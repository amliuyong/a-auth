//! C4.7 — 安全降级判定(字段级单调性方向表 + 未知字段 fail-safe)。
//!
//! 任何朝"更弱"方向的受管字段变更 = 降级,MUST 带 `confirm_downgrade:true` 才生效。
//! 🔴 fail-safe:方向表**未定义**或无法归类单调方向的字段变更,默认按降级处理(未知即降级),
//! MUST NOT 默认放行——防"可扩展清单"成为绕过口。收紧(朝更强方向)不是降级、无需 flag。
//!
//! 决策真相源:docs/DESIGN §3.2、公理 7、docs/CONFORMANCE C4.7。

/// 受管字段的一次变更(旧值 → 新值),值用规范化字符串表示。
#[derive(Debug, Clone)]
pub struct FieldChange {
    pub field: String,
    pub old: String,
    pub new: String,
}

/// 单次变更的判定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeVerdict {
    /// 朝更弱方向 = 降级(需 confirm_downgrade)。
    Downgrade,
    /// 朝更强/中性方向 = 收紧或无关(无需 flag)。
    NotDowngrade,
}

/// 把某字段的取值映射到**安全强度序**(数字越大越强)。返回 None = 该取值未知/不可归类。
fn strength(field: &str, value: &str) -> Option<i32> {
    match field {
        // 越强 → 越大。private_key_jwt > client_secret_* > none。
        "token_endpoint_auth_method" => match value {
            "private_key_jwt" => Some(3),
            "client_secret_basic" | "client_secret_post" => Some(2),
            "none" => Some(1),
            _ => None,
        },
        // 开 > 关。
        "refresh_rotation" => match value {
            "on" | "true" => Some(2),
            "off" | "false" => Some(1),
            _ => None,
        },
        // exact/loopback(更严) > prefix/通配(更松)。
        "redirect_mode" => match value {
            "exact" | "loopback" => Some(2),
            "prefix" | "wildcard" => Some(1),
            _ => None,
        },
        // 强制 > 可选 > 无。
        "dpop" => match value {
            "required" => Some(3),
            "optional" => Some(2),
            "none" | "off" => Some(1),
            _ => None,
        },
        _ => None, // 未知字段:交给 fail-safe。
    }
}

/// 判定一次字段变更是否降级(C4.7)。
pub fn classify(change: &FieldChange) -> ChangeVerdict {
    // token validity:数值字段,延长(增大)= 降级。单独处理(非枚举)。
    if change.field == "token_validity_secs" {
        return match (change.old.parse::<u64>(), change.new.parse::<u64>()) {
            (Ok(o), Ok(n)) if n > o => ChangeVerdict::Downgrade, // 延长 = 降级
            (Ok(_), Ok(_)) => ChangeVerdict::NotDowngrade,       // 不变/缩短
            _ => ChangeVerdict::Downgrade,                       // 解析不了 → fail-safe
        };
    }

    match (
        strength(&change.field, &change.old),
        strength(&change.field, &change.new),
    ) {
        (Some(o), Some(n)) => {
            if n < o {
                ChangeVerdict::Downgrade // 变弱
            } else {
                ChangeVerdict::NotDowngrade // 变强或不变
            }
        }
        // 🔴 fail-safe:任一侧取值未知/字段未定义方向 → 默认按降级(未知即降级)。
        _ => ChangeVerdict::Downgrade,
    }
}

/// 对一组变更做整体判定:是否含降级、以及降级明细字段。
pub struct DowngradeReport {
    pub has_downgrade: bool,
    pub downgraded_fields: Vec<String>,
}

/// 评估一批变更。若 `has_downgrade` 为真,则要求 `confirm_downgrade:true` 才可生效。
pub fn evaluate(changes: &[FieldChange]) -> DowngradeReport {
    let mut downgraded = Vec::new();
    for c in changes {
        if classify(c) == ChangeVerdict::Downgrade {
            downgraded.push(c.field.clone());
        }
    }
    DowngradeReport {
        has_downgrade: !downgraded.is_empty(),
        downgraded_fields: downgraded,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ch(field: &str, old: &str, new: &str) -> FieldChange {
        FieldChange {
            field: field.into(),
            old: old.into(),
            new: new.into(),
        }
    }

    // C4.7:各类降级判为 Downgrade。
    #[test]
    fn downgrades_detected() {
        assert_eq!(
            classify(&ch("refresh_rotation", "on", "off")),
            ChangeVerdict::Downgrade
        );
        assert_eq!(
            classify(&ch("redirect_mode", "exact", "prefix")),
            ChangeVerdict::Downgrade
        );
        assert_eq!(
            classify(&ch(
                "token_endpoint_auth_method",
                "private_key_jwt",
                "client_secret_post"
            )),
            ChangeVerdict::Downgrade
        );
        assert_eq!(
            classify(&ch("dpop", "required", "optional")),
            ChangeVerdict::Downgrade
        );
        assert_eq!(
            classify(&ch("token_validity_secs", "900", "3600")),
            ChangeVerdict::Downgrade
        );
    }

    // C4.7:收紧不算降级。
    #[test]
    fn tightening_not_downgrade() {
        assert_eq!(
            classify(&ch(
                "token_endpoint_auth_method",
                "client_secret_post",
                "private_key_jwt"
            )),
            ChangeVerdict::NotDowngrade
        );
        assert_eq!(
            classify(&ch("redirect_mode", "prefix", "exact")),
            ChangeVerdict::NotDowngrade
        );
        assert_eq!(
            classify(&ch("token_validity_secs", "3600", "900")),
            ChangeVerdict::NotDowngrade
        );
    }

    // C4.7 fail-safe:未知字段 → 默认降级。
    #[test]
    fn unknown_field_fails_safe_to_downgrade() {
        assert_eq!(
            classify(&ch("some_future_field", "a", "b")),
            ChangeVerdict::Downgrade
        );
    }

    // C4.7 fail-safe:已知字段但未知取值 → 默认降级。
    #[test]
    fn unknown_value_fails_safe_to_downgrade() {
        assert_eq!(
            classify(&ch(
                "token_endpoint_auth_method",
                "private_key_jwt",
                "weird_new_method"
            )),
            ChangeVerdict::Downgrade
        );
    }

    // C4.7 fail-safe:validity 解析失败 → 降级。
    #[test]
    fn unparseable_validity_fails_safe() {
        assert_eq!(
            classify(&ch("token_validity_secs", "abc", "def")),
            ChangeVerdict::Downgrade
        );
    }

    // 整体评估:含降级时报明细。
    #[test]
    fn evaluate_reports_downgraded_fields() {
        let changes = [
            ch("refresh_rotation", "on", "off"),
            ch("client_name", "A", "B"), // 未知字段 → fail-safe 降级
            ch("redirect_mode", "prefix", "exact"), // 收紧
        ];
        let r = evaluate(&changes);
        assert!(r.has_downgrade);
        assert!(r
            .downgraded_fields
            .contains(&"refresh_rotation".to_string()));
        assert!(r.downgraded_fields.contains(&"client_name".to_string()));
        assert!(!r.downgraded_fields.contains(&"redirect_mode".to_string()));
    }

    // 纯收紧变更:无降级。
    #[test]
    fn all_tightening_no_downgrade() {
        let changes = [
            ch("redirect_mode", "prefix", "exact"),
            ch("dpop", "optional", "required"),
        ];
        assert!(!evaluate(&changes).has_downgrade);
    }
}
