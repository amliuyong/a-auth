//! 不可变策略工件(spec 005 §7 补强 ⑨):按 `{tenant, version, digest}` 标识;**先分发校验、后激活**。

use crate::AuthzError;

/// 一份已解析 + 校验的 Cedar 策略工件。`version` = 逐租户 policy_version 快照;`digest` = 文本 sha256(可审计防篡改)。
pub struct PolicyArtifact {
    pub version: u64,
    pub digest: String,
    pub(crate) policies: cedar_policy::PolicySet,
}

impl PolicyArtifact {
    /// 解析 + 校验策略文本。**parse 失败 → `PolicyParse`(可辨,非 deny)**——fail-closed 前提。
    /// `digest` = sha256(text) 十六进制(不可变工件标识;同文本必同 digest)。
    pub fn parse(text: &str, version: u64) -> Result<PolicyArtifact, AuthzError> {
        let policies: cedar_policy::PolicySet = text
            .parse()
            .map_err(|e| AuthzError::PolicyParse(format!("{e}")))?;
        use sha2::{Digest, Sha256};
        let digest = format!("{:x}", Sha256::digest(text.as_bytes()));
        Ok(PolicyArtifact {
            version,
            digest,
            policies,
        })
    }

    pub(crate) fn policies(&self) -> &cedar_policy::PolicySet {
        &self.policies
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ok_and_bad_distinguishable() {
        let ok = PolicyArtifact::parse(
            r#"permit(principal, action == Action::"issue", resource);"#,
            1,
        );
        assert!(ok.is_ok());
        let art = ok.unwrap();
        assert_eq!(art.version, 1);
        assert_eq!(art.digest.len(), 64); // sha256 hex

        // 坏策略 → PolicyParse(可辨,非 deny)。
        let bad = PolicyArtifact::parse("not cedar at all", 1);
        assert!(matches!(bad, Err(AuthzError::PolicyParse(_))));
    }

    #[test]
    fn digest_stable_for_same_text() {
        let a = PolicyArtifact::parse(r#"permit(principal, action, resource);"#, 1).unwrap();
        let b = PolicyArtifact::parse(r#"permit(principal, action, resource);"#, 2).unwrap();
        assert_eq!(a.digest, b.digest, "同文本 digest 稳定(与 version 无关)");
    }
}
