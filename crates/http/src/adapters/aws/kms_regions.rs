#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RegionalKeyArnError {
    InvalidArn,
    SingleRegionKey,
}

#[derive(Debug)]
struct KmsKeyArn<'a> {
    partition: &'a str,
    region: &'a str,
    account: &'a str,
    key_id: &'a str,
}

fn parse_key_arn(value: &str) -> Result<KmsKeyArn<'_>, RegionalKeyArnError> {
    let mut parts = value.splitn(6, ':');
    if parts.next() != Some("arn") {
        return Err(RegionalKeyArnError::InvalidArn);
    }
    let partition = parts.next().ok_or(RegionalKeyArnError::InvalidArn)?;
    if parts.next() != Some("kms") {
        return Err(RegionalKeyArnError::InvalidArn);
    }
    let region = parts.next().ok_or(RegionalKeyArnError::InvalidArn)?;
    let account = parts.next().ok_or(RegionalKeyArnError::InvalidArn)?;
    let resource = parts.next().ok_or(RegionalKeyArnError::InvalidArn)?;
    let key_id = resource
        .strip_prefix("key/")
        .ok_or(RegionalKeyArnError::InvalidArn)?;
    if partition.is_empty()
        || region.is_empty()
        || account.len() != 12
        || !account.bytes().all(|byte| byte.is_ascii_digit())
        || key_id.is_empty()
    {
        return Err(RegionalKeyArnError::InvalidArn);
    }
    Ok(KmsKeyArn {
        partition,
        region,
        account,
        key_id,
    })
}

pub(super) fn key_arn_for_region(
    value: &str,
    target_region: &str,
) -> Result<String, RegionalKeyArnError> {
    let parsed = parse_key_arn(value)?;
    if target_region.is_empty() {
        return Err(RegionalKeyArnError::InvalidArn);
    }
    if parsed.region == target_region {
        return Ok(value.to_string());
    }
    if !parsed.key_id.starts_with("mrk-") {
        return Err(RegionalKeyArnError::SingleRegionKey);
    }
    Ok(format!(
        "arn:{}:kms:{}:{}:key/{}",
        parsed.partition, target_region, parsed.account, parsed.key_id
    ))
}

pub(super) fn require_primary_mrk(value: &str) -> Result<(), RegionalKeyArnError> {
    let parsed = parse_key_arn(value)?;
    if !parsed.key_id.starts_with("mrk-") {
        return Err(RegionalKeyArnError::SingleRegionKey);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MRK: &str = "arn:aws:kms:us-east-1:123456789012:key/mrk-1234567890abcdef1234567890abcdef";

    #[test]
    fn rebinds_only_multi_region_keys() {
        assert_eq!(
            key_arn_for_region(MRK, "us-west-2").unwrap(),
            "arn:aws:kms:us-west-2:123456789012:key/mrk-1234567890abcdef1234567890abcdef"
        );
        assert_eq!(key_arn_for_region(MRK, "us-east-1").unwrap(), MRK);

        assert_eq!(
            key_arn_for_region(
                "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
                "us-west-2",
            ),
            Err(RegionalKeyArnError::SingleRegionKey)
        );
    }

    #[test]
    fn rejects_non_key_or_malformed_arns() {
        for value in [
            "",
            "arn:aws:s3:us-east-1:123456789012:key/mrk-test",
            "arn:aws:kms:us-east-1:123:key/mrk-test",
            "arn:aws:kms:us-east-1:123456789012:alias/test",
        ] {
            assert_eq!(
                key_arn_for_region(value, "us-west-2"),
                Err(RegionalKeyArnError::InvalidArn)
            );
        }
    }
}
