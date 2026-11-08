use crate::ports::{RecoveryConsume, RecoveryRecord};

pub(crate) fn consume_recovery_record(
    record: &mut RecoveryRecord,
    presented_hash: &str,
    now: i64,
) -> RecoveryConsume {
    use agent_auth_authn::recovery::{hash_eq_b64, is_locked, on_failed_attempt};

    if is_locked(record.locked_until, now) {
        return RecoveryConsume::Locked {
            retry_after_secs: record.locked_until - now,
        };
    }
    if let Some(entry) = record
        .code_hashes
        .iter_mut()
        .find(|entry| !entry.consumed && hash_eq_b64(&entry.hash_b64, presented_hash))
    {
        entry.consumed = true;
        record.attempt_count = 0;
        record.locked_until = 0;
        RecoveryConsume::Valid
    } else {
        let (attempt_count, locked_until) = on_failed_attempt(record.attempt_count, now);
        record.attempt_count = attempt_count;
        record.locked_until = locked_until;
        if is_locked(locked_until, now) {
            RecoveryConsume::Locked {
                retry_after_secs: locked_until - now,
            }
        } else {
            RecoveryConsume::Invalid
        }
    }
}
