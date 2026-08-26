use crate::ports::{JtiRecord, JtiStore, StoreError};

pub(crate) enum JtiAuthority {
    Current(JtiRecord),
    Missing,
    Expired,
}

pub(crate) async fn read_current_jti<S, N>(
    store: &S,
    tenant_id: &str,
    jti: &str,
    now: N,
) -> Result<JtiAuthority, StoreError>
where
    S: JtiStore + ?Sized,
    N: FnOnce() -> i64,
{
    let record = store.get(tenant_id, jti).await?;
    let observed_at = now();
    Ok(match record {
        Some(record)
            if agent_auth_infra_core::lifecycle::shortlived_is_expired(
                observed_at,
                record.expires_at,
            ) =>
        {
            JtiAuthority::Expired
        }
        Some(record) => JtiAuthority::Current(record),
        None => JtiAuthority::Missing,
    })
}

#[cfg(test)]
mod tests {
    use super::{read_current_jti, JtiAuthority};
    use crate::ports::{JtiRecord, JtiStore, StoreError};
    use std::sync::atomic::{AtomicI64, Ordering};

    struct AdvancingJtiStore<'a> {
        now: &'a AtomicI64,
        record: JtiRecord,
    }

    impl JtiStore for AdvancingJtiStore<'_> {
        async fn put(&self, _record: JtiRecord) -> Result<(), StoreError> {
            Ok(())
        }

        async fn get(&self, _tenant_id: &str, _jti: &str) -> Result<Option<JtiRecord>, StoreError> {
            self.now.store(1_000, Ordering::SeqCst);
            Ok(Some(self.record.clone()))
        }

        async fn delete_by_user(
            &self,
            _tenant_id: &str,
            _user_id: &str,
        ) -> Result<usize, StoreError> {
            Ok(0)
        }

        async fn delete_all_by_tenant(&self, _tenant_id: &str) -> Result<usize, StoreError> {
            Ok(0)
        }
    }

    #[tokio::test]
    async fn jti_authority_samples_time_after_store_read() {
        let now = AtomicI64::new(999);
        let store = AdvancingJtiStore {
            now: &now,
            record: JtiRecord {
                jti: "jti-1".into(),
                tenant_id: "tenant-a".into(),
                user_id: "user-1".into(),
                family_id: None,
                grant_id: None,
                expires_at: 1_000,
            },
        };

        let result = read_current_jti(&store, "tenant-a", "jti-1", || now.load(Ordering::SeqCst))
            .await
            .unwrap();

        assert!(matches!(result, JtiAuthority::Expired));
    }
}
