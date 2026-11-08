use super::{db_error, PostgresStore, PostgresUsersStore};
use crate::ports::{CodeIssueOutcome, CodeRecord, StoreError, UserStatus};

impl PostgresUsersStore {
    pub(crate) async fn put_code_authorized(
        &self,
        tenant: &str,
        record: CodeRecord,
        expected_epoch: u64,
    ) -> Result<CodeIssueOutcome, StoreError> {
        let mut transaction = self.base.pool.begin().await.map_err(db_error)?;
        if crate::user_gate::is_human_user(&record.user_id) {
            let Some(user) = Self::lock_user(&mut transaction, tenant, &record.user_id).await?
            else {
                return Ok(CodeIssueOutcome::AuthorityChanged);
            };
            if user.record.status != UserStatus::Active
                || user.record.revocation_pending
                || user.record.credential_epoch != expected_epoch
            {
                return Ok(CodeIssueOutcome::AuthorityChanged);
            }
        }
        if !PostgresStore::insert_code(&mut transaction, tenant, &record).await? {
            return Ok(CodeIssueOutcome::CodeExists);
        }
        if record.cimd_snapshot.is_none() {
            PostgresStore::add_client_authority(&mut transaction, tenant, &record.client_id)
                .await?;
        }
        transaction.commit().await.map_err(db_error)?;
        Ok(CodeIssueOutcome::Stored)
    }
}
