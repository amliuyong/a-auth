use super::{db_error, PostgresStore};
use crate::ports::StoreError;
use sqlx::Row;

impl PostgresStore {
    /// Confirm that no newer admission replaced this complete receipt. Combined
    /// with the final mounted-file read, this fences a snapshot held across a
    /// lock wait or a publication/rollback while another replica advanced trust.
    pub(crate) async fn mounted_admin_checkpoint_matches(
        &self,
        namespace: &str,
        digest: &[u8],
        created: i64,
        record: &str,
    ) -> Result<bool, StoreError> {
        sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM a_auth.mounted_admin_checkpoints \
             WHERE namespace=$1 AND document_digest=$2 \
             AND version_created_at=$3 AND record=$4)",
        )
        .bind(namespace.as_bytes())
        .bind(digest)
        .bind(created)
        .bind(record)
        .fetch_one(&self.pool)
        .await
        .map_err(db_error)
    }

    /// Serialize checkpoint admission across replicas. Validation runs after
    /// acquiring the row lock and again after the write, before commit.
    pub(crate) async fn admit_mounted_admin_checkpoint(
        &self,
        namespace: &str,
        digest: &[u8],
        created: i64,
        record: &str,
        mut validate: impl FnMut(&[u8], i64, &str) -> Result<(), StoreError> + Send,
    ) -> Result<(), StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        sqlx::query(
            "INSERT INTO a_auth.mounted_admin_checkpoints \
             (namespace,document_digest,version_created_at,record) \
             VALUES ($1,$2,$3,$4) ON CONFLICT (namespace) DO NOTHING",
        )
        .bind(namespace.as_bytes())
        .bind(digest)
        .bind(created)
        .bind(record)
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
        let row = sqlx::query(
            "SELECT namespace,document_digest,version_created_at,record \
             FROM a_auth.mounted_admin_checkpoints WHERE namespace=$1 FOR UPDATE",
        )
        .bind(namespace.as_bytes())
        .fetch_one(&mut *transaction)
        .await
        .map_err(db_error)?;
        if row.try_get::<Vec<u8>, _>("namespace").map_err(db_error)? != namespace.as_bytes() {
            return Err(StoreError::Permanent(
                "Invalid mounted admin checkpoint identity".into(),
            ));
        }
        let prior_digest: Vec<u8> = row.try_get("document_digest").map_err(db_error)?;
        let prior_created: i64 = row.try_get("version_created_at").map_err(db_error)?;
        let prior_record: String = row.try_get("record").map_err(db_error)?;
        validate(&prior_digest, prior_created, &prior_record)?;
        sqlx::query(
            "UPDATE a_auth.mounted_admin_checkpoints SET document_digest=$2, \
             version_created_at=$3,record=$4 WHERE namespace=$1",
        )
        .bind(namespace.as_bytes())
        .bind(digest)
        .bind(created)
        .bind(record)
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
        validate(&prior_digest, prior_created, &prior_record)?;
        transaction.commit().await.map_err(db_error)
    }
}
