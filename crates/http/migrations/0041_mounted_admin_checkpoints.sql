-- Credential values stay in operator mounts. Only irreversible hashes,
-- lifetimes, owner/revision and retirement metadata enter this checkpoint.
CREATE TABLE a_auth.mounted_admin_checkpoints (
    namespace BYTEA PRIMARY KEY,
    document_digest BYTEA NOT NULL CHECK (octet_length(document_digest) = 32),
    version_created_at BIGINT NOT NULL CHECK (version_created_at > 0),
    record TEXT NOT NULL
);
