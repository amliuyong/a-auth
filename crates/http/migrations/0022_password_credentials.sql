-- Password hashes are separate from serializable directory/API records.
CREATE TABLE a_auth.password_credentials (
    tenant TEXT NOT NULL,
    user_id TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    must_change BOOLEAN NOT NULL,
    revocation_pending BOOLEAN NOT NULL,
    -- Preserve opaque UTF-8 operation IDs, including escaped control values.
    credential_change_id BYTEA,
    version NUMERIC(20, 0) NOT NULL CHECK (version BETWEEN 0 AND 18446744073709551615),
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (tenant, user_id)
);
