CREATE TABLE a_auth.passkey_credentials (
    tenant BYTEA NOT NULL,
    credential_id BYTEA NOT NULL,
    user_id BYTEA NOT NULL,
    sign_count BIGINT NOT NULL CHECK (sign_count BETWEEN 0 AND 4294967295),
    created_at BIGINT NOT NULL,
    record TEXT NOT NULL,
    PRIMARY KEY (tenant, credential_id)
);
CREATE INDEX passkey_credentials_user_idx
    ON a_auth.passkey_credentials (tenant, user_id);
