CREATE TABLE a_auth.recovery_codes (
    tenant BYTEA NOT NULL,
    user_lookup BYTEA NOT NULL,
    user_id BYTEA NOT NULL,
    activation_id BYTEA NOT NULL,
    record TEXT NOT NULL,
    PRIMARY KEY (tenant, user_lookup)
);
CREATE INDEX recovery_codes_user_idx ON a_auth.recovery_codes (tenant, user_id);

-- Only server-derived operation HMACs and code verifiers enter this receipt.
-- The authorized credential/session transaction must create it atomically.
CREATE TABLE a_auth.recovery_success_results (
    tenant BYTEA NOT NULL,
    operation_key BYTEA NOT NULL,
    user_lookup BYTEA NOT NULL,
    user_id BYTEA NOT NULL,
    credential_epoch NUMERIC(20, 0) NOT NULL
        CHECK (credential_epoch BETWEEN 0 AND 18446744073709551615),
    session_id BYTEA NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    record TEXT NOT NULL,
    PRIMARY KEY (tenant, operation_key)
);
CREATE INDEX recovery_success_lookup_idx
    ON a_auth.recovery_success_results (tenant, user_lookup);
