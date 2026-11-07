CREATE TABLE a_auth.invitations (
    tenant BYTEA NOT NULL,
    locator BYTEA NOT NULL,
    user_id BYTEA NOT NULL,
    email BYTEA NOT NULL,
    activation_id BYTEA NOT NULL,
    credential_epoch NUMERIC(20, 0) NOT NULL
        CHECK (credential_epoch BETWEEN 0 AND 18446744073709551615),
    expires_at BIGINT NOT NULL,
    record TEXT NOT NULL,
    PRIMARY KEY (tenant, locator)
);
CREATE INDEX invitations_user_idx ON a_auth.invitations (tenant, user_id);
