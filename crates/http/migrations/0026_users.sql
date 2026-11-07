-- A directory row fences absent aliases and canonical identities.
CREATE TABLE a_auth.user_directories (
    tenant BYTEA PRIMARY KEY
);
CREATE TABLE a_auth.users (
    tenant BYTEA NOT NULL,
    user_id BYTEA NOT NULL,
    user_id_folded BYTEA NOT NULL,
    email BYTEA NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled', 'tombstoned')),
    scim_external_id BYTEA,
    scim_user_name BYTEA,
    credential_change_id BYTEA,
    record TEXT NOT NULL,
    PRIMARY KEY (tenant, user_id)
);
CREATE UNIQUE INDEX users_email_idx ON a_auth.users (tenant, email)
    WHERE email <> ''::BYTEA;
CREATE UNIQUE INDEX users_scim_external_idx ON a_auth.users (tenant, scim_external_id)
    WHERE scim_external_id IS NOT NULL;
CREATE UNIQUE INDEX users_scim_name_idx ON a_auth.users (tenant, scim_user_name)
    WHERE scim_user_name IS NOT NULL;
CREATE INDEX users_status_idx ON a_auth.users (tenant, status, user_id);

-- The POST tuple remains bound even when a later PUT moves visible aliases.
CREATE TABLE a_auth.scim_create_claims (
    tenant BYTEA NOT NULL,
    external_id BYTEA NOT NULL,
    user_name BYTEA NOT NULL,
    user_id BYTEA NOT NULL,
    pending_initial_epoch NUMERIC(20, 0)
        CHECK (pending_initial_epoch BETWEEN 0 AND 18446744073709551615),
    PRIMARY KEY (tenant, external_id, user_name)
);
CREATE INDEX scim_create_claims_user_idx
    ON a_auth.scim_create_claims (tenant, user_id);

-- Admission reads this append-only authority under the directory fence.
-- Governance writers must acquire the same fence before publishing a digest.
CREATE TABLE a_auth.governance_suppressions (
    tenant BYTEA NOT NULL,
    target_class TEXT NOT NULL,
    digest TEXT NOT NULL,
    epoch NUMERIC(20, 0) NOT NULL
        CHECK (epoch BETWEEN 0 AND 18446744073709551615),
    record JSONB NOT NULL,
    PRIMARY KEY (tenant, target_class, digest, epoch)
);
