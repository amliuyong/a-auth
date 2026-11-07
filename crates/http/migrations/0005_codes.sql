CREATE TABLE a_auth.codes (
    tenant TEXT NOT NULL,
    code TEXT NOT NULL,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    record JSONB NOT NULL,
    consumed BOOLEAN NOT NULL DEFAULT FALSE,
    lease_owner TEXT,
    lease_until BIGINT,
    issued_grant_id TEXT,
    replay_detected BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (tenant, code),
    CHECK (record->>'code' = code),
    CHECK (record->>'client_id' = client_id),
    CHECK (record->>'user_id' = user_id),
    CHECK ((record->>'expires_at')::BIGINT = expires_at),
    CHECK ((lease_owner IS NULL) = (lease_until IS NULL))
);

CREATE INDEX codes_client_authority ON a_auth.codes (tenant, client_id, expires_at)
    WHERE NOT consumed;
CREATE INDEX codes_user ON a_auth.codes (tenant, user_id);
CREATE INDEX codes_expiry ON a_auth.codes (expires_at);
