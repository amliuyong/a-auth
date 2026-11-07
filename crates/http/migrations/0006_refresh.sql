CREATE TABLE a_auth.refresh_families (
    tenant TEXT NOT NULL,
    family_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    record JSONB NOT NULL,
    lease_owner TEXT,
    lease_until BIGINT,
    lease_version NUMERIC(20, 0),
    PRIMARY KEY (tenant, family_id),
    CHECK (record->>'family_id' = family_id),
    CHECK (record->>'client_id' = client_id),
    CHECK (record->>'user_id' = user_id),
    CHECK ((lease_owner IS NULL) = (lease_until IS NULL)),
    CHECK ((lease_owner IS NULL) = (lease_version IS NULL))
);

CREATE INDEX refresh_active_client ON a_auth.refresh_families (tenant, client_id)
    WHERE NOT (record->>'revoked')::BOOLEAN;
CREATE INDEX refresh_user ON a_auth.refresh_families (tenant, user_id);
