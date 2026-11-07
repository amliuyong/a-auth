CREATE TABLE a_auth.federation_flows (
    state TEXT PRIMARY KEY,
    tenant TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    record JSONB NOT NULL,
    CHECK (record->>'state' = state),
    CHECK (record->>'tenant_id' = tenant),
    CHECK ((record->>'expires_at')::BIGINT = expires_at)
);

CREATE INDEX federation_flows_tenant ON a_auth.federation_flows (tenant);
CREATE INDEX federation_flows_expiry ON a_auth.federation_flows (expires_at);
