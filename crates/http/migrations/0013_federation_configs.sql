CREATE TABLE a_auth.federation_configs (
    tenant TEXT NOT NULL,
    upstream_idp_id TEXT NOT NULL,
    record JSONB NOT NULL,
    PRIMARY KEY (tenant, upstream_idp_id),
    CHECK (record->>'tenant_id' = tenant),
    CHECK (record->>'upstream_idp_id' = upstream_idp_id)
);
