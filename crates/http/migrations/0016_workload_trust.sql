CREATE TABLE a_auth.workload_trust (
    tenant TEXT NOT NULL,
    binding_id TEXT NOT NULL,
    record JSONB NOT NULL,
    PRIMARY KEY (tenant, binding_id),
    CHECK (record->>'tenant_id' = tenant)
);
