CREATE TABLE a_auth.admin_oidc_configs (
    tenant TEXT PRIMARY KEY,
    record JSONB NOT NULL,
    CHECK (record->>'tenant_id' = tenant),
    CHECK ((record->>'revision')::NUMERIC BETWEEN 1 AND 18446744073709551615)
);

CREATE TABLE a_auth.admin_oidc_flows (
    state_hash TEXT PRIMARY KEY,
    tenant TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    record JSONB NOT NULL,
    CHECK (record->>'state_hash' = state_hash),
    CHECK (record->>'tenant_id' = tenant),
    CHECK ((record->>'expires_at')::BIGINT = expires_at)
);
CREATE INDEX admin_oidc_flows_tenant ON a_auth.admin_oidc_flows (tenant);
CREATE INDEX admin_oidc_flows_expiry ON a_auth.admin_oidc_flows (expires_at);

CREATE TABLE a_auth.admin_sessions (
    session_hash TEXT PRIMARY KEY,
    tenant TEXT NOT NULL,
    user_id TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    record JSONB NOT NULL,
    CHECK (record->>'session_hash' = session_hash),
    CHECK (record->>'tenant_id' = tenant),
    CHECK (record->>'user_id' = user_id),
    CHECK ((record->>'expires_at')::BIGINT = expires_at)
);
CREATE INDEX admin_sessions_user ON a_auth.admin_sessions (tenant, user_id);
CREATE INDEX admin_sessions_expiry ON a_auth.admin_sessions (expires_at);
