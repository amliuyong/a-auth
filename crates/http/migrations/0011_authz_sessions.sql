CREATE TABLE a_auth.authz_sessions (
    tenant TEXT NOT NULL,
    session_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    user_id TEXT,
    expires_at BIGINT NOT NULL,
    record JSONB NOT NULL,
    PRIMARY KEY (tenant, session_id),
    CHECK (record->>'session_id' = session_id),
    CHECK (record->>'client_id' = client_id),
    CHECK ((record->>'user_id') IS NOT DISTINCT FROM user_id),
    CHECK ((record->>'expires_at')::BIGINT = expires_at)
);

CREATE INDEX authz_sessions_client ON a_auth.authz_sessions (tenant, client_id);
CREATE INDEX authz_sessions_user ON a_auth.authz_sessions (tenant, user_id);
CREATE INDEX authz_sessions_expiry ON a_auth.authz_sessions (expires_at);
