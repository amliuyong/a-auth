CREATE TABLE a_auth.jti (
    tenant TEXT NOT NULL,
    jti TEXT NOT NULL,
    delegated BOOLEAN NOT NULL,
    user_id TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    record JSONB NOT NULL,
    PRIMARY KEY (tenant, jti, delegated),
    CHECK (record->>'tenant_id' = tenant),
    CHECK (record->>'jti' = jti),
    CHECK (record->>'user_id' = user_id),
    CHECK ((record->>'expires_at')::BIGINT = expires_at),
    CHECK (delegated = (record->'delegation' <> 'null'::JSONB))
);

CREATE INDEX jti_user ON a_auth.jti (tenant, user_id);
CREATE INDEX jti_expiry ON a_auth.jti (expires_at);
