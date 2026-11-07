CREATE TABLE a_auth.grants (
    tenant TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    record JSONB NOT NULL,
    PRIMARY KEY (tenant, grant_id),
    CHECK (record->>'grant_id' = grant_id),
    CHECK (record->>'user_id' = user_id),
    CHECK (record->>'client_id' = client_id),
    CHECK (record->>'status' IN ('active', 'revoked', 'expired'))
);

CREATE INDEX grants_user ON a_auth.grants (tenant, user_id);
CREATE INDEX grants_client ON a_auth.grants (tenant, client_id);
CREATE INDEX grants_stale ON a_auth.grants (tenant, ((record->>'effective_pv')::NUMERIC))
    WHERE record->>'status' = 'active';
