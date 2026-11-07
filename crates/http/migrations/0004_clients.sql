CREATE TABLE a_auth.clients (
    tenant TEXT NOT NULL,
    client_id TEXT NOT NULL,
    record JSONB NOT NULL,
    PRIMARY KEY (tenant, client_id),
    CHECK (jsonb_typeof(record) = 'object'),
    CHECK (record->>'client_id' = client_id),
    CHECK (record->>'client_secret' IS NULL),
    CHECK (record->>'reg_token_hash' IS NULL)
);

CREATE INDEX clients_reclaim_day ON a_auth.clients
    (((record->>'last_used_day')::BIGINT))
    WHERE record->>'last_used_day' IS NOT NULL;

-- Audit metadata deliberately excludes all credential material.
CREATE TABLE a_auth.client_reclaim_audit (
    tenant TEXT NOT NULL,
    client_id TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    tombstoned_at BIGINT,
    hard_deleted_at BIGINT NOT NULL,
    last_used_day BIGINT,
    PRIMARY KEY (tenant, client_id)
);
