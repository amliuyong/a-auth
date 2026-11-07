CREATE TABLE a_auth.initial_access_tokens (
    tenant TEXT NOT NULL,
    token_id TEXT NOT NULL,
    record JSONB NOT NULL,
    PRIMARY KEY (tenant, token_id),
    CHECK (jsonb_typeof(record) = 'object'),
    CHECK (record->>'token_id' = token_id)
);
