CREATE TABLE a_auth.device_grants (
    tenant TEXT NOT NULL,
    device_code TEXT NOT NULL,
    user_code TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    record JSONB NOT NULL,
    PRIMARY KEY (tenant, device_code),
    CHECK (record->>'device_code' = device_code),
    CHECK (record->>'user_code' = user_code),
    CHECK ((record->>'expires_at')::BIGINT = expires_at),
    CHECK (record->>'status' IN ('pending', 'approved', 'denied'))
);

CREATE INDEX device_grants_user_code ON a_auth.device_grants (tenant, user_code, device_code);
CREATE INDEX device_grants_user ON a_auth.device_grants (tenant, (record->>'user_id'));
CREATE INDEX device_grants_expiry ON a_auth.device_grants (expires_at);
