-- Immutable typed events and their separately mutable delivery evidence.
CREATE TABLE a_auth.security_events (
    event_id TEXT PRIMARY KEY,
    tenant TEXT NOT NULL,
    occurred_at BIGINT NOT NULL CHECK (occurred_at > 0),
    expires_at BIGINT NOT NULL,
    event JSONB NOT NULL,
    delivery JSONB NOT NULL,
    source_delivery JSONB NOT NULL
);
CREATE INDEX security_events_tenant_time_idx
    ON a_auth.security_events (tenant, occurred_at DESC, event_id COLLATE "C" DESC);
CREATE INDEX security_events_expiry_idx ON a_auth.security_events (expires_at);
