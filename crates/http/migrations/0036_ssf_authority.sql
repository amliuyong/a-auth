CREATE TABLE a_auth.ssf_streams (
    tenant BYTEA NOT NULL,
    stream_id BYTEA NOT NULL,
    revision NUMERIC(20, 0) NOT NULL CHECK (revision BETWEEN 1 AND 18446744073709551615),
    status TEXT NOT NULL CHECK (status IN ('enabled', 'paused', 'revoked')),
    record TEXT NOT NULL,
    PRIMARY KEY (tenant, stream_id)
);

CREATE TABLE a_auth.ssf_deliveries (
    tenant BYTEA NOT NULL,
    stream_id BYTEA NOT NULL,
    stream_revision NUMERIC(20, 0) NOT NULL CHECK (stream_revision BETWEEN 1 AND 18446744073709551615),
    event_id BYTEA NOT NULL,
    created_at BIGINT NOT NULL,
    next_attempt_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    status TEXT NOT NULL CHECK (status IN
        ('pending', 'retry_wait', 'delivered', 'terminal', 'dead_lettered', 'suppressed')),
    lease_id BYTEA,
    lease_expires_at BIGINT,
    kid TEXT NOT NULL,
    key_nonce BYTEA NOT NULL CHECK (octet_length(key_nonce) = 12),
    encrypted_key BYTEA NOT NULL CHECK (octet_length(encrypted_key) = 48),
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 12),
    ciphertext BYTEA NOT NULL CHECK (octet_length(ciphertext) >= 16),
    PRIMARY KEY (tenant, stream_id, stream_revision, event_id),
    FOREIGN KEY (tenant, stream_id) REFERENCES a_auth.ssf_streams (tenant, stream_id),
    CHECK ((lease_id IS NULL) = (lease_expires_at IS NULL))
);
CREATE INDEX ssf_deliveries_due_idx ON a_auth.ssf_deliveries
    (next_attempt_at, created_at) WHERE status IN ('pending', 'retry_wait');
CREATE INDEX ssf_deliveries_page_idx ON a_auth.ssf_deliveries
    (tenant, stream_id, created_at DESC, stream_revision DESC, event_id DESC);
