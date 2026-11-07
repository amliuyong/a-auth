CREATE TABLE a_auth.message_outbox (
    tenant BYTEA NOT NULL,
    message_id BYTEA NOT NULL,
    kind BYTEA NOT NULL,
    recipient BYTEA NOT NULL,
    created_at BIGINT NOT NULL,
    ttl BIGINT NOT NULL,
    kid TEXT NOT NULL,
    key_nonce BYTEA NOT NULL CHECK (octet_length(key_nonce) = 12),
    encrypted_key BYTEA NOT NULL CHECK (octet_length(encrypted_key) = 48),
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 12),
    ciphertext BYTEA NOT NULL CHECK (octet_length(ciphertext) >= 16),
    PRIMARY KEY (tenant, message_id)
);
CREATE INDEX message_outbox_recent_idx
    ON a_auth.message_outbox (tenant, created_at DESC, message_id DESC);
CREATE INDEX message_outbox_recipient_idx
    ON a_auth.message_outbox (tenant, recipient);
