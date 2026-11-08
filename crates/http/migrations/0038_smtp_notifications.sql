CREATE TABLE a_auth.smtp_notifications (
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
    status TEXT NOT NULL CHECK (status IN ('pending', 'leased', 'sending', 'accepted', 'uncertain')),
    lease_id BYTEA,
    lease_until BIGINT,
    PRIMARY KEY (tenant, message_id),
    CHECK ((status = 'pending') = (lease_id IS NULL)),
    CHECK ((status = 'leased') = (lease_until IS NOT NULL))
);
CREATE INDEX smtp_notifications_pending_idx
    ON a_auth.smtp_notifications (created_at, tenant, message_id)
    WHERE status IN ('pending', 'leased');
CREATE INDEX smtp_notifications_recipient_idx
    ON a_auth.smtp_notifications (tenant, recipient);
