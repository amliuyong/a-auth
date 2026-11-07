-- Token-bearing state uses per-record AES-GCM envelope encryption.
-- Only externally managed key IDs and encrypted data keys are persisted.
CREATE TABLE a_auth.grace_responses (
    family_id BYTEA NOT NULL,
    version NUMERIC(20, 0) NOT NULL CHECK (version BETWEEN 0 AND 18446744073709551615),
    expires_at BIGINT NOT NULL,
    kid VARCHAR(64) NOT NULL,
    key_nonce BYTEA NOT NULL CHECK (octet_length(key_nonce) = 12),
    encrypted_key BYTEA NOT NULL CHECK (octet_length(encrypted_key) = 48),
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 12),
    ciphertext BYTEA NOT NULL CHECK (octet_length(ciphertext) >= 16),
    PRIMARY KEY (family_id, version)
);
CREATE INDEX grace_responses_expiry_idx ON a_auth.grace_responses (expires_at);
