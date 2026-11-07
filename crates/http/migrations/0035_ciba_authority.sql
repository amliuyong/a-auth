CREATE TABLE a_auth.ciba_requests (
    tenant BYTEA NOT NULL,
    auth_req_id BYTEA NOT NULL,
    client_id BYTEA NOT NULL,
    user_id BYTEA NOT NULL,
    expires_at BIGINT NOT NULL,
    status BYTEA NOT NULL,
    consumed BOOLEAN NOT NULL,
    last_poll_at BIGINT,
    kid TEXT NOT NULL,
    key_nonce BYTEA NOT NULL CHECK (octet_length(key_nonce) = 12),
    encrypted_key BYTEA NOT NULL CHECK (octet_length(encrypted_key) = 48),
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 12),
    ciphertext BYTEA NOT NULL CHECK (octet_length(ciphertext) >= 16),
    PRIMARY KEY (tenant, auth_req_id)
);
CREATE INDEX ciba_requests_subject_idx ON a_auth.ciba_requests (tenant, user_id);
CREATE INDEX ciba_requests_expiry_idx ON a_auth.ciba_requests (expires_at);

CREATE TABLE a_auth.ciba_throttle (
    tenant BYTEA NOT NULL,
    user_id BYTEA NOT NULL,
    last_authorize_at BIGINT NOT NULL,
    PRIMARY KEY (tenant, user_id)
);
