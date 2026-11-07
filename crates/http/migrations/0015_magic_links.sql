CREATE TABLE a_auth.magic_links (
    tenant TEXT NOT NULL,
    link_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    session_nonce TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    record JSONB NOT NULL,
    PRIMARY KEY (tenant, link_id),
    CHECK (record->>'link_id' = link_id),
    CHECK (record->>'user_id' = user_id),
    CHECK (record->>'session_nonce' = session_nonce),
    CHECK ((record->>'expires_at')::BIGINT = expires_at)
);

CREATE INDEX magic_links_user ON a_auth.magic_links (tenant, user_id);
CREATE INDEX magic_links_expiry ON a_auth.magic_links (expires_at);

CREATE TABLE a_auth.magic_link_cooldowns (
    tenant TEXT NOT NULL,
    email TEXT NOT NULL,
    last_sent_at BIGINT NOT NULL,
    PRIMARY KEY (tenant, email)
);
