CREATE TABLE a_auth.replay (
    tenant TEXT NOT NULL,
    replay_key TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    PRIMARY KEY (tenant, replay_key)
);

CREATE INDEX replay_expiry ON a_auth.replay (expires_at);
