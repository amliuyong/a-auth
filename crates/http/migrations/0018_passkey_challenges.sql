CREATE TABLE a_auth.passkey_challenges (
    challenge TEXT PRIMARY KEY,
    tenant TEXT NOT NULL,
    user_id TEXT,
    ceremony TEXT NOT NULL CHECK (ceremony IN ('registration', 'authentication')),
    rp_id TEXT NOT NULL,
    origin TEXT NOT NULL,
    expires_at BIGINT NOT NULL
);

CREATE INDEX passkey_challenges_user ON a_auth.passkey_challenges (tenant, user_id);
CREATE INDEX passkey_challenges_expiry ON a_auth.passkey_challenges (expires_at);
