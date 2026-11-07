CREATE TABLE a_auth.login_session_generations (
    tenant BYTEA NOT NULL,
    user_id BYTEA NOT NULL,
    generation NUMERIC(20, 0) NOT NULL
        CHECK (generation BETWEEN 0 AND 18446744073709551615),
    PRIMARY KEY (tenant, user_id)
);
CREATE TABLE a_auth.login_sessions (
    tenant BYTEA NOT NULL,
    session_id BYTEA NOT NULL,
    user_id BYTEA NOT NULL,
    credential_epoch NUMERIC(20, 0) NOT NULL
        CHECK (credential_epoch BETWEEN 0 AND 18446744073709551615),
    session_generation NUMERIC(20, 0) NOT NULL
        CHECK (session_generation BETWEEN 0 AND 18446744073709551615),
    expires_at BIGINT NOT NULL,
    last_used_at BIGINT NOT NULL,
    record TEXT NOT NULL,
    PRIMARY KEY (tenant, session_id),
    FOREIGN KEY (tenant, user_id)
        REFERENCES a_auth.login_session_generations (tenant, user_id)
);
CREATE INDEX login_sessions_user_idx ON a_auth.login_sessions
    (tenant, user_id, session_generation, expires_at);
