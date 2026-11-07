CREATE TABLE a_auth.policy_artifacts (
    tenant TEXT NOT NULL,
    version NUMERIC(20, 0) NOT NULL,
    policy_text TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    PRIMARY KEY (tenant, version),
    CHECK (version >= 0 AND version <= 18446744073709551615)
);
