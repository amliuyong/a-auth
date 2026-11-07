CREATE TABLE a_auth.policy_versions (
    tenant TEXT PRIMARY KEY,
    version NUMERIC(20, 0) NOT NULL,
    CHECK (version > 0 AND version <= 18446744073709551615)
);
