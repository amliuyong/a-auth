-- A stable one-way check rejects replicas using a different suppression key.
-- Runtime roles may SELECT/INSERT this immutable binding, never UPDATE/DELETE.
CREATE TABLE a_auth.user_authority_binding (
    singleton BOOLEAN PRIMARY KEY CHECK (singleton),
    key_check BYTEA NOT NULL CHECK (octet_length(key_check) = 32)
);
