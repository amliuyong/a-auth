-- Immutable envelopes fence event-id rebinding across source snapshots.
CREATE TABLE a_auth.security_event_fallback_identity (
    event_id TEXT COLLATE "C" PRIMARY KEY,
    event TEXT NOT NULL
);

CREATE TABLE a_auth.security_event_fallback (
    event_id TEXT COLLATE "C" NOT NULL REFERENCES a_auth.security_event_fallback_identity(event_id),
    source_id BYTEA NOT NULL CHECK (octet_length(source_id) = 32),
    record TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'leased', 'acked', 'dead_lettered')),
    receive_count BIGINT NOT NULL CHECK (receive_count BETWEEN 0 AND 4294967295),
    created_at BIGINT NOT NULL,
    available_at BIGINT NOT NULL,
    lease_id BYTEA,
    lease_until BIGINT,
    PRIMARY KEY (event_id, source_id),
    CHECK ((lease_id IS NULL) = (lease_until IS NULL)),
    CHECK ((status = 'leased') = (lease_id IS NOT NULL))
);
CREATE INDEX security_event_fallback_due_idx ON a_auth.security_event_fallback
    (available_at, created_at) WHERE status IN ('pending', 'leased');
