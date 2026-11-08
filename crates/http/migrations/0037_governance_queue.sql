CREATE TABLE a_auth.governance_queue (
    tenant BYTEA NOT NULL,
    job_id BYTEA NOT NULL,
    revision NUMERIC(20, 0) NOT NULL CHECK (revision BETWEEN 0 AND 18446744073709551615),
    failure_attempt SMALLINT NOT NULL CHECK (failure_attempt BETWEEN 0 AND 255),
    record TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'leased', 'acked', 'dead_lettered')),
    created_at BIGINT NOT NULL,
    available_at BIGINT NOT NULL,
    lease_id BYTEA,
    lease_until BIGINT,
    wake_requested BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (tenant, job_id, revision, failure_attempt),
    CHECK ((lease_id IS NULL) = (lease_until IS NULL)),
    CHECK ((status = 'leased') = (lease_id IS NOT NULL)),
    CHECK (status = 'leased' OR NOT wake_requested)
);
CREATE INDEX governance_queue_due_idx ON a_auth.governance_queue
    (available_at, created_at) WHERE status IN ('pending', 'leased');
