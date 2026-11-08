-- PostgreSQL 16+, standard features only. Applied transactionally by SQLx.
CREATE SCHEMA a_auth;

CREATE TABLE a_auth.par (
    tenant TEXT NOT NULL,
    request_uri TEXT NOT NULL,
    client_id TEXT NOT NULL,
    raw_params TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    PRIMARY KEY (tenant, request_uri)
);

CREATE INDEX par_expiry ON a_auth.par (expires_at);
