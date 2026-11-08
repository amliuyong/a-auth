CREATE TABLE a_auth.branding (
    deployment_host BYTEA PRIMARY KEY,
    version INTEGER NOT NULL CHECK (version = 1),
    revision NUMERIC(16, 0) NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    record TEXT NOT NULL
);
