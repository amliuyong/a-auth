CREATE TABLE a_auth.governance_authority (
    tenant BYTEA PRIMARY KEY,
    generation NUMERIC(20, 0) NOT NULL
        CHECK (generation BETWEEN 0 AND 18446744073709551615),
    record TEXT NOT NULL
);

-- Preserve the full UTF-8 domain (including embedded NULs) in authority keys
-- and escaped JSON records. Existing append-only suppression rows survive.
ALTER TABLE a_auth.governance_suppressions
    ALTER COLUMN target_class TYPE BYTEA USING convert_to(target_class, 'UTF8'),
    ALTER COLUMN digest TYPE BYTEA USING convert_to(digest, 'UTF8'),
    ALTER COLUMN record TYPE TEXT USING record::text;
