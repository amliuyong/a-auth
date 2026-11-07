-- One tenant row locks exact-audience claims and migration receipts together,
-- including formerly unbound names. Namespace administration is infrequent.
CREATE TABLE a_auth.namespace_catalogs (
    tenant TEXT PRIMARY KEY,
    -- Serialize JSON as text so valid escaped control values round-trip.
    -- PostgreSQL JSONB rejects U+0000, which the operation-id port permits.
    record TEXT NOT NULL DEFAULT '{}'
);
