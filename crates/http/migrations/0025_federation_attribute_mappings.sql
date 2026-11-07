-- The tenant row fences target ownership, including targets not yet claimed.
-- Application snapshots retain registries and permanently used mapping IDs.
CREATE TABLE a_auth.federation_mapping_catalogs (
    tenant TEXT PRIMARY KEY,
    record TEXT NOT NULL
);
