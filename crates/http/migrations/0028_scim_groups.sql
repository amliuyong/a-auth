-- Aliases and membership authority are part of the canonical row.
-- The shared tenant directory fence serializes absent aliases and bulk changes.
CREATE TABLE a_auth.scim_groups (
    tenant BYTEA NOT NULL,
    group_id BYTEA NOT NULL,
    external_id BYTEA NOT NULL,
    members BYTEA[] NOT NULL CHECK (cardinality(members) <= 40),
    role TEXT CHECK (role IN ('member', 'auditor', 'admin', 'owner')),
    deleted BOOLEAN NOT NULL,
    record TEXT NOT NULL,
    PRIMARY KEY (tenant, group_id)
);
CREATE UNIQUE INDEX scim_groups_external_idx
    ON a_auth.scim_groups (tenant, external_id) WHERE NOT deleted;
