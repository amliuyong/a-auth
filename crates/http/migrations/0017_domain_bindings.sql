CREATE TABLE a_auth.domain_bindings (
    domain TEXT PRIMARY KEY CHECK (domain = lower(domain)),
    resource_id TEXT NOT NULL,
    tenant TEXT NOT NULL,
    client_id TEXT NOT NULL
);

CREATE INDEX domain_bindings_client ON a_auth.domain_bindings (client_id);
CREATE INDEX domain_bindings_tenant ON a_auth.domain_bindings (tenant);
