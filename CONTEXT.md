# Agent Auth authorization domains

Agent Auth identifies users and workloads and bounds their access to resource
servers. Consumer applications own their business authorization domains.

## Language

**Authorization tenant**:
An identity and authorization boundary with its own issuer, users, credentials
and management authority.
_Avoid_: Business organization, SCIM Group

**Canonical user**:
The tenant-local identity to which authentication credentials and user consent
belong.
_Avoid_: Pairwise subject, email address

**Pairwise subject**:
A user identifier scoped to a relying-party sector or resource server that
limits identity correlation outside that boundary.
_Avoid_: Canonical user ID, global user ID

**SCIM Group**:
A tenant-local directory group containing canonical users.
_Avoid_: Business organization, tenant role

**Tenant management role**:
An explicit role governing access to the Agent Auth management plane.
_Avoid_: Consumer business role, RS attribute

**RS namespace**:
The boundary for business attributes belonging to a resource server.
_Avoid_: Authorization tenant, business organization

**Grant**:
A user's consent authority for a client, selected resources, permissions and
bounded workload delegation.
_Avoid_: Organization membership, tenant management role

**Business organization**:
A consumer application's business boundary with its own members and permissions,
potentially sharing an authorization tenant with other business organizations.
_Avoid_: Authorization tenant, SCIM Group
