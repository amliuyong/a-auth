# Mounted administrator credentials

The PostgreSQL profile can load an operator-owned administrator registry from
an explicitly mapped `FileSecretResolver` reference. The file stays outside
PostgreSQL and inherits the resolver's projected-file confinement, permission,
size and regular-file checks.

## Registry and ownership

The complete file is one JSON bundle with `schema_version: 1`, a positive
`version_created_at` and exactly three `AdminCredentialSet` values in `sets`.
They belong to the platform, the `default` tenant, and SCIM for the `default`
tenant. Platform/tenant usage is `break_glass`; SCIM usage is
`scim_provisioning`. SaaS owners are rejected.

Each set uses the existing credential schema, explicit owner/usage/revision,
credential IDs, lifetime fields, optional next credential/rotation and retired
credential hashes. The existing normalization, active-lifetime, uniqueness and
retirement-transition rules apply across the whole bundle. Publish all owners
and slots together using one atomic projected Secret generation.

## Durable trust

Migration `0041_mounted_admin_checkpoints.sql` stores a checkpoint under a
stable deployment namespace. It contains credential hashes, IDs, owner,
revision, lifetime/retirement metadata and the source-document digest. It
contains no credential value, signing key or resolved client secret.

Independent replicas serialize checkpoint admission through a PostgreSQL row
lock. The complete private codec requires nullable retirement fields and binds
namespace, document digest and creation time to physical columns. Identical
revisions must have identical lifecycle metadata; newer revisions must preserve
the existing transition and retirement rules. A lower revision fails even after
a process restart. Validation rechecks the clock after lock waits and again
before commit. Credential verification checks the current clock after loading.
After admission the provider rereads the mounted file and strongly confirms its
complete current database receipt. A file retired during a checkpoint lock wait
or a receipt replaced by another replica cannot authorize the old snapshot.

The first trusted operator bundle establishes a namespace's initial checkpoint.
Changing the namespace, deleting checkpoints or restoring an older database
changes this trust history. Backup/restore procedures must preserve the latest
mounted registry and restore safeguards; installed recovery qualification
remains pending.

The provider reads a complete current file snapshot and does not perform AWS
version-stage mutations. Rotation is an operator action on the mounted bundle.
Invalid files, truncated checkpoints and failed checkpoint updates fail closed.
The mounted constructor requires a zero cache TTL. Every verification loads the
current file and checks its durable trust; a cached credential cannot outlive a
new projected retirement boundary. Mounted values bypass the legacy provider
cache and live only for the current verification.

## Evidence and remaining work

Owned PostgreSQL fixtures exercise 16 concurrent verifiers across two pools,
rotation and cold-start rollback refusal, wrong owners, duplicate credentials
and invalid lifetimes. They check that stored checkpoints contain none of the
fixture credential values. Additional fixtures cover expiry during an observed
checkpoint lock wait, missing retirement fields and an actual rejected update.
They also reject a higher-revision attempt to resurrect a retired credential
and reject nonzero provider cache configuration. An observed row-lock fixture
publishes a new bundle that retires the waiting verifier's snapshot; that
verifier must not authenticate the old credential.

Production AppState construction, chart mounts, readiness verification,
operator procedures and installed rotation/restore acceptance remain required.
