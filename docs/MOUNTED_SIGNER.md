# Mounted signing keys

The `postgres` feature provides `MountedSignerRing` for single-tenant
self-hosted signing. It loads P-256 ES256 and RSA RS256 private keys from
operator-mounted files. Private key material stays outside PostgreSQL.

The production PostgreSQL runtime loads these files, reloads the ring during
readiness checks and resolves a complete signing snapshot per request.
Both native installations passed publication, activation and retirement
with independent EC/RSA verification. Full acceptance remains in the
[delivery ledger](KUBERNETES_DELIVERY.md).

## Files

Use an absolute root directory that the application can read. The directory
must prohibit group and other writes, or be a verified read-only Kubernetes
projection mount. Every file must prohibit group and other writes. Private files must also
prohibit other reads; `0600`, or `0640` with a dedicated application group, is
appropriate. Public keys and the manifest may use `0644`.

Private keys use unencrypted PKCS#8 PEM. Public keys use SubjectPublicKeyInfo
PEM. EC keys must use P-256; RSA keys must have 2048 through 8192 bits.
Each file is limited to 64 KiB. Do not put operator private keys in source
control, logs, test reports or database backups.

Paths in the manifest are relative to the root. Absolute paths, parent
traversal and symlinks that resolve outside the root are rejected. The loader
also rejects unknown or duplicate manifest fields, duplicate public keys,
unpublished active keys, incomplete files and unsupported keys.

For example, a generation that publishes a replacement before activation:

```json
{
  "schema": 1,
  "generation": 2,
  "es256_key": "current.ec.private.pem",
  "rs256_key": "current.rsa.private.pem",
  "ec_public_keys": ["current.ec.public.pem", "next.ec.public.pem"],
  "rsa_public_keys": ["current.rsa.public.pem", "next.rsa.public.pem"]
}
```

Both public lists must contain one through eight keys. Key IDs are RFC 7638
thumbprints derived from the public material, rather than operator labels.

## Rotation

1. Start with a positive generation and both active keys in its public sets.
2. Publish the replacement EC and RSA public keys in a higher generation,
   retaining the current active private keys. Replace the manifest atomically
   after installing its referenced files.
3. Allow public-key caches to refresh. `/jwks.json` currently advertises a
   300-second cache lifetime. Coordinate all replicas before activation.
4. In another higher generation, activate the replacement private keys while
   retaining the old public keys. Each new active key must already have been
   published in the previous accepted generation.
5. Retain the old public keys for the validity of previously issued tokens and
   cache propagation. Then remove them in a further generation.

Call `reload()` after each file update. It publishes one complete EC/RSA
snapshot. Unchanged material returns `false`. Lower generations, changed
material under the same generation, or invalid files return an error and keep
the prior complete snapshot.

`TenantKeyService::mounted` resolves a snapshot for each request. A request
captured before activation retains its original key pair through signing;
later requests see the accepted generation. SaaS registry writes and lifecycle
commands are disabled in this service.

The adapter does not enforce token lifetimes, cache waiting periods or
coordination between replicas. Installed deployment acceptance must verify
those operator steps. Signing has a shared concurrency limit across
generations and rejects inputs larger than 256 KiB.

## Validation

```bash
source scripts/rust_test_stack.sh
cargo test -p agent-auth-http --no-default-features --features postgres \
  --test mounted_signer --locked
```

Tests independently verify EC and RSA signatures, retain old-token verification
during overlap, reject changed payloads, reject retired key IDs, preserve
captured request snapshots, and retain authority after invalid reloads.
Filesystem tests cover permissions, confined paths and partial updates.
These are local adapter tests. Installed rotation also passed in kind and EKS:
new EC/RSA publication, activation after the real cache interval, old/new token
verification during overlap and retirement after the real token/cache interval.
An incomplete later publication made all four HTTP replicas unready and public
protocol requests return 503. A complete higher generation restored readiness
without resurrecting retired key IDs. Keep the current operator publication
with recovery material; reapplying an older fixture is not a valid recovery.
