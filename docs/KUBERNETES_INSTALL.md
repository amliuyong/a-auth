# Install and upgrade Kubernetes + PostgreSQL

The immutable artifacts below have been installed on kind with PostgreSQL 16
and EKS with PostgreSQL 17 RDS. Full qualification remains in the
[delivery ledger](KUBERNETES_DELIVERY.md); this guide does not authorize
production promotion.

For source release 1.2.0, use the matching backend/frontend digest and full
source commit from the
[published release](https://github.com/amliuyong/a-auth/releases/tag/v1.2.0),
with chart 0.1.3. Copy the values example privately and update
`image.digest`, `image.sourceCommit`, the equivalent `frontend.image` fields,
and `runtime.deployment_commit` together. The immutable 0.1.2/component
selection below remains a historical reproducible installation; it does not
identify the new 1.2.0 candidate.

## Choose the deployment identity

Use PostgreSQL 16 or later, a Kubernetes cluster, an HTTPS ingress controller,
a TLS certificate for the exact issuer host, and a TLS SMTP relay. Replace
every `example.test` value in
[the complete values example](../deploy/examples/kubernetes-values.json).
Keep `runtime.namespace`, the issuer, subject policy and HMAC material stable.
The namespace in runtime configuration is a durable deployment identity,
independent of the Kubernetes namespace.

The example selects the published backend and frontend from component commit
`0a9fb2efbd1a9f933f3d52656a242927d3139d70`. Their respective immutable digests
are `sha256:9851f4a725dad04100eed12e45add9785512888e4502fb09acabea845c021c04`
and `sha256:aeb4bfc4dcba36d50829f842ad52c3d180afaaee0cbbfa35857cf08426fc5b2e`.
Chart 0.1.2 comes from `7ba6bdeb3be5f9005b013acc8cde9b005e37d989`,
with digest
`sha256:217e937f1f8b95946c01fcd4dd765e640e6fc386e9ab506ea858d1d4d1ebe34a`.

The backend, frontend and Helm chart packages are public on GHCR and support
anonymous pulls. The example uses `imagePullSecrets: []`; no registry login or
image-pull Secret is required for these packages. For a private mirror, set
`imagePullSecrets` to the namespace's registry Secret. Keep any registry
credential outside application mounts and runtime configuration, and use
protected registry configuration with password-stdin authentication.

## Provision database roles and protected mounts

Provision an empty database and two distinct login roles through the database
operator. The migration role needs authority to create schemas and tables;
the runtime role must have no superuser, role-creation, database-creation,
role-membership, schema-creation or authority-table ownership privileges.
Use different credentials and protected PostgreSQL service files.

For a database whose owner is separate from the migrator, grant the migrator
`CREATE` on the new database and its `public` schema. The migration framework
stores `_sqlx_migrations` there and creates application authority under
`a_auth`. Restrict these grants to this database. The migration Job applies
the embedded migrations, then grants the existing runtime role the required
schema usage, table DML and migration-metadata SELECT. It does not create
database roles. Ordinary application processes never apply DDL.

Prepare the following Secrets in the selected Kubernetes namespace:

| Default Secret | Required files |
| --- | --- |
| `a-auth-runtime-database` | `database`: runtime-role URL with verified TLS |
| `a-auth-migration-database` | `database`: separate migration-role URL |
| `a-auth-token-crypto` | `server-key`, `governance-key`, `grace`, `ciba`, `outbox`, `ssf` |
| `a-auth-web-crypto` | Same purpose files, excluding `grace` |
| `a-auth-signing` | `keys.json` and every private/public key it references |
| `a-auth-administrators` | `bundle`: complete administrator registry |
| `a-auth-external` | `retention` and explicitly configured external-secret leaves |

Override `secrets.*` when using different Secret names. Both crypto Secrets
must agree on shared purposes; each purpose uses distinct material. Follow
the [runtime encoding](POSTGRES_RUNTIME.md),
[signing manifest](MOUNTED_SIGNER.md),
[administrator registry](MOUNTED_ADMIN_CREDENTIALS.md) and
[external reference](MOUNTED_SECRETS.md) formats.
Prepare the retention file according to
[external backup/log attestation](POSTGRES_GOVERNANCE_RESOURCES.md);
an empty statement set cannot establish external erasure.

Remote database connections require `sslmode=verify-full` with a trusted CA.
Preserve the selected hostname; do not replace it with a numeric address.
Budget database connections across all HTTP replicas, workers and Jobs.

For example, create the database Secret from a protected file without printing
the credential:

```sh
kubectl --kubeconfig /private/kubeconfig -n a-auth create secret generic \
  a-auth-runtime-database \
  --from-file=database=/private/a-auth/runtime-database
```

Use the same file-based method for the remaining mounts. Preserve file
contents exactly: an unintended newline changes an external client secret.
Protect operator files and backups; Kubernetes Secret base64 is an encoding,
not encryption.

## Install and verify

Create the namespace, operator Secrets and ingress TLS Secret before
installation. Prepare a protected copy of the example values.
Choose the ingress class and its controller annotations. The provided
Traefik priorities ensure the exact token route wins over the web prefix.

Pull the chart by digest:

```sh
helm pull \
  oci://ghcr.io/amliuyong/a-auth-charts/a-auth@sha256:217e937f1f8b95946c01fcd4dd765e640e6fc386e9ab506ea858d1d4d1ebe34a \
  --destination /private/a-auth-charts
```

Use the pulled package path for installation:

```sh
helm install a-auth /private/a-auth-charts/CHART_PACKAGE.tgz \
  --kubeconfig /private/kubeconfig --namespace a-auth \
  --values /private/a-auth/values.json --wait --timeout 10m
kubectl --kubeconfig /private/kubeconfig -n a-auth get \
  deployments,jobs,cronjobs,ingresses
```

Check the revision-specific migration Job separately. Helm readiness does
not replace migration, protocol or worker evidence. Verify HTTPS discovery
reports the selected issuer and backend commit, JWKS contains the active
ES256/RS256 keys, and a real browser completes login, consent and PKCE
exchange. Confirm `POST /token` reaches the token Service.

Public `/admin` and `/scim` requests must return 404 even with a valid
administrator credential. Management defaults to Pod loopback with no
Service. Enable `management.serviceEnabled` only with restricted network
admission and the existing administrator authentication. Verify the
cluster's CNI actually enforces NetworkPolicy.

Observe all four worker classes, their durable effects and failed Jobs.
Reclamation and recomputation default to dry runs. S3-compatible archive
export is explicitly disabled; primary hot records remain retained until
their documented physical-removal conditions hold.

For federation, mount the upstream client secret in `a-auth-external`, add
its logical reference to `runtime.external_secrets.bindings`, enable the
capability and upgrade the runtime configuration. Register the provider
through authenticated private `/admin/federation`. Register the exact
`https://ISSUER_HOST/federation/callback` with the upstream provider.
Discovery/JWKS diagnostics leave real login `NOT_RUN`; execute an actual
browser login before claiming interoperability.

## Upgrade and recover

Retain the previous immutable artifacts, complete effective Helm values,
current operator mounts and database backup before upgrading. Use
`helm get values RELEASE --all -o json`; partial override files can omit
security settings. Preserve the current signing generation and administrator
bundle, rather than reapplying an old installation fixture.

Select immutable component digests and matching component commits. Update
`runtime.deployment_commit` with the backend identity and `rolloutRevision`
when an operator-controlled restart is required. Review forward migrations
against the current backup and recovery plan, then run `helm upgrade` with
the complete values and wait for its migration Job and all deployments.
Recheck HTTPS routing, probes, mounted authority, live protocol effects and
worker progress.

Migrations are forward-only. A Helm rollback does not reverse database
migrations or lifecycle checkpoints. Return to an older image only after
checking its compatibility with the current schema and authority; otherwise
use a reviewed forward fix. Follow the
[restore containment procedure](KUBERNETES_RECOVERY.md) when database recovery
is required.
