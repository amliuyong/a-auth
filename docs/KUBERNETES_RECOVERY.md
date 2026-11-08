# Backup and restore Kubernetes authority

A successful PostgreSQL restore does not by itself preserve revocation.
Restoring a snapshot taken before a grant was revoked can make its still-valid
token and refresh family usable again. Both native installations reproduced
this behavior in separate clone databases, then verified reconciliation of
the known revocation across two restored web and token replicas.
There is no automatic stale-snapshot rejection.

## Backup set

Retain a consistent PostgreSQL backup with its timestamp, database version,
schema checksums, source identity, checksum and recovery point. Include all
authority tables and migration metadata. A table-by-table export can split
transactions and omit consumed, revoked or suppressed authority.

Use a verified TLS PostgreSQL service configuration and a matching supported
client version. A protected migration-role client successfully used the
standard custom-format tools in both environments:

```sh
PGSERVICEFILE=/private/postgresql-services.conf PGSERVICE=a-auth-migration \
  pg_dump --format=custom --file=/private/backup/a-auth.dump
sha256sum /private/backup/a-auth.dump > /private/backup/a-auth.dump.sha256
```

Independently preserve the current operator signing manifest and referenced
private/public files, HMAC and encryption purpose keys, administrator bundle,
external-secret bindings and values, effective runtime configuration and
immutable artifacts. Keep this material encrypted under operator custody.
The database cannot reconstruct it. Retain decrypting keys for the lifetime
of encrypted records; changing the server or governance HMAC changes durable
identity/authority bindings.

Keep current operator lifecycle checkpoints outside a database recovery
snapshot. Signing generations are fenced within a running process, rather
than by an independent durable cold-start checkpoint. Restoring an older
database can also lose administrator retirement, user suppression and
credential lifecycle history. An old database plus old mounts is unsafe.

## Restore under containment

1. Select a separate database. Disable Ingress, workers and maintenance, and
   install HTTP deployments with zero replicas. Prevent production DNS or
   load-balancer routing to the recovery deployment.
2. Provision its migration/runtime URLs and verified CA separately. Preserve
   the logical deployment namespace and compatible identity material.
   Restore with the migration role, retaining current operator mounts:

   ```sh
   PGSERVICEFILE=/private/postgresql-services.conf PGSERVICE=a-auth-restore \
     pg_restore --single-transaction --no-owner --no-acl --exit-on-error \
       /private/backup/a-auth.dump
   ```

3. Run the exact compatible migration/grant Job. Restore into an empty target;
   reuse of an existing target requires an explicit, reviewed destructive
   cleanup. Never direct recovery cleanup at the live database.
4. Before creating recovered HTTP Pods, set both protocol listeners to
   `A_AUTH_BIND=127.0.0.1:8080`. Keep probe listeners available to kubelet.
   Scale only these isolated deployments and access them through authorized
   operator Pod port-forwards. Verify direct Pod-IP TCP connections to port
   8080 fail; absence of an Ingress alone does not prove internal isolation.
5. Validate migration checksums, mounted authority and current source identity
   on each replica. Keep workers stopped so an old queue cannot repeat
   external effects before reconciliation.

The drill used zero-replica Helm values, then set the documented listener
environment on the isolated deployments before scaling. These operator
changes must remain part of the recovery hold: a later Helm upgrade can
restore the normal public-listener bind.

## Reconcile lost lifecycle authority

Compare the recovery point with a trusted, independently retained history of
post-backup changes. Reconcile grants and refresh-family revocations, consumed
codes/IATs, DPoP replay history, sessions, password/recovery/passkey changes,
administrator retirement, deleted-user suppression, provider/client
credentials, governance operations and external delivery settlements.
An incomplete history leaves the recovery hold in place.

The known-revocation drill revoked the recovered grant through authenticated
`DELETE /grants/{grant_id}` with its recovered owner session. Both restored
web replicas then reported the unexpired access token inactive. Both token
replicas rejected the original refresh token and the refresh token newly
issued from the stale snapshot. This proves reconciliation for that known
grant; it does not establish a complete bulk reset or reconstruction of
unidentified lost revocations.

If lost authority cannot be reconciled, do not reopen the recovered
deployment. Plan and independently validate a complete credential/session/
grant reset and required re-enrollment, or choose a recovery point with
complete authority. Changing signing keys alone does not revoke opaque
refresh tokens or restore administrator and suppression history.

For queued external work, distinguish a recorded settlement from an uncertain
effect. Reconcile the SMTP relay and downstream event/SSF receivers before
redelivery. Do not assume absence from an old database means an external
effect never happened.

## Prove recovery before release

Both environments restored a post-revocation backup and passed four HTTP
checks: runtime/current mounts ready; unexpired revoked grant and refresh
family rejected; a still-fresh used DPoP proof rejected; and a fresh proof
accepted on another restored token replica using a newly issued code.
The separate old-backup drill demonstrates the missing-revocation hazard
and the scope of known-grant remediation.

The final drill disposition in both environments was `HOLD_NO_RELEASE`.
Complete post-backup lifecycle authority was unavailable, so the isolated
clone web and token deployments were scaled to zero replicas. Readback
confirmed no clone Ingress or maintenance schedule and unchanged readiness
and identities for all twelve primary application Pods. Backup databases
and private evidence were retained. This exercises the documented containment
option; it does not turn the stale snapshot into a safe production recovery.

Before production release, validate the complete reconciled authority on
distinct replicas, including current signing/administrator lifecycle and
credential status. Cryptographically valid offline JWTs can remain valid
until expiry unless resource servers apply an online revocation check or
an independently enforced replacement trust policy. Account for verifier
caches and the full token lifetime before retiring keys.

Reopen ingress and resume workers only after the complete reconciliation,
protocol, delivery and external-resource checks pass. Preserve the backup
manifest, operator checkpoints, containment checks, remediation record and
release decision. PostgreSQL observations do not prove that external backup
copies or logs were erased; those remain a separate
[operator attestation](POSTGRES_GOVERNANCE_RESOURCES.md).
