# PostgreSQL governance resource observations

`PostgresGovernanceResourceBackend` implements resource observations for the
single-tenant portable profile. It uses the configured PostgreSQL primary,
the same encrypted SSF store and explicitly mapped operator-mounted files.
It rejects foreign tenants, storage namespaces, additional logical regions,
pool mismatches and unknown secret references.
Workers also require this backend and the job's governance store to share the
same connection pool before accepting observations or inspecting lifecycle
resources. A different database cannot establish replica absence.

## Live authority

Replica evidence covers one configured logical region backed by PostgreSQL
primary reads. It does not claim that every physical PostgreSQL standby or
external recovery copy was inspected. User and tenant observations reuse the
existing governance inventory, directory locks and repeatable-read
transactions. Disabled optional tables are still inventoried so old authority
cannot disappear from evidence merely because configuration changed.

## Retained records

The portable profile retains the existing 400-day hot security-event policy.
External security-event archives are explicitly disabled. PostgreSQL ledger
events, ingress identities and source snapshots, including terminal snapshots,
remain retained until physical removal. Malformed authority rejects
verification. SSF delivery audit is conservatively counted for the entire
tenant through the retention anchor, including suppressed deliveries; revoked
stream control records remain permanent.

The backend reports PostgreSQL observations using
`postgresql_repeatable_read`. It does not infer physical deletion from TTL,
elapsed time, configuration, or a successful primary-erasure phase.

## Operator-owned resources

Mounted signing keys and external client secrets belong to the operator.
Scheduling deletion returns an error and never removes a file. Inspection
checks the explicit reference, resource fingerprint and current confined
file read; an unknown reference cannot establish absence.

PostgreSQL backups and runtime logs require an operator statement because this
backend cannot inspect storage outside its database. The dedicated retention
reference resolves a protected, bounded file using `FileSecretResolver`.
Its schema is:

```json
{
  "schema_version": 1,
  "receipts": [
    {
      "request_sha256": "64-lowercase-hex-digest",
      "observed_at": 1,
      "valid_until": 2,
      "resources": {
        "operator_backups": {
          "absent": true,
          "manifest_sha256": "64-lowercase-hex-digest"
        },
        "operator_logs": {
          "absent": true,
          "manifest_sha256": "64-lowercase-hex-digest"
        }
      }
    }
  ]
}
```

These example digests are placeholders and do not pass validation. Obtain the
request binding with `retention_request_digest`; it binds deployment, target,
job, primary-erasure timestamp and exact retention anchor. Manifest digests
identify independently retained operator inspection artifacts. The backend
does not retrieve or independently verify those artifacts.

Each statement has a validity interval of at most five minutes. Both external
resource categories are required. Unknown or duplicate fields, duplicate
request bindings and invalid digests reject the document. A missing, stale,
future or unmatched statement cannot complete retention. Publish the whole
bundle atomically; readback fences replacement during verification.
Expiry and the minimum retention window use the current wall clock after
database lock waits. A caller-supplied future timestamp cannot elapse the window.

The resulting evidence states `operator_attested_absent` or
`operator_attested_retained`, with basis `trusted_operator_attestation`.
This is an explicit trust boundary: the operator must inspect every relevant
backup/recovery copy and log location and preserve the cited manifest.
It is not native provider verification. An attestation alone cannot override
live or physically retained PostgreSQL records or the minimum retention window.

## Acceptance boundary

These adapters and local contracts do not establish production startup,
installed worker scheduling, garbage collection, native replica observation,
backup/restore safety or external artifact authenticity. Those remain required
by [the Kubernetes delivery ledger](KUBERNETES_DELIVERY.md).
