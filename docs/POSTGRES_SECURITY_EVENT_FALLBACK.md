# PostgreSQL security event fallback

`PostgresSecurityEventFallback` durably retains security-event ingress
snapshots for a bounded hot-ledger recovery batch. It shares PostgreSQL
availability with the hot ledger. A whole-database outage cannot be covered by
this queue; the existing bounded application emergency path remains necessary.

## Admission and delivery

Migration `0039_security_event_fallback.sql` separates immutable event-ID
envelopes from ingress snapshots. An event ID cannot be rebound to another
tenant or event envelope. Identical snapshots coalesce, including after
acknowledgment or dead-lettering. A changed source delivery snapshot has its own
SHA-256 identity and does not overwrite an existing lease.

Private queue records require the explicit ingress counter, a canonical valid
event and bounded delivery history. The complete serialized snapshot must
match its physical event ID and digest. A missing counter or damaged record
fails admission/claim without being overwritten. Batch admission returns one
outcome per input, preserves valid entries when another is invalid, and accepts
at most ten inputs, matching the application fallback batch boundary.

Claims lock at most 100 due snapshots with `FOR UPDATE SKIP LOCKED` and issue
fresh private random lease capabilities for one to 360 seconds. A transaction
that cannot validate or lease every selected row rolls back the whole claim.
Durable receive counts reconstruct prior source failure/retry history using
the existing ingress receive helper. Counter exhaustion is rejected before
that helper can saturate.

Acknowledgment, retry and dead-letter transitions require the exact current
snapshot, receive count, nonce and deadline. Expiry is checked after lock waits
and before commit. Retry delays cannot exceed 3,600 seconds. Lease fields are
not exposed through mutation, serialization or `Debug`.

## Recovery batch and limits

`run_once` writes the received ingress to the existing PostgreSQL hot ledger
before acknowledgment. A crash after the ledger commit leaves a reclaimable
queue lease. Redelivery preserves one immutable event and extends its source
attempt history through the existing duplicate reconciliation logic.

Successful persistence acknowledges the snapshot. Transient persistence
failures retry after five seconds until the existing four-ingress-attempt
budget is spent. Permanent failures and exhausted attempts enter retained
dead-letter state. Lost settlement authority is reported separately. The
aggregate report contains counts without event envelopes or lease secrets.

Seven owned-database fixtures use independent pools and 16 concurrent actors.
They cover coalescing, event-envelope collision rejection, crash redelivery,
actual failed-claim rollback, missing-counter rejection, per-input outcomes,
locked-head progress, a new source arriving during a lease, and settlement
expiry during an observed row-lock wait. A PostgreSQL trigger injects a
transient ledger failure to exercise all four attempts and retained dead-letter
state; an actual ledger envelope collision exercises permanent failure.

This adapter and batch do not establish production composition, worker
polling/shutdown, operational dead-letter handling, queue/identity retention,
archive delivery, or installed Kubernetes acceptance. Those remain required
by issue #142.
