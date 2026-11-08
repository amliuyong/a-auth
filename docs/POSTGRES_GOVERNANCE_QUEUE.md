# PostgreSQL governance wake-ups

The PostgreSQL adapter implements `GovernanceJobQueue` and a bounded worker
batch. The governance job revision and destructive phase lease continue to
authorize effects. Queue delivery is at least once.

## Delivery and acknowledgment

Migration `0037_governance_queue.sql` creates a queue keyed by tenant, job,
expected revision and failure attempt. Concurrent identical enqueues coalesce.
The stored command must match its physical key, including the explicit failure
attempt; malformed authority is rejected without being overwritten.

`claim` locks at most 100 due rows using `FOR UPDATE SKIP LOCKED`. It assigns
each row a fresh private random lease capability, with a lease duration of one
to 360 seconds. A locked head does not block another worker from claiming the
next row. Failed claim transactions roll back every tentative lease.

Acknowledgment, retry and dead-letter operations lock the exact row and require
the current command, nonce and deadline. They check expiry again after lock
waits and before commit. An expired or replaced lease cannot settle a newer
delivery. Retry delays are bounded to 3,600 seconds.

A wake-up arriving during a lease sets a durable flag. Settling that lease
returns the command to pending immediately instead of discarding the new
wake-up. A later explicit enqueue can also reactivate an acknowledged or
dead-lettered command. These rules preserve legitimate retries of an unchanged
job revision; the job state machine prevents repeated destructive phases.

Queue rows retain opaque commands and delivery metadata. They do not contain
resolved secrets or private signing keys. Lease capabilities are not exposed
through mutable fields, `Debug` or serialization.

## Worker batch

`run_postgres_queue_once` requires PostgreSQL governance and queue adapters from
the same pool. It checks active region admission before claiming and configured
tenant admission before processing. The existing `process_command_once`
advances or repairs the job's current revision.

Successful processing acknowledges the wake-up. A transient store failure
returns it to pending after five seconds; other engine failures enter
dead-letter state. If acknowledgment fails or the process exits, the lease
expires and another worker can redeliver. The aggregate report contains counts
without commands, user data or lease capabilities.

## Evidence and remaining work

Seven PostgreSQL tests use owned databases and independent connection pools.
They cover concurrent enqueue/claim, locked-head progress, expiry/redelivery,
in-flight wake preservation, failed-claim rollback, malformed commands and
expiry during an observed database lock wait.

The worker fixture starts user erasure through HTTP, commits a phase and its
next wake-up, then simulates a crash before acknowledgment. A different pool
repairs delivery without repeating that phase or incrementing the credential
epoch twice. Another fixture rejects a foreign-pool composition before claim.
These fixtures use development control/transports with explicit PostgreSQL
data authority.

Production composition, polling/shutdown entrypoints, retention scheduling,
operational dead-letter handling and installed Kubernetes worker qualification
remain required. Queue tests do not establish those acceptance results.
