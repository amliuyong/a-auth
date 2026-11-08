# PostgreSQL notifications and SMTP

The portable profile provides a TLS SMTP transport and a PostgreSQL `Notifier`.
Notification calls durably admit work. A worker submits admitted work and records
the result. Production configuration and Kubernetes entrypoints still need to
compose these adapters.

## TLS and credentials

`SmtpRelayConfig` selects implicit TLS or required STARTTLS. Certificate and
hostname verification remain enabled in both modes. There is no plaintext or
opportunistic TLS configuration. A private relay can use one explicitly
configured PEM root certificate; malformed, empty or invalid certificates fail
initialization. SMTP credentials come from mounted configuration and never
enter notification records.

The transport rejects invalid addresses, header controls, unsupported message
kinds, expired messages and oversized bodies before networking. Lettre encodes
headers, message bodies and SMTP framing. A stable hashed Message-ID avoids
exposing the internal operation identifier. Per-command timeouts and a ten-second
submission bound limit network work. Delivery errors omit relay addresses,
recipients and credentials.

SMTP acceptance means the relay returned a positive DATA receipt. It does not
establish arrival in a recipient's mailbox.

## Durable authority

Migration `0038_smtp_notifications.sql` stores encrypted complete notifications
and delivery metadata. It uses the notification encryption purpose already
shared with delivery observations. Private SMTP credentials are absent. The
recipient query metadata allows keyless privacy erasure.

Recovery notification identity comes from the caller's opaque operation ID.
Repeated calls preserve the first admission and cannot change its recipient or
body. Magic-link identity hashes the link and coalesces retries of the same
notification. Tenant directory locks, the stable external user authority and
permanent tenant/recipient suppression fence admission.

| State | Meaning | Automatic submission |
| --- | --- | --- |
| `pending` | Durably admitted, unclaimed | Eligible before expiry |
| `leased` | Private bounded lease, no submission admitted | Eligible after lease expiry |
| `sending` | Single-submission admission committed | Never reopened |
| `accepted` | Positive SMTP receipt and encrypted observation committed | Never reopened |
| `uncertain` | Submission result was not confirmed | Never reopened |

Claims use `FOR UPDATE SKIP LOCKED`, at most 16 rows and leases no longer than
360 seconds. Before SMTP work, `prepare_send` checks the exact nonce, immutable
message and deadline after row-lock waits, checks current recipient suppression,
and commits `sending`. An expired or replaced lease cannot submit.

The irreversible admission separates safe pre-submission redelivery from an
unknown external outcome. A process crash after admission can leave `sending`
even if the relay received nothing. A lost DATA receipt can also mean the relay
accepted the mail. Neither case is automatically resubmitted: SMTP has no
transaction shared with PostgreSQL or universally supported idempotency key.
Operators must treat such records as an unknown external result and reconcile
them with relay evidence. The implementation preserves the rule that repeated
calls for one recovery operation must not generate multiple notifications.

`record_acceptance` commits the encrypted outbox observation and `accepted`
state together. A failed database transaction can be retried using the same
private send capability without another SMTP submission. `run_once` performs
claim, admission, one transport submission and durable result recording, returning
aggregate counts without message bodies or lease capabilities.

## Privacy and evidence

Recipient and tenant outbox deletion also remove pending and in-flight
notification authority. Governance user and tenant cleanup include this table,
with inventory and deletion inside the existing authorized transactions.
A late send observation cannot recreate a removed notification. Recipient
suppression rejects a new admission after user erasure.

Local TLS fixtures exercise required STARTTLS, certificate hostname rejection,
header/configuration guards and encoded message submission. Combined PostgreSQL
and TLS tests use two independent pools, 16 concurrent admissions and 16
workers. They verify one submission and observation, and no resubmission when
the DATA receipt is lost.

The PostgreSQL journal tests cover duplicate admission, identity rebinding,
pre-submission lease replacement, uncertain outcomes, observation rollback,
recipient erasure, corrupted encrypted authority, actual expiry after a database
lock wait, and HTTP-started governance erasure. Journal-only fixtures do not
claim an SMTP receipt.

Production Secret loading, worker polling/shutdown, operational status reporting
and installed Kubernetes qualification remain required.
