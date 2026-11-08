# Kubernetes port inventory (#142)

This inventory covers the 57 public capability traits in `crates/http/src`:
41 in [ports.rs](../crates/http/src/ports.rs) and 16 in other modules.
It records the storage and external dependencies that must be accounted for
before [the delivery ledger](KUBERNETES_DELIVERY.md) can pass.

An adapter implementation alone does not establish production wiring or
deployment acceptance. [`PostgresRuntime`](../crates/http/src/postgres_runtime.rs)
now explicitly constructs all thirty-five PostgreSQL ports and the mounted
authority and portable transports. Development memory stores are not production
fallback authority. Installed evidence and its limits are recorded in the
[delivery ledger](KUBERNETES_DELIVERY.md).

## Implemented PostgreSQL authority

These thirty-five traits have PostgreSQL adapters. Shared contracts exercise the
memory, actual AWS adapters against a loopback emulator, and PostgreSQL
implementations. The delivery ledger records the candidate validation results.
The AWS grace contract additionally uses a loopback KMS response fixture;
it does not establish native KMS acceptance.

| Trait | PostgreSQL authority and relevant conditions |
| --- | --- |
| `ParStore` | Tenant-scoped atomic consume, application expiry |
| `CodeStore` | Create-once, user epoch/status-authorized issuance, client authority revision, owner-fenced signing lease, failed-exchange transaction |
| `ClientStore` | Complete typed authority and physical identity validation, credential metadata CAS, active/retired authority, reclaim audit |
| `InitialAccessTokenStore` | Bound issue limit, expiry, one-time consumption |
| `RefreshStore` | Family create-once, client authority revision, lease owner/version CAS, revocation |
| `ReplayStore` | Tenant-scoped conditional admission and expiry boundary |
| `GrantStore` | Active-client-fenced admission and usage/revision transaction, revision CAS, revocation monotonicity, credential epoch predicates |
| `PolicyVersionStore` | Atomic increment with exhaustion guard |
| `PolicyArtifactStore` | Immutable version, identical retry |
| `JtiStore` | Root/delegation namespaces, immutable delegated authority, monotonic revoke |
| `AuthzSessionStore` | Locked legal transitions, sequence increment, immutable user binding |
| `RateLimitStore` | Locked token-bucket admission; read-only availability check |
| `FederationConfigStore` | Tenant/IdP composite key and physical identity validation; mapping-fenced issuer replacement/deletion; resolved secret is absent |
| `FederationFlowStore` | One-time upstream/downstream binding; expiry after lock wait |
| `MagicLinkStore` | Browser-bound consume; subject and cooldown erasure in one transaction |
| `WorkloadTrustStore` | Tenant-scoped binding identity and authoritative listing |
| `DomainMapStore` | Global normalized-domain uniqueness, owner-conditional deletion |
| `PasskeyChallengeStore` | Tenant-bound one-time ceremony, complete RP binding, expiry after lock wait |
| `DeviceStore` | Tenant-scoped user-code lookup, field CAS for polling/decision/consumption |
| `AdminAuthStore` | Config revision CAS, create-once hashed flows/sessions, tenant cleanup transaction |
| [`AttributeNamespaceStore`](../crates/http/src/attribute_namespace.rs) | Tenant-locked exact-audience claims, migration revision CAS, durable cancellation receipts and burned operation IDs |
| `PasswordStore` | Separate validated PHC hashes, operation-owned enrollment/rotation and administrator reset transactions, version CAS, temporary/pending predicates and exhaustion rejection |
| `GraceStore` | Per-record encrypted responses, authenticated family/version/expiry, external key rotation and delete-only capability |
| [`SecurityEventStore`](../crates/http/src/security_event.rs) | Immutable typed events, idempotent admission, atomic source-history reconciliation and tenant/time pagination |
| [`FederationAttributeMappingsStore`](../crates/http/src/federation_attributes.rs) | Tenant-locked registry/mapping CAS, unique enabled target owners, permanent retired IDs and validated snapshots |
| `UsersStore` | Tenant-fenced canonical/SCIM alias admission with durable user/tenant suppression, operation-owned credential epochs, namespace-fenced attribute CAS, mapping-fenced reconciliation/owner purge, irreversible erasure fence and authenticated pagination |
| `ScimGroupsStore` | Tenant-fenced unique active aliases, irreversible group IDs, explicit role mappings and atomic membership batches |
| `SessionStore` | Captured user generation, session ID collision rejection, actor-fenced revocation and atomic retained-session generation changes |
| `RecoveryStore` | Operation-owned rotation, atomic code/user/session generation/receipt consumption, current-authority replay, bounded failures/lockout and atomic tenant cleanup |
| `PasskeyStore` | User/session generation-authorized registration, operation-owned deletion/completion, create-once credential IDs, monotonic counter CAS and atomic user/tenant cleanup |
| `InvitationStore` | Verifier-only issue bound to active local user/password absence, atomic consume/session creation and scoped invalidation |
| `MessageOutbox` | Encrypted immutable delivery observations, deterministic tenant/time selection, recipient erasure and keyless tenant cleanup |
| `GovernanceStore` | Tenant-locked legal holds, job/lease/continuation CAS, lease/policy/lifecycle-authorized user and tenant data transactions, snapshot residual inventory, permanent suppression, immutable evidence and atomic task completion |
| `CibaStore` | Complete encrypted callback/request snapshots, field-level polling/decision/consumption CAS, bounded-arithmetic throttle and atomic request/throttle cleanup |
| [`SsfStore`](../crates/http/src/ssf.rs) | Generation-bound streams, encrypted signed SETs/lease credentials/history, `SKIP LOCKED` claims and atomic retained-audit revocation |

Cross-port authority remains necessary even when individual traits are implemented.
Raw port CRUD does not replace an authorized transaction involving user,
credential, session, client, grant, or attribute authority.
All seven existing governance data operations select coherent PostgreSQL
ports. Destructive commits recheck the claimed lease after row-lock waits;
cleanup retains SSF audit and erases credential/session/recovery/notification
authority atomically. Data-plane fixtures and installed worker checks have
different scopes: the former cover failure atomicity and lease fencing; the
latter prove the production composition and controlled native effects.

## Optional persistent authority

These traits are in their linked modules. Optional protocol surfaces need either
a complete production
implementation or an explicit disabled capability with its existing
fail-closed behavior. They must never silently select memory stores.

| Trait | Required durable behavior |
| --- | --- |
| [`PaymentRegistry`](../crates/http/src/payment/registry.rs) | Trusted owner/version-bound funding and payee records when payments are enabled |
| [`PaymentStore`](../crates/http/src/payment/store.rs) | Order uniqueness, status/revision CAS and durable unsettled attempts when payments are enabled |

The payment module is currently optional: `AppState.payments = None` disables
its profile and routes. A portable configuration must preserve this explicit
capability decision and reject unsupported payment settings at startup.

## External adapters, queues, and projections

| Trait | Portable requirement |
| --- | --- |
| `Signer` | Mounted ES256/RS256 private keys, request-coherent key snapshot and overlapping JWKS rotation |
| `JwksFetcher` | Shared [portable HTTP](PORTABLE_HTTP.md) TLS fetch/cache and existing trust/SSRF restrictions, selected by production startup |
| `OidcMetadataFetcher` | Shared portable bounded TLS metadata fetch, selected by production startup |
| `StsCaller` | Explicitly disabled in the AWS-free profile; retain the existing optional AWS path |
| `SecretResolver` | [`FileSecretResolver`](MOUNTED_SECRETS.md) with explicit reference bindings and confined mounted-file reads; real mounted-credential Cognito flows passed in both installations |
| `UpstreamTokenExchanger` | Shared portable TLS exchange with registered endpoint trust; production composition and real Cognito flows passed |
| `GovernanceJobQueue` | [PostgreSQL durable wake-ups and worker batch](POSTGRES_GOVERNANCE_QUEUE.md), `SKIP LOCKED` claim, lease fencing and retry; native primary-erasure and acknowledgment checks passed |
| `Notifier` | [TLS SMTP and PostgreSQL notification authority](POSTGRES_SMTP.md) with recovery-operation deduplication and uncertain-send fencing; native delivery and ambiguous-send no-replay checks passed |
| `AuthzEventSink` | Explicit projection configuration; authority commit independent of projection failure |
| `CibaCallbackDelivery` | Shared portable bounded callback HTTP with existing destination/credential checks; selected by production startup; installed CIBA callback qualification is not claimed |
| [`ArchiveDeliverySink`](../crates/http/src/security_event_archive.rs) | Optional S3-compatible archive or explicit archive disablement |
| [`CimdHttpClient`](../crates/http/src/cimd.rs) | Shared portable transport with existing metadata allowlist, DNS/IP pinning, size/timeout and SSRF protections |
| [`SsfPushClient`](../crates/http/src/ssf_worker.rs) | Shared portable bounded push; native delivery, receipt-loss retry and actual-lease crash recovery passed against an authenticated receiver |
| [`SsfSignerResolver`](../crates/http/src/ssf_worker.rs) | Resolve the configured mounted signer for each delivery snapshot |
| [`SecurityEventFallback`](../crates/http/src/security_event.rs) | [PostgreSQL durable ingress snapshots and recovery batch](POSTGRES_SECURITY_EVENT_FALLBACK.md), per-input batch outcomes and fenced redelivery; native insertion and actual-lease crash recovery passed |
| [`GovernanceResourceBackend`](../crates/http/src/governance_resources.rs) | [PostgreSQL primary inventory and retained-record observations](POSTGRES_GOVERNANCE_RESOURCES.md), same-pool worker fencing and explicit operator statements for external backups/logs; native primary erasure passed while external copies remain operator-owned |

Queues and delivery state have both independent-pool contracts and controlled
native worker checks. The runtime supplies four worker Deployments and three
maintenance CronJobs. Native zero-row maintenance runs preserve the default
dry-run flags and do not establish destructive maintenance acceptance.

State helpers also use explicit durable production composition.
`BrandingStore::postgres` persists bounded deployment presentation with revision
CAS. [Mounted administrator credentials](MOUNTED_ADMIN_CREDENTIALS.md) preserve
platform, tenant and SCIM ownership plus durable rollback/retirement trust.
Production startup selects both helpers. Lifecycle contracts and installed
scope are recorded separately in the delivery ledger and recovery guide.

## Excluded SaaS and multi-Region capabilities

| Trait | Scope reason and startup condition |
| --- | --- |
| [`TenantKeyRegistry`](../crates/http/src/tenant_keys.rs) | Per-tenant key registry is SaaS scope; single-tenant key snapshots still require the mounted signer |
| [`TenantKeyCommandSink`](../crates/http/src/tenant_keys.rs) | SaaS per-tenant key provisioning commands remain in the existing AWS deployment |
| [`TenantKeyProvisioningBackend`](../crates/http/src/tenant_key_provisioner.rs) | SaaS KMS provisioning is outside #142 |
| [`RegionControlStore`](../crates/http/src/region.rs) | Multi-Region ownership is outside #142; use explicit single-Region runtime without control authority |

Portable startup must reject SaaS/multi-Region settings. CloudFront origin
authentication and Lambda@Edge ingress are excluded configuration paths, not
replacement PostgreSQL ports.

## Production wiring review

Review [AppState](../crates/http/src/state.rs) and the worker constructors
against this inventory before declaring storage complete. In addition to
trait implementations, the review must cover:

- Every enabled state field dispatches to its configured durable backend.
- Credential, recovery, invitation, passkey, SCIM, and federated-attribute
  mutations preserve their existing cross-port authority transaction.
- Secrets and private signing material come from mounted configuration;
  secret-bearing durable response/delivery state is encrypted.
- Only the token runtime mounts grace encryption keys. Other paths receive
  the delete-only grace capability; keys for other encryption purposes must
  not grant grace decryption. Mounted private key roots stay separate from
  dynamically referenced external client-secret roots.
- Unsupported or excluded configuration fails at startup rather than
  advertising an unavailable capability.
- Runtime and migration roles are distinct. Migration sessions close after
  success, error, or cancellation and never relax runtime connection timeouts.
- The production build and installed runtime meet the AWS-free checks in the
  delivery ledger.
