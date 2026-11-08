# Mounted external client secrets

`FileSecretResolver` implements the existing `SecretResolver` port with a
dedicated operator-mounted directory and explicit reference-to-key bindings.
The `postgres` feature provides this adapter and its runtime dispatch variant.
Production configuration and chart mounts are installed. Both kind and EKS
passed real Cognito OIDC exchange using operator-mounted client secrets.
This does not establish interoperability with every enterprise provider;
see the [delivery ledger](KUBERNETES_DELIVERY.md).

## References and mount layout

Configuration binds a logical reference to one flat filename. For example:

| Logical reference | Mounted filename |
| --- | --- |
| `agent-auth/federation/default/example` | `example-client-secret` |
| `agent-auth/admin-oidc/default` | `admin-client-secret` |

The logical reference stays in federation or Admin OIDC configuration.
PostgreSQL never receives its resolved value. Unknown references return
`None`; the adapter never interprets them as filesystem paths. An empty binding
map explicitly disables resolution. The same reference cannot be bound twice.
At most 256 bindings are allowed.

Use a dedicated client-secret mount. Keep signing private keys, database
credentials, server and governance HMAC keys, and durable-state encryption
keys in separate mounts. Mapping configuration contains references and
filenames, never the values.

## Read and rotation behavior

Every resolution reads the current file; there is no plaintext cache.
Kubernetes projected Secret links such as
`example-client-secret → ..data/example-client-secret` are supported when the
target stays inside the configured mount. Updating the projection changes
subsequent resolutions across resolver clones. A resolution already reading
the old generation may finish with that value; rotate the upstream credential
with an overlap window when the provider supports it.

The mount and target directories must reject group and world writes, or be
verified read-only Kubernetes projection directories.
Secret targets must be regular UTF-8 files with modes such as `0600` or
`0640`: executable files, group writes and all world access are rejected.
Values must contain 1–65,536 bytes and no NUL. Whitespace is preserved exactly,
so create Secret values without an unintended trailing newline.

Bindings reject absolute paths, nested paths, traversal and Kubernetes
internal names beginning with `..`. Resolution confines canonical targets to
the mount and opens each target component relative to held directory
descriptors without following further symlinks. The opened file must match
the inspected inode. Nonblocking opens and file-type checks reject FIFOs and
other nonregular targets without waiting for a writer.

Reads run on blocking I/O workers, with at most sixteen active reads shared
across clones. Temporary byte buffers are zeroized. The existing port returns
an owned string for the exchange call; callers must continue to keep that
value out of logs, configuration writes and durable records.

## Failures and evidence

A configured file that is absent returns `None`. Invalid mappings,
permissions, escaped links, malformed contents or rebound mounts fail closed.
I/O availability failures return a transient store error. Diagnostics contain
neither the reference, filesystem path nor secret value.

The adapter tests cover explicit resolution, preservation of whitespace,
Kubernetes-style projection updates, outside links, permission changes,
invalid UTF-8/NUL/empty/oversized values, invalid configuration and nonregular
files. These local tests are separate from the installed projected-mount,
production startup and real Cognito exchange evidence above.
