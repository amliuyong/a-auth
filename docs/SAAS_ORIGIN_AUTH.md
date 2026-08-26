# SaaS edge-to-origin authentication

## Trust boundary

The managed SaaS deployment derives tenant and issuer context from the viewer
host copied by the CloudFront `ForwardHost` function into
`X-Forwarded-Host`. API Gateway itself is an origin, not a tenant-facing trust
boundary. A request may use forwarded host data only after it authenticates the
managed CloudFront-to-origin hop.

The application attaches `saas_origin_auth_layer` to the complete Axum router
before tenant readiness, mutation fencing, Region admission, or any handler
runs. In SaaS form, missing or invalid edge credentials return `403
untrusted_origin`. SelfHosted form does not use this gate; its custom-domain and
mTLS behavior remains unchanged.

An origin-request Lambda@Edge function reads both values from Secrets Manager
with a 30-second in-memory cache, then overwrites these viewer-supplied headers:

- `X-Agent-Auth-Origin-Auth-Primary`
- `X-Agent-Auth-Origin-Auth-Secondary`
- `X-Agent-Auth-Origin-Auth` during the rolling migration from the earlier
  passkey-only gate
- `X-Agent-Auth-Origin-Auth-Revision`, a non-secret deployment revision

The runtime compares credential bytes in constant time. It accepts either
managed slot. The two values must be distinct and at least 32 bytes.
The CloudFront distribution stores only the immutable Lambda@Edge version ARN;
`GetDistributionConfig` cannot disclose either credential.

## Route inventory

Every route is assembled into one router before the global middleware is
attached. This includes both CORS groups and all modules currently merged by
`api_router`:

| Surface | Router modules |
| --- | --- |
| Discovery and metadata | `api_document`, `discovery`, `jwks`, `prm` |
| OAuth/OIDC protocol | `authorize`, `token`, `userinfo`, `introspect`, `revoke`, `register` |
| Extended grants and policy | `device_flow`, `ciba_flow`, `authz_session`, `grants`, `rs_attributes` |
| Browser identity | `login`, `password_login`, `invitation`, `consent`, `recover`, `end_session`, `federation_flow`, `passkey_flow` |
| User account | `account_credentials`, `account_sessions` |
| Tenant administration | `admin`, `admin_sso`, `ssf_admin`, `data_governance` |
| Provisioning | `scim`, `scim_groups` |

Because the middleware wraps the combined router, a new route is protected by
default. It must not be mounted outside `build_router`.

Host validity remains a separate check after edge authentication. A valid edge
credential does not turn the zone apex, control host, nested subdomain, unknown
tenant, or malformed host into an issuer.

## Secret ownership

The primary stack creates and replicates two Secrets Manager secrets:

```text
<stack-name>/cloudfront-origin-auth
<stack-name>/cloudfront-origin-auth-secondary
```

The existing runtime bootstrap field `passkey_origin_secret_arn` retains the
primary ARN for rolling compatibility. The runtime accepts only the exact
deployment-managed primary name, with or without the six-character Secrets
Manager ARN suffix, and derives the fixed secondary name. The Lambda role has
`GetSecretValue` only for both managed secrets. Secret values are never placed
in Lambda environment variables or CloudFormation outputs.

The primary and standby stacks read replicas with the same names. CloudFront
exists only in the primary stack. Its Lambda@Edge execution role can read
exactly the two primary-region secrets and injects both slots for whichever
regional API is configured as the origin. The function code, distribution
configuration, Lambda environments, and CloudFormation outputs contain secret
identifiers only, never secret values.

CDK declares `AgentAuthSaasStandby` dependent on `AgentAuthSaas`, so
`cdk deploy --all` and ordinary dependency-aware deployments create and
replicate the two secrets before the standby imports them. Do not use
`--exclusively` to bypass that dependency during the first deployment.

## Zero-downtime rotation

Rotate exactly one slot at a time. The unchanged slot authenticates requests
while Secrets Manager replication, Lambda replacement, and CloudFront
propagation converge.

1. Record the current `SAAS_ORIGIN_AUTH_REVISION`.
2. Generate a new random 48-byte-or-longer value in a mode-`0600` file. Do not
   pass the value on a command line or store it in shell history.
3. Write the new value to the **secondary** secret in `us-east-1`.
4. Wait until the `us-west-2` replica returns the same version/value without
   printing either value.
5. Set `SAAS_ORIGIN_AUTH_REVISION` to a new bounded identifier.
6. Deploy `AgentAuthSaas`, wait for the distribution to finish propagating,
   then deploy `AgentAuthSaasStandby`. The primary slot remains valid
   throughout.
7. Run `e2e/saas_origin_auth.sh`; require both slots and both runtimes to pass.
8. Repeat steps 2-7 for the **primary** secret with another revision. The
   already-rotated secondary slot remains valid throughout.

Do not rotate both secrets before a successful deployment and live check.
Rollback uses the unchanged slot: restore the failed slot's previous secret
version, bump the revision again, and redeploy primary then standby.

Changing `SAAS_ORIGIN_AUTH_REVISION` updates both regional Lambda environments
and the inline Lambda@Edge code, creating an immutable edge-function version.
This refreshes runtime secret reads and edge caches even though the secret names
remain stable. During propagation, old and new edge/runtime combinations share
the unchanged slot.

## Live acceptance

Run only against stable `CREATE_COMPLETE` or `UPDATE_COMPLETE` primary and
standby stacks:

```bash
ISSUER=https://t1.example.com \
EXPECTED_COMMIT="$(git rev-parse HEAD)" \
AWS_PROFILE=default \
./e2e/saas_origin_auth.sh
```

The harness is read-only. It requires a clean checkout and locally built
`deployment-provenance.json`, downloads both deployed Lambda packages, and
compares their bootstrap bytes with that exact reviewed artifact. It also
validates the CloudFront alias and origin, absence of credentials from the
distribution configuration, immutable origin-request Lambda@Edge association,
both secret replicas, both rotation slots, active/inactive Region fencing,
direct-origin rejection, and parent/control host rejection. It deletes
temporary secret-bearing files on exit. Optional `EVIDENCE_FILE` contains only
sanitized API-host hashes, status results, the deployment commit, revision, and
UTC observation time.
