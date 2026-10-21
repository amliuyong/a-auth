# Self-hosted login and consent branding

Self-hosted administrators can adjust the name, built-in logo and primary color
of the login and consent pages from **Admin → Branding**. Preview uses the same
page components with fixed synthetic authorization facts. It cannot sign in,
approve, deny, exchange tokens or execute payments.

## Bounded settings

| Setting | Allowed values |
|---|---|
| Name | Default localized product name, or 1–64 Unicode characters of plain text |
| Logo | None, shield or key, rendered from built-in shapes |
| Primary color | Blue, teal or violet from the built-in palette |

Names cannot have leading or trailing whitespace, control characters or bidi
formatting controls. There are no custom images, external URLs, uploads, HTML,
JavaScript or CSS inputs. Display text is escaped.

Branding changes presentation only. The real consent page keeps authoritative
client, resource, scope, workload actor, authorization detail and payment facts.
It does not rewrite issuer, tenant, client, identity provider, redirect URI,
authorization policy or token settings.

## Permissions and preview

An administrator with read permission can inspect settings and edit a local
preview. Only an Owner with manage-access permission, or the existing break-glass
administrator, can save or restore defaults. The HTTP handlers enforce these
permissions independently of the UI.

Preview supports login and consent, desktop and mobile widths, and English and
Chinese. Preview language is isolated from the administrator's language choice.
Synthetic resources, workload actors, payees and payment terms are examples,
never live authorization inputs. Preview controls are disabled and their action
handlers cannot start authorization requests.

SaaS mode reports `unsupported_deployment`. It reads no branding record and
offers no editor or preview; save and reset return HTTP 501.

## Persistence and recovery

Version 1 stores deployment settings in the existing administrator-authentication
table on AWS. The row key uses the configured self-hosted deployment hostname,
not a hostname, tenant or key supplied by the HTTP caller. Local development uses
an in-memory store.

An older installation with no row keeps the default appearance. Every successful
save or reset advances a revision atomically. A stale editor receives HTTP 409
and must reload current settings before editing again; the UI does not replay a
failed save. Reset persists defaults with a new revision rather than deleting
the row, so a pre-reset editor cannot overwrite the reset.

A future stored schema version is read-only for this application. It reports
`unsupported_version`, hides editing and preview, and cannot be overwritten by
save or reset. Unavailable or invalid public settings fall back to the existing
appearance without blocking login. Public responses use `Cache-Control: no-store`.

The public read endpoint is `GET /ui/branding`. Authenticated administration uses
`GET /admin/branding`, `PUT /admin/branding` and
`POST /admin/branding/reset`; writes include `expected_revision`.

## Validation boundaries

The production-bundle HtmlUnit smoke controls the branding response while email
or password is being edited. Default, custom and unavailable branding must retain
the input and complete login, consent and callback. Chromium checks also cover
English/Chinese keyboard password visibility and disabled preview inputs.

HTTP acceptance covers defaults, bounded input, permissions, stale editors,
concurrent writers, SaaS isolation and future-version protection. The DynamoDB
Local acceptance starts fresh HTTP processes against one table to verify
durability, concurrent compare-and-swap and reset recovery:

```bash
source ./scripts/rust_test_stack.sh
cargo test -p agent-auth-http --features aws --test branding_e2e --locked
A_AUTH_TEST_DYNAMODB_ENDPOINT=http://127.0.0.1:8000 \
  cargo test -p agent-auth-http --features aws --test branding_e2e --locked \
  branding_dynamodb_survives_http_restart_and_fences_concurrent_editors \
  -- --exact --ignored
cd web
npx playwright test e2e/branding.spec.ts --project chromium
```

The ignored test accepts only a loopback DynamoDB emulator and uses synthetic
credentials. Browser acceptance uses mocked HTTP responses and synthetic consent
facts. These checks do not assert a production AWS deployment or a live payment.
Lambda HTTP access must use authenticated API Gateway, ALB or SDK Invoke;
Lambda Function URLs are prohibited.
