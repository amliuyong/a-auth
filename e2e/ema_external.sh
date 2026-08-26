#!/usr/bin/env bash
# External or transparently simulated acceptance for spec 031 / C13.8.
#
# Run this once against AgentAuthDev and once against an AgentAuthSaas tenant.
# The operator-provided command must acquire a fresh standards-compatible
# ID-JAG and write only that compact JWT to stdout. Its stdout and stderr are
# captured and never echoed.
#
# Required:
#   EMA_DEPLOYMENT_KIND=dev|saas
#   EMA_BASE_URL=https://<public-cloudfront-or-custom-domain>
#   EMA_AGENT_AUTH_TENANT=default|<saas-tenant>
#   EMA_POLICY_ID=<non-secret operator policy id>
#   EMA_CLIENT_ID=<pre-registered confidential Agent Auth client>
#   EMA_CLIENT_SECRET_FILE=/secure/path
#   EMA_ASSERTION_CLIENT_ID=<ID-JAG client_id>
#   EMA_IDP_ISSUER=https://<enterprise-idp>
#   EMA_IDP_TENANT=<issuer tenant, or empty for a single-tenant issuer>
#   EMA_ID_JAG_ALG=RS256|ES256
#   EMA_RESOURCE=https://<canonical-mcp-resource>
#   EMA_SCOPE='required scope set'
#   EMA_IDP_PRODUCT=<product>
#   EMA_IDP_VERSION=<version>
#   EMA_CLIENT_PRODUCT=<enterprise MCP client>
#   EMA_CLIENT_VERSION=<version>
#   EMA_ID_JAG_COMMAND='<command that obtains a fresh ID-JAG>'
#   EMA_RS_VERIFY_URL=https://<real-rs-protected-verifier>
#   EMA_RS_SCOPE_DENY_URL=https://<same-rs-route-requiring-an-ungranted-scope>
#
# Optional:
#   EMA_AWS_PROFILE=default                         (optional AWS profile)
#   EMA_AWS_REGION=us-east-1                     (default us-east-1)
#   EMA_EVIDENCE_KIND=third_party|simulator      (default third_party)
#   EMA_SIMULATOR_STACK=AgentAuthEmaSimulator    (required for simulator)
#   EMA_RS_VERIFY_METHOD=GET|POST               (default GET)
#   EMA_RS_REQUEST_FILE=/path/to/request.json   (required for POST)
#   EMA_RS_EXPECTED_STATUS=200                  (default 200)
#
# This external gate intentionally exercises the profile's unbound Bearer
# variant. C13.4 DPoP/cnf propagation is covered by the HTTP integration suite.
set -euo pipefail
set +x

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_PATH="e2e/ema_external.sh"
DEPLOYMENT_KIND="${EMA_DEPLOYMENT_KIND:?EMA_DEPLOYMENT_KIND is required}"
BASE_URL="${EMA_BASE_URL:?EMA_BASE_URL is required}"
BASE_URL="${BASE_URL%/}"
AGENT_AUTH_TENANT="${EMA_AGENT_AUTH_TENANT:?EMA_AGENT_AUTH_TENANT is required}"
POLICY_ID="${EMA_POLICY_ID:?EMA_POLICY_ID is required}"
CLIENT_ID="${EMA_CLIENT_ID:?EMA_CLIENT_ID is required}"
CLIENT_SECRET_FILE="${EMA_CLIENT_SECRET_FILE:?EMA_CLIENT_SECRET_FILE is required}"
ASSERTION_CLIENT_ID="${EMA_ASSERTION_CLIENT_ID:?EMA_ASSERTION_CLIENT_ID is required}"
IDP_ISSUER="${EMA_IDP_ISSUER:?EMA_IDP_ISSUER is required}"
IDP_TENANT="${EMA_IDP_TENANT-}"
ID_JAG_ALG="${EMA_ID_JAG_ALG:?EMA_ID_JAG_ALG is required}"
RESOURCE="${EMA_RESOURCE:?EMA_RESOURCE is required}"
SCOPE="${EMA_SCOPE:?EMA_SCOPE is required}"
IDP_PRODUCT="${EMA_IDP_PRODUCT:?EMA_IDP_PRODUCT is required}"
IDP_VERSION="${EMA_IDP_VERSION:?EMA_IDP_VERSION is required}"
CLIENT_PRODUCT="${EMA_CLIENT_PRODUCT:?EMA_CLIENT_PRODUCT is required}"
CLIENT_VERSION="${EMA_CLIENT_VERSION:?EMA_CLIENT_VERSION is required}"
ID_JAG_COMMAND="${EMA_ID_JAG_COMMAND:?EMA_ID_JAG_COMMAND is required}"
RS_VERIFY_URL="${EMA_RS_VERIFY_URL:?EMA_RS_VERIFY_URL is required}"
RS_SCOPE_DENY_URL="${EMA_RS_SCOPE_DENY_URL:?EMA_RS_SCOPE_DENY_URL is required}"
RS_VERIFY_METHOD="${EMA_RS_VERIFY_METHOD:-GET}"
RS_REQUEST_FILE="${EMA_RS_REQUEST_FILE:-}"
RS_EXPECTED_STATUS="${EMA_RS_EXPECTED_STATUS:-200}"
AWS_PROFILE_NAME="${EMA_AWS_PROFILE:-default}"
AWS_REGION_NAME="${EMA_AWS_REGION:-us-east-1}"
EVIDENCE_KIND="${EMA_EVIDENCE_KIND:-third_party}"
SIMULATOR_STACK="${EMA_SIMULATOR_STACK:-}"
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SOURCE_LABEL="third-party"

umask 077
WORK="$(mktemp -d)"
cleanup() {
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
require() { command -v "$1" >/dev/null || fail "missing command: $1"; }

for command in aws curl git jq python3 sha256sum unzip; do
  require "$command"
done
python3 - <<'PY' >/dev/null 2>&1 ||
import cryptography
import jwt
PY
  fail "python3 modules PyJWT and cryptography are required"

[[ "$DEPLOYMENT_KIND" == "dev" || "$DEPLOYMENT_KIND" == "saas" ]] ||
  fail "EMA_DEPLOYMENT_KIND must be dev or saas"
[[ "$EVIDENCE_KIND" == "third_party" || "$EVIDENCE_KIND" == "simulator" ]] ||
  fail "EMA_EVIDENCE_KIND must be third_party or simulator"
if [[ "$EVIDENCE_KIND" == "simulator" ]]; then
  [[ -n "$SIMULATOR_STACK" ]] ||
    fail "EMA_SIMULATOR_STACK is required for simulator evidence"
  SOURCE_LABEL="simulated"
fi
if [[ "$DEPLOYMENT_KIND" == "dev" ]]; then
  STACK_NAME="AgentAuthDev"
  [[ "$AGENT_AUTH_TENANT" == "default" ]] ||
    fail "dev acceptance must use EMA_AGENT_AUTH_TENANT=default"
else
  STACK_NAME="AgentAuthSaas"
  [[ "$AGENT_AUTH_TENANT" != "default" ]] ||
    fail "saas acceptance must name the SaaS tenant"
fi
[[ "$BASE_URL" == https://* ]] || fail "EMA_BASE_URL must be HTTPS"
[[ "$BASE_URL" != *execute-api.* ]] ||
  fail "EMA_BASE_URL must use the public CloudFront/custom-domain origin"
[[ "$IDP_ISSUER" == https://* ]] || fail "EMA_IDP_ISSUER must be HTTPS"
[[ "$RESOURCE" == https://* ]] || fail "EMA_RESOURCE must be HTTPS"
[[ "$RS_VERIFY_URL" == https://* ]] || fail "EMA_RS_VERIFY_URL must be HTTPS"
[[ "$RS_SCOPE_DENY_URL" == https://* ]] || fail "EMA_RS_SCOPE_DENY_URL must be HTTPS"
[[ "$CLIENT_ID" != *:* ]] || fail "EMA_CLIENT_ID must not contain ':'"
[[ "$ID_JAG_ALG" == "RS256" || "$ID_JAG_ALG" == "ES256" ]] ||
  fail "EMA_ID_JAG_ALG must be RS256 or ES256"
[[ "$RS_VERIFY_METHOD" == "GET" || "$RS_VERIFY_METHOD" == "POST" ]] ||
  fail "EMA_RS_VERIFY_METHOD must be GET or POST"
[[ "$RS_EXPECTED_STATUS" =~ ^2[0-9][0-9]$ ]] ||
  fail "EMA_RS_EXPECTED_STATUS must be a successful 2xx status"
[[ -r "$CLIENT_SECRET_FILE" ]] || fail "EMA_CLIENT_SECRET_FILE is not readable"
if [[ "$RS_VERIFY_METHOD" == "POST" ]]; then
  [[ -n "$RS_REQUEST_FILE" && -r "$RS_REQUEST_FILE" ]] ||
    fail "POST RS verification requires readable EMA_RS_REQUEST_FILE"
fi

SIMULATOR_COMMIT=""
SIMULATOR_STACK_ID=""
SIMULATOR_ISSUER_FUNCTION_ARN=""
SIMULATOR_ISSUER_CODE_SHA256=""
SIMULATOR_RESOURCE_FUNCTION_ARN=""
SIMULATOR_RESOURCE_CODE_SHA256=""
if [[ "$EVIDENCE_KIND" == "simulator" ]]; then
  aws cloudformation describe-stacks \
    --profile "$AWS_PROFILE_NAME" \
    --region "$AWS_REGION_NAME" \
    --stack-name "$SIMULATOR_STACK" \
    --output json >"$WORK/simulator-stack.json"
  jq -e '
    .Stacks | length == 1 and
    (.[0].StackStatus == "CREATE_COMPLETE" or .[0].StackStatus == "UPDATE_COMPLETE")
  ' "$WORK/simulator-stack.json" >/dev/null ||
    fail "$SIMULATOR_STACK is not in a successful deployed state"

  simulator_output() {
    local key="$1"
    jq -er --arg key "$key" '
      .Stacks[0].Outputs
      | map(select(.OutputKey == $key))
      | if length == 1 then .[0].OutputValue else error("missing or duplicate simulator output") end
    ' "$WORK/simulator-stack.json"
  }

  SIMULATOR_COMMIT="$(simulator_output SimulatorCommit)"
  SIMULATOR_STACK_ID="$(jq -er '.Stacks[0].StackId' "$WORK/simulator-stack.json")"
  [[ "$SIMULATOR_COMMIT" =~ ^[0-9a-f]{40}$ ]] ||
    fail "simulator stack does not expose a full lowercase Git SHA"
  [[ "$(simulator_output IssuerUrl)" == "$IDP_ISSUER" ]] ||
    fail "simulator issuer output does not match EMA_IDP_ISSUER"
  [[ "$(simulator_output JwksUrl)" == "$IDP_ISSUER/jwks.json" ]] ||
    fail "simulator JWKS output does not match the issuer"
  [[ "$(simulator_output AssertionClientId)" == "$ASSERTION_CLIENT_ID" ]] ||
    fail "simulator assertion client output does not match"
  [[ "$(simulator_output ResourceUrl)" == "$RESOURCE" ]] ||
    fail "simulator resource output does not match EMA_RESOURCE"
  [[ "$(simulator_output RsAllowUrl)" == "$RS_VERIFY_URL" ]] ||
    fail "simulator allow route output does not match EMA_RS_VERIFY_URL"
  [[ "$(simulator_output RsDenyUrl)" == "$RS_SCOPE_DENY_URL" ]] ||
    fail "simulator deny route output does not match EMA_RS_SCOPE_DENY_URL"

  aws lambda get-function \
    --profile "$AWS_PROFILE_NAME" \
    --region "$AWS_REGION_NAME" \
    --function-name "$(simulator_output IssuerFunctionName)" \
    --query '{arn:Configuration.FunctionArn,sha:Configuration.CodeSha256,state:Configuration.State,last_update:Configuration.LastUpdateStatus}' \
    --output json >"$WORK/simulator-issuer-function.json"
  aws lambda get-function \
    --profile "$AWS_PROFILE_NAME" \
    --region "$AWS_REGION_NAME" \
    --function-name "$(simulator_output ResourceFunctionName)" \
    --query '{arn:Configuration.FunctionArn,sha:Configuration.CodeSha256,state:Configuration.State,last_update:Configuration.LastUpdateStatus}' \
    --output json >"$WORK/simulator-resource-function.json"
  for function_file in \
    "$WORK/simulator-issuer-function.json" \
    "$WORK/simulator-resource-function.json"; do
    jq -e '.state == "Active" and .last_update == "Successful"' \
      "$function_file" >/dev/null ||
      fail "simulator Lambda is not active and successfully updated"
  done
  SIMULATOR_ISSUER_FUNCTION_ARN="$(
    jq -er '.arn' "$WORK/simulator-issuer-function.json"
  )"
  SIMULATOR_ISSUER_CODE_SHA256="$(
    jq -er '.sha' "$WORK/simulator-issuer-function.json"
  )"
  SIMULATOR_RESOURCE_FUNCTION_ARN="$(
    jq -er '.arn' "$WORK/simulator-resource-function.json"
  )"
  SIMULATOR_RESOURCE_CODE_SHA256="$(
    jq -er '.sha' "$WORK/simulator-resource-function.json"
  )"
  pass "simulator stack identity, endpoints, and active Lambda code are bound"
fi

aws cloudformation describe-stacks \
  --profile "$AWS_PROFILE_NAME" \
  --region "$AWS_REGION_NAME" \
  --stack-name "$STACK_NAME" \
  --output json >"$WORK/stack.json"
jq -e '
  .Stacks | length == 1 and
  (.[0].StackStatus == "CREATE_COMPLETE" or .[0].StackStatus == "UPDATE_COMPLETE")
' "$WORK/stack.json" >/dev/null ||
  fail "$STACK_NAME is not in a successful deployed state"

stack_output() {
  local key="$1"
  jq -er --arg key "$key" '
    .Stacks[0].Outputs
    | map(select(.OutputKey == $key))
    | if length == 1 then .[0].OutputValue else error("missing or duplicate stack output") end
  ' "$WORK/stack.json"
}

DEPLOYED_COMMIT="$(stack_output DeploymentCommit)"
AUTH_FN_NAME="$(stack_output AuthFnName)"
STACK_ID="$(jq -er '.Stacks[0].StackId' "$WORK/stack.json")"
[[ "$DEPLOYED_COMMIT" =~ ^[0-9a-f]{40}$ ]] ||
  fail "deployed stack does not expose a full lowercase Git SHA"

aws lambda get-function \
  --profile "$AWS_PROFILE_NAME" \
  --region "$AWS_REGION_NAME" \
  --function-name "$AUTH_FN_NAME" \
  --query '{commit:Configuration.Environment.Variables.AGENT_AUTH_DEPLOYMENT_COMMIT,enabled:Configuration.Environment.Variables.AGENT_AUTH_EMA_ENABLED,policies_secret_arn:Configuration.Environment.Variables.AGENT_AUTH_EMA_POLICIES_SECRET_ARN,state:Configuration.State,last_update_status:Configuration.LastUpdateStatus,function_arn:Configuration.FunctionArn,code_sha256:Configuration.CodeSha256,code_url:Code.Location}' \
  --output json >"$WORK/runtime.json"

EMA_POLICIES_SECRET_ARN="$(jq -er '.policies_secret_arn' "$WORK/runtime.json")"
aws secretsmanager get-secret-value \
  --profile "$AWS_PROFILE_NAME" \
  --region "$AWS_REGION_NAME" \
  --secret-id "$EMA_POLICIES_SECRET_ARN" \
  --query SecretString \
  --output text >"$WORK/ema-policies.json"
chmod 600 "$WORK/ema-policies.json"
jq -e 'type == "array" and length > 0' "$WORK/ema-policies.json" >/dev/null ||
  fail "deployed EMA policy Secret does not contain a non-empty JSON array"

curl -fsS --proto '=https' --connect-timeout 10 --max-time 120 \
  "$(jq -er '.code_url' "$WORK/runtime.json")" \
  -o "$WORK/function.zip"
DOWNLOADED_CODE_SHA256="$(
  python3 - "$WORK/function.zip" <<'PY'
import base64
import hashlib
import sys
from pathlib import Path

print(base64.b64encode(hashlib.sha256(Path(sys.argv[1]).read_bytes()).digest()).decode())
PY
)"
FUNCTION_CODE_SHA256="$(jq -er '.code_sha256' "$WORK/runtime.json")"
[[ "$DOWNLOADED_CODE_SHA256" == "$FUNCTION_CODE_SHA256" ]] ||
  fail "downloaded Lambda package does not match the active AWS CodeSha256"
unzip -p "$WORK/function.zip" deployment-provenance.json \
  >"$WORK/deployment-provenance.json" ||
  fail "deployed Lambda package is missing deployment-provenance.json"
unzip -p "$WORK/function.zip" bootstrap >"$WORK/bootstrap" ||
  fail "deployed Lambda package is missing the Auth bootstrap"
BOOTSTRAP_SHA256="$(sha256sum "$WORK/bootstrap" | cut -d' ' -f1)"
jq -e \
  --arg commit "$DEPLOYED_COMMIT" \
  --arg bootstrap_sha256 "$BOOTSTRAP_SHA256" '
    (keys | sort) == (["bootstrap_sha256", "commit", "schema"] | sort) and
    .schema == "agent-auth-lambda-provenance-v1" and
    .commit == $commit and
    .bootstrap_sha256 == $bootstrap_sha256
  ' "$WORK/deployment-provenance.json" >/dev/null ||
  fail "deployed Lambda provenance does not bind the stack commit and bootstrap"

POLICY_ATTESTATION_SHA256="$(
  python3 - "$WORK/runtime.json" "$WORK/ema-policies.json" \
    "$WORK/policy-attestation.json" \
    "$DEPLOYED_COMMIT" "$DEPLOYMENT_KIND" "$STACK_NAME" "$BASE_URL" \
    "$AGENT_AUTH_TENANT" "$POLICY_ID" "$CLIENT_ID" "$ASSERTION_CLIENT_ID" \
    "$IDP_ISSUER" "$IDP_TENANT" "$ID_JAG_ALG" "$RESOURCE" "$SCOPE" \
    "$RS_VERIFY_URL" "$RS_SCOPE_DENY_URL" <<'PY'
import hashlib
import json
import posixpath
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

try:
    (
        runtime_file,
        policies_file,
        attestation_file,
        commit,
        deployment_kind,
        stack_name,
        issuer,
        tenant,
        policy_id,
        client_id,
        assertion_client_id,
        idp_issuer,
        idp_tenant,
        id_jag_alg,
        resource,
        scope,
        verify_url,
        deny_url,
    ) = sys.argv[1:]
    runtime = json.loads(Path(runtime_file).read_text(encoding="utf-8"))
    if (
        runtime.get("commit") != commit
        or runtime.get("enabled") != "1"
        or runtime.get("state") != "Active"
        or runtime.get("last_update_status") != "Successful"
    ):
        raise ValueError
    policies = json.loads(Path(policies_file).read_text(encoding="utf-8"))
    matches = [
        item
        for item in policies
        if item.get("tenant") == tenant
        and isinstance(item.get("policy"), dict)
        and item["policy"].get("policy_id") == policy_id
    ]
    if len(matches) != 1:
        raise ValueError
    policy = matches[0]["policy"]
    expected_policy = {
        "trusted_issuer": idp_issuer,
        "issuer_tenant": idp_tenant or None,
        "authenticated_client_id": client_id,
        "assertion_client_id": assertion_client_id,
    }
    if any(policy.get(key) != value for key, value in expected_policy.items()):
        raise ValueError
    if id_jag_alg not in policy.get("allowed_algorithms", []):
        raise ValueError
    if policy.get("allow_legacy_missing_resource", False) is not False:
        raise ValueError
    resources = [
        item
        for item in policy.get("resources", [])
        if isinstance(item, dict) and item.get("resource") == resource
    ]
    if len(resources) != 1:
        raise ValueError
    policy_scopes = resources[0].get("scopes")
    if not isinstance(policy_scopes, list) or not set(scope.split()).issubset(policy_scopes):
        raise ValueError

    attestation = {
        "agent_auth_commit": commit.lower(),
        "deployment_kind": deployment_kind,
        "stack_name": stack_name,
        "function_arn": runtime.get("function_arn"),
        "issuer": issuer,
        "tenant": tenant,
        "policy_id": policy_id,
        "authenticated_client_id": client_id,
        "assertion_client_id": assertion_client_id,
        "idp_issuer": idp_issuer,
        "idp_tenant": idp_tenant or None,
        "allowed_algorithm": id_jag_alg,
        "resource": resource,
        "scopes": sorted(policy_scopes),
        "allow_legacy_missing_resource": False,
    }

    def split_bound_url(value):
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError
        decoded = unquote(parsed.path or "/")
        if decoded != parsed.path and parsed.path:
            raise ValueError
        normalized = posixpath.normpath(decoded)
        trimmed = decoded.rstrip("/") or "/"
        if not normalized.startswith("/") or normalized != trimmed or ".." in decoded.split("/"):
            raise ValueError
        port = parsed.port or 443
        return parsed.hostname.lower(), port, normalized

    resource_host, resource_port, resource_path = split_bound_url(resource)
    base_path = resource_path.rstrip("/") or "/"
    for candidate in (verify_url, deny_url):
        host, port, path = split_bound_url(candidate)
        if (host, port) != (resource_host, resource_port):
            raise ValueError
        if base_path != "/" and path != base_path and not path.startswith(f"{base_path}/"):
            raise ValueError
    raw = json.dumps(attestation, sort_keys=True, separators=(",", ":")).encode("utf-8")
    Path(attestation_file).write_bytes(raw)
    print(hashlib.sha256(raw).hexdigest())
except Exception:
    print("deployed runtime, policy, or RS URL binding validation failed", file=sys.stderr)
    raise SystemExit(1)
PY
)"
FUNCTION_ARN="$(jq -er '.function_arn' "$WORK/runtime.json")"
pass "CloudFormation and the deployed Lambda artifact bind the commit and strict EMA policy"

SCRIPT_COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
git -C "$ROOT" cat-file -e "$SCRIPT_COMMIT:$SCRIPT_PATH" 2>/dev/null ||
  fail "$SCRIPT_PATH must be committed before external acceptance"
SCRIPT_BLOB="$(git -C "$ROOT" rev-parse "$SCRIPT_COMMIT:$SCRIPT_PATH")"
CURRENT_BLOB="$(git -C "$ROOT" hash-object "$ROOT/$SCRIPT_PATH")"
[[ "$SCRIPT_BLOB" == "$CURRENT_BLOB" ]] ||
  fail "$SCRIPT_PATH differs from commit $SCRIPT_COMMIT"

http_status() {
  local name="$1"
  tr -d '\r\n' <"$WORK/$name.status"
}

header_value() {
  local file="$1" name="$2"
  awk -v wanted="$name" '
    BEGIN { IGNORECASE=1 }
    {
      key=$1
      sub(/:$/, "", key)
      if (tolower(key) == tolower(wanted)) {
        sub(/^[^:]*:[[:space:]]*/, "")
        sub(/\r$/, "")
        value=$0
      }
    }
    END { print value }
  ' "$file"
}

assert_no_store() {
  local file="$1" value
  value="$(header_value "$file" cache-control)"
  [[ "${value,,}" == *no-store* ]] || fail "response is missing Cache-Control: no-store"
}

assert_cloudfront() {
  local file="$1"
  if ! awk '
    BEGIN { found=0 }
    {
      line=tolower($0)
      if (line ~ /^x-amz-cf-id:/ || line ~ /^x-cache:/ ||
          (line ~ /^via:/ && line ~ /cloudfront/)) {
        found=1
      }
    }
    END { exit(found ? 0 : 1) }
  ' "$file"; then
    fail "public response does not contain CloudFront evidence"
  fi
}

request_public_json() {
  local name="$1" url="$2"
  curl -sS --proto '=https' --connect-timeout 10 --max-time 45 \
    -D "$WORK/$name.headers" -o "$WORK/$name.body" \
    -w '%{http_code}' "$url" >"$WORK/$name.status"
  [[ "$(http_status "$name")" == "200" ]] ||
    fail "$name returned HTTP $(http_status "$name")"
  assert_cloudfront "$WORK/$name.headers"
  jq -e . "$WORK/$name.body" >/dev/null || fail "$name did not return JSON"
}

request_public_json oidc "$BASE_URL/.well-known/openid-configuration"
request_public_json oauth "$BASE_URL/.well-known/oauth-authorization-server"
for metadata in oidc oauth; do
  jq -e \
    --arg issuer "$BASE_URL" \
    --arg grant "urn:ietf:params:oauth:grant-type:jwt-bearer" \
    --arg profile "urn:ietf:params:oauth:grant-profile:id-jag" '
      .issuer == $issuer and
      (.grant_types_supported | index($grant) != null) and
      (.authorization_grant_profiles_supported == [$profile])
    ' "$WORK/$metadata.body" >/dev/null ||
    fail "$metadata metadata does not advertise the configured EMA profile"
done
pass "public CloudFront OIDC/OAuth metadata consistently advertises EMA"

export EMA_ID_JAG_AUDIENCE="$BASE_URL"
export EMA_ID_JAG_RESOURCE="$RESOURCE"
export EMA_ID_JAG_SCOPE="$SCOPE"
export EMA_ID_JAG_EXPECTED_ISSUER="$IDP_ISSUER"
export EMA_ID_JAG_EXPECTED_TENANT="$IDP_TENANT"
export EMA_ID_JAG_EXPECTED_CLIENT_ID="$ASSERTION_CLIENT_ID"
printf '%s\n' "$ID_JAG_COMMAND" >"$WORK/acquire-id-jag.sh"
chmod 0600 "$WORK/acquire-id-jag.sh"
if ! bash "$WORK/acquire-id-jag.sh" >"$WORK/assertion.jwt" 2>"$WORK/id-jag-command.stderr"; then
  fail "EMA_ID_JAG_COMMAND failed; captured output was destroyed"
fi
[[ "$(wc -c <"$WORK/assertion.jwt")" -le 131072 ]] ||
  fail "ID-JAG exceeds the 128 KiB acceptance limit"

python3 - \
  "$WORK/assertion.jwt" "$WORK/assertion-meta.json" "$BASE_URL" \
  "$IDP_ISSUER" "$IDP_TENANT" "$ASSERTION_CLIENT_ID" "$ID_JAG_ALG" \
  "$RESOURCE" "$SCOPE" <<'PY'
import base64
import json
import sys
from pathlib import Path

try:
    source, output, audience, issuer, tenant, client_id, algorithm, resource, scope = sys.argv[1:]
    token = Path(source).read_text(encoding="utf-8").strip()
    if any(character.isspace() for character in token):
        raise ValueError
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        raise ValueError

    def decode(segment):
        padding = "=" * (-len(segment) % 4)
        return json.loads(base64.urlsafe_b64decode(segment + padding))

    header = decode(parts[0])
    claims = decode(parts[1])
    if header.get("typ") != "oauth-id-jag+jwt" or header.get("alg") != algorithm:
        raise ValueError
    aud = claims.get("aud")
    audiences = aud if isinstance(aud, list) else [aud]
    if audiences != [audience]:
        raise ValueError
    if claims.get("iss") != issuer or claims.get("client_id") != client_id:
        raise ValueError
    if tenant:
        if claims.get("tenant") != tenant:
            raise ValueError
    elif "tenant" in claims:
        raise ValueError
    resources = claims.get("resource")
    resources = resources if isinstance(resources, list) else [resources]
    if resource not in resources:
        raise ValueError
    requested_scopes = set(scope.split())
    granted_scopes = set(str(claims.get("scope", "")).split())
    if not requested_scopes or not requested_scopes.issubset(granted_scopes):
        raise ValueError
    if claims.get("act") is not None:
        raise ValueError
    details = claims.get("authorization_details")
    if details not in (None, []):
        raise ValueError
    if claims.get("cnf") is not None:
        raise ValueError
    for required in ("sub", "jti", "exp", "iat"):
        if required not in claims:
            raise ValueError
    Path(output).write_text(
        json.dumps(
            {
                "alg": algorithm,
                "has_kid": isinstance(header.get("kid"), str) and bool(header["kid"]),
                "resource_bound": True,
                "scope_bound": True,
                "proof_bound": False,
            },
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
except Exception:
    print("ID-JAG failed strict profile shape validation", file=sys.stderr)
    raise SystemExit(1)
PY
pass "$SOURCE_LABEL acquisition command returned a strict resource-bound ID-JAG"

python3 - "$CLIENT_ID" "$CLIENT_SECRET_FILE" "$WORK/token.headers" <<'PY'
import base64
import sys
from pathlib import Path

client_id, secret_file, output = sys.argv[1:]
secret = Path(secret_file).read_text(encoding="utf-8").rstrip("\r\n")
if not secret or "\n" in secret or "\r" in secret:
    raise SystemExit("client secret file must contain exactly one non-empty value")
encoded = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
Path(output).write_text(
    f"authorization: Basic {encoded}\n"
    "content-type: application/x-www-form-urlencoded\n"
    "accept: application/json\n",
    encoding="utf-8",
)
PY

python3 - "$WORK/assertion.jwt" "$WORK/token.form" "$RESOURCE" "$SCOPE" <<'PY'
import sys
import urllib.parse
from pathlib import Path

assertion_file, output, resource, scope = sys.argv[1:]
body = urllib.parse.urlencode(
    {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": Path(assertion_file).read_text(encoding="utf-8").strip(),
        "resource": resource,
        "scope": scope,
    }
)
Path(output).write_text(body, encoding="utf-8")
PY

curl -sS --proto '=https' --connect-timeout 10 --max-time 60 \
  -X POST -H "@$WORK/token.headers" --data-binary "@$WORK/token.form" \
  -D "$WORK/token.headers.out" -o "$WORK/token.body" \
  -w '%{http_code}' "$BASE_URL/token" >"$WORK/token.status"
[[ "$(http_status token)" == "200" ]] ||
  fail "EMA token exchange returned HTTP $(http_status token)"
assert_cloudfront "$WORK/token.headers.out"
assert_no_store "$WORK/token.headers.out"
jq -e '
  .access_token | type == "string" and length > 0
' "$WORK/token.body" >/dev/null || fail "EMA response did not contain an access token"
jq -e \
  --arg resource "$RESOURCE" \
  --argjson requested_scopes "$(jq -cn --arg scope "$SCOPE" '$scope | split(" ") | map(select(length > 0)) | sort')" '
    .resource == $resource and
    ((.scope | split(" ") | map(select(length > 0)) | sort) == $requested_scopes) and
    (.token_type == "Bearer") and
    (.refresh_token == null) and
    (.id_token == null)
  ' "$WORK/token.body" >/dev/null ||
  fail "EMA response resource/scope/token shape is invalid"
pass "public /token issued a no-store, single-resource EMA access token"

request_public_json jwks "$BASE_URL/jwks.json"
python3 - \
  "$WORK/token.body" "$WORK/jwks.body" "$WORK/access-meta.json" \
  "$BASE_URL" "$RESOURCE" "$SCOPE" "$CLIENT_ID" <<'PY'
import json
import sys
from pathlib import Path

import jwt

try:
    response_file, jwks_file, output, issuer, resource, scope, client_id = sys.argv[1:]
    response = json.loads(Path(response_file).read_text(encoding="utf-8"))
    token = response["access_token"]
    header = jwt.get_unverified_header(token)
    if header.get("alg") != "ES256" or header.get("typ") != "at+jwt":
        raise ValueError
    keys = [
        key for key in json.loads(Path(jwks_file).read_text(encoding="utf-8")).get("keys", [])
        if key.get("kid") == header.get("kid") and key.get("alg") in (None, "ES256")
    ]
    if len(keys) != 1:
        raise ValueError
    claims = jwt.decode(
        token,
        jwt.PyJWK.from_dict(keys[0]).key,
        algorithms=["ES256"],
        audience=resource,
        issuer=issuer,
        options={
            "require": [
                "iss", "sub", "aud", "exp", "iat", "jti", "client_id",
                "scope",
            ]
        },
    )
    audiences = claims.get("aud")
    audiences = audiences if isinstance(audiences, list) else [audiences]
    if audiences != [resource] or claims.get("client_id") != client_id:
        raise ValueError
    namespace = claims.get("https://a-auth.com/c")
    if not isinstance(namespace, dict):
        raise ValueError
    if namespace.get("sub_type") != "user" or namespace.get("auth_grant") != "id-jag":
        raise ValueError
    if set(claims.get("scope", "").split()) != set(scope.split()):
        raise ValueError
    Path(output).write_text(
        json.dumps(
            {
                "alg": "ES256",
                "typ": "at+jwt",
                "audience_verified": True,
                "scope_verified": True,
                "subject_type": "user",
                "proof_bound": False,
                "token_type": response["token_type"],
                "expires_in": response["expires_in"],
            },
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
except Exception:
    print("access token signature or claims validation failed", file=sys.stderr)
    raise SystemExit(1)
PY
pass "live JWKS independently verified the ES256 access token and exact audience/scope"

curl -sS --proto '=https' --connect-timeout 10 --max-time 60 \
  -X POST -H "@$WORK/token.headers" --data-binary "@$WORK/token.form" \
  -D "$WORK/replay.headers" -o "$WORK/replay.body" \
  -w '%{http_code}' "$BASE_URL/token" >"$WORK/replay.status"
[[ "$(http_status replay)" == "400" ]] ||
  fail "ID-JAG replay returned HTTP $(http_status replay), expected 400"
assert_cloudfront "$WORK/replay.headers"
assert_no_store "$WORK/replay.headers"
jq -e '.error == "invalid_grant"' "$WORK/replay.body" >/dev/null ||
  fail "ID-JAG replay did not return invalid_grant"
pass "the same $SOURCE_LABEL ID-JAG was rejected as a no-store replay"

rs_unauth_args=(
  -sS --proto '=https' --connect-timeout 10 --max-time 60
  -X "$RS_VERIFY_METHOD" -H "accept: application/json"
  -D "$WORK/rs-unauth.headers" -o "$WORK/rs-unauth.body"
  -w '%{http_code}' "$RS_VERIFY_URL"
)
if [[ "$RS_VERIFY_METHOD" == "POST" ]]; then
  rs_unauth_args=(-H "content-type: application/json" --data-binary "@$RS_REQUEST_FILE" "${rs_unauth_args[@]}")
fi
curl "${rs_unauth_args[@]}" >"$WORK/rs-unauth.status"
[[ "$(http_status rs-unauth)" == "401" ]] ||
  fail "$SOURCE_LABEL RS verifier without a token returned HTTP $(http_status rs-unauth), expected 401"
pass "$SOURCE_LABEL RS verifier rejects the same request without a bearer token"

python3 - "$WORK/token.body" "$WORK/rs.headers" <<'PY'
import json
import sys
from pathlib import Path

response_file, output = sys.argv[1:]
token = json.loads(Path(response_file).read_text(encoding="utf-8"))["access_token"]
Path(output).write_text(
    f"authorization: Bearer {token}\naccept: application/json\n",
    encoding="utf-8",
)
PY
rs_args=(
  -sS --proto '=https' --connect-timeout 10 --max-time 60
  -X "$RS_VERIFY_METHOD" -H "@$WORK/rs.headers"
  -D "$WORK/rs.headers.out" -o "$WORK/rs.body"
  -w '%{http_code}' "$RS_VERIFY_URL"
)
if [[ "$RS_VERIFY_METHOD" == "POST" ]]; then
  rs_args=(-H "content-type: application/json" --data-binary "@$RS_REQUEST_FILE" "${rs_args[@]}")
fi
curl "${rs_args[@]}" >"$WORK/rs.status"
[[ "$(http_status rs)" == "$RS_EXPECTED_STATUS" ]] ||
  fail "$SOURCE_LABEL RS verifier returned HTTP $(http_status rs), expected $RS_EXPECTED_STATUS"
pass "$SOURCE_LABEL RS verifier accepted the audience/scope-bound access token"

curl -sS --proto '=https' --connect-timeout 10 --max-time 60 \
  -X GET -H "@$WORK/rs.headers" \
  -D "$WORK/rs-scope-deny.headers" -o "$WORK/rs-scope-deny.body" \
  -w '%{http_code}' "$RS_SCOPE_DENY_URL" >"$WORK/rs-scope-deny.status"
[[ "$(http_status rs-scope-deny)" == "403" ]] ||
  fail "$SOURCE_LABEL RS scope-negative route returned HTTP $(http_status rs-scope-deny), expected 403"
pass "$SOURCE_LABEL RS verifier rejects the token on a route requiring an ungranted scope"

FINISHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
jq -n \
  --arg agent_auth_commit "${DEPLOYED_COMMIT,,}" \
  --arg script_commit "$SCRIPT_COMMIT" \
  --arg script_blob "$SCRIPT_BLOB" \
  --arg evidence_kind "$EVIDENCE_KIND" \
  --arg deployment_kind "$DEPLOYMENT_KIND" \
  --arg stack_id "$STACK_ID" \
  --arg function_arn "$FUNCTION_ARN" \
  --arg function_code_sha256 "$FUNCTION_CODE_SHA256" \
  --arg bootstrap_sha256 "$BOOTSTRAP_SHA256" \
  --arg issuer "$BASE_URL" \
  --arg agent_auth_tenant "$AGENT_AUTH_TENANT" \
  --arg started_at "$STARTED_AT" \
  --arg finished_at "$FINISHED_AT" \
  --arg idp_product "$IDP_PRODUCT" \
  --arg idp_version "$IDP_VERSION" \
  --arg client_product "$CLIENT_PRODUCT" \
  --arg client_version "$CLIENT_VERSION" \
  --arg policy_id "$POLICY_ID" \
  --arg policy_attestation_sha256 "$POLICY_ATTESTATION_SHA256" \
  --arg idp_issuer "$IDP_ISSUER" \
  --arg idp_tenant "$IDP_TENANT" \
  --arg assertion_client_id "$ASSERTION_CLIENT_ID" \
  --arg resource "$RESOURCE" \
  --arg scope "$SCOPE" \
  --arg rs_verifier "$RS_VERIFY_URL" \
  --arg rs_scope_deny_url "$RS_SCOPE_DENY_URL" \
  --arg simulator_stack_id "$SIMULATOR_STACK_ID" \
  --arg simulator_commit "$SIMULATOR_COMMIT" \
  --arg simulator_issuer_function_arn "$SIMULATOR_ISSUER_FUNCTION_ARN" \
  --arg simulator_issuer_code_sha256 "$SIMULATOR_ISSUER_CODE_SHA256" \
  --arg simulator_resource_function_arn "$SIMULATOR_RESOURCE_FUNCTION_ARN" \
  --arg simulator_resource_code_sha256 "$SIMULATOR_RESOURCE_CODE_SHA256" \
  --arg source_label "$SOURCE_LABEL" \
  --argjson assertion_meta "$(cat "$WORK/assertion-meta.json")" \
  --argjson access_meta "$(cat "$WORK/access-meta.json")" \
  --argjson token_status "$(http_status token)" \
  --argjson replay_status "$(http_status replay)" \
  --argjson rs_unauth_status "$(http_status rs-unauth)" \
  --argjson rs_status "$(http_status rs)" \
  --argjson rs_scope_deny_status "$(http_status rs-scope-deny)" '
  {
    schema: "agent-auth-ema-evidence-v2",
    evidence_kind: $evidence_kind,
    agent_auth_commit: $agent_auth_commit,
    script: {
      commit: $script_commit,
      blob: $script_blob
    },
    deployment: {
      kind: $deployment_kind,
      issuer: $issuer,
      tenant: $agent_auth_tenant,
      stack_id: $stack_id,
      function_arn: $function_arn,
      function_code_sha256: $function_code_sha256,
      bootstrap_sha256: $bootstrap_sha256
    },
    executed_at: {
      started: $started_at,
      finished: $finished_at
    },
    external_systems: {
      idp: {
        product: $idp_product,
        version: $idp_version,
        issuer: $idp_issuer,
        issuer_tenant: (if $idp_tenant == "" then null else $idp_tenant end),
        simulated: ($evidence_kind == "simulator")
      },
      client: {
        product: $client_product,
        version: $client_version,
        assertion_client_id: $assertion_client_id
      },
      rs_verifier: $rs_verifier
    },
    simulator:
      (if $evidence_kind == "simulator" then {
        transparent_non_third_party_evidence: true,
        stack_id: $simulator_stack_id,
        commit: $simulator_commit,
        issuer_function: {
          arn: $simulator_issuer_function_arn,
          code_sha256: $simulator_issuer_code_sha256
        },
        resource_function: {
          arn: $simulator_resource_function_arn,
          code_sha256: $simulator_resource_code_sha256
        }
      } else null end),
    strict_profile_config: {
      policy_id: $policy_id,
      deployment_attestation_sha256: $policy_attestation_sha256,
      resource: $resource,
      scope: $scope,
      allow_legacy_missing_resource: false,
      assertion: $assertion_meta
    },
    results: {
      token: {
        http_status: $token_status,
        cache_control: "no-store",
        independent_verification: $access_meta
      },
      replay: {
        http_status: $replay_status,
        error: "invalid_grant",
        cache_control: "no-store"
      },
      resource_server: {
        unauthenticated_http_status: $rs_unauth_status,
        http_status: $rs_status,
        accepted: true,
        scope_negative_url: $rs_scope_deny_url,
        scope_negative_http_status: $rs_scope_deny_status
      }
    },
    redacted_wire_transcript: [
      "GET OIDC metadata -> 200 via CloudFront; EMA advertised",
      "GET OAuth metadata -> 200 via CloudFront; EMA advertised",
      ($source_label + " IdP/client -> ID-JAG captured but not printed"),
      "POST /token -> 200 no-store; access token captured but not printed",
      "GET /jwks.json -> 200 via CloudFront; ES256 signature verified",
      "POST /token replay -> 400 invalid_grant no-store",
      "RS verifier request without token -> 401",
      "RS verifier request -> expected 2xx; authorization value not printed",
      "RS scope-negative request -> 403; authorization value not printed"
    ]
  }'
