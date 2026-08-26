#!/usr/bin/env bash
# Live acceptance for the managed SaaS CloudFront-to-origin trust boundary.
#
# This script is read-only. It proves that:
# - CloudFront overwrites viewer-supplied origin-auth headers;
# - direct API Gateway requests cannot select a tenant without a managed secret;
# - both rotation slots are accepted by primary and standby runtimes; and
# - the active/inactive Region fence still runs after edge authentication.
#
# Usage:
#   ISSUER=https://t1.example.com EXPECTED_COMMIT=<full git sha> \
#   AWS_PROFILE=default ./e2e/saas_origin_auth.sh
set -euo pipefail
umask 077

ISSUER="${ISSUER:?ISSUER is required}"
EXPECTED_COMMIT="${EXPECTED_COMMIT:?EXPECTED_COMMIT is required}"
AWS_PROFILE_NAME="${AWS_PROFILE:-default}"
PRIMARY_REGION="${PRIMARY_REGION:-us-east-1}"
STANDBY_REGION="${STANDBY_REGION:-us-west-2}"
PRIMARY_STACK="${PRIMARY_STACK:-AgentAuthSaas}"
STANDBY_STACK="${STANDBY_STACK:-AgentAuthSaasStandby}"
EVIDENCE_FILE="${EVIDENCE_FILE:-}"

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

for command in aws cmp curl date git jq python3 sha256sum unzip; do
  command -v "$command" >/dev/null || fail "missing command: $command"
done
[[ "$EXPECTED_COMMIT" =~ ^[0-9a-f]{40}$ ]] ||
  fail "EXPECTED_COMMIT must be a full lowercase Git SHA"
[[ "$PRIMARY_REGION" == "us-east-1" && "$STANDBY_REGION" == "us-west-2" ]] ||
  fail "qualifying SaaS evidence requires the reviewed us-east-1/us-west-2 Region pair"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ "$(git -C "$REPO_ROOT" rev-parse HEAD)" == "$EXPECTED_COMMIT" ]] ||
  fail "local HEAD must equal EXPECTED_COMMIT"
[[ -z "$(git -C "$REPO_ROOT" status --porcelain \
  --untracked-files=normal --ignore-submodules=dirty)" ]] ||
  fail "qualifying evidence requires a clean worktree"
LOCAL_LAMBDA_ASSET="$REPO_ROOT/target/lambda/agent-auth-lambda"
LOCAL_BOOTSTRAP="$LOCAL_LAMBDA_ASSET/bootstrap"
LOCAL_PROVENANCE="$LOCAL_LAMBDA_ASSET/deployment-provenance.json"
[[ -f "$LOCAL_BOOTSTRAP" && -f "$LOCAL_PROVENANCE" ]] ||
  fail "build exact-commit Lambda artifacts before running live acceptance"
LOCAL_BOOTSTRAP_SHA256="$(sha256sum "$LOCAL_BOOTSTRAP" | cut -d' ' -f1)"
jq -e --arg commit "$EXPECTED_COMMIT" --arg sha "$LOCAL_BOOTSTRAP_SHA256" '
  (keys | sort) == (["bootstrap_sha256", "commit", "schema"] | sort)
  and .schema == "agent-auth-lambda-provenance-v1"
  and .commit == $commit
  and .bootstrap_sha256 == $sha
' "$LOCAL_PROVENANCE" >/dev/null ||
  fail "local Lambda provenance does not bind EXPECTED_COMMIT and bootstrap"

ISSUER="${ISSUER%/}"
read -r TENANT_HOST SAAS_ZONE CONTROL_HOST < <(
  ISSUER="$ISSUER" python3 - <<'PY'
import os
from urllib.parse import urlsplit

parsed = urlsplit(os.environ["ISSUER"])
try:
    port = parsed.port
except ValueError:
    raise SystemExit("ISSUER has an invalid port")
host = parsed.hostname
if (
    parsed.scheme != "https"
    or host is None
    or parsed.netloc != host
    or port is not None
    or parsed.path != ""
    or parsed.query != ""
    or parsed.fragment != ""
):
    raise SystemExit("ISSUER must be an exact HTTPS tenant origin")
tenant, separator, zone = host.partition(".")
if not separator or not tenant or not zone or tenant == "c":
    raise SystemExit("ISSUER host must contain a tenant label and SaaS zone")
print(host, zone, f"c.{zone}")
PY
)

WORK="$(mktemp -d)"
chmod 700 "$WORK"
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  rm -rf "$WORK"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

PRIMARY_AWS=(aws --profile "$AWS_PROFILE_NAME" --region "$PRIMARY_REGION")
STANDBY_AWS=(aws --profile "$AWS_PROFILE_NAME" --region "$STANDBY_REGION")

stack_output() {
  local file="$1" key="$2"
  jq -er --arg key "$key" '
    [.Stacks[0].Outputs[] | select(.OutputKey == $key) | .OutputValue]
    | if length == 1 then .[0] else error("missing stack output " + $key) end
  ' "$file"
}

describe_stack() {
  local region="$1" stack="$2" output="$3"
  aws cloudformation describe-stacks \
    --profile "$AWS_PROFILE_NAME" \
    --region "$region" \
    --stack-name "$stack" \
    --output json >"$output"
  jq -e '
    .Stacks[0].StackStatus == "CREATE_COMPLETE"
    or .Stacks[0].StackStatus == "UPDATE_COMPLETE"
  ' "$output" >/dev/null || fail "$stack is not in a stable complete state"
}

auth_function_name() {
  local region="$1" stack="$2"
  aws cloudformation list-stack-resources \
    --profile "$AWS_PROFILE_NAME" \
    --region "$region" \
    --stack-name "$stack" \
    --output json |
    jq -er '
      [.StackResourceSummaries[]
       | select(
           .ResourceType == "AWS::Lambda::Function"
           and (.LogicalResourceId | startswith("AuthFn"))
         )
       | .PhysicalResourceId]
      | unique
      | if length == 1 then .[0] else error("expected exactly one AuthFn") end
    '
}

validate_deployed_artifact() {
  local region="$1" function_name="$2" label="$3"
  local function_json="$WORK/$label-function.json"
  local zip_file="$WORK/$label-function.zip"
  local manifest="$WORK/$label-deployment-provenance.json"
  local bootstrap="$WORK/$label-bootstrap"
  local downloaded_code_sha256 deployed_code_sha256 deployed_bootstrap_sha256

  aws lambda get-function \
    --profile "$AWS_PROFILE_NAME" \
    --region "$region" \
    --function-name "$function_name" \
    --output json >"$function_json"
  curl -fsS --proto '=https' --connect-timeout 10 --max-time 120 \
    "$(jq -er '.Code.Location' "$function_json")" -o "$zip_file"
  downloaded_code_sha256="$(
    python3 - "$zip_file" <<'PY'
import base64
import hashlib
import pathlib
import sys

print(base64.b64encode(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).digest()).decode())
PY
  )"
  deployed_code_sha256="$(jq -er '.Configuration.CodeSha256' "$function_json")"
  [[ "$downloaded_code_sha256" == "$deployed_code_sha256" ]] ||
    fail "$label downloaded Lambda package does not match AWS CodeSha256"
  unzip -p "$zip_file" deployment-provenance.json >"$manifest" ||
    fail "$label deployed Lambda package is missing deployment provenance"
  unzip -p "$zip_file" bootstrap >"$bootstrap" ||
    fail "$label deployed Lambda package is missing the Auth bootstrap"
  deployed_bootstrap_sha256="$(sha256sum "$bootstrap" | cut -d' ' -f1)"
  [[ "$deployed_bootstrap_sha256" == "$LOCAL_BOOTSTRAP_SHA256" ]] ||
    fail "$label deployed bootstrap differs from the exact local commit artifact"
  jq -e --arg commit "$EXPECTED_COMMIT" --arg sha "$deployed_bootstrap_sha256" '
    (keys | sort) == (["bootstrap_sha256", "commit", "schema"] | sort)
    and .schema == "agent-auth-lambda-provenance-v1"
    and .commit == $commit
    and .bootstrap_sha256 == $sha
  ' "$manifest" >/dev/null ||
    fail "$label deployed provenance does not bind the reviewed source artifact"
  jq '.Configuration | {
    commit: .Environment.Variables.AGENT_AUTH_DEPLOYMENT_COMMIT,
    revision: .Environment.Variables.AGENT_AUTH_ORIGIN_AUTH_REVISION,
    state: .State,
    last_update: .LastUpdateStatus,
    code_sha256: .CodeSha256
  }' "$function_json" >"$WORK/$label-runtime.json"
}

https_host() {
  local url="$1"
  URL="$url" python3 - <<'PY'
import os
from urllib.parse import urlsplit

parsed = urlsplit(os.environ["URL"])
if parsed.scheme != "https" or not parsed.hostname:
    raise SystemExit("stack ApiUrl is not HTTPS")
print(parsed.hostname)
PY
}

write_header_file() {
  local host="$1" secret_file="$2" slot="$3" output="$4"
  python3 - "$host" "$secret_file" "$slot" "$output" <<'PY'
import pathlib
import sys

host, secret_file, slot, output = sys.argv[1:]
secret = pathlib.Path(secret_file).read_text().rstrip("\n")
if len(secret) < 32:
    raise SystemExit("origin credential is unexpectedly short")
pathlib.Path(output).write_text(
    f"X-Forwarded-Host: {host}\n"
    f"X-Agent-Auth-Origin-Auth-{slot}: {secret}\n"
)
PY
  chmod 600 "$output"
}

request_status() {
  local url="$1" output="$2"
  shift 2
  curl -sS --proto '=https' --max-time 30 \
    -o "$output" -w '%{http_code}' "$@" "$url"
}

describe_stack "$PRIMARY_REGION" "$PRIMARY_STACK" "$WORK/primary-stack.json"
describe_stack "$STANDBY_REGION" "$STANDBY_STACK" "$WORK/standby-stack.json"
PRIMARY_COMMIT="$(stack_output "$WORK/primary-stack.json" DeploymentCommit)"
STANDBY_COMMIT="$(stack_output "$WORK/standby-stack.json" DeploymentCommit)"
[[ "$PRIMARY_COMMIT" == "$EXPECTED_COMMIT" && "$STANDBY_COMMIT" == "$EXPECTED_COMMIT" ]] ||
  fail "primary and standby must both run EXPECTED_COMMIT"

PRIMARY_API="$(stack_output "$WORK/primary-stack.json" ApiUrl)"
STANDBY_API="$(stack_output "$WORK/standby-stack.json" ApiUrl)"
PRIMARY_API="${PRIMARY_API%/}"
STANDBY_API="${STANDBY_API%/}"
PRIMARY_API_HOST="$(https_host "$PRIMARY_API")"
STANDBY_API_HOST="$(https_host "$STANDBY_API")"
[[ "$PRIMARY_API_HOST" != "$STANDBY_API_HOST" ]] ||
  fail "primary and standby API origins must differ"

DISTRIBUTION_ID="$(stack_output "$WORK/primary-stack.json" FailoverDistributionId)"
aws cloudfront get-distribution-config \
  --profile "$AWS_PROFILE_NAME" \
  --id "$DISTRIBUTION_ID" \
  --output json >"$WORK/distribution.json"

PRIMARY_SECRET_NAME="$PRIMARY_STACK/cloudfront-origin-auth"
SECONDARY_SECRET_NAME="$PRIMARY_STACK/cloudfront-origin-auth-secondary"
"${PRIMARY_AWS[@]}" secretsmanager get-secret-value \
  --secret-id "$PRIMARY_SECRET_NAME" \
  --query SecretString --output text >"$WORK/primary-secret"
"${PRIMARY_AWS[@]}" secretsmanager get-secret-value \
  --secret-id "$SECONDARY_SECRET_NAME" \
  --query SecretString --output text >"$WORK/secondary-secret"
"${STANDBY_AWS[@]}" secretsmanager get-secret-value \
  --secret-id "$PRIMARY_SECRET_NAME" \
  --query SecretString --output text >"$WORK/standby-primary-secret"
"${STANDBY_AWS[@]}" secretsmanager get-secret-value \
  --secret-id "$SECONDARY_SECRET_NAME" \
  --query SecretString --output text >"$WORK/standby-secondary-secret"
chmod 600 "$WORK"/*secret
cmp -s "$WORK/primary-secret" "$WORK/standby-primary-secret" ||
  fail "primary origin credential replica does not match"
cmp -s "$WORK/secondary-secret" "$WORK/standby-secondary-secret" ||
  fail "secondary origin credential replica does not match"
cmp -s "$WORK/primary-secret" "$WORK/secondary-secret" &&
  fail "primary and secondary origin credentials must be distinct"

PRIMARY_FN="$(auth_function_name "$PRIMARY_REGION" "$PRIMARY_STACK")"
STANDBY_FN="$(auth_function_name "$STANDBY_REGION" "$STANDBY_STACK")"
validate_deployed_artifact "$PRIMARY_REGION" "$PRIMARY_FN" primary
validate_deployed_artifact "$STANDBY_REGION" "$STANDBY_FN" standby
REVISION="$(jq -er '.revision' "$WORK/primary-runtime.json")"
jq -e --arg commit "$EXPECTED_COMMIT" --arg revision "$REVISION" '
  .commit == $commit and .revision == $revision
  and .state == "Active" and .last_update == "Successful"
' "$WORK/primary-runtime.json" >/dev/null ||
  fail "primary runtime is not active on the expected commit and revision"
jq -e --arg commit "$EXPECTED_COMMIT" --arg revision "$REVISION" '
  .commit == $commit and .revision == $revision
  and .state == "Active" and .last_update == "Successful"
' "$WORK/standby-runtime.json" >/dev/null ||
  fail "standby runtime is not active on the expected commit and revision"

python3 - "$WORK/distribution.json" "$TENANT_HOST" \
  "$PRIMARY_API_HOST" <<'PY'
import json
import pathlib
import re
import sys

config_file, tenant, api_host = sys.argv[1:]
document = json.loads(pathlib.Path(config_file).read_text())
config = document["DistributionConfig"]
if not config.get("Enabled") or tenant not in config.get("Aliases", {}).get("Items", []):
    raise SystemExit("tenant issuer is not an enabled distribution alias")
origins = [
    origin for origin in config["Origins"]["Items"]
    if origin["DomainName"] == api_host
]
if len(origins) != 1:
    raise SystemExit("primary API is not the unique distribution origin")
headers = {
    item["HeaderName"].lower(): item["HeaderValue"]
    for item in origins[0].get("OriginCustomHeaders", {}).get("Items", [])
}
if any(name.startswith("x-agent-auth-origin-auth") for name in headers):
    raise SystemExit("distribution configuration exposes an origin-auth value")
associations = config["DefaultCacheBehavior"].get("LambdaFunctionAssociations", {})
items = associations.get("Items", [])
origin_request = [
    item for item in items if item.get("EventType") == "origin-request"
]
if len(origin_request) != 1:
    raise SystemExit("default API behavior must have one origin-request Lambda@Edge")
if not re.fullmatch(
    r"arn:aws:lambda:us-east-1:[0-9]{12}:function:[^:]+:[1-9][0-9]*",
    origin_request[0].get("LambdaFunctionARN", ""),
):
    raise SystemExit("origin authentication must use an immutable Lambda@Edge version")
PY

DISCOVERY_PATH="/.well-known/openid-configuration"
PUBLIC_STATUS="$(
  request_status "$ISSUER$DISCOVERY_PATH" "$WORK/public.json" \
    -H 'X-Forwarded-Host: attacker.invalid' \
    -H 'X-Agent-Auth-Origin-Auth: attacker' \
    -H 'X-Agent-Auth-Origin-Auth-Primary: attacker' \
    -H 'X-Agent-Auth-Origin-Auth-Secondary: attacker'
)"
[[ "$PUBLIC_STATUS" == "200" ]] ||
  fail "CloudFront request with viewer-supplied spoof headers returned HTTP $PUBLIC_STATUS"
jq -e --arg issuer "$ISSUER" '.issuer == $issuer' "$WORK/public.json" >/dev/null ||
  fail "CloudFront did not preserve the exact tenant issuer after overwriting viewer headers"

printf 'X-Forwarded-Host: %s\n' "$TENANT_HOST" >"$WORK/missing.headers"
printf 'X-Forwarded-Host: %s\nX-Agent-Auth-Origin-Auth: wrong\nX-Agent-Auth-Origin-Auth-Primary: wrong\nX-Agent-Auth-Origin-Auth-Secondary: wrong\n' \
  "$TENANT_HOST" >"$WORK/wrong.headers"
write_header_file "$TENANT_HOST" "$WORK/primary-secret" Primary "$WORK/primary.headers"
write_header_file "$TENANT_HOST" "$WORK/secondary-secret" Secondary "$WORK/secondary.headers"

for region in primary standby; do
  if [[ "$region" == "primary" ]]; then
    api="$PRIMARY_API"
  else
    api="$STANDBY_API"
  fi
  missing_status="$(
    request_status "$api$DISCOVERY_PATH" "$WORK/$region-missing.json" \
      -H "@$WORK/missing.headers"
  )"
  wrong_status="$(
    request_status "$api$DISCOVERY_PATH" "$WORK/$region-wrong.json" \
      -H "@$WORK/wrong.headers"
  )"
  [[ "$missing_status" == "403" && "$wrong_status" == "403" ]] ||
    fail "$region direct origin accepted a missing or wrong edge credential"
done

PRIMARY_SLOT_PRIMARY_STATUS="$(
  request_status "$PRIMARY_API$DISCOVERY_PATH" "$WORK/primary-primary.json" \
    -H "@$WORK/primary.headers"
)"
PRIMARY_SLOT_SECONDARY_STATUS="$(
  request_status "$PRIMARY_API$DISCOVERY_PATH" "$WORK/primary-secondary.json" \
    -H "@$WORK/secondary.headers"
)"
STANDBY_SLOT_PRIMARY_STATUS="$(
  request_status "$STANDBY_API$DISCOVERY_PATH" "$WORK/standby-primary.json" \
    -H "@$WORK/primary.headers"
)"
STANDBY_SLOT_SECONDARY_STATUS="$(
  request_status "$STANDBY_API$DISCOVERY_PATH" "$WORK/standby-secondary.json" \
    -H "@$WORK/secondary.headers"
)"
[[ "$PRIMARY_SLOT_PRIMARY_STATUS" == "$PRIMARY_SLOT_SECONDARY_STATUS" ]] ||
  fail "primary runtime does not accept both rotation slots equivalently"
[[ "$STANDBY_SLOT_PRIMARY_STATUS" == "$STANDBY_SLOT_SECONDARY_STATUS" ]] ||
  fail "standby runtime does not accept both rotation slots equivalently"
if [[ "$PRIMARY_SLOT_PRIMARY_STATUS" == "200" && "$STANDBY_SLOT_PRIMARY_STATUS" == "503" ]]; then
  ACTIVE_REGION="$PRIMARY_REGION"
  ACTIVE_API="$PRIMARY_API"
elif [[ "$PRIMARY_SLOT_PRIMARY_STATUS" == "503" && "$STANDBY_SLOT_PRIMARY_STATUS" == "200" ]]; then
  ACTIVE_REGION="$STANDBY_REGION"
  ACTIVE_API="$STANDBY_API"
else
  fail "expected exactly one active Region after successful edge authentication"
fi

for host_kind in parent control; do
  if [[ "$host_kind" == "parent" ]]; then
    rejected_host="$SAAS_ZONE"
  else
    rejected_host="$CONTROL_HOST"
  fi
  write_header_file "$rejected_host" "$WORK/primary-secret" Primary \
    "$WORK/$host_kind.headers"
  status="$(
    request_status "$ACTIVE_API$DISCOVERY_PATH" "$WORK/$host_kind.json" \
      -H "@$WORK/$host_kind.headers"
  )"
  [[ "$status" == "400" ]] ||
    fail "authenticated direct origin treated the SaaS $host_kind host as a tenant"
done

PRIMARY_API_SHA256="$(printf '%s' "$PRIMARY_API_HOST" | sha256sum | cut -d' ' -f1)"
STANDBY_API_SHA256="$(printf '%s' "$STANDBY_API_HOST" | sha256sum | cut -d' ' -f1)"
OBSERVED_AT="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
EVIDENCE="$(
  jq -n \
    --arg commit "$EXPECTED_COMMIT" \
    --arg observed_at "$OBSERVED_AT" \
    --arg issuer_host "$TENANT_HOST" \
    --arg revision "$REVISION" \
    --arg active_region "$ACTIVE_REGION" \
    --arg primary_api_sha256 "$PRIMARY_API_SHA256" \
    --arg standby_api_sha256 "$STANDBY_API_SHA256" \
    '{
      schema_version: 1,
      issue: 151,
      deployment_commit: $commit,
      observed_at_utc: $observed_at,
      issuer_host: $issuer_host,
      origin_auth_revision: $revision,
      active_region: $active_region,
      sanitized_origins: {
        primary_api_host_sha256: $primary_api_sha256,
        standby_api_host_sha256: $standby_api_sha256
      },
      checks: {
        cloudfront_overwrites_viewer_headers: "pass",
        cloudfront_configuration_contains_no_origin_secret: "pass",
        deployed_primary_artifact_matches_reviewed_source: "pass",
        deployed_standby_artifact_matches_reviewed_source: "pass",
        missing_direct_origin_credential_rejected: "pass",
        wrong_direct_origin_credential_rejected: "pass",
        primary_slot_accepted_in_both_regions: "pass",
        secondary_slot_accepted_in_both_regions: "pass",
        exactly_one_region_admitted_after_edge_auth: "pass",
        parent_host_not_a_tenant: "pass",
        control_host_not_a_tenant: "pass",
        secret_replication_matches_without_secret_disclosure: "pass"
      },
      result: "pass"
    }'
)"
if [[ -n "$EVIDENCE_FILE" ]]; then
  printf '%s\n' "$EVIDENCE" >"$EVIDENCE_FILE"
  chmod 600 "$EVIDENCE_FILE"
fi
printf '%s\n' "$EVIDENCE"
