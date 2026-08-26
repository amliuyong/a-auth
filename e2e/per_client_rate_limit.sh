#!/usr/bin/env bash
# C10.7 live gate: authenticated per-client /token rate-limit isolation.
#
# The gate creates two temporary t1 SPIFFE JWT workload clients, proves both
# can mint a real token, deterministically exhausts only client A's DynamoDB
# bucket, then requires A=429 and B=200. PASS evidence is written only after
# every temporary client, trust binding, rate-limit row, and JWKS object has
# been removed and verified absent.
set -euo pipefail
set +x

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
STACK="${SAAS_STACK:-AgentAuthSaas}"
TENANT="${TENANT:-t1}"
EXPECTED_DEPLOYED_COMMIT="${EXPECTED_DEPLOYED_COMMIT:?set EXPECTED_DEPLOYED_COMMIT to the full deployed SHA}"
EVIDENCE_FILE="${EVIDENCE_FILE:-/tmp/agent-auth-c10-7-evidence-$(date -u +%Y%m%dT%H%M%SZ).json}"
SCOPE="kb:read"

for command in aws curl git jq python3 sha256sum; do
  command -v "$command" >/dev/null ||
    { echo "missing required command: $command" >&2; exit 1; }
done

pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

WORK="$(mktemp -d)"
RUN_ID="$(python3 -c 'import secrets; print(secrets.token_hex(6))')"
RESOURCE="https://c10-7-$RUN_ID.invalid"
CLIENT_A=""
CLIENT_B=""
BINDING_A="c10-7-a-$RUN_ID"
BINDING_B="c10-7-b-$RUN_ID"
TD_A="c10-7-a-$RUN_ID.spiffe.test"
TD_B="c10-7-b-$RUN_ID.spiffe.test"
BUNDLE_KEY="assets/c10-7-$RUN_ID.json"
FRONTEND_BUCKET=""
ADMIN_HEADER="$WORK/admin.headers"
CLEANED=0

tpk() {
  printf '%s\x1f%s' "$TENANT" "$1"
}

best_effort_cleanup() {
  set +e
  for binding in "$BINDING_A" "$BINDING_B"; do
    [[ -n "${TRUST_TABLE:-}" ]] &&
      aws dynamodb delete-item --profile "$PROFILE" --region "$REGION" \
        --table-name "$TRUST_TABLE" \
        --key "$(jq -cn --arg key "$(tpk "$binding")" \
          '{binding_id:{S:$key}}')" >/dev/null
  done
  for client in "$CLIENT_A" "$CLIENT_B"; do
    [[ -n "$client" && -n "${RATE_TABLE:-}" ]] &&
      aws dynamodb delete-item --profile "$PROFILE" --region "$REGION" \
        --table-name "$RATE_TABLE" \
        --key "$(jq -cn --arg key "$(tpk "$client")" '{key:{S:$key}}')" \
        >/dev/null
  done
  if [[ -s "$ADMIN_HEADER" ]]; then
    for client in "$CLIENT_A" "$CLIENT_B"; do
      [[ -n "$client" ]] &&
        curl -sS --proto '=https' --connect-timeout 5 --max-time 30 \
          -o /dev/null -X DELETE -H "@$ADMIN_HEADER" \
          "$API_URL/admin/clients/$client"
    done
  fi
  [[ -n "$FRONTEND_BUCKET" ]] &&
    aws s3 rm "s3://$FRONTEND_BUCKET/$BUNDLE_KEY" \
      --profile "$PROFILE" --region "$REGION" >/dev/null
  set -e
}

cleanup() {
  if [[ "$CLEANED" != "1" ]]; then
    best_effort_cleanup
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

stack_output() {
  local key="$1"
  jq -er --arg key "$key" '
    .Stacks[0].Outputs[]
    | select(.OutputKey == $key)
    | .OutputValue
  ' "$WORK/stack.json"
}

aws cloudformation describe-stacks \
  --stack-name "$STACK" --profile "$PROFILE" --region "$REGION" \
  --output json >"$WORK/stack.json"
[[ "$(jq -er '.Stacks[0].StackStatus' "$WORK/stack.json")" == "UPDATE_COMPLETE" ]] ||
  fail "$STACK is not UPDATE_COMPLETE"

DEPLOYED_COMMIT="$(stack_output DeploymentCommit)"
[[ "$DEPLOYED_COMMIT" == "$EXPECTED_DEPLOYED_COMMIT" &&
  "$DEPLOYED_COMMIT" =~ ^[0-9a-f]{40}$ ]] ||
  fail "deployed commit does not match EXPECTED_DEPLOYED_COMMIT"

HARNESS_COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD)"
[[ -z "$(git -C "$REPO_ROOT" status --porcelain)" ]] ||
  fail "live evidence requires a clean worktree"
git -C "$REPO_ROOT" merge-base --is-ancestor \
  "$DEPLOYED_COMMIT" "$HARNESS_COMMIT" ||
  fail "deployed commit is not an ancestor of the harness commit"
git -C "$REPO_ROOT" diff --quiet "$DEPLOYED_COMMIT..$HARNESS_COMMIT" -- \
  crates/http/src/ratelimit_gate.rs \
  crates/http/src/workload_flow.rs \
  crates/http/src/adapters/aws/authorization.rs \
  infra/lib/agent-auth-stack.ts ||
  fail "rate-limit runtime changed after the deployed commit"

CLIENTS_TABLE="$(stack_output ClientsTableName)"
TRUST_TABLE="$(stack_output WorkloadTrustTableName)"
RATE_TABLE="$(stack_output RateLimitTableName)"
AUTH_FN="$(stack_output AuthFnName)"

aws lambda get-function-configuration \
  --function-name "$AUTH_FN" --profile "$PROFILE" --region "$REGION" \
  --output json >"$WORK/auth.json"
jq -e --arg commit "$DEPLOYED_COMMIT" '
  .LastUpdateStatus == "Successful"
  and .Environment.Variables.AGENT_AUTH_DEPLOYMENT_COMMIT == $commit
  and .Environment.Variables.AGENT_AUTH_FORM == "saas"
  and (.Environment.Variables.AGENT_AUTH_ZONE | type == "string" and length > 0)
  and (.Environment.Variables.AGENT_AUTH_BOOTSTRAP_CONFIG_SECRET_ARN
    | type == "string" and length > 0)
' "$WORK/auth.json" >/dev/null ||
  fail "AuthFn runtime identity does not match the deployed stack"

ZONE="$(jq -er '.Environment.Variables.AGENT_AUTH_ZONE' "$WORK/auth.json")"
API_URL="https://$TENANT.$ZONE"
BOOTSTRAP_ARN="$(
  jq -er '.Environment.Variables.AGENT_AUTH_BOOTSTRAP_CONFIG_SECRET_ARN' \
    "$WORK/auth.json"
)"
aws secretsmanager get-secret-value \
  --secret-id "$BOOTSTRAP_ARN" --profile "$PROFILE" --region "$REGION" \
  --query SecretString --output text >"$WORK/bootstrap.json"
ADMIN_ARN="$(jq -er --arg tenant "$TENANT" \
  '.tenant_admin_secret_arns[$tenant]' "$WORK/bootstrap.json")"
aws secretsmanager get-secret-value \
  --secret-id "$ADMIN_ARN" --profile "$PROFILE" --region "$REGION" \
  --output json |
  jq -er '.SecretString | fromjson | .current.secret
    | select(type == "string" and length >= 16)' >"$WORK/admin.token"
chmod 0600 "$WORK/admin.token"
printf 'authorization: Bearer %s\n' "$(<"$WORK/admin.token")" >"$ADMIN_HEADER"
chmod 0600 "$ADMIN_HEADER"
rm -f "$WORK/admin.token" "$WORK/bootstrap.json"

curl -sS --proto '=https' --connect-timeout 5 --max-time 30 \
  "$API_URL/.well-known/openid-configuration" >"$WORK/discovery.json"
[[ "$(jq -er '.issuer' "$WORK/discovery.json")" == "$API_URL" ]] ||
  fail "tenant issuer is not ready"

aws cloudformation list-stack-resources \
  --stack-name "$STACK" --profile "$PROFILE" --region "$REGION" \
  --output json >"$WORK/resources.json"
FRONTEND_BUCKET="$(jq -er '
  [
    .StackResourceSummaries[]
    | select(
        .ResourceType == "AWS::S3::Bucket"
        and (.LogicalResourceId | startswith("FrontendSpaBucket"))
        and .ResourceStatus == "CREATE_COMPLETE"
      )
    | .PhysicalResourceId
  ]
  | unique
  | if length == 1 then .[0] else error("expected one frontend bucket") end
' "$WORK/resources.json")"

python3 - "$WORK/signing-key.pem" "$WORK/jwks.json" <<'PY'
import base64
import json
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

key_path, jwks_path = sys.argv[1:3]
key = ec.generate_private_key(ec.SECP256R1())
numbers = key.public_key().public_numbers()

def b64u(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()

with open(key_path, "wb") as output:
    output.write(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
with open(jwks_path, "w", encoding="utf-8") as output:
    json.dump(
        {
            "keys": [
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "kid": "c10-7-live",
                    "x": b64u(numbers.x.to_bytes(32, "big")),
                    "y": b64u(numbers.y.to_bytes(32, "big")),
                    "use": "sig",
                    "alg": "ES256",
                }
            ]
        },
        output,
        separators=(",", ":"),
    )
PY
chmod 0600 "$WORK/signing-key.pem"
aws s3 cp "$WORK/jwks.json" "s3://$FRONTEND_BUCKET/$BUNDLE_KEY" \
  --profile "$PROFILE" --region "$REGION" \
  --content-type application/json --cache-control 'max-age=60' >/dev/null
BUNDLE_URL="$API_URL/$BUNDLE_KEY"

stable=0
for _ in $(seq 1 30); do
  if curl -fsS --proto '=https' --connect-timeout 5 --max-time 15 \
    "$BUNDLE_URL" | jq -e '.keys[0].kid == "c10-7-live"' >/dev/null; then
    stable=$((stable + 1))
  else
    stable=0
  fi
  [[ "$stable" -ge 3 ]] && break
  sleep 2
done
[[ "$stable" -ge 3 ]] || fail "temporary JWKS did not become stable"

create_client() {
  local label="$1"
  local response="$WORK/client-$label.json" status
  status="$(curl -sS --proto '=https' --connect-timeout 5 --max-time 30 \
    -o "$response" -w '%{http_code}' -X POST \
    -H "@$ADMIN_HEADER" -H 'content-type: application/json' \
    --data-binary '{"redirect_uris":["https://rate-limit.example/cb"],"token_endpoint_auth_method":"none"}' \
    "$API_URL/admin/clients")"
  [[ "$status" == "201" ]] ||
    fail "temporary client $label creation returned HTTP $status"
  jq -er '.client_id' "$response"
}

CLIENT_A="$(create_client a)"
CLIENT_B="$(create_client b)"
[[ "$CLIENT_A" != "$CLIENT_B" ]] || fail "temporary client IDs collided"

for client in "$CLIENT_A" "$CLIENT_B"; do
  aws dynamodb update-item \
    --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
    --key "$(jq -cn --arg client "$(tpk "$client")" \
      '{client_id:{S:$client}}')" \
    --update-expression \
      'SET client_type = :workload, allowed_resources = :resources, allowed_scopes = :scopes' \
    --expression-attribute-values "$(jq -cn --arg resource "$RESOURCE" --arg scope "$SCOPE" '
      {
        ":workload": {S:"workload"},
        ":resources": {L:[{S:$resource}]},
        ":scopes": {L:[{S:$scope}]}
      }
    ')" >/dev/null
done

create_binding() {
  local binding="$1" td="$2" client="$3"
  local body="$WORK/binding-$binding.json" response="$WORK/binding-$binding.response"
  local status=""
  jq -cn --arg binding "$binding" --arg tenant "$TENANT" --arg td "$td" \
    --arg uri "$BUNDLE_URL" --arg client "$client" '
    {
      binding_id:$binding,
      tenant_id:$tenant,
      mechanism:"spiffe_jwt",
      trust_domain:$td,
      jwks_uri:$uri,
      subject_pattern:("spiffe://" + $td + "/agent/*"),
      mapped_client_id:$client
    }
  ' >"$body"
  for _ in $(seq 1 15); do
    status="$(curl -sS --proto '=https' --connect-timeout 5 --max-time 30 \
      -o "$response" -w '%{http_code}' -X POST \
      -H "@$ADMIN_HEADER" -H 'content-type: application/json' \
      --data-binary "@$body" "$API_URL/admin/workload-trust")"
    [[ "$status" == "201" ]] && break
    sleep 1
  done
  [[ "$status" == "201" ]] ||
    fail "temporary workload binding returned HTTP $status: $(<"$response")"
}

create_binding "$BINDING_A" "$TD_A" "$CLIENT_A"
create_binding "$BINDING_B" "$TD_B" "$CLIENT_B"

make_assertion() {
  local td="$1" output="$2"
  python3 - "$WORK/signing-key.pem" "$API_URL" "$td" >"$output" <<'PY'
import base64
import json
import secrets
import sys
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

key_path, audience, trust_domain = sys.argv[1:4]
key = serialization.load_pem_private_key(open(key_path, "rb").read(), None)

def b64u(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()

now = int(time.time())
header = {"typ": "JWT", "alg": "ES256", "kid": "c10-7-live"}
claims = {
    "iss": "https://spire." + trust_domain,
    "sub": "spiffe://" + trust_domain + "/agent/live",
    "aud": audience,
    "iat": now,
    "exp": now + 300,
    "jti": secrets.token_urlsafe(18),
}
signing_input = (
    b64u(json.dumps(header, separators=(",", ":")).encode())
    + "."
    + b64u(json.dumps(claims, separators=(",", ":")).encode())
)
der = key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
r, s = decode_dss_signature(der)
sys.stdout.write(
    signing_input + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
)
PY
  chmod 0600 "$output"
}

token_request() {
  local td="$1" label="$2"
  local assertion="$WORK/$label.assertion"
  make_assertion "$td" "$assertion"
  curl -sS --proto '=https' --connect-timeout 5 --max-time 60 \
    -D "$WORK/$label.headers" -o "$WORK/$label.body" -w '%{http_code}' \
    -X POST -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=client_credentials' \
    --data-urlencode \
      'client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer' \
    --data-urlencode "client_assertion@${assertion}" \
    --data-urlencode "resource=$RESOURCE" \
    --data-urlencode "scope=$SCOPE" \
    "$API_URL/token"
}

wait_for_token() {
  local td="$1" label="$2"
  local status=""
  for attempt in $(seq 1 15); do
    status="$(token_request "$td" "$label-$attempt")"
    printf '%s\n' "$status" >"$WORK/$label.last-status"
    cp "$WORK/$label-$attempt.body" "$WORK/$label.last-body"
    if [[ "$status" == "200" ]]; then
      cp "$WORK/$label-$attempt.body" "$WORK/$label.body"
      cp "$WORK/$label-$attempt.headers" "$WORK/$label.headers"
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_for_token "$TD_A" warm-a ||
  fail "client A warm-up token request failed: HTTP $(<"$WORK/warm-a.last-status") $(jq -cer '{error,error_description}' "$WORK/warm-a.last-body")"
jq -e '.access_token | type == "string" and length > 0' "$WORK/warm-a.body" >/dev/null ||
  fail "client A warm-up response has no access token"
wait_for_token "$TD_B" warm-b ||
  fail "client B warm-up token request failed: HTTP $(<"$WORK/warm-b.last-status") $(jq -cer '{error,error_description}' "$WORK/warm-b.last-body")"
jq -e '.access_token | type == "string" and length > 0' "$WORK/warm-b.body" >/dev/null ||
  fail "client B warm-up response has no access token"
pass "both authenticated clients mint real workload tokens before isolation"

now="$(date +%s)"
future=$((now + 10))
expires=$((now + 3600))
aws dynamodb update-item \
  --profile "$PROFILE" --region "$REGION" --table-name "$RATE_TABLE" \
  --key "$(jq -cn --arg key "$(tpk "$CLIENT_A")" '{key:{S:$key}}')" \
  --update-expression \
    'SET tokens = :zero, last_refill = :future, version = if_not_exists(version, :zero) + :one, expires_at = :expires' \
  --expression-attribute-values "$(jq -cn \
    --arg zero "0" --arg future "$future" --arg one "1" --arg expires "$expires" '
    {
      ":zero": {N:$zero},
      ":future": {N:$future},
      ":one": {N:$one},
      ":expires": {N:$expires}
    }
  ')" >/dev/null

A_STATUS="$(token_request "$TD_A" exhausted-a)"
[[ "$A_STATUS" == "429" ]] ||
  fail "exhausted client A returned HTTP $A_STATUS instead of 429"
grep -iq '^retry-after: [1-9][0-9]*' "$WORK/exhausted-a.headers" ||
  fail "client A 429 response has no positive Retry-After"
jq -e '
  .error == "temporarily_unavailable"
  and (.error_description | type == "string" and length > 0)
' "$WORK/exhausted-a.body" >/dev/null ||
  fail "client A 429 response is not a valid OAuth rate-limit response"

B_STATUS="$(token_request "$TD_B" isolated-b)"
[[ "$B_STATUS" == "200" ]] ||
  fail "client B was affected by client A bucket (HTTP $B_STATUS)"
jq -e '.access_token | type == "string" and length > 0' "$WORK/isolated-b.body" >/dev/null ||
  fail "client B isolation response has no access token"
pass "client A is rate limited while client B remains available"

best_effort_cleanup

dynamo_item_absent() {
  local response_file="$1"
  [[ ! -s "$response_file" ]] ||
    jq -e 'has("Item") | not' "$response_file" >/dev/null
}

cleanup_absent() {
  local client binding object_count public_status
  for client in "$CLIENT_A" "$CLIENT_B"; do
    aws dynamodb get-item \
      --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
      --key "$(jq -cn --arg client "$(tpk "$client")" '{client_id:{S:$client}}')" \
      --consistent-read --output json >"$WORK/client-clean.json" ||
      return 1
    dynamo_item_absent "$WORK/client-clean.json" ||
      return 1
    aws dynamodb get-item \
      --profile "$PROFILE" --region "$REGION" --table-name "$RATE_TABLE" \
      --key "$(jq -cn --arg key "$(tpk "$client")" '{key:{S:$key}}')" \
      --consistent-read --output json >"$WORK/rate-clean.json" ||
      return 1
    dynamo_item_absent "$WORK/rate-clean.json" ||
      return 1
  done
  for binding in "$BINDING_A" "$BINDING_B"; do
    aws dynamodb get-item \
      --profile "$PROFILE" --region "$REGION" --table-name "$TRUST_TABLE" \
      --key "$(jq -cn --arg key "$(tpk "$binding")" \
        '{binding_id:{S:$key}}')" \
      --consistent-read --output json >"$WORK/trust-clean.json" ||
      return 1
    dynamo_item_absent "$WORK/trust-clean.json" ||
      return 1
  done
  object_count="$(
    # JMESPath backticks are literals.
    # shellcheck disable=SC2016
    aws s3api list-objects-v2 --profile "$PROFILE" --region "$REGION" \
      --bucket "$FRONTEND_BUCKET" --prefix "$BUNDLE_KEY" --max-keys 1 \
      --query 'length(Contents || `[]`)' --output text
  )" || return 1
  [[ "$object_count" == "0" ]] || return 1

  public_status="$(
    curl -sS --proto '=https' --connect-timeout 5 --max-time 15 \
      -o "$WORK/public-jwks-clean.body" -w '%{http_code}' "$BUNDLE_URL"
  )" || return 1
  case "$public_status" in
    200)
      ! jq -e '.keys[0].kid == "c10-7-live"' \
        "$WORK/public-jwks-clean.body" >/dev/null 2>&1
      ;;
    403 | 404) return 0 ;;
    *) return 1 ;;
  esac
}

cleanup_verified=0
for _ in $(seq 1 90); do
  if cleanup_absent; then
    cleanup_verified=1
    break
  fi
  best_effort_cleanup
  sleep 1
done
[[ "$cleanup_verified" == "1" ]] ||
  fail "temporary resource cleanup did not converge"
CLEANED=1
rm -rf "$WORK"
pass "all temporary mutable test state and local credential files are absent"

SCRIPT_SHA256="$(sha256sum "$SCRIPT_DIR/per_client_rate_limit.sh" | awk '{print $1}')"
EXECUTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
jq -n \
  --arg executed_at "$EXECUTED_AT" \
  --arg deployed_commit "$DEPLOYED_COMMIT" \
  --arg harness_commit "$HARNESS_COMMIT" \
  --arg script_sha256 "$SCRIPT_SHA256" \
  --arg tenant "$TENANT" \
  '{
    schema_version:1,
    result:"pass",
    requirement:"C10.7",
    executed_at:$executed_at,
    deployed_commit:$deployed_commit,
    harness_commit:$harness_commit,
    script_sha256:$script_sha256,
    tenant:$tenant,
    assertions:{
      authenticated_clients_ready:true,
      exhausted_client_status:429,
      retry_after_present:true,
      isolated_client_status:200,
      mutable_test_state_cleanup_verified:true,
      local_credential_files_removed:true,
      test_resource_uses_reserved_invalid_tld:true
    }
  }' >"$EVIDENCE_FILE"
chmod 0600 "$EVIDENCE_FILE"
EVIDENCE_SHA256="$(sha256sum "$EVIDENCE_FILE" | awk '{print $1}')"
printf 'C10.7 live acceptance passed.\n'
printf 'Evidence: %s\n' "$EVIDENCE_FILE"
printf 'Evidence SHA-256: %s\n' "$EVIDENCE_SHA256"
