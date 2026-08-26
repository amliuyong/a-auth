#!/usr/bin/env bash
# C10.2 live gate: proactive KMS signing backpressure before the Sign call.
#
# The gate runs against the non-production self-hosted stack. It creates one
# temporary authenticated SPIFFE workload client, enables a capacity-2 global
# signing bucket with a Lambda RevisionId CAS, and sends eight concurrent token
# requests. PASS requires exactly two 200 responses and six 503 responses with
# Retry-After, followed by verified restoration of the original Lambda
# environment, global bucket, temporary authority, CDN object, and local files.
set -euo pipefail
set +x

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
STACK="${STACK_NAME:-AgentAuthDev}"
EXPECTED_DEPLOYED_COMMIT="${EXPECTED_DEPLOYED_COMMIT:?set EXPECTED_DEPLOYED_COMMIT to the full deployed SHA}"
EVIDENCE_FILE="${EVIDENCE_FILE:-/tmp/agent-auth-c10-2-evidence-$(date -u +%Y%m%dT%H%M%SZ).json}"
CAPACITY=2
REQUEST_COUNT=8
SCOPE="kb:read"

for command in aws cmp curl git jq python3 sha256sum; do
  command -v "$command" >/dev/null ||
    { echo "missing required command: $command" >&2; exit 1; }
done

pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

WORK="$(mktemp -d)"
RUN_ID="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
GLOBAL_KEY="global-kms-sign:test:$RUN_ID"
RESOURCE="https://c10-2-$RUN_ID.invalid"
CLIENT_ID="c10-2-$RUN_ID"
BINDING_ID="c10-2-binding-$RUN_ID"
TRUST_DOMAIN="c10-2-$RUN_ID.spiffe.test"
BUNDLE_KEY="assets/c10-2-$RUN_ID.json"
ADMIN_HEADER="$WORK/admin.headers"
LAMBDA_ENV_CHANGED=0
GLOBAL_BUCKET_OWNED=0
CLEANUP_RECOVERY_REQUIRED=0
CLEANUP_STATE_UNVERIFIED=0
CLEANED=0

stack_output() {
  local key="$1"
  jq -er --arg key "$key" '
    .Stacks[0].Outputs[]
    | select(.OutputKey == $key)
    | .OutputValue
  ' "$WORK/stack.json"
}

dynamo_item_absent() {
  local response_file="$1"
  [[ ! -s "$response_file" ]] ||
    jq -e 'has("Item") | not' "$response_file" >/dev/null
}

canonical_environment() {
  local config_file="$1" output_file="$2"
  jq -S '.Environment' "$config_file" >"$output_file"
}

receipt_environment_matches() {
  local receipt_file="$1" expected_env="$2" rendered_env="$3"
  canonical_environment "$receipt_file" "$rendered_env" || return 1
  cmp -s "$rendered_env" "$expected_env"
}

restore_lambda_environment() {
  local current_config="$WORK/auth.current.json"
  local current_env="$WORK/env.current.json"
  local current_revision

  # The update can be accepted even if the CLI is interrupted before returning.
  # Only an exact AWS request receipt plus a stable exact config proves restoration.
  aws lambda wait function-updated \
    --function-name "$AUTH_FN" --profile "$PROFILE" --region "$REGION" \
    >/dev/null 2>&1 || return 1
  aws lambda get-function-configuration \
    --function-name "$AUTH_FN" --profile "$PROFILE" --region "$REGION" \
    --output json >"$current_config" || return 1
  jq -e '.State == "Active" and .LastUpdateStatus == "Successful"' \
    "$current_config" >/dev/null || return 1
  canonical_environment "$current_config" "$current_env"
  current_revision="$(jq -er '.RevisionId' "$current_config")" || return 1

  if cmp -s "$current_env" "$WORK/env.before.json"; then
    receipt_environment_matches \
      "$WORK/auth.restore.update.json" "$WORK/env.before.json" \
      "$WORK/env.restore-receipt.json" || return 1
    LAMBDA_ENV_CHANGED=0
    return 0
  fi
  cmp -s "$current_env" "$WORK/env.test.json" || return 1
  if [[ -s "$WORK/auth.test.update.json" ]]; then
    receipt_environment_matches \
      "$WORK/auth.test.update.json" "$WORK/env.test.json" \
      "$WORK/env.test-receipt.json" || return 1
  fi

  aws lambda update-function-configuration \
    --function-name "$AUTH_FN" --profile "$PROFILE" --region "$REGION" \
    --revision-id "$current_revision" \
    --environment "file://$WORK/env.before.json" \
    --output json >"$WORK/auth.restore.update.pending.json" || return 1
  mv "$WORK/auth.restore.update.pending.json" \
    "$WORK/auth.restore.update.json"
  receipt_environment_matches \
    "$WORK/auth.restore.update.json" "$WORK/env.before.json" \
    "$WORK/env.restore-receipt.json" || return 1
  aws lambda wait function-updated \
    --function-name "$AUTH_FN" --profile "$PROFILE" --region "$REGION" ||
    return 1
  aws lambda get-function-configuration \
    --function-name "$AUTH_FN" --profile "$PROFILE" --region "$REGION" \
    --output json >"$current_config" || return 1
  jq -e '.State == "Active" and .LastUpdateStatus == "Successful"' \
    "$current_config" >/dev/null || return 1
  canonical_environment "$current_config" "$current_env"
  cmp -s "$current_env" "$WORK/env.before.json" || return 1
  LAMBDA_ENV_CHANGED=0
}

delete_owned_global_bucket() {
  [[ "$GLOBAL_BUCKET_OWNED" == "1" ]] || return 0
  aws dynamodb delete-item \
    --profile "$PROFILE" --region "$REGION" --table-name "$RATE_TABLE" \
    --key "$(jq -cn --arg key "$GLOBAL_KEY" '{key:{S:$key}}')" \
    >/dev/null || return 1
}

best_effort_cleanup() {
  local restored=0
  set +e
  if [[ "$LAMBDA_ENV_CHANGED" == "1" ]]; then
    for _ in $(seq 1 6); do
      if restore_lambda_environment; then
        restored=1
        break
      fi
      sleep 5
    done
    [[ "$restored" == "1" ]] || CLEANUP_RECOVERY_REQUIRED=1
  fi
  delete_owned_global_bucket
  [[ -n "${TRUST_TABLE:-}" ]] &&
    aws dynamodb delete-item \
      --profile "$PROFILE" --region "$REGION" --table-name "$TRUST_TABLE" \
      --key "$(jq -cn --arg binding "$BINDING_ID" \
        '{binding_id:{S:$binding}}')" >/dev/null
  [[ -n "${RATE_TABLE:-}" ]] &&
    aws dynamodb delete-item \
      --profile "$PROFILE" --region "$REGION" --table-name "$RATE_TABLE" \
      --key "$(jq -cn --arg key "$CLIENT_ID" '{key:{S:$key}}')" >/dev/null
  [[ -n "${CLIENTS_TABLE:-}" ]] &&
    aws dynamodb delete-item \
      --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
      --key "$(jq -cn --arg client "$CLIENT_ID" \
        '{client_id:{S:$client}}')" >/dev/null
  [[ -n "${FRONTEND_BUCKET:-}" ]] &&
    aws s3 rm "s3://$FRONTEND_BUCKET/$BUNDLE_KEY" \
      --profile "$PROFILE" --region "$REGION" >/dev/null
  set -e
}

cleanup() {
  if [[ "$CLEANED" != "1" ]]; then
    best_effort_cleanup
  fi
  if [[ "$CLEANUP_RECOVERY_REQUIRED" == "1" ||
    "$CLEANUP_STATE_UNVERIFIED" == "1" ]]; then
    rm -f \
      "$ADMIN_HEADER" "$WORK"/*.assertion "$WORK"/*.body \
      "$WORK"/signing-key.pem "$WORK"/jwks.json "$WORK"/binding.json
    if [[ "$CLEANUP_RECOVERY_REQUIRED" == "1" ]]; then
      printf 'FAIL: Lambda environment restoration requires manual recovery; protected snapshot retained at %s\n' \
        "$WORK" >&2
    else
      printf 'FAIL: temporary-state cleanup requires manual verification; protected snapshot retained at %s\n' \
        "$WORK" >&2
    fi
  else
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

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
  crates/http/src/token.rs \
  crates/http/src/refresh_flow.rs \
  crates/http/src/token_exchange.rs \
  crates/http/src/workload_flow.rs \
  crates/http/src/ema_flow.rs \
  crates/http/src/adapters/aws/authorization.rs \
  crates/infra-core/src/ratelimit.rs \
  crates/infra-core/src/lease.rs ||
  fail "KMS backpressure runtime changed after the deployed commit"

ADMIN_URL="$(stack_output AdminUrl)"
API_URL="${ADMIN_URL%/admin}"
AUTH_FN="$(stack_output AuthFnName)"
CLIENTS_TABLE="$(stack_output ClientsTableName)"
TRUST_TABLE="$(stack_output WorkloadTrustTableName)"
RATE_TABLE="$(stack_output RateLimitTableName)"
ADMIN_SECRET_ARN="$(stack_output AdminSecretArn)"

aws lambda get-function-configuration \
  --function-name "$AUTH_FN" --profile "$PROFILE" --region "$REGION" \
  --output json >"$WORK/auth.before.json"
jq -e --arg commit "$DEPLOYED_COMMIT" '
  .State == "Active"
  and .LastUpdateStatus == "Successful"
  and .Environment.Variables.AGENT_AUTH_DEPLOYMENT_COMMIT == $commit
  and (.Environment.Variables.AGENT_AUTH_KMS_GATE_CAPACITY // "") == ""
  and (.Environment.Variables.AGENT_AUTH_KMS_GATE_REFILL_PER_SEC // "") == ""
' "$WORK/auth.before.json" >/dev/null ||
  fail "AuthFn is not in the expected gate-off deployed state"
canonical_environment "$WORK/auth.before.json" "$WORK/env.before.json"

aws secretsmanager get-secret-value \
  --secret-id "$ADMIN_SECRET_ARN" --profile "$PROFILE" --region "$REGION" \
  --query SecretString --output text >"$WORK/admin.json"
jq -er '.current.secret | select(type == "string" and length >= 16)' \
  "$WORK/admin.json" >"$WORK/admin.token"
chmod 0600 "$WORK/admin.token"
printf 'authorization: Bearer %s\n' "$(<"$WORK/admin.token")" >"$ADMIN_HEADER"
chmod 0600 "$ADMIN_HEADER"
rm -f "$WORK/admin.json" "$WORK/admin.token"

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
                    "kid": "c10-2-live",
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
    "$BUNDLE_URL" | jq -e '.keys[0].kid == "c10-2-live"' >/dev/null; then
    stable=$((stable + 1))
  else
    stable=0
  fi
  [[ "$stable" -ge 3 ]] && break
  sleep 2
done
[[ "$stable" -ge 3 ]] || fail "temporary JWKS did not become stable"

aws dynamodb put-item \
  --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --item "$(jq -cn --arg client "$CLIENT_ID" --arg resource "$RESOURCE" \
    --arg scope "$SCOPE" '
    {
      client_id:{S:$client},
      redirect_uris:{L:[]},
      token_endpoint_auth_method:{S:"none"},
      client_type:{S:"workload"},
      allowed_resources:{L:[{S:$resource}]},
      allowed_scopes:{L:[{S:$scope}]}
    }
  ')" >/dev/null

jq -cn --arg binding "$BINDING_ID" --arg td "$TRUST_DOMAIN" \
  --arg uri "$BUNDLE_URL" --arg client "$CLIENT_ID" '
  {
    binding_id:$binding,
    tenant_id:"default",
    mechanism:"spiffe_jwt",
    trust_domain:$td,
    jwks_uri:$uri,
    subject_pattern:("spiffe://" + $td + "/agent/*"),
    mapped_client_id:$client
  }
' >"$WORK/binding.json"
BINDING_STATUS="$(curl -sS --proto '=https' --connect-timeout 5 --max-time 30 \
  -o "$WORK/binding.response" -w '%{http_code}' -X POST \
  -H "@$ADMIN_HEADER" -H 'content-type: application/json' \
  --data-binary "@$WORK/binding.json" "$API_URL/admin/workload-trust")"
[[ "$BINDING_STATUS" == "201" ]] ||
  fail "temporary workload binding returned HTTP $BINDING_STATUS"

make_assertion() {
  local output="$1"
  python3 - "$WORK/signing-key.pem" "$API_URL" "$TRUST_DOMAIN" >"$output" <<'PY'
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
header = {"typ": "JWT", "alg": "ES256", "kid": "c10-2-live"}
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
  local label="$1"
  local assertion="$WORK/$label.assertion"
  make_assertion "$assertion"
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

warm_status=""
for attempt in $(seq 1 15); do
  warm_status="$(token_request "warm-$attempt")"
  [[ "$warm_status" == "200" ]] && break
  sleep 1
done
[[ "$warm_status" == "200" ]] ||
  fail "temporary authenticated workload client did not become ready"
jq -e '.access_token | type == "string" and length > 0' \
  "$WORK/warm-$attempt.body" >/dev/null ||
  fail "warm-up response has no access token"
pass "temporary workload authority is ready before the gate is enabled"

aws dynamodb get-item \
  --profile "$PROFILE" --region "$REGION" --table-name "$RATE_TABLE" \
  --key "$(jq -cn --arg key "$GLOBAL_KEY" '{key:{S:$key}}')" \
  --consistent-read --output json >"$WORK/global-bucket.before.json"
dynamo_item_absent "$WORK/global-bucket.before.json" ||
  fail "isolated signing test bucket already exists"
GLOBAL_BUCKET_OWNED=1

jq -S --arg run "$RUN_ID" --arg capacity "$CAPACITY" '
  .Variables += {
    "AGENT_AUTH_KMS_GATE_CAPACITY":$capacity,
    "AGENT_AUTH_KMS_GATE_REFILL_PER_SEC":"0",
    "AGENT_AUTH_KMS_GATE_TEST_RUN":$run
  }
' "$WORK/env.before.json" >"$WORK/env.test.json"
ORIGINAL_REVISION="$(jq -er '.RevisionId' "$WORK/auth.before.json")"
LAMBDA_ENV_CHANGED=1
aws lambda update-function-configuration \
  --function-name "$AUTH_FN" --profile "$PROFILE" --region "$REGION" \
  --revision-id "$ORIGINAL_REVISION" --environment "file://$WORK/env.test.json" \
  --output json >"$WORK/auth.test.update.pending.json"
mv "$WORK/auth.test.update.pending.json" "$WORK/auth.test.update.json"
receipt_environment_matches \
  "$WORK/auth.test.update.json" "$WORK/env.test.json" \
  "$WORK/env.test-receipt.json" ||
  fail "AuthFn test update receipt does not contain the exact test environment"
aws lambda wait function-updated \
  --function-name "$AUTH_FN" --profile "$PROFILE" --region "$REGION"
aws lambda get-function-configuration \
  --function-name "$AUTH_FN" --profile "$PROFILE" --region "$REGION" \
  --output json >"$WORK/auth.test.json"
jq -e '.State == "Active" and .LastUpdateStatus == "Successful"' \
  "$WORK/auth.test.json" >/dev/null ||
  fail "AuthFn test update did not reach a stable successful state"
canonical_environment "$WORK/auth.test.json" "$WORK/env.current.json"
cmp -s "$WORK/env.current.json" "$WORK/env.test.json" ||
  fail "AuthFn did not enter the exact test environment"

pids=()
for index in $(seq 1 "$REQUEST_COUNT"); do
  (
    touch "$WORK/load-$index.ready"
    while [[ ! -e "$WORK/load.start" ]]; do
      sleep 0.01
    done
    status="$(token_request "load-$index")"
    printf '%s\n' "$status" >"$WORK/load-$index.status"
  ) &
  pids+=("$!")
done
workers_ready=0
for _ in $(seq 1 500); do
  workers_ready="$(find "$WORK" -maxdepth 1 -name 'load-*.ready' | wc -l)"
  [[ "$workers_ready" == "$REQUEST_COUNT" ]] && break
  sleep 0.01
done
[[ "$workers_ready" == "$REQUEST_COUNT" ]] ||
  fail "concurrent request workers did not reach the start barrier"
touch "$WORK/load.start"
for pid in "${pids[@]}"; do
  wait "$pid"
done

restore_lambda_environment ||
  fail "failed to restore the exact original Lambda environment"
aws dynamodb get-item \
  --profile "$PROFILE" --region "$REGION" --table-name "$RATE_TABLE" \
  --key "$(jq -cn --arg key "$GLOBAL_KEY" '{key:{S:$key}}')" \
  --consistent-read --output json >"$WORK/global-bucket.after.json"
jq -e --arg expected "$REQUEST_COUNT" '
  .Item.version.N == $expected
  and .Item.tokens.N == "0"
' "$WORK/global-bucket.after.json" >/dev/null ||
  fail "global signing bucket does not prove exactly eight successful gate decisions"
delete_owned_global_bucket ||
  fail "failed to remove the isolated signing test bucket"
pass "Lambda environment was restored and the isolated signing test bucket was removed"

ok_count=0
shed_count=0
for index in $(seq 1 "$REQUEST_COUNT"); do
  status="$(<"$WORK/load-$index.status")"
  case "$status" in
    200)
      jq -e '.access_token | type == "string" and length > 0' \
        "$WORK/load-$index.body" >/dev/null ||
        fail "HTTP 200 response $index has no access token"
      ok_count=$((ok_count + 1))
      ;;
    503)
      grep -iq '^retry-after: [1-9][0-9]*' "$WORK/load-$index.headers" ||
        fail "HTTP 503 response $index has no positive Retry-After"
      jq -e '.error == "temporarily_unavailable"' \
        "$WORK/load-$index.body" >/dev/null ||
        fail "HTTP 503 response $index is not temporarily_unavailable"
      shed_count=$((shed_count + 1))
      ;;
    500)
      fail "request $index returned 500 instead of proactive backpressure"
      ;;
    *)
      fail "request $index returned unexpected HTTP $status"
      ;;
  esac
done
[[ "$ok_count" == "$CAPACITY" ]] ||
  fail "capacity $CAPACITY allowed $ok_count requests"
[[ "$shed_count" == "$((REQUEST_COUNT - CAPACITY))" ]] ||
  fail "capacity $CAPACITY shed $shed_count requests"
pass "capacity 2 admitted exactly 2 requests and shed exactly 6 with 503"

RECOVERY_STATUS="$(token_request recovery)"
[[ "$RECOVERY_STATUS" == "200" ]] ||
  fail "token issuance did not recover after the gate was restored"
pass "token issuance recovered after gate removal"

best_effort_cleanup

cleanup_absent() {
  local public_status object_count
  aws dynamodb get-item \
    --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
    --key "$(jq -cn --arg client "$CLIENT_ID" '{client_id:{S:$client}}')" \
    --consistent-read --output json >"$WORK/client-clean.json" ||
    return 1
  dynamo_item_absent "$WORK/client-clean.json" || return 1
  aws dynamodb get-item \
    --profile "$PROFILE" --region "$REGION" --table-name "$TRUST_TABLE" \
    --key "$(jq -cn --arg binding "$BINDING_ID" \
      '{binding_id:{S:$binding}}')" \
    --consistent-read --output json >"$WORK/trust-clean.json" ||
    return 1
  dynamo_item_absent "$WORK/trust-clean.json" || return 1
  aws dynamodb get-item \
    --profile "$PROFILE" --region "$REGION" --table-name "$RATE_TABLE" \
    --key "$(jq -cn --arg key "$CLIENT_ID" '{key:{S:$key}}')" \
    --consistent-read --output json >"$WORK/client-rate-clean.json" ||
    return 1
  dynamo_item_absent "$WORK/client-rate-clean.json" || return 1
  aws dynamodb get-item \
    --profile "$PROFILE" --region "$REGION" --table-name "$RATE_TABLE" \
    --key "$(jq -cn --arg key "$GLOBAL_KEY" '{key:{S:$key}}')" \
    --consistent-read --output json >"$WORK/global-rate-clean.json" ||
    return 1
  dynamo_item_absent "$WORK/global-rate-clean.json" || return 1

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
      ! jq -e '.keys[0].kid == "c10-2-live"' \
        "$WORK/public-jwks-clean.body" >/dev/null 2>&1
      ;;
    403 | 404) return 0 ;;
    *) return 1 ;;
  esac
}

cleanup_verified=0
cleanup_stable=0
for _ in $(seq 1 90); do
  if cleanup_absent; then
    cleanup_stable=$((cleanup_stable + 1))
    if [[ "$cleanup_stable" -ge 15 ]]; then
      cleanup_verified=1
      break
    fi
  else
    cleanup_stable=0
    best_effort_cleanup
  fi
  sleep 1
done
if [[ "$cleanup_verified" != "1" ]]; then
  CLEANUP_STATE_UNVERIFIED=1
  fail "temporary resource cleanup did not reach a stable absence window"
fi
[[ "$LAMBDA_ENV_CHANGED" == "0" ]] ||
  fail "Lambda environment remains changed"
GLOBAL_BUCKET_OWNED=0
CLEANED=1
rm -rf "$WORK"
pass "temporary authority, CDN object, rate rows, and local credentials are absent"

SCRIPT_SHA256="$(sha256sum "$SCRIPT_DIR/kms_backpressure.sh" | awk '{print $1}')"
EXECUTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
jq -n \
  --arg executed_at "$EXECUTED_AT" \
  --arg deployed_commit "$DEPLOYED_COMMIT" \
  --arg harness_commit "$HARNESS_COMMIT" \
  --arg script_sha256 "$SCRIPT_SHA256" \
  --arg stack "$STACK" \
  '{
    schema_version:1,
    result:"pass",
    requirement:"C10.2",
    executed_at:$executed_at,
    deployed_commit:$deployed_commit,
    harness_commit:$harness_commit,
    script_sha256:$script_sha256,
    stack:$stack,
    assertions:{
      authenticated_workload_ready:true,
      configured_capacity:2,
      concurrent_requests:8,
      admitted_status_200:2,
      shed_status_503:6,
      retry_after_present_on_all_shed:true,
      no_status_500:true,
      post_restore_status_200:true,
      lambda_environment_restored:true,
      global_bucket_version_after_load:8,
      global_bucket_tokens_after_load:0,
      isolated_test_bucket:true,
      isolated_test_bucket_removed:true,
      isolated_test_bucket_stable_absence_seconds:15,
      mutable_test_state_cleanup_verified:true,
      local_credential_files_removed:true,
      test_resource_uses_reserved_invalid_tld:true
    }
  }' >"$EVIDENCE_FILE"
chmod 0600 "$EVIDENCE_FILE"
EVIDENCE_SHA256="$(sha256sum "$EVIDENCE_FILE" | awk '{print $1}')"
printf 'C10.2 live acceptance passed.\n'
printf 'Evidence: %s\n' "$EVIDENCE_FILE"
printf 'Evidence SHA-256: %s\n' "$EVIDENCE_SHA256"
