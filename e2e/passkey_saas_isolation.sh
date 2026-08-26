#!/usr/bin/env bash
# Live C9.4 acceptance against two deployed AgentAuthSaas tenant issuers.
#
# The stack must already run the exact commit under test with
# SAAS_PASSKEY_ENABLED=1. This script never mutates Lambda configuration.
#
# Usage:
#   TENANT_A_URL=https://t1.example.com TENANT_B_URL=https://t3.example.com \
#   TENANT_A_ADMIN_TOKEN=<t1 token> TENANT_B_ADMIN_TOKEN=<t3 token> \
#   TENANT_A_ID=t1 TENANT_B_ID=t3 EXPECTED_COMMIT=<full git sha> \
#   AWS_PROFILE=default ./e2e/passkey_saas_isolation.sh
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
T1_URL="${TENANT_A_URL:-${T1_URL:-}}"
T2_URL="${TENANT_B_URL:-${T2_URL:-}}"
T1_ADMIN_TOKEN="${TENANT_A_ADMIN_TOKEN:-${T1_ADMIN_TOKEN:-}}"
T2_ADMIN_TOKEN="${TENANT_B_ADMIN_TOKEN:-${T2_ADMIN_TOKEN:-}}"
TENANT_A_ID="${TENANT_A_ID:-t1}"
TENANT_B_ID="${TENANT_B_ID:-t3}"
[[ -n "$T1_URL" ]] || { echo "TENANT_A_URL is required" >&2; exit 1; }
[[ -n "$T2_URL" ]] || { echo "TENANT_B_URL is required" >&2; exit 1; }
[[ -n "$T1_ADMIN_TOKEN" ]] ||
  { echo "TENANT_A_ADMIN_TOKEN is required" >&2; exit 1; }
[[ -n "$T2_ADMIN_TOKEN" ]] ||
  { echo "TENANT_B_ADMIN_TOKEN is required" >&2; exit 1; }
[[ "$TENANT_A_ID" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] ||
  { echo "TENANT_A_ID is invalid" >&2; exit 1; }
[[ "$TENANT_B_ID" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] ||
  { echo "TENANT_B_ID is invalid" >&2; exit 1; }
[[ "$TENANT_A_ID" != "$TENANT_B_ID" ]] ||
  { echo "tenant IDs must differ" >&2; exit 1; }
[[ "$TENANT_A_ID" != "t2" && "$TENANT_B_ID" != "t2" ]] ||
  { echo "the permanently offboarded t2 tenant must never be reused" >&2; exit 1; }
EXPECTED_COMMIT="${EXPECTED_COMMIT:?EXPECTED_COMMIT is required}"
STACK_NAME="${STACK_NAME:-AgentAuthSaas}"
AWS_PROFILE_NAME="${AWS_PROFILE:-default}"
AWS_REGION_NAME="${REGION:-us-east-1}"
EVIDENCE_FILE="${EVIDENCE_FILE:-}"

[[ "$EXPECTED_COMMIT" =~ ^[0-9a-f]{40}$ ]] || {
  echo "EXPECTED_COMMIT must be a full lowercase Git SHA" >&2
  exit 1
}
for command in aws curl find git jq python3 rmdir seq sha256sum sleep; do
  command -v "$command" >/dev/null ||
    { echo "missing required command: $command" >&2; exit 1; }
done
T1_URL="${T1_URL%/}"
T2_URL="${T2_URL%/}"
read -r T1_HOST T2_HOST < <(
  T1_URL="$T1_URL" T2_URL="$T2_URL" python3 - <<'PY'
import os
import urllib.parse

hosts = []
for name in ("T1_URL", "T2_URL"):
    parsed = urllib.parse.urlparse(os.environ[name])
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.port
        or parsed.path not in ("", "/")
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise SystemExit(
            f"{name} must be an HTTPS origin without credentials, port, path, query, or fragment"
        )
    hosts.append(parsed.hostname)
if hosts[0] == hosts[1]:
    raise SystemExit("tenant issuers must use different hosts")
print(*hosts)
PY
)
[[ "${T1_HOST%%.*}" == "$TENANT_A_ID" ]] ||
  { echo "TENANT_A_URL host is not bound to TENANT_A_ID" >&2; exit 1; }
[[ "${T2_HOST%%.*}" == "$TENANT_B_ID" ]] ||
  { echo "TENANT_B_URL host is not bound to TENANT_B_ID" >&2; exit 1; }

WORK="$(mktemp -d)"
chmod 700 "$WORK"
SECRETS="$WORK/secrets"
mkdir -m 700 "$SECRETS"
COOKIE_JAR="$SECRETS/t1.cookies"
KEY_FILE="$SECRETS/authenticator.pem"
T1_ADMIN_HEADERS="$SECRETS/t1-admin.headers"
T2_ADMIN_HEADERS="$SECRETS/t2-admin.headers"
RUN_ID="$(python3 -c 'import secrets; print(secrets.token_hex(6))')"
EMAIL="passkey-c9-4-${RUN_ID}@example.com"
T1_USER_ID="user:${EMAIL}"
T2_USER_ID="user:${EMAIL}"
USER_INTENT=0
T2_USER_INTENT=0
CLEANED=0

fail() {
  echo "FAIL: $*" >&2
  rm -f "$EVIDENCE_FILE"
  exit 1
}

urlencode() {
  python3 -c \
    'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' \
    "$1"
}

recover_user_id() {
  local base_url="$1" headers="$2" output="$3"
  curl -sS --proto '=https' --connect-timeout 5 --max-time 30 \
    -H "@$headers" -G "$base_url/admin/users" \
    --data-urlencode 'limit=2' --data-urlencode "q=$EMAIL" -o "$output" ||
    return 1
  jq -er --arg email "${EMAIL,,}" '
    [.users[]? | select((.email | ascii_downcase) == $email) | .user_id]
    | if length == 0 then "__absent__"
      elif length == 1 then .[0]
      else error("multiple users matched the unique email")
      end
  ' "$output"
}

user_cleanup_round() {
  local base_url="$1" headers="$2" intent="$3" user_id_name="$4" label="$5"
  local user_id="${!user_id_name}" recovered encoded status
  [[ "$intent" == "1" ]] || return 0
  recovered="$(recover_user_id "$base_url" "$headers" \
    "$WORK/$label-user-recovery.json")" || return 1
  if [[ "$recovered" == "__absent__" ]]; then
    return 0
  fi
  user_id="$recovered"
  printf -v "$user_id_name" '%s' "$user_id"
  encoded="$(urlencode "$user_id")"
  status="$(
    curl -sS --proto '=https' --connect-timeout 5 --max-time 30 \
      -H "@$headers" -o "$WORK/$label-user-delete.json" -w '%{http_code}' \
      -X DELETE "$base_url/admin/users/$encoded"
  )" || return 1
  [[ "$status" == "200" || "$status" == "404" ]] || return 1
  status="$(
    curl -sS --proto '=https' --connect-timeout 5 --max-time 30 \
      -H "@$headers" -o "$WORK/$label-user-after.json" -w '%{http_code}' \
      "$base_url/admin/users/$encoded"
  )" || return 1
  if [[ "$status" == "404" ]]; then
    return 0
  fi
  [[ "$status" == "200" ]] || return 1
  jq -e '
    .status == "tombstoned"
    and .active_grants == 0
    and .sessions == 0
    and .passkeys == 0
    and .password_status == "not_configured"
    and .has_recovery == false
  ' "$WORK/$label-user-after.json" >/dev/null
}

cleanup_resources() {
  local stable_started=-1 round_failed
  for _ in $(seq 1 60); do
    round_failed=0
    user_cleanup_round "$T1_URL" "$T1_ADMIN_HEADERS" "$USER_INTENT" \
      T1_USER_ID tenant-a || round_failed=1
    user_cleanup_round "$T2_URL" "$T2_ADMIN_HEADERS" "$T2_USER_INTENT" \
      T2_USER_ID tenant-b || round_failed=1
    if [[ "$round_failed" == "0" ]]; then
      if [[ "$stable_started" -lt 0 ]]; then
        stable_started="$SECONDS"
      elif ((SECONDS - stable_started >= 15)); then
        CLEANED=1
        return 0
      fi
    else
      stable_started=-1
    fi
    sleep 1
  done
  return 1
}

scrub_secrets() {
  local status=0
  [[ -d "$SECRETS" ]] || return 0
  find "$SECRETS" -type f -exec sh -c '
    for file do
      : >"$file" && rm -f -- "$file" || exit 1
    done
  ' sh {} + || status=1
  find "$SECRETS" -mindepth 1 -depth -type d -empty -delete || status=1
  rmdir "$SECRETS" 2>/dev/null || status=1
  [[ ! -e "$SECRETS" ]] || status=1
  return "$status"
}

purge_work_files() {
  local status=0
  find "$WORK" -mindepth 1 -type f -delete || status=1
  find "$WORK" -mindepth 1 -depth -type d -empty -delete || status=1
  return "$status"
}

cleanup() {
  local status=$? scrubbed=1
  trap '' INT TERM
  trap - EXIT
  set +e
  [[ "$CLEANED" == "1" ]] || cleanup_resources ||
    { echo "FAIL: passkey fixture cleanup did not converge" >&2; status=1; }
  scrub_secrets || {
    echo "FAIL: sensitive-file scrub did not complete" >&2
    scrubbed=0
    status=1
  }
  if [[ "$status" == "0" && "$CLEANED" == "1" ]]; then
    purge_work_files && rmdir "$WORK" || status=1
  else
    rm -f "$EVIDENCE_FILE"
    if [[ "$scrubbed" == "1" ]] && purge_work_files; then
      jq -n \
        --arg status "$status" \
        --arg cleaned "$CLEANED" \
        --arg run_id "$RUN_ID" \
        --arg tenant_a "$TENANT_A_ID" \
        --arg tenant_b "$TENANT_B_ID" \
        '{
          result:"fail",
          exit_status:($status|tonumber),
          cleanup_verified:($cleaned=="1"),
          run_id:$run_id,
          tenant_ids:[$tenant_a,$tenant_b],
          sensitive_values_retained:false
        }' >"$WORK/failure.json"
      echo "Redacted recovery material retained at $WORK" >&2
    else
      echo "Sensitive-file deletion could not be proven; no redacted-only diagnostic claim was written" >&2
    fi
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf 'authorization: Bearer %s\n' "$T1_ADMIN_TOKEN" >"$T1_ADMIN_HEADERS"
printf 'authorization: Bearer %s\n' "$T2_ADMIN_TOKEN" >"$T2_ADMIN_HEADERS"
unset T1_ADMIN_TOKEN T2_ADMIN_TOKEN
python3 -c 'import secrets; print("Init-" + secrets.token_urlsafe(24), end="")' \
  >"$SECRETS/initial.password"
python3 -c 'import secrets; print("Active-" + secrets.token_urlsafe(24), end="")' \
  >"$SECRETS/active.password"

HARNESS_COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD)"
[[ "$HARNESS_COMMIT" == "$EXPECTED_COMMIT" ]] ||
  fail "harness and deployment must use the same exact commit"
[[ -z "$(git -C "$REPO_ROOT" status --porcelain)" ]] ||
  fail "live evidence requires a clean worktree"
SCRIPT_SHA256="$(sha256sum "$SCRIPT_DIR/passkey_saas_isolation.sh" | cut -d' ' -f1)"
COMMITTED_SCRIPT_SHA256="$(
  git -C "$REPO_ROOT" show "$EXPECTED_COMMIT:e2e/passkey_saas_isolation.sh" |
    sha256sum | cut -d' ' -f1
)"
[[ "$SCRIPT_SHA256" == "$COMMITTED_SCRIPT_SHA256" ]] ||
  fail "passkey harness does not match the exact deployed commit"

aws cloudformation describe-stacks \
  --profile "$AWS_PROFILE_NAME" \
  --region "$AWS_REGION_NAME" \
  --stack-name "$STACK_NAME" \
  --output json >"$WORK/stack.json"
DEPLOYED_COMMIT="$(
  jq -er '
    .Stacks[0].Outputs
    | map(select(.OutputKey == "DeploymentCommit"))
    | if length == 1 then .[0].OutputValue else error("missing DeploymentCommit") end
  ' "$WORK/stack.json"
)"
AUTH_FN_NAME="$(
  jq -er '
    .Stacks[0].Outputs
    | map(select(.OutputKey == "AuthFnName"))
    | if length == 1 then .[0].OutputValue else error("missing AuthFnName") end
  ' "$WORK/stack.json"
)"
API_URL="$(
  jq -er '
    .Stacks[0].Outputs
    | map(select(.OutputKey == "ApiUrl"))
    | if length == 1 then .[0].OutputValue else error("missing ApiUrl") end
  ' "$WORK/stack.json"
)"
STACK_STATUS="$(jq -er '.Stacks[0].StackStatus' "$WORK/stack.json")"
[[ "$STACK_STATUS" == "CREATE_COMPLETE" || "$STACK_STATUS" == "UPDATE_COMPLETE" ]] ||
  fail "stack is not in a stable complete state"
[[ "$DEPLOYED_COMMIT" == "$EXPECTED_COMMIT" ]] ||
  fail "deployed commit does not match EXPECTED_COMMIT"
API_HOST="$(
  API_URL="$API_URL" python3 - <<'PY'
import os
import urllib.parse

parsed = urllib.parse.urlparse(os.environ["API_URL"])
if parsed.scheme != "https" or not parsed.hostname:
    raise SystemExit("stack ApiUrl is not an HTTPS URL")
print(parsed.hostname)
PY
)"
DISTRIBUTION_ID="$(
  aws cloudformation list-stack-resources \
    --profile "$AWS_PROFILE_NAME" \
    --region "$AWS_REGION_NAME" \
    --stack-name "$STACK_NAME" \
    --output json |
    jq -er '
      [.StackResourceSummaries[]
       | select(.ResourceType == "AWS::CloudFront::Distribution")
       | .PhysicalResourceId]
      | unique
      | if length == 1 then .[0] else error("expected one CloudFront distribution") end
    '
)"
aws cloudfront get-distribution \
  --profile "$AWS_PROFILE_NAME" \
  --id "$DISTRIBUTION_ID" \
  --output json >"$WORK/distribution.json"
jq -e \
  --arg t1 "$T1_HOST" \
  --arg t2 "$T2_HOST" \
  --arg api "$API_HOST" '
    .Distribution.Status == "Deployed"
    and .Distribution.DistributionConfig.Enabled == true
    and (.Distribution.DistributionConfig.Aliases.Items | index($t1) != null)
    and (.Distribution.DistributionConfig.Aliases.Items | index($t2) != null)
    and any(
      .Distribution.DistributionConfig.Origins.Items[];
      .DomainName == $api
    )
  ' "$WORK/distribution.json" >/dev/null ||
  fail "tenant hosts and API origin are not bound to the named stack distribution"

aws lambda get-function-configuration \
  --profile "$AWS_PROFILE_NAME" \
  --region "$AWS_REGION_NAME" \
  --function-name "$AUTH_FN_NAME" \
  --query '{commit:Environment.Variables.AGENT_AUTH_DEPLOYMENT_COMMIT,passkey:Environment.Variables.AGENT_AUTH_PASSKEY_ENABLED,partitioning:Environment.Variables.AGENT_AUTH_ENABLE_TENANT_PARTITIONING,state:State,last_update:LastUpdateStatus}' \
  --output json >"$WORK/runtime.json"
jq -e \
  --arg commit "$EXPECTED_COMMIT" \
  '.commit == $commit and .passkey == "1" and .partitioning == "1"
   and .state == "Active" and .last_update == "Successful"' \
  "$WORK/runtime.json" >/dev/null ||
  fail "runtime is not active on the expected commit with passkey and tenant partitioning enabled"
curl -fsS --proto '=https' --connect-timeout 5 --max-time 30 \
  "$T1_URL/.well-known/openid-configuration" >"$WORK/tenant-a-discovery.json"
curl -fsS --proto '=https' --connect-timeout 5 --max-time 30 \
  "$T2_URL/.well-known/openid-configuration" >"$WORK/tenant-b-discovery.json"
[[ "$(jq -er '.issuer' "$WORK/tenant-a-discovery.json")" == "$T1_URL" ]] ||
  fail "TENANT_A_URL does not expose its exact issuer"
[[ "$(jq -er '.issuer' "$WORK/tenant-b-discovery.json")" == "$T2_URL" ]] ||
  fail "TENANT_B_URL does not expose its exact issuer"

echo "== Provision tenant t1 local user =="
EMAIL="$EMAIL" PASSWORD_FILE="$SECRETS/initial.password" \
  python3 - >"$SECRETS/create-user.json" <<'PY'
import json
import os
password = open(os.environ["PASSWORD_FILE"], encoding="utf-8").read()
print(json.dumps({
    "email": os.environ["EMAIL"],
    "initial_password": password,
}))
PY
USER_INTENT=1
CREATE_STATUS="$(
  curl -sS --proto '=https' -o "$SECRETS/create.json" -w '%{http_code}' \
    -X POST "$T1_URL/admin/users" \
    -H "@$T1_ADMIN_HEADERS" \
    -H "content-type: application/json" \
    --data-binary "@$SECRETS/create-user.json"
)"
[[ "$CREATE_STATUS" == "201" ]] || fail "tenant t1 user create returned HTTP $CREATE_STATUS"
# Cleanup updates this variable by name after recovery.
# shellcheck disable=SC2034
T1_USER_ID="$(jq -er '.user_id' "$SECRETS/create.json")"

EMAIL="$EMAIL" PASSWORD_FILE="$SECRETS/initial.password" \
  python3 - >"$SECRETS/tenant-b-create-user.json" <<'PY'
import json
import os
password = open(os.environ["PASSWORD_FILE"], encoding="utf-8").read()
print(json.dumps({
    "email": os.environ["EMAIL"],
    "initial_password": password,
}))
PY
T2_USER_INTENT=1
T2_CREATE_STATUS="$(
  curl -sS --proto '=https' -o "$SECRETS/tenant-b-create.json" -w '%{http_code}' \
    -X POST "$T2_URL/admin/users" \
    -H "@$T2_ADMIN_HEADERS" \
    -H "content-type: application/json" \
    --data-binary "@$SECRETS/tenant-b-create-user.json"
)"
[[ "$T2_CREATE_STATUS" == "201" ]] ||
  fail "tenant $TENANT_B_ID user create returned HTTP $T2_CREATE_STATUS"
# Cleanup updates this variable by name after recovery.
# shellcheck disable=SC2034
T2_USER_ID="$(jq -er '.user_id' "$SECRETS/tenant-b-create.json")"

EMAIL="$EMAIL" CURRENT_FILE="$SECRETS/initial.password" \
  NEW_FILE="$SECRETS/active.password" python3 - >"$SECRETS/change-password.json" <<'PY'
import json
import os
current = open(os.environ["CURRENT_FILE"], encoding="utf-8").read()
new = open(os.environ["NEW_FILE"], encoding="utf-8").read()
print(json.dumps({
    "email": os.environ["EMAIL"],
    "current_password": current,
    "new_password": new,
}))
PY
CHANGE_STATUS="$(
  curl -sS --proto '=https' -o "$SECRETS/change.json" -w '%{http_code}' \
    -c "$COOKIE_JAR" -X POST "$T1_URL/login/password/change" \
    -H "content-type: application/json" \
    --data-binary "@$SECRETS/change-password.json"
)"
[[ "$CHANGE_STATUS" == "200" ]] || fail "tenant t1 password activation returned HTTP $CHANGE_STATUS"
grep -q "__Host-agent_auth_session" "$COOKIE_JAR" ||
  fail "password activation did not establish a t1 session"

make_registration() {
  local rp_id="$1" origin="$2" challenge="$3" output="$4"
  RP_ID="$rp_id" ORIGIN="$origin" CHALLENGE="$challenge" KEY_FILE="$KEY_FILE" \
    python3 - "$output" <<'PY'
import base64
import hashlib
import json
import os
import secrets
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

def b64u(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()

def cbor_uint(major, value):
    if value < 24:
        return bytes([major | value])
    if value < 256:
        return bytes([major | 24, value])
    if value < 65536:
        return bytes([major | 25]) + value.to_bytes(2, "big")
    raise ValueError("CBOR value too large")

def encode(value):
    if isinstance(value, int):
        return cbor_uint(0, value) if value >= 0 else cbor_uint(0x20, -1 - value)
    if isinstance(value, bytes):
        return cbor_uint(0x40, len(value)) + value
    if isinstance(value, str):
        raw = value.encode()
        return cbor_uint(0x60, len(raw)) + raw
    if isinstance(value, dict):
        return cbor_uint(0xa0, len(value)) + b"".join(
            encode(key) + encode(item) for key, item in value.items()
        )
    raise ValueError(type(value))

key = ec.generate_private_key(ec.SECP256R1())
with open(os.environ["KEY_FILE"], "wb") as handle:
    handle.write(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
numbers = key.public_key().public_numbers()
x = numbers.x.to_bytes(32, "big")
y = numbers.y.to_bytes(32, "big")
cose = encode({1: 2, 3: -7, -1: 1, -2: x, -3: y})
credential = secrets.token_bytes(20)
auth_data = (
    hashlib.sha256(os.environ["RP_ID"].encode()).digest()
    + bytes([0x45])
    + (0).to_bytes(4, "big")
    + bytes(16)
    + len(credential).to_bytes(2, "big")
    + credential
    + cose
)
client_data = json.dumps({
    "type": "webauthn.create",
    "challenge": os.environ["CHALLENGE"],
    "origin": os.environ["ORIGIN"],
}, separators=(",", ":")).encode()
payload = {
    "credential_id": b64u(credential),
    "client_data_json": b64u(client_data),
    "attestation_object": b64u(encode({
        "fmt": "none",
        "attStmt": {},
        "authData": auth_data,
    })),
}
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(payload, handle)
PY
}

make_assertion() {
  local rp_id="$1" origin="$2" challenge="$3" count="$4" output="$5"
  RP_ID="$rp_id" ORIGIN="$origin" CHALLENGE="$challenge" SIGN_COUNT="$count" \
    KEY_FILE="$KEY_FILE" python3 - "$output" <<'PY'
import base64
import hashlib
import json
import os
import sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

def b64u(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()

with open(os.environ["KEY_FILE"], "rb") as handle:
    key = serialization.load_pem_private_key(handle.read(), password=None)
auth_data = (
    hashlib.sha256(os.environ["RP_ID"].encode()).digest()
    + bytes([0x05])
    + int(os.environ["SIGN_COUNT"]).to_bytes(4, "big")
)
client_data = json.dumps({
    "type": "webauthn.get",
    "challenge": os.environ["CHALLENGE"],
    "origin": os.environ["ORIGIN"],
}, separators=(",", ":")).encode()
signature = key.sign(
    auth_data + hashlib.sha256(client_data).digest(),
    ec.ECDSA(hashes.SHA256()),
)
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump({
        "client_data_json": b64u(client_data),
        "authenticator_data": b64u(auth_data),
        "signature": b64u(signature),
    }, handle)
PY
}

auth_begin() {
  local base_url="$1" output="$2"
  curl -fsS --proto '=https' -G "$base_url/passkey/authenticate/begin" \
    --data-urlencode "login_hint=$EMAIL" -o "$output"
}

post_auth_finish() {
  local base_url="$1" challenge="$2" assertion="$3" output="$4" headers="$5"
  jq -c --arg challenge "$challenge" --arg credential "$CREDENTIAL_ID" \
    '{challenge:$challenge,credential_id:$credential,client_data_json,authenticator_data,signature}' \
    "$assertion" |
    curl -sS --proto '=https' -D "$headers" -o "$output" -w '%{http_code}' \
      -X POST "$base_url/passkey/authenticate/finish" \
      -H "content-type: application/json" --data-binary @-
}

echo "== Register passkey at tenant t1 =="
curl -fsS --proto '=https' -b "$COOKIE_JAR" -X POST \
  "$T1_URL/passkey/register/begin" -o "$SECRETS/register-begin.json"
jq -e --arg rp "$T1_HOST" '.rp_id == $rp and .user_verification == "required"' \
  "$SECRETS/register-begin.json" >/dev/null ||
  fail "tenant t1 registration did not return its exact host as RP ID"
REGISTER_CHALLENGE="$(jq -er '.challenge' "$SECRETS/register-begin.json")"
make_registration "$T1_HOST" "$T1_URL" "$REGISTER_CHALLENGE" "$SECRETS/registration.json"
CREDENTIAL_ID="$(jq -er '.credential_id' "$SECRETS/registration.json")"
REGISTER_STATUS="$(
  jq -c --arg challenge "$REGISTER_CHALLENGE" \
    '{challenge:$challenge,client_data_json,attestation_object}' "$SECRETS/registration.json" |
    curl -sS --proto '=https' -o "$SECRETS/register-finish.json" -w '%{http_code}' \
      -b "$COOKIE_JAR" -X POST "$T1_URL/passkey/register/finish" \
      -H "content-type: application/json" --data-binary @-
)"
[[ "$REGISTER_STATUS" == "200" ]] || fail "tenant t1 registration returned HTTP $REGISTER_STATUS"

echo "== Prove tenant $TENANT_B_ID cannot enumerate or use the $TENANT_A_ID credential =="
auth_begin "$T2_URL" "$SECRETS/tenant-b-begin.json"
jq -e --arg rp "$T2_HOST" --arg credential "$CREDENTIAL_ID" \
  '.rp_id == $rp and (.allow_credentials | index($credential) | not)' \
  "$SECRETS/tenant-b-begin.json" >/dev/null ||
  fail "tenant $TENANT_B_ID exposed tenant $TENANT_A_ID credential or returned the wrong RP ID"
T2_CHALLENGE="$(jq -er '.challenge' "$SECRETS/tenant-b-begin.json")"
make_assertion "$T2_HOST" "$T2_URL" "$T2_CHALLENGE" 1 "$SECRETS/tenant-b-forged.json"
T2_FORGED_STATUS="$(
  post_auth_finish "$T2_URL" "$T2_CHALLENGE" "$SECRETS/tenant-b-forged.json" \
    "$SECRETS/tenant-b-forged.body" "$SECRETS/tenant-b-forged.headers"
)"
[[ "$T2_FORGED_STATUS" == "400" ]] ||
  fail "forged tenant $TENANT_B_ID assertion using tenant $TENANT_A_ID key returned HTTP $T2_FORGED_STATUS"
! grep -qi '^set-cookie:.*__Host-agent_auth_session' "$SECRETS/tenant-b-forged.headers" ||
  fail "tenant $TENANT_B_ID denial established a session"

echo "== Prove challenge and ceremony bindings fail closed =="
auth_begin "$T1_URL" "$SECRETS/tenant-a-begin.json"
T1_CHALLENGE="$(jq -er '.challenge' "$SECRETS/tenant-a-begin.json")"
make_assertion "$T1_HOST" "$T1_URL" "$T1_CHALLENGE" 1 "$SECRETS/tenant-a-assertion.json"
T1_AT_T2_STATUS="$(
  post_auth_finish "$T2_URL" "$T1_CHALLENGE" "$SECRETS/tenant-a-assertion.json" \
    "$SECRETS/tenant-a-at-b.body" "$SECRETS/tenant-a-at-b.headers"
)"
[[ "$T1_AT_T2_STATUS" == "400" ]] ||
  fail "tenant $TENANT_B_ID consumed tenant $TENANT_A_ID challenge with HTTP $T1_AT_T2_STATUS"
T1_SUCCESS_STATUS="$(
  post_auth_finish "$T1_URL" "$T1_CHALLENGE" "$SECRETS/tenant-a-assertion.json" \
    "$SECRETS/tenant-a-success.body" "$SECRETS/tenant-a-success.headers"
)"
[[ "$T1_SUCCESS_STATUS" == "200" ]] ||
  fail "tenant t1 could not consume its challenge after tenant t2 denial"
grep -qi '^set-cookie:.*__Host-agent_auth_session' "$SECRETS/tenant-a-success.headers" ||
  fail "tenant t1 authentication did not establish a session"

curl -fsS --proto '=https' -b "$COOKIE_JAR" -X POST \
  "$T1_URL/passkey/register/begin" -o "$SECRETS/register-only-begin.json"
REGISTER_ONLY_CHALLENGE="$(jq -er '.challenge' "$SECRETS/register-only-begin.json")"
make_assertion \
  "$T1_HOST" "$T1_URL" "$REGISTER_ONLY_CHALLENGE" 2 "$SECRETS/cross-ceremony.json"
CROSS_CEREMONY_STATUS="$(
  post_auth_finish "$T1_URL" "$REGISTER_ONLY_CHALLENGE" "$SECRETS/cross-ceremony.json" \
    "$SECRETS/cross-ceremony.body" "$SECRETS/cross-ceremony.headers"
)"
[[ "$CROSS_CEREMONY_STATUS" == "400" ]] ||
  fail "registration challenge authorized authentication with HTTP $CROSS_CEREMONY_STATUS"

auth_begin "$T1_URL" "$SECRETS/wrong-origin-begin.json"
WRONG_ORIGIN_CHALLENGE="$(jq -er '.challenge' "$SECRETS/wrong-origin-begin.json")"
make_assertion \
  "$T1_HOST" "$T2_URL" "$WRONG_ORIGIN_CHALLENGE" 2 "$SECRETS/wrong-origin.json"
WRONG_ORIGIN_STATUS="$(
  post_auth_finish "$T1_URL" "$WRONG_ORIGIN_CHALLENGE" "$SECRETS/wrong-origin.json" \
    "$SECRETS/wrong-origin.body" "$SECRETS/wrong-origin.headers"
)"
[[ "$WRONG_ORIGIN_STATUS" == "400" ]] ||
  fail "tenant t1 accepted tenant t2 origin with HTTP $WRONG_ORIGIN_STATUS"

echo "== Remove both temporary tenant users =="
cleanup_resources || fail "passkey fixture cleanup did not converge"
scrub_secrets || fail "sensitive-file scrub did not complete"
if ! purge_work_files; then
  fail "temporary passkey work files did not cleanly converge"
fi
if ! rmdir "$WORK"; then
  fail "temporary passkey work directory did not cleanly converge"
fi
trap - EXIT INT TERM

UTC_TIME="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
EVIDENCE="$(
  jq -n \
    --arg commit "$DEPLOYED_COMMIT" \
    --arg t1_host "$T1_HOST" \
    --arg t2_host "$T2_HOST" \
    --arg tenant_a "$TENANT_A_ID" \
    --arg tenant_b "$TENANT_B_ID" \
    --arg harness_commit "$HARNESS_COMMIT" \
    --arg script_sha256 "$SCRIPT_SHA256" \
    --arg utc "$UTC_TIME" \
    '{
      schema_version: 1,
      issue: 190,
      requirement: "C9.4",
      deployment_commit: $commit,
      harness_commit: $harness_commit,
      script_sha256: $script_sha256,
      tenant_ids: [$tenant_a, $tenant_b],
      tenant_hosts: [$t1_host, $t2_host],
      observed_at_utc: $utc,
      checks: {
        exact_tenant_rp_ids: "pass",
        tenant_credential_enumeration_denied: "pass",
        forged_cross_tenant_assertion_denied: "pass",
        cross_tenant_challenge_denied_without_consuming_source: "pass",
        cross_ceremony_challenge_denied: "pass",
        wrong_origin_denied: "pass",
        same_deployment_distribution_binding: "pass",
        both_tenant_user_indexes_exercised: "pass",
        fixture_cascade_cleanup: "pass",
        offboarded_t2_not_reused: "pass"
      },
      sensitive_values_in_evidence: false,
      result: "pass"
    }'
)"
if [ -n "$EVIDENCE_FILE" ]; then
  printf '%s\n' "$EVIDENCE" >"$EVIDENCE_FILE"
fi
printf '%s\n' "$EVIDENCE"
printf 'PASS: C9.4 tenant passkey isolation evidence published\n'
