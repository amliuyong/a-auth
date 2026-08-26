#!/usr/bin/env bash
# Live acceptance for issue #26: per-tenant EC/RSA signing keys.
#
# This script exercises the deployed AgentAuthSaas control plane and data plane:
#   * automatic t1/t2 onboarding and readiness admission;
#   * tenant-only EC+RSA JWKS and real ES256 access / RS256 ID tokens;
#   * cross-tenant signature rejection for both algorithms;
#   * publish-ahead, activate, rollback-overlap, and resumable full retirement;
#   * no key or availability change for the unrelated tenant.
#
# The default rollback gate takes about 11 minutes and leaves safe overlap
# retirement to the reconciler. The forward gate is split across
# ROTATION_MODE=forward-start and ROTATION_MODE=forward-finish so no local
# process needs to remain alive during the production 24-hour overlap.
#
# Usage:
#   AWS_PROFILE=default ./e2e/saas_tenant_keys.sh
#   ROTATION_MODE=forward-start AWS_PROFILE=default ./e2e/saas_tenant_keys.sh
#   # After the checkpoint's retire_after:
#   ROTATION_MODE=forward-finish AWS_PROFILE=default ./e2e/saas_tenant_keys.sh
set -euo pipefail
set +x

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
PROFILE="${PROFILE:-${AWS_PROFILE:-default}}"
REGION="${REGION:-${AWS_REGION:-us-east-1}}"
SAAS_STACK="${SAAS_STACK:-AgentAuthSaas}"
PUBLISH_WAIT_SECS="${PUBLISH_WAIT_SECS:-610}"
ROTATION_MODE="${ROTATION_MODE:-rollback}"
CHECKPOINT_FILE="${CHECKPOINT_FILE:-$REPO_ROOT/_my/e2e/issue26-forward.json}"
MIN_OVERLAP_SECS=86430

[[ "$ROTATION_MODE" == "rollback" ||
  "$ROTATION_MODE" == "forward-start" ||
  "$ROTATION_MODE" == "forward-finish" ]] ||
  { echo "ROTATION_MODE must be rollback, forward-start, or forward-finish" >&2; exit 1; }
if [[ "$ROTATION_MODE" != "forward-finish" ]]; then
  [[ "$PUBLISH_WAIT_SECS" -ge 600 ]] ||
    { echo "PUBLISH_WAIT_SECS must be at least 600" >&2; exit 1; }
fi

for command in aws curl jq python3; do
  command -v "$command" >/dev/null ||
    { echo "missing command: $command" >&2; exit 1; }
done
python3 -c 'import cryptography, jwt' >/dev/null 2>&1 ||
  { echo "python3 requires cryptography and PyJWT" >&2; exit 1; }

umask 077
WORK="$(mktemp -d)"
RUN_ID="$(python3 -c 'import secrets; print(secrets.token_hex(6))')"
OPERATION_ID="issue26-${RUN_ID}"
ROTATION_STARTED=0
ROTATION_FINISHED=0
CHECKPOINT_HANDOFF_DURABLE=0

declare -A BASE HEADER CLIENT USER_ID COOKIE INITIAL ACTIVE
declare -A INITIAL_KEY_ARN CANDIDATE_KEY_ARN CANDIDATE_KEY_KID

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

pass() {
  printf 'PASS: %s\n' "$1"
}

stack_resources() {
  aws cloudformation list-stack-resources \
    --stack-name "$SAAS_STACK" --profile "$PROFILE" --region "$REGION" \
    --output json
}

control_status() {
  local tenant="$1" output="$2"
  curl -fsS --proto '=https' --connect-timeout 5 --max-time 30 \
    -H "@${HEADER[platform]}" \
    "${BASE[platform]}/admin/control/tenants/${tenant}/keys" >"$output"
}

post_action() {
  local tenant="$1" action="$2" operation="$3" output="$4"
  local request="$WORK/action-${tenant}-${action}.json"
  local status
  jq -cn --arg operation "$operation" '{operation_id:$operation}' >"$request"
  status="$(curl -sS --proto '=https' --connect-timeout 5 --max-time 30 \
    -o "$output" -w '%{http_code}' -X POST \
    -H "@${HEADER[platform]}" -H 'content-type: application/json' \
    --data-binary "@$request" \
    "${BASE[platform]}/admin/control/tenants/${tenant}/keys/${action}")"
  [[ "$status" == "202" ]] ||
    fail "$tenant $action returned HTTP $status: $(<"$output")"
}

best_effort_rollback() {
  [[ "$ROTATION_STARTED" == "1" && "$ROTATION_FINISHED" == "0" ]] || return
  [[ -n "${HEADER[platform]:-}" && -f "${HEADER[platform]}" ]] || return
  local state="$WORK/cleanup-state.json"
  local request="$WORK/cleanup-rollback.json"
  local response="$WORK/cleanup-rollback-response.json"
  local deadline=$((SECONDS + 900))
  local observed_owned_operation=0
  local rollback_accepted=0
  local ready_without_operation_polls=0
  jq -cn --arg operation "$OPERATION_ID" '{operation_id:$operation}' >"$request"
  while (( SECONDS < deadline )); do
    if control_status t1 "$state" 2>/dev/null; then
      local lifecycle operation
      operation="$(jq -r '.operation_id // ""' "$state")"
      if [[ -n "$operation" && "$operation" != "$OPERATION_ID" ]]; then
        printf 'RECOVERY REQUIRED: t1 is owned by operation %s, not %s\n' \
          "$operation" "$OPERATION_ID" >&2
        return
      fi
      lifecycle="$(jq -r '.lifecycle' "$state")"
      case "$lifecycle" in
        provisioning)
          observed_owned_operation=1
          ;;
        publishing | active_overlap)
          observed_owned_operation=1
          if [[ "$lifecycle" == "active_overlap" &&
            "$CHECKPOINT_HANDOFF_DURABLE" == "1" &&
            -f "$CHECKPOINT_FILE" ]] &&
            jq -e --arg operation "$OPERATION_ID" \
              --argjson retire_after "$(jq -r '.retire_after' "$state")" '
              .phase == "active_overlap"
              and .operation_id == $operation
              and .retire_after == $retire_after
            ' "$CHECKPOINT_FILE" >/dev/null 2>&1; then
            printf 'RECOVERY: durable forward handoff retained for operation %s\n' \
              "$OPERATION_ID" >&2
            return
          fi
          local status
          if ! status="$(curl -sS -o "$response" -w '%{http_code}' --proto '=https' \
            --connect-timeout 5 --max-time 30 -X POST \
            -H "@${HEADER[platform]}" -H 'content-type: application/json' \
            --data-binary "@$request" \
            "${BASE[platform]}/admin/control/tenants/t1/keys/rollback" 2>/dev/null)"; then
            status=000
          fi
          if [[ "$status" == "202" ]]; then
            if [[ "$rollback_accepted" == "0" ]]; then
              printf 'RECOVERY: rollback accepted for interrupted operation %s\n' \
                "$OPERATION_ID" >&2
            fi
            rollback_accepted=1
          else
            printf 'RECOVERY RETRY: rollback returned HTTP %s: %s\n' \
              "$status" "$(cat "$response" 2>/dev/null)" >&2
          fi
          ;;
        rollback_overlap)
          printf 'RECOVERY: operation %s reached rollback_overlap\n' \
            "$OPERATION_ID" >&2
          return
          ;;
        ready)
          if status_failure_is_terminal_for_operation "$state" "$OPERATION_ID"; then
            printf 'RECOVERY: operation failed closed and t1 returned to ready: %s\n' \
              "$(jq -r '.last_failure' "$state")" >&2
            return
          fi
          if [[ "$rollback_accepted" == "1" ||
            "$observed_owned_operation" == "1" ]]; then
            printf 'RECOVERY: operation %s returned to ready\n' "$OPERATION_ID" >&2
            return
          fi
          ready_without_operation_polls=$((ready_without_operation_polls + 1))
          if (( ready_without_operation_polls >= 12 )); then
            printf 'RECOVERY: no remote operation observed for %s\n' \
              "$OPERATION_ID" >&2
            return
          fi
          ;;
        *)
          printf 'RECOVERY REQUIRED: unexpected t1 lifecycle %s for operation %s\n' \
            "$lifecycle" "$OPERATION_ID" >&2
          return
          ;;
      esac
    fi
    sleep 5
  done
  printf 'RECOVERY REQUIRED: operation %s did not reach a rollback-safe state\n' \
    "$OPERATION_ID" >&2
}

urlencode() {
  python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"
}

delete_fixture() {
  local header="$1" url="$2"
  local attempt status
  for attempt in 1 2 3; do
    if ! status="$(curl -sS -o /dev/null -w '%{http_code}' --proto '=https' \
      --connect-timeout 5 --max-time 30 -X DELETE -H "@$header" \
      "$url" 2>/dev/null)"; then
      status=000
    fi
    if [[ "$status" == "404" || "$status" == 2* ]]; then
      return
    fi
    sleep "$attempt"
  done
  printf 'CLEANUP WARNING: DELETE %s returned HTTP %s\n' "$url" "$status" >&2
}

cleanup_fixtures() {
  local tenant encoded
  for tenant in t1 t2; do
    if [[ -n "${CLIENT[$tenant]:-}" && -f "${HEADER[$tenant]:-}" ]]; then
      delete_fixture "${HEADER[$tenant]}" \
        "${BASE[$tenant]}/admin/clients/${CLIENT[$tenant]}"
    fi
    if [[ -n "${USER_ID[$tenant]:-}" && -f "${HEADER[$tenant]:-}" ]]; then
      encoded="$(urlencode "${USER_ID[$tenant]}")"
      delete_fixture "${HEADER[$tenant]}" \
        "${BASE[$tenant]}/admin/users/${encoded}"
    fi
  done
}

cleanup() {
  best_effort_rollback
  cleanup_fixtures
  rm -f -- "${CHECKPOINT_FILE}.tmp.$$"
  rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

status_failure_is_terminal_for_operation() {
  local output="$1" operation="$2"
  jq -e --arg operation "$operation" '
    (.last_failure // "") as $failure
    | (.last_failure_operation_id // "") as $failure_operation
    | ($failure != "")
      and ($failure_operation == $operation)
  ' "$output" >/dev/null
}

wait_for_lifecycle() {
  local tenant="$1" expected="$2" operation="$3" timeout="$4"
  local deadline=$((SECONDS + timeout))
  local output="$WORK/status-${tenant}.json"
  while (( SECONDS < deadline )); do
    if control_status "$tenant" "$output" 2>/dev/null; then
      local lifecycle current_operation
      lifecycle="$(jq -r '.lifecycle' "$output")"
      current_operation="$(jq -r '.operation_id // ""' "$output")"
      if [[ "$lifecycle" == "$expected" &&
        ( -z "$operation" || "$current_operation" == "$operation" ) ]]; then
        cp "$output" "$WORK/status-${tenant}-${expected}.json"
        return 0
      fi
      if status_failure_is_terminal_for_operation "$output" "$operation"; then
        fail "$tenant entered failure state: $(<"$output")"
      fi
    fi
    sleep 5
  done
  fail "timed out waiting for $tenant lifecycle=$expected; last status: $(<"$output")"
}

wait_for_ready() {
  local tenant="$1" timeout="$2"
  local deadline=$((SECONDS + timeout))
  local output="$WORK/status-${tenant}.json"
  while (( SECONDS < deadline )); do
    if control_status "$tenant" "$output" 2>/dev/null &&
      [[ "$(jq -r '.ready' "$output")" == "true" &&
        "$(jq -r '.lifecycle' "$output")" == "ready" &&
        "$(jq -r '.pending_deletions' "$output")" == "0" ]]; then
      cp "$output" "$WORK/status-${tenant}-ready.json"
      return 0
    fi
    sleep 5
  done
  fail "timed out waiting for $tenant readiness; last status: $(<"$output")"
}

fetch_jwks() {
  local tenant="$1" output="$2"
  curl -fsS --proto '=https' --connect-timeout 5 --max-time 30 \
    "${BASE[$tenant]}/jwks.json" >"$output"
}

assert_jwks_counts() {
  local file="$1" ec="$2" rsa="$3"
  python3 - "$file" "$ec" "$rsa" <<'PY'
import json
import pathlib
import sys

jwks = json.loads(pathlib.Path(sys.argv[1]).read_text())
ec = [key for key in jwks.get("keys", []) if key.get("kty") == "EC"]
rsa = [key for key in jwks.get("keys", []) if key.get("kty") == "RSA"]
assert len(ec) == int(sys.argv[2]), (len(ec), int(sys.argv[2]))
assert len(rsa) == int(sys.argv[3]), (len(rsa), int(sys.argv[3]))
assert len({key["kid"] for key in ec + rsa}) == len(ec) + len(rsa)
assert all(key.get("alg") == "ES256" and key.get("use") == "sig" for key in ec)
assert all(key.get("alg") == "RS256" and key.get("use") == "sig" for key in rsa)
PY
}

wait_for_jwks_counts() {
  local tenant="$1" ec="$2" rsa="$3" timeout="$4" output="$5"
  local deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if fetch_jwks "$tenant" "$output" 2>/dev/null &&
      assert_jwks_counts "$output" "$ec" "$rsa" 2>/dev/null; then
      return 0
    fi
    sleep 10
  done
  fail "timed out waiting for $tenant JWKS counts EC=$ec RSA=$rsa"
}

assert_disjoint_jwks() {
  local left="$1" right="$2"
  python3 - "$left" "$right" <<'PY'
import json
import pathlib
import sys

left = json.loads(pathlib.Path(sys.argv[1]).read_text())["keys"]
right = json.loads(pathlib.Path(sys.argv[2]).read_text())["keys"]
left_kids = {key["kid"] for key in left}
right_kids = {key["kid"] for key in right}
assert left_kids.isdisjoint(right_kids), (left_kids, right_kids)
PY
}

load_secret_header() {
  local owner="$1" arn="$2"
  local secret="$WORK/${owner}.token"
  aws secretsmanager get-secret-value \
    --secret-id "$arn" --profile "$PROFILE" --region "$REGION" \
    --output json |
    jq -er '.SecretString | fromjson | .current.secret
      | select(type == "string" and length >= 16)' >"$secret"
  printf 'authorization: Bearer %s\n' "$(<"$secret")" >"$WORK/${owner}.headers"
  HEADER["$owner"]="$WORK/${owner}.headers"
  rm -f "$secret"
}

setup_actor() {
  local tenant="$1"
  local email="issue26-${tenant}-${RUN_ID}@example.com"
  local create_user="$WORK/${tenant}-create-user.json"
  local create_client="$WORK/${tenant}-create-client.json"
  local change_password="$WORK/${tenant}-change-password.json"
  local response="$WORK/${tenant}-setup-response.json"
  local status

  INITIAL["$tenant"]="Init-$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
  ACTIVE["$tenant"]="Active-$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
  COOKIE["$tenant"]="$WORK/${tenant}.cookies"

  jq -cn --arg email "$email" --arg password "${INITIAL[$tenant]}" \
    '{email:$email,initial_password:$password}' >"$create_user"
  status="$(curl -sS -o "$response" -w '%{http_code}' --proto '=https' \
    --connect-timeout 5 --max-time 60 -X POST \
    -H "@${HEADER[$tenant]}" -H 'content-type: application/json' \
    --data-binary "@$create_user" "${BASE[$tenant]}/admin/users")"
  [[ "$status" == "201" ]] ||
    fail "$tenant user creation returned HTTP $status: $(<"$response")"
  USER_ID["$tenant"]="$(jq -er '.user_id' "$response")"

  jq -cn --arg email "$email" --arg current "${INITIAL[$tenant]}" \
    --arg new "${ACTIVE[$tenant]}" \
    '{email:$email,current_password:$current,new_password:$new}' >"$change_password"
  status="$(curl -sS -o "$response" -w '%{http_code}' --proto '=https' \
    --connect-timeout 5 --max-time 60 -c "${COOKIE[$tenant]}" -X POST \
    -H 'content-type: application/json' --data-binary "@$change_password" \
    "${BASE[$tenant]}/login/password/change")"
  [[ "$status" == "200" ]] ||
    fail "$tenant password activation returned HTTP $status: $(<"$response")"
  grep -q '__Host-agent_auth_session' "${COOKIE[$tenant]}" ||
    fail "$tenant password activation did not create a session"

  jq -cn '{redirect_uris:["http://127.0.0.1/callback"],
    token_endpoint_auth_method:"none"}' >"$create_client"
  status="$(curl -sS -o "$response" -w '%{http_code}' --proto '=https' \
    --connect-timeout 5 --max-time 60 -X POST \
    -H "@${HEADER[$tenant]}" -H 'content-type: application/json' \
    --data-binary "@$create_client" "${BASE[$tenant]}/admin/clients")"
  [[ "$status" == "201" ]] ||
    fail "$tenant client creation returned HTTP $status: $(<"$response")"
  CLIENT["$tenant"]="$(jq -er '.client_id' "$response")"
}

mint_pair() {
  local tenant="$1" label="$2"
  local verifier="0123456789012345678901234567890123456789abc"
  local challenge nonce query csrf redirect_result code status
  local response="$WORK/${tenant}-${label}-response.json"
  local token_file="$WORK/${tenant}-${label}-tokens.json"
  local decision="$WORK/${tenant}-${label}-decision.json"
  local jwks="$WORK/${tenant}-${label}-jwks.json"

  challenge="$(VERIFIER="$verifier" python3 -c \
    'import base64,hashlib,os; print(base64.urlsafe_b64encode(hashlib.sha256(os.environ["VERIFIER"].encode()).digest()).rstrip(b"=").decode())')"
  nonce="${tenant}-${label}-${RUN_ID}"
  query="$(python3 - "${CLIENT[$tenant]}" "$challenge" "$nonce" <<'PY'
import sys
import urllib.parse

print(urllib.parse.urlencode({
    "client_id": sys.argv[1],
    "redirect_uri": "http://127.0.0.1/callback",
    "scope": "openid",
    "state": "issue26",
    "code_challenge": sys.argv[2],
    "code_challenge_method": "S256",
    "nonce": sys.argv[3],
}))
PY
)"
  curl -fsS --proto '=https' --connect-timeout 5 --max-time 30 \
    -b "${COOKIE[$tenant]}" \
    "${BASE[$tenant]}/consent/context?${query}" >"$response"
  csrf="$(jq -er '.csrf_token' "$response")"
  jq -cn --arg csrf "$csrf" --arg query "$query" \
    '{decision:"approve",csrf:$csrf,authorize_query:$query}' >"$decision"
  curl -fsS --proto '=https' --connect-timeout 5 --max-time 30 \
    -b "${COOKIE[$tenant]}" -X POST -H 'content-type: application/json' \
    --data-binary "@$decision" "${BASE[$tenant]}/consent/decision" >"$response"
  redirect_result="$(jq -er '.redirect' "$response")"
  code="$(REDIRECT_RESULT="$redirect_result" python3 -c \
    'import os,urllib.parse; print(urllib.parse.parse_qs(urllib.parse.urlparse(os.environ["REDIRECT_RESULT"]).query).get("code",[""])[0])')"
  [[ -n "$code" ]] || fail "$tenant $label consent returned no code"

  status="$(curl -sS -o "$token_file" -w '%{http_code}' --proto '=https' \
    --connect-timeout 5 --max-time 60 -X POST \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=authorization_code' \
    --data-urlencode "code=$code" \
    --data-urlencode "code_verifier=$verifier" \
    --data-urlencode 'redirect_uri=http://127.0.0.1/callback' \
    --data-urlencode "client_id=${CLIENT[$tenant]}" \
    "${BASE[$tenant]}/token")"
  [[ "$status" == "200" ]] ||
    fail "$tenant $label token exchange returned HTTP $status: $(<"$token_file")"
  fetch_jwks "$tenant" "$jwks"
  verify_pair "$token_file" "$jwks" "${BASE[$tenant]}" "${CLIENT[$tenant]}" 0
}

verify_pair() {
  local tokens="$1" jwks="$2" issuer="$3" client="$4" allow_expired="${5:-0}"
  python3 - "$tokens" "$jwks" "$issuer" "$client" "$allow_expired" <<'PY'
import json
import pathlib
import sys

import jwt
from jwt import algorithms

tokens = json.loads(pathlib.Path(sys.argv[1]).read_text())
jwks = json.loads(pathlib.Path(sys.argv[2]).read_text())["keys"]
issuer, client = sys.argv[3], sys.argv[4]
options = {"verify_exp": sys.argv[5] != "1"}

def matching_key(token, kty):
    header = jwt.get_unverified_header(token)
    matches = [key for key in jwks
               if key.get("kid") == header.get("kid") and key.get("kty") == kty]
    assert len(matches) == 1, (header, [key.get("kid") for key in jwks])
    return header, matches[0]

access = tokens["access_token"]
access_header, access_jwk = matching_key(access, "EC")
assert access_header["alg"] == "ES256"
access_key = algorithms.ECAlgorithm.from_jwk(json.dumps(access_jwk))
access_claims = jwt.decode(
    access,
    key=access_key,
    algorithms=["ES256"],
    audience=issuer + "/userinfo",
    issuer=issuer,
    options=options,
)

identity = tokens["id_token"]
identity_header, identity_jwk = matching_key(identity, "RSA")
assert identity_header["alg"] == "RS256"
identity_key = algorithms.RSAAlgorithm.from_jwk(json.dumps(identity_jwk))
identity_claims = jwt.decode(
    identity,
    key=identity_key,
    algorithms=["RS256"],
    audience=client,
    issuer=issuer,
    options=options,
)
assert access_claims["sub"] == identity_claims["sub"]
PY
}

token_kid() {
  local tokens="$1" field="$2"
  python3 - "$tokens" "$field" <<'PY'
import json
import pathlib
import sys

import jwt

tokens = json.loads(pathlib.Path(sys.argv[1]).read_text())
print(jwt.get_unverified_header(tokens[sys.argv[2]])["kid"])
PY
}

assert_cross_tenant_rejection() {
  local left_tokens="$1" left_jwks="$2" right_tokens="$3" right_jwks="$4"
  python3 - "$left_tokens" "$left_jwks" "$right_tokens" "$right_jwks" <<'PY'
import json
import pathlib
import sys

import jwt
from jwt import algorithms

left_tokens = json.loads(pathlib.Path(sys.argv[1]).read_text())
left_keys = json.loads(pathlib.Path(sys.argv[2]).read_text())["keys"]
right_tokens = json.loads(pathlib.Path(sys.argv[3]).read_text())
right_keys = json.loads(pathlib.Path(sys.argv[4]).read_text())["keys"]

def reject(tokens, foreign_keys, field, kty, alg, loader):
    token = tokens[field]
    header = jwt.get_unverified_header(token)
    assert header["kid"] not in {key["kid"] for key in foreign_keys}
    candidates = [key for key in foreign_keys if key.get("kty") == kty]
    assert candidates
    for jwk in candidates:
        key = loader.from_jwk(json.dumps(jwk))
        try:
            jwt.decode(
                token,
                key=key,
                algorithms=[alg],
                options={"verify_aud": False, "verify_iss": False},
            )
        except jwt.InvalidSignatureError:
            continue
        raise AssertionError(f"{field} validated with a foreign tenant key")

for tokens, foreign in ((left_tokens, right_keys), (right_tokens, left_keys)):
    reject(tokens, foreign, "access_token", "EC", "ES256", algorithms.ECAlgorithm)
    reject(tokens, foreign, "id_token", "RSA", "RS256", algorithms.RSAAlgorithm)
PY
}

assert_managed_key_tags() {
  local tenant="$1" operation="$2" generation="$3" algorithm="$4"
  local key_arn="$5" region="$6"
  local output="$WORK/${tenant}-${algorithm}-${region}-tags.json"
  aws kms list-resource-tags \
    --key-id "$key_arn" --profile "$PROFILE" --region "$region" \
    --output json >"$output"
  jq -e \
    --arg deployment "$TENANT_KEYS_TABLE" \
    --arg tenant "$tenant" \
    --arg operation "$operation" \
    --arg generation "$generation" \
    --arg algorithm "$algorithm" '
    [.Tags[]
      | select(.TagKey | startswith("agent-auth-"))
      | {key: .TagKey, value: .TagValue}]
    | from_entries == {
        "agent-auth-managed": "true",
        "agent-auth-deployment": $deployment,
        "agent-auth-tenant": $tenant,
        "agent-auth-operation": $operation,
        "agent-auth-algorithm": $algorithm,
        "agent-auth-generation": $generation
      }
  ' "$output" >/dev/null ||
    fail "$tenant $algorithm key in $region has an invalid deployment-scoped tag set"
}

assert_candidate_mrk_replicas() {
  local tenant="$1"
  local record="$WORK/${tenant}-candidate-record.json"
  aws dynamodb get-item \
    --table-name "$TENANT_KEYS_TABLE" \
    --key "{\"tenant_id\":{\"S\":\"$tenant\"}}" \
    --consistent-read --profile "$PROFILE" --region "$REGION" \
    --query 'Item.record_json.S' --output text >"$record"
  jq -e --arg operation "$OPERATION_ID" '
    .lifecycle == "publishing"
    and .operation.operation_id == $operation
    and (.operation.candidate.ec.public_jwk | type == "object")
    and (.operation.candidate.rsa.public_jwk | type == "object")
  ' "$record" >/dev/null ||
    fail "$tenant registry has no fully probed publishing candidate"

  local algorithm primary_arn signing_algorithm jwk_file primary_public
  local generation tag_algorithm
  generation="$(jq -er '.operation.candidate.generation' "$record")"
  for algorithm in ec rsa; do
    primary_arn="$(jq -er ".operation.candidate.${algorithm}.key_arn" "$record")"
    CANDIDATE_KEY_ARN["$algorithm"]="$primary_arn"
    CANDIDATE_KEY_KID["$algorithm"]="$(jq -er \
      ".operation.candidate.${algorithm}.public_jwk.kid" "$record")"
    [[ "$primary_arn" == *":key/mrk-"* ]] ||
      fail "$tenant $algorithm candidate is not a KMS multi-Region key"
    jwk_file="$WORK/${tenant}-${algorithm}-candidate-jwk.json"
    jq ".operation.candidate.${algorithm}.public_jwk" "$record" >"$jwk_file"
    if [[ "$algorithm" == "ec" ]]; then
      signing_algorithm=ECDSA_SHA_256
      tag_algorithm=es256
    else
      signing_algorithm=RSASSA_PKCS1_V1_5_SHA_256
      tag_algorithm=rs256
    fi
    primary_public="$(aws kms get-public-key \
      --key-id "$primary_arn" --profile "$PROFILE" --region "$REGION" \
      --query PublicKey --output text)"
    assert_managed_key_tags \
      "$tenant" "$OPERATION_ID" "$generation" "$tag_algorithm" \
      "$primary_arn" "$REGION"

    local replica_region replica_arn replica_metadata replica_public signature_file
    while IFS= read -r replica_region; do
      replica_arn="$(python3 - "$primary_arn" "$replica_region" <<'PY'
import sys

parts = sys.argv[1].split(":", 5)
assert len(parts) == 6 and parts[2] == "kms" and parts[5].startswith("key/mrk-")
parts[3] = sys.argv[2]
print(":".join(parts))
PY
)"
      replica_metadata="$WORK/${tenant}-${algorithm}-${replica_region}-metadata.json"
      aws kms describe-key \
        --key-id "$replica_arn" --profile "$PROFILE" --region "$replica_region" \
        --query 'KeyMetadata.{state:KeyState,type:MultiRegionConfiguration.MultiRegionKeyType,primary:MultiRegionConfiguration.PrimaryKey.Arn}' \
        --output json >"$replica_metadata"
      jq -e --arg primary "$primary_arn" '
        .state == "Enabled" and .type == "REPLICA" and .primary == $primary
      ' "$replica_metadata" >/dev/null ||
        fail "$tenant $algorithm replica in $replica_region is not enabled or bound to primary"
      replica_public="$(aws kms get-public-key \
        --key-id "$replica_arn" --profile "$PROFILE" --region "$replica_region" \
        --query PublicKey --output text)"
      [[ "$replica_public" == "$primary_public" ]] ||
        fail "$tenant $algorithm replica public key differs in $replica_region"
      assert_managed_key_tags \
        "$tenant" "$OPERATION_ID" "$generation" "$tag_algorithm" \
        "$replica_arn" "$replica_region"

      signature_file="$WORK/${tenant}-${algorithm}-${replica_region}.signature"
      aws kms sign \
        --key-id "$replica_arn" --profile "$PROFILE" --region "$replica_region" \
        --message-type RAW --signing-algorithm "$signing_algorithm" \
        --message "fileb://$WORK/mrk-probe-message" \
        --query Signature --output text |
        python3 -c 'import base64,sys; sys.stdout.buffer.write(base64.b64decode(sys.stdin.read()))' \
          >"$signature_file"
      python3 - "$algorithm" "$jwk_file" "$signature_file" "$WORK/mrk-probe-message" <<'PY'
import base64
import json
import pathlib
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

algorithm, jwk_path, signature_path, message_path = sys.argv[1:]
jwk = json.loads(pathlib.Path(jwk_path).read_text())
signature = pathlib.Path(signature_path).read_bytes()
message = pathlib.Path(message_path).read_bytes()

def b64url(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

if algorithm == "ec":
    public = ec.EllipticCurvePublicNumbers(
        int.from_bytes(b64url(jwk["x"]), "big"),
        int.from_bytes(b64url(jwk["y"]), "big"),
        ec.SECP256R1(),
    ).public_key()
    public.verify(signature, message, ec.ECDSA(hashes.SHA256()))
else:
    public = rsa.RSAPublicNumbers(
        int.from_bytes(b64url(jwk["e"]), "big"),
        int.from_bytes(b64url(jwk["n"]), "big"),
    ).public_key()
    public.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
PY
    done < <(jq -r '.[]' <<<"$REPLICA_REGIONS_JSON")
  done
}

read_registry_record() {
  local tenant="$1" record="$2"
  aws dynamodb get-item \
    --table-name "$TENANT_KEYS_TABLE" \
    --key "{\"tenant_id\":{\"S\":\"$tenant\"}}" \
    --consistent-read --profile "$PROFILE" --region "$REGION" \
    --query 'Item.record_json.S' --output text >"$record"
}

capture_initial_key_records() {
  local tenant
  for tenant in t1 t2; do
    read_registry_record "$tenant" "$WORK/${tenant}-initial-record.json"
  done
  INITIAL_KEY_ARN[ec]="$(jq -er '.served_snapshot.ec.active.key_arn' \
    "$WORK/t1-initial-record.json")"
  INITIAL_KEY_ARN[rsa]="$(jq -er '.served_snapshot.rsa.active.key_arn' \
    "$WORK/t1-initial-record.json")"
}

assert_t2_registry_unchanged() {
  local current="$WORK/t2-current-record.json"
  read_registry_record t2 "$current"
  jq -e \
    --argjson revision "$(jq -er '.revision' "$WORK/t2-initial-record.json")" \
    --arg ec "$(jq -er '.served_snapshot.ec.active.key_arn' \
      "$WORK/t2-initial-record.json")" \
    --arg rsa "$(jq -er '.served_snapshot.rsa.active.key_arn' \
      "$WORK/t2-initial-record.json")" '
    .lifecycle == "ready"
    and .revision == $revision
    and .served_snapshot.ec.active.key_arn == $ec
    and .served_snapshot.rsa.active.key_arn == $rsa
  ' "$current" >/dev/null ||
    fail "t2 key registry changed during the t1 lifecycle"
}

wait_for_retired_key_deletion() {
  local algorithm="$1" key_arn="$2"
  local metadata="$WORK/t1-${algorithm}-retired-metadata.json"
  local error="$WORK/t1-${algorithm}-retired-error.txt"
  local deadline=$((SECONDS + 300))
  local deletion_observed=0
  while (( SECONDS < deadline )); do
    if aws kms describe-key \
      --key-id "$key_arn" --profile "$PROFILE" --region "$REGION" \
      --query 'KeyMetadata.{state:KeyState,multi_region:MultiRegion,type:MultiRegionConfiguration.MultiRegionKeyType,replicas:MultiRegionConfiguration.ReplicaKeys[].{arn:Arn,region:Region}}' \
      --output json >"$metadata" 2>"$error" &&
      jq -e '
        if .multi_region
        then .type == "PRIMARY"
          and (
            .state == "PendingDeletion"
            or (
              .state == "PendingReplicaDeletion"
              and (.replicas | type == "array")
            )
          )
        else .state == "PendingDeletion"
        end
      ' "$metadata" >/dev/null; then
      deletion_observed=1
      break
    fi
    if grep -q 'NotFoundException' "$error" 2>/dev/null; then
      return
    fi
    sleep 5
  done
  if [[ "$deletion_observed" == "0" ]]; then
    fail "$algorithm retired KMS primary did not enter its deletion state: $(cat "$metadata" "$error" 2>/dev/null)"
  fi

  if [[ "$(jq -r '.multi_region' "$metadata")" != "true" ||
    "$(jq -r '.state' "$metadata")" == "PendingDeletion" ]]; then
    return
  fi

  local replica_arn replica_region replica_metadata replica_error
  while IFS=$'\t' read -r replica_region replica_arn; do
    replica_metadata="$WORK/t1-${algorithm}-${replica_region}-retired-metadata.json"
    replica_error="$WORK/t1-${algorithm}-${replica_region}-retired-error.txt"
    deadline=$((SECONDS + 300))
    deletion_observed=0
    while (( SECONDS < deadline )); do
      if aws kms describe-key \
        --key-id "$replica_arn" --profile "$PROFILE" --region "$replica_region" \
        --query 'KeyMetadata.{state:KeyState,type:MultiRegionConfiguration.MultiRegionKeyType,primary:MultiRegionConfiguration.PrimaryKey.Arn}' \
        --output json >"$replica_metadata" 2>"$replica_error" &&
        jq -e --arg primary "$key_arn" '
          .state == "PendingDeletion"
          and .type == "REPLICA"
          and .primary == $primary
        ' "$replica_metadata" >/dev/null; then
        deletion_observed=1
        break
      fi
      if grep -q 'NotFoundException' "$replica_error" 2>/dev/null; then
        deletion_observed=1
        break
      fi
      sleep 5
    done
    if [[ "$deletion_observed" == "0" ]]; then
      fail "$algorithm replica in $replica_region did not enter PendingDeletion: $(cat "$replica_metadata" "$replica_error" 2>/dev/null)"
    fi
  done < <(jq -r '.replicas[] | [.region, .arn] | @tsv' "$metadata")
}

write_forward_checkpoint() {
  local phase="$1"
  local checkpoint_dir checkpoint_tmp activated_at_json retire_after_json
  [[ "$phase" == "prepared" || "$phase" == "active_overlap" ]] ||
    fail "invalid forward checkpoint phase: $phase"
  if [[ "$phase" == "active_overlap" ]]; then
    activated_at_json="$ACTIVATE_REQUESTED_AT"
    retire_after_json="$RETIRE_AFTER"
  else
    activated_at_json=null
    retire_after_json=null
  fi
  checkpoint_dir="$(dirname -- "$CHECKPOINT_FILE")"
  checkpoint_tmp="${CHECKPOINT_FILE}.tmp.$$"
  mkdir -p -- "$checkpoint_dir"
  jq -n \
    --arg kind "agent-auth-saas-tenant-keys-forward" \
    --arg phase "$phase" \
    --arg account_id "$ACCOUNT_ID" \
    --arg region "$REGION" \
    --arg stack_name "$SAAS_STACK" \
    --arg stack_id "$STACK_ID" \
    --arg tenant_keys_table "$TENANT_KEYS_TABLE" \
    --arg operation_id "$OPERATION_ID" \
    --argjson activated_at "$activated_at_json" \
    --argjson retire_after "$retire_after_json" \
    --arg t1_old_ec_arn "${INITIAL_KEY_ARN[ec]}" \
    --arg t1_old_ec_kid "$T1_OLD_EC" \
    --arg t1_old_rsa_arn "${INITIAL_KEY_ARN[rsa]}" \
    --arg t1_old_rsa_kid "$T1_OLD_RSA" \
    --arg t1_new_ec_arn "${CANDIDATE_KEY_ARN[ec]}" \
    --arg t1_new_ec_kid "$T1_NEW_EC" \
    --arg t1_new_rsa_arn "${CANDIDATE_KEY_ARN[rsa]}" \
    --arg t1_new_rsa_kid "$T1_NEW_RSA" \
    --arg t2_ec_arn "$(jq -er '.served_snapshot.ec.active.key_arn' \
      "$WORK/t2-initial-record.json")" \
    --arg t2_ec_kid "$(jq -er '.served_snapshot.ec.active.public_jwk.kid' \
      "$WORK/t2-initial-record.json")" \
    --arg t2_rsa_arn "$(jq -er '.served_snapshot.rsa.active.key_arn' \
      "$WORK/t2-initial-record.json")" \
    --arg t2_rsa_kid "$(jq -er '.served_snapshot.rsa.active.public_jwk.kid' \
      "$WORK/t2-initial-record.json")" \
    --argjson t2_revision "$(jq -er '.revision' "$WORK/t2-initial-record.json")" \
    '{
      schema_version: 1,
      kind: $kind,
      phase: $phase,
      target: {
        account_id: $account_id,
        region: $region,
        stack_name: $stack_name,
        stack_id: $stack_id,
        tenant_keys_table: $tenant_keys_table
      },
      operation_id: $operation_id,
      activated_at: $activated_at,
      retire_after: $retire_after,
      t1: {
        old: {
          ec: {arn: $t1_old_ec_arn, kid: $t1_old_ec_kid},
          rsa: {arn: $t1_old_rsa_arn, kid: $t1_old_rsa_kid}
        },
        new: {
          ec: {arn: $t1_new_ec_arn, kid: $t1_new_ec_kid},
          rsa: {arn: $t1_new_rsa_arn, kid: $t1_new_rsa_kid}
        }
      },
      t2: {
        revision: $t2_revision,
        ec: {arn: $t2_ec_arn, kid: $t2_ec_kid},
        rsa: {arn: $t2_rsa_arn, kid: $t2_rsa_kid}
      }
    }' >"$checkpoint_tmp"
  chmod 600 "$checkpoint_tmp"
  python3 - "$checkpoint_tmp" <<'PY'
import os
import sys

fd = os.open(sys.argv[1], os.O_RDONLY)
try:
    os.fsync(fd)
finally:
    os.close(fd)
PY
  mv -f -- "$checkpoint_tmp" "$CHECKPOINT_FILE"
  python3 - "$checkpoint_dir" <<'PY'
import os
import sys

fd = os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(fd)
finally:
    os.close(fd)
PY
  if [[ "$phase" == "active_overlap" ]]; then
    CHECKPOINT_HANDOFF_DURABLE=1
  fi
}

finish_forward_gate() {
  [[ -f "$CHECKPOINT_FILE" ]] ||
    fail "forward checkpoint not found: $CHECKPOINT_FILE"
  jq -e '
    .schema_version == 1
    and .kind == "agent-auth-saas-tenant-keys-forward"
    and (.phase == "prepared" or .phase == "active_overlap")
    and (.operation_id | type == "string" and length > 0)
    and (
      if .phase == "active_overlap"
      then (.activated_at | type == "number")
        and (.retire_after | type == "number")
      else .activated_at == null and .retire_after == null
      end
    )
    and (.t2.revision | type == "number")
    and ([.t1.old.ec, .t1.old.rsa, .t1.new.ec, .t1.new.rsa, .t2.ec, .t2.rsa]
      | all(
          (.arn | type == "string" and length > 0)
          and (.kid | type == "string" and length > 0)
        ))
  ' "$CHECKPOINT_FILE" >/dev/null ||
    fail "invalid forward checkpoint: $CHECKPOINT_FILE"

  [[ "$(jq -r '.target.account_id' "$CHECKPOINT_FILE")" == "$ACCOUNT_ID" &&
    "$(jq -r '.target.region' "$CHECKPOINT_FILE")" == "$REGION" &&
    "$(jq -r '.target.stack_name' "$CHECKPOINT_FILE")" == "$SAAS_STACK" &&
    "$(jq -r '.target.stack_id' "$CHECKPOINT_FILE")" == "$STACK_ID" &&
    "$(jq -r '.target.tenant_keys_table' "$CHECKPOINT_FILE")" == "$TENANT_KEYS_TABLE" ]] ||
    fail "forward checkpoint target does not match the deployed stack"

  OPERATION_ID="$(jq -er '.operation_id' "$CHECKPOINT_FILE")"
  local phase
  phase="$(jq -er '.phase' "$CHECKPOINT_FILE")"
  if [[ "$phase" == "prepared" ]]; then
    local prepared_record="$WORK/t1-forward-prepared-record.json"
    read_registry_record t1 "$prepared_record"
    if [[ "$(jq -r '.operation.operation_id // ""' "$prepared_record")" == \
      "$OPERATION_ID" ]]; then
      ROTATION_STARTED=1
      best_effort_rollback
      ROTATION_STARTED=0
    fi
    fail "forward-start did not complete its active handoff; remote recovery was attempted, rerun forward-start"
  fi

  RETIRE_AFTER="$(jq -er '.retire_after' "$CHECKPOINT_FILE")"
  local now lifecycle record="$WORK/t1-forward-finish-record.json"
  now="$(date +%s)"
  if (( now < RETIRE_AFTER )); then
    fail "forward overlap is not eligible for retirement until $(date -u -d "@$RETIRE_AFTER" '+%Y-%m-%d %H:%M:%S UTC')"
  fi

  echo "== 2. Complete or observe the persisted forward retirement =="
  read_registry_record t1 "$record"
  lifecycle="$(jq -er '.lifecycle' "$record")"
  case "$lifecycle" in
    active_overlap)
      jq -e --arg operation "$OPERATION_ID" --argjson retire_after "$RETIRE_AFTER" '
        .operation.operation_id == $operation
        and .operation.retire_after == $retire_after
      ' "$record" >/dev/null ||
        fail "deployed forward overlap does not match the checkpoint"
      post_action t1 retire "$OPERATION_ID" "$WORK/retire-accepted.json"
      ;;
    ready)
      ;;
    *)
      fail "expected t1 active_overlap or ready, got $lifecycle"
      ;;
  esac
  wait_for_ready t1 420
  read_registry_record t1 "$record"

  local old_ec_arn old_rsa_arn new_ec_arn new_rsa_arn
  local new_ec_kid new_rsa_kid t2_revision
  local t2_ec_arn t2_rsa_arn t2_ec_kid t2_rsa_kid
  old_ec_arn="$(jq -er '.t1.old.ec.arn' "$CHECKPOINT_FILE")"
  old_rsa_arn="$(jq -er '.t1.old.rsa.arn' "$CHECKPOINT_FILE")"
  new_ec_arn="$(jq -er '.t1.new.ec.arn' "$CHECKPOINT_FILE")"
  new_rsa_arn="$(jq -er '.t1.new.rsa.arn' "$CHECKPOINT_FILE")"
  new_ec_kid="$(jq -er '.t1.new.ec.kid' "$CHECKPOINT_FILE")"
  new_rsa_kid="$(jq -er '.t1.new.rsa.kid' "$CHECKPOINT_FILE")"
  t2_ec_arn="$(jq -er '.t2.ec.arn' "$CHECKPOINT_FILE")"
  t2_rsa_arn="$(jq -er '.t2.rsa.arn' "$CHECKPOINT_FILE")"
  t2_ec_kid="$(jq -er '.t2.ec.kid' "$CHECKPOINT_FILE")"
  t2_rsa_kid="$(jq -er '.t2.rsa.kid' "$CHECKPOINT_FILE")"
  t2_revision="$(jq -er '.t2.revision' "$CHECKPOINT_FILE")"

  jq -e \
    --arg operation "$OPERATION_ID" \
    --arg old_ec "$old_ec_arn" --arg old_rsa "$old_rsa_arn" \
    --arg new_ec "$new_ec_arn" --arg new_rsa "$new_rsa_arn" \
    --arg new_ec_kid "$new_ec_kid" --arg new_rsa_kid "$new_rsa_kid" '
    .lifecycle == "ready"
    and .last_completed_operation_id == $operation
    and .last_completed_outcome == "retired_forward"
    and (.pending_deletion_arns | length == 0)
    and (.scheduled_deletion_arns | index($old_ec) != null)
    and (.scheduled_deletion_arns | index($old_rsa) != null)
    and .served_snapshot.ec.active.key_arn == $new_ec
    and .served_snapshot.rsa.active.key_arn == $new_rsa
    and .served_snapshot.ec.active.public_jwk.kid == $new_ec_kid
    and .served_snapshot.rsa.active.public_jwk.kid == $new_rsa_kid
  ' "$record" >/dev/null ||
    fail "t1 retirement record does not match the forward checkpoint"

  echo "== 3. Re-check final JWKS, signing, and tenant isolation =="
  wait_for_jwks_counts t1 1 1 420 "$WORK/t1-final-jwks.json"
  fetch_jwks t2 "$WORK/t2-final-jwks.json"
  assert_jwks_counts "$WORK/t2-final-jwks.json" 1 1
  [[ "$(jq -r '.keys[] | select(.kty=="EC") | .kid' \
    "$WORK/t1-final-jwks.json")" == "$new_ec_kid" &&
    "$(jq -r '.keys[] | select(.kty=="RSA") | .kid' \
      "$WORK/t1-final-jwks.json")" == "$new_rsa_kid" ]] ||
    fail "t1 final JWKS did not preserve the activated generation"

  read_registry_record t2 "$WORK/t2-forward-finish-record.json"
  jq -e \
    --argjson revision "$t2_revision" \
    --arg ec "$t2_ec_arn" --arg rsa "$t2_rsa_arn" \
    --arg ec_kid "$t2_ec_kid" --arg rsa_kid "$t2_rsa_kid" '
    .lifecycle == "ready"
    and .revision == $revision
    and .served_snapshot.ec.active.key_arn == $ec
    and .served_snapshot.rsa.active.key_arn == $rsa
    and .served_snapshot.ec.active.public_jwk.kid == $ec_kid
    and .served_snapshot.rsa.active.public_jwk.kid == $rsa_kid
  ' "$WORK/t2-forward-finish-record.json" >/dev/null ||
    fail "t2 key record changed during the t1 forward lifecycle"
  [[ "$(jq -r '.keys[] | select(.kty=="EC") | .kid' \
    "$WORK/t2-final-jwks.json")" == "$t2_ec_kid" &&
    "$(jq -r '.keys[] | select(.kty=="RSA") | .kid' \
      "$WORK/t2-final-jwks.json")" == "$t2_rsa_kid" ]] ||
    fail "t2 JWKS changed during the t1 forward lifecycle"

  local tenant
  for tenant in t1 t2; do
    setup_actor "$tenant"
    mint_pair "$tenant" final
  done
  assert_cross_tenant_rejection \
    "$WORK/t1-final-tokens.json" "$WORK/t1-final-jwks.json" \
    "$WORK/t2-final-tokens.json" "$WORK/t2-final-jwks.json"
  assert_disjoint_jwks "$WORK/t1-final-jwks.json" "$WORK/t2-final-jwks.json"
  wait_for_retired_key_deletion ec "$old_ec_arn"
  wait_for_retired_key_deletion rsa "$old_rsa_arn"
  pass "forward retirement completed, KMS deletion was scheduled, and t2 stayed unchanged"
  echo "Issue #26 forward live acceptance passed."
}

echo "== 1. Discover the deployed SaaS registry and credentials =="
aws cloudformation describe-stacks \
  --stack-name "$SAAS_STACK" --profile "$PROFILE" --region "$REGION" \
  --query 'Stacks[0].{status:StackStatus,id:StackId}' --output json >"$WORK/stack.json"
STACK_STATUS="$(jq -er '.status' "$WORK/stack.json")"
STACK_ID="$(jq -er '.id' "$WORK/stack.json")"
ACCOUNT_ID="$(aws sts get-caller-identity --profile "$PROFILE" \
  --query Account --output text)"
[[ "$STACK_STATUS" == "UPDATE_COMPLETE" ]] ||
  fail "$SAAS_STACK must be UPDATE_COMPLETE, got $STACK_STATUS"

stack_resources >"$WORK/resources.json"
printf 'agent-auth-tenant-key-readiness-v1' >"$WORK/mrk-probe-message"
AUTH_FN="$(jq -er '
  [.StackResourceSummaries[]
   | select(.ResourceType == "AWS::Lambda::Function")
   | select(.LogicalResourceId | startswith("AuthFn"))
   | .PhysicalResourceId] | unique
   | if length == 1 then .[0] else error("expected one AuthFn") end
' "$WORK/resources.json")"
PROVISIONER_FN="$(jq -er '
  [.StackResourceSummaries[]
   | select(.ResourceType == "AWS::Lambda::Function")
   | select(.LogicalResourceId | startswith("TenantKeyProvisionerFn"))
   | .PhysicalResourceId] | unique
   | if length == 1 then .[0] else error("expected one TenantKeyProvisionerFn") end
' "$WORK/resources.json")"
aws lambda get-function-configuration \
  --function-name "$AUTH_FN" --profile "$PROFILE" --region "$REGION" \
  --query 'Environment.Variables.{form:AGENT_AUTH_FORM,zone:AGENT_AUTH_ZONE,control_host:AGENT_AUTH_CONTROL_HOST,bootstrap:AGENT_AUTH_BOOTSTRAP_CONFIG_SECRET_ARN,tenant_keys_table:TENANT_KEYS_TABLE}' \
  --output json >"$WORK/runtime.json"
aws secretsmanager get-secret-value \
  --secret-id "$(jq -er '.bootstrap' "$WORK/runtime.json")" \
  --profile "$PROFILE" --region "$REGION" \
  --query SecretString --output text >"$WORK/runtime-bootstrap.json"
aws lambda get-function-configuration \
  --function-name "$PROVISIONER_FN" --profile "$PROFILE" --region "$REGION" \
  --query 'Environment.Variables.{replica_regions:TENANT_KEY_REPLICA_REGIONS}' \
  --output json >"$WORK/provisioner-runtime.json"
jq -e '
  .form == "saas"
  and (.tenant_keys_table | type == "string" and length > 0)
' "$WORK/runtime.json" >/dev/null ||
  fail "deployed AuthFn is not the expected t1/t2 tenant-key SaaS runtime"
jq -e '
  .schema_version == 1
  and (.saas_tenants == ["t1","t2"])
  and ((.tenant_admin_secret_arns | keys | sort) == ["t1","t2"])
  and (.admin_credential_secret_arn | contains(":secretsmanager:"))
' "$WORK/runtime-bootstrap.json" >/dev/null ||
  fail "deployed AuthFn bootstrap config is not the expected t1/t2 registry"
REPLICA_REGIONS_JSON="$(jq -cer '
  .replica_regions | fromjson
  | select(type == "array" and length > 0)
' "$WORK/provisioner-runtime.json")" ||
  fail "deployed tenant key provisioner has no replica regions"

ZONE="$(jq -er '.zone' "$WORK/runtime.json")"
CONTROL_HOST="$(jq -er '.control_host' "$WORK/runtime.json")"
TENANT_KEYS_TABLE="$(jq -er '.tenant_keys_table' "$WORK/runtime.json")"
BASE[platform]="https://${CONTROL_HOST}"
BASE[t1]="https://t1.${ZONE}"
BASE[t2]="https://t2.${ZONE}"
load_secret_header platform "$(
  jq -er '.admin_credential_secret_arn' "$WORK/runtime-bootstrap.json"
)"
for tenant in t1 t2; do
  ARN="$(jq -er --arg tenant "$tenant" \
    '.tenant_admin_secret_arns[$tenant]' "$WORK/runtime-bootstrap.json")"
  load_secret_header "$tenant" "$ARN"
done
pass "deployed registry, control host, and owner-bound credentials discovered"

if [[ "$ROTATION_MODE" == "forward-finish" ]]; then
  finish_forward_gate
  exit 0
fi

echo "== 2. Wait for atomic EC+RSA onboarding readiness =="
for tenant in t1 t2; do
  wait_for_ready "$tenant" 1200
  DISCOVERY_ISSUER="$(curl -fsS --proto '=https' "${BASE[$tenant]}/.well-known/openid-configuration" |
    jq -er '.issuer')"
  [[ "$DISCOVERY_ISSUER" == "${BASE[$tenant]}" ]] ||
    fail "$tenant discovery issuer mismatch: $DISCOVERY_ISSUER"
done
capture_initial_key_records
pass "t1/t2 are ready only after complete tenant snapshots"

echo "== 3. Assert tenant-only JWKS and mint real EC/RSA tokens =="
fetch_jwks t1 "$WORK/t1-initial-jwks.json"
fetch_jwks t2 "$WORK/t2-initial-jwks.json"
assert_jwks_counts "$WORK/t1-initial-jwks.json" 1 1
assert_jwks_counts "$WORK/t2-initial-jwks.json" 1 1
assert_disjoint_jwks "$WORK/t1-initial-jwks.json" "$WORK/t2-initial-jwks.json"
for tenant in t1 t2; do
  setup_actor "$tenant"
  mint_pair "$tenant" baseline
done
assert_cross_tenant_rejection \
  "$WORK/t1-baseline-tokens.json" "$WORK/t1-initial-jwks.json" \
  "$WORK/t2-baseline-tokens.json" "$WORK/t2-initial-jwks.json"
pass "ES256 access and RS256 ID tokens reject both foreign tenant key sets"

T1_OLD_EC="$(token_kid "$WORK/t1-baseline-tokens.json" access_token)"
T1_OLD_RSA="$(token_kid "$WORK/t1-baseline-tokens.json" id_token)"

echo "== 4. Rotate t1 into publish-ahead without changing t2 =="
ROTATION_STARTED=1
post_action t1 rotate "$OPERATION_ID" "$WORK/rotate-accepted.json"
wait_for_lifecycle t1 publishing "$OPERATION_ID" 900
assert_candidate_mrk_replicas t1
T1_NEW_EC="${CANDIDATE_KEY_KID[ec]}"
T1_NEW_RSA="${CANDIDATE_KEY_KID[rsa]}"
wait_for_jwks_counts t1 2 2 420 "$WORK/t1-publishing-jwks.json"
fetch_jwks t2 "$WORK/t2-during-publish-jwks.json"
assert_jwks_counts "$WORK/t2-during-publish-jwks.json" 1 1
cmp -s "$WORK/t2-initial-jwks.json" "$WORK/t2-during-publish-jwks.json" ||
  fail "t2 JWKS changed during t1 publish-ahead"
mint_pair t2 during-publish
verify_pair "$WORK/t2-during-publish-tokens.json" \
  "$WORK/t2-during-publish-jwks.json" "${BASE[t2]}" "${CLIENT[t2]}" 1
pass "t1 publishes only after every MRK replica signs successfully; t2 remains unchanged"

if [[ "$ROTATION_MODE" == "forward-start" ]]; then
  write_forward_checkpoint prepared
fi

printf 'Waiting %s seconds for the real publish-ahead window...\n' "$PUBLISH_WAIT_SECS"
sleep "$PUBLISH_WAIT_SECS"

echo "== 5. Activate the new t1 generation and prove old-token overlap =="
ACTIVATE_REQUESTED_AT="$(date +%s)"
post_action t1 activate "$OPERATION_ID" "$WORK/activate-accepted.json"
wait_for_lifecycle t1 active_overlap "$OPERATION_ID" 300
mint_pair t1 activated
[[ "$(token_kid "$WORK/t1-activated-tokens.json" access_token)" == "$T1_NEW_EC" &&
  "$(token_kid "$WORK/t1-activated-tokens.json" id_token)" == "$T1_NEW_RSA" &&
  "$T1_NEW_EC" != "$T1_OLD_EC" && "$T1_NEW_RSA" != "$T1_OLD_RSA" ]] ||
  fail "activation did not switch both EC and RSA active keys"
fetch_jwks t1 "$WORK/t1-active-overlap-jwks.json"
assert_jwks_counts "$WORK/t1-active-overlap-jwks.json" 2 2
verify_pair "$WORK/t1-baseline-tokens.json" "$WORK/t1-active-overlap-jwks.json" \
  "${BASE[t1]}" "${CLIENT[t1]}" 1
fetch_jwks t2 "$WORK/t2-active-overlap-jwks.json"
mint_pair t2 during-active
verify_pair "$WORK/t2-during-active-tokens.json" \
  "$WORK/t2-active-overlap-jwks.json" "${BASE[t2]}" "${CLIENT[t2]}" 1
RETIRE_AFTER="$(jq -er '.retire_after' "$WORK/status-t1-active_overlap.json")"
(( RETIRE_AFTER >= ACTIVATE_REQUESTED_AT + MIN_OVERLAP_SECS )) ||
  fail "forward overlap is shorter than the immutable SET retry window"
pass "new tokens use generation 2 while generation 1 tokens still verify"

if [[ "$ROTATION_MODE" == "forward-start" ]]; then
  cmp -s "$WORK/t2-initial-jwks.json" "$WORK/t2-active-overlap-jwks.json" ||
    fail "t2 JWKS changed during the t1 forward-start lifecycle"
  write_forward_checkpoint active_overlap
  ROTATION_FINISHED=1
  pass "forward overlap persisted; resumable checkpoint written to $CHECKPOINT_FILE"
  printf 'Run ROTATION_MODE=forward-finish after %s.\n' \
    "$(date -u -d "@$RETIRE_AFTER" '+%Y-%m-%d %H:%M:%S UTC')"
  exit 0
fi

if [[ "$ROTATION_MODE" == "rollback" ]]; then
  echo "== 6. Roll back both algorithms to generation 1 =="
  ROLLBACK_REQUESTED_AT="$(date +%s)"
  post_action t1 rollback "$OPERATION_ID" "$WORK/rollback-accepted.json"
  wait_for_lifecycle t1 rollback_overlap "$OPERATION_ID" 300
  mint_pair t1 rolled-back
  [[ "$(token_kid "$WORK/t1-rolled-back-tokens.json" access_token)" == "$T1_OLD_EC" ]] ||
    fail "rollback did not restore the original EC active key"
  [[ "$(token_kid "$WORK/t1-rolled-back-tokens.json" id_token)" == "$T1_OLD_RSA" ]] ||
    fail "rollback did not restore the original RSA active key"
  fetch_jwks t1 "$WORK/t1-rollback-overlap-jwks.json"
  assert_jwks_counts "$WORK/t1-rollback-overlap-jwks.json" 2 2
  verify_pair "$WORK/t1-activated-tokens.json" \
    "$WORK/t1-rollback-overlap-jwks.json" "${BASE[t1]}" "${CLIENT[t1]}" 1
  fetch_jwks t2 "$WORK/t2-rollback-overlap-jwks.json"
  mint_pair t2 during-rollback
  verify_pair "$WORK/t2-during-rollback-tokens.json" \
    "$WORK/t2-rollback-overlap-jwks.json" "${BASE[t2]}" "${CLIENT[t2]}" 1
  RETIRE_AFTER="$(jq -er '.retire_after' \
    "$WORK/status-t1-rollback_overlap.json")"
  (( RETIRE_AFTER >= ROLLBACK_REQUESTED_AT + MIN_OVERLAP_SECS )) ||
    fail "rollback overlap is shorter than the immutable SET retry window"
  pass "rollback restores generation 1 and keeps generation 2 verifiable for 24h+skew"

  fetch_jwks t2 "$WORK/t2-final-jwks.json"
  cmp -s "$WORK/t2-initial-jwks.json" "$WORK/t2-final-jwks.json" ||
    fail "t2 JWKS changed during the t1 rollback lifecycle"
  assert_t2_registry_unchanged
  assert_disjoint_jwks \
    "$WORK/t1-rollback-overlap-jwks.json" "$WORK/t2-final-jwks.json"
  ROTATION_FINISHED=1
  pass "rollback overlap gate passed; reconciler will retire the candidate at $RETIRE_AFTER"
  echo "Issue #26 rollback overlap gate passed."
  exit 0
fi

fail "unhandled rotation mode: $ROTATION_MODE"
