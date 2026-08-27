#!/usr/bin/env bash
# Real Okta directory provisioning acceptance for Issue #1 / C12.2.
#
# Prerequisite: an active Okta private SCIM integration configured with the
# Agent Auth SCIM base URL, bearer credential, Create Users, and Deactivate
# Users enabled. This script drives that real integration through Okta APIs.
#
# Required:
#   OKTA_ORG_URL=https://example.okta.com
#   OKTA_API_TOKEN_FILE=/secure/path/okta-api-token
#   OKTA_APP_ID=<private-scim-app-id>
#   BASE_URL=https://<agent-auth-public-issuer>
#   SCIM_SECRET_ARN=arn:aws:secretsmanager:... (or SCIM_TOKEN_FILE=/secure/path)
#
# Optional:
#   PROFILE=default
#   REGION=us-east-1
#   STACK_NAME=AgentAuthDev
#   OKTA_TEST_EMAIL_DOMAIN=example.invalid
#   SCIM_WAIT_SECONDS=300
#   KEEP_OKTA_FIXTURE=1
#   EVIDENCE_FILE=/secure/path/issue18-okta-evidence.json
set -euo pipefail
set +x

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="${PROFILE:-${AWS_PROFILE:-default}}"
REGION="${REGION:-${AWS_REGION:-us-east-1}}"
OKTA_ORG_URL="${OKTA_ORG_URL:?OKTA_ORG_URL is required}"
OKTA_API_TOKEN_FILE="${OKTA_API_TOKEN_FILE:?OKTA_API_TOKEN_FILE is required}"
OKTA_APP_ID="${OKTA_APP_ID:?OKTA_APP_ID is required}"
BASE_URL="${BASE_URL:?BASE_URL is required}"
STACK_NAME="${STACK_NAME:-AgentAuthDev}"
TEST_EMAIL_DOMAIN="${OKTA_TEST_EMAIL_DOMAIN:-example.invalid}"
WAIT_SECONDS="${SCIM_WAIT_SECONDS:-300}"
KEEP_FIXTURE="${KEEP_OKTA_FIXTURE:-0}"
RUN_ID="${OKTA_SCIM_RUN_ID:-$(date -u +%Y%m%d%H%M%S)-$RANDOM}"
TEST_EMAIL="agent-auth-scim-$RUN_ID@$TEST_EMAIL_DOMAIN"
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
EVIDENCE_FILE="${EVIDENCE_FILE:-$ROOT/_my/e2e/issue18-okta-$RUN_ID.json}"

umask 077
WORK="$(mktemp -d)"
OKTA_USER_ID=""
ASSIGNED=0
SUCCESS=0
FIXTURE_CLEANUP_COMPLETE=0
FIXTURE_CLEANUP_VERIFIED=0
SCIM_CLEANUP_VERIFIED=0
EVIDENCE_PUBLISH_STARTED=0
EVIDENCE_TEMP=""
CHECKSUM_TEMP=""
EVIDENCE_LOCK=""

pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
require() { command -v "$1" >/dev/null || fail "missing command: $1"; }

cleanup_work() {
  if [[ -n "$EVIDENCE_LOCK" ]]; then
    rmdir "$EVIDENCE_LOCK" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup_work EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for command in aws curl git jq mv openssl python3 sha256sum stat; do
  require "$command"
done

normalize_https_origin() {
  python3 - "$1" <<'PY'
import sys
import urllib.parse

value = sys.argv[1]
parsed = urllib.parse.urlsplit(value.rstrip("/"))
if (
    parsed.scheme != "https"
    or parsed.hostname is None
    or parsed.username is not None
    or parsed.password is not None
    or parsed.path not in {"", "/"}
    or parsed.query
    or parsed.fragment
    or "\\" in value
    or any(ord(char) < 0x21 or ord(char) == 0x7F for char in value)
):
    raise SystemExit(1)
try:
    port = parsed.port
except ValueError:
    raise SystemExit(1)
host = parsed.hostname
if ":" in host:
    host = f"[{host}]"
if port is not None:
    host = f"{host}:{port}"
print(f"https://{host}")
PY
}

OKTA_ORG_URL="$(normalize_https_origin "$OKTA_ORG_URL")" ||
  fail "OKTA_ORG_URL must be an HTTPS origin without userinfo, path, query, or fragment"
BASE_URL="$(normalize_https_origin "$BASE_URL")" ||
  fail "BASE_URL must be an HTTPS origin without userinfo, path, query, or fragment"
[[ "$OKTA_APP_ID" =~ ^[A-Za-z0-9]+$ ]] ||
  fail "OKTA_APP_ID contains unexpected characters"
[[ "$STACK_NAME" =~ ^[A-Za-z0-9-]+$ ]] ||
  fail "STACK_NAME contains unexpected characters"
[[ "$TEST_EMAIL_DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]] ||
  fail "OKTA_TEST_EMAIL_DOMAIN contains unexpected characters"
[[ "$WAIT_SECONDS" =~ ^[0-9]+$ && "$WAIT_SECONDS" -ge 30 ]] ||
  fail "SCIM_WAIT_SECONDS must be an integer of at least 30"
[[ "$KEEP_FIXTURE" == "0" || "$KEEP_FIXTURE" == "1" ]] ||
  fail "KEEP_OKTA_FIXTURE must be 0 or 1"
[[ "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$ && "$RUN_ID" != *..* ]] ||
  fail "OKTA_SCIM_RUN_ID must be a safe identifier of at most 80 characters"
[[ "$REGION" == "us-east-1" ]] ||
  fail "qualifying Okta acceptance requires REGION=us-east-1"
[[ ! -e "$EVIDENCE_FILE" && ! -L "$EVIDENCE_FILE" &&
  ! -e "$EVIDENCE_FILE.sha256" && ! -L "$EVIDENCE_FILE.sha256" ]] ||
  fail "EVIDENCE_FILE and its checksum path must not already exist"
mkdir -p "$(dirname "$EVIDENCE_FILE")"
mkdir "${EVIDENCE_FILE}.lock" ||
  fail "could not exclusively reserve EVIDENCE_FILE"
EVIDENCE_LOCK="${EVIDENCE_FILE}.lock"

protected_value() {
  local path="$1" label="$2" mode value
  [[ -r "$path" ]] || fail "$label is not readable"
  mode="$(stat -c '%a' "$path")"
  (( (8#$mode & 077) == 0 )) ||
    fail "$label must not be accessible by group or other"
  value="$(<"$path")"
  [[ -n "$value" && "$value" != *$'\n'* && "$value" != *$'\r'* ]] ||
    fail "$label must contain one non-empty line"
  printf '%s' "$value"
}

OKTA_API_TOKEN="$(protected_value "$OKTA_API_TOKEN_FILE" OKTA_API_TOKEN_FILE)"
SCIM_TOKEN=""
if [[ -n "${SCIM_TOKEN_FILE:-}" ]]; then
  SCIM_TOKEN="$(protected_value "$SCIM_TOKEN_FILE" SCIM_TOKEN_FILE)"
else
  SCIM_SECRET_ARN="${SCIM_SECRET_ARN:?SCIM_SECRET_ARN or SCIM_TOKEN_FILE is required}"
  SCIM_TOKEN="$(
    aws secretsmanager get-secret-value \
      --profile "$PROFILE" \
      --region "$REGION" \
      --secret-id "$SCIM_SECRET_ARN" \
      --query SecretString \
      --output text |
      jq -er '
        .current.secret
        | select(
            type == "string"
            and length >= 16
            and (contains("\n") | not)
            and (contains("\r") | not)
          )
      '
  )"
fi

OKTA_HEADERS="$WORK/okta.headers"
SCIM_HEADERS="$WORK/scim.headers"
printf 'Accept: application/json\nContent-Type: application/json\nAuthorization: SSWS %s\n' \
  "$OKTA_API_TOKEN" >"$OKTA_HEADERS"
printf 'Accept: application/scim+json\nAuthorization: Bearer %s\n' \
  "$SCIM_TOKEN" >"$SCIM_HEADERS"
unset OKTA_API_TOKEN SCIM_TOKEN

okta_request() {
  local name="$1" method="$2" path="$3" body_file="${4:-}"
  local -a args=(
    --silent --show-error --proto '=https' --connect-timeout 10 --max-time 60
    --request "$method" --header "@$OKTA_HEADERS"
    --output "$WORK/$name.json" --write-out '%{http_code}'
  )
  if [[ -n "$body_file" ]]; then
    args+=(--data-binary "@$body_file")
  fi
  curl "${args[@]}" "$OKTA_ORG_URL$path" >"$WORK/$name.status"
}

expect_okta_status() {
  local name="$1" expected="$2" actual
  actual="$(<"$WORK/$name.status")"
  [[ "$actual" == "$expected" ]] ||
    fail "$name expected Okta HTTP $expected, got $actual"
}

stack_output() {
  local key="$1"
  aws cloudformation describe-stacks \
    --profile "$PROFILE" --region "$REGION" --stack-name "$STACK_NAME" \
    --query "Stacks[0].Outputs[?OutputKey=='$key'].OutputValue | [0]" \
    --output text
}

stack_frontend_origin() {
  aws cloudformation describe-stacks \
    --profile "$PROFILE" --region "$REGION" --stack-name "$STACK_NAME" \
    --query "Stacks[0].Outputs[?starts_with(OutputKey, 'FrontendSpaUrl')].OutputValue | [0]" \
    --output text
}

scim_lookup() {
  local name="$1" filter encoded
  filter="userName eq \"$TEST_EMAIL\""
  encoded="$(jq -rn --arg value "$filter" '$value | @uri')"
  curl --silent --show-error --proto '=https' \
    --connect-timeout 10 --max-time 60 \
    --header "@$SCIM_HEADERS" \
    --output "$WORK/$name.json" --write-out '%{http_code}' \
    "$BASE_URL/scim/v2/Users?filter=$encoded" >"$WORK/$name.status"
}

wait_for_scim_state() {
  local stage="$1" expected="$2" deadline status
  deadline=$((SECONDS + WAIT_SECONDS))
  while (( SECONDS < deadline )); do
    scim_lookup "$stage"
    status="$(<"$WORK/$stage.status")"
    if [[ "$status" == "200" ]] &&
      jq -e --argjson active "$expected" '
        .totalResults == 1
        and (.Resources | length) == 1
        and .Resources[0].active == $active
        and (.Resources[0].id | type == "string" and length > 0)
        and (.Resources[0].externalId | type == "string" and length > 0)
      ' "$WORK/$stage.json" >/dev/null; then
      return 0
    fi
    sleep 5
  done
  fail "Okta provisioning did not produce SCIM active=$expected within ${WAIT_SECONDS}s"
}

hash_value() {
  printf '%s' "$1" | sha256sum | cut -d' ' -f1
}

recover_created_okta_user_id() {
  local create_status recovered_id
  [[ -z "$OKTA_USER_ID" ]] || return 0
  [[ -f "$WORK/create-user.status" && -f "$WORK/create-user.json" ]] || return 0
  create_status="$(<"$WORK/create-user.status")"
  [[ "$create_status" == "200" ]] || return 0
  recovered_id="$(
    jq -er '.id | select(type == "string" and length > 0)' \
      "$WORK/create-user.json" 2>/dev/null
  )" || {
    printf 'FAIL: could not recover created Okta user id from HTTP 200 response\n' >&2
    return 1
  }
  OKTA_USER_ID="$recovered_id"
}

cleanup_fixture() {
  local cleanup_status
  [[ "$FIXTURE_CLEANUP_COMPLETE" == "0" ]] || return 0
  if [[ "$KEEP_FIXTURE" == "1" ]]; then
    FIXTURE_CLEANUP_COMPLETE=1
    return 0
  fi
  recover_created_okta_user_id || return 1
  if [[ -z "$OKTA_USER_ID" ]]; then
    FIXTURE_CLEANUP_COMPLETE=1
    FIXTURE_CLEANUP_VERIFIED=1
    return 0
  fi
  if [[ "$ASSIGNED" == "1" ]]; then
    okta_request cleanup-unassign DELETE \
      "/api/v1/apps/$OKTA_APP_ID/users/$OKTA_USER_ID?sendEmail=false" || return 1
    cleanup_status="$(<"$WORK/cleanup-unassign.status")"
    if [[ "$cleanup_status" != "204" && "$cleanup_status" != "404" ]]; then
      printf 'FAIL: cleanup unassign returned Okta HTTP %s\n' "$cleanup_status" >&2
      return 1
    fi
    ASSIGNED=0
  fi
  okta_request cleanup-deactivate POST \
    "/api/v1/users/$OKTA_USER_ID/lifecycle/deactivate?sendEmail=false" || return 1
  cleanup_status="$(<"$WORK/cleanup-deactivate.status")"
  if [[ "$cleanup_status" != "200" && "$cleanup_status" != "403" &&
    "$cleanup_status" != "404" ]]; then
    printf 'FAIL: cleanup deactivate returned Okta HTTP %s\n' "$cleanup_status" >&2
    return 1
  fi
  okta_request cleanup-delete DELETE "/api/v1/users/$OKTA_USER_ID" || return 1
  cleanup_status="$(<"$WORK/cleanup-delete.status")"
  if [[ "$cleanup_status" != "204" && "$cleanup_status" != "404" ]]; then
    printf 'FAIL: cleanup delete returned Okta HTTP %s\n' "$cleanup_status" >&2
    return 1
  fi
  okta_request cleanup-verify GET "/api/v1/users/$OKTA_USER_ID" || return 1
  cleanup_status="$(<"$WORK/cleanup-verify.status")"
  if [[ "$cleanup_status" != "404" ]]; then
    printf 'FAIL: deleted Okta user remained readable with HTTP %s\n' \
      "$cleanup_status" >&2
    return 1
  fi
  FIXTURE_CLEANUP_COMPLETE=1
  FIXTURE_CLEANUP_VERIFIED=1
}

cleanup() {
  local exit_status=$? fixture_status=0
  trap - EXIT
  set +e
  cleanup_fixture
  fixture_status=$?
  if [[ "$SUCCESS" != "1" && "$EVIDENCE_PUBLISH_STARTED" == "1" ]]; then
    [[ -z "$EVIDENCE_TEMP" ]] || rm -f -- "$EVIDENCE_TEMP"
    [[ -z "$CHECKSUM_TEMP" ]] || rm -f -- "$CHECKSUM_TEMP"
    rm -f -- "$EVIDENCE_FILE" "$EVIDENCE_FILE.sha256"
  fi
  if [[ -n "$EVIDENCE_LOCK" ]]; then
    rmdir "$EVIDENCE_LOCK"
    EVIDENCE_LOCK=""
  fi
  rm -rf "$WORK"
  if [[ "$exit_status" == "0" && "$fixture_status" != "0" ]]; then
    exit_status="$fixture_status"
  fi
  if [[ "$SUCCESS" == "1" && "$exit_status" == "0" ]]; then
    printf 'Evidence: %s\n' "$EVIDENCE_FILE"
  fi
  exit "$exit_status"
}
trap cleanup EXIT

SOURCE_COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
[[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] ||
  fail "source commit is not a full Git SHA"
[[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=normal)" ]] ||
  fail "acceptance must run from a clean committed worktree"
DEPLOYED_COMMIT="$(stack_output DeploymentCommit)"
[[ "$DEPLOYED_COMMIT" =~ ^[0-9a-f]{40}$ ]] ||
  fail "$STACK_NAME has no valid DeploymentCommit output"
[[ "$DEPLOYED_COMMIT" == "$SOURCE_COMMIT" ]] ||
  fail "source commit does not match $STACK_NAME DeploymentCommit"
DEPLOYED_ORIGIN="$(normalize_https_origin "$(stack_frontend_origin)")" ||
  fail "$STACK_NAME has no valid FrontendSpaUrl output"
[[ "$DEPLOYED_ORIGIN" == "$BASE_URL" ]] ||
  fail "BASE_URL does not match the deployed stack frontend origin"
HARNESS_SHA256="$(sha256sum "$ROOT/e2e/okta_scim_users.sh" | cut -d' ' -f1)"
pass "source, harness, stack deployment, and public origin are bound"

okta_request app GET "/api/v1/apps/$OKTA_APP_ID"
expect_okta_status app 200
jq -e '.status == "ACTIVE"' "$WORK/app.json" >/dev/null ||
  fail "Okta private SCIM app is not ACTIVE"
pass "Okta private SCIM app is active"

ENCODED_TEST_EMAIL="$(jq -rn --arg value "$TEST_EMAIL" '$value | @uri')"
okta_request preflight-user GET "/api/v1/users/$ENCODED_TEST_EMAIL"
PREFLIGHT_STATUS="$(<"$WORK/preflight-user.status")"
if [[ "$PREFLIGHT_STATUS" == "200" ]]; then
  fail "disposable Okta login already exists; choose a new OKTA_SCIM_RUN_ID"
fi
[[ "$PREFLIGHT_STATUS" == "404" ]] ||
  fail "disposable Okta login preflight returned HTTP $PREFLIGHT_STATUS"
pass "disposable Okta login is unused"

PASSWORD="Okta!$(openssl rand -hex 18)Aa1"
jq -n \
  --arg email "$TEST_EMAIL" \
  --arg password "$PASSWORD" '{
    profile: {
      firstName: "AgentAuth",
      lastName: "SCIMAcceptance",
      email: $email,
      login: $email
    },
    credentials: {password: {value: $password}}
  }' >"$WORK/create-user.body.json"
unset PASSWORD

okta_request create-user POST "/api/v1/users?activate=true" "$WORK/create-user.body.json"
expect_okta_status create-user 200
OKTA_USER_ID="$(jq -er '.id | select(type == "string" and length > 0)' \
  "$WORK/create-user.json")"
jq -e '.status == "ACTIVE"' "$WORK/create-user.json" >/dev/null ||
  fail "Okta test user was not activated"
pass "created active disposable Okta directory user"

jq -n --arg id "$OKTA_USER_ID" '{id: $id, scope: "USER"}' \
  >"$WORK/assign.body.json"
okta_request assign POST "/api/v1/apps/$OKTA_APP_ID/users" "$WORK/assign.body.json"
expect_okta_status assign 200
ASSIGNED=1
wait_for_scim_state provision true

CANONICAL_USER_ID="$(jq -er '.Resources[0].id' "$WORK/provision.json")"
EXTERNAL_ID="$(jq -er '.Resources[0].externalId' "$WORK/provision.json")"
[[ "$EXTERNAL_ID" == "$OKTA_USER_ID" ]] ||
  fail "Agent Auth externalId is not the Okta directory user id"
PROVISIONED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
pass "Okta assignment provisioned one active Agent Auth user"

okta_request unassign DELETE \
  "/api/v1/apps/$OKTA_APP_ID/users/$OKTA_USER_ID?sendEmail=false"
expect_okta_status unassign 204
ASSIGNED=0
wait_for_scim_state deprovision false
jq -e --arg id "$CANONICAL_USER_ID" --arg external "$EXTERNAL_ID" '
  .Resources[0].id == $id and .Resources[0].externalId == $external
' "$WORK/deprovision.json" >/dev/null ||
  fail "Okta deprovision changed the canonical or external identity"
DEPROVISIONED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
pass "Okta unassignment deprovisioned the same Agent Auth user"

okta_request reassign POST "/api/v1/apps/$OKTA_APP_ID/users" "$WORK/assign.body.json"
expect_okta_status reassign 200
ASSIGNED=1
wait_for_scim_state reprovision true
jq -e --arg id "$CANONICAL_USER_ID" --arg external "$EXTERNAL_ID" '
  .Resources[0].id == $id and .Resources[0].externalId == $external
' "$WORK/reprovision.json" >/dev/null ||
  fail "Okta re-provision did not preserve canonical and external identity"
REPROVISIONED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
pass "Okta reassignment re-provisioned the same Agent Auth user"

if [[ "$KEEP_FIXTURE" == "0" ]]; then
  cleanup_fixture || fail "could not verify disposable Okta fixture cleanup"
  wait_for_scim_state cleanup false
  jq -e --arg id "$CANONICAL_USER_ID" --arg external "$EXTERNAL_ID" '
    .Resources[0].id == $id and .Resources[0].externalId == $external
  ' "$WORK/cleanup.json" >/dev/null ||
    fail "fixture cleanup did not preserve canonical and external identity"
  SCIM_CLEANUP_VERIFIED=1
  pass "deleted the Okta fixture and verified final Agent Auth deprovisioning"
fi
CLEANED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
COMPLETED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
EVIDENCE_DIRECTORY="$(dirname "$EVIDENCE_FILE")"
EVIDENCE_BASENAME="$(basename "$EVIDENCE_FILE")"
EVIDENCE_PUBLISH_STARTED=1
EVIDENCE_TEMP="$(mktemp "$EVIDENCE_DIRECTORY/.${EVIDENCE_BASENAME}.tmp.XXXXXX")"
CHECKSUM_TEMP="$(mktemp "$EVIDENCE_DIRECTORY/.${EVIDENCE_BASENAME}.sha256.tmp.XXXXXX")"
jq -n \
  --arg run_id "$RUN_ID" \
  --arg source_commit "$SOURCE_COMMIT" \
  --arg deployed_commit "$DEPLOYED_COMMIT" \
  --arg harness_sha256 "$HARNESS_SHA256" \
  --arg stack_name "$STACK_NAME" \
  --arg issuer "$BASE_URL" \
  --arg started_at "$STARTED_AT" \
  --arg provisioned_at "$PROVISIONED_AT" \
  --arg deprovisioned_at "$DEPROVISIONED_AT" \
  --arg reprovisioned_at "$REPROVISIONED_AT" \
  --arg cleaned_at "$CLEANED_AT" \
  --arg completed_at "$COMPLETED_AT" \
  --arg org_hash "$(hash_value "$OKTA_ORG_URL")" \
  --arg app_hash "$(hash_value "$OKTA_APP_ID")" \
  --arg directory_user_hash "$(hash_value "$OKTA_USER_ID")" \
  --arg login_hash "$(hash_value "$TEST_EMAIL")" \
  --arg canonical_hash "$(hash_value "$CANONICAL_USER_ID")" \
  --arg external_hash "$(hash_value "$EXTERNAL_ID")" \
  --argjson cleanup_requested "$([[ "$KEEP_FIXTURE" == "0" ]] && printf true || printf false)" \
  --argjson cleanup_verified "$([[ "$FIXTURE_CLEANUP_VERIFIED" == "1" && "$SCIM_CLEANUP_VERIFIED" == "1" ]] && printf true || printf false)" '{
    schema_version: 1,
    evidence_kind: "third_party",
    provider: "Okta",
    flow: "private-scim-assignment",
    run_id: $run_id,
    source_commit: $source_commit,
    deployed_commit: $deployed_commit,
    harness_sha256: $harness_sha256,
    stack_name: $stack_name,
    issuer: $issuer,
    started_at: $started_at,
    completed_at: $completed_at,
    identifiers_sha256: {
      okta_org_origin: $org_hash,
      okta_app_id: $app_hash,
      okta_user_id: $directory_user_hash,
      login: $login_hash,
      canonical_user_id: $canonical_hash,
      external_id: $external_hash
    },
    checks: [
      {stage: "provision", okta_assignment_http: 200, scim_active: true, observed_at: $provisioned_at},
      {stage: "deprovision", okta_unassignment_http: 204, scim_active: false, observed_at: $deprovisioned_at},
      {stage: "re-provision", okta_assignment_http: 200, scim_active: true, observed_at: $reprovisioned_at}
    ],
    stable_canonical_identity: true,
    stable_external_id: true,
    fixture_cleanup: {
      requested: $cleanup_requested,
      verified: $cleanup_verified,
      agent_auth_inactive: $cleanup_verified,
      observed_at: (if $cleanup_verified then $cleaned_at else null end)
    }
  }' >"$EVIDENCE_TEMP"
chmod 0600 "$EVIDENCE_TEMP"
EVIDENCE_SHA256="$(sha256sum "$EVIDENCE_TEMP" | cut -d' ' -f1)"
printf '%s  %s\n' "$EVIDENCE_SHA256" "$EVIDENCE_FILE" >"$CHECKSUM_TEMP"
chmod 0600 "$CHECKSUM_TEMP"
mv "$EVIDENCE_TEMP" "$EVIDENCE_FILE"
EVIDENCE_TEMP=""
mv "$CHECKSUM_TEMP" "$EVIDENCE_FILE.sha256"
CHECKSUM_TEMP=""
SUCCESS=1
pass "wrote redacted third-party lifecycle evidence"
