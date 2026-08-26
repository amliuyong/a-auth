#!/usr/bin/env bash
# Deployed acceptance for Issue #23. This script exercises the real DynamoDB
# adapters and deployed HTTP surface. It creates a disposable local user,
# converts it to an already-provisioned passwordless user for first-enrollment
# coverage, then verifies password, recovery, and passkey management.
#
# Usage:
#   API_URL=https://<host> STACK=AgentAuthDev \
#   USERS_TABLE=<name> PASSWORD_TABLE=<name> SESSION_TABLE=<name> \
#   PASSKEY_TABLE=<name> RECOVERY_TABLE=<name> MESSAGES_TABLE=<name> \
#   AWS_PROFILE=default ./e2e/account_credentials.sh
set -euo pipefail
# shellcheck source=e2e/lib/local_user.sh
source "$(dirname "$0")/lib/local_user.sh"

API_URL="${API_URL:?API_URL is required}"
USERS_TABLE="${USERS_TABLE:?USERS_TABLE is required}"
PASSWORD_TABLE="${PASSWORD_TABLE:?PASSWORD_TABLE is required}"
SESSION_TABLE="${SESSION_TABLE:?SESSION_TABLE is required}"
PASSKEY_TABLE="${PASSKEY_TABLE:?PASSKEY_TABLE is required}"
RECOVERY_TABLE="${RECOVERY_TABLE:?RECOVERY_TABLE is required}"
MESSAGES_TABLE="${MESSAGES_TABLE:?MESSAGES_TABLE is required}"
STACK="${STACK:-AgentAuthDev}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
RUN_ID="$(python3 -c 'import secrets; print(secrets.token_hex(6))')"
EMAIL="e2e-credentials-${RUN_ID}@example.com"
USER_ID="user:${EMAIL}"
INITIAL="$(python3 -c 'import secrets; print("Init-" + secrets.token_urlsafe(24))')"
BOOTSTRAP="$(python3 -c 'import secrets; print("Bootstrap-" + secrets.token_urlsafe(24))')"
ENROLLED="$(python3 -c 'import secrets; print("Enroll-" + secrets.token_urlsafe(24))')"
ROTATED="$(python3 -c 'import secrets; print("Rotate-" + secrets.token_urlsafe(24))')"
RP_ID="$(printf '%s' "$API_URL" | sed -E 's#^https?://##; s#/.*$##')"
WORK="$(mktemp -d)"
JAR_MAGIC="$WORK/magic.cookies"
JAR_ACTIVE="$WORK/active.cookies"
JAR_RECOVERY="$WORK/recovery.cookies"
JAR_RECOVERY_ONLY="$WORK/recovery-only.cookies"
JAR_PASSKEY="$WORK/passkey.cookies"
JAR_ROTATE="$WORK/rotate.cookies"
PASSWORD_KEY=""
PASSKEY_PHYSICAL_ID=""
RECOVERY_PHYSICAL_KEY=""
USER_PHYSICAL_ID=""

cleanup() {
  local status=$?
  local message_cleanup_failed=0
  local message_id
  local message_ids=""
  local message_filter_names='{"#recipient":"recipient"}'
  local message_filter_values
  trap - EXIT INT TERM
  set +e
  message_filter_values="$(
    jq -cn --arg email "$EMAIL" --arg user_id "$USER_ID" \
      '{":email":{S:$email},":user_id":{S:$user_id}}'
  )"
  if message_ids="$(
    aws dynamodb scan --profile "$PROFILE" --region "$REGION" \
      --table-name "$MESSAGES_TABLE" \
      --projection-expression "message_id" \
      --filter-expression "#recipient IN (:email, :user_id)" \
      --expression-attribute-names "$message_filter_names" \
      --expression-attribute-values "$message_filter_values" \
      --consistent-read --output json 2>/dev/null |
      jq -r '.Items[]?.message_id.S'
  )"; then
    while IFS= read -r message_id; do
      [ -n "$message_id" ] || continue
      if ! aws dynamodb delete-item --profile "$PROFILE" --region "$REGION" \
        --table-name "$MESSAGES_TABLE" \
        --key "$(jq -cn --arg id "$message_id" '{message_id:{S:$id}}')" \
        >/dev/null 2>&1; then
        message_cleanup_failed=1
      fi
    done <<<"$message_ids"
  else
    message_cleanup_failed=1
  fi
  if ! aws dynamodb scan --profile "$PROFILE" --region "$REGION" \
    --table-name "$MESSAGES_TABLE" \
    --select COUNT \
    --filter-expression "#recipient IN (:email, :user_id)" \
    --expression-attribute-names "$message_filter_names" \
    --expression-attribute-values "$message_filter_values" \
    --consistent-read --output json 2>/dev/null |
    jq -e '.Count == 0' >/dev/null; then
    message_cleanup_failed=1
  fi
  if [ "$message_cleanup_failed" -ne 0 ]; then
    echo "Failed to remove all message fixtures for $EMAIL" >&2
    [ "$status" -ne 0 ] || status=1
  fi
  if [ -n "${ADMIN_TOKEN:-}" ]; then
    curl -sS -o /dev/null -X DELETE "$API_URL/admin/users/$USER_ID" \
      -H "authorization: Bearer $ADMIN_TOKEN" || true
  fi
  if [ -n "$PASSKEY_PHYSICAL_ID" ]; then
    aws dynamodb delete-item --profile "$PROFILE" --region "$REGION" \
      --table-name "$PASSKEY_TABLE" \
      --key "$(jq -cn --arg key "$PASSKEY_PHYSICAL_ID" \
        '{credential_id:{S:$key}}')" >/dev/null 2>&1 || true
  fi
  if [ -n "$RECOVERY_PHYSICAL_KEY" ]; then
    aws dynamodb delete-item --profile "$PROFILE" --region "$REGION" \
      --table-name "$RECOVERY_TABLE" \
      --key "$(jq -cn --arg key "$RECOVERY_PHYSICAL_KEY" \
        '{user_lookup:{S:$key}}')" >/dev/null 2>&1 || true
  fi
  if [ -n "$PASSWORD_KEY" ]; then
    aws dynamodb delete-item --profile "$PROFILE" --region "$REGION" \
      --table-name "$PASSWORD_TABLE" \
      --key "$(jq -cn --arg key "$PASSWORD_KEY" \
        '{user_id:{S:$key}}')" >/dev/null 2>&1 || true
  fi
  if [ -n "$USER_PHYSICAL_ID" ]; then
    aws dynamodb delete-item --profile "$PROFILE" --region "$REGION" \
      --table-name "$USERS_TABLE" \
      --key "$(jq -cn --arg key "$USER_PHYSICAL_ID" \
        '{user_id:{S:$key}}')" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

json_password() {
  local password="${1:?password required}"
  PASSWORD="$password" python3 -c \
    'import json,os; print(json.dumps({"new_password":os.environ["PASSWORD"]}))'
}

password_login() {
  local password="${1:?password required}"
  local jar="${2:?cookie jar required}"
  local expected="${3:-200}"
  local body status retry_after
  body="$(EMAIL="$EMAIL" PASSWORD="$password" python3 -c \
    'import json,os; print(json.dumps({"email":os.environ["EMAIL"],"password":os.environ["PASSWORD"]}))')"
  for _ in 1 2 3; do
    status="$(printf '%s' "$body" | curl -sS -D "$WORK/password-login.headers" \
      -o "$WORK/password-login.body" -w '%{http_code}' -c "$jar" \
      -X POST "$API_URL/login/password" \
      -H "content-type: application/json" --data-binary @-)"
    if [ "$status" != "429" ]; then
      [ "$status" = "$expected" ] || {
        echo "Password login expected HTTP $expected, got $status" >&2
        return 1
      }
      return 0
    fi
    retry_after="$(awk 'tolower($1) == "retry-after:" { gsub(/\r/, "", $2); print $2; exit }' \
      "$WORK/password-login.headers")"
    [[ "$retry_after" =~ ^[0-9]+$ ]] || retry_after=60
    sleep "$retry_after"
  done
  echo "Password login remained throttled after bounded retries" >&2
  return 1
}

session_status() {
  local jar="${1:?cookie jar required}"
  curl -sS -o /dev/null -w '%{http_code}' -b "$jar" \
    "$API_URL/account/credentials"
}

find_physical_key() {
  local table="${1:?table required}"
  local attribute="${2:?attribute required}"
  local suffix="${3:?suffix required}"
  aws dynamodb scan --profile "$PROFILE" --region "$REGION" \
    --table-name "$table" \
    --projection-expression "#key" \
    --expression-attribute-names "{\"#key\":\"$attribute\"}" \
    --output json |
    jq -er --arg attribute "$attribute" --arg suffix "$suffix" \
      '.Items[] | .[$attribute].S | select(endswith($suffix))' |
    head -n 1
}

agent_auth_admin_token

echo "== 1. Create and authenticate a disposable local user =="
CREATE_BODY="$(EMAIL="$EMAIL" PASSWORD="$INITIAL" python3 -c \
  'import json,os; print(json.dumps({"email":os.environ["EMAIL"],"initial_password":os.environ["PASSWORD"]}))')"
CREATE_STATUS="$(printf '%s' "$CREATE_BODY" | curl -sS -o "$WORK/create.body" \
  -w '%{http_code}' -X POST "$API_URL/admin/users" \
  -H "authorization: Bearer $ADMIN_TOKEN" \
  -H "content-type: application/json" --data-binary @-)"
[ "$CREATE_STATUS" = "201" ] || {
  echo "Admin create failed: HTTP $CREATE_STATUS" >&2
  exit 1
}
CHANGE_BODY="$(EMAIL="$EMAIL" CURRENT="$INITIAL" NEW="$BOOTSTRAP" python3 -c \
  'import json,os; print(json.dumps({"email":os.environ["EMAIL"],"current_password":os.environ["CURRENT"],"new_password":os.environ["NEW"],"authorize_query":""}))')"
CHANGE_STATUS="$(printf '%s' "$CHANGE_BODY" | curl -sS -o "$WORK/change.body" \
  -w '%{http_code}' -c "$JAR_MAGIC" -X POST "$API_URL/login/password/change" \
  -H "content-type: application/json" --data-binary @-)"
[ "$CHANGE_STATUS" = "200" ] || {
  echo "Initial password activation failed: HTTP $CHANGE_STATUS" >&2
  exit 1
}
grep -q "__Host-agent_auth_session" "$JAR_MAGIC"
PASSWORD_KEY="$(find_physical_key "$PASSWORD_TABLE" user_id "$USER_ID")"
USER_PHYSICAL_ID="$PASSWORD_KEY"
TENANT_PREFIX="${PASSWORD_KEY%"$USER_ID"}"
RECOVERY_LOOKUP="$(USER_ID="$USER_ID" python3 -c \
  'import base64,hashlib,os; print(base64.urlsafe_b64encode(hashlib.sha256(os.environ["USER_ID"].encode()).digest()[:16]).rstrip(b"=").decode())')"
RECOVERY_PHYSICAL_KEY="${TENANT_PREFIX}${RECOVERY_LOOKUP}"

echo "== 2. Convert the authenticated fixture to an existing passwordless account =="
# The retained login session is the existing authentication factor for this
# deployed adapter test. This setup works on both Dev and SaaS and does not
# depend on the development-only magic-link `dev_link` response.
aws dynamodb delete-item --profile "$PROFILE" --region "$REGION" \
  --table-name "$PASSWORD_TABLE" \
  --key "$(jq -cn --arg key "$PASSWORD_KEY" '{user_id:{S:$key}}')" >/dev/null
DETAIL_STATUS="$(curl -sS -o "$WORK/detail.body" -w '%{http_code}' \
  "$API_URL/admin/users/$USER_ID" -H "authorization: Bearer $ADMIN_TOKEN")"
[ "$DETAIL_STATUS" = "200" ] || {
  echo "Admin detail failed after passwordless setup: HTTP $DETAIL_STATUS" >&2
  exit 1
}
jq -e '.password_status == "not_configured"' "$WORK/detail.body" >/dev/null

curl -sS -b "$JAR_MAGIC" "$API_URL/account/credentials" \
  >"$WORK/summary-passwordless.json"
python3 - "$WORK/summary-passwordless.json" <<'PY'
import json
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text()
body = json.loads(text)
assert body["password_status"] == "not_configured"
assert body["password_supported"] is True
assert body["reauthenticated"] is True
assert "password_hash" not in text
assert "credential_id" not in text
assert "public_key" not in text
PY

echo "== 3. A stale authentication is rejected with a reauthentication contract =="
SESSION_ID="$(awk '$6 == "__Host-agent_auth_session" { value = $7 } END { print value }' \
  "$JAR_MAGIC")"
SESSION_KEY="$(find_physical_key "$SESSION_TABLE" session_id "$SESSION_ID")"
STALE_AUTH="$(( $(date +%s) - 301 ))"
aws dynamodb update-item --profile "$PROFILE" --region "$REGION" \
  --table-name "$SESSION_TABLE" \
  --key "$(jq -cn --arg key "$SESSION_KEY" '{session_id:{S:$key}}')" \
  --update-expression "SET auth_time = :auth" \
  --expression-attribute-values "{\":auth\":{\"N\":\"$STALE_AUTH\"}}" >/dev/null
STALE_STATUS="$(json_password "$ENROLLED" | curl -sS -o "$WORK/stale.body" \
  -w '%{http_code}' -b "$JAR_MAGIC" -X PUT "$API_URL/account/password" \
  -H "content-type: application/json" --data-binary @-)"
[ "$STALE_STATUS" = "403" ] || {
  echo "Stale credential mutation expected 403, got $STALE_STATUS" >&2
  exit 1
}
jq -e '.error == "reauthentication_required" and .reauthenticate_url == "/login?next=%2Faccount"' \
  "$WORK/stale.body" >/dev/null

echo "== 4. First password enrollment revokes the actor session =="
FRESH_AUTH="$(date +%s)"
aws dynamodb update-item --profile "$PROFILE" --region "$REGION" \
  --table-name "$SESSION_TABLE" \
  --key "$(jq -cn --arg key "$SESSION_KEY" '{session_id:{S:$key}}')" \
  --update-expression "SET auth_time = :auth" \
  --expression-attribute-values "{\":auth\":{\"N\":\"$FRESH_AUTH\"}}" >/dev/null
ENROLL_STATUS="$(json_password "$ENROLLED" | curl -sS -D "$WORK/enroll.headers" \
  -o "$WORK/enroll.body" -w '%{http_code}' -b "$JAR_MAGIC" \
  -X PUT "$API_URL/account/password" -H "content-type: application/json" \
  --data-binary @-)"
[ "$ENROLL_STATUS" = "204" ] || {
  echo "First password enrollment failed: HTTP $ENROLL_STATUS" >&2
  exit 1
}
grep -qi '^set-cookie: __Host-agent_auth_session=;.*Max-Age=0' \
  "$WORK/enroll.headers"
[ "$(session_status "$JAR_MAGIC")" = "401" ] || {
  echo "Enrollment did not revoke the actor session" >&2
  exit 1
}
password_login "$ENROLLED" "$JAR_ACTIVE"
curl -sS -b "$JAR_ACTIVE" "$API_URL/account/credentials" >"$WORK/summary-active.json"
jq -e '.password_status == "active" and .password_supported == true' \
  "$WORK/summary-active.json" >/dev/null

echo "== 5. Recovery rotation returns plaintext once and revokes the session =="
RECOVERY_STATUS="$(curl -sS -D "$WORK/recovery.headers" -o "$WORK/recovery.body" \
  -w '%{http_code}' -b "$JAR_ACTIVE" -X POST "$API_URL/recovery/generate")"
[ "$RECOVERY_STATUS" = "200" ] || {
  echo "Recovery rotation failed: HTTP $RECOVERY_STATUS" >&2
  exit 1
}
grep -qi '^cache-control: no-store' "$WORK/recovery.headers"
jq -e '.recovery_codes | length == 10 and all(startswith("v1."))' \
  "$WORK/recovery.body" >/dev/null
[ "$(session_status "$JAR_ACTIVE")" = "401" ] || {
  echo "Recovery rotation did not revoke the actor session" >&2
  exit 1
}
password_login "$ENROLLED" "$JAR_RECOVERY"
curl -sS -b "$JAR_RECOVERY" "$API_URL/account/credentials" \
  >"$WORK/summary-recovery.json"
jq -e '.recovery_configured == true and .recovery_codes_remaining == 10' \
  "$WORK/summary-recovery.json" >/dev/null

echo "== 6. A recovery-only session cannot rotate away its last recovery path =="
RECOVERY_ONLY_CODE="$(jq -er '.recovery_codes[0]' "$WORK/recovery.body")"
RECOVER_BODY="$(RECOVERY_CODE="$RECOVERY_ONLY_CODE" python3 -c \
  'import json,os,secrets; print(json.dumps({"code":os.environ["RECOVERY_CODE"],"operation_id":secrets.token_urlsafe(32)}))')"
RECOVER_STATUS="$(printf '%s' "$RECOVER_BODY" | curl -sS \
  -o "$WORK/recover.body" -w '%{http_code}' -c "$JAR_RECOVERY_ONLY" \
  -X POST "$API_URL/recovery/verify" \
  -H "content-type: application/json" --data-binary @-)"
[ "$RECOVER_STATUS" = "200" ] || {
  echo "Recovery-code login failed: HTTP $RECOVER_STATUS" >&2
  exit 1
}
RECOVERY_MESSAGE_VISIBLE=""
for attempt in 1 2 3 4 5; do
  aws dynamodb scan --profile "$PROFILE" --region "$REGION" \
    --table-name "$MESSAGES_TABLE" \
    --projection-expression "kind,recipient" \
    --output json >"$WORK/recovery-messages.json"
  if jq -e --arg email "$EMAIL" --arg user_id "$USER_ID" \
    'any(.Items[]?;
       .kind.S == "recovery" and .recipient.S == $email) and
     all(.Items[]?;
       .recipient.S != $user_id)' \
    "$WORK/recovery-messages.json" >/dev/null; then
    RECOVERY_MESSAGE_VISIBLE=1
    break
  fi
  sleep "$attempt"
done
[ -n "$RECOVERY_MESSAGE_VISIBLE" ] || {
  echo "Recovery notification did not use the fixture email recipient" >&2
  exit 1
}
aws dynamodb get-item --profile "$PROFILE" --region "$REGION" \
  --table-name "$PASSWORD_TABLE" \
  --key "$(jq -cn --arg key "$PASSWORD_KEY" '{user_id:{S:$key}}')" \
  --consistent-read --output json |
  jq -e '.Item' >"$WORK/password-item.json"
aws dynamodb delete-item --profile "$PROFILE" --region "$REGION" \
  --table-name "$PASSWORD_TABLE" \
  --key "$(jq -cn --arg key "$PASSWORD_KEY" '{user_id:{S:$key}}')" >/dev/null
curl -sS -b "$JAR_RECOVERY_ONLY" "$API_URL/account/credentials" \
  >"$WORK/recovery-only-before.json"
RECOVERY_ONLY_STATUS="$(curl -sS -o "$WORK/recovery-only-denial.body" \
  -w '%{http_code}' -b "$JAR_RECOVERY_ONLY" \
  -X POST "$API_URL/recovery/generate")"
[ "$RECOVERY_ONLY_STATUS" = "409" ] || {
  echo "Recovery-only rotation expected 409, got $RECOVERY_ONLY_STATUS" >&2
  exit 1
}
jq -e '.error == "last_viable_factor"' \
  "$WORK/recovery-only-denial.body" >/dev/null
[ "$(session_status "$JAR_RECOVERY_ONLY")" = "200" ] || {
  echo "Recovery-only denial consumed the actor session" >&2
  exit 1
}
curl -sS -b "$JAR_RECOVERY_ONLY" "$API_URL/account/credentials" \
  >"$WORK/recovery-only-after.json"
jq -e --slurpfile before "$WORK/recovery-only-before.json" \
  '.recovery_codes_remaining == $before[0].recovery_codes_remaining and
   .recovery_codes_remaining == 9' \
  "$WORK/recovery-only-after.json" >/dev/null
aws dynamodb put-item --profile "$PROFILE" --region "$REGION" \
  --table-name "$PASSWORD_TABLE" \
  --item "file://$WORK/password-item.json" >/dev/null

echo "== 7. Seed one valid passkey record and verify redacted management =="
CREDENTIAL_ID="$(python3 -c \
  'import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(24)).rstrip(b"=").decode())')"
if [ "$PASSWORD_KEY" = "$USER_ID" ]; then
  PASSKEY_PHYSICAL_ID="$CREDENTIAL_ID"
else
  TENANT_PREFIX="${PASSWORD_KEY%"$USER_ID"}"
  PASSKEY_PHYSICAL_ID="${TENANT_PREFIX}${CREDENTIAL_ID}"
fi
USER_PHYSICAL_ID="$PASSWORD_KEY"
RP_ID="$RP_ID" USER_ID="$USER_ID" USER_PHYSICAL_ID="$USER_PHYSICAL_ID" \
  CREDENTIAL_ID="$CREDENTIAL_ID" PASSKEY_PHYSICAL_ID="$PASSKEY_PHYSICAL_ID" \
  python3 - "$WORK/passkey-item.json" <<'PY'
import json
import os
import pathlib
import time
from cryptography.hazmat.primitives.asymmetric import ec

key = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
public = [4] + list(key.x.to_bytes(32, "big")) + list(key.y.to_bytes(32, "big"))
credential = {
    "credential_id": os.environ["CREDENTIAL_ID"],
    "user_id": os.environ["USER_ID"],
    "rp_id": os.environ["RP_ID"],
    "public_key_sec1": public,
    "sign_count": 0,
    "name": "Seeded passkey",
    "created_at": int(time.time()),
}
item = {
    "credential_id": {"S": os.environ["PASSKEY_PHYSICAL_ID"]},
    "user_id": {"S": os.environ["USER_PHYSICAL_ID"]},
    "sign_count": {"N": "0"},
    "cred_json": {"S": json.dumps(credential, separators=(",", ":"))},
}
pathlib.Path(__import__("sys").argv[1]).write_text(json.dumps(item))
PY
aws dynamodb put-item --profile "$PROFILE" --region "$REGION" \
  --table-name "$PASSKEY_TABLE" \
  --item "file://$WORK/passkey-item.json" >/dev/null
password_login "$ENROLLED" "$JAR_PASSKEY"
PASSKEY_VISIBLE=""
for attempt in 1 2 3 4 5; do
  curl -sS -b "$JAR_PASSKEY" "$API_URL/account/credentials" \
    >"$WORK/summary-passkey.json"
  if jq -e '.passkeys | length == 1' "$WORK/summary-passkey.json" >/dev/null; then
    PASSKEY_VISIBLE=1
    break
  fi
  sleep "$attempt"
done
[ -n "$PASSKEY_VISIBLE" ] || {
  echo "Passkey GSI did not expose the seeded record" >&2
  exit 1
}
HANDLE="$(jq -er '.passkeys[0].id' "$WORK/summary-passkey.json")"
CREDENTIAL_ID="$CREDENTIAL_ID" python3 - "$WORK/summary-passkey.json" <<'PY'
import json
import os
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text()
body = json.loads(text)
assert body["passkeys"][0]["name"] == "Seeded passkey"
assert os.environ["CREDENTIAL_ID"] not in text
assert "public_key_sec1" not in text
assert "cred_json" not in text
PY
RENAME_STATUS="$(curl -sS -o /dev/null -w '%{http_code}' -b "$JAR_PASSKEY" \
  -X PATCH "$API_URL/account/passkeys/$HANDLE" \
  -H "content-type: application/json" -d '{"name":"Work security key"}')"
[ "$RENAME_STATUS" = "204" ] || {
  echo "Passkey rename failed: HTTP $RENAME_STATUS" >&2
  exit 1
}
curl -sS -b "$JAR_PASSKEY" "$API_URL/account/credentials" \
  >"$WORK/summary-renamed.json"
jq -e '.passkeys[0].name == "Work security key"' \
  "$WORK/summary-renamed.json" >/dev/null
DELETE_STATUS="$(curl -sS -D "$WORK/delete-passkey.headers" -o /dev/null \
  -w '%{http_code}' -b "$JAR_PASSKEY" \
  -X DELETE "$API_URL/account/passkeys/$HANDLE")"
[ "$DELETE_STATUS" = "204" ] || {
  echo "Passkey delete failed: HTTP $DELETE_STATUS" >&2
  exit 1
}
grep -qi '^set-cookie: __Host-agent_auth_session=;.*Max-Age=0' \
  "$WORK/delete-passkey.headers"
[ "$(session_status "$JAR_PASSKEY")" = "401" ] || {
  echo "Passkey delete did not revoke the actor session" >&2
  exit 1
}
PASSKEY_PHYSICAL_ID=""

echo "== 8. Active password rotation rejects the previous password =="
password_login "$ENROLLED" "$JAR_ROTATE"
ROTATE_STATUS="$(json_password "$ROTATED" | curl -sS -o /dev/null \
  -w '%{http_code}' -b "$JAR_ROTATE" -X PUT "$API_URL/account/password" \
  -H "content-type: application/json" --data-binary @-)"
[ "$ROTATE_STATUS" = "204" ] || {
  echo "Active password rotation failed: HTTP $ROTATE_STATUS" >&2
  exit 1
}
password_login "$ENROLLED" "$WORK/old-password.cookies" 401
password_login "$ROTATED" "$WORK/rotated-password.cookies"

echo "== 9. Responses and stored records do not expose plaintext credentials =="
INITIAL="$INITIAL" BOOTSTRAP="$BOOTSTRAP" ENROLLED="$ENROLLED" ROTATED="$ROTATED" \
  python3 - "$WORK" <<'PY'
import os
import pathlib
import sys

needles = [
    os.environ["INITIAL"],
    os.environ["BOOTSTRAP"],
    os.environ["ENROLLED"],
    os.environ["ROTATED"],
]
for path in pathlib.Path(sys.argv[1]).glob("*.body"):
    text = path.read_text(errors="replace")
    for needle in needles:
        assert needle not in text, f"plaintext password leaked in {path.name}"
PY

echo "PASS: deployed account credential management is redacted, reauthenticated, fenced, and lockout-safe"
