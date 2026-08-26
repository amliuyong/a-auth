#!/usr/bin/env bash
# spec 003 C9.7-C9.10 deployed e2e: Admin provisioning/reset, forced password
# change, active password login, session/refresh revocation, Dynamo credential
# evidence, and plaintext leak checks.
#
# Usage:
#   API_URL=https://<host> PASSWORD_TABLE=<PasswordCredentialsTableName> \
#   SESSION_TABLE=<SessionsTableName> \
#   AWS_PROFILE=default ./e2e/password_login.sh
set -euo pipefail
source "$(dirname "$0")/lib/local_user.sh"

API_URL="${API_URL:?API_URL is required}"
PASSWORD_TABLE="${PASSWORD_TABLE:?PASSWORD_TABLE is required}"
SESSION_TABLE="${SESSION_TABLE:?SESSION_TABLE is required}"
STACK="${STACK:-AgentAuthDev}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
RAND="$(python3 -c 'import secrets; print(secrets.token_hex(6))')"
EMAIL="e2e-password-${RAND}@example.com"
USER_ID="user:${EMAIL}"
INITIAL="$(python3 -c 'import secrets; print("Init-" + secrets.token_urlsafe(24))')"
PERMANENT="$(python3 -c 'import secrets; print("Active-" + secrets.token_urlsafe(24))')"
RESET_TEMPORARY="$(python3 -c 'import secrets; print("Reset-" + secrets.token_urlsafe(24))')"
WORK="$(mktemp -d)"
JAR_CHANGE="$WORK/change.cookies"
JAR_ACTIVE="$WORK/active.cookies"
CLIENT_ID=""
START_MS="$(python3 -c 'import time; print(int(time.time() * 1000) - 1000)')"

cleanup() {
  if [ -n "${ADMIN_TOKEN:-}" ] && [ -n "$CLIENT_ID" ]; then
    curl -sS -o /dev/null -X DELETE "$API_URL/admin/clients/$CLIENT_ID" \
      -H "authorization: Bearer $ADMIN_TOKEN" || true
  fi
  if [ -n "${ADMIN_TOKEN:-}" ]; then
    curl -sS -o /dev/null -X DELETE "$API_URL/admin/users/$USER_ID" \
      -H "authorization: Bearer $ADMIN_TOKEN" || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

json_body() {
  EMAIL="$EMAIL" FIRST="$INITIAL" SECOND="$PERMANENT" RESET="$RESET_TEMPORARY" python3 -c "$1"
}

assert_no_plaintext() {
  INITIAL="$INITIAL" PERMANENT="$PERMANENT" RESET_TEMPORARY="$RESET_TEMPORARY" python3 - "$@" <<'PY'
import os
import pathlib
import sys

needles = [
    os.environ["INITIAL"],
    os.environ["PERMANENT"],
    os.environ["RESET_TEMPORARY"],
]
for name in sys.argv[1:]:
    text = pathlib.Path(name).read_text(errors="replace")
    for needle in needles:
        assert needle not in text, f"plaintext password leaked in {name}"
PY
}

agent_auth_admin_token

echo "== 1. Admin creates a local user with a temporary password =="
CREATE="$(json_body 'import json,os; print(json.dumps({"email":os.environ["EMAIL"],"initial_password":os.environ["FIRST"]}))')"
CREATE_STATUS="$(printf '%s' "$CREATE" | curl -sS -D "$WORK/create.headers" \
  -o "$WORK/create.body" -w '%{http_code}' -X POST "$API_URL/admin/users" \
  -H "authorization: Bearer $ADMIN_TOKEN" -H "content-type: application/json" \
  --data-binary @-)"
[ "$CREATE_STATUS" = "201" ] || {
  echo "Admin create failed: HTTP $CREATE_STATUS" >&2
  exit 1
}
assert_no_plaintext "$WORK/create.headers" "$WORK/create.body"
python3 - "$WORK/create.body" <<'PY'
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text()
assert "password_hash" not in text
assert "argon2" not in text.lower()
PY

echo "== 2. Temporary password requires change and creates no session =="
LOGIN_TEMP="$(json_body 'import json,os; print(json.dumps({"email":os.environ["EMAIL"],"password":os.environ["FIRST"]}))')"
TEMP_STATUS="$(printf '%s' "$LOGIN_TEMP" | curl -sS -D "$WORK/temp.headers" \
  -o "$WORK/temp.body" -w '%{http_code}' -X POST "$API_URL/login/password" \
  -H "content-type: application/json" --data-binary @-)"
[ "$TEMP_STATUS" = "200" ] || {
  echo "Temporary-password login failed: HTTP $TEMP_STATUS" >&2
  exit 1
}
python3 - "$WORK/temp.headers" "$WORK/temp.body" <<'PY'
import json
import pathlib
import sys

headers = pathlib.Path(sys.argv[1]).read_text().lower()
body = json.loads(pathlib.Path(sys.argv[2]).read_text())
assert "set-cookie:" not in headers
assert body == {"authenticated": False, "password_change_required": True}
PY
assert_no_plaintext "$WORK/temp.headers" "$WORK/temp.body"

echo "== 3. First change activates the credential and creates a pwd session =="
CHANGE="$(json_body 'import json,os; print(json.dumps({"email":os.environ["EMAIL"],"current_password":os.environ["FIRST"],"new_password":os.environ["SECOND"]}))')"
CHANGE_STATUS="$(printf '%s' "$CHANGE" | curl -sS -D "$WORK/change.headers" \
  -o "$WORK/change.body" -c "$JAR_CHANGE" -w '%{http_code}' \
  -X POST "$API_URL/login/password/change" -H "content-type: application/json" \
  --data-binary @-)"
[ "$CHANGE_STATUS" = "200" ] || {
  echo "First password change failed: HTTP $CHANGE_STATUS" >&2
  exit 1
}
grep -q "__Host-agent_auth_session" "$JAR_CHANGE" || {
  echo "First password change did not create a session" >&2
  exit 1
}
assert_no_plaintext "$WORK/change.headers" "$WORK/change.body"

echo "== 4. Old password is rejected; active password logs in =="
OLD_STATUS="$(printf '%s' "$LOGIN_TEMP" | curl -sS -o "$WORK/old.body" \
  -w '%{http_code}' -X POST "$API_URL/login/password" \
  -H "content-type: application/json" --data-binary @-)"
[ "$OLD_STATUS" = "401" ] || {
  echo "Old temporary password was not rejected: HTTP $OLD_STATUS" >&2
  exit 1
}
LOGIN_ACTIVE="$(json_body 'import json,os; print(json.dumps({"email":os.environ["EMAIL"],"password":os.environ["SECOND"]}))')"
ACTIVE_STATUS="$(printf '%s' "$LOGIN_ACTIVE" | curl -sS -D "$WORK/active.headers" \
  -o "$WORK/active.body" -c "$JAR_ACTIVE" -w '%{http_code}' \
  -X POST "$API_URL/login/password" -H "content-type: application/json" \
  --data-binary @-)"
[ "$ACTIVE_STATUS" = "200" ] || {
  echo "Active password login failed: HTTP $ACTIVE_STATUS" >&2
  exit 1
}
grep -q "__Host-agent_auth_session" "$JAR_ACTIVE" || {
  echo "Active password login did not create a session" >&2
  exit 1
}
assert_no_plaintext "$WORK/old.body" "$WORK/active.headers" "$WORK/active.body"

echo "== 5. Active login persists a pwd-authenticated session =="
SESSION_ID="$(awk '$6 == "__Host-agent_auth_session" { value = $7 } END { print value }' "$JAR_ACTIVE")"
[ -n "$SESSION_ID" ] || {
  echo "Could not read the active session id from the cookie jar" >&2
  exit 1
}
aws dynamodb get-item --profile "$PROFILE" --region "$REGION" \
  --table-name "$SESSION_TABLE" --consistent-read \
  --key "{\"session_id\":{\"S\":\"$SESSION_ID\"}}" >"$WORK/session.json"
USER_ID="$USER_ID" python3 - "$WORK/session.json" <<'PY'
import json
import os
import pathlib
import sys

item = json.loads(pathlib.Path(sys.argv[1]).read_text()).get("Item")
assert item, "password session item is missing"
assert item["user_id"]["S"] == os.environ["USER_ID"]
assert [entry["S"] for entry in item["amr"]["L"]] == ["pwd"]
assert int(item["expires_at"]["N"]) > int(item["auth_time"]["N"])
PY
assert_no_plaintext "$WORK/session.json"

echo "== 6. Admin detail exposes status, never the credential =="
DETAIL_STATUS="$(curl -sS -o "$WORK/detail.body" -w '%{http_code}' \
  "$API_URL/admin/users/$USER_ID" -H "authorization: Bearer $ADMIN_TOKEN")"
[ "$DETAIL_STATUS" = "200" ] || {
  echo "Admin detail failed: HTTP $DETAIL_STATUS" >&2
  exit 1
}
python3 - "$WORK/detail.body" <<'PY'
import json
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text()
body = json.loads(text)
assert body["password_status"] == "active"
assert isinstance(body.get("last_login_at"), int) and body["last_login_at"] > 0
assert "password_hash" not in text
assert "argon2" not in text.lower()
PY
assert_no_plaintext "$WORK/detail.body"

echo "== 7. Dynamo stores only the reviewed Argon2id PHC profile and metadata =="
aws dynamodb get-item --profile "$PROFILE" --region "$REGION" \
  --table-name "$PASSWORD_TABLE" --consistent-read \
  --key "{\"user_id\":{\"S\":\"$USER_ID\"}}" >"$WORK/credential.json"
USER_ID="$USER_ID" INITIAL="$INITIAL" PERMANENT="$PERMANENT" \
  python3 - "$WORK/credential.json" <<'PY'
import json
import os
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text()
item = json.loads(text).get("Item")
assert item, "password credential item is missing"
assert set(item) == {
    "user_id",
    "password_hash",
    "must_change",
    "revocation_pending",
    "version",
    "updated_at",
}
assert item["user_id"]["S"] == os.environ["USER_ID"]
phc = item["password_hash"]["S"]
assert phc.startswith("$argon2id$v=19$m=19456,t=2,p=1$")
assert item["must_change"]["BOOL"] is False
assert item["revocation_pending"]["BOOL"] is False
assert item["version"]["N"] == "2"
int(item["updated_at"]["N"])
assert os.environ["INITIAL"] not in text
assert os.environ["PERMANENT"] not in text
PY
TTL_STATUS="$(aws dynamodb describe-time-to-live --profile "$PROFILE" --region "$REGION" \
  --table-name "$PASSWORD_TABLE" --query 'TimeToLiveDescription.TimeToLiveStatus' \
  --output text)"
[ "$TTL_STATUS" = "DISABLED" ] || {
  echo "Password credential table unexpectedly has TTL status $TTL_STATUS" >&2
  exit 1
}

echo "== 8. Active password session issues a refresh token =="
REDIRECT="http://127.0.0.1/callback"
VERIFIER="0123456789012345678901234567890123456789abc"
CHALLENGE="$(VERIFIER="$VERIFIER" python3 -c \
  'import base64,hashlib,os; print(base64.urlsafe_b64encode(hashlib.sha256(os.environ["VERIFIER"].encode()).digest()).rstrip(b"=").decode())')"
CLIENT_CREATE_STATUS="$(curl -sS -o "$WORK/client.body" -w '%{http_code}' \
  -X POST "$API_URL/admin/clients" \
  -H "authorization: Bearer $ADMIN_TOKEN" -H "content-type: application/json" \
  -d "{\"redirect_uris\":[\"$REDIRECT\"],\"application_type\":\"native\",\"token_endpoint_auth_method\":\"none\"}")"
[ "$CLIENT_CREATE_STATUS" = "201" ] || {
  echo "Refresh-test client creation failed: HTTP $CLIENT_CREATE_STATUS" >&2
  exit 1
}
CLIENT_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["client_id"])' \
  "$WORK/client.body")"
AQ="client_id=$CLIENT_ID&redirect_uri=$REDIRECT&scope=openid&state=reset-test&code_challenge=$CHALLENGE&code_challenge_method=S256"
CSRF="$(curl -sS -b "$JAR_ACTIVE" "$API_URL/consent/context?$AQ" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin).get("csrf_token",""))')"
[ -n "$CSRF" ] || {
  echo "Could not obtain consent CSRF token for refresh test" >&2
  exit 1
}
CONSENT_BODY="$(CSRF="$CSRF" AQ="$AQ" python3 -c \
  'import json,os; print(json.dumps({"decision":"approve","csrf":os.environ["CSRF"],"authorize_query":os.environ["AQ"]}))')"
REDIRECT_RESULT="$(printf '%s' "$CONSENT_BODY" | curl -sS -b "$JAR_ACTIVE" \
  -X POST "$API_URL/consent/decision" -H "content-type: application/json" \
  --data-binary @- | python3 -c 'import json,sys; print(json.load(sys.stdin).get("redirect",""))')"
AUTH_CODE="$(REDIRECT_RESULT="$REDIRECT_RESULT" python3 -c \
  'import os,urllib.parse; print(urllib.parse.parse_qs(urllib.parse.urlparse(os.environ["REDIRECT_RESULT"]).query).get("code",[""])[0])')"
[ -n "$AUTH_CODE" ] || {
  echo "Consent did not issue an authorization code" >&2
  exit 1
}
TOKEN_STATUS="$(curl -sS -o "$WORK/token.body" -w '%{http_code}' \
  -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=$AUTH_CODE" \
  --data-urlencode "code_verifier=$VERIFIER" \
  --data-urlencode "redirect_uri=$REDIRECT" \
  --data-urlencode "client_id=$CLIENT_ID")"
[ "$TOKEN_STATUS" = "200" ] || {
  echo "Authorization-code exchange failed: HTTP $TOKEN_STATUS" >&2
  exit 1
}
REFRESH_TOKEN="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("refresh_token",""))' \
  "$WORK/token.body")"
[ -n "$REFRESH_TOKEN" ] || {
  echo "Authorization-code exchange did not return a refresh token" >&2
  exit 1
}
curl -sS "$API_URL/admin/clients/$CLIENT_ID" \
  -H "authorization: Bearer $ADMIN_TOKEN" >"$WORK/client-after-token.body"
python3 - "$WORK/client-after-token.body" <<'PY'
import json
import pathlib
import sys

body = json.loads(pathlib.Path(sys.argv[1]).read_text())
last_used_at = body.get("last_used_at")
assert isinstance(last_used_at, int) and last_used_at > 0
assert last_used_at % 86400 == 0, "client activity must be a UTC-day boundary"
PY
assert_no_plaintext "$WORK/client.body" "$WORK/token.body"

echo "== 9. Admin resets the password without leaking the temporary value =="
SAME_RESET_BODY="$(json_body 'import json,os; print(json.dumps({"temporary_password":os.environ["SECOND"]}))')"
SAME_RESET_STATUS="$(printf '%s' "$SAME_RESET_BODY" | curl -sS \
  -o "$WORK/same-reset.body" -w '%{http_code}' -X POST \
  "$API_URL/admin/users/$USER_ID/reset-password" \
  -H "authorization: Bearer $ADMIN_TOKEN" -H "content-type: application/json" \
  --data-binary @-)"
[ "$SAME_RESET_STATUS" = "400" ] || {
  echo "Reset accepted the current password: HTTP $SAME_RESET_STATUS" >&2
  exit 1
}
assert_no_plaintext "$WORK/same-reset.body"
RESET_BODY="$(json_body 'import json,os; print(json.dumps({"temporary_password":os.environ["RESET"]}))')"
RESET_STATUS="$(printf '%s' "$RESET_BODY" | curl -sS -D "$WORK/reset.headers" \
  -o "$WORK/reset.body" -w '%{http_code}' -X POST \
  "$API_URL/admin/users/$USER_ID/reset-password" \
  -H "authorization: Bearer $ADMIN_TOKEN" -H "content-type: application/json" \
  --data-binary @-)"
[ "$RESET_STATUS" = "200" ] || {
  echo "Admin password reset failed: HTTP $RESET_STATUS" >&2
  exit 1
}
assert_no_plaintext "$WORK/reset.headers" "$WORK/reset.body"

echo "== 10. Reset revokes the old session, refresh token, and password =="
aws dynamodb get-item --profile "$PROFILE" --region "$REGION" \
  --table-name "$SESSION_TABLE" --consistent-read \
  --key "{\"session_id\":{\"S\":\"$SESSION_ID\"}}" >"$WORK/session-after-reset.json"
python3 - "$WORK/session-after-reset.json" <<'PY'
import json
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text().strip()
assert not text or "Item" not in json.loads(text)
PY
REFRESH_STATUS="$(curl -sS -o "$WORK/old-refresh.body" -w '%{http_code}' \
  -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "refresh_token=$REFRESH_TOKEN" \
  --data-urlencode "client_id=$CLIENT_ID")"
[ "$REFRESH_STATUS" = "400" ] || {
  echo "Pre-reset refresh token was not rejected: HTTP $REFRESH_STATUS" >&2
  exit 1
}
python3 - "$WORK/old-refresh.body" <<'PY'
import json
import pathlib
import sys

body = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert body.get("error") == "invalid_grant", body
PY
OLD_ACTIVE_STATUS="$(printf '%s' "$LOGIN_ACTIVE" | curl -sS -o "$WORK/old-active.body" \
  -w '%{http_code}' -X POST "$API_URL/login/password" \
  -H "content-type: application/json" --data-binary @-)"
[ "$OLD_ACTIVE_STATUS" = "401" ] || {
  echo "Pre-reset password was not rejected: HTTP $OLD_ACTIVE_STATUS" >&2
  exit 1
}
assert_no_plaintext \
  "$WORK/session-after-reset.json" "$WORK/old-refresh.body" "$WORK/old-active.body"

echo "== 11. Reset password requires change and creates no session =="
LOGIN_RESET="$(json_body 'import json,os; print(json.dumps({"email":os.environ["EMAIL"],"password":os.environ["RESET"]}))')"
RESET_LOGIN_STATUS="$(printf '%s' "$LOGIN_RESET" | curl -sS -D "$WORK/reset-login.headers" \
  -o "$WORK/reset-login.body" -w '%{http_code}' -X POST "$API_URL/login/password" \
  -H "content-type: application/json" --data-binary @-)"
if [ "$RESET_LOGIN_STATUS" = "429" ]; then
  RETRY_AFTER="$(awk 'tolower($1) == "retry-after:" {gsub("\r", "", $2); print $2}' \
    "$WORK/reset-login.headers" | tail -1)"
  [[ "$RETRY_AFTER" =~ ^[0-9]+$ ]] || RETRY_AFTER=60
  sleep "$((RETRY_AFTER + 1))"
  RESET_LOGIN_STATUS="$(printf '%s' "$LOGIN_RESET" | curl -sS -D "$WORK/reset-login.headers" \
    -o "$WORK/reset-login.body" -w '%{http_code}' -X POST "$API_URL/login/password" \
    -H "content-type: application/json" --data-binary @-)"
fi
[ "$RESET_LOGIN_STATUS" = "200" ] || {
  echo "Reset temporary-password login failed: HTTP $RESET_LOGIN_STATUS" >&2
  exit 1
}
python3 - "$WORK/reset-login.headers" "$WORK/reset-login.body" <<'PY'
import json
import pathlib
import sys

headers = pathlib.Path(sys.argv[1]).read_text().lower()
body = json.loads(pathlib.Path(sys.argv[2]).read_text())
assert "set-cookie:" not in headers
assert body == {"authenticated": False, "password_change_required": True}
PY
assert_no_plaintext "$WORK/reset-login.headers" "$WORK/reset-login.body"

echo "== 12. Reset increments the credential version and marks it temporary =="
curl -sS "$API_URL/admin/users/$USER_ID" \
  -H "authorization: Bearer $ADMIN_TOKEN" >"$WORK/detail-after-reset.body"
aws dynamodb get-item --profile "$PROFILE" --region "$REGION" \
  --table-name "$PASSWORD_TABLE" --consistent-read \
  --key "{\"user_id\":{\"S\":\"$USER_ID\"}}" >"$WORK/credential-after-reset.json"
INITIAL="$INITIAL" PERMANENT="$PERMANENT" RESET_TEMPORARY="$RESET_TEMPORARY" \
  python3 - "$WORK/detail-after-reset.body" "$WORK/credential-after-reset.json" <<'PY'
import json
import os
import pathlib
import sys

detail_text = pathlib.Path(sys.argv[1]).read_text()
detail = json.loads(detail_text)
credential_text = pathlib.Path(sys.argv[2]).read_text()
item = json.loads(credential_text).get("Item")
assert detail["password_status"] == "change_required"
assert "password_hash" not in detail_text
assert item, "reset password credential item is missing"
assert item["password_hash"]["S"].startswith("$argon2id$v=19$m=19456,t=2,p=1$")
assert item["must_change"]["BOOL"] is True
assert item["revocation_pending"]["BOOL"] is False
assert item["version"]["N"] == "3"
for password in (
    os.environ["INITIAL"],
    os.environ["PERMANENT"],
    os.environ["RESET_TEMPORARY"],
):
    assert password not in detail_text
    assert password not in credential_text
PY

echo "== 13. Recent Auth Lambda logs contain no plaintext password =="
AUTH_FN=""
while read -r fn; do
  [ -n "$fn" ] || continue
  DOMAIN_TABLE="$(aws lambda get-function-configuration --profile "$PROFILE" --region "$REGION" \
    --function-name "$fn" --query 'Environment.Variables.DOMAIN_MAP_TABLE' --output text 2>/dev/null || true)"
  if [ -n "$DOMAIN_TABLE" ] && [ "$DOMAIN_TABLE" != "None" ]; then
    AUTH_FN="$fn"
    break
  fi
done < <(aws cloudformation list-stack-resources --profile "$PROFILE" --region "$REGION" \
  --stack-name "$STACK" \
  --query "StackResourceSummaries[?ResourceType=='AWS::Lambda::Function'].PhysicalResourceId" \
  --output text | tr '\t' '\n')
[ -n "$AUTH_FN" ] || {
  echo "Could not identify the Auth Lambda" >&2
  exit 1
}
sleep 5
aws logs filter-log-events --profile "$PROFILE" --region "$REGION" \
  --log-group-name "/aws/lambda/$AUTH_FN" --start-time "$START_MS" \
  --output json >"$WORK/logs.json"
assert_no_plaintext "$WORK/logs.json"

echo "Password login deployed e2e passed"
