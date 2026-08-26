#!/usr/bin/env bash
# Deployed acceptance for Issue #22:
#   - provision one local user and create multiple browser login sessions
#   - list only opaque management handles and normalized device metadata
#   - revoke one session, then revoke every session except the current one
#   - prove revoked cookies fail while the retained cookie remains usable
#   - prove forged marker cookies cannot remove the generation fence
#   - sign out the current session and verify tenant-scoped, secret-free audit logs
#
# Usage:
#   API_URL=https://<tenant-host> STACK=AgentAuthDev \
#   AWS_PROFILE=default ./e2e/account_sessions.sh
#   API_URL=https://t1.<saas-zone> STACK=AgentAuthSaas EXPECTED_TENANT=t1 \
#   ADMIN_TOKEN=<tenant-admin-token> CROSS_TENANT_API_URL=https://t2.<saas-zone> \
#   CROSS_TENANT_ADMIN_TOKEN=<other-tenant-admin-token> \
#   AWS_PROFILE=default ./e2e/account_sessions.sh
set -euo pipefail
# shellcheck source=e2e/lib/local_user.sh
source "$(dirname "$0")/lib/local_user.sh"

API_URL="${API_URL:?API_URL is required}"
STACK="${STACK:-AgentAuthDev}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
EXPECTED_TENANT="${EXPECTED_TENANT:-}"
CROSS_TENANT_API_URL="${CROSS_TENANT_API_URL:-}"
CROSS_TENANT_ADMIN_TOKEN="${CROSS_TENANT_ADMIN_TOKEN:-}"
RUN_ID="$(python3 -c 'import secrets; print(secrets.token_hex(6))')"
EMAIL="e2e-sessions-${RUN_ID}@example.com"
USER_ID="user:${EMAIL}"
CROSS_EMAIL="e2e-sessions-cross-${RUN_ID}@example.com"
CROSS_USER_ID="user:${CROSS_EMAIL}"
INITIAL="$(python3 -c 'import secrets; print("Init-" + secrets.token_urlsafe(24))')"
PERMANENT="$(python3 -c 'import secrets; print("Active-" + secrets.token_urlsafe(24))')"
CROSS_INITIAL="$(python3 -c 'import secrets; print("Init-" + secrets.token_urlsafe(24))')"
CROSS_PERMANENT="$(python3 -c 'import secrets; print("Active-" + secrets.token_urlsafe(24))')"
WORK="$(mktemp -d)"
JAR_CURRENT="$WORK/current.cookies"
JAR_IPHONE="$WORK/iphone.cookies"
JAR_FIREFOX="$WORK/firefox.cookies"
JAR_RACE_CURRENT="$WORK/race-current.cookies"
JAR_RACE_OLD="$WORK/race-old.cookies"
JAR_CROSS="$WORK/cross.cookies"
START_MS="$(python3 -c 'import time; print(int(time.time() * 1000) - 1000)')"

cleanup() {
  if [ -n "${ADMIN_TOKEN:-}" ]; then
    curl -sS -o /dev/null -X DELETE "$API_URL/admin/users/$USER_ID" \
      -H "authorization: Bearer $ADMIN_TOKEN" || true
  fi
  if [ -n "$CROSS_TENANT_API_URL" ] && [ -n "$CROSS_TENANT_ADMIN_TOKEN" ]; then
    curl -sS -o /dev/null -X DELETE \
      "$CROSS_TENANT_API_URL/admin/users/$CROSS_USER_ID" \
      -H "authorization: Bearer $CROSS_TENANT_ADMIN_TOKEN" || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

json_body() {
  EMAIL="$EMAIL" INITIAL="$INITIAL" PERMANENT="$PERMANENT" python3 -c "$1"
}

cross_json_body() {
  EMAIL="$CROSS_EMAIL" INITIAL="$CROSS_INITIAL" PERMANENT="$CROSS_PERMANENT" \
    python3 -c "$1"
}

login() {
  local jar="${1:?cookie jar required}"
  local user_agent="${2:?user agent required}"
  local body status
  body="$(json_body 'import json,os; print(json.dumps({"email":os.environ["EMAIL"],"password":os.environ["PERMANENT"]}))')"
  status="$(printf '%s' "$body" | curl -sS -o "$WORK/login.body" -w '%{http_code}' \
    -c "$jar" -A "$user_agent" -X POST "$API_URL/login/password" \
    -H "content-type: application/json" --data-binary @-)"
  [ "$status" = "200" ] || {
    echo "Active password login failed: HTTP $status" >&2
    return 1
  }
  grep -q "__Host-agent_auth_session" "$jar" || {
    echo "Active password login did not create a session cookie" >&2
    return 1
  }
}

status_with_jar() {
  local jar="${1:?cookie jar required}"
  curl -sS -o /dev/null -w '%{http_code}' -b "$jar" "$API_URL/account/sessions"
}

if [ "$STACK" = "AgentAuthSaas" ] && [ -z "${ADMIN_TOKEN:-}" ]; then
  echo "AgentAuthSaas requires the selected tenant's ADMIN_TOKEN" >&2
  exit 1
fi
if { [ -n "$CROSS_TENANT_API_URL" ] && [ -z "$CROSS_TENANT_ADMIN_TOKEN" ]; } ||
  { [ -z "$CROSS_TENANT_API_URL" ] && [ -n "$CROSS_TENANT_ADMIN_TOKEN" ]; }; then
  echo "CROSS_TENANT_API_URL and CROSS_TENANT_ADMIN_TOKEN must be set together" >&2
  exit 1
fi
agent_auth_admin_token

echo "== 1. Provision a local user and activate its password =="
CREATE="$(json_body 'import json,os; print(json.dumps({"email":os.environ["EMAIL"],"initial_password":os.environ["INITIAL"]}))')"
CREATE_STATUS="$(printf '%s' "$CREATE" | curl -sS -o "$WORK/create.body" -w '%{http_code}' \
  -X POST "$API_URL/admin/users" -H "authorization: Bearer $ADMIN_TOKEN" \
  -H "content-type: application/json" --data-binary @-)"
[ "$CREATE_STATUS" = "201" ] || {
  echo "Admin create failed: HTTP $CREATE_STATUS" >&2
  exit 1
}
CHANGE="$(json_body 'import json,os; print(json.dumps({"email":os.environ["EMAIL"],"current_password":os.environ["INITIAL"],"new_password":os.environ["PERMANENT"]}))')"
CHANGE_STATUS="$(printf '%s' "$CHANGE" | curl -sS -o "$WORK/change.body" -w '%{http_code}' \
  -c "$JAR_CURRENT" \
  -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36" \
  -X POST "$API_URL/login/password/change" -H "content-type: application/json" \
  --data-binary @-)"
[ "$CHANGE_STATUS" = "200" ] || {
  echo "Password activation failed: HTTP $CHANGE_STATUS" >&2
  exit 1
}
grep -q "__Host-agent_auth_session" "$JAR_CURRENT" || {
  echo "Password activation did not create the current session cookie" >&2
  exit 1
}
if [ -n "$CROSS_TENANT_API_URL" ]; then
  CROSS_CREATE="$(cross_json_body 'import json,os; print(json.dumps({"email":os.environ["EMAIL"],"initial_password":os.environ["INITIAL"]}))')"
  CROSS_CREATE_STATUS="$(printf '%s' "$CROSS_CREATE" | curl -sS \
    -o "$WORK/cross-create.body" -w '%{http_code}' \
    -X POST "$CROSS_TENANT_API_URL/admin/users" \
    -H "authorization: Bearer $CROSS_TENANT_ADMIN_TOKEN" \
    -H "content-type: application/json" --data-binary @-)"
  [ "$CROSS_CREATE_STATUS" = "201" ] || {
    echo "Cross-tenant Admin create failed: HTTP $CROSS_CREATE_STATUS" >&2
    exit 1
  }
  CROSS_CHANGE="$(cross_json_body 'import json,os; print(json.dumps({"email":os.environ["EMAIL"],"current_password":os.environ["INITIAL"],"new_password":os.environ["PERMANENT"]}))')"
  CROSS_CHANGE_STATUS="$(printf '%s' "$CROSS_CHANGE" | curl -sS \
    -o "$WORK/cross-change.body" -w '%{http_code}' -c "$JAR_CROSS" \
    -X POST "$CROSS_TENANT_API_URL/login/password/change" \
    -H "content-type: application/json" --data-binary @-)"
  [ "$CROSS_CHANGE_STATUS" = "200" ] || {
    echo "Cross-tenant password activation failed: HTTP $CROSS_CHANGE_STATUS" >&2
    exit 1
  }
fi

echo "== 2. Create Chrome, Safari, and Firefox login sessions =="
login "$JAR_IPHONE" \
  "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1"
login "$JAR_FIREFOX" \
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"

echo "== 3. List opaque handles and useful device/time metadata =="
curl -sS -b "$JAR_CURRENT" "$API_URL/account/sessions" >"$WORK/sessions.json"
CURRENT_COOKIE="$(awk '$6 == "__Host-agent_auth_session" { value = $7 } END { print value }' "$JAR_CURRENT")"
IPHONE_COOKIE="$(awk '$6 == "__Host-agent_auth_session" { value = $7 } END { print value }' "$JAR_IPHONE")"
FIREFOX_COOKIE="$(awk '$6 == "__Host-agent_auth_session" { value = $7 } END { print value }' "$JAR_FIREFOX")"
CURRENT_COOKIE="$CURRENT_COOKIE" IPHONE_COOKIE="$IPHONE_COOKIE" FIREFOX_COOKIE="$FIREFOX_COOKIE" \
  python3 - "$WORK/sessions.json" "$WORK/iphone.handle" <<'PY'
import json
import os
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text()
sessions = json.loads(text)
assert len(sessions) == 3, sessions
assert sum(session["current"] for session in sessions) == 1, sessions
assert {session["device"] for session in sessions} == {
    "Chrome on Linux",
    "Safari on iPhone",
    "Firefox on Windows",
}, sessions
for session in sessions:
    assert 60 <= len(session["id"]) <= 512
    assert all(character.isalnum() or character in "-_" for character in session["id"])
    assert all(isinstance(session[field], int) for field in (
        "created_at", "last_used_at", "expires_at"
    ))
    assert session["created_at"] <= session["last_used_at"] < session["expires_at"]
for name in ("CURRENT_COOKIE", "IPHONE_COOKIE", "FIREFOX_COOKIE"):
    assert os.environ[name] not in text, "active cookie leaked through the management API"
iphone = next(session for session in sessions if session["device"] == "Safari on iPhone")
pathlib.Path(sys.argv[2]).write_text(iphone["id"])
PY

echo "== 4. Revoke one selected session; retries stay idempotent =="
IPHONE_HANDLE="$(<"$WORK/iphone.handle")"
if [ -n "$CROSS_TENANT_API_URL" ]; then
  CROSS_REPLAY_STATUS="$(curl -sS -o /dev/null -w '%{http_code}' \
    -b "$JAR_CROSS" -X DELETE \
    "$CROSS_TENANT_API_URL/account/sessions/$IPHONE_HANDLE")"
  [ "$CROSS_REPLAY_STATUS" = "204" ] || {
    echo "Cross-tenant handle replay returned HTTP $CROSS_REPLAY_STATUS" >&2
    exit 1
  }
  [ "$(status_with_jar "$JAR_IPHONE")" = "200" ] || {
    echo "Cross-tenant handle replay revoked the source tenant session" >&2
    exit 1
  }
fi
for attempt in 1 2; do
  STATUS="$(curl -sS -o /dev/null -w '%{http_code}' -b "$JAR_CURRENT" \
    -X DELETE "$API_URL/account/sessions/$IPHONE_HANDLE")"
  [ "$STATUS" = "204" ] || {
    echo "Selected-session revoke attempt $attempt failed: HTTP $STATUS" >&2
    exit 1
  }
done
[ "$(status_with_jar "$JAR_IPHONE")" = "401" ] || {
  echo "Revoked Safari cookie still authenticates" >&2
  exit 1
}
[ "$(status_with_jar "$JAR_CURRENT")" = "200" ] || {
  echo "Current Chrome cookie was not retained" >&2
  exit 1
}

echo "== 5. Revoke every other session behind the generation fence =="
for attempt in 1 2; do
  STATUS="$(curl -sS -o /dev/null -w '%{http_code}' -b "$JAR_CURRENT" \
    -X DELETE "$API_URL/account/sessions")"
  [ "$STATUS" = "204" ] || {
    echo "Revoke-others attempt $attempt failed: HTTP $STATUS" >&2
    exit 1
  }
done
[ "$(status_with_jar "$JAR_FIREFOX")" = "401" ] || {
  echo "Revoked Firefox cookie still authenticates" >&2
  exit 1
}
[ "$(status_with_jar "$JAR_CURRENT")" = "200" ] || {
  echo "Current Chrome cookie did not survive revoke-others" >&2
  exit 1
}
curl -sS -b "$JAR_CURRENT" "$API_URL/account/sessions" \
  >"$WORK/retained-sessions.json"
python3 - "$WORK/retained-sessions.json" "$WORK/current.handle" <<'PY'
import json
import pathlib
import sys

sessions = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert len(sessions) == 1 and sessions[0]["current"], sessions
pathlib.Path(sys.argv[2]).write_text(sessions[0]["id"])
PY

echo "== 6. A forged generation-marker cookie cannot log out the retained session =="
MARKER_COOKIE="__login_session_generation__:${USER_ID}"
MARKER_STATUS="$(curl -sS -o "$WORK/marker.body" -w '%{http_code}' \
  -H "cookie: __Host-agent_auth_session=$MARKER_COOKIE" "$API_URL/end-session")"
[ "$MARKER_STATUS" = "200" ] || {
  echo "Forged marker logout returned HTTP $MARKER_STATUS" >&2
  exit 1
}
[ "$(status_with_jar "$JAR_CURRENT")" = "200" ] || {
  echo "Forged marker cookie deleted the generation fence" >&2
  exit 1
}

echo "== 7. Sign out the current session through its management handle =="
CURRENT_HANDLE="$(<"$WORK/current.handle")"
CURRENT_DELETE_STATUS="$(curl -sS -D "$WORK/current-delete.headers" -o /dev/null \
  -w '%{http_code}' -b "$JAR_CURRENT" \
  -X DELETE "$API_URL/account/sessions/$CURRENT_HANDLE")"
[ "$CURRENT_DELETE_STATUS" = "204" ] || {
  echo "Current-session revoke failed: HTTP $CURRENT_DELETE_STATUS" >&2
  exit 1
}
grep -qi '^set-cookie: __Host-agent_auth_session=;.*Max-Age=0' \
  "$WORK/current-delete.headers" || {
  echo "Current-session revoke did not clear the browser cookie" >&2
  exit 1
}
[ "$(status_with_jar "$JAR_CURRENT")" = "401" ] || {
  echo "Revoked current Chrome cookie still authenticates" >&2
  exit 1
}

echo "== 8. Race a stale actor against revoke-others on the deployed store =="
login "$JAR_RACE_CURRENT" \
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"
login "$JAR_RACE_OLD" \
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Version/17.5 Safari/605.1.15"
for _ in $(seq 1 12); do
  curl -sS -b "$JAR_RACE_OLD" "$API_URL/account/sessions" \
    >"$WORK/race-sessions.json"
  if python3 - "$WORK/race-sessions.json" "$WORK/race-target.handle" <<'PY'
import json
import pathlib
import sys

sessions = json.loads(pathlib.Path(sys.argv[1]).read_text())
target = next(
    (session for session in sessions if session["device"] == "Chrome on Linux"),
    None,
)
if target is None:
    raise SystemExit(1)
pathlib.Path(sys.argv[2]).write_text(target["id"])
PY
  then
    break
  fi
  sleep 1
done
[ -s "$WORK/race-target.handle" ] || {
  echo "The retained race session never became visible through the user index" >&2
  exit 1
}
RACE_TARGET_HANDLE="$(<"$WORK/race-target.handle")"
(
  curl -sS -o /dev/null -w '%{http_code}' -b "$JAR_RACE_OLD" \
    -X DELETE "$API_URL/account/sessions/$RACE_TARGET_HANDLE" \
    >"$WORK/race-selected.status"
) &
RACE_SELECTED_PID=$!
(
  curl -sS -o /dev/null -w '%{http_code}' -b "$JAR_RACE_CURRENT" \
    -X DELETE "$API_URL/account/sessions" \
    >"$WORK/race-fence.status"
) &
RACE_FENCE_PID=$!
wait "$RACE_SELECTED_PID"
wait "$RACE_FENCE_PID"
RACE_SELECTED_STATUS="$(<"$WORK/race-selected.status")"
RACE_FENCE_STATUS="$(<"$WORK/race-fence.status")"
[[ "$RACE_SELECTED_STATUS" =~ ^(204|401)$ ]] || {
  echo "Unexpected selected-session race status: $RACE_SELECTED_STATUS" >&2
  exit 1
}
[[ "$RACE_FENCE_STATUS" =~ ^(204|401)$ ]] || {
  echo "Unexpected revoke-others race status: $RACE_FENCE_STATUS" >&2
  exit 1
}
if [ "$RACE_SELECTED_STATUS" != "204" ] && [ "$RACE_FENCE_STATUS" != "204" ]; then
  echo "Neither racing revocation established a valid order" >&2
  exit 1
fi
RACE_CURRENT_AUTH="$(status_with_jar "$JAR_RACE_CURRENT")"
RACE_OLD_AUTH="$(status_with_jar "$JAR_RACE_OLD")"
if [ "$RACE_CURRENT_AUTH" = "200" ]; then
  if [ "$RACE_FENCE_STATUS" != "204" ] || [ "$RACE_OLD_AUTH" != "401" ]; then
    echo "The committed fence did not retain only its current session" >&2
    exit 1
  fi
elif [ "$RACE_CURRENT_AUTH" = "401" ]; then
  if [ "$RACE_SELECTED_STATUS" != "204" ] || [ "$RACE_OLD_AUTH" != "200" ]; then
    echo "Selected-session revoke did not establish the expected winning order" >&2
    exit 1
  fi
else
  echo "Unexpected retained-session auth status: $RACE_CURRENT_AUTH" >&2
  exit 1
fi

RACE_CURRENT_COOKIE="$(awk '$6 == "__Host-agent_auth_session" { value = $7 } END { print value }' "$JAR_RACE_CURRENT")"
RACE_OLD_COOKIE="$(awk '$6 == "__Host-agent_auth_session" { value = $7 } END { print value }' "$JAR_RACE_OLD")"

echo "== 9. Verify tenant-scoped operations and secret-free Lambda logs =="
AUTH_FN="$(aws cloudformation describe-stack-resources --stack-name "$STACK" \
  --profile "$PROFILE" --region "$REGION" \
  --query "StackResources[?ResourceType=='AWS::Lambda::Function' && starts_with(LogicalResourceId, 'AuthFn')].PhysicalResourceId | [0]" \
  --output text)"
if [ -z "$AUTH_FN" ] || [ "$AUTH_FN" = "None" ]; then
  echo "Could not resolve the deployed AuthFn from stack $STACK" >&2
  exit 1
fi
for _ in $(seq 1 12); do
  aws logs filter-log-events --log-group-name "/aws/lambda/$AUTH_FN" \
    --profile "$PROFILE" --region "$REGION" --start-time "$START_MS" \
    --filter-pattern '"USER_SESSION_OPERATION"' >"$WORK/audit.json"
  if USER_ID="$USER_ID" EXPECTED_TENANT="$EXPECTED_TENANT" \
    python3 - "$WORK/audit.json" <<'PY'
import json
import os
import sys

messages = [
    event["message"]
    for event in json.load(open(sys.argv[1], encoding="utf-8")).get("events", [])
    if f"actor={os.environ['USER_ID']}" in event["message"]
]
actions = {
    part.split("=", 1)[1]
    for message in messages
    for part in message.split()
    if part.startswith("action=")
}
required = {"list", "revoke", "revoke_others"}
if not required.issubset(actions):
    raise SystemExit(1)
tenant = os.environ["EXPECTED_TENANT"]
for message in messages:
    assert f"tenant={tenant} " in message, message
assert any(
    "action=revoke_others" in message and "affected=unknown" in message
    for message in messages
), messages
PY
  then
    break
  fi
  sleep 5
done
USER_ID="$USER_ID" EXPECTED_TENANT="$EXPECTED_TENANT" python3 - "$WORK/audit.json" <<'PY'
import json
import os
import sys

messages = [
    event["message"]
    for event in json.load(open(sys.argv[1], encoding="utf-8")).get("events", [])
    if f"actor={os.environ['USER_ID']}" in event["message"]
]
actions = {
    part.split("=", 1)[1]
    for message in messages
    for part in message.split()
    if part.startswith("action=")
}
assert {"list", "revoke", "revoke_others"}.issubset(actions), messages
for message in messages:
    assert f"tenant={os.environ['EXPECTED_TENANT']} " in message, message
assert any(
    "action=revoke_others" in message and "affected=unknown" in message
    for message in messages
), messages
PY

aws logs filter-log-events --log-group-name "/aws/lambda/$AUTH_FN" \
  --profile "$PROFILE" --region "$REGION" --start-time "$START_MS" \
  >"$WORK/all-logs.json"
CURRENT_COOKIE="$CURRENT_COOKIE" IPHONE_COOKIE="$IPHONE_COOKIE" \
FIREFOX_COOKIE="$FIREFOX_COOKIE" MARKER_COOKIE="$MARKER_COOKIE" \
RACE_CURRENT_COOKIE="$RACE_CURRENT_COOKIE" RACE_OLD_COOKIE="$RACE_OLD_COOKIE" \
  python3 - "$WORK/all-logs.json" <<'PY'
import json
import os
import sys

messages = "\n".join(
    event["message"]
    for event in json.load(open(sys.argv[1], encoding="utf-8")).get("events", [])
)
for name in (
    "CURRENT_COOKIE",
    "IPHONE_COOKIE",
    "FIREFOX_COOKIE",
    "MARKER_COOKIE",
    "RACE_CURRENT_COOKIE",
    "RACE_OLD_COOKIE",
):
    value = os.environ[name]
    assert value and value not in messages, f"{name} leaked into CloudWatch"
PY

echo "PASS: deployed self-service login-session workflow"
