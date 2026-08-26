#!/usr/bin/env bash
# Issue #34 deployed acceptance: real Admin SPA show-once copy, separate-browser
# acceptance, verifier-only Dynamo evidence, replay rejection, and bearer-free logs.
#
# Usage:
#   API_URL=https://<cloudfront-host> AWS_PROFILE=default ./e2e/invitation.sh
set -euo pipefail
source "$(dirname "$0")/lib/local_user.sh"

API_URL="${API_URL:?API_URL is required}"
API_URL="${API_URL%/}"
STACK="${STACK:-AgentAuthDev}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
STATE="$WORK/invitation.json"
START_MS="$(python3 -c 'import time; print(int(time.time() * 1000) - 1000)')"
EMAIL="e2e-invitation-$(python3 -c 'import secrets; print(secrets.token_hex(6))')@example.com"
USER_ID="user:${EMAIL}"

stack_output() {
  aws cloudformation describe-stacks --stack-name "$STACK" \
    --profile "$PROFILE" --region "$REGION" \
    --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue | [0]" \
    --output text
}

INVITATIONS_TABLE="${INVITATIONS_TABLE:-$(stack_output InvitationsTableName)}"
SESSIONS_TABLE="${SESSIONS_TABLE:-$(stack_output SessionsTableName)}"
for value in "$INVITATIONS_TABLE" "$SESSIONS_TABLE"; do
  if [ -z "$value" ] || [ "$value" = "None" ]; then
    echo "Required stack output is missing from $STACK" >&2
    exit 1
  fi
done

agent_auth_admin_token

cleanup() {
  if [ -n "${ADMIN_TOKEN:-}" ]; then
    curl -sS -o /dev/null -X DELETE "$API_URL/admin/users/$USER_ID" \
      -H "authorization: Bearer $ADMIN_TOKEN" || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "== 1. Admin SPA issues, displays, and copies the invitation once =="
API_URL="$API_URL" ADMIN_TOKEN="$ADMIN_TOKEN" EMAIL="$EMAIL" OUTPUT_FILE="$STATE" \
  node "$ROOT/web/e2e/invitation-live.mjs" issue
[ "$(stat -c '%a' "$STATE")" = "600" ] || {
  echo "Invitation state file permissions are not 0600" >&2
  exit 1
}

read_state() {
  FIELD="$1" python3 - "$STATE" <<'PY'
import json
import os
import sys

print(json.load(open(sys.argv[1], encoding="utf-8"))[os.environ["FIELD"]])
PY
}

TOKEN="$(read_state token)"
LOCATOR="$(read_state locator)"
SECRET="$(read_state secret)"
INVITATION_URL="$(read_state invitation_url)"
EXPIRES_AT="$(read_state expires_at)"

echo "== 2. Dynamo stores the verifier and metadata, never the bearer secret =="
LOCATOR="$LOCATOR" python3 - "$WORK/invitation-key.json" <<'PY'
import json
import os
import sys

json.dump({"locator": {"S": os.environ["LOCATOR"]}}, open(sys.argv[1], "w", encoding="utf-8"))
PY
aws dynamodb get-item --table-name "$INVITATIONS_TABLE" --consistent-read \
  --key "file://$WORK/invitation-key.json" --profile "$PROFILE" --region "$REGION" \
  >"$WORK/invitation-item.json"
LOCATOR="$LOCATOR" SECRET="$SECRET" USER_ID="$USER_ID" EMAIL="$EMAIL" \
EXPIRES_AT="$EXPIRES_AT" TOKEN="$TOKEN" INVITATION_URL="$INVITATION_URL" \
  python3 - "$WORK/invitation-item.json" <<'PY'
import base64
import hashlib
import json
import os
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
item = json.loads(text).get("Item")
assert item, "invitation row is missing"
assert set(item) == {
    "locator", "activation_id", "user_id", "email", "verifier_hash",
    "credential_epoch", "issued_at", "expires_at",
}
assert item["locator"]["S"] == os.environ["LOCATOR"]
assert item["activation_id"]["S"]
assert item["user_id"]["S"] == os.environ["USER_ID"]
assert item["email"]["S"] == os.environ["EMAIL"]
expected = base64.urlsafe_b64encode(
    hashlib.sha256(os.environ["SECRET"].encode()).digest()
).rstrip(b"=").decode()
assert item["verifier_hash"]["S"] == expected
assert item["expires_at"]["N"] == os.environ["EXPIRES_AT"]
for value in (
    os.environ["SECRET"],
    os.environ["TOKEN"],
    os.environ["INVITATION_URL"],
):
    assert value not in text, "plaintext invitation bearer leaked into DynamoDB"
PY

echo "== 3. A separate browser accepts the fragment URL and reaches /account =="
API_URL="$API_URL" OUTPUT_FILE="$STATE" \
  node "$ROOT/web/e2e/invitation-live.mjs" accept
SESSION_ID="$(read_state session_id)"

echo "== 4. Consume deletes the invitation and creates only amr=invite session =="
aws dynamodb get-item --table-name "$INVITATIONS_TABLE" --consistent-read \
  --key "file://$WORK/invitation-key.json" --profile "$PROFILE" --region "$REGION" \
  >"$WORK/invitation-after.json"
python3 - "$WORK/invitation-after.json" <<'PY'
import json
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
body = json.loads(text) if text.strip() else {}
assert "Item" not in body
PY
SESSION_ID="$SESSION_ID" python3 - "$WORK/session-key.json" <<'PY'
import json
import os
import sys

json.dump({"session_id": {"S": os.environ["SESSION_ID"]}}, open(sys.argv[1], "w", encoding="utf-8"))
PY
aws dynamodb get-item --table-name "$SESSIONS_TABLE" --consistent-read \
  --key "file://$WORK/session-key.json" --profile "$PROFILE" --region "$REGION" \
  >"$WORK/session-item.json"
SESSION_ID="$SESSION_ID" USER_ID="$USER_ID" TOKEN="$TOKEN" SECRET="$SECRET" \
  python3 - "$WORK/session-item.json" <<'PY'
import json
import os
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
item = json.loads(text).get("Item")
assert item, "invitation session row is missing"
assert item["session_id"]["S"] == os.environ["SESSION_ID"]
assert item["user_id"]["S"] == os.environ["USER_ID"]
assert [entry["S"] for entry in item["amr"]["L"]] == ["invite"]
assert os.environ["TOKEN"] not in text
assert os.environ["SECRET"] not in text
PY

echo "== 5. Replay is rejected and Admin detail remains password-not-configured =="
REPLAY_BODY="$(TOKEN="$TOKEN" python3 -c \
  'import json,os; print(json.dumps({"token":os.environ["TOKEN"]}))')"
REPLAY_STATUS="$(printf '%s' "$REPLAY_BODY" | curl -sS -o "$WORK/replay.json" \
  -w '%{http_code}' -X POST "$API_URL/login/invitation" \
  -H "content-type: application/json" --data-binary @-)"
[ "$REPLAY_STATUS" = "400" ] || {
  echo "Invitation replay was not rejected: HTTP $REPLAY_STATUS" >&2
  exit 1
}
DETAIL_STATUS="$(curl -sS -o "$WORK/detail.json" -w '%{http_code}' \
  "$API_URL/admin/users/$USER_ID" -H "authorization: Bearer $ADMIN_TOKEN")"
[ "$DETAIL_STATUS" = "200" ] || {
  echo "Admin user detail failed: HTTP $DETAIL_STATUS" >&2
  exit 1
}
python3 - "$WORK/detail.json" <<'PY'
import json
import sys

body = json.load(open(sys.argv[1], encoding="utf-8"))
assert body["password_status"] == "not_configured"
assert isinstance(body.get("last_login_at"), int) and body["last_login_at"] > 0
PY

echo "== 6. Lambda and API access logs contain no invitation bearer =="
AUTH_LOG="$(aws cloudformation describe-stack-resources --stack-name "$STACK" \
  --profile "$PROFILE" --region "$REGION" \
  --query "StackResources[?ResourceType=='AWS::Logs::LogGroup' && starts_with(LogicalResourceId, 'AuthFnLogGroup')].PhysicalResourceId | [0]" \
  --output text)"
API_LOG="$(aws cloudformation describe-stack-resources --stack-name "$STACK" \
  --profile "$PROFILE" --region "$REGION" \
  --query "StackResources[?ResourceType=='AWS::Logs::LogGroup' && starts_with(LogicalResourceId, 'ApiAccessLogs')].PhysicalResourceId | [0]" \
  --output text)"
for pair in "lambda:$AUTH_LOG" "access:$API_LOG"; do
  name="${pair%%:*}"
  group="${pair#*:}"
  if [ -z "$group" ] || [ "$group" = "None" ]; then
    echo "Could not resolve $name log group from stack $STACK" >&2
    exit 1
  fi
  found=0
  for _ in $(seq 1 12); do
    aws logs filter-log-events --log-group-name "$group" --start-time "$START_MS" \
      --profile "$PROFILE" --region "$REGION" >"$WORK/$name-logs.json"
    if NAME="$name" USER_ID="$USER_ID" python3 - "$WORK/$name-logs.json" <<'PY'
import json
import os
import sys

messages = "\n".join(
    event["message"]
    for event in json.load(open(sys.argv[1], encoding="utf-8")).get("events", [])
)
needle = os.environ["USER_ID"] if os.environ["NAME"] == "lambda" else "/login/invitation"
raise SystemExit(0 if needle in messages else 1)
PY
    then
      found=1
      break
    fi
    sleep 5
  done
  if [ "$found" != "1" ]; then
    echo "Expected $name log evidence did not arrive" >&2
    exit 1
  fi
done
TOKEN="$TOKEN" SECRET="$SECRET" INVITATION_URL="$INVITATION_URL" \
  python3 - "$WORK/lambda-logs.json" "$WORK/access-logs.json" <<'PY'
import json
import os
import sys

messages = "\n".join(
    event["message"]
    for path in sys.argv[1:]
    for event in json.load(open(path, encoding="utf-8")).get("events", [])
)
for name in ("TOKEN", "SECRET", "INVITATION_URL"):
    value = os.environ[name]
    assert value and value not in messages, f"{name} leaked into CloudWatch"
PY

echo "PASS: deployed Admin one-time invitation workflow"
