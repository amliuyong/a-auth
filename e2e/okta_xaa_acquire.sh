#!/usr/bin/env bash
# Acquire one ID-JAG from Okta Cross App Access for e2e/ema_external.sh.
# Uses the state file written once by e2e/okta_xaa_login.py and exchanges its
# refresh token at the Okta org token endpoint. Stdout contains only the
# compact assertion; diagnostics stay on stderr.
#
# Required:
#   EMA_ID_JAG_AUDIENCE=<Agent Auth issuer>
#   EMA_ID_JAG_RESOURCE=<canonical MCP resource>
#   EMA_ID_JAG_SCOPE='requested scope set'
# Optional:
#   EMA_OKTA_STATE_FILE=~/.config/agent-auth/okta-xaa.json
set -euo pipefail
set +x

STATE_FILE="${EMA_OKTA_STATE_FILE:-$HOME/.config/agent-auth/okta-xaa.json}"
AUDIENCE="${EMA_ID_JAG_AUDIENCE:?EMA_ID_JAG_AUDIENCE is required}"
RESOURCE="${EMA_ID_JAG_RESOURCE:?EMA_ID_JAG_RESOURCE is required}"
SCOPE="${EMA_ID_JAG_SCOPE:?EMA_ID_JAG_SCOPE is required}"

fail() {
  printf 'okta xaa acquisition failed: %s\n' "$1" >&2
  exit 1
}

for command in curl jq python3; do
  command -v "$command" >/dev/null || fail "missing command: $command"
done
[[ -r "$STATE_FILE" ]] || fail "state file is missing; run e2e/okta_xaa_login.py"
jq -e '
  (.org_url | type == "string" and startswith("https://")) and
  (.client_id | type == "string" and length > 0) and
  (.client_secret | type == "string" and length >= 16) and
  (.refresh_token | type == "string" and length > 0)
' "$STATE_FILE" >/dev/null || fail "state file is malformed"

umask 077
WORK="$(mktemp -d)"
cleanup() {
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

ORG_URL="$(jq -er '.org_url' "$STATE_FILE")"
python3 -I - "$STATE_FILE" "$WORK/request.form" \
  "$AUDIENCE" "$RESOURCE" "$SCOPE" <<'PY'
import json
import sys
import urllib.parse
from pathlib import Path

state_file, form_file, audience, resource, scope = sys.argv[1:]
state = json.loads(Path(state_file).read_text(encoding="utf-8"))
Path(form_file).write_text(
    urllib.parse.urlencode(
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
            "requested_token_type": "urn:ietf:params:oauth:token-type:id-jag",
            "subject_token": state["refresh_token"],
            "audience": audience,
            "resource": resource,
            "scope": scope,
            "client_id": state["client_id"],
            "client_secret": state["client_secret"],
        }
    ),
    encoding="utf-8",
)
PY

STATUS="$(
  curl -sS --proto '=https' --connect-timeout 10 --max-time 60 \
    -X POST \
    -H 'content-type: application/x-www-form-urlencoded' \
    -H 'accept: application/json' \
    --data-binary "@$WORK/request.form" \
    -o "$WORK/response.json" \
    -w '%{http_code}' \
    "$ORG_URL/oauth2/v1/token"
)"
if [[ "$STATUS" != "200" ]]; then
  ERROR="$(jq -r '[.error // "unknown", .error_description // empty] | join(": ")' "$WORK/response.json" 2>/dev/null || echo unknown)"
  fail "Okta returned HTTP $STATUS ($ERROR)"
fi
jq -e \
  '.issued_token_type == "urn:ietf:params:oauth:token-type:id-jag"' \
  "$WORK/response.json" >/dev/null ||
  fail "Okta response has the wrong token type"
# Keep the stored refresh token current if Okta rotated it.
if jq -e '.refresh_token | type == "string" and length > 0' \
  "$WORK/response.json" >/dev/null; then
  jq --slurpfile response "$WORK/response.json" \
    '.refresh_token = $response[0].refresh_token' \
    "$STATE_FILE" >"$WORK/state.json"
  mv "$WORK/state.json" "$STATE_FILE"
fi
jq -er '.access_token' "$WORK/response.json"
