#!/usr/bin/env bash
# Real HTTPS CIMD authorization-code validation through a public issuer.
#
# Usage:
#   API_URL=https://<public-cloudfront-or-tenant-issuer> ./e2e/cimd.sh
# For SaaS, provide the tenant Admin credential as ADMIN_TOKEN and set STACK=AgentAuthSaas.
set -euo pipefail
set +x

API_URL="${API_URL:?API_URL must be the public CloudFront or tenant issuer origin}"
STACK="${STACK:-AgentAuthDev}"
CLIENT_ID="${CIMD_CLIENT_ID:-https://gist.githubusercontent.com/amliuyong/80ef76c59dd32bf244c5ba1ca0715dd2/raw/cimd-client.json}"
REDIRECT="${CIMD_REDIRECT_URI:-https://client.example.com/callback}"
VERIFIER="0123456789012345678901234567890123456789abc"
EMAIL="cimd-live-$(date +%s)-$RANDOM@example.com"
WORK="$(mktemp -d)"
JAR="$WORK/cookies"
USER_ID="user:$EMAIL"

cleanup() {
  if [[ -n "${ADMIN_TOKEN:-}" ]]; then
    encoded_user_id="$(USER_ID="$USER_ID" python3 -c \
      'import os,urllib.parse; print(urllib.parse.quote(os.environ["USER_ID"], safe=""))')"
    curl -sS -o /dev/null --proto '=https' --max-time 20 \
      -X DELETE "$API_URL/admin/users/$encoded_user_id" \
      -H "authorization: Bearer $ADMIN_TOKEN" || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

for command in curl jq python3; do
  command -v "$command" >/dev/null || fail "missing command: $command"
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/local_user.sh"

oauth_metadata="$(curl -fsS --proto '=https' --max-time 20 \
  "$API_URL/.well-known/oauth-authorization-server")"
oidc_metadata="$(curl -fsS --proto '=https' --max-time 20 \
  "$API_URL/.well-known/openid-configuration")"
for metadata in "$oauth_metadata" "$oidc_metadata"; do
  jq -e '.client_id_metadata_document_supported == true' <<<"$metadata" >/dev/null ||
    fail 'discovery does not advertise active CIMD support'
done
jq -e --argjson oidc "$oidc_metadata" \
  '.issuer == $oidc.issuer and
   .authorization_endpoint == $oidc.authorization_endpoint and
   .token_endpoint == $oidc.token_endpoint and
   .client_id_metadata_document_supported == $oidc.client_id_metadata_document_supported' \
  <<<"$oauth_metadata" >/dev/null ||
  fail 'OAuth and OIDC metadata disagree on the active CIMD issuer'

fixture="$(curl -fsS --proto '=https' --max-time 20 "$CLIENT_ID")"
jq -e --arg client_id "$CLIENT_ID" '.client_id == $client_id' <<<"$fixture" >/dev/null ||
  fail 'public CIMD fixture does not exactly identify its URL'
expected_fixture="$(jq -S -c . "$SCRIPT_DIR/fixtures/cimd-client.json")"
actual_fixture="$(jq -S -c . <<<"$fixture")"
[[ "$actual_fixture" == "$expected_fixture" ]] ||
  fail 'public CIMD fixture differs from this checkout'

agent_auth_provision_local_user "$API_URL" "$EMAIL" "$JAR"
grep -q '__Host-agent_auth_session' "$JAR" ||
  fail 'local-user provisioning did not establish a login session'

challenge="$(VERIFIER="$VERIFIER" python3 -c \
  'import base64,hashlib,os; print(base64.urlsafe_b64encode(hashlib.sha256(os.environ["VERIFIER"].encode()).digest()).rstrip(b"=").decode())')"
location="$(curl -fsS -b "$JAR" -o /dev/null -D - --proto '=https' --max-time 30 -G \
  "$API_URL/authorize" \
  --data-urlencode 'response_type=code' \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "redirect_uri=$REDIRECT" \
  --data-urlencode "code_challenge=$challenge" \
  --data-urlencode 'code_challenge_method=S256' \
  --data-urlencode 'scope=openid' |
  tr -d '\r' | awk 'tolower($1)=="location:"{print $2}')"
[[ "$location" == "$API_URL/consent?"* ]] ||
  fail "authorize did not continue to consent: $location"

authorize_query="$(LOCATION="$location" python3 -c \
  'import os,urllib.parse; print(urllib.parse.urlparse(os.environ["LOCATION"]).query)')"
context="$(curl -fsS -b "$JAR" --proto '=https' --max-time 30 \
  "$API_URL/consent/context?$authorize_query")"
csrf="$(jq -er '.csrf_token | select(length > 0)' <<<"$context")"
expected_redirect_host="$(REDIRECT="$REDIRECT" python3 -c \
  'import os,urllib.parse; print(urllib.parse.urlparse(os.environ["REDIRECT"]).hostname or "")')"
jq -e --arg host "$expected_redirect_host" '.redirect_uri_host == $host' <<<"$context" >/dev/null ||
  fail 'consent context does not identify the redirect hostname'
decision="$(CSRF="$csrf" AQ="$authorize_query" python3 -c \
  'import json,os; print(json.dumps({"decision":"approve","csrf":os.environ["CSRF"],"authorize_query":os.environ["AQ"]}))')"
redirect_result="$(curl -fsS -b "$JAR" --proto '=https' --max-time 30 \
  -X POST "$API_URL/consent/decision" \
  -H 'content-type: application/json' --data-binary "$decision" |
  jq -er '.redirect')"
code="$(REDIRECT_RESULT="$redirect_result" python3 -c \
  'import os,urllib.parse; print(urllib.parse.parse_qs(urllib.parse.urlparse(os.environ["REDIRECT_RESULT"]).query).get("code",[""])[0])')"
[[ -n "$code" ]] || fail 'consent did not issue an authorization code'

token="$(curl -fsS --proto '=https' --max-time 30 -X POST "$API_URL/token" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode "code=$code" \
  --data-urlencode "code_verifier=$VERIFIER" \
  --data-urlencode "redirect_uri=$REDIRECT" \
  --data-urlencode "client_id=$CLIENT_ID")"
jq -e '.access_token | type == "string" and length > 0' <<<"$token" >/dev/null ||
  fail 'token exchange did not return an access token'
jq -e '.refresh_token | type == "string" and length > 0' <<<"$token" >/dev/null ||
  fail 'token exchange did not return a refresh token'

printf 'PASS: CIMD OAuth/OIDC discovery + public HTTPS document + authorize/code/token at %s\n' "$API_URL"
