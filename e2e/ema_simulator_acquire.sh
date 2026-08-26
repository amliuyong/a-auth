#!/usr/bin/env bash
# Acquire one ID-JAG from the transparent Cognito-backed EMA simulator.
# Stdout contains only the compact assertion; diagnostics stay on stderr.
set -euo pipefail
set +x

STACK="${EMA_SIMULATOR_STACK:-AgentAuthEmaSimulator}"
PROFILE="${EMA_AWS_PROFILE:-default}"
REGION="${EMA_AWS_REGION:-us-east-1}"
AUDIENCE="${EMA_ID_JAG_AUDIENCE:?EMA_ID_JAG_AUDIENCE is required}"
RESOURCE="${EMA_ID_JAG_RESOURCE:?EMA_ID_JAG_RESOURCE is required}"
SCOPE="${EMA_ID_JAG_SCOPE:?EMA_ID_JAG_SCOPE is required}"
EXPECTED_ISSUER="${EMA_ID_JAG_EXPECTED_ISSUER:?EMA_ID_JAG_EXPECTED_ISSUER is required}"
EXPECTED_TENANT="${EMA_ID_JAG_EXPECTED_TENANT-}"
EXPECTED_CLIENT_ID="${EMA_ID_JAG_EXPECTED_CLIENT_ID:?EMA_ID_JAG_EXPECTED_CLIENT_ID is required}"

fail() {
  printf 'ema simulator acquisition failed: %s\n' "$1" >&2
  exit 1
}

for command in aws curl grep jq python3; do
  command -v "$command" >/dev/null || fail "missing command: $command"
done
[[ -z "$EXPECTED_TENANT" ]] ||
  fail "the single-tenant simulator does not issue a tenant claim"

umask 077
WORK="$(mktemp -d)"
cleanup() {
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

aws cloudformation describe-stacks \
  --profile "$PROFILE" \
  --region "$REGION" \
  --stack-name "$STACK" \
  --output json >"$WORK/stack.json"

output() {
  local name="$1"
  jq -er --arg name "$name" '
    .Stacks[0].Outputs
    | map(select(.OutputKey == $name))
    | if length == 1 then .[0].OutputValue else error("missing stack output") end
  ' "$WORK/stack.json"
}

POOL_ID="$(output IdentitySourceUserPoolId)"
SOURCE_CLIENT_ID="$(output IdentitySourceClientId)"
USERNAME="$(output TestUsername)"
PASSWORD_SECRET_ARN="$(output TestUserPasswordSecretArn)"
BROKER_SECRET_ARN="$(output BrokerSecretArn)"
ISSUER="$(output IssuerUrl)"
ASSERTION_CLIENT_ID="$(output AssertionClientId)"
DEPLOYED_RESOURCE="$(output ResourceUrl)"

[[ "$EXPECTED_ISSUER" == "$ISSUER" ]] ||
  fail "expected issuer does not match the simulator stack"
[[ "$EXPECTED_CLIENT_ID" == "$ASSERTION_CLIENT_ID" ]] ||
  fail "expected assertion client does not match the simulator stack"
[[ "${RESOURCE%/}" == "${DEPLOYED_RESOURCE%/}" ]] ||
  fail "requested resource does not match the simulator stack"

aws secretsmanager get-secret-value \
  --profile "$PROFILE" \
  --region "$REGION" \
  --secret-id "$PASSWORD_SECRET_ARN" \
  --query SecretString \
  --output text >"$WORK/user-secret.json"
jq -e \
  --arg username "$USERNAME" '
    .username == $username and
    (.password | type == "string" and length >= 16)
  ' "$WORK/user-secret.json" >/dev/null ||
  fail "test user secret is malformed"
PASSWORD="$(jq -er '.password' "$WORK/user-secret.json")"

if ! aws cognito-idp admin-get-user \
  --profile "$PROFILE" \
  --region "$REGION" \
  --user-pool-id "$POOL_ID" \
  --username "$USERNAME" >"$WORK/user.json" 2>"$WORK/admin-get-user.stderr"; then
  grep -q 'UserNotFoundException' "$WORK/admin-get-user.stderr" ||
    fail "Cognito user lookup failed for a reason other than absence"
  jq -n \
    --arg pool_id "$POOL_ID" \
    --arg username "$USERNAME" \
    --arg password "$PASSWORD" '
    {
      UserPoolId: $pool_id,
      Username: $username,
      TemporaryPassword: $password,
      MessageAction: "SUPPRESS"
    }' >"$WORK/create-user-input.json"
  aws cognito-idp admin-create-user \
    --profile "$PROFILE" \
    --region "$REGION" \
    --cli-input-json "file://$WORK/create-user-input.json" \
    >"$WORK/create-user.json"
fi
jq -n \
  --arg pool_id "$POOL_ID" \
  --arg username "$USERNAME" \
  --arg password "$PASSWORD" '
  {
    UserPoolId: $pool_id,
    Username: $username,
    Password: $password,
    Permanent: true
  }' >"$WORK/set-password-input.json"
aws cognito-idp admin-set-user-password \
  --profile "$PROFILE" \
  --region "$REGION" \
  --cli-input-json "file://$WORK/set-password-input.json" >/dev/null

jq -n \
  --arg client_id "$SOURCE_CLIENT_ID" \
  --arg username "$USERNAME" \
  --arg password "$PASSWORD" '
  {
    AuthFlow: "USER_PASSWORD_AUTH",
    ClientId: $client_id,
    AuthParameters: {
      USERNAME: $username,
      PASSWORD: $password
    }
  }' >"$WORK/auth.json"
aws cognito-idp initiate-auth \
  --profile "$PROFILE" \
  --region "$REGION" \
  --cli-input-json "file://$WORK/auth.json" \
  --output json >"$WORK/auth-response.json"
jq -er '.AuthenticationResult.IdToken' \
  "$WORK/auth-response.json" >"$WORK/cognito-id-token"

aws secretsmanager get-secret-value \
  --profile "$PROFILE" \
  --region "$REGION" \
  --secret-id "$BROKER_SECRET_ARN" \
  --query SecretString \
  --output text >"$WORK/broker-secret.json"
jq -e '
  (.client_id | type == "string" and length > 0) and
  (.client_secret | type == "string" and length >= 32)
' "$WORK/broker-secret.json" >/dev/null ||
  fail "broker secret is malformed"

python3 - \
  "$WORK/broker-secret.json" \
  "$WORK/request.headers" \
  "$WORK/cognito-id-token" \
  "$WORK/request.form" \
  "$AUDIENCE" \
  "$RESOURCE" \
  "$SCOPE" <<'PY'
import base64
import json
import sys
import urllib.parse
from pathlib import Path

secret_file, header_file, token_file, form_file, audience, resource, scope = sys.argv[1:]
secret = json.loads(Path(secret_file).read_text(encoding="utf-8"))
credential = base64.b64encode(
    f"{secret['client_id']}:{secret['client_secret']}".encode()
).decode()
Path(header_file).write_text(
    f"authorization: Basic {credential}\n"
    "content-type: application/x-www-form-urlencoded\n"
    "accept: application/json\n",
    encoding="utf-8",
)
Path(form_file).write_text(
    urllib.parse.urlencode(
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
            "requested_token_type": "urn:ietf:params:oauth:token-type:id-jag",
            "subject_token": Path(token_file).read_text(encoding="utf-8").strip(),
            "audience": audience,
            "resource": resource,
            "scope": scope,
        }
    ),
    encoding="utf-8",
)
PY

STATUS="$(
  curl -sS --proto '=https' --connect-timeout 10 --max-time 60 \
    -X POST \
    -H "@$WORK/request.headers" \
    --data-binary "@$WORK/request.form" \
    -o "$WORK/response.json" \
    -w '%{http_code}' \
    "$ISSUER/token"
)"
[[ "$STATUS" == "200" ]] ||
  fail "issuer returned HTTP $STATUS"
jq -e \
  '.issued_token_type == "urn:ietf:params:oauth:token-type:id-jag"' \
  "$WORK/response.json" >/dev/null ||
  fail "issuer response has the wrong token type"
jq -er '.access_token' "$WORK/response.json"
