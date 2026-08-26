#!/usr/bin/env bash
# C9.5 live acceptance: real Cognito OIDC federation, assurance fail-closed,
# prompt/max_age, exact deployed artifact binding, and verified cleanup.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STACK_NAME="${STACK_NAME:-AgentAuthDev}"
REGION="${REGION:-us-east-1}"
PROFILE="${AWS_PROFILE:-default}"
COGNITO_POOL_ID="${COGNITO_POOL_ID:?set COGNITO_POOL_ID}"
COGNITO_DOMAIN="${COGNITO_DOMAIN:?set COGNITO_DOMAIN}"
COGNITO_ISSUER="${COGNITO_ISSUER:?set COGNITO_ISSUER}"
COGNITO_TOKEN_ENDPOINT="${COGNITO_TOKEN_ENDPOINT:?set COGNITO_TOKEN_ENDPOINT}"
COGNITO_JWKS_URI="${COGNITO_JWKS_URI:?set COGNITO_JWKS_URI}"
EVIDENCE_FILE="${EVIDENCE_FILE:-/tmp/agent-auth-c9-5-$(date -u +%Y%m%dT%H%M%SZ).json}"

for command in aws base64 cmp curl git grep jq openssl python3 sha256sum unzip; do
  command -v "$command" >/dev/null || {
    echo "missing required command: $command" >&2
    exit 1
  }
done

umask 077
WORK="$(mktemp -d)"
RUN_ID="$(python3 -c 'import secrets; print(secrets.token_hex(8))')"
UPSTREAM_IDP_ID="c9-5-cognito-$RUN_ID"
COGNITO_CLIENT_NAME="agent-auth-c9-5-$RUN_ID"
COGNITO_USER="c9-5-$RUN_ID@example.com"
SECRET_NAME="agent-auth/federation/c9-5-$RUN_ID"
DOWN_CLIENT_ID="c9-5-down-$RUN_ID"
DOWN_REDIRECT="https://c9-5-$RUN_ID.invalid/callback"
COGNITO_CLIENT_ID=""
SESSION_ID=""
USER_ID=""
API_URL=""
PUBLIC_ORIGIN=""
CLIENTS_TABLE=""
SESSIONS_TABLE=""
USERS_TABLE=""
FEDERATION_CONFIG_TABLE=""
FEDERATION_FLOW_TABLE=""
ADMIN_HEADER_FILE="$WORK/admin-header"
PASSWORD_FILE="$WORK/cognito-password"
PASSWORD_INPUT_FILE="$WORK/cognito-password-input.json"
COGNITO_CLIENT_FILE="$WORK/cognito-client.json"
COGNITO_SECRET_FILE="$WORK/cognito-client-secret"
ROUNDTRIP_RESULT="$WORK/roundtrip.json"
RECOVERY_FILE="$WORK/recovery.json"
AUTH_ZIP="$WORK/auth.zip"
AUTH_UNPACKED="$WORK/auth"
AUTH_FUNCTION=""
DEPLOYED_COMMIT=""

stack_output() {
  local key="$1"
  aws cloudformation describe-stacks \
    --profile "$PROFILE" --region "$REGION" --stack-name "$STACK_NAME" \
    --query "Stacks[0].Outputs[?OutputKey=='$key'].OutputValue | [0]" \
    --output text
}

ddb_absent() {
  local table="$1" key="$2"
  local output
  if ! output="$(aws dynamodb get-item \
    --profile "$PROFILE" --region "$REGION" --table-name "$table" \
    --consistent-read --key "$key" --output json)"; then
    return 1
  fi
  [[ -z "$output" ]] && return 0
  jq -e 'has("Item") | not' <<<"$output" >/dev/null
}

secret_absent() {
  local error_file="$WORK/secret-absent.error"
  if aws secretsmanager describe-secret \
    --profile "$PROFILE" --region "$REGION" --secret-id "$SECRET_NAME" \
    >/dev/null 2>"$error_file"; then
    return 1
  fi
  grep -q 'ResourceNotFoundException' "$error_file"
}

cognito_client_absent() {
  local error_file="$WORK/client-absent.error"
  [[ -z "$COGNITO_CLIENT_ID" ]] && return 0
  if aws cognito-idp describe-user-pool-client \
    --profile "$PROFILE" --region "$REGION" --user-pool-id "$COGNITO_POOL_ID" \
    --client-id "$COGNITO_CLIENT_ID" >/dev/null 2>"$error_file"; then
    return 1
  fi
  grep -q 'ResourceNotFoundException' "$error_file"
}

cognito_user_absent() {
  local error_file="$WORK/user-absent.error"
  if aws cognito-idp admin-get-user \
    --profile "$PROFILE" --region "$REGION" --user-pool-id "$COGNITO_POOL_ID" \
    --username "$COGNITO_USER" >/dev/null 2>"$error_file"; then
    return 1
  fi
  grep -q 'UserNotFoundException' "$error_file"
}

wait_for_absence() {
  local check="$1"
  local remaining=30
  while ((remaining > 0)); do
    if "$check"; then
      return 0
    fi
    sleep 1
    remaining=$((remaining - 1))
  done
  return 1
}

delete_recovery_flows() {
  [[ -n "$FEDERATION_FLOW_TABLE" && -s "$RECOVERY_FILE" ]] || return 0
  while IFS= read -r flow_state; do
    aws dynamodb delete-item \
      --profile "$PROFILE" --region "$REGION" --table-name "$FEDERATION_FLOW_TABLE" \
      --key "$(jq -cn --arg state "$flow_state" '{state:{S:$state}}')" >/dev/null
  done < <(jq -r '.flow_states[]' "$RECOVERY_FILE")
}

cleanup() {
  local status=$?
  set +e
  if [[ -s "$RECOVERY_FILE" ]]; then
    SESSION_ID="${SESSION_ID:-$(jq -r '.session_id // empty' "$RECOVERY_FILE")}"
  fi
  if [[ -n "$SESSION_ID" && -n "$SESSIONS_TABLE" && -z "$USER_ID" ]]; then
    USER_ID="$(aws dynamodb get-item \
      --profile "$PROFILE" --region "$REGION" --table-name "$SESSIONS_TABLE" \
      --consistent-read --key "$(jq -cn --arg id "$SESSION_ID" '{session_id:{S:$id}}')" \
      --query 'Item.user_id.S' --output text 2>/dev/null)"
    [[ "$USER_ID" == "None" ]] && USER_ID=""
  fi
  if [[ -n "$API_URL" && -s "$ADMIN_HEADER_FILE" ]]; then
    curl -sS -o /dev/null -X DELETE \
      "$API_URL/admin/federation/default/$UPSTREAM_IDP_ID" \
      --header "@$ADMIN_HEADER_FILE"
  fi
  delete_recovery_flows
  if [[ -n "$SESSION_ID" && -n "$SESSIONS_TABLE" ]]; then
    aws dynamodb delete-item \
      --profile "$PROFILE" --region "$REGION" --table-name "$SESSIONS_TABLE" \
      --key "$(jq -cn --arg id "$SESSION_ID" '{session_id:{S:$id}}')" >/dev/null
  fi
  if [[ -n "$USER_ID" && -n "$USERS_TABLE" ]]; then
    aws dynamodb delete-item \
      --profile "$PROFILE" --region "$REGION" --table-name "$USERS_TABLE" \
      --key "$(jq -cn --arg id "$USER_ID" '{user_id:{S:$id}}')" >/dev/null
  fi
  if [[ -n "$CLIENTS_TABLE" ]]; then
    aws dynamodb delete-item \
      --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
      --key "$(jq -cn --arg id "$DOWN_CLIENT_ID" '{client_id:{S:$id}}')" >/dev/null
  fi
  if [[ -n "$COGNITO_CLIENT_ID" ]]; then
    aws cognito-idp delete-user-pool-client \
      --profile "$PROFILE" --region "$REGION" --user-pool-id "$COGNITO_POOL_ID" \
      --client-id "$COGNITO_CLIENT_ID" >/dev/null
  fi
  aws cognito-idp admin-delete-user \
    --profile "$PROFILE" --region "$REGION" --user-pool-id "$COGNITO_POOL_ID" \
    --username "$COGNITO_USER" >/dev/null
  aws secretsmanager delete-secret \
    --profile "$PROFILE" --region "$REGION" --secret-id "$SECRET_NAME" \
    --force-delete-without-recovery >/dev/null

  if [[ -n "$FEDERATION_CONFIG_TABLE" ]]; then
    ddb_absent "$FEDERATION_CONFIG_TABLE" \
      "$(jq -cn --arg t default --arg i "$UPSTREAM_IDP_ID" \
        '{tenant_id:{S:$t},upstream_idp_id:{S:$i}}')" || status=1
  fi
  if [[ -n "$SESSION_ID" && -n "$SESSIONS_TABLE" ]]; then
    ddb_absent "$SESSIONS_TABLE" \
      "$(jq -cn --arg id "$SESSION_ID" '{session_id:{S:$id}}')" || status=1
  fi
  if [[ -n "$USER_ID" && -n "$USERS_TABLE" ]]; then
    ddb_absent "$USERS_TABLE" \
      "$(jq -cn --arg id "$USER_ID" '{user_id:{S:$id}}')" || status=1
  fi
  if [[ -n "$CLIENTS_TABLE" ]]; then
    ddb_absent "$CLIENTS_TABLE" \
      "$(jq -cn --arg id "$DOWN_CLIENT_ID" '{client_id:{S:$id}}')" || status=1
  fi
  if [[ -n "$FEDERATION_FLOW_TABLE" && -s "$RECOVERY_FILE" ]]; then
    while IFS= read -r flow_state; do
      ddb_absent "$FEDERATION_FLOW_TABLE" \
        "$(jq -cn --arg state "$flow_state" '{state:{S:$state}}')" || status=1
    done < <(jq -r '.flow_states[]' "$RECOVERY_FILE")
  fi
  wait_for_absence cognito_client_absent || status=1
  wait_for_absence cognito_user_absent || status=1
  wait_for_absence secret_absent || status=1

  find "$WORK" -type f -delete
  find "$WORK" -depth -type d -empty -delete
  rmdir "$WORK" 2>/dev/null || true
  if [[ "$status" -ne 0 ]]; then
    rm -f "$EVIDENCE_FILE"
  fi
  trap - EXIT
  exit "$status"
}
trap cleanup EXIT

[[ "$STACK_NAME" == "AgentAuthDev" ]] || {
  echo "C9.5 qualifying gate requires STACK_NAME=AgentAuthDev" >&2
  exit 1
}
[[ "$(git -C "$ROOT" status --porcelain)" == "" ]] || {
  echo "worktree must be clean" >&2
  exit 1
}
HEAD_COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
[[ "$HEAD_COMMIT" =~ ^[0-9a-f]{40}$ ]] || {
  echo "HEAD is not an exact Git revision" >&2
  exit 1
}

STACK_STATUS="$(aws cloudformation describe-stacks \
  --profile "$PROFILE" --region "$REGION" --stack-name "$STACK_NAME" \
  --query 'Stacks[0].StackStatus' --output text)"
[[ "$STACK_STATUS" == "UPDATE_COMPLETE" ]] || {
  echo "$STACK_NAME is not UPDATE_COMPLETE" >&2
  exit 1
}
DEPLOYED_COMMIT="$(stack_output DeploymentCommit)"
[[ "$DEPLOYED_COMMIT" == "$HEAD_COMMIT" ]] || {
  echo "deployed commit does not match clean HEAD" >&2
  exit 1
}

API_URL="$(stack_output ApiUrl)"
ADMIN_URL="$(stack_output AdminUrl)"
PUBLIC_ORIGIN="${ADMIN_URL%/admin}"
[[ "$PUBLIC_ORIGIN" =~ ^https://[^/]+$ ]] || {
  echo "AdminUrl does not expose a valid public browser origin" >&2
  exit 1
}
CLIENTS_TABLE="$(stack_output ClientsTableName)"
SESSIONS_TABLE="$(stack_output SessionsTableName)"
USERS_TABLE="$(stack_output UsersTableName)"
AUTH_FUNCTION="$(stack_output AuthFnName)"
ADMIN_SECRET_ARN="$(stack_output AdminSecretArn)"

AUTH_CONFIG="$(aws lambda get-function-configuration \
  --profile "$PROFILE" --region "$REGION" --function-name "$AUTH_FUNCTION" --output json)"
[[ "$(jq -r '.State' <<<"$AUTH_CONFIG")" == "Active" ]] || {
  echo "Auth Lambda is not Active" >&2
  exit 1
}
[[ "$(jq -r '.LastUpdateStatus' <<<"$AUTH_CONFIG")" == "Successful" ]] || {
  echo "Auth Lambda update is not Successful" >&2
  exit 1
}
[[ "$(jq -r '.Environment.Variables.AGENT_AUTH_DEPLOYMENT_COMMIT' <<<"$AUTH_CONFIG")" == "$DEPLOYED_COMMIT" ]]
[[ "$(jq -r '.Environment.Variables.AGENT_AUTH_FEDERATION_ENABLED' <<<"$AUTH_CONFIG")" == "1" ]] || {
  echo "federation is not enabled in the deployed runtime" >&2
  exit 1
}
FEDERATION_CONFIG_TABLE="$(jq -r '.Environment.Variables.FEDERATION_CONFIG_TABLE' <<<"$AUTH_CONFIG")"
FEDERATION_FLOW_TABLE="$(jq -r '.Environment.Variables.FEDERATION_FLOW_TABLE' <<<"$AUTH_CONFIG")"

mkdir "$AUTH_UNPACKED"
AUTH_LOCATION="$(aws lambda get-function \
  --profile "$PROFILE" --region "$REGION" --function-name "$AUTH_FUNCTION" \
  --query 'Code.Location' --output text)"
curl -sS "$AUTH_LOCATION" -o "$AUTH_ZIP"
AWS_CODE_SHA="$(aws lambda get-function-configuration \
  --profile "$PROFILE" --region "$REGION" --function-name "$AUTH_FUNCTION" \
  --query 'CodeSha256' --output text)"
[[ "$(openssl dgst -sha256 -binary "$AUTH_ZIP" | base64 | tr -d '\n')" == "$AWS_CODE_SHA" ]] || {
  echo "downloaded Auth package does not match AWS CodeSha256" >&2
  exit 1
}
unzip -q "$AUTH_ZIP" -d "$AUTH_UNPACKED"
LOCAL_ASSET="$ROOT/target/lambda/agent-auth-lambda"
LOCAL_BOOTSTRAP="$LOCAL_ASSET/bootstrap"
LOCAL_PROVENANCE="$LOCAL_ASSET/deployment-provenance.json"
[[ -x "$LOCAL_BOOTSTRAP" && -f "$LOCAL_PROVENANCE" ]] || {
  echo "exact-commit local Auth artifact/provenance is missing" >&2
  exit 1
}
cmp "$AUTH_UNPACKED/bootstrap" "$LOCAL_BOOTSTRAP"
[[ "$(jq -r '.commit' "$LOCAL_PROVENANCE")" == "$DEPLOYED_COMMIT" ]]
[[ "$(jq -r '.bootstrap_sha256' "$LOCAL_PROVENANCE")" == \
  "$(sha256sum "$LOCAL_BOOTSTRAP" | cut -d' ' -f1)" ]]

aws secretsmanager get-secret-value \
  --profile "$PROFILE" --region "$REGION" --secret-id "$ADMIN_SECRET_ARN" \
  --query SecretString --output text |
  jq -er '"authorization: Bearer " + .current.secret' >"$ADMIN_HEADER_FILE"
python3 - <<'PY' >"$PASSWORD_FILE"
import secrets
import string
alphabet = string.ascii_letters + string.digits + "!@#%^*-_"
print("Aa1!" + "".join(secrets.choice(alphabet) for _ in range(36)), end="")
PY

CALLBACK_URL="$PUBLIC_ORIGIN/federation/callback"
aws cognito-idp create-user-pool-client \
  --profile "$PROFILE" --region "$REGION" --user-pool-id "$COGNITO_POOL_ID" \
  --client-name "$COGNITO_CLIENT_NAME" --generate-secret \
  --allowed-o-auth-flows code --allowed-o-auth-scopes openid email profile \
  --allowed-o-auth-flows-user-pool-client --supported-identity-providers COGNITO \
  --callback-urls "$CALLBACK_URL" --output json >"$COGNITO_CLIENT_FILE"
COGNITO_CLIENT_ID="$(jq -er '.UserPoolClient.ClientId' "$COGNITO_CLIENT_FILE")"
jq -jer '.UserPoolClient.ClientSecret' "$COGNITO_CLIENT_FILE" >"$COGNITO_SECRET_FILE"
aws secretsmanager create-secret \
  --profile "$PROFILE" --region "$REGION" --name "$SECRET_NAME" \
  --secret-string "file://$COGNITO_SECRET_FILE" >/dev/null
rm -f "$COGNITO_CLIENT_FILE" "$COGNITO_SECRET_FILE"

aws cognito-idp admin-create-user \
  --profile "$PROFILE" --region "$REGION" --user-pool-id "$COGNITO_POOL_ID" \
  --username "$COGNITO_USER" --message-action SUPPRESS \
  --user-attributes Name=email,Value="$COGNITO_USER" Name=email_verified,Value=true >/dev/null
jq -n \
  --arg pool "$COGNITO_POOL_ID" \
  --arg user "$COGNITO_USER" \
  --rawfile password "$PASSWORD_FILE" '{
    UserPoolId:$pool,
    Username:$user,
    Password:$password,
    Permanent:true
  }' >"$PASSWORD_INPUT_FILE"
aws cognito-idp admin-set-user-password \
  --profile "$PROFILE" --region "$REGION" \
  --cli-input-json "file://$PASSWORD_INPUT_FILE"
rm -f "$PASSWORD_INPUT_FILE"

CONFIG_BODY="$WORK/federation-config.json"
jq -n \
  --arg idp "$UPSTREAM_IDP_ID" \
  --arg issuer "$COGNITO_ISSUER" \
  --arg client "$COGNITO_CLIENT_ID" \
  --arg secret "$SECRET_NAME" \
  --arg authorize "$COGNITO_DOMAIN/oauth2/authorize" \
  --arg token "$COGNITO_TOKEN_ENDPOINT" \
  --arg jwks "$COGNITO_JWKS_URI" '{
    tenant_id:"default",
    upstream_idp_id:$idp,
    upstream_issuer:$issuer,
    client_id:$client,
    client_secret_ref:$secret,
    authorization_endpoint:$authorize,
    token_endpoint:$token,
    jwks_uri:$jwks,
    scopes:["openid","email","profile"],
    strong_acr_values:["urn:agent-auth:e2e:cognito-mfa"]
  }' >"$CONFIG_BODY"
CONFIG_STATUS="$(curl -sS -o "$WORK/config-response" -w '%{http_code}' \
  -X PUT "$API_URL/admin/federation" \
  --header "@$ADMIN_HEADER_FILE" \
  -H 'content-type: application/json' --data-binary "@$CONFIG_BODY")"
[[ "$CONFIG_STATUS" == "201" ]] || {
  echo "federation config registration returned HTTP $CONFIG_STATUS" >&2
  exit 1
}
CONFIG_ITEM="$(aws dynamodb get-item \
  --profile "$PROFILE" --region "$REGION" --table-name "$FEDERATION_CONFIG_TABLE" \
  --consistent-read --key "$(jq -cn --arg t default --arg i "$UPSTREAM_IDP_ID" \
    '{tenant_id:{S:$t},upstream_idp_id:{S:$i}}')" --output json)"
[[ "$(jq -r '.Item.config_json.S | length > 0' <<<"$CONFIG_ITEM")" == "true" ]]

aws dynamodb put-item \
  --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --condition-expression 'attribute_not_exists(client_id)' \
  --item "$(jq -cn --arg id "$DOWN_CLIENT_ID" --arg redirect "$DOWN_REDIRECT" '{
    client_id:{S:$id},
    redirect_uris:{L:[{S:$redirect}]},
    token_endpoint_auth_method:{S:"none"}
  }')" >/dev/null
CLIENT_ITEM="$(aws dynamodb get-item \
  --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --consistent-read --key "$(jq -cn --arg id "$DOWN_CLIENT_ID" '{client_id:{S:$id}}')" \
  --output json)"
[[ "$(jq -r '.Item.client_id.S == $id' --arg id "$DOWN_CLIENT_ID" <<<"$CLIENT_ITEM")" == "true" ]]
sleep 2

AS_URL="$PUBLIC_ORIGIN" \
COGNITO_DOMAIN="$COGNITO_DOMAIN" \
DOWN_CLIENT_ID="$DOWN_CLIENT_ID" \
DOWN_REDIRECT="$DOWN_REDIRECT" \
UPSTREAM_IDP_ID="$UPSTREAM_IDP_ID" \
TEST_USER="$COGNITO_USER" \
TEST_PASSWORD_FILE="$PASSWORD_FILE" \
RESULT_FILE="$ROUNDTRIP_RESULT" \
RECOVERY_FILE="$RECOVERY_FILE" \
EXPECTED_STRONG_ACR="urn:agent-auth:e2e:cognito-mfa" \
EXPECTED_STRONG_MAX_AGE=300 \
python3 "$ROOT/e2e/federation_assurance_roundtrip.py"

SESSION_ID="$(jq -er '.session_id' "$ROUNDTRIP_RESULT")"
SESSION_ITEM="$(aws dynamodb get-item \
  --profile "$PROFILE" --region "$REGION" --table-name "$SESSIONS_TABLE" \
  --consistent-read --key "$(jq -cn --arg id "$SESSION_ID" '{session_id:{S:$id}}')" \
  --output json)"
USER_ID="$(jq -er '.Item.user_id.S' <<<"$SESSION_ITEM")"
[[ "$(jq -r '.Item.acr.S' <<<"$SESSION_ITEM")" == "urn:agent-auth:assurance:baseline" ]] || {
  echo "real Cognito session did not remain at canonical baseline" >&2
  exit 1
}
[[ "$(jq -r '.Item.auth_time.N | tonumber > 0' <<<"$SESSION_ITEM")" == "true" ]]
[[ "$(jq -r '
  .baseline_roundtrip and
  .strong_without_trusted_acr_rejected and
  .upstream_strong_parameters_forwarded and
  .prompt_none_no_session_login_required and
  .prompt_none_no_consent_consent_required and
  .prompt_login_reauthentication and
  .max_age_zero_reauthentication
' "$ROUNDTRIP_RESULT")" == "true" ]]

# Delete all mutable credentials before producing PASS evidence. The cleanup
# function still verifies absence and handles any later failure.
DELETE_CONFIG_STATUS="$(curl -sS -o /dev/null -w '%{http_code}' -X DELETE \
  "$API_URL/admin/federation/default/$UPSTREAM_IDP_ID" \
  --header "@$ADMIN_HEADER_FILE")"
[[ "$DELETE_CONFIG_STATUS" == "200" ]] || {
  echo "federation config deletion returned HTTP $DELETE_CONFIG_STATUS" >&2
  exit 1
}
delete_recovery_flows
aws dynamodb delete-item \
  --profile "$PROFILE" --region "$REGION" --table-name "$SESSIONS_TABLE" \
  --key "$(jq -cn --arg id "$SESSION_ID" '{session_id:{S:$id}}')" >/dev/null
aws dynamodb delete-item \
  --profile "$PROFILE" --region "$REGION" --table-name "$USERS_TABLE" \
  --key "$(jq -cn --arg id "$USER_ID" '{user_id:{S:$id}}')" >/dev/null
aws dynamodb delete-item \
  --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --key "$(jq -cn --arg id "$DOWN_CLIENT_ID" '{client_id:{S:$id}}')" >/dev/null
aws cognito-idp delete-user-pool-client \
  --profile "$PROFILE" --region "$REGION" --user-pool-id "$COGNITO_POOL_ID" \
  --client-id "$COGNITO_CLIENT_ID"
aws cognito-idp admin-delete-user \
  --profile "$PROFILE" --region "$REGION" --user-pool-id "$COGNITO_POOL_ID" \
  --username "$COGNITO_USER"
aws secretsmanager delete-secret \
  --profile "$PROFILE" --region "$REGION" --secret-id "$SECRET_NAME" \
  --force-delete-without-recovery >/dev/null

ddb_absent "$FEDERATION_CONFIG_TABLE" \
  "$(jq -cn --arg t default --arg i "$UPSTREAM_IDP_ID" \
    '{tenant_id:{S:$t},upstream_idp_id:{S:$i}}')"
ddb_absent "$SESSIONS_TABLE" "$(jq -cn --arg id "$SESSION_ID" '{session_id:{S:$id}}')"
ddb_absent "$USERS_TABLE" "$(jq -cn --arg id "$USER_ID" '{user_id:{S:$id}}')"
ddb_absent "$CLIENTS_TABLE" "$(jq -cn --arg id "$DOWN_CLIENT_ID" '{client_id:{S:$id}}')"
while IFS= read -r flow_state; do
  ddb_absent "$FEDERATION_FLOW_TABLE" \
    "$(jq -cn --arg state "$flow_state" '{state:{S:$state}}')"
done < <(jq -r '.flow_states[]' "$RECOVERY_FILE")
wait_for_absence cognito_client_absent
wait_for_absence cognito_user_absent
wait_for_absence secret_absent

rm -f "$ADMIN_HEADER_FILE" "$PASSWORD_FILE" "$ROUNDTRIP_RESULT" "$RECOVERY_FILE"
[[ ! -e "$ADMIN_HEADER_FILE" && ! -e "$PASSWORD_FILE" && ! -e "$RECOVERY_FILE" ]]

jq -n \
  --arg executed_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg stack "$STACK_NAME" \
  --arg deployed_commit "$DEPLOYED_COMMIT" \
  --arg harness_commit "$HEAD_COMMIT" \
  --arg auth_sha "$(sha256sum "$LOCAL_BOOTSTRAP" | cut -d' ' -f1)" '{
    result:"pass",
    executed_at:$executed_at,
    stack:$stack,
    deployed_commit:$deployed_commit,
    harness_commit:$harness_commit,
    deployed_auth_bootstrap_sha256:$auth_sha,
    real_cognito_oidc_roundtrip:true,
    missing_or_untrusted_acr_remained_baseline:true,
    explicit_strong_without_trusted_acr_rejected:true,
    upstream_acr_prompt_and_max_age_forwarded:true,
    prompt_none_no_session_login_required:true,
    prompt_none_no_consent_consent_required:true,
    prompt_login_forced_reauthentication:true,
    max_age_zero_forced_reauthentication:true,
    federation_flow_one_time_state_consumed:true,
    mutable_test_state_removed:true,
    local_credentials_removed_before_evidence:true
  }' >"$EVIDENCE_FILE"

echo "C9.5 federation assurance live gate passed"
echo "evidence=$EVIDENCE_FILE"
echo "evidence_sha256=$(sha256sum "$EVIDENCE_FILE" | cut -d' ' -f1)"
