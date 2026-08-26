#!/usr/bin/env bash
# C3.4 live gate: /token runtime isolation and grace-cache envelope encryption.
set -euo pipefail
set +x

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="${AWS_PROFILE:-default}"
PRIMARY_REGION="${REGION:-us-east-1}"
STANDBY_REGION="${STANDBY_REGION:-us-west-2}"
DEV_STACK="${DEV_STACK:-AgentAuthDev}"
SAAS_STACK="${SAAS_STACK:-AgentAuthSaas}"
STANDBY_STACK="${STANDBY_STACK:-AgentAuthSaasStandby}"
EXPECTED_COMMIT="${EXPECTED_COMMIT:-$(git -C "$ROOT" rev-parse HEAD)}"
EVIDENCE_FILE="${EVIDENCE_FILE:-/tmp/agent-auth-c3-4-$(date -u +%Y%m%dT%H%M%SZ).json}"
CUTOVER_STATE_FILE="${CUTOVER_STATE_FILE:-/var/tmp/agent-auth-c3-4-cutover-$EXPECTED_COMMIT.json}"
LOCAL_ASSET="$ROOT/target/lambda/agent-auth-lambda"
LOCAL_BOOTSTRAP="$LOCAL_ASSET/bootstrap"
LOCAL_PROVENANCE="$LOCAL_ASSET/deployment-provenance.json"

for command in aws base64 cmp curl find git jq openssl python3 seq sha256sum sleep unzip; do
  command -v "$command" >/dev/null || {
    printf 'missing required command: %s\n' "$command" >&2
    exit 1
  }
done
[[ "$EXPECTED_COMMIT" =~ ^[0-9a-f]{40}$ ]] || {
  echo "EXPECTED_COMMIT must be a full lowercase Git SHA" >&2
  exit 1
}
[[ -z "$(git -C "$ROOT" status --porcelain)" ]] || {
  echo "live evidence requires a clean worktree" >&2
  exit 1
}
[[ "$(git -C "$ROOT" rev-parse HEAD)" == "$EXPECTED_COMMIT" ]] || {
  echo "worktree HEAD does not match EXPECTED_COMMIT" >&2
  exit 1
}
[[ -x "$LOCAL_BOOTSTRAP" && -f "$LOCAL_PROVENANCE" ]] || {
  echo "exact-commit Lambda artifact/provenance is missing" >&2
  exit 1
}
LOCAL_BOOTSTRAP_SHA="$(sha256sum "$LOCAL_BOOTSTRAP" | cut -d' ' -f1)"
jq -e --arg commit "$EXPECTED_COMMIT" --arg sha "$LOCAL_BOOTSTRAP_SHA" '
  .schema == "agent-auth-lambda-provenance-v1"
  and .commit == $commit
  and .bootstrap_sha256 == $sha
' "$LOCAL_PROVENANCE" >/dev/null || {
  echo "local Lambda provenance does not bind the exact artifact" >&2
  exit 1
}
[[ -f "$CUTOVER_STATE_FILE" ]] || {
  echo "exact-commit cutover state is missing" >&2
  exit 1
}
jq -e --arg commit "$EXPECTED_COMMIT" '
  .schema == "agent-auth-c3-4-cutover-v1"
  and .target_commit == $commit
  and .status == "prepared"
  and .legacy_keys_disabled == true
  and .active_legacy_ciphertext == 0
  and ([.stacks[].label] | sort) == ["dev","saas","standby"]
' "$CUTOVER_STATE_FILE" >/dev/null || {
  echo "cutover state is not prepared for the exact commit" >&2
  exit 1
}
CUTOVER_STATE_SHA="$(sha256sum "$CUTOVER_STATE_FILE" | cut -d' ' -f1)"

umask 077
WORK="$(mktemp -d)"
RUN_HEX="$(python3 -c 'import secrets; print(secrets.token_hex(8))')"
EMAIL="c3-4-$RUN_HEX@example.com"
# 异常恢复回退；正常路径必须由 create-user 201 响应覆盖。
USER_ID="user:$EMAIL"
REDIRECT="https://c3-4-$RUN_HEX.invalid/callback"
VERIFIER="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
CLIENT_ID=""
FAMILY_ID=""
ADMIN_CONFIG=""
CLIENT_CREATED=0
USER_CREATED=0
CLEANED=0

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  rm -f "$EVIDENCE_FILE"
  exit 1
}

stack_output() {
  local file="$1" key="$2"
  jq -er --arg key "$key" '
    .Stacks[0].Outputs[]
    | select(.OutputKey == $key)
    | .OutputValue
  ' "$file"
}

ddb_get() {
  local table="$1" key_name="$2" key_value="$3" output="$4"
  aws dynamodb get-item \
    --profile "$PROFILE" --region "$PRIMARY_REGION" --table-name "$table" \
    --consistent-read \
    --key "$(jq -cn --arg name "$key_name" --arg value "$key_value" \
      '{($name):{S:$value}}')" --output json >"$output"
}

ddb_absent() {
  local table="$1" key_name="$2" key_value="$3" output="$4"
  ddb_get "$table" "$key_name" "$key_value" "$output" || return 1
  [[ ! -s "$output" ]] && return 0
  jq -e 'has("Item") | not' "$output" >/dev/null
}

recover_client_id() {
  local output="$1"
  aws dynamodb scan \
    --profile "$PROFILE" --region "$PRIMARY_REGION" \
    --table-name "$DEV_CLIENTS_TABLE" --consistent-read \
    --projection-expression 'client_id,redirect_uris' --output json >"$output" ||
    return 1
  jq -er --arg redirect "$REDIRECT" '
    [.Items[]?
     | select(any(.redirect_uris.L[]?; .S == $redirect))
     | .client_id.S]
    | if length == 0 then "__absent__"
      elif length == 1 then .[0]
      else error("multiple clients matched the unique redirect")
      end
  ' "$output"
}

admin_request() {
  local method="$1" path="$2" body="${3:-}" output="$4"
  local args=(--silent --show-error --output "$output" --write-out '%{http_code}'
    --request "$method" --config "$ADMIN_CONFIG" "$DEV_ORIGIN$path")
  if [[ -n "$body" ]]; then
    args+=(--header 'content-type: application/json' --data-binary "@$body")
  fi
  curl "${args[@]}"
}

urlencode() {
  python3 -c \
    'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' \
    "$1"
}

remove_local_recovery_material() {
  find "$WORK" -mindepth 1 -type f -exec rm -f -- {} +
  find "$WORK" -mindepth 1 -depth -type d -empty -delete
}

verify_cleanup() {
  local failed=0 recovered_client_id round_failed stable_absence_started_at=-1 status
  set +e
  for _ in $(seq 1 45); do
    round_failed=0
    if [[ "$CLIENT_CREATED" == "1" && -f "$ADMIN_CONFIG" ]]; then
      if [[ -z "$CLIENT_ID" ]]; then
        if recovered_client_id="$(
          recover_client_id "$WORK/client-recovery-scan.json"
        )"; then
          if [[ "$recovered_client_id" != "__absent__" ]]; then
            CLIENT_ID="$recovered_client_id"
          fi
        else
          failed=1
          break
        fi
      fi
      if [[ -n "$CLIENT_ID" ]]; then
        if status="$(admin_request DELETE "/admin/clients/$CLIENT_ID" "" \
          "$WORK/client-delete.json")"; then
          [[ "$status" == "200" || "$status" == "404" ]] || round_failed=1
        else
          round_failed=1
        fi
        ddb_absent "$DEV_CLIENTS_TABLE" client_id "$CLIENT_ID" \
          "$WORK/client-absent.json" || round_failed=1
      fi
    fi
    if [[ "$USER_CREATED" == "1" && -f "$ADMIN_CONFIG" ]]; then
      local user_path
      user_path="$(urlencode "$USER_ID")"
      if status="$(admin_request DELETE "/admin/users/$user_path" "" \
        "$WORK/user-delete.json")"; then
        [[ "$status" == "200" || "$status" == "404" ]] || round_failed=1
      else
        round_failed=1
      fi
      if status="$(admin_request GET "/admin/users/$user_path" "" \
        "$WORK/user-after-delete.json")"; then
        if [[ "$status" == "200" ]]; then
          jq -e '
            .status == "tombstoned"
            and .active_grants == 0
            and .sessions == 0
            and .passkeys == 0
            and .password_status == "not_configured"
            and .has_recovery == false
          ' "$WORK/user-after-delete.json" >/dev/null || round_failed=1
        else
          round_failed=1
        fi
      else
        round_failed=1
      fi
    fi
    if [[ -n "$FAMILY_ID" ]]; then
      aws dynamodb query \
        --profile "$PROFILE" --region "$PRIMARY_REGION" \
        --table-name "$DEV_GRACE_TABLE" --consistent-read \
        --key-condition-expression 'family_id = :family' \
        --expression-attribute-values \
          "$(jq -cn --arg family "$FAMILY_ID" '{":family":{S:$family}}')" \
        --select COUNT --output json >"$WORK/grace-after-cleanup.json" ||
        round_failed=1
      jq -e '.Count == 0' "$WORK/grace-after-cleanup.json" >/dev/null ||
        round_failed=1
    fi
    if [[ -n "$CLIENT_ID" ]]; then
      aws dynamodb scan \
        --profile "$PROFILE" --region "$PRIMARY_REGION" \
        --table-name "$DEV_GRANTS_TABLE" --consistent-read \
        --projection-expression 'grant_json' --output json \
        >"$WORK/grants-after-cleanup.json" || round_failed=1
      jq -e --arg client "$CLIENT_ID" '
        [.Items[]?
         | .grant_json.S
         | fromjson
         | select(.client_id == $client)] | length == 0
      ' "$WORK/grants-after-cleanup.json" >/dev/null || round_failed=1
      aws dynamodb scan \
        --profile "$PROFILE" --region "$PRIMARY_REGION" \
        --table-name "$DEV_REFRESH_TABLE" --consistent-read \
        --projection-expression 'client_id,revoked' --output json \
        >"$WORK/refresh-after-cleanup.json" || round_failed=1
      jq -e --arg client "$CLIENT_ID" '
        [.Items[]?
         | select(.client_id.S == $client)
         | select((.revoked.BOOL // false) == false)] | length == 0
      ' "$WORK/refresh-after-cleanup.json" >/dev/null || round_failed=1
    fi
    if [[ "$round_failed" == "0" ]]; then
      if ((stable_absence_started_at < 0)); then
        local now
        now="$SECONDS"
        stable_absence_started_at="$now"
      elif ((SECONDS - stable_absence_started_at >= 15)); then
        CLEANED=1
        break
      fi
    else
      stable_absence_started_at=-1
    fi
    sleep 1
  done
  rm -f "$WORK"/*.token "$WORK"/*.password "$WORK"/*.curl \
    "$WORK"/*.cookies "$WORK"/*token*.json
  if [[ "$CLEANED" != "1" ]]; then
    failed=1
    rm -f "$EVIDENCE_FILE"
    printf 'cleanup did not converge; recovery directory: %s\n' "$WORK" >&2
  fi
  set -e
  [[ "$failed" == "0" ]]
}

on_exit() {
  local status=$?
  if [[ "$CLEANED" != "1" ]]; then
    verify_cleanup || status=1
  fi
  if [[ "$status" != "0" ]]; then
    rm -f "$EVIDENCE_FILE"
  else
    remove_local_recovery_material
    rmdir "$WORK"
  fi
  return "$status"
}
trap 'exit 130' INT
trap 'exit 143' TERM
trap on_exit EXIT

describe_stack() {
  local stack="$1" region="$2" output="$3"
  aws cloudformation describe-stacks \
    --profile "$PROFILE" --region "$region" --stack-name "$stack" \
    --output json >"$output"
  jq -e --arg commit "$EXPECTED_COMMIT" '
    .Stacks[0].StackStatus == "UPDATE_COMPLETE"
    and any(.Stacks[0].Outputs[];
      .OutputKey == "DeploymentCommit" and .OutputValue == $commit)
  ' "$output" >/dev/null ||
    fail "$stack is not UPDATE_COMPLETE at the exact commit"
}

validate_runtime() {
  local stack_file="$1" region="$2" label="$3" output_key="$4" scope="$5"
  local function_name function_json code_zip unpacked code_sha
  function_name="$(stack_output "$stack_file" "$output_key")"
  function_json="$WORK/$label-function.json"
  code_zip="$WORK/$label-function.zip"
  unpacked="$WORK/$label-unpacked"
  aws lambda get-function \
    --profile "$PROFILE" --region "$region" --function-name "$function_name" \
    --output json >"$function_json"
  jq -e --arg commit "$EXPECTED_COMMIT" --arg scope "$scope" '
    .Configuration.State == "Active"
    and .Configuration.LastUpdateStatus == "Successful"
    and .Configuration.Environment.Variables.AGENT_AUTH_DEPLOYMENT_COMMIT == $commit
    and .Configuration.Environment.Variables.SCOPE == $scope
    and (.Configuration.Environment.Variables.CIBA_KMS | startswith("alias/c-"))
    and (if $scope == "token"
         then (.Configuration.Environment.Variables.GRACE_KMS_KEY_ID | length > 0)
         else (.Configuration.Environment.Variables | has("GRACE_KMS_KEY_ID") | not)
         end)
  ' "$function_json" >/dev/null ||
    fail "$label runtime environment does not enforce the reviewed scope"
  curl -fsS --proto '=https' --connect-timeout 10 --max-time 120 \
    "$(jq -er '.Code.Location' "$function_json")" -o "$code_zip"
  code_sha="$(openssl dgst -sha256 -binary "$code_zip" | base64 | tr -d '\n')"
  [[ "$code_sha" == "$(jq -er '.Configuration.CodeSha256' "$function_json")" ]] ||
    fail "$label downloaded package does not match AWS CodeSha256"
  mkdir "$unpacked"
  unzip -q "$code_zip" -d "$unpacked"
  cmp "$unpacked/bootstrap" "$LOCAL_BOOTSTRAP" ||
    fail "$label deployed bootstrap differs from the exact local artifact"
  jq -e --arg commit "$EXPECTED_COMMIT" --arg sha "$LOCAL_BOOTSTRAP_SHA" '
    .schema == "agent-auth-lambda-provenance-v1"
    and .commit == $commit
    and .bootstrap_sha256 == $sha
  ' "$unpacked/deployment-provenance.json" >/dev/null ||
    fail "$label deployed provenance does not bind the exact artifact"
}

simulate_key_access() {
  local function_json="$1" key_arn="$2" expected="$3" output="$4"
  aws iam simulate-principal-policy \
    --profile "$PROFILE" \
    --policy-source-arn "$(jq -er '.Configuration.Role' "$function_json")" \
    --action-names kms:Decrypt kms:GenerateDataKey \
    --resource-arns "$key_arn" --output json >"$output"
  if [[ "$expected" == "allowed" ]]; then
    jq -e '
      (.EvaluationResults | length) == 2
      and all(.EvaluationResults[]; .EvalDecision == "allowed")
    ' "$output" >/dev/null
  else
    jq -e '
      (.EvaluationResults | length) == 2
      and all(.EvaluationResults[]; .EvalDecision != "allowed")
    ' "$output" >/dev/null
  fi
}

describe_stack "$DEV_STACK" "$PRIMARY_REGION" "$WORK/dev-stack.json"
describe_stack "$SAAS_STACK" "$PRIMARY_REGION" "$WORK/saas-stack.json"
describe_stack "$STANDBY_STACK" "$STANDBY_REGION" "$WORK/standby-stack.json"

for tuple in \
  "dev:$WORK/dev-stack.json:$PRIMARY_REGION" \
  "saas:$WORK/saas-stack.json:$PRIMARY_REGION" \
  "standby:$WORK/standby-stack.json:$STANDBY_REGION"; do
  IFS=: read -r label stack_file region <<<"$tuple"
  validate_runtime "$stack_file" "$region" "$label-auth" AuthFnName non_token
  validate_runtime "$stack_file" "$region" "$label-token" TokenFnName token
  grace_key_arn="$(aws kms describe-key \
    --profile "$PROFILE" --region "$region" \
    --key-id "$(stack_output "$stack_file" GraceEnvelopeKeyId)" \
    --query 'KeyMetadata.Arn' --output text)"
  legacy_grace_key_id="$(stack_output "$stack_file" LegacyGraceEnvelopeKeyId)"
  [[ "$legacy_grace_key_id" == "$(jq -er --arg label "$label" \
    '.stacks[] | select(.label == $label) | .legacy_key_id' \
    "$CUTOVER_STATE_FILE")" ]] ||
    fail "$label legacy grace key does not match the prepared cutover"
  legacy_grace_key_arn="$(aws kms describe-key \
    --profile "$PROFILE" --region "$region" --key-id "$legacy_grace_key_id" \
    --query 'KeyMetadata.Arn' --output text)"
  [[ "$(aws kms describe-key \
    --profile "$PROFILE" --region "$region" --key-id "$legacy_grace_key_id" \
    --query 'KeyMetadata.KeyState' --output text)" == "Disabled" ]] ||
    fail "$label legacy grace key is not disabled"
  ciba_key_arn="$(aws kms describe-key \
    --profile "$PROFILE" --region "$region" \
    --key-id "$(stack_output "$stack_file" CibaNotificationEnvelopeKeyId)" \
    --query 'KeyMetadata.Arn' --output text)"
  [[ "$legacy_grace_key_arn" != "$grace_key_arn" ]] ||
    fail "$label legacy and token grace keys are not distinct"
  [[ "$grace_key_arn" != "$ciba_key_arn" ]] ||
    fail "$label grace and CIBA keys are not distinct"
  simulate_key_access "$WORK/$label-auth-function.json" "$legacy_grace_key_arn" denied \
    "$WORK/$label-auth-legacy-grace-simulation.json" ||
    fail "$label Auth role can use the legacy grace key"
  simulate_key_access "$WORK/$label-token-function.json" "$legacy_grace_key_arn" denied \
    "$WORK/$label-token-legacy-grace-simulation.json" ||
    fail "$label Token role can use the legacy grace key"
  simulate_key_access "$WORK/$label-auth-function.json" "$grace_key_arn" denied \
    "$WORK/$label-auth-grace-simulation.json" ||
    fail "$label Auth role can use the grace key"
  simulate_key_access "$WORK/$label-token-function.json" "$grace_key_arn" allowed \
    "$WORK/$label-token-grace-simulation.json" ||
    fail "$label Token role cannot use the grace key"
  simulate_key_access "$WORK/$label-auth-function.json" "$ciba_key_arn" allowed \
    "$WORK/$label-auth-ciba-simulation.json" ||
    fail "$label Auth role cannot use the CIBA key"
  simulate_key_access "$WORK/$label-token-function.json" "$ciba_key_arn" allowed \
    "$WORK/$label-token-ciba-simulation.json" ||
    fail "$label Token role cannot use the CIBA key"
done

DEV_ORIGIN="$(stack_output "$WORK/dev-stack.json" AdminUrl)"
DEV_ORIGIN="${DEV_ORIGIN%/admin}"
DEV_HOST="$(python3 -c 'import sys,urllib.parse; print(urllib.parse.urlparse(sys.argv[1]).hostname)' \
  "$DEV_ORIGIN")"
DEV_CLIENTS_TABLE="$(stack_output "$WORK/dev-stack.json" ClientsTableName)"
DEV_REFRESH_TABLE="$(stack_output "$WORK/dev-stack.json" RefreshTableName)"
DEV_GRACE_TABLE="$(stack_output "$WORK/dev-stack.json" GraceTableName)"
DEV_GRANTS_TABLE="$(stack_output "$WORK/dev-stack.json" GrantsTableName)"

lambda_event() {
  local method="$1" path="$2" body="$3" output="$4"
  jq -n --arg method "$method" --arg path "$path" --arg body "$body" \
    --arg host "$DEV_HOST" '{
      version:"2.0",routeKey:"$default",rawPath:$path,rawQueryString:"",
      headers:{"content-type":"application/x-www-form-urlencoded",host:$host},
      requestContext:{
        accountId:"000000000000",apiId:"c34",domainName:$host,
        domainPrefix:"c34",
        http:{method:$method,path:$path,protocol:"HTTP/1.1",
          sourceIp:"127.0.0.1",userAgent:"c3.4-live"},
        requestId:"c3-4",routeKey:"$default",stage:"$default",
        time:"08/Aug/2026:00:00:00 +0000",timeEpoch:0
      },
      body:$body,isBase64Encoded:false
    }' >"$output"
}

invoke_and_status() {
  local function_name="$1" event="$2" response="$3" metadata="$4"
  aws lambda invoke \
    --profile "$PROFILE" --region "$PRIMARY_REGION" \
    --function-name "$function_name" \
    --cli-binary-format raw-in-base64-out --payload "fileb://$event" \
    "$response" --output json >"$metadata"
  jq -e 'has("FunctionError") | not' "$metadata" >/dev/null ||
    fail "direct Lambda invocation returned FunctionError"
  jq -er '.statusCode' "$response"
}

DEV_AUTH_FN="$(stack_output "$WORK/dev-stack.json" AuthFnName)"
DEV_TOKEN_FN="$(stack_output "$WORK/dev-stack.json" TokenFnName)"
lambda_event GET '/.well-known/openid-configuration' '' "$WORK/discovery-event.json"
[[ "$(invoke_and_status "$DEV_TOKEN_FN" "$WORK/discovery-event.json" \
  "$WORK/token-discovery-response.json" "$WORK/token-discovery-meta.json")" == "404" ]] ||
  fail "TokenFn exposed discovery"
lambda_event POST '/token' 'grant_type=invalid' "$WORK/token-event.json"
[[ "$(invoke_and_status "$DEV_AUTH_FN" "$WORK/token-event.json" \
  "$WORK/auth-token-response.json" "$WORK/auth-token-meta.json")" == "404" ]] ||
  fail "AuthFn exposed /token"
[[ "$(invoke_and_status "$DEV_TOKEN_FN" "$WORK/token-event.json" \
  "$WORK/token-response.json" "$WORK/token-meta.json")" == "400" ]] ||
  fail "TokenFn did not handle /token"

STACK="$DEV_STACK" REGION="$PRIMARY_REGION" PROFILE="$PROFILE" \
  "$ROOT/e2e/get-admin-token.sh" \
  >"$WORK/admin.token"
chmod 0600 "$WORK/admin.token"
printf 'header = "authorization: Bearer %s"\n' "$(cat "$WORK/admin.token")" \
  >"$WORK/admin.curl"
chmod 0600 "$WORK/admin.curl"
ADMIN_CONFIG="$WORK/admin.curl"

INITIAL="$(python3 -c 'import secrets; print("Init-" + secrets.token_urlsafe(24))')"
PERMANENT="$(python3 -c 'import secrets; print("Active-" + secrets.token_urlsafe(24))')"
printf '%s' "$INITIAL" >"$WORK/initial.password"
printf '%s' "$PERMANENT" >"$WORK/permanent.password"
python3 - "$EMAIL" "$WORK/initial.password" >"$WORK/create-user.json" <<'PY'
import json
import pathlib
import sys
print(json.dumps({
    "email": sys.argv[1],
    "initial_password": pathlib.Path(sys.argv[2]).read_text(),
}))
PY
USER_CREATED=1
[[ "$(admin_request POST /admin/users "$WORK/create-user.json" \
  "$WORK/create-user-response.json")" == "201" ]] ||
  fail "temporary user creation failed"
USER_ID="$(jq -er '.user_id | select(type == "string" and length > 0)' \
  "$WORK/create-user-response.json")"
python3 - "$EMAIL" "$WORK/initial.password" "$WORK/permanent.password" \
  >"$WORK/change-password.json" <<'PY'
import json
import pathlib
import sys
print(json.dumps({
    "email": sys.argv[1],
    "current_password": pathlib.Path(sys.argv[2]).read_text(),
    "new_password": pathlib.Path(sys.argv[3]).read_text(),
}))
PY
[[ "$(curl --silent --show-error --output "$WORK/change-password-response.json" \
  --write-out '%{http_code}' --cookie-jar "$WORK/session.cookies" \
  --request POST --header 'content-type: application/json' \
  --data-binary "@$WORK/change-password.json" \
  "$DEV_ORIGIN/login/password/change")" == "200" ]] ||
  fail "temporary user activation failed"

jq -n --arg redirect "$REDIRECT" '{
  redirect_uris:[$redirect],
  application_type:"web",
  token_endpoint_auth_method:"none"
}' >"$WORK/create-client.json"
CLIENT_CREATED=1
[[ "$(admin_request POST /admin/clients "$WORK/create-client.json" \
  "$WORK/create-client-response.json")" == "201" ]] ||
  fail "temporary client creation failed"
CLIENT_ID="$(jq -er '.client_id' "$WORK/create-client-response.json")"

CHALLENGE="$(python3 -c \
  'import base64,hashlib,sys; print(base64.urlsafe_b64encode(hashlib.sha256(sys.argv[1].encode()).digest()).rstrip(b"=").decode())' \
  "$VERIFIER")"
AQ="$(python3 -c \
  'import urllib.parse,sys; print(urllib.parse.urlencode({
    "client_id":sys.argv[1],"redirect_uri":sys.argv[2],"scope":"openid",
    "state":"c34","code_challenge":sys.argv[3],
    "code_challenge_method":"S256"}))' "$CLIENT_ID" "$REDIRECT" "$CHALLENGE")"
AUTHZ_STATUS="$(curl --silent --show-error --output /dev/null \
  --dump-header "$WORK/authorize.headers" --write-out '%{http_code}' \
  --cookie "$WORK/session.cookies" \
  "$DEV_ORIGIN/authorize?response_type=code&$AQ")"
[[ "$AUTHZ_STATUS" == "303" ]] ||
  fail "authorization request did not enter the consent flow"
AUTHZ_LOCATION="$(awk '
  BEGIN { IGNORECASE=1 }
  /^location:/ {
    sub(/\r$/, "")
    sub(/^[^:]+:[[:space:]]*/, "")
    print
  }
' "$WORK/authorize.headers" | tail -1)"
CONSENT_QUERY="$(python3 - "$DEV_ORIGIN" "$AUTHZ_LOCATION" "$CLIENT_ID" <<'PY'
import sys
import urllib.parse

origin = urllib.parse.urlparse(sys.argv[1])
location = urllib.parse.urlparse(sys.argv[2])
params = urllib.parse.parse_qs(location.query, keep_blank_values=True)
assert (location.scheme, location.netloc) == (origin.scheme, origin.netloc)
assert location.path == "/consent"
assert params.get("client_id") == [sys.argv[3]]
assert len(params.get("authz_session_id", [])) == 1
assert params["authz_session_id"][0]
print(location.query)
PY
)" || fail "authorization redirect did not bind the consent session"
CSRF="$(curl --silent --show-error --cookie "$WORK/session.cookies" \
  "$DEV_ORIGIN/consent/context?$CONSENT_QUERY" | jq -er '.csrf_token')"
jq -n --arg csrf "$CSRF" --arg query "$CONSENT_QUERY" \
  '{decision:"approve",csrf:$csrf,authorize_query:$query}' \
  >"$WORK/consent.json"
curl --silent --show-error --cookie "$WORK/session.cookies" \
  --request POST --header 'content-type: application/json' \
  --data-binary "@$WORK/consent.json" "$DEV_ORIGIN/consent/decision" \
  >"$WORK/consent-response.json"
AUTH_CODE="$(python3 - "$WORK/consent-response.json" <<'PY'
import json
import pathlib
import sys
import urllib.parse
body = json.loads(pathlib.Path(sys.argv[1]).read_text())
print(urllib.parse.parse_qs(
    urllib.parse.urlparse(body["redirect"]).query)["code"][0])
PY
)"
python3 - "$AUTH_CODE" "$VERIFIER" "$REDIRECT" "$CLIENT_ID" \
  >"$WORK/code-token.form" <<'PY'
import sys
import urllib.parse
print(urllib.parse.urlencode({
    "grant_type":"authorization_code","code":sys.argv[1],
    "code_verifier":sys.argv[2],"redirect_uri":sys.argv[3],
    "client_id":sys.argv[4],
}), end="")
PY
[[ "$(curl --silent --show-error --output "$WORK/code-token.json" \
  --write-out '%{http_code}' --request POST \
  --header 'content-type: application/x-www-form-urlencoded' \
  --data-binary "@$WORK/code-token.form" "$DEV_ORIGIN/token")" == "200" ]] ||
  fail "authorization-code exchange failed"
jq -j '.refresh_token' "$WORK/code-token.json" >"$WORK/r0.token"
[[ -s "$WORK/r0.token" ]] || fail "authorization-code exchange returned no refresh token"

make_refresh_form() {
  local token_file="$1" output="$2"
  python3 - "$token_file" "$CLIENT_ID" >"$output" <<'PY'
import pathlib
import sys
import urllib.parse
print(urllib.parse.urlencode({
    "grant_type":"refresh_token",
    "refresh_token":pathlib.Path(sys.argv[1]).read_text(),
    "client_id":sys.argv[2],
}), end="")
PY
}
make_refresh_form "$WORK/r0.token" "$WORK/r0.form"
[[ "$(curl --silent --show-error --output "$WORK/r1.json" \
  --write-out '%{http_code}' --request POST \
  --header 'content-type: application/x-www-form-urlencoded' \
  --data-binary "@$WORK/r0.form" "$DEV_ORIGIN/token")" == "200" ]] ||
  fail "first refresh rotation failed"
jq -j '.refresh_token' "$WORK/r1.json" >"$WORK/r1.token"
[[ -s "$WORK/r1.token" ]] || fail "first refresh rotation returned no refresh token"

[[ "$(curl --silent --show-error --output "$WORK/replay.json" \
  --write-out '%{http_code}' --request POST \
  --header 'content-type: application/x-www-form-urlencoded' \
  --data-binary "@$WORK/r0.form" "$DEV_ORIGIN/token")" == "200" ]] ||
  fail "grace replay did not return 200"
jq -S '{access_token,refresh_token,id_token,scope,expires_in}' "$WORK/r1.json" \
  >"$WORK/r1-projection.json"
jq -S '{access_token,refresh_token,id_token,scope,expires_in}' "$WORK/replay.json" \
  >"$WORK/replay-projection.json"
cmp "$WORK/r1-projection.json" "$WORK/replay-projection.json" ||
  fail "grace replay did not return the exact cached token response"

FAMILY_ID="$(python3 - "$WORK/r0.token" <<'PY'
import pathlib
import sys
token = pathlib.Path(sys.argv[1]).read_text()
print(token.rsplit(".", 1)[0])
PY
)"
aws dynamodb query \
  --profile "$PROFILE" --region "$PRIMARY_REGION" \
  --table-name "$DEV_GRACE_TABLE" --consistent-read \
  --key-condition-expression 'family_id = :family' \
  --expression-attribute-values \
    "$(jq -cn --arg family "$FAMILY_ID" '{":family":{S:$family}}')" \
  --output json >"$WORK/grace-items.json"
jq -e '
  (.Items | length) >= 1
  and all(.Items[];
    ((keys - [
      "family_id", "version", "fingerprint", "client_id", "enc_dk",
      "nonce", "ciphertext", "expires_at", "dpop_jkt"
    ]) | length == 0)
    and (.family_id.S | type == "string" and length > 0)
    and (.version.N | tonumber >= 0)
    and (.fingerprint.B | type == "string" and length > 0)
    and (.client_id.S | type == "string" and length > 0)
    and (.enc_dk.B | type == "string" and length > 0)
    and (.nonce.B | type == "string" and length > 0)
    and (.ciphertext.B | type == "string" and length > 0)
    and (.expires_at.N | tonumber > 0)
    and has("ciphertext") and has("enc_dk") and has("nonce")
  )
' "$WORK/grace-items.json" >/dev/null ||
  fail "GraceTable did not contain ciphertext-only cache entries"

make_refresh_form "$WORK/r1.token" "$WORK/r1.form"
[[ "$(curl --silent --show-error --output "$WORK/r2.json" \
  --write-out '%{http_code}' --request POST \
  --header 'content-type: application/x-www-form-urlencoded' \
  --data-binary "@$WORK/r1.form" "$DEV_ORIGIN/token")" == "200" ]] ||
  fail "current refresh token was invalidated by the grace replay"

verify_cleanup || fail "temporary authority did not cleanly converge"
rm -f "$WORK"/*.json "$WORK"/*.form "$WORK"/*.zip

jq -n --arg commit "$EXPECTED_COMMIT" \
  --arg completed_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg local_sha "$LOCAL_BOOTSTRAP_SHA" \
  --arg cutover_sha "$CUTOVER_STATE_SHA" '{
    schema:"agent-auth-c3-4-evidence-v1",
    deployment_commit:$commit,
    completed_at:$completed_at,
    artifact_sha256:$local_sha,
    cutover_state_sha256:$cutover_sha,
    assertions:{
      rollback_legacy_keys_disabled:"pass",
      primary_and_standby_runtime_scopes:"pass",
      auth_roles_denied_grace_kms:"pass",
      token_roles_allowed_grace_kms:"pass",
      ciba_uses_distinct_cmk:"pass",
      direct_lambda_route_isolation:"pass",
      exact_grace_replay:"pass",
      grace_table_ciphertext_only:"pass",
      current_refresh_remains_usable:"pass",
      temporary_authority_cleanup:"pass"
    },
    sensitive_values_in_evidence:false
  }' >"$EVIDENCE_FILE"
chmod 0600 "$EVIDENCE_FILE"
jq -e '
  .schema == "agent-auth-c3-4-evidence-v1"
  and (.assertions | to_entries | all(.value == "pass"))
  and .sensitive_values_in_evidence == false
' "$EVIDENCE_FILE" >/dev/null || fail "final evidence validation failed"
CLEANED=1
printf 'C3.4 evidence: %s\n' "$EVIDENCE_FILE"
printf 'C3.4 evidence sha256: %s\n' \
  "$(sha256sum "$EVIDENCE_FILE" | cut -d' ' -f1)"
