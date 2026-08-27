#!/usr/bin/env bash
# Live SCIM Users acceptance for issue #1.
#
# Required:
#   BASE_URL=https://tenant.example.com
#   SCIM_SECRET_ARN=arn:aws:secretsmanager:...  (or SCIM_TOKEN_FILE=/secure/path)
#
# Optional tenant-isolation matrix:
#   OTHER_BASE_URL=https://other-tenant.example.com
#   OTHER_SCIM_SECRET_ARN=arn:...                (or OTHER_SCIM_TOKEN_FILE=...)
#
# Optional Admin/SCIM credential-domain checks:
#   ADMIN_SECRET_ARN=arn:...                     (or ADMIN_TOKEN_FILE=...)
#
# Optional deployed Dynamo lifecycle acceptance:
#   STACK_NAME=AgentAuthDev STORAGE_TENANT=
#   STACK_NAME=AgentAuthSaas STORAGE_TENANT=t1
#
# The script creates uniquely named e2e users because the supported SCIM profile
# intentionally has no DELETE operation. Deep lifecycle mode writes and cleans
# synthetic session/refresh/Grant items; it never mutates AWS resources or Secrets.
set -euo pipefail
set +x

PROFILE="${PROFILE:-${AWS_PROFILE:-default}}"
REGION="${REGION:-${AWS_REGION:-us-east-1}}"
BASE_URL="${BASE_URL:?BASE_URL is required}"
BASE_URL="${BASE_URL%/}"
OTHER_BASE_URL="${OTHER_BASE_URL:-}"
OTHER_BASE_URL="${OTHER_BASE_URL%/}"
RUN_ID="${SCIM_RUN_ID:-$(date -u +%Y%m%d%H%M%S)-$RANDOM}"
STACK_NAME="${STACK_NAME:-}"
STORAGE_TENANT="${STORAGE_TENANT:-}"

USER_SCHEMA='urn:ietf:params:scim:schemas:core:2.0:User'
PATCH_SCHEMA='urn:ietf:params:scim:api:messages:2.0:PatchOp'
LIST_SCHEMA='urn:ietf:params:scim:api:messages:2.0:ListResponse'
CONFIG_SCHEMA='urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'
ERROR_SCHEMA='urn:ietf:params:scim:api:messages:2.0:Error'

umask 077
WORK="$(mktemp -d)"
USERS_TABLE=""
SESSIONS_TABLE=""
REFRESH_TABLE=""
GRANTS_TABLE=""
LIFECYCLE_SESSION_KEY=""
LIFECYCLE_FAMILY_KEY=""
LIFECYCLE_GRANT_KEY=""
cleanup() {
  set +e
  if [[ -n "$SESSIONS_TABLE" && -n "$LIFECYCLE_SESSION_KEY" ]]; then
    aws dynamodb delete-item --profile "$PROFILE" --region "$REGION" \
      --table-name "$SESSIONS_TABLE" \
      --key "$(jq -cn --arg value "$LIFECYCLE_SESSION_KEY" '{session_id:{S:$value}}')" \
      >/dev/null 2>&1
  fi
  if [[ -n "$REFRESH_TABLE" && -n "$LIFECYCLE_FAMILY_KEY" ]]; then
    aws dynamodb delete-item --profile "$PROFILE" --region "$REGION" \
      --table-name "$REFRESH_TABLE" \
      --key "$(jq -cn --arg value "$LIFECYCLE_FAMILY_KEY" '{family_id:{S:$value}}')" \
      >/dev/null 2>&1
  fi
  if [[ -n "$GRANTS_TABLE" && -n "$LIFECYCLE_GRANT_KEY" ]]; then
    aws dynamodb delete-item --profile "$PROFILE" --region "$REGION" \
      --table-name "$GRANTS_TABLE" \
      --key "$(jq -cn --arg value "$LIFECYCLE_GRANT_KEY" '{grant_id:{S:$value}}')" \
      >/dev/null 2>&1
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
require() { command -v "$1" >/dev/null || fail "missing command: $1"; }

stack_output() {
  local key="$1"
  aws cloudformation describe-stacks \
    --profile "$PROFILE" --region "$REGION" --stack-name "$STACK_NAME" \
    --query "Stacks[0].Outputs[?OutputKey=='$key'].OutputValue | [0]" \
    --output text
}

physical_key() {
  local logical="$1"
  if [[ -n "$STORAGE_TENANT" ]]; then
    printf '%s\x1f%s' "$STORAGE_TENANT" "$logical"
  else
    printf '%s' "$logical"
  fi
}

for command in curl jq; do
  require "$command"
done
[[ "$BASE_URL" == https://* ]] || fail "BASE_URL must be HTTPS"
if [[ -n "$OTHER_BASE_URL" ]]; then
  [[ "$OTHER_BASE_URL" == https://* ]] || fail "OTHER_BASE_URL must be HTTPS"
  [[ "$OTHER_BASE_URL" != "$BASE_URL" ]] || fail "tenant base URLs must differ"
fi

load_token() {
  local owner="$1" token_file="$2" secret_arn="$3"
  local output="$WORK/$owner.token"
  if [[ -n "$token_file" ]]; then
    [[ -r "$token_file" ]] || fail "$owner token file is not readable"
    cp "$token_file" "$output"
  else
    [[ -n "$secret_arn" ]] || fail "$owner token file or Secret ARN is required"
    require aws
    aws secretsmanager get-secret-value \
      --secret-id "$secret_arn" --profile "$PROFILE" --region "$REGION" \
      --query SecretString --output text |
      jq -er '
        .current.secret
        | select(type == "string" and length >= 16)
      ' >"$output"
  fi
  [[ -s "$output" ]] || fail "$owner token is empty"
  chmod 0600 "$output"
  printf '%s\n' "$output"
}

PRIMARY_TOKEN="$(load_token primary "${SCIM_TOKEN_FILE:-}" "${SCIM_SECRET_ARN:-}")"
OTHER_TOKEN=""
if [[ -n "$OTHER_BASE_URL" ]]; then
  OTHER_TOKEN="$(
    load_token other "${OTHER_SCIM_TOKEN_FILE:-}" "${OTHER_SCIM_SECRET_ARN:-}"
  )"
fi
ADMIN_TOKEN=""
if [[ -n "${ADMIN_TOKEN_FILE:-}" || -n "${ADMIN_SECRET_ARN:-}" ]]; then
  ADMIN_TOKEN="$(load_token admin "${ADMIN_TOKEN_FILE:-}" "${ADMIN_SECRET_ARN:-}")"
fi
if [[ -n "$STACK_NAME" ]]; then
  require aws
  USERS_TABLE="$(stack_output UsersTableName)"
  SESSIONS_TABLE="$(stack_output SessionsTableName)"
  REFRESH_TABLE="$(stack_output RefreshTableName)"
  GRANTS_TABLE="$(stack_output GrantsTableName)"
  for value in "$USERS_TABLE" "$SESSIONS_TABLE" "$REFRESH_TABLE" "$GRANTS_TABLE"; do
    [[ -n "$value" && "$value" != "None" ]] ||
      fail "STACK_NAME is missing a required lifecycle table output"
  done
fi

request() {
  local name="$1" method="$2" url="$3" token_file="${4:-}" body_file="${5:-}"
  local headers="$WORK/$name.request-headers"
  local response_headers="$WORK/$name.headers"
  local response_body="$WORK/$name.json"
  local -a curl_args=(
    -sS --proto '=https' --connect-timeout 5 --max-time 30
    -X "$method" -H "@$headers" -D "$response_headers" -o "$response_body"
  )
  : >"$headers"
  if [[ -n "$token_file" ]]; then
    printf 'authorization: Bearer %s\n' "$(<"$token_file")" >>"$headers"
  fi
  if [[ -n "$body_file" ]]; then
    printf 'content-type: application/scim+json\n' >>"$headers"
    curl_args+=(--data-binary "@$body_file")
  fi
  curl_args+=(-w '%{http_code}' "$url")
  curl "${curl_args[@]}" >"$WORK/$name.status"
}

assert_status() {
  local name="$1" expected="$2"
  local actual
  actual="$(<"$WORK/$name.status")"
  [[ "$actual" == "$expected" ]] ||
    fail "$name expected HTTP $expected, got $actual: $(<"$WORK/$name.json")"
}

assert_status_one_of() {
  local name="$1" first="$2" second="$3"
  local actual
  actual="$(<"$WORK/$name.status")"
  [[ "$actual" == "$first" || "$actual" == "$second" ]] ||
    fail "$name expected HTTP $first or $second, got $actual: $(<"$WORK/$name.json")"
}

assert_scim_media_type() {
  local name="$1" content_type
  content_type="$(
    tr -d '\r' <"$WORK/$name.headers" |
      awk 'tolower($1) == "content-type:" { value=tolower($2) } END { print value }'
  )"
  [[ "$content_type" == application/scim+json* ]] ||
    fail "$name returned non-SCIM content type: ${content_type:-missing}"
  jq -e . "$WORK/$name.json" >/dev/null || fail "$name returned invalid JSON"
}

dynamodb_get_item() {
  local table="$1" key="$2" output
  output="$(
    aws dynamodb get-item --profile "$PROFILE" --region "$REGION" \
      --table-name "$table" --key "$key" --consistent-read --output json
  )"
  if [[ -n "$output" ]]; then
    printf '%s\n' "$output"
  else
    printf '{}\n'
  fi
}

wait_for_user_index_item() {
  local table="$1" id_attribute="$2" id_value="$3" user_key="$4"
  local values result
  values="$(jq -cn --arg user "$user_key" '{":user":{S:$user}}')"
  for _ in $(seq 1 30); do
    result="$(
      aws dynamodb query --profile "$PROFILE" --region "$REGION" \
        --table-name "$table" --index-name user_id-index \
        --key-condition-expression '#user = :user' \
        --expression-attribute-names '{"#user":"user_id"}' \
        --expression-attribute-values "$values" --output json
    )"
    if jq -e --arg attr "$id_attribute" --arg value "$id_value" \
      'any(.Items[]; .[$attr].S == $value)' <<<"$result" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  fail "$table user_id-index did not expose $id_value"
}

wait_for_gsi_active() {
  local table="$1" index="$2" status
  for _ in $(seq 1 180); do
    status="$(
      aws dynamodb describe-table --profile "$PROFILE" --region "$REGION" \
        --table-name "$table" \
        --query "Table.GlobalSecondaryIndexes[?IndexName=='$index'].IndexStatus | [0]" \
        --output text
    )"
    if [[ "$status" == "ACTIVE" ]]; then
      return 0
    fi
    [[ "$status" == "CREATING" || "$status" == "UPDATING" ]] ||
      fail "$table $index has unexpected status: ${status:-missing}"
    sleep 5
  done
  fail "$table $index did not become ACTIVE"
}

filter_url() {
  local base="$1" expression="$2" encoded
  encoded="$(jq -rn --arg value "$expression" '$value | @uri')"
  printf '%s/scim/v2/Users?filter=%s\n' "$base" "$encoded"
}

if [[ -n "$STACK_NAME" ]]; then
  wait_for_gsi_active "$USERS_TABLE" scim_tenant-index
  wait_for_gsi_active "$SESSIONS_TABLE" user_id-index
  wait_for_gsi_active "$REFRESH_TABLE" user_id-index
  wait_for_gsi_active "$GRANTS_TABLE" user_id-index
  pass "deployed lifecycle indexes are ACTIVE"
fi

request no-auth GET "$BASE_URL/scim/v2/ServiceProviderConfig"
assert_status no-auth 401
assert_scim_media_type no-auth
jq -e --arg schema "$ERROR_SCHEMA" '
  .schemas == [$schema] and .status == "401"
' "$WORK/no-auth.json" >/dev/null || fail "missing-bearer response is not a SCIM error"
pass "SCIM endpoints require a bearer credential"

if [[ -n "$ADMIN_TOKEN" ]]; then
  request admin-on-scim GET "$BASE_URL/scim/v2/ServiceProviderConfig" "$ADMIN_TOKEN"
  assert_status admin-on-scim 401
  request scim-on-admin GET "$BASE_URL/admin/overview" "$PRIMARY_TOKEN"
  assert_status scim-on-admin 401
  pass "Admin and SCIM credential domains reject each other"
fi

request config GET "$BASE_URL/scim/v2/ServiceProviderConfig" "$PRIMARY_TOKEN"
assert_status config 200
assert_scim_media_type config
jq -e --arg schema "$CONFIG_SCHEMA" '
  .schemas == [$schema]
  and .patch.supported == true
  and .filter.supported == true
  and .filter.maxResults == 100
  and .bulk.supported == false
  and .changePassword.supported == false
  and .sort.supported == false
  and .etag.supported == false
' "$WORK/config.json" >/dev/null || fail "ServiceProviderConfig is not truthful"
pass "ServiceProviderConfig is authenticated and truthful"

INACTIVE_EXTERNAL_ID="agent-auth-scim-inactive-e2e-$RUN_ID"
INACTIVE_USER_NAME="agent-auth-scim-inactive-e2e-$RUN_ID@example.invalid"
INACTIVE_CREATE_BODY="$WORK/inactive-create.json"
jq -n \
  --arg schema "$USER_SCHEMA" \
  --arg external_id "$INACTIVE_EXTERNAL_ID" \
  --arg user_name "$INACTIVE_USER_NAME" '{
    schemas: [$schema],
    externalId: $external_id,
    userName: $user_name,
    displayName: "Agent Auth inactive SCIM live e2e",
    active: false
  }' >"$INACTIVE_CREATE_BODY"
request inactive-create POST \
  "$BASE_URL/scim/v2/Users" "$PRIMARY_TOKEN" "$INACTIVE_CREATE_BODY"
assert_status_one_of inactive-create 201 200
assert_scim_media_type inactive-create
INACTIVE_USER_ID="$(jq -er '
  select(.active == false)
  | .id | select(type == "string" and length > 0)
' "$WORK/inactive-create.json")"
request inactive-create-retry POST \
  "$BASE_URL/scim/v2/Users" "$PRIMARY_TOKEN" "$INACTIVE_CREATE_BODY"
assert_status inactive-create-retry 200
assert_scim_media_type inactive-create-retry
jq -e --arg id "$INACTIVE_USER_ID" '
  .id == $id and .active == false
' "$WORK/inactive-create-retry.json" >/dev/null ||
  fail "inactive POST retry changed or enabled the canonical user"
pass "inactive POST commits fail-closed state and retries idempotently"

EXTERNAL_ID="agent-auth-scim-e2e-$RUN_ID"
USER_NAME="agent-auth-scim-e2e-$RUN_ID@example.invalid"
MOVED_EXTERNAL_ID="$EXTERNAL_ID-moved"
MOVED_USER_NAME="agent-auth-scim-e2e-$RUN_ID-moved@example.invalid"
CREATE_BODY="$WORK/create.json"
jq -n \
  --arg schema "$USER_SCHEMA" \
  --arg external_id "$EXTERNAL_ID" \
  --arg user_name "$USER_NAME" '{
    schemas: [$schema],
    externalId: $external_id,
    userName: $user_name,
    displayName: "Agent Auth SCIM live e2e",
    active: true
  }' >"$CREATE_BODY"

request create POST "$BASE_URL/scim/v2/Users" "$PRIMARY_TOKEN" "$CREATE_BODY"
assert_status_one_of create 201 200
assert_scim_media_type create
USER_ID="$(jq -er --arg schema "$USER_SCHEMA" '
  select(.schemas == [$schema] and .active == true)
  | .id | select(type == "string" and length > 0)
' "$WORK/create.json")"
pass "provisioned canonical user $USER_ID"

request retry POST "$BASE_URL/scim/v2/Users" "$PRIMARY_TOKEN" "$CREATE_BODY"
assert_status retry 200
assert_scim_media_type retry
[[ "$(jq -er '.id' "$WORK/retry.json")" == "$USER_ID" ]] ||
  fail "exact retry created a different canonical user"
pass "exact POST retry is idempotent"

request get GET "$BASE_URL/scim/v2/Users/$USER_ID" "$PRIMARY_TOKEN"
assert_status get 200
assert_scim_media_type get
[[ "$(jq -er '.id' "$WORK/get.json")" == "$USER_ID" ]] ||
  fail "GET by id returned a different resource"

request filter GET \
  "$(filter_url "$BASE_URL" "externalId eq \"$EXTERNAL_ID\"")" "$PRIMARY_TOKEN"
assert_status filter 200
assert_scim_media_type filter
jq -e --arg schema "$LIST_SCHEMA" --arg id "$USER_ID" '
  .schemas == [$schema]
  and .totalResults == 1
  and .Resources[0].id == $id
' "$WORK/filter.json" >/dev/null || fail "externalId filter did not return the user"
pass "GET by id and externalId filter resolve the canonical user"

PUT_BODY="$WORK/put.json"
jq -n \
  --arg schema "$USER_SCHEMA" \
  --arg external_id "$MOVED_EXTERNAL_ID" \
  --arg user_name "$MOVED_USER_NAME" '{
    schemas: [$schema],
    externalId: $external_id,
    userName: $user_name,
    displayName: "Agent Auth SCIM live e2e moved",
    active: true
  }' >"$PUT_BODY"
request replace PUT "$BASE_URL/scim/v2/Users/$USER_ID" "$PRIMARY_TOKEN" "$PUT_BODY"
assert_status replace 200
assert_scim_media_type replace
jq -e --arg id "$USER_ID" --arg external_id "$MOVED_EXTERNAL_ID" '
  .id == $id and .externalId == $external_id and .active == true
' "$WORK/replace.json" >/dev/null || fail "PUT did not preserve the canonical id"

request stale-filter GET \
  "$(filter_url "$BASE_URL" "externalId eq \"$EXTERNAL_ID\"")" "$PRIMARY_TOKEN"
assert_status stale-filter 200
jq -e '.totalResults == 0' "$WORK/stale-filter.json" >/dev/null ||
  fail "old externalId still resolves after PUT"
pass "PUT atomically moved aliases while preserving the canonical id"

PUT_OFF_BODY="$WORK/put-off.json"
jq -n \
  --arg schema "$USER_SCHEMA" \
  --arg external_id "$MOVED_EXTERNAL_ID" \
  --arg user_name "$MOVED_USER_NAME" '{
    schemas: [$schema],
    externalId: $external_id,
    userName: $user_name,
    displayName: "Agent Auth SCIM live e2e moved",
    active: false
  }' >"$PUT_OFF_BODY"
request put-disable PUT \
  "$BASE_URL/scim/v2/Users/$USER_ID" "$PRIMARY_TOKEN" "$PUT_OFF_BODY"
assert_status put-disable 200
assert_scim_media_type put-disable
jq -e --arg id "$USER_ID" '
  .id == $id and .active == false
' "$WORK/put-disable.json" >/dev/null ||
  fail "PUT active=false did not disable the user"
request put-disable-retry PUT \
  "$BASE_URL/scim/v2/Users/$USER_ID" "$PRIMARY_TOKEN" "$PUT_OFF_BODY"
assert_status put-disable-retry 200
assert_scim_media_type put-disable-retry
jq -e --arg id "$USER_ID" '
  .id == $id and .active == false
' "$WORK/put-disable-retry.json" >/dev/null ||
  fail "repeated PUT active=false changed or enabled the user"
pass "inactive PUT commits fail-closed state and retries idempotently"

PATCH_OFF="$WORK/patch-off.json"
PATCH_ON="$WORK/patch-on.json"
jq -n --arg schema "$PATCH_SCHEMA" '{
  schemas: [$schema],
  Operations: [{op: "replace", path: "active", value: false}]
}' >"$PATCH_OFF"
jq -n --arg schema "$PATCH_SCHEMA" '{
  schemas: [$schema],
  Operations: [{op: "replace", path: "active", value: true}]
}' >"$PATCH_ON"

request put-reenable PATCH \
  "$BASE_URL/scim/v2/Users/$USER_ID" "$PRIMARY_TOKEN" "$PATCH_ON"
assert_status put-reenable 200
assert_scim_media_type put-reenable
jq -e '.active == true' "$WORK/put-reenable.json" >/dev/null ||
  fail "PATCH active=true did not restore the PUT-disabled user"

LIFECYCLE_EPOCH=""
if [[ -n "$STACK_NAME" ]]; then
  PHYSICAL_USER_KEY="$(physical_key "$USER_ID")"
  USER_KEY_JSON="$(jq -cn --arg value "$PHYSICAL_USER_KEY" '{user_id:{S:$value}}')"
  USER_ITEM="$(dynamodb_get_item "$USERS_TABLE" "$USER_KEY_JSON")"
  LIFECYCLE_EPOCH="$(jq -er '.Item.credential_epoch.N | tonumber' <<<"$USER_ITEM")"
  jq -e '
    .Item.status.S == "active"
    and ((.Item.revocation_pending.BOOL // false) == false)
  ' <<<"$USER_ITEM" >/dev/null ||
    fail "canonical user is not active before lifecycle artifact seeding"

  LIFECYCLE_SESSION_ID="scim-live-session-$RUN_ID"
  LIFECYCLE_FAMILY_ID="scim-live-family-$RUN_ID"
  LIFECYCLE_GRANT_ID="scim-live-grant-$RUN_ID"
  LIFECYCLE_CLIENT_ID="scim-live-client-$RUN_ID"
  LIFECYCLE_SESSION_KEY="$(physical_key "$LIFECYCLE_SESSION_ID")"
  LIFECYCLE_FAMILY_KEY="$(physical_key "$LIFECYCLE_FAMILY_ID")"
  LIFECYCLE_GRANT_KEY="$(physical_key "$LIFECYCLE_GRANT_ID")"
  PHYSICAL_CLIENT_KEY="$(physical_key "$LIFECYCLE_CLIENT_ID")"
  GV_TENANT_KEY="$(physical_key gv)"
  NOW="$(date +%s)"
  EXPIRES_AT="$((NOW + 3600))"

  SESSION_ITEM="$(jq -cn \
    --arg sid "$LIFECYCLE_SESSION_KEY" --arg uid "$PHYSICAL_USER_KEY" \
    --arg epoch "$LIFECYCLE_EPOCH" --arg now "$NOW" --arg expires "$EXPIRES_AT" '{
      session_id:{S:$sid}, user_id:{S:$uid}, credential_epoch:{N:$epoch},
      auth_time:{N:$now}, expires_at:{N:$expires}, amr:{L:[{S:"pwd"}]}
    }')"
  REFRESH_ITEM="$(jq -cn \
    --arg fid "$LIFECYCLE_FAMILY_KEY" --arg uid "$PHYSICAL_USER_KEY" \
    --arg cid "$PHYSICAL_CLIENT_KEY" --arg epoch "$LIFECYCLE_EPOCH" '{
      family_id:{S:$fid}, current_version:{N:"0"}, revoked:{BOOL:false},
      client_id:{S:$cid}, user_id:{S:$uid}, credential_epoch:{N:$epoch},
      resources:{L:[]}, scope:{L:[]}, actor_allowlist:{L:[]},
      max_act_chain:{N:"1"}
    }')"
  GRANT_JSON="$(jq -cn \
    --arg gid "$LIFECYCLE_GRANT_ID" --arg uid "$USER_ID" \
    --arg cid "$LIFECYCLE_CLIENT_ID" --argjson epoch "$LIFECYCLE_EPOCH" \
    --argjson expires "$EXPIRES_AT" '{
      grant_id:$gid, user_id:$uid, client_id:$cid, per_resource:[],
      effective_per_resource:[], effective_pv:0, allowed_ip_cidrs:[],
      allowed_vpce:[], credential_epoch:$epoch, revision:0,
      constraints:{max_act_chain:1,actor_allowlist:[],expires_at:$expires},
      status:"active"
    }')"
  GRANT_ITEM="$(jq -cn \
    --arg gid "$LIFECYCLE_GRANT_KEY" --arg uid "$PHYSICAL_USER_KEY" \
    --arg gv "$GV_TENANT_KEY" --arg epoch "$LIFECYCLE_EPOCH" \
    --arg grant "$GRANT_JSON" '{
      grant_id:{S:$gid}, user_id:{S:$uid}, gv_tenant:{S:$gv},
      effective_pv:{N:"0"}, revision:{N:"0"}, credential_epoch:{N:$epoch},
      grant_json:{S:$grant}
    }')"

  aws dynamodb put-item --profile "$PROFILE" --region "$REGION" \
    --table-name "$SESSIONS_TABLE" --item "$SESSION_ITEM" >/dev/null
  aws dynamodb put-item --profile "$PROFILE" --region "$REGION" \
    --table-name "$REFRESH_TABLE" --item "$REFRESH_ITEM" >/dev/null
  aws dynamodb put-item --profile "$PROFILE" --region "$REGION" \
    --table-name "$GRANTS_TABLE" --item "$GRANT_ITEM" >/dev/null
  pass "seeded epoch-$LIFECYCLE_EPOCH artifacts without waiting for GSI convergence"
fi

request disable PATCH "$BASE_URL/scim/v2/Users/$USER_ID" "$PRIMARY_TOKEN" "$PATCH_OFF"
assert_status disable 200
assert_scim_media_type disable
jq -e '.active == false' "$WORK/disable.json" >/dev/null ||
  fail "PATCH active=false did not disable the user"

if [[ -n "$STACK_NAME" ]]; then
  SESSION_BEFORE_RETRY="$(dynamodb_get_item "$SESSIONS_TABLE" \
    "$(jq -cn --arg value "$LIFECYCLE_SESSION_KEY" '{session_id:{S:$value}}')")"
  if [[ "$(jq '.Item | length' <<<"$SESSION_BEFORE_RETRY")" != "0" ]]; then
    wait_for_user_index_item \
      "$SESSIONS_TABLE" session_id "$LIFECYCLE_SESSION_KEY" "$PHYSICAL_USER_KEY"
  fi

  REFRESH_BEFORE_RETRY="$(dynamodb_get_item "$REFRESH_TABLE" \
    "$(jq -cn --arg value "$LIFECYCLE_FAMILY_KEY" '{family_id:{S:$value}}')")"
  if ! jq -e '.Item.revoked.BOOL == true' <<<"$REFRESH_BEFORE_RETRY" >/dev/null; then
    wait_for_user_index_item \
      "$REFRESH_TABLE" family_id "$LIFECYCLE_FAMILY_KEY" "$PHYSICAL_USER_KEY"
  fi

  GRANT_BEFORE_RETRY="$(dynamodb_get_item "$GRANTS_TABLE" \
    "$(jq -cn --arg value "$LIFECYCLE_GRANT_KEY" '{grant_id:{S:$value}}')")"
  if ! jq -e '.Item.grant_json.S | fromjson | .status == "revoked"' \
    <<<"$GRANT_BEFORE_RETRY" >/dev/null; then
    wait_for_user_index_item \
      "$GRANTS_TABLE" grant_id "$LIFECYCLE_GRANT_KEY" "$PHYSICAL_USER_KEY"
  fi
fi

request disable-retry PATCH "$BASE_URL/scim/v2/Users/$USER_ID" "$PRIMARY_TOKEN" "$PATCH_OFF"
assert_status disable-retry 200
jq -e '.active == false' "$WORK/disable-retry.json" >/dev/null ||
  fail "repeated disable was not idempotent"
pass "deprovision is idempotent and retries cleanup after GSI convergence"

if [[ -n "$STACK_NAME" ]]; then
  SESSION_RESULT="$(dynamodb_get_item "$SESSIONS_TABLE" \
    "$(jq -cn --arg value "$LIFECYCLE_SESSION_KEY" '{session_id:{S:$value}}')")"
  [[ "$(jq '.Item | length' <<<"$SESSION_RESULT")" == "0" ]] ||
    fail "SCIM disable did not delete the old-epoch session"

  REFRESH_RESULT="$(dynamodb_get_item "$REFRESH_TABLE" \
    "$(jq -cn --arg value "$LIFECYCLE_FAMILY_KEY" '{family_id:{S:$value}}')")"
  jq -e '.Item.revoked.BOOL == true' <<<"$REFRESH_RESULT" >/dev/null ||
    fail "SCIM disable did not revoke the old-epoch refresh family"

  GRANT_RESULT="$(dynamodb_get_item "$GRANTS_TABLE" \
    "$(jq -cn --arg value "$LIFECYCLE_GRANT_KEY" '{grant_id:{S:$value}}')")"
  jq -e '.Item.grant_json.S | fromjson | .status == "revoked"' \
    <<<"$GRANT_RESULT" >/dev/null ||
    fail "SCIM disable did not revoke the old-epoch Grant"

  USER_RESULT="$(dynamodb_get_item "$USERS_TABLE" "$USER_KEY_JSON")"
  DISABLE_EPOCH="$(jq -er '.Item.credential_epoch.N | tonumber' <<<"$USER_RESULT")"
  [[ "$DISABLE_EPOCH" -eq $((LIFECYCLE_EPOCH + 1)) ]] ||
    fail "SCIM disable did not advance the lifecycle epoch exactly once"
  jq -e '
    .Item.status.S == "disabled"
    and .Item.revocation_pending.BOOL == false
  ' <<<"$USER_RESULT" >/dev/null ||
    fail "SCIM disable did not durably complete revocation"
  pass "deployed disable removed session, revoked refresh/Grant, and completed one epoch"
fi

request reenable PATCH "$BASE_URL/scim/v2/Users/$USER_ID" "$PRIMARY_TOKEN" "$PATCH_ON"
assert_status reenable 200
assert_scim_media_type reenable
jq -e '.active == true' "$WORK/reenable.json" >/dev/null ||
  fail "PATCH active=true did not re-provision the user"
pass "re-provision restored only the user status"

if [[ -n "$STACK_NAME" ]]; then
  USER_RESULT="$(dynamodb_get_item "$USERS_TABLE" "$USER_KEY_JSON")"
  jq -e --arg epoch "$DISABLE_EPOCH" '
    .Item.status.S == "active"
    and .Item.credential_epoch.N == $epoch
    and ((.Item.revocation_pending.BOOL // false) == false)
  ' <<<"$USER_RESULT" >/dev/null ||
    fail "SCIM re-enable changed the completed lifecycle epoch"
  pass "deployed re-enable preserved the completed epoch and did not recreate artifacts"
fi

if [[ -n "$OTHER_BASE_URL" ]]; then
  request primary-on-other GET \
    "$OTHER_BASE_URL/scim/v2/ServiceProviderConfig" "$PRIMARY_TOKEN"
  assert_status primary-on-other 401
  request other-on-primary GET \
    "$BASE_URL/scim/v2/ServiceProviderConfig" "$OTHER_TOKEN"
  assert_status other-on-primary 401
  request crossed-id GET \
    "$OTHER_BASE_URL/scim/v2/Users/$USER_ID" "$OTHER_TOKEN"
  assert_status crossed-id 404

  request other-create POST \
    "$OTHER_BASE_URL/scim/v2/Users" "$OTHER_TOKEN" "$PUT_BODY"
  assert_status_one_of other-create 201 200
  assert_scim_media_type other-create
  OTHER_USER_ID="$(jq -er '.id' "$WORK/other-create.json")"
  [[ "$OTHER_USER_ID" != "$USER_ID" ]] ||
    fail "different tenants returned the same canonical user"
  request other-filter GET \
    "$(filter_url "$OTHER_BASE_URL" "externalId eq \"$MOVED_EXTERNAL_ID\"")" \
    "$OTHER_TOKEN"
  assert_status other-filter 200
  jq -e --arg id "$OTHER_USER_ID" '
    .totalResults == 1 and .Resources[0].id == $id
  ' "$WORK/other-filter.json" >/dev/null ||
    fail "other tenant filter did not resolve its own user"
  pass "cross-tenant credentials and ids are rejected; aliases stay tenant-local"
fi

printf 'SCIM live acceptance passed for %s (run_id=%s)\n' "$BASE_URL" "$RUN_ID"
