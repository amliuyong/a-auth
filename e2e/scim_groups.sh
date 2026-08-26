#!/usr/bin/env bash
# Live SCIM Groups and explicit tenant-role mapping acceptance for issue #19.
#
# Required:
#   BASE_URL=https://tenant.example.com
#   SCIM_SECRET_ARN=arn:...  (or SCIM_TOKEN_FILE=/secure/path)
#   ADMIN_SECRET_ARN=arn:... (or ADMIN_TOKEN_FILE=/secure/path)
#
# Optional tenant-isolation matrix:
#   OTHER_BASE_URL=https://other-tenant.example.com
#   OTHER_SCIM_SECRET_ARN=arn:...  (or OTHER_SCIM_TOKEN_FILE=...)
#   OTHER_ADMIN_SECRET_ARN=arn:... (or OTHER_ADMIN_TOKEN_FILE=...)
#
# Optional deployed-table checks:
#   STACK_NAME=AgentAuthDev STORAGE_TENANT=
#   STACK_NAME=AgentAuthSaas STORAGE_TENANT=t1
set -euo pipefail
set +x

PROFILE="${PROFILE:-${AWS_PROFILE:-default}}"
REGION="${REGION:-${AWS_REGION:-us-east-1}}"
BASE_URL="${BASE_URL:?BASE_URL is required}"
BASE_URL="${BASE_URL%/}"
OTHER_BASE_URL="${OTHER_BASE_URL:-}"
OTHER_BASE_URL="${OTHER_BASE_URL%/}"
STACK_NAME="${STACK_NAME:-}"
STORAGE_TENANT="${STORAGE_TENANT:-}"
RUN_ID="${SCIM_GROUP_RUN_ID:-$(date -u +%Y%m%d%H%M%S)-$RANDOM}"

USER_SCHEMA='urn:ietf:params:scim:schemas:core:2.0:User'
GROUP_SCHEMA='urn:ietf:params:scim:schemas:core:2.0:Group'
PATCH_SCHEMA='urn:ietf:params:scim:api:messages:2.0:PatchOp'
ERROR_SCHEMA='urn:ietf:params:scim:api:messages:2.0:Error'

umask 077
WORK="$(mktemp -d)"
PRIMARY_GROUP_IDS=()
OTHER_GROUP_IDS=()
PRIMARY_USER_IDS=()
OTHER_USER_IDS=()

pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
require() { command -v "$1" >/dev/null || fail "missing command: $1"; }

load_token() {
  local owner="$1" token_file="$2" secret_arn="$3"
  local output="$WORK/$owner.token"
  if [[ -n "$token_file" ]]; then
    [[ -r "$token_file" ]] || fail "$owner token file is not readable"
    cp "$token_file" "$output"
  else
    [[ -n "$secret_arn" ]] || fail "$owner token file or Secret ARN is required"
    aws secretsmanager get-secret-value \
      --secret-id "$secret_arn" --profile "$PROFILE" --region "$REGION" \
      --query SecretString --output text |
      jq -er '.current.secret | select(type == "string" and length >= 16)' >"$output"
  fi
  chmod 0600 "$output"
  printf '%s\n' "$output"
}

request() {
  local name="$1" method="$2" url="$3" token_file="${4:-}" body_file="${5:-}"
  local response_body="$WORK/$name.json"
  local request_headers="$WORK/$name.request-headers"
  local -a args=(
    -sS --proto '=https' --connect-timeout 5 --max-time 30
    -X "$method" -H "@$request_headers"
    -D "$WORK/$name.headers" -o "$response_body"
  )
  : >"$request_headers"
  if [[ -n "$token_file" ]]; then
    printf 'authorization: Bearer %s\n' "$(<"$token_file")" >>"$request_headers"
  fi
  if [[ -n "$body_file" ]]; then
    printf 'content-type: application/scim+json\n' >>"$request_headers"
    args+=(--data-binary "@$body_file")
  fi
  curl "${args[@]}" -w '%{http_code}' "$url" >"$WORK/$name.status"
}

assert_status() {
  local name="$1" expected="$2" actual
  actual="$(<"$WORK/$name.status")"
  [[ "$actual" == "$expected" ]] ||
    fail "$name expected HTTP $expected, got $actual: $(<"$WORK/$name.json")"
}

assert_status_one_of() {
  local name="$1" first="$2" second="$3" actual
  actual="$(<"$WORK/$name.status")"
  [[ "$actual" == "$first" || "$actual" == "$second" ]] ||
    fail "$name expected HTTP $first or $second, got $actual: $(<"$WORK/$name.json")"
}

delete_group_quietly() {
  local base="$1" token_file="$2" group_id="$3"
  [[ -n "$group_id" ]] || return 0
  printf 'authorization: Bearer %s\n' "$(<"$token_file")" >"$WORK/cleanup.request-headers"
  curl -sS --proto '=https' --connect-timeout 5 --max-time 30 \
    -X DELETE -H "@$WORK/cleanup.request-headers" \
    "$base/scim/v2/Groups/$group_id" >/dev/null 2>&1 || true
}

delete_user_quietly() {
  local base="$1" token_file="$2" user_id="$3"
  [[ -n "$user_id" ]] || return 0
  printf 'authorization: Bearer %s\n' "$(<"$token_file")" >"$WORK/cleanup.request-headers"
  curl -sS --proto '=https' --connect-timeout 5 --max-time 30 \
    -X DELETE -H "@$WORK/cleanup.request-headers" \
    "$base/admin/users/$user_id" >/dev/null 2>&1 || true
}

cleanup() {
  set +e
  if [[ -n "${PRIMARY_SCIM_TOKEN:-}" ]]; then
    for group_id in "${PRIMARY_GROUP_IDS[@]}"; do
      delete_group_quietly "$BASE_URL" "$PRIMARY_SCIM_TOKEN" "$group_id"
    done
  fi
  if [[ -n "${PRIMARY_ADMIN_TOKEN:-}" ]]; then
    for user_id in "${PRIMARY_USER_IDS[@]}"; do
      delete_user_quietly "$BASE_URL" "$PRIMARY_ADMIN_TOKEN" "$user_id"
    done
  fi
  if [[ -n "${OTHER_SCIM_TOKEN:-}" && -n "$OTHER_BASE_URL" ]]; then
    for group_id in "${OTHER_GROUP_IDS[@]}"; do
      delete_group_quietly "$OTHER_BASE_URL" "$OTHER_SCIM_TOKEN" "$group_id"
    done
  fi
  if [[ -n "${OTHER_ADMIN_TOKEN:-}" && -n "$OTHER_BASE_URL" ]]; then
    for user_id in "${OTHER_USER_IDS[@]}"; do
      delete_user_quietly "$OTHER_BASE_URL" "$OTHER_ADMIN_TOKEN" "$user_id"
    done
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

for command in curl jq aws; do
  require "$command"
done
[[ "$BASE_URL" == https://* ]] || fail "BASE_URL must be HTTPS"

PRIMARY_SCIM_TOKEN="$(
  load_token primary-scim "${SCIM_TOKEN_FILE:-}" "${SCIM_SECRET_ARN:-}"
)"
PRIMARY_ADMIN_TOKEN="$(
  load_token primary-admin "${ADMIN_TOKEN_FILE:-}" "${ADMIN_SECRET_ARN:-}"
)"
OTHER_SCIM_TOKEN=""
OTHER_ADMIN_TOKEN=""
if [[ -n "$OTHER_BASE_URL" ]]; then
  [[ "$OTHER_BASE_URL" == https://* && "$OTHER_BASE_URL" != "$BASE_URL" ]] ||
    fail "OTHER_BASE_URL must be a distinct HTTPS origin"
  OTHER_SCIM_TOKEN="$(
    load_token other-scim "${OTHER_SCIM_TOKEN_FILE:-}" "${OTHER_SCIM_SECRET_ARN:-}"
  )"
  OTHER_ADMIN_TOKEN="$(
    load_token other-admin "${OTHER_ADMIN_TOKEN_FILE:-}" "${OTHER_ADMIN_SECRET_ARN:-}"
  )"
fi

stack_output() {
  aws cloudformation describe-stacks \
    --profile "$PROFILE" --region "$REGION" --stack-name "$STACK_NAME" \
    --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue | [0]" \
    --output text
}

wait_for_index() {
  local table="$1" index="$2" status
  for _ in $(seq 1 180); do
    status="$(
      aws dynamodb describe-table --profile "$PROFILE" --region "$REGION" \
        --table-name "$table" \
        --query "Table.GlobalSecondaryIndexes[?IndexName=='$index'].IndexStatus | [0]" \
        --output text
    )"
    [[ "$status" == "ACTIVE" ]] && return 0
    [[ "$status" == "CREATING" || "$status" == "UPDATING" ]] ||
      fail "$table $index has unexpected status: ${status:-missing}"
    sleep 5
  done
  fail "$table $index did not become ACTIVE"
}

if [[ -n "$STACK_NAME" ]]; then
  GROUPS_TABLE="$(stack_output ScimGroupsTableName)"
  [[ -n "$GROUPS_TABLE" && "$GROUPS_TABLE" != "None" ]] ||
    fail "stack is missing ScimGroupsTableName"
  wait_for_index "$GROUPS_TABLE" tenant_kind-index
  pass "deployed SCIM Groups tenant index is ACTIVE"
fi

create_user() {
  local name="$1" external_id="$2" user_name="$3" base="$4" token="$5"
  local body="$WORK/$name.body"
  jq -n --arg schema "$USER_SCHEMA" --arg external "$external_id" --arg user "$user_name" '{
    schemas:[$schema], externalId:$external, userName:$user,
    displayName:"SCIM Groups live acceptance", active:true
  }' >"$body"
  request "$name" POST "$base/scim/v2/Users" "$token" "$body"
  assert_status_one_of "$name" 201 200
  jq -er '.id | select(type == "string" and length > 0)' "$WORK/$name.json"
}

USER_1_ID="$(
  create_user user-1 "group-user-1-$RUN_ID" "group-user-1-$RUN_ID@example.invalid" \
    "$BASE_URL" "$PRIMARY_SCIM_TOKEN"
)"
PRIMARY_USER_IDS+=("$USER_1_ID")
USER_2_ID="$(
  create_user user-2 "group-user-2-$RUN_ID" "group-user-2-$RUN_ID@example.invalid" \
    "$BASE_URL" "$PRIMARY_SCIM_TOKEN"
)"
PRIMARY_USER_IDS+=("$USER_2_ID")
pass "provisioned two tenant-local SCIM Users"

ROLE_PAYLOAD="$WORK/role-payload.body.json"
jq -n --arg schema "$GROUP_SCHEMA" --arg user "$USER_1_ID" '{
  schemas:[$schema], externalId:"forbidden-role", displayName:"Forbidden",
  members:[{value:$user,type:"User"}], role:"owner"
}' >"$ROLE_PAYLOAD"
request role-payload POST "$BASE_URL/scim/v2/Groups" "$PRIMARY_SCIM_TOKEN" "$ROLE_PAYLOAD"
assert_status role-payload 400
jq -e --arg schema "$ERROR_SCHEMA" '
  .schemas == [$schema] and .scimType == "invalidPath"
' "$WORK/role-payload.json" >/dev/null ||
  fail "SCIM role payload was not rejected as a SCIM error"
pass "SCIM bearer cannot supply a tenant role"

create_group_body() {
  local output="$1" external="$2" display="$3"
  shift 3
  jq -n --arg schema "$GROUP_SCHEMA" --arg external "$external" \
    --arg display "$display" --args '{
      schemas:[$schema], externalId:$external, displayName:$display,
      members:[$ARGS.positional[] | {value:.,type:"User"}]
    }' "$@" >"$output"
}

ADMINS_EXTERNAL="directory-admins-$RUN_ID"
ADMINS_BODY="$WORK/admins.json"
create_group_body "$ADMINS_BODY" "$ADMINS_EXTERNAL" "Directory Admins" "$USER_1_ID"
request group-create POST "$BASE_URL/scim/v2/Groups" "$PRIMARY_SCIM_TOKEN" "$ADMINS_BODY"
assert_status group-create 201
ADMIN_GROUP_ID="$(jq -er '.id' "$WORK/group-create.json")"
PRIMARY_GROUP_IDS+=("$ADMIN_GROUP_ID")
request group-retry POST "$BASE_URL/scim/v2/Groups" "$PRIMARY_SCIM_TOKEN" "$ADMINS_BODY"
assert_status group-retry 200
jq -e --arg id "$ADMIN_GROUP_ID" '.id == $id' "$WORK/group-retry.json" >/dev/null ||
  fail "exact Group POST retry changed the id"

CONFLICTING_GROUP_BODY="$WORK/conflicting-group.json"
create_group_body "$CONFLICTING_GROUP_BODY" "$ADMINS_EXTERNAL" "Conflicting Group" "$USER_2_ID"
request group-conflict POST "$BASE_URL/scim/v2/Groups" \
  "$PRIMARY_SCIM_TOKEN" "$CONFLICTING_GROUP_BODY"
assert_status group-conflict 409
jq -e --arg schema "$ERROR_SCHEMA" '
  .schemas == [$schema] and .scimType == "uniqueness"
' "$WORK/group-conflict.json" >/dev/null ||
  fail "conflicting Group POST was not rejected as a uniqueness error"

FILTER="$(jq -rn --arg value "externalId eq \"$ADMINS_EXTERNAL\"" '$value | @uri')"
request group-filter GET "$BASE_URL/scim/v2/Groups?filter=$FILTER" "$PRIMARY_SCIM_TOKEN"
assert_status group-filter 200
jq -e --arg id "$ADMIN_GROUP_ID" '
  .totalResults == 1 and .Resources[0].id == $id
' "$WORK/group-filter.json" >/dev/null || fail "Group externalId filter failed"

request group-put PUT "$BASE_URL/scim/v2/Groups/$ADMIN_GROUP_ID" \
  "$PRIMARY_SCIM_TOKEN" "$ADMINS_BODY"
assert_status group-put 200
request group-put-retry PUT "$BASE_URL/scim/v2/Groups/$ADMIN_GROUP_ID" \
  "$PRIMARY_SCIM_TOKEN" "$ADMINS_BODY"
assert_status group-put-retry 200
jq -e --arg id "$ADMIN_GROUP_ID" --arg user "$USER_1_ID" '
  .id == $id and .displayName == "Directory Admins" and
  [.members[].value] == [$user]
' "$WORK/group-put-retry.json" >/dev/null ||
  fail "exact Group PUT retry changed the representation"
pass "Group create/retry/read/filter and exact PUT retry are stable"

ADD_MEMBER="$WORK/add-member.body.json"
jq -n --arg schema "$PATCH_SCHEMA" --arg user "$USER_2_ID" '{
  schemas:[$schema],
  Operations:[{op:"add",path:"members",value:[{value:$user,type:"User"}]}]
}' >"$ADD_MEMBER"
request add-member PATCH "$BASE_URL/scim/v2/Groups/$ADMIN_GROUP_ID" \
  "$PRIMARY_SCIM_TOKEN" "$ADD_MEMBER"
assert_status add-member 200
request add-member-retry PATCH "$BASE_URL/scim/v2/Groups/$ADMIN_GROUP_ID" \
  "$PRIMARY_SCIM_TOKEN" "$ADD_MEMBER"
assert_status add-member-retry 200
jq -e --arg user "$USER_2_ID" '
  [.members[] | select(.value == $user)] | length == 1
' "$WORK/add-member-retry.json" >/dev/null ||
  fail "repeated member add duplicated membership"
pass "Group PATCH retry is idempotent"

request scim-on-mapping PUT \
  "$BASE_URL/admin/scim/group-role-mappings/$ADMINS_EXTERNAL" \
  "$PRIMARY_SCIM_TOKEN" <(jq -n '{role:"owner"}')
assert_status scim-on-mapping 401

request unknown-role PUT \
  "$BASE_URL/admin/scim/group-role-mappings/$ADMINS_EXTERNAL" \
  "$PRIMARY_ADMIN_TOKEN" <(jq -n '{role:"superadmin"}')
assert_status unknown-role 400

request unmapped GET "$BASE_URL/admin/scim/effective-role/$USER_2_ID" "$PRIMARY_ADMIN_TOKEN"
assert_status unmapped 200
jq -e '.role == null and .mappings == []' "$WORK/unmapped.json" >/dev/null ||
  fail "unmapped Group granted a role"

RS_NAMESPACE="$(jq -rn --arg value 'https://rs.example.invalid' '$value | @uri')"
request rs-role PUT \
  "$BASE_URL/admin/users/$USER_2_ID/attributes?namespace=$RS_NAMESPACE" \
  "$PRIMARY_ADMIN_TOKEN" <(jq -n '{role:"owner"}')
if [[ -n "$STORAGE_TENANT" ]]; then
  assert_status rs-role 404
  pass "SaaS keeps the self-hosted RS attribute management endpoint closed"
else
  assert_status rs-role 200
  jq -e '.revision >= 1' "$WORK/rs-role.json" >/dev/null ||
    fail "RS attribute write did not return a persisted revision"
  request rs-role-read GET "$BASE_URL/admin/users/$USER_2_ID" "$PRIMARY_ADMIN_TOKEN"
  assert_status rs-role-read 200
  jq -e --arg namespace 'https://rs.example.invalid' '
    .attributes[$namespace].kv.role == "owner"
  ' "$WORK/rs-role-read.json" >/dev/null ||
    fail "RS attribute was not persisted before non-interference validation"
  pass "self-hosted RS attribute was persisted before role non-interference validation"
fi
request rs-role-effective GET \
  "$BASE_URL/admin/scim/effective-role/$USER_2_ID" "$PRIMARY_ADMIN_TOKEN"
assert_status rs-role-effective 200
jq -e '.role == null' "$WORK/rs-role-effective.json" >/dev/null ||
  fail "RS namespace attribute was interpreted as a tenant role"
pass "unmapped membership, unknown roles, and RS attributes grant no tenant role"

RACE_EXTERNAL="directory-race-$RUN_ID"
RACE_BODY="$WORK/race-group.json"
create_group_body "$RACE_BODY" "$RACE_EXTERNAL" "Directory Race" "$USER_1_ID"
request race-create POST "$BASE_URL/scim/v2/Groups" "$PRIMARY_SCIM_TOKEN" "$RACE_BODY"
assert_status race-create 201
RACE_GROUP_ID="$(jq -er '.id' "$WORK/race-create.json")"
PRIMARY_GROUP_IDS+=("$RACE_GROUP_ID")
RACE_MAP_ADMIN="$WORK/race-map-admin.body.json"
jq -n '{role:"admin"}' >"$RACE_MAP_ADMIN"

request race-add-member PATCH "$BASE_URL/scim/v2/Groups/$RACE_GROUP_ID" \
  "$PRIMARY_SCIM_TOKEN" "$ADD_MEMBER" &
RACE_ADD_PID=$!
request race-map-admin PUT \
  "$BASE_URL/admin/scim/group-role-mappings/$RACE_EXTERNAL" \
  "$PRIMARY_ADMIN_TOKEN" "$RACE_MAP_ADMIN" &
RACE_MAP_PID=$!
wait "$RACE_ADD_PID"
wait "$RACE_MAP_PID"
assert_status race-add-member 200
assert_status race-map-admin 200
request race-effective GET \
  "$BASE_URL/admin/scim/effective-role/$USER_2_ID" "$PRIMARY_ADMIN_TOKEN"
assert_status race-effective 200
jq -e '.role == "admin" and (.mappings | length) == 1' \
  "$WORK/race-effective.json" >/dev/null ||
  fail "concurrent membership and mapping updates did not converge"

RACE_REPLACE="$WORK/race-replace.body.json"
create_group_body "$RACE_REPLACE" "$RACE_EXTERNAL" "Directory Race" "$USER_1_ID"
request race-replace PUT "$BASE_URL/scim/v2/Groups/$RACE_GROUP_ID" \
  "$PRIMARY_SCIM_TOKEN" "$RACE_REPLACE" &
RACE_REPLACE_PID=$!
request race-unmap DELETE \
  "$BASE_URL/admin/scim/group-role-mappings/$RACE_EXTERNAL" \
  "$PRIMARY_ADMIN_TOKEN" &
RACE_UNMAP_PID=$!
wait "$RACE_REPLACE_PID"
wait "$RACE_UNMAP_PID"
assert_status race-replace 200
assert_status race-unmap 204
request race-effective-after-remove GET \
  "$BASE_URL/admin/scim/effective-role/$USER_2_ID" "$PRIMARY_ADMIN_TOKEN"
assert_status race-effective-after-remove 200
jq -e '.role == null and .mappings == []' \
  "$WORK/race-effective-after-remove.json" >/dev/null ||
  fail "concurrent membership and mapping removal left stale privilege"

request race-remap-owner PUT \
  "$BASE_URL/admin/scim/group-role-mappings/$RACE_EXTERNAL" \
  "$PRIMARY_ADMIN_TOKEN" <(jq -n '{role:"owner"}')
assert_status race-remap-owner 200
request race-delete DELETE "$BASE_URL/scim/v2/Groups/$RACE_GROUP_ID" \
  "$PRIMARY_SCIM_TOKEN" &
RACE_DELETE_PID=$!
request race-remap-admin PUT \
  "$BASE_URL/admin/scim/group-role-mappings/$RACE_EXTERNAL" \
  "$PRIMARY_ADMIN_TOKEN" "$RACE_MAP_ADMIN" &
RACE_REMAP_PID=$!
wait "$RACE_DELETE_PID"
wait "$RACE_REMAP_PID"
assert_status race-delete 204
assert_status_one_of race-remap-admin 200 404
request race-mapping-list GET \
  "$BASE_URL/admin/scim/group-role-mappings" "$PRIMARY_ADMIN_TOKEN"
assert_status race-mapping-list 200
jq -e --arg external "$RACE_EXTERNAL" '
  [.mappings[] | select(.externalId == $external)] | length == 0
' "$WORK/race-mapping-list.json" >/dev/null ||
  fail "concurrent Group delete and mapping update left a stale mapping"
pass "DynamoDB mutation, mapping, removal, and delete races converge without stale privilege"

for role in member auditor admin; do
  request "map-$role" PUT \
    "$BASE_URL/admin/scim/group-role-mappings/$ADMINS_EXTERNAL" \
    "$PRIMARY_ADMIN_TOKEN" <(jq -n --arg role "$role" '{role:$role}')
  assert_status "map-$role" 200
  request "effective-$role" GET \
    "$BASE_URL/admin/scim/effective-role/$USER_2_ID" "$PRIMARY_ADMIN_TOKEN"
  assert_status "effective-$role" 200
  jq -e --arg role "$role" '.role == $role and (.mappings | length) == 1' \
    "$WORK/effective-$role.json" >/dev/null ||
    fail "explicit $role mapping was not effective"
done

OWNERS_EXTERNAL="directory-owners-$RUN_ID"
OWNERS_BODY="$WORK/owners.json"
create_group_body "$OWNERS_BODY" "$OWNERS_EXTERNAL" "Directory Owners" "$USER_2_ID"
request owner-create POST "$BASE_URL/scim/v2/Groups" "$PRIMARY_SCIM_TOKEN" "$OWNERS_BODY"
assert_status owner-create 201
OWNER_GROUP_ID="$(jq -er '.id' "$WORK/owner-create.json")"
PRIMARY_GROUP_IDS+=("$OWNER_GROUP_ID")
request map-owner PUT \
  "$BASE_URL/admin/scim/group-role-mappings/$OWNERS_EXTERNAL" \
  "$PRIMARY_ADMIN_TOKEN" <(jq -n '{role:"owner"}')
assert_status map-owner 200
request effective-owner GET \
  "$BASE_URL/admin/scim/effective-role/$USER_2_ID" "$PRIMARY_ADMIN_TOKEN"
assert_status effective-owner 200
jq -e '.role == "owner" and (.mappings | length) == 2' \
  "$WORK/effective-owner.json" >/dev/null || fail "fixed role priority did not select owner"

REMOVE_OWNER="$WORK/remove-owner.body.json"
jq -n --arg schema "$PATCH_SCHEMA" --arg user "$USER_2_ID" '{
  schemas:[$schema],
  Operations:[{op:"remove",path:("members[value eq \"" + $user + "\"]")}]
}' >"$REMOVE_OWNER"
request remove-owner PATCH "$BASE_URL/scim/v2/Groups/$OWNER_GROUP_ID" \
  "$PRIMARY_SCIM_TOKEN" "$REMOVE_OWNER"
assert_status remove-owner 200
request effective-after-remove GET \
  "$BASE_URL/admin/scim/effective-role/$USER_2_ID" "$PRIMARY_ADMIN_TOKEN"
assert_status effective-after-remove 200
jq -e '.role == "admin" and (.mappings | length) == 1' \
  "$WORK/effective-after-remove.json" >/dev/null ||
  fail "removed membership retained the owner role"
pass "multiple mappings use fixed priority and membership removal revokes the higher role"

if [[ -n "$OTHER_BASE_URL" ]]; then
  request crossed-credential GET "$OTHER_BASE_URL/scim/v2/Groups" "$PRIMARY_SCIM_TOKEN"
  assert_status crossed-credential 401
  request crossed-id GET "$OTHER_BASE_URL/scim/v2/Groups/$ADMIN_GROUP_ID" "$OTHER_SCIM_TOKEN"
  assert_status crossed-id 404
  request crossed-mapping PUT \
    "$OTHER_BASE_URL/admin/scim/group-role-mappings/$ADMINS_EXTERNAL" \
    "$OTHER_ADMIN_TOKEN" <(jq -n '{role:"owner"}')
  assert_status crossed-mapping 404

  OTHER_BAD_BODY="$WORK/other-bad-member.json"
  create_group_body "$OTHER_BAD_BODY" "cross-member-$RUN_ID" "Cross Member" "$USER_2_ID"
  request crossed-member POST "$OTHER_BASE_URL/scim/v2/Groups" \
    "$OTHER_SCIM_TOKEN" "$OTHER_BAD_BODY"
  assert_status crossed-member 400
  pass "credentials, Group ids, mappings, and member references are tenant-isolated"
fi

request delete-mapping DELETE \
  "$BASE_URL/admin/scim/group-role-mappings/$ADMINS_EXTERNAL" "$PRIMARY_ADMIN_TOKEN"
assert_status delete-mapping 204
request effective-after-unmap GET \
  "$BASE_URL/admin/scim/effective-role/$USER_2_ID" "$PRIMARY_ADMIN_TOKEN"
assert_status effective-after-unmap 200
jq -e '.role == null and .mappings == []' "$WORK/effective-after-unmap.json" >/dev/null ||
  fail "deleted mapping retained privilege"

request remap-admin PUT \
  "$BASE_URL/admin/scim/group-role-mappings/$ADMINS_EXTERNAL" \
  "$PRIMARY_ADMIN_TOKEN" <(jq -n '{role:"admin"}')
assert_status remap-admin 200
request delete-group DELETE "$BASE_URL/scim/v2/Groups/$ADMIN_GROUP_ID" "$PRIMARY_SCIM_TOKEN"
assert_status delete-group 204
request delete-group-retry DELETE \
  "$BASE_URL/scim/v2/Groups/$ADMIN_GROUP_ID" "$PRIMARY_SCIM_TOKEN"
assert_status delete-group-retry 204
request effective-after-delete GET \
  "$BASE_URL/admin/scim/effective-role/$USER_2_ID" "$PRIMARY_ADMIN_TOKEN"
assert_status effective-after-delete 200
jq -e '.role == null and .mappings == []' "$WORK/effective-after-delete.json" >/dev/null ||
  fail "deleted Group retained its role mapping"
request mapping-list GET \
  "$BASE_URL/admin/scim/group-role-mappings" "$PRIMARY_ADMIN_TOKEN"
assert_status mapping-list 200
jq -e --arg external "$ADMINS_EXTERNAL" '
  [.mappings[] | select(.externalId == $external)] | length == 0
' "$WORK/mapping-list.json" >/dev/null || fail "deleted Group left a stale mapping"
pass "mapping deletion and Group deletion revoke privilege; Group DELETE retry is idempotent"

printf 'SCIM Groups live acceptance passed for %s (run_id=%s)\n' "$BASE_URL" "$RUN_ID"
