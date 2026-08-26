#!/usr/bin/env bash
# Issue #25 live interoperability acceptance.
# Deploys a transient API Gateway + Node receiver that independently validates
# ES256 SETs and records jti deduplication in DynamoDB. Exercises the deployed
# Dev and SaaS t1/t2 canonical SecurityEvents -> DynamoDB Stream -> KMS -> HTTPS
# path, then removes the transient receiver, fixture users, and stream rows. The
# canonical security-event ledger and archive remain intact as acceptance evidence.
set -Eeuo pipefail
set +x

PROFILE="${PROFILE:-${AWS_PROFILE:-default}}"
REGION="${REGION:-${AWS_REGION:-us-east-1}}"
DEV_STACK="${DEV_STACK:-AgentAuthDev}"
SAAS_STACK="${SAAS_STACK:-AgentAuthSaas}"
RUN_ID="$(openssl rand -hex 6)"
RECEIVER_STACK="AgentAuthSsfE2e-${RUN_ID}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
AWS=(aws --profile "$PROFILE" --region "$REGION")
CODE_BUCKET=""
CODE_KEY="agent-auth-e2e/ssf/${RUN_ID}.zip"
RECEIVER_TABLE=""
RECEIVER_URL=""
cleanup_failed=0

declare -A BASE TOKEN_FILE SCIM_TOKEN_FILE SECURITY_TABLE SSF_TABLE
declare -A STREAM_ID STREAM_REV EVENT_ID REVOKED USER_ID USER_EMAIL
declare -A SSF_RULE SSF_RULE_ORIGINAL_STATE SSF_RULE_CHANGED

pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
require() { command -v "$1" >/dev/null || fail "missing command: $1"; }
unexpected_error() {
  local status=$?
  if ((BASH_SUBSHELL == 0)); then
    printf 'FAIL: unexpected exit %s at line %s: %s\n' \
      "$status" "${BASH_LINENO[0]}" "$BASH_COMMAND" >&2
  fi
  return "$status"
}
trap unexpected_error ERR

stack_output() {
  local stack="$1" key="$2"
  "${AWS[@]}" cloudformation describe-stacks --stack-name "$stack" \
    --query "Stacks[0].Outputs[?OutputKey=='$key'].OutputValue | [0]" \
    --output text
}

stack_function() {
  local stack="$1" prefix="$2"
  "${AWS[@]}" cloudformation list-stack-resources --stack-name "$stack" \
    --output json | jq -er --arg prefix "$prefix" '
      [.StackResourceSummaries[]
       | select(.ResourceType == "AWS::Lambda::Function")
       | select(.LogicalResourceId | startswith($prefix))
       | .PhysicalResourceId] | unique
      | if length == 1 then .[0] else error("expected one function") end
    '
}

load_token() {
  local owner="$1" arn="$2"
  local destination="$WORK/$owner.token"
  "${AWS[@]}" secretsmanager get-secret-value --secret-id "$arn" --output json |
    jq -er '
      .SecretString | fromjson | .current.secret
      | select(type == "string" and length >= 16)
      | select(test("^[A-Za-z0-9._~+/=-]+$"))
    ' >"$destination"
  chmod 0600 "$destination"
  TOKEN_FILE["$owner"]="$destination"
}

api_request() {
  local owner="$1" method="$2" path="$3" body="${4:-}" output="$5"
  local header="$WORK/header-${owner}-${RANDOM}"
  printf 'authorization: Bearer %s\ncontent-type: application/json\n' \
    "$(<"${TOKEN_FILE[$owner]}")" >"$header"
  chmod 0600 "$header"
  if [[ -n "$body" ]]; then
    curl -sS --proto '=https' --connect-timeout 5 --max-time 20 \
      -o "$output" -w '%{http_code}' -X "$method" \
      -H "@$header" -d "$body" "${BASE[$owner]}$path"
  else
    curl -sS --proto '=https' --connect-timeout 5 --max-time 20 \
      -o "$output" -w '%{http_code}' -X "$method" \
      -H "@$header" "${BASE[$owner]}$path"
  fi
  rm -f "$header"
}

api_request_at() {
  local token_owner="$1" host_owner="$2" method="$3" path="$4" body="${5:-}" output="$6"
  local header="$WORK/header-${token_owner}-${RANDOM}"
  printf 'authorization: Bearer %s\ncontent-type: application/json\n' \
    "$(<"${TOKEN_FILE[$token_owner]}")" >"$header"
  chmod 0600 "$header"
  if [[ -n "$body" ]]; then
    curl -sS --proto '=https' --connect-timeout 5 --max-time 20 \
      -o "$output" -w '%{http_code}' -X "$method" \
      -H "@$header" -d "$body" "${BASE[$host_owner]}$path"
  else
    curl -sS --proto '=https' --connect-timeout 5 --max-time 20 \
      -o "$output" -w '%{http_code}' -X "$method" \
      -H "@$header" "${BASE[$host_owner]}$path"
  fi
  rm -f "$header"
}

create_stream() {
  local owner="$1" endpoint="$2" audience="$3" event_uri="$4"
  local body output="$WORK/$owner.stream.json" status
  body="$(jq -cn --arg endpoint "$endpoint" --arg audience "$audience" \
    --arg event "$event_uri" \
    '{endpoint:$endpoint,audience:$audience,event_types:[$event]}')"
  status="$(api_request "$owner" POST /admin/ssf/streams "$body" "$output")"
  [[ "$status" == "201" ]] || fail "$owner stream create returned HTTP $status: $(<"$output")"
  STREAM_ID["$owner"]="$(jq -er '.stream_id' "$output")"
  STREAM_REV["$owner"]="$(jq -er '.revision' "$output")"
}

scim_request() {
  local owner="$1" method="$2" path="$3" body="${4:-}" output="$5"
  local header="$WORK/scim-header-${owner}-${RANDOM}"
  printf 'authorization: Bearer %s\naccept: application/scim+json\n' \
    "$(<"${SCIM_TOKEN_FILE[$owner]}")" >"$header"
  if [[ -n "$body" ]]; then
    printf 'content-type: application/scim+json\n' >>"$header"
    curl -sS --proto '=https' --connect-timeout 5 --max-time 30 \
      -o "$output" -w '%{http_code}' -X "$method" \
      -H "@$header" --data-binary "$body" "${BASE[$owner]}$path"
  else
    curl -sS --proto '=https' --connect-timeout 5 --max-time 30 \
      -o "$output" -w '%{http_code}' -X "$method" \
      -H "@$header" "${BASE[$owner]}$path"
  fi
  rm -f "$header"
}

create_scim_user() {
  local owner="$1" email="$2"
  local slot="${3:-$owner}" body output status
  output="$WORK/$slot.scim-create.json"
  body="$(jq -cn --arg email "$email" --arg run "$RUN_ID-$slot" '{
    schemas:["urn:ietf:params:scim:schemas:core:2.0:User"],
    externalId:("agent-auth-ssf-e2e-"+$run),
    userName:$email,
    displayName:"Agent Auth SSF live e2e",
    active:true
  }')"
  status="$(scim_request "$owner" POST /scim/v2/Users "$body" "$output")"
  [[ "$status" == "201" || "$status" == "200" ]] ||
    fail "$slot SCIM create returned HTTP $status: $(<"$output")"
  USER_ID["$slot"]="$(jq -er '
    select(.active == true) | .id | select(type == "string" and length > 0)
  ' "$output")"
  USER_EMAIL["$slot"]="$email"
}

disable_scim_user() {
  local owner="$1"
  local slot="${2:-$owner}" encoded body output status
  encoded="$(jq -rn --arg value "${USER_ID[$slot]}" '$value|@uri')"
  body='{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}'
  output="$WORK/$slot.scim-disable.json"
  status="$(scim_request "$owner" PATCH "/scim/v2/Users/$encoded" "$body" "$output")"
  [[ "$status" == "200" ]] ||
    fail "$slot SCIM disable returned HTTP $status: $(<"$output")"
  jq -e '.active == false' "$output" >/dev/null ||
    fail "$slot SCIM disable did not return inactive user"
}

login_magic_link() {
  local owner="$1"
  local slot="${2:-$owner}"
  local email="${USER_EMAIL[$slot]}"
  local jar="$WORK/$slot.cookies" request="$WORK/$slot.magic-request.json"
  local messages="$WORK/$slot.messages.json" status link=""
  status="$(curl -sS --proto '=https' --connect-timeout 5 --max-time 30 \
    -c "$jar" -o "$request" -w '%{http_code}' -X POST \
    -H 'content-type: application/json' \
    --data-binary "$(jq -cn --arg email "$email" '{email:$email}')" \
    "${BASE[$owner]}/login/magic-link")"
  [[ "$status" == "200" ]] ||
    fail "$slot magic-link request returned HTTP $status: $(<"$request")"
  for _ in $(seq 1 30); do
    status="$(api_request "$owner" GET /admin/messages "" "$messages")"
    if [[ "$status" == "200" ]]; then
      link="$(jq -er --arg email "$email" '
        first(.messages[] | select(.kind=="magic_link" and .recipient==$email) | .body)
      ' "$messages" 2>/dev/null || true)"
    fi
    [[ -n "$link" ]] && break
    sleep 2
  done
  [[ "$link" == "${BASE[$owner]}/login/callback?"* ]] ||
    fail "$slot magic-link message was not observed for the email recipient"
  status="$(curl -sS --proto '=https' --connect-timeout 5 --max-time 30 \
    -b "$jar" -c "$jar" -o /dev/null -w '%{http_code}' "$link")"
  [[ "$status" == "303" ]] ||
    fail "$slot magic-link callback returned HTTP $status"
  grep -q '__Host-agent_auth_session' "$jar" ||
    fail "$slot magic-link callback did not create a session"
}

set_account_password() {
  local owner="$1"
  local slot="${2:-$owner}"
  local output="$WORK/$slot.password.json"
  local password status
  password="SSF live $(openssl rand -base64 24) 123!"
  status="$(curl -sS --proto '=https' --connect-timeout 5 --max-time 30 \
    -b "$WORK/$slot.cookies" -c "$WORK/$slot.cookies" -o "$output" \
    -w '%{http_code}' -X PUT -H 'content-type: application/json' \
    --data-binary "$(jq -cn --arg password "$password" '{new_password:$password}')" \
    "${BASE[$owner]}/account/password")"
  [[ "$status" == "204" ]] ||
    fail "$slot password enrollment returned HTTP $status: $(<"$output")"
}

revoke_current_session() {
  local owner="$1"
  local slot="${2:-$owner}"
  local sessions="$WORK/$slot.sessions.json"
  local handle encoded status output="$WORK/$slot.session-revoke.json"
  status="$(curl -sS --proto '=https' --connect-timeout 5 --max-time 30 \
    -b "$WORK/$slot.cookies" -o "$sessions" -w '%{http_code}' \
    "${BASE[$owner]}/account/sessions")"
  [[ "$status" == "200" ]] ||
    fail "$slot session list returned HTTP $status: $(<"$sessions")"
  handle="$(jq -er 'first(.[] | select(.current == true) | .id)' "$sessions")"
  encoded="$(jq -rn --arg value "$handle" '$value|@uri')"
  status="$(curl -sS --proto '=https' --connect-timeout 5 --max-time 30 \
    -b "$WORK/$slot.cookies" -c "$WORK/$slot.cookies" -o "$output" \
    -w '%{http_code}' -X DELETE \
    "${BASE[$owner]}/account/sessions/$encoded")"
  [[ "$status" == "204" ]] ||
    fail "$slot current-session revoke returned HTTP $status: $(<"$output")"
}

find_security_event() {
  local owner="$1" slot="$2" action="$3" subject="$4" from="$5"
  local output="$WORK/$slot.security-events.json" status event=""
  for _ in $(seq 1 60); do
    status="$(api_request "$owner" GET \
      "/admin/security-events?from=$from&through=$(($(date +%s) + 60))&limit=500" \
      "" "$output")"
    if [[ "$status" == "200" ]]; then
      event="$(jq -cer --arg action "$action" --arg subject "$subject" '
        first(.events[]
          | select(.event.action==$action)
          | select(.event.outcome=="success")
          | select(.event.subject.kind=="user" and .event.subject.id==$subject)
          | .event)
      ' "$output" 2>/dev/null || true)"
    fi
    [[ -n "$event" ]] && break
    sleep 2
  done
  [[ -n "$event" ]] ||
    fail "$slot canonical $action event was not observable through Admin API"
  EVENT_ID["$slot"]="$(jq -er '.event_id' <<<"$event")"
  printf '%s\n' "$event" >"$WORK/$slot.event.json"
}

receiver_item() {
  local target="$1"
  "${AWS[@]}" dynamodb scan --table-name "$RECEIVER_TABLE" \
    --filter-expression '#target = :target' \
    --expression-attribute-names '{"#target":"target"}' \
    --expression-attribute-values "{\":target\":{\"S\":\"$target\"}}" \
    --consistent-read --output json
}

wait_receiver() {
  local target="$1" minimum="$2"
  local output="$WORK/$target.receiver.json"
  for _ in $(seq 1 72); do
    receiver_item "$target" >"$output"
    if jq -e --argjson minimum "$minimum" '
      (.Items | length) == 1
      and (.Items[0].receive_count.N | tonumber) >= $minimum
    ' "$output" >/dev/null; then
      return
    fi
    sleep 5
  done
  fail "$target receiver did not observe $minimum delivery attempts"
}

wait_delivery() {
  local owner="$1" minimum="$2" status
  local output="$WORK/$owner.deliveries.json"
  for _ in $(seq 1 72); do
    status="$(api_request "$owner" GET \
      "/admin/ssf/streams/${STREAM_ID[$owner]}/deliveries" "" "$output")"
    if [[ "$status" == "200" ]] && jq -e \
      --arg event "${EVENT_ID[$owner]}" --argjson minimum "$minimum" '
        .deliveries[]
        | select(.event_id == $event)
        | .status == "delivered"
          and .attempts >= $minimum
          and (.attempt_history | length) >= $minimum
          and (all(.attempt_history[]; .set_sha256 and .signing_kid))
      ' "$output" >/dev/null; then
      return
    fi
    sleep 5
  done
  fail "$owner delivery did not reach delivered with $minimum attempts"
}

wait_delivery_status() {
  local owner="$1" revision="$2" event_id="$3" expected="$4"
  local output="$WORK/$owner.$event_id.delivery.json" status
  for _ in $(seq 1 72); do
    status="$(api_request "$owner" GET \
      "/admin/ssf/streams/${STREAM_ID[$owner]}/deliveries/$revision/$event_id" \
      "" "$output")"
    if [[ "$status" == "200" ]] &&
      jq -e --arg expected "$expected" '.status == $expected' "$output" >/dev/null; then
      return
    fi
    sleep 5
  done
  fail "$owner delivery $event_id did not reach $expected"
}

receiver_totals() {
  local target="$1"
  receiver_item "$target" | jq -c '{
    items:(.Items|length),
    receives:([.Items[]?.receive_count.N|tonumber]|add//0),
    duplicates:([.Items[]?.dedupe_count.N|tonumber]|add//0)
  }'
}

receiver_state() {
  "${AWS[@]}" dynamodb scan --table-name "$RECEIVER_TABLE" \
    --consistent-read --output json |
    jq -Sc '.Items | sort_by(.jti.S)'
}

post_set() {
  local target="$1" compact_set="$2"
  curl -sS -o /dev/null -w '%{http_code}' --proto '=https' \
    --connect-timeout 5 --max-time 20 -X POST \
    -H 'content-type: application/secevent+jwt' \
    --data-binary "$compact_set" "$RECEIVER_URL/receive/$target/success"
}

delete_object_versions() {
  local bucket="$1" key="$2" listing="$WORK/object-versions-${RANDOM}.json"
  [[ -n "$bucket" && -n "$key" ]] || return
  if ! "${AWS[@]}" s3api list-object-versions --bucket "$bucket" --prefix "$key" \
    --output json >"$listing" 2>/dev/null; then
    cleanup_failed=1
    return
  fi
  local deletion="$WORK/delete-object-versions-${RANDOM}.json"
  jq --arg key "$key" '{
    Objects:[(.Versions[]?,.DeleteMarkers[]?)|select(.Key==$key)|{Key,VersionId}],
    Quiet:true
  }' "$listing" >"$deletion"
  if [[ "$(jq '.Objects|length' "$deletion")" -gt 0 ]]; then
    "${AWS[@]}" s3api delete-objects --bucket "$bucket" \
      --delete "file://$deletion" >/dev/null || cleanup_failed=1
  fi
}

delete_ssf_rows() {
  local owner="$1" tenant="$2"
  local stream="${STREAM_ID[$owner]:-}"
  [[ -n "$stream" && -n "${SSF_TABLE[$owner]:-}" ]] || return
  local rows="$WORK/$owner.ssf-rows.json"
  local values="$WORK/$owner.ssf-values.json"
  jq -n --arg tenant "$tenant" --arg prefix "delivery#$stream#" '{
    ":tenant":{S:$tenant},":prefix":{S:$prefix}
  }' >"$values"
  if ! "${AWS[@]}" dynamodb query --table-name "${SSF_TABLE[$owner]}" \
    --key-condition-expression \
      'tenant_id = :tenant AND begins_with(record_key, :prefix)' \
    --expression-attribute-values "file://$values" \
    --projection-expression 'tenant_id,record_key' --output json >"$rows" 2>/dev/null; then
    cleanup_failed=1
    return
  fi
  while IFS= read -r key; do
    "${AWS[@]}" dynamodb delete-item --table-name "${SSF_TABLE[$owner]}" \
      --key "$key" >/dev/null || cleanup_failed=1
  done < <(jq -c '.Items[] | {tenant_id:.tenant_id,record_key:.record_key}' "$rows")
  local transaction="$WORK/$owner.ssf-delete-transaction.json"
  jq -n --arg table "${SSF_TABLE[$owner]}" --arg tenant "$tenant" \
    --arg stream_key "stream#$stream" '[
      {Delete:{
        TableName:$table,
        Key:{tenant_id:{S:$tenant},record_key:{S:$stream_key}},
        ConditionExpression:"attribute_exists(record_key)"
      }},
      {Update:{
        TableName:$table,
        Key:{tenant_id:{S:$tenant},record_key:{S:"meta#stream-registry"}},
        UpdateExpression:"SET #count = #count - :one",
        ConditionExpression:"#entity = :registry AND #count >= :one",
        ExpressionAttributeNames:{
          "#count":"registered_stream_count",
          "#entity":"entity_type"
        },
        ExpressionAttributeValues:{
          ":one":{N:"1"},
          ":registry":{S:"stream_registry"}
        }
      }}
    ]' >"$transaction"
  "${AWS[@]}" dynamodb transact-write-items \
    --transact-items "file://$transaction" >/dev/null || cleanup_failed=1
}

revoke_stream() {
  local owner="$1" tenant="$2" status
  local output="$WORK/$owner.revoke.json"
  status="$(api_request "$owner" POST \
    "/admin/ssf/streams/${STREAM_ID[$owner]}/revoke" \
    "$(jq -cn --argjson revision "${STREAM_REV[$owner]}" \
      '{expected_revision:$revision}')" "$output")"
  [[ "$status" == "200" ]] ||
    fail "$owner stream revoke returned HTTP $status: $(<"$output")"
  STREAM_REV["$owner"]="$(jq -er '.revision' "$output")"
  REVOKED["$owner"]=1

  local operation="${STREAM_ID[$owner]}:revision:${STREAM_REV[$owner]}"
  local values="$WORK/$owner.audit-values.json" audit="$WORK/$owner.audit.json"
  jq -n --arg tenant "$tenant" '{
    ":tenant":{S:$tenant},":from":{N:"0"},":through":{N:"9999999999"},
    ":action":{S:"ssf.stream.revoke"}
  }' >"$values"
  for _ in $(seq 1 24); do
    "${AWS[@]}" dynamodb query --table-name "${SECURITY_TABLE[$owner]}" \
      --index-name tenant_occurred_at-index \
      --key-condition-expression \
        'tenant_id = :tenant AND occurred_at BETWEEN :from AND :through' \
      --filter-expression '#action = :action' \
      --expression-attribute-names '{"#action":"action"}' \
      --expression-attribute-values "file://$values" --output json >"$audit"
    if jq -e --arg operation "$operation" '
      any(.Items[]?; (.envelope.S | fromjson | .correlation.operation_id) == $operation)
    ' "$audit" >/dev/null; then
      return
    fi
    sleep 5
  done
  fail "$owner stream revoke audit was not persisted"
}

set_schedule_state() {
  local stack_kind="$1" desired="$2"
  local rule="${SSF_RULE[$stack_kind]}"
  local state
  if [[ "$desired" == "ENABLED" ]]; then
    "${AWS[@]}" events enable-rule --name "$rule" >/dev/null
  else
    "${AWS[@]}" events disable-rule --name "$rule" >/dev/null
  fi
  SSF_RULE_CHANGED["$stack_kind"]=1
  for _ in $(seq 1 30); do
    state="$("${AWS[@]}" events describe-rule --name "$rule" \
      --query State --output text)"
    [[ "$state" == "$desired" ]] && return
    sleep 2
  done
  fail "$stack_kind SSF schedule did not become $desired"
}

deploy_receiver() {
  local targets="$1"
  if [[ -z "$RECEIVER_URL" ]]; then
    "${AWS[@]}" cloudformation deploy --stack-name "$RECEIVER_STACK" \
      --template-file "$HERE/ssf_receiver_stack.yaml" \
      --capabilities CAPABILITY_NAMED_IAM \
      --parameter-overrides "CodeBucket=$CODE_BUCKET" "CodeKey=$CODE_KEY" \
      --no-fail-on-empty-changeset >/dev/null
    RECEIVER_URL="$(stack_output "$RECEIVER_STACK" ReceiverUrl)"
    RECEIVER_TABLE="$(stack_output "$RECEIVER_STACK" ReceiverTableName)"
  fi
  local config="$WORK/receiver-targets-${RANDOM}.json"
  jq -n --arg targets "$targets" '{
    jti:{S:"__config__"},
    expected_targets:{S:$targets}
  }' >"$config"
  "${AWS[@]}" dynamodb put-item --table-name "$RECEIVER_TABLE" \
    --item "file://$config" >/dev/null
}

delete_fixture_user() {
  local owner="$1" slot="$2"
  local id="${USER_ID[$slot]:-}" encoded status
  [[ -n "$id" ]] || return
  encoded="$(jq -rn --arg value "$id" '$value|@uri')"
  status="$(api_request "$owner" DELETE "/admin/users/$encoded" "" \
    "$WORK/$slot.user-delete.json" 2>/dev/null || true)"
  [[ "$status" == "200" || "$status" == "404" ]] || cleanup_failed=1
}

cleanup() {
  local original_status=$?
  trap - EXIT INT TERM
  set +e
  for owner in dev t1 t2; do
    if [[ -n "${STREAM_ID[$owner]:-}" && "${REVOKED[$owner]:-0}" != "1" ]]; then
      api_request "$owner" POST \
        "/admin/ssf/streams/${STREAM_ID[$owner]}/revoke" \
        "$(jq -cn --argjson revision "${STREAM_REV[$owner]:-1}" \
          '{expected_revision:$revision}')" "$WORK/$owner.revoke.json" >/dev/null || true
    fi
  done
  for stack_kind in dev saas; do
    if [[ "${SSF_RULE_CHANGED[$stack_kind]:-0}" == "1" &&
      -n "${SSF_RULE[$stack_kind]:-}" ]]; then
      if [[ "${SSF_RULE_ORIGINAL_STATE[$stack_kind]}" == "ENABLED" ]]; then
        "${AWS[@]}" events enable-rule --name "${SSF_RULE[$stack_kind]}" >/dev/null ||
          cleanup_failed=1
      else
        "${AWS[@]}" events disable-rule --name "${SSF_RULE[$stack_kind]}" >/dev/null ||
          cleanup_failed=1
      fi
      SSF_RULE_CHANGED["$stack_kind"]=0
    fi
  done
  delete_ssf_rows dev default
  delete_ssf_rows t1 t1
  delete_ssf_rows t2 t2
  delete_fixture_user dev dev-revoke
  delete_fixture_user dev dev
  delete_fixture_user t1 t1
  delete_fixture_user t2 t2
  if "${AWS[@]}" cloudformation describe-stacks --stack-name "$RECEIVER_STACK" \
    >/dev/null 2>&1; then
    "${AWS[@]}" cloudformation delete-stack --stack-name "$RECEIVER_STACK" ||
      cleanup_failed=1
    "${AWS[@]}" cloudformation wait stack-delete-complete \
      --stack-name "$RECEIVER_STACK" || cleanup_failed=1
  fi
  if [[ -n "$CODE_BUCKET" ]]; then
    delete_object_versions "$CODE_BUCKET" "$CODE_KEY"
  fi
  rm -rf "$WORK"
  if [[ "$cleanup_failed" != "0" ]]; then
    printf 'FAIL: SSF E2E cleanup was incomplete\n' >&2
    if [[ "$original_status" == "0" ]]; then
      exit 1
    fi
  fi
  exit "$original_status"
}
trap cleanup EXIT INT TERM

[[ "$REGION" == "us-east-1" ]] || fail "SSF live acceptance requires us-east-1"
for command in aws curl jq openssl zip node; do require "$command"; done

"${AWS[@]}" sts get-caller-identity >/dev/null
for stack in "$DEV_STACK" "$SAAS_STACK"; do
  status="$("${AWS[@]}" cloudformation describe-stacks --stack-name "$stack" \
    --query 'Stacks[0].StackStatus' --output text)"
  [[ "$status" == "UPDATE_COMPLETE" ]] || fail "$stack is $status"
done

BASE[dev]="$(stack_output "$DEV_STACK" AdminUrl)"
BASE[dev]="${BASE[dev]%/admin}"
DEV_ARN="$(stack_output "$DEV_STACK" AdminSecretArn)"
load_token dev "$DEV_ARN"
DEV_SCIM_ARN="$(stack_output "$DEV_STACK" ScimSecretArn)"
load_token dev-scim "$DEV_SCIM_ARN"
SCIM_TOKEN_FILE[dev]="${TOKEN_FILE[dev-scim]}"

SAAS_AUTH_FN="$(stack_function "$SAAS_STACK" AuthFn)"
"${AWS[@]}" lambda get-function-configuration --function-name "$SAAS_AUTH_FN" \
  --query 'Environment.Variables.{zone:AGENT_AUTH_ZONE,bootstrap:AGENT_AUTH_BOOTSTRAP_CONFIG_SECRET_ARN}' \
  --output json >"$WORK/saas-runtime.json"
SAAS_ZONE="$(jq -er '.zone' "$WORK/saas-runtime.json")"
"${AWS[@]}" secretsmanager get-secret-value \
  --secret-id "$(jq -er '.bootstrap' "$WORK/saas-runtime.json")" \
  --query SecretString --output text >"$WORK/saas-bootstrap.json"
jq -e '
  .schema_version == 1 and
  (.saas_tenants == ["t1", "t2"]) and
  (.tenant_admin_secret_arns | keys | sort) == ["t1", "t2"]
' "$WORK/saas-bootstrap.json" >/dev/null ||
  fail "deployed SaaS bootstrap config is malformed"
BASE[t1]="https://t1.$SAAS_ZONE"
BASE[t2]="https://t2.$SAAS_ZONE"
for tenant in t1 t2; do
  arn="$(jq -er --arg tenant "$tenant" \
    '.tenant_admin_secret_arns[$tenant]' "$WORK/saas-bootstrap.json")"
  load_token "$tenant" "$arn"
done
SAAS_SCIM_ARNS="$(stack_output "$SAAS_STACK" ScimSecretArns)"
for tenant in t1 t2; do
  arn="$(jq -er --arg tenant "$tenant" '.[$tenant]' <<<"$SAAS_SCIM_ARNS")"
  load_token "$tenant-scim" "$arn"
  SCIM_TOKEN_FILE["$tenant"]="${TOKEN_FILE[$tenant-scim]}"
done

for owner in dev t1 t2; do
  stack="$DEV_STACK"; [[ "$owner" != "dev" ]] && stack="$SAAS_STACK"
  SECURITY_TABLE["$owner"]="$(stack_output "$stack" SecurityEventsTableName)"
  SSF_TABLE["$owner"]="$(stack_output "$stack" SsfDeliveriesTableName)"
done
SSF_RULE[dev]="$(stack_output "$DEV_STACK" SsfDeliveryScheduleName)"
SSF_RULE[saas]="$(stack_output "$SAAS_STACK" SsfDeliveryScheduleName)"
for stack_kind in dev saas; do
  SSF_RULE_ORIGINAL_STATE["$stack_kind"]="$("${AWS[@]}" events describe-rule \
    --name "${SSF_RULE[$stack_kind]}" --query State --output text)"
  [[ "${SSF_RULE_ORIGINAL_STATE[$stack_kind]}" == "ENABLED" ]] ||
    fail "$stack_kind SSF delivery schedule must be enabled before acceptance"
  SSF_RULE_CHANGED["$stack_kind"]=0
done

DEV_ISSUER="${BASE[dev]}"
T1_ISSUER="${BASE[t1]}"
T2_ISSUER="${BASE[t2]}"
ACCOUNT_DISABLED="https://schemas.openid.net/secevent/risc/event-type/account-disabled"
CREDENTIAL_CHANGE="https://schemas.openid.net/secevent/caep/event-type/credential-change"
SESSION_REVOKED="https://schemas.openid.net/secevent/caep/event-type/session-revoked"
DEV_AUD="urn:agent-auth:e2e:ssf:${RUN_ID}:dev"
T1_AUD="urn:agent-auth:e2e:ssf:${RUN_ID}:t1"
T2_AUD="urn:agent-auth:e2e:ssf:${RUN_ID}:t2"

for owner in dev t1 t2; do
  metadata="$WORK/$owner.metadata.json"
  curl -fsS --proto '=https' --connect-timeout 5 --max-time 20 \
    "${BASE[$owner]}/.well-known/ssf-configuration" >"$metadata"
  jq -e --arg issuer "${BASE[$owner]}" '
    .spec_version=="1_0" and .issuer==$issuer
    and .jwks_uri==($issuer+"/jwks.json")
  ' "$metadata" >/dev/null || fail "$owner SSF metadata mismatch"
done
pass "Dev/SaaS t1/t2 publish tenant-exact SSF metadata"

set_schedule_state dev DISABLED
set_schedule_state saas DISABLED

create_scim_user dev "e2e-ssf-${RUN_ID}@example.com"
create_scim_user t1 "e2e-ssf-${RUN_ID}-t1@example.com"
create_scim_user t2 "e2e-ssf-${RUN_ID}-t2@example.com"
pass "fixture users were provisioned through tenant-scoped SCIM APIs"

INITIAL_TARGETS="$(jq -cn \
  --arg di "$DEV_ISSUER" --arg da "$DEV_AUD" --arg de "$ACCOUNT_DISABLED" \
  --arg ds "${USER_ID[dev]}" \
  --arg i1 "$T1_ISSUER" --arg a1 "$T1_AUD" --arg e1 "$CREDENTIAL_CHANGE" \
  --arg s1 "${USER_ID[t1]}" \
  --arg i2 "$T2_ISSUER" --arg a2 "$T2_AUD" --arg e2 "$SESSION_REVOKED" \
  --arg s2 "${USER_ID[t2]}" '{
    dev:{
      issuer:$di,audience:$da,eventUri:$de,txns:["pending"],
      subject:{format:"iss_sub",iss:$di,sub:$ds},
      payload:{event_timestamp:null}
    },
    t1:{
      issuer:$i1,audience:$a1,eventUri:$e1,txns:["pending"],
      subject:{format:"iss_sub",iss:$i1,sub:$s1},
      payload:{
        event_timestamp:null,credential_type:"password",change_type:"update"
      }
    },
    t2:{
      issuer:$i2,audience:$a2,eventUri:$e2,txns:["pending"],
      subject:{format:"complex"},
      payload:{event_timestamp:null}
    }
  }')"

CODE_BUCKET="$("${AWS[@]}" cloudformation describe-stacks --stack-name CDKToolkit \
  --query "Stacks[0].Outputs[?OutputKey=='BucketName'].OutputValue | [0]" \
  --output text)"
[[ "$CODE_BUCKET" != "None" && -n "$CODE_BUCKET" ]] ||
  fail "CDK bootstrap bucket not found"
cp "$HERE/ssf_receiver.mjs" "$WORK/index.mjs"
(cd "$WORK" && zip -q receiver.zip index.mjs)
"${AWS[@]}" s3 cp "$WORK/receiver.zip" "s3://$CODE_BUCKET/$CODE_KEY" \
  --only-show-errors
deploy_receiver "$INITIAL_TARGETS"
invalid_status="$(curl -sS -o /dev/null -w '%{http_code}' --proto '=https' \
  --connect-timeout 5 --max-time 20 "$RECEIVER_URL/receive/dev/success")"
[[ "$invalid_status" == "401" ]] || fail "receiver accepted unauthenticated request"
pass "transient receiver is reachable only with a valid SET"

create_stream dev "$RECEIVER_URL/receive/dev/success" "$DEV_AUD" "$ACCOUNT_DISABLED"
create_stream t1 "$RECEIVER_URL/receive/t1/timeout-once" "$T1_AUD" "$CREDENTIAL_CHANGE"
create_stream t2 "$RECEIVER_URL/receive/t2/success" "$T2_AUD" "$SESSION_REVOKED"

cross_body="$(jq -cn --arg endpoint "$RECEIVER_URL/receive/t2/success" \
  --arg audience "$T2_AUD" --arg event "$SESSION_REVOKED" \
  '{endpoint:$endpoint,audience:$audience,event_types:[$event]}')"
cross_status="$(api_request_at t1 t2 POST /admin/ssf/streams "$cross_body" \
  "$WORK/cross-tenant.json")"
[[ "$cross_status" == "401" ]] ||
  fail "t1 credential created a t2 stream: HTTP $cross_status"
pass "tenant Admin credentials cannot subscribe across SaaS tenant hosts"

EVENT_FROM="$(($(date +%s) - 5))"
disable_scim_user dev
login_magic_link t1
set_account_password t1
login_magic_link t2
revoke_current_session t2

find_security_event dev dev user.disable "${USER_ID[dev]}" "$EVENT_FROM"
find_security_event t1 t1 credential.password.set "${USER_ID[t1]}" "$EVENT_FROM"
find_security_event t2 t2 session.revoke "${USER_ID[t2]}" "$EVENT_FROM"
T2_SESSION_FINGERPRINT="$(jq -er '
  .correlation.session_fingerprint
  | select(type == "string" and test("^[A-Za-z0-9_-]{43}$"))
' "$WORK/t2.event.json")"
TARGETS="$(jq -cn \
  --arg di "$DEV_ISSUER" --arg da "$DEV_AUD" --arg de "$ACCOUNT_DISABLED" \
  --arg dt "${EVENT_ID[dev]}" --arg ds "${USER_ID[dev]}" \
  --arg i1 "$T1_ISSUER" --arg a1 "$T1_AUD" --arg e1 "$CREDENTIAL_CHANGE" \
  --arg t1t "${EVENT_ID[t1]}" --arg s1 "${USER_ID[t1]}" \
  --arg i2 "$T2_ISSUER" --arg a2 "$T2_AUD" --arg e2 "$SESSION_REVOKED" \
  --arg t2t "${EVENT_ID[t2]}" --arg s2 "${USER_ID[t2]}" \
  --arg sf "$T2_SESSION_FINGERPRINT" '{
    dev:{
      issuer:$di,audience:$da,eventUri:$de,txns:[$dt],
      subject:{format:"iss_sub",iss:$di,sub:$ds},
      payload:{event_timestamp:null}
    },
    t1:{
      issuer:$i1,audience:$a1,eventUri:$e1,txns:[$t1t],
      subject:{format:"iss_sub",iss:$i1,sub:$s1},
      payload:{
        event_timestamp:null,credential_type:"password",change_type:"update"
      }
    },
    t2:{
      issuer:$i2,audience:$a2,eventUri:$e2,txns:[$t2t],
      subject:{
        format:"complex",
        session:{format:"opaque",id:$sf},
        user:{format:"iss_sub",iss:$i2,sub:$s2},
        tenant:{format:"opaque",id:"t2"}
      },
      payload:{event_timestamp:null}
    }
  }')"
deploy_receiver "$TARGETS"

wait_delivery_status dev 1 "${EVENT_ID[dev]}" pending
wait_delivery_status t1 1 "${EVENT_ID[t1]}" pending
wait_delivery_status t2 1 "${EVENT_ID[t2]}" pending
pass "real mutations projected their canonical event IDs into pending outboxes"

set_schedule_state dev ENABLED
set_schedule_state saas ENABLED

wait_receiver dev 1
wait_receiver t1 2
wait_receiver t2 1
wait_delivery dev 1
wait_delivery t1 2
wait_delivery t2 1

jq -e --arg issuer "$DEV_ISSUER" --arg audience "$DEV_AUD" \
  --arg event "$ACCOUNT_DISABLED" '
  .Items[0] | .issuer.S==$issuer and .audience.S==$audience
  and .event_uri.S==$event and (.dedupe_count.N|tonumber)==0
' "$WORK/dev.receiver.json" >/dev/null || fail "Dev receiver evidence mismatch"
jq -e --arg issuer "$T1_ISSUER" --arg audience "$T1_AUD" \
  --arg event "$CREDENTIAL_CHANGE" '
  .Items[0] | .issuer.S==$issuer and .audience.S==$audience
  and .event_uri.S==$event and (.receive_count.N|tonumber)>=2
  and (.dedupe_count.N|tonumber)>=1
' "$WORK/t1.receiver.json" >/dev/null || fail "t1 retry/dedupe evidence mismatch"
jq -e --arg issuer "$T2_ISSUER" --arg audience "$T2_AUD" \
  --arg event "$SESSION_REVOKED" '
  .Items[0] | .issuer.S==$issuer and .audience.S==$audience
  and .event_uri.S==$event and (.dedupe_count.N|tonumber)==0
' "$WORK/t2.receiver.json" >/dev/null || fail "t2 receiver evidence mismatch"
jq -e --arg event "${EVENT_ID[t1]}" '
  .deliveries[]
  | select(.event_id==$event)
  | any(.attempt_history[];
      .outcome=="retryable" and .error_class=="timeout")
    and .attempt_history[-1].outcome=="accepted"
' "$WORK/t1.deliveries.json" >/dev/null ||
  fail "t1 delivery ledger did not retain timeout then accepted outcomes"
pass "independent receiver verified all three event types and tenant bindings"
pass "timeout retried the exact SET and receiver deduplicated one jti"

dev_set="$(jq -er '.Items[0].compact_set.S' "$WORK/dev.receiver.json")"
t1_set="$(jq -er '.Items[0].compact_set.S' "$WORK/t1.receiver.json")"
IFS=. read -r set_header set_payload set_signature <<<"$dev_set"
replacement=A
[[ "${set_signature:0:1}" == "A" ]] && replacement=B
forged_set="$set_header.$set_payload.$replacement${set_signature:1}"

rejected_state_before="$(receiver_state)"
forged_status="$(post_set dev "$forged_set")"
[[ "$forged_status" == "401" ]] ||
  fail "receiver accepted a SET with a forged signature: HTTP $forged_status"
rejected_state_after="$(receiver_state)"
[[ "$rejected_state_after" == "$rejected_state_before" ]] ||
  fail "forged SET mutated receiver state"

cross_target_status="$(post_set t2 "$t1_set")"
[[ "$cross_target_status" == "401" ]] ||
  fail "t2 receiver accepted a valid t1 SET: HTTP $cross_target_status"
rejected_state_after="$(receiver_state)"
[[ "$rejected_state_after" == "$rejected_state_before" ]] ||
  fail "cross-tenant SET mutated receiver state"
pass "receiver rejected forged and cross-tenant SETs without mutating state"

duplicate_before="$(receiver_totals dev)"
duplicate_status="$(post_set dev "$dev_set")"
[[ "$duplicate_status" == "202" ]] ||
  fail "receiver rejected an exact SET replay: HTTP $duplicate_status"
duplicate_after="$(receiver_totals dev)"
jq -en --argjson before "$duplicate_before" --argjson after "$duplicate_after" '
  $after.items == $before.items
  and $after.receives == ($before.receives + 1)
  and $after.duplicates == ($before.duplicates + 1)
' >/dev/null || fail \
  "exact SET replay did not deduplicate: before=$duplicate_before after=$duplicate_after"
pass "receiver returned 202 for an exact replay and incremented dedupe once"

set_schedule_state dev DISABLED
receiver_before_revoke="$(receiver_totals dev)"
create_scim_user dev "e2e-ssf-${RUN_ID}-revoke@example.com" dev-revoke
REVOKE_FROM="$(($(date +%s) - 2))"
disable_scim_user dev dev-revoke
find_security_event dev revoke user.disable "${USER_ID[dev-revoke]}" "$REVOKE_FROM"
wait_delivery_status dev 1 "${EVENT_ID[revoke]}" pending
revoke_stream dev default
set_schedule_state dev ENABLED
wait_delivery_status dev 1 "${EVENT_ID[revoke]}" suppressed
receiver_after_revoke="$(receiver_totals dev)"
[[ "$receiver_after_revoke" == "$receiver_before_revoke" ]] ||
  fail "revoked stream reached receiver: before=$receiver_before_revoke after=$receiver_after_revoke"
pass "revoke-before-lease changed pending delivery to suppressed with zero receiver calls"

revoke_stream t1 t1
revoke_stream t2 t2
pass "receiver revocation was enforced and persisted in each tenant audit ledger"

for owner in dev t1 t2; do
  for _ in $(seq 1 36); do
    status="$("${AWS[@]}" dynamodb get-item \
      --table-name "${SECURITY_TABLE[$owner]}" \
      --key "{\"event_id\":{\"S\":\"${EVENT_ID[$owner]}\"}}" \
      --consistent-read --query 'Item.delivery_status.S' --output text)"
    [[ "$status" == "archived" ]] && break
    sleep 5
  done
  [[ "$status" == "archived" ]] || fail "$owner canonical event was not archived"
done
pass "canonical source events remained independently archived and auditable"
printf 'PASS: SSF live interoperability acceptance completed for run %s\n' "$RUN_ID"
