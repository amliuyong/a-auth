#!/usr/bin/env bash
# Live acceptance for Issue #24. By default this validates AgentAuthDev and
# tenant t1 on AgentAuthSaas with the selected AWS profile in us-east-1.
#
# The test covers:
#   - an Auth Lambda event written to DynamoDB, exported by the tenant Admin API,
#     archived to S3, and queried through the projected Athena table;
#   - the Auth Lambda's real DynamoDB-to-SQS fallback plus a controlled ingress
#     fixture whose prior delivery history is preserved;
#   - a 17-Grant lifecycle cascade delivered through the bounded SQS batch path;
#   - durable dead_letter_pending recovery into the FIFO incident queue followed
#     by scheduled S3 redrive;
#   - deployed stream/SQS wiring, seven-year failure retention, pagination, and
#     real producer-path ALARM -> OK transitions for all five alarms.
#
# Usage:
#   AWS_PROFILE=default ./e2e/security_events.sh
#   STACKS="AgentAuthDev" AWS_PROFILE=default ./e2e/security_events.sh
#   STACKS="AgentAuthSaas" SAAS_TENANT=t2 AWS_PROFILE=default ./e2e/security_events.sh
set -euo pipefail
set +x

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="${PROFILE:-${AWS_PROFILE:-default}}"
REGION="${REGION:-${AWS_REGION:-us-east-1}}"
STACKS="${STACKS:-AgentAuthDev AgentAuthSaas}"
SAAS_TENANT="${SAAS_TENANT:-t1}"

CURRENT_STACK=""
API_URL=""
TENANT=""
ADMIN_TOKEN=""
USER_ID=""
SECURITY_TABLE=""
GRANTS_TABLE=""
LARGE_BATCH_FROM=""
LARGE_BATCH_TRIGGERED=0
DISCOVERED_BATCH_SUBJECTS=0
DISCOVERED_BATCH_ARCHIVES=0
ARCHIVE_BUCKET=""
ARCHIVE_DLQ=""
INGRESS_QUEUE=""
INGRESS_DLQ=""
STREAM_FAILURE_NOTIFICATION_QUEUE=""
STREAM_FAILURE_NOTIFICATION_DLQ=""
FAILURE_BUCKET=""
INGRESS_FAILURE_BUCKET=""
AUTH_FN=""
AUTH_LOG_GROUP=""
ARCHIVE_FN=""
GLUE_DATABASE=""
ATHENA_PREFIX=""
RESULT_EVENT_ID=""
ARCHIVE_RESERVED_CONCURRENCY=""
ARCHIVE_CONCURRENCY_BLOCKED=0
AUTH_CONFIG_MUTATED=0
declare -a FIXTURE_IDS=()
declare -a FIXTURE_KEYS=()
declare -a BATCH_FIXTURE_IDS=()
declare -a BATCH_FIXTURE_KEYS=()
declare -a GRANT_KEYS=()

pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
require() { command -v "$1" >/dev/null || fail "missing command: $1"; }

for command in aws curl jq openssl python3; do
  require "$command"
done

[[ "$REGION" == "us-east-1" ]] ||
  fail "security-events E2E requires AWS region us-east-1 (got $REGION)"
[[ -z "${AWS_CONFIG_FILE:-}" ]] ||
  fail "security-events E2E rejects AWS_CONFIG_FILE overrides"
[[ -z "${AWS_SHARED_CREDENTIALS_FILE:-}" ]] ||
  fail "security-events E2E rejects AWS_SHARED_CREDENTIALS_FILE overrides"
while IFS= read -r endpoint_variable; do
  case "$endpoint_variable" in
    AWS_ENDPOINT_URL | AWS_ENDPOINT_URL_*)
      [[ -z "${!endpoint_variable}" ]] ||
        fail "security-events E2E rejects $endpoint_variable overrides"
      ;;
  esac
done < <(compgen -e)
export AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true

RUN_ID="$(date -u +%Y%m%d%H%M%S)-$(openssl rand -hex 4)"
WORK="$(mktemp -d)"
AWS=(aws --profile "$PROFILE" --region "$REGION")

restore_archive_concurrency() {
  local attempt current
  [[ "$ARCHIVE_CONCURRENCY_BLOCKED" == "1" && -n "$ARCHIVE_FN" ]] || return 0
  for attempt in $(seq 1 12); do
    if [[ -n "$ARCHIVE_RESERVED_CONCURRENCY" ]]; then
      "${AWS[@]}" lambda put-function-concurrency --function-name "$ARCHIVE_FN" \
        --reserved-concurrent-executions "$ARCHIVE_RESERVED_CONCURRENCY" >/dev/null 2>&1 || true
    else
      "${AWS[@]}" lambda delete-function-concurrency \
        --function-name "$ARCHIVE_FN" >/dev/null 2>&1 || true
    fi
    current="$("${AWS[@]}" lambda get-function-concurrency \
      --function-name "$ARCHIVE_FN" --query ReservedConcurrentExecutions \
      --output text 2>/dev/null)" || current="unavailable"
    [[ "$current" == "None" ]] && current=""
    if [[ "$current" == "$ARCHIVE_RESERVED_CONCURRENCY" ]]; then
      ARCHIVE_CONCURRENCY_BLOCKED=0
      return 0
    fi
    sleep 5
  done
  printf 'FAIL: could not restore reserved concurrency for %s after %s attempts\n' \
    "$ARCHIVE_FN" "$attempt" >&2
  return 1
}

restore_auth_environment() {
  local attempt current original="$WORK/$CURRENT_STACK.auth-environment.json"
  [[ "$AUTH_CONFIG_MUTATED" == "1" && -n "$AUTH_FN" && -s "$original" ]] || return 0
  for attempt in $(seq 1 12); do
    "${AWS[@]}" lambda update-function-configuration --function-name "$AUTH_FN" \
      --environment "file://$original" >/dev/null 2>&1 || true
    "${AWS[@]}" lambda wait function-updated-v2 --function-name "$AUTH_FN" \
      >/dev/null 2>&1 || true
    current="$("${AWS[@]}" lambda get-function-configuration \
      --function-name "$AUTH_FN" \
      --query 'Environment.Variables.{table:SECURITY_EVENTS_TABLE,queue:SECURITY_EVENT_INGRESS_QUEUE_URL}' \
      --output json 2>/dev/null)" ||
      current="unavailable"
    if jq -e --arg table "$SECURITY_TABLE" --arg queue "$INGRESS_QUEUE" '
      .table == $table and .queue == $queue
    ' <<<"$current" >/dev/null 2>&1; then
      AUTH_CONFIG_MUTATED=0
      return 0
    fi
    sleep 5
  done
  printf 'FAIL: could not restore Auth Lambda environment for %s after %s attempts\n' \
    "$AUTH_FN" "$attempt" >&2
  return 1
}

delete_archive_versions() {
  local prefix="${1:?archive prefix required}" exact="${2:-1}"
  local versions delete_file count
  versions="$("${AWS[@]}" s3api list-object-versions \
    --bucket "$ARCHIVE_BUCKET" --prefix "$prefix" --output json)" || return 1
  delete_file="$(mktemp "$WORK/archive-delete.XXXXXX.json")"
  jq --arg prefix "$prefix" --argjson exact "$exact" '{
    Objects: ([
      (.Versions[]?, .DeleteMarkers[]?)
      | select(
          if $exact == 1 then .Key == $prefix
          else (.Key | startswith($prefix))
          end
        )
      | {Key, VersionId}
    ]),
    Quiet: true
  }' <<<"$versions" >"$delete_file" || {
    rm -f "$delete_file"
    return 1
  }
  count="$(jq '.Objects | length' "$delete_file")"
  if ((count > 0)); then
    "${AWS[@]}" s3api delete-objects --bucket "$ARCHIVE_BUCKET" \
      --delete "file://$delete_file" >/dev/null || {
      rm -f "$delete_file"
      return 1
    }
  fi
  rm -f "$delete_file"
  versions="$("${AWS[@]}" s3api list-object-versions \
    --bucket "$ARCHIVE_BUCKET" --prefix "$prefix" --output json)" || return 1
  jq -e --arg prefix "$prefix" --argjson exact "$exact" '
    [(.Versions[]?, .DeleteMarkers[]?)
      | select(
          if $exact == 1 then .Key == $prefix
          else (.Key | startswith($prefix))
          end
        )]
    | length == 0
  ' <<<"$versions" >/dev/null
}

cleanup_current() {
  local event_id key grant_key physical_user values visible observed
  local delete_started delete_status delete_event delete_key
  local batch_archives_complete=1 grants_drained=1 restore_failed=0
  set +e
  restore_auth_environment || restore_failed=1
  restore_archive_concurrency || restore_failed=1
  if [[ "$LARGE_BATCH_TRIGGERED" == "1" &&
    (${#BATCH_FIXTURE_IDS[@]} -lt 17 || ${#BATCH_FIXTURE_KEYS[@]} -lt 17) ]]; then
    DISCOVERED_BATCH_SUBJECTS=0
    DISCOVERED_BATCH_ARCHIVES=0
    for _ in $(seq 1 30); do
      discover_large_batch_fixtures || {
        restore_failed=1
        break
      }
      if [[ "$DISCOVERED_BATCH_SUBJECTS" == "17" &&
        "$DISCOVERED_BATCH_ARCHIVES" == "17" ]]; then
        break
      fi
      sleep 2
    done
    if [[ "$DISCOVERED_BATCH_SUBJECTS" != "17" ||
      "$DISCOVERED_BATCH_ARCHIVES" != "17" ]]; then
      printf 'FAIL: cleanup found %s subjects and %s archives for %s Grant batch\n' \
        "$DISCOVERED_BATCH_SUBJECTS" "$DISCOVERED_BATCH_ARCHIVES" \
        "$CURRENT_STACK" >&2
      batch_archives_complete=0
      restore_failed=1
    fi
  fi
  # Remove the seeded Grants before deleting the user. Otherwise user deletion
  # cascades over them and creates a second, untracked 17-event batch.
  if [[ -n "$GRANTS_TABLE" ]]; then
    for grant_key in "${GRANT_KEYS[@]}"; do
      "${AWS[@]}" dynamodb delete-item --table-name "$GRANTS_TABLE" \
        --key "$(jq -cn --arg id "$grant_key" '{grant_id:{S:$id}}')" >/dev/null
    done
  fi
  if [[ -n "$GRANTS_TABLE" && -n "$USER_ID" && ${#GRANT_KEYS[@]} -gt 0 ]]; then
    physical_user="$(storage_key "$USER_ID")"
    values="$(jq -cn --arg uid "$physical_user" '{":uid":{S:$uid}}')"
    visible=-1
    for _ in $(seq 1 30); do
      visible="$("${AWS[@]}" dynamodb query --table-name "$GRANTS_TABLE" \
        --index-name user_id-index --key-condition-expression 'user_id = :uid' \
        --expression-attribute-values "$values" --select COUNT \
        --query Count --output text 2>/dev/null)" || visible=-1
      [[ "$visible" == "0" ]] && break
      sleep 2
    done
    if [[ "$visible" != "0" ]]; then
      printf 'FAIL: seeded Grants remained visible during %s cleanup\n' \
        "$CURRENT_STACK" >&2
      grants_drained=0
      restore_failed=1
    fi
  fi
  if [[ "$LARGE_BATCH_TRIGGERED" == "1" ]]; then
    discover_large_batch_fixtures || restore_failed=1
  fi
  if [[ -n "$USER_ID" && -n "$API_URL" && -n "$ADMIN_TOKEN" &&
    "$grants_drained" == "1" ]]; then
    delete_started="$(date +%s)"
    delete_status="$(curl -sS -o /dev/null -w '%{http_code}' \
      -X DELETE "$API_URL/admin/users/$USER_ID" \
      -H "authorization: Bearer $ADMIN_TOKEN")"
    if [[ "$delete_status" != "200" ]]; then
      printf 'FAIL: %s user cleanup returned HTTP %s\n' \
        "$CURRENT_STACK" "$delete_status" >&2
      restore_failed=1
    fi
    if ! delete_event="$(find_user_event "$USER_ID" "$delete_started" user.delete)"; then
      printf 'FAIL: %s user cleanup did not write user.delete audit\n' \
        "$CURRENT_STACK" >&2
      restore_failed=1
    else
      if ! wait_for_item_status "$delete_event" archived; then
        printf 'FAIL: %s user.delete audit was not archived\n' \
          "$CURRENT_STACK" >&2
        restore_failed=1
      else
        if ! delete_key="$(
          jq -er '.Item.archive_key.S' \
            "$WORK/$CURRENT_STACK.$delete_event.item.json"
        )"; then
          printf 'FAIL: %s user.delete audit has no archive key\n' \
            "$CURRENT_STACK" >&2
          restore_failed=1
        else
          register_fixture "$delete_event" "$delete_key"
          if ! "${AWS[@]}" s3api head-object \
            --bucket "$ARCHIVE_BUCKET" --key "$delete_key" >/dev/null; then
            printf 'FAIL: %s user.delete archive object is missing\n' \
              "$CURRENT_STACK" >&2
            restore_failed=1
          fi
        fi
      fi
    fi
  elif [[ -n "$USER_ID" && "$grants_drained" != "1" ]]; then
    printf 'FAIL: skipped %s user cleanup because seeded Grants remain indexed\n' \
      "$CURRENT_STACK" >&2
  fi
  if [[ -n "$SECURITY_TABLE" ]]; then
    for event_id in "${FIXTURE_IDS[@]}"; do
      if [[ "$batch_archives_complete" != "1" ]] &&
        array_contains "$event_id" "${BATCH_FIXTURE_IDS[@]}"; then
        continue
      fi
      if ! "${AWS[@]}" dynamodb delete-item --table-name "$SECURITY_TABLE" \
        --key "$(jq -cn --arg id "$event_id" '{event_id:{S:$id}}')" >/dev/null; then
        printf 'FAIL: could not delete %s security-event fixture %s\n' \
          "$CURRENT_STACK" "$event_id" >&2
        restore_failed=1
        continue
      fi
      observed="$("${AWS[@]}" dynamodb get-item --table-name "$SECURITY_TABLE" \
        --key "$(jq -cn --arg id "$event_id" '{event_id:{S:$id}}')" \
        --consistent-read --query 'Item.event_id.S' --output text 2>/dev/null)" ||
        observed="unavailable"
      if [[ "$observed" != "None" ]]; then
        printf 'FAIL: %s security-event fixture still exists: %s\n' \
          "$CURRENT_STACK" "$event_id" >&2
        restore_failed=1
      fi
    done
  fi
  if [[ -n "$ARCHIVE_BUCKET" ]]; then
    for key in "${FIXTURE_KEYS[@]}"; do
      if [[ "$batch_archives_complete" != "1" ]] &&
        array_contains "$key" "${BATCH_FIXTURE_KEYS[@]}"; then
        continue
      fi
      if ! delete_archive_versions "$key"; then
        printf 'FAIL: could not delete every %s archive fixture version: %s\n' \
          "$CURRENT_STACK" "$key" >&2
        restore_failed=1
      fi
    done
    if [[ -n "$ATHENA_PREFIX" ]]; then
      if ! delete_archive_versions "$ATHENA_PREFIX" 0; then
        printf 'FAIL: could not delete every %s Athena result version under %s\n' \
          "$CURRENT_STACK" "$ATHENA_PREFIX" >&2
        restore_failed=1
      fi
    fi
  fi
  set -e
  if [[ "$restore_failed" == "0" ]]; then
    USER_ID=""
    LARGE_BATCH_FROM=""
    LARGE_BATCH_TRIGGERED=0
    DISCOVERED_BATCH_SUBJECTS=0
    DISCOVERED_BATCH_ARCHIVES=0
    FIXTURE_IDS=()
    FIXTURE_KEYS=()
    BATCH_FIXTURE_IDS=()
    BATCH_FIXTURE_KEYS=()
    GRANT_KEYS=()
    ATHENA_PREFIX=""
    AUTH_CONFIG_MUTATED=0
    ARCHIVE_RESERVED_CONCURRENCY=""
    ARCHIVE_CONCURRENCY_BLOCKED=0
  fi
  return "$restore_failed"
}

cleanup() {
  local status=$? cleanup_status=0
  trap - EXIT INT TERM
  cleanup_current || cleanup_status=$?
  if [[ "$cleanup_status" != "0" ]]; then
    printf 'FAIL: cleanup recovery data preserved at %s\n' "$WORK" >&2
    exit "$cleanup_status"
  fi
  rm -rf "$WORK"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

stack_output() {
  local key="${1:?output key required}"
  jq -er --arg key "$key" '
    .Stacks[0].Outputs[]
    | select(.OutputKey == $key)
    | .OutputValue
  ' "$WORK/$CURRENT_STACK.stack.json"
}

physical_resource() {
  local type="${1:?resource type required}" prefix="${2:?logical prefix required}"
  jq -er --arg type "$type" --arg prefix "$prefix" '
    [.StackResourceSummaries[]
      | select(.ResourceType == $type)
      | select(.LogicalResourceId | startswith($prefix))
      | .PhysicalResourceId]
    | if length == 1 then .[0] else error("expected one matching resource") end
  ' "$WORK/$CURRENT_STACK.resources.json"
}

load_stack() {
  local stack="${1:?stack required}" admin_arn secret
  CURRENT_STACK="$stack"
  USER_ID=""
  LARGE_BATCH_FROM=""
  LARGE_BATCH_TRIGGERED=0
  DISCOVERED_BATCH_SUBJECTS=0
  DISCOVERED_BATCH_ARCHIVES=0
  FIXTURE_IDS=()
  FIXTURE_KEYS=()
  BATCH_FIXTURE_IDS=()
  BATCH_FIXTURE_KEYS=()
  GRANT_KEYS=()
  ATHENA_PREFIX=""
  ARCHIVE_RESERVED_CONCURRENCY=""
  ARCHIVE_CONCURRENCY_BLOCKED=0
  AUTH_CONFIG_MUTATED=0
  AUTH_LOG_GROUP=""

  "${AWS[@]}" cloudformation describe-stacks --stack-name "$stack" \
    >"$WORK/$stack.stack.json"
  jq -e '.Stacks[0].StackStatus | endswith("_COMPLETE")' \
    "$WORK/$stack.stack.json" >/dev/null ||
    fail "$stack is not in a complete state"
  "${AWS[@]}" cloudformation list-stack-resources --stack-name "$stack" \
    >"$WORK/$stack.resources.json"

  AUTH_FN="$(physical_resource AWS::Lambda::Function AuthFn)"
  ARCHIVE_FN="$(physical_resource AWS::Lambda::Function SecurityEventArchiveFn)"
  "${AWS[@]}" lambda get-function-configuration --function-name "$AUTH_FN" \
    >"$WORK/$stack.auth-config.json"
  jq '.Environment.Variables' "$WORK/$stack.auth-config.json" \
    >"$WORK/$stack.runtime.json"
  jq '{Variables:.Environment.Variables}' "$WORK/$stack.auth-config.json" \
    >"$WORK/$stack.auth-environment.json"
  AUTH_LOG_GROUP="$(
    jq -r --arg default "/aws/lambda/$AUTH_FN" \
      '.LoggingConfig.LogGroup // $default' "$WORK/$stack.auth-config.json"
  )"

  SECURITY_TABLE="$(stack_output SecurityEventsTableName)"
  GRANTS_TABLE="$(stack_output GrantsTableName)"
  ARCHIVE_BUCKET="$(stack_output SecurityEventArchiveBucketName)"
  ARCHIVE_DLQ="$(stack_output SecurityEventArchiveDlqUrl)"
  INGRESS_QUEUE="$(stack_output SecurityEventIngressQueueUrl)"
  INGRESS_DLQ="$(stack_output SecurityEventIngressDlqUrl)"
  STREAM_FAILURE_NOTIFICATION_QUEUE="$(
    stack_output SecurityEventStreamFailureNotificationQueueUrl
  )"
  STREAM_FAILURE_NOTIFICATION_DLQ="$(
    stack_output SecurityEventStreamFailureNotificationDlqUrl
  )"
  FAILURE_BUCKET="$(stack_output SecurityEventStreamFailureBucketName)"
  INGRESS_FAILURE_BUCKET="$(stack_output SecurityEventIngressFailureBucketName)"
  GLUE_DATABASE="$(physical_resource AWS::Glue::Database SecurityEventArchiveDatabase)"

  if [[ "$stack" == "AgentAuthSaas" ]]; then
    TENANT="$SAAS_TENANT"
    API_URL="https://$TENANT.$(jq -er '.AGENT_AUTH_ZONE' "$WORK/$stack.runtime.json")"
    "${AWS[@]}" secretsmanager get-secret-value \
      --secret-id "$(
        jq -er '.AGENT_AUTH_BOOTSTRAP_CONFIG_SECRET_ARN' \
          "$WORK/$stack.runtime.json"
      )" \
      --query SecretString --output text >"$WORK/$stack.bootstrap.json"
    admin_arn="$(
      jq -er --arg tenant "$TENANT" \
        '.tenant_admin_secret_arns[$tenant]' \
        "$WORK/$stack.bootstrap.json"
    )"
  else
    TENANT="default"
    API_URL="$(stack_output AdminUrl)"
    API_URL="${API_URL%/admin}"
    admin_arn="$(stack_output AdminSecretArn)"
  fi

  secret="$("${AWS[@]}" secretsmanager get-secret-value --secret-id "$admin_arn" \
    --query SecretString --output text)"
  ADMIN_TOKEN="$(jq -er '.current.secret | select(type == "string" and length >= 16)' \
    <<<"$secret")"
  [[ "$API_URL" == https://* ]] || fail "$stack did not resolve to an HTTPS tenant origin"
}

storage_key() {
  local logical="${1:?logical key required}"
  if [[ "$CURRENT_STACK" == "AgentAuthSaas" ]]; then
    printf '%s\x1f%s' "$TENANT" "$logical"
  else
    printf '%s' "$logical"
  fi
}

wait_for_item_status() {
  local event_id="${1:?event id required}" expected="${2:?status required}"
  local output="$WORK/$CURRENT_STACK.$event_id.item.json"
  for _ in $(seq 1 45); do
    "${AWS[@]}" dynamodb get-item --table-name "$SECURITY_TABLE" \
      --key "$(jq -cn --arg id "$event_id" '{event_id:{S:$id}}')" \
      --consistent-read >"$output"
    if jq -e --arg expected "$expected" \
      '.Item.delivery_status.S == $expected' "$output" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  return 1
}

assert_archived() {
  local event_id="${1:?event id required}"
  local item="$WORK/$CURRENT_STACK.$event_id.item.json"
  local key body="$WORK/$CURRENT_STACK.$event_id.archive.json"

  wait_for_item_status "$event_id" archived ||
    fail "$CURRENT_STACK event $event_id was not archived"
  jq -e --arg id "$event_id" '
    .Item.event_id.S == $id
    and .Item.delivery_status.S == "archived"
    and ((.Item.delivery_attempts.N | tonumber) >= 1)
    and ((.Item.expires_at.N | tonumber)
      == ((.Item.occurred_at.N | tonumber) + 34560000))
    and ([.Item.delivery_history.L[].M.status.S] | index("pending") != null)
    and (.Item.delivery_history.L[-1].M.status.S == "archived")
  ' "$item" >/dev/null ||
    fail "$CURRENT_STACK event $event_id has invalid delivery metadata"

  key="$(jq -er '.Item.archive_key.S' "$item")"
  "${AWS[@]}" s3api head-object --bucket "$ARCHIVE_BUCKET" --key "$key" >/dev/null
  "${AWS[@]}" s3api get-object --bucket "$ARCHIVE_BUCKET" --key "$key" "$body" >/dev/null
  jq -e --arg id "$event_id" '.event_id == $id and .schema_version == "1.0"' \
    "$body" >/dev/null ||
    fail "$CURRENT_STACK archive object does not contain the expected envelope"
  printf '%s\n' "$key"
}

find_user_event() {
  local subject="${1:?subject required}" from="${2:?from required}"
  local action="${3:?action required}"
  local values output="$WORK/$CURRENT_STACK.user-event-query.json"
  values="$(jq -cn --arg tenant "$TENANT" --arg from "$from" \
    --arg through "$(( $(date +%s) + 60 ))" \
    '{":tenant":{S:$tenant},":from":{N:$from},":through":{N:$through}}')"
  for _ in $(seq 1 30); do
    "${AWS[@]}" dynamodb query --table-name "$SECURITY_TABLE" \
      --index-name tenant_occurred_at-index \
      --key-condition-expression \
        'tenant_id = :tenant AND occurred_at BETWEEN :from AND :through' \
      --expression-attribute-values "$values" --no-scan-index-forward \
      --output json >"$output"
    if jq -er --arg subject "$subject" --arg action "$action" '
      .Items[]
      | select(.action.S == $action)
      | .envelope.S
      | fromjson
      | select(.subject.id == $subject)
      | .event_id
    ' "$output" 2>/dev/null | head -n 1; then
      return 0
    fi
    sleep 2
  done
  return 1
}

create_auth_event() {
  local started email password body status event_id key
  started="$(date +%s)"
  email="e2e-security-${RUN_ID}-${CURRENT_STACK,,}@example.com"
  email="${email//agentauth/}"
  USER_ID="user:$email"
  password="Init-${RUN_ID}-Aa9!"
  body="$(jq -cn --arg email "$email" --arg password "$password" \
    '{email:$email,initial_password:$password}')"
  status="$(printf '%s' "$body" | curl -sS -o "$WORK/$CURRENT_STACK.create.json" \
    -w '%{http_code}' -X POST "$API_URL/admin/users" \
    -H "authorization: Bearer $ADMIN_TOKEN" \
    -H "content-type: application/json" --data-binary @-)"
  [[ "$status" == "201" ]] ||
    fail "$CURRENT_STACK Admin user creation returned HTTP $status"

  event_id="$(find_user_event "$USER_ID" "$started" user.create)" ||
    fail "$CURRENT_STACK did not write the user.create security event"
  key="$(assert_archived "$event_id")"
  register_fixture "$event_id" "$key"
  pass "$CURRENT_STACK Auth Lambda wrote $event_id and Stream archived $key"
  RESULT_EVENT_ID="$event_id"
}

seed_large_grant_batch() {
  local count=17 now expires physical_user physical_gv values visible
  local index grant_id physical_grant grant_json item
  now="$(date +%s)"
  expires="$((now + 3600))"
  physical_user="$(storage_key "$USER_ID")"
  physical_gv="$(storage_key gv)"

  for index in $(seq 0 $((count - 1))); do
    grant_id="e2e-security-batch-${RUN_ID}-${index}"
    physical_grant="$(storage_key "$grant_id")"
    grant_json="$(jq -cn --arg gid "$grant_id" --arg uid "$USER_ID" \
      --arg cid "e2e-security-batch-client" --argjson expires "$expires" '{
        grant_id:$gid, user_id:$uid, client_id:$cid, per_resource:[],
        effective_per_resource:[], effective_pv:0, allowed_ip_cidrs:[],
        allowed_vpce:[], credential_epoch:0, revision:0,
        constraints:{max_act_chain:1,actor_allowlist:[],expires_at:$expires},
        status:"active"
      }')"
    item="$(jq -cn --arg gid "$physical_grant" --arg uid "$physical_user" \
      --arg gv "$physical_gv" --arg grant "$grant_json" '{
        grant_id:{S:$gid}, user_id:{S:$uid}, gv_tenant:{S:$gv},
        effective_pv:{N:"0"}, revision:{N:"0"}, credential_epoch:{N:"0"},
        grant_json:{S:$grant}
      }')"
    "${AWS[@]}" dynamodb put-item --table-name "$GRANTS_TABLE" --item "$item" >/dev/null
    GRANT_KEYS+=("$physical_grant")
  done

  values="$(jq -cn --arg uid "$physical_user" '{":uid":{S:$uid}}')"
  for _ in $(seq 1 30); do
    visible="$("${AWS[@]}" dynamodb query --table-name "$GRANTS_TABLE" \
      --index-name user_id-index --key-condition-expression 'user_id = :uid' \
      --expression-attribute-values "$values" --select COUNT \
      --query Count --output text)"
    [[ "$visible" -ge "$count" ]] && break
    sleep 2
  done
  [[ "$visible" -ge "$count" ]] ||
    fail "$CURRENT_STACK did not expose the 17 seeded Grants through user_id-index"
  pass "$CURRENT_STACK seeded 17 tenant-scoped Grants for batch delivery"
}

assert_large_grant_batch() {
  local from="${1:?start time required}" output values complete
  local logs expected_ids observed
  output="$WORK/$CURRENT_STACK.grant-batch.json"
  values="$(jq -cn --arg tenant "$TENANT" --arg from "$from" \
    --arg through "$(( $(date +%s) + 60 ))" \
    '{":tenant":{S:$tenant},":from":{N:$from},":through":{N:$through}}')"

  for _ in $(seq 1 60); do
    "${AWS[@]}" dynamodb query --table-name "$SECURITY_TABLE" \
      --index-name tenant_occurred_at-index \
      --key-condition-expression \
        'tenant_id = :tenant AND occurred_at BETWEEN :from AND :through' \
      --expression-attribute-values "$values" --output json >"$output"
    discover_large_batch_fixtures "$output"
    complete="$(jq --arg run "$RUN_ID" '
      ([range(0; 17) | "e2e-security-batch-\($run)-\(.)"] | sort) as $expected
      | [.Items[]
        | select(.action.S == "grant.revoke")
        | . as $item
        | (.envelope.S | fromjson) as $event
        | select($expected | index($event.subject.id))
        | select($item.delivery_status.S == "archived")
        | select((($item.source_delivery_attempts.N // "0") | tonumber) >= 2)
        | {subject:$event.subject.id,event_id:$event.event_id}]
      | length == 17
        and ([.[].subject] | sort) == $expected
        and ([.[].event_id] | unique | length) == 17
    ' "$output")"
    [[ "$complete" == "true" ]] && break
    sleep 2
  done
  [[ "$complete" == "true" ]] ||
    fail "$CURRENT_STACK did not archive exactly one event for each of the 17 Grants"

  expected_ids="$(jq -c --arg run "$RUN_ID" '
    ([range(0; 17) | "e2e-security-batch-\($run)-\(.)"]) as $expected
    | [.Items[]
      | select(.action.S == "grant.revoke")
      | (.envelope.S | fromjson)
      | . as $event
      | select($expected | index($event.subject.id))
      | .event_id]
    | unique
  ' "$output")"
  logs="$WORK/$CURRENT_STACK.grant-batch-logs.json"
  observed=0
  for _ in $(seq 1 30); do
    "${AWS[@]}" logs filter-log-events \
      --log-group-name "$AUTH_LOG_GROUP" \
      --start-time "$((from * 1000))" \
      --filter-pattern '"SECURITY_EVENT_BATCH_RECOVERY"' \
      --output json >"$logs"
    observed="$(jq --argjson ids "$expected_ids" '
      [.events[].message
        | try capture(
            "^SECURITY_EVENT_BATCH_RECOVERY " +
            "event_id=(?<event_id>[A-Za-z0-9._-]+) payload=[A-Za-z0-9_-]+" +
            "[\\r\\n]*$"
          ).event_id catch empty
        | select(. as $event_id | $ids | index($event_id) != null)]
      | unique
      | length
    ' "$logs")"
    [[ "$observed" == "17" ]] && break
    sleep 2
  done
  [[ "$observed" == "17" ]] ||
    fail "$CURRENT_STACK runtime logs did not prove all 17 events used the batch path"
  pass "$CURRENT_STACK archived all 17 Grant events through the SQS batch path"
}

array_contains() {
  local needle="${1:?value required}" current
  shift
  for current in "$@"; do
    [[ "$current" == "$needle" ]] && return 0
  done
  return 1
}

register_fixture() {
  local event_id="${1:?event id required}" archive_key="${2:-}"
  array_contains "$event_id" "${FIXTURE_IDS[@]}" || FIXTURE_IDS+=("$event_id")
  [[ -n "$archive_key" ]] || return 0
  array_contains "$archive_key" "${FIXTURE_KEYS[@]}" || FIXTURE_KEYS+=("$archive_key")
}

register_batch_fixture() {
  local event_id="${1:?event id required}" archive_key="${2:-}"
  register_fixture "$event_id" "$archive_key"
  array_contains "$event_id" "${BATCH_FIXTURE_IDS[@]}" ||
    BATCH_FIXTURE_IDS+=("$event_id")
  [[ -n "$archive_key" ]] || return 0
  array_contains "$archive_key" "${BATCH_FIXTURE_KEYS[@]}" ||
    BATCH_FIXTURE_KEYS+=("$archive_key")
}

same_invocation_candidate() {
  local anchor_id="${1:?anchor event ID required}"
  local from="${2:?start time required}"
  local through="${3:?end time required}"
  shift 3
  local anchor_logs="$WORK/$CURRENT_STACK.$anchor_id.anchor-logs.json"
  local invocation_logs="$WORK/$CURRENT_STACK.$anchor_id.invocation-logs.json"
  local stream

  "${AWS[@]}" logs filter-log-events \
    --log-group-name "$AUTH_LOG_GROUP" \
    --start-time "$((from * 1000))" --end-time "$((through * 1000))" \
    --filter-pattern "\"$anchor_id\"" --output json >"$anchor_logs"
  stream="$(jq -er --arg id "$anchor_id" '
    [.events[]
      | select(
          (.message
            | try capture(
                "^SECURITY_EVENT_(?:EMERGENCY|BATCH_RECOVERY) " +
                "event_id=(?<event_id>[A-Za-z0-9._-]+) " +
                "payload=[A-Za-z0-9_-]+[\\r\\n]*$"
              ).event_id catch "") == $id
        )
      | .logStreamName]
    | unique
    | select(length == 1)
    | .[0]
  ' "$anchor_logs")" || return 1
  "${AWS[@]}" logs filter-log-events \
    --log-group-name "$AUTH_LOG_GROUP" --log-stream-names "$stream" \
    --start-time "$((from * 1000))" --end-time "$((through * 1000))" \
    --output json >"$invocation_logs"
  python3 - "$invocation_logs" "$anchor_id" "$@" <<'PY'
import json
import re
import sys

source, anchor_id, *candidate_ids = sys.argv[1:]
with open(source, encoding="utf-8") as handle:
    events = json.load(handle)["events"]

marker = re.compile(
    r"^SECURITY_EVENT_(?:EMERGENCY|BATCH_RECOVERY) "
    r"event_id=([A-Za-z0-9._-]+) payload=[A-Za-z0-9_-]+\r?\n?$"
)
start = re.compile(r"^START RequestId: ([0-9a-f-]+) ")
end = re.compile(r"^END RequestId: ([0-9a-f-]+)\r?\n?$")
anchors = [
    index
    for index, event in enumerate(events)
    if (match := marker.match(event["message"])) and match.group(1) == anchor_id
]
if len(anchors) != 1:
    raise SystemExit("anchor marker is not unique in its log stream")
anchor = anchors[0]
starts = [
    (index, match.group(1))
    for index, event in enumerate(events[:anchor])
    if (match := start.match(event["message"]))
]
ends = [
    (index, match.group(1))
    for index, event in enumerate(events[anchor + 1 :], anchor + 1)
    if (match := end.match(event["message"]))
]
if not starts or not ends or starts[-1][1] != ends[0][1]:
    raise SystemExit("anchor marker has no complete Lambda invocation boundary")
lower, request_id = starts[-1]
upper, _ = ends[0]
candidates = set(candidate_ids)
matches = {
    match.group(1)
    for event in events[lower + 1 : upper]
    if (match := marker.match(event["message"])) and match.group(1) in candidates
}
if len(matches) != 1:
    raise SystemExit(
        f"expected one break-glass marker in invocation {request_id}, got {len(matches)}"
    )
print(matches.pop())
PY
}

discover_large_batch_fixtures() {
  local source="${1:-}" output values counts event_id archive_key
  DISCOVERED_BATCH_SUBJECTS=0
  DISCOVERED_BATCH_ARCHIVES=0
  [[ -n "$LARGE_BATCH_FROM" && -n "$SECURITY_TABLE" && -n "$TENANT" ]] || return 0
  if [[ -z "$source" ]]; then
    output="$WORK/$CURRENT_STACK.grant-batch-cleanup.json"
    values="$(jq -cn --arg tenant "$TENANT" --arg from "$LARGE_BATCH_FROM" \
      --arg through "$(( $(date +%s) + 60 ))" \
      '{":tenant":{S:$tenant},":from":{N:$from},":through":{N:$through}}')"
    "${AWS[@]}" dynamodb query --table-name "$SECURITY_TABLE" \
      --index-name tenant_occurred_at-index \
      --key-condition-expression \
        'tenant_id = :tenant AND occurred_at BETWEEN :from AND :through' \
      --expression-attribute-values "$values" --output json >"$output" || return 1
  else
    output="$source"
  fi
  counts="$(jq -r --arg run "$RUN_ID" '
    ([range(0; 17) | "e2e-security-batch-\($run)-\(.)"]) as $expected
    | [.Items[]
      | select(.action.S == "grant.revoke")
      | . as $item
      | (.envelope.S | fromjson).subject.id as $subject
      | select($expected | index($subject))
      | {
          subject:$subject,
          status:($item.delivery_status.S // ""),
          key:($item.archive_key.S // "")
        }] as $matches
    | [
        ([$matches[].subject] | unique | length),
        ([$matches[]
          | select(.status == "archived" and (.key | length) > 0)
          | .subject] | unique | length)
      ]
    | @tsv
  ' "$output")"
  IFS=$'\t' read -r DISCOVERED_BATCH_SUBJECTS DISCOVERED_BATCH_ARCHIVES <<<"$counts"
  while IFS=$'\t' read -r event_id archive_key; do
    register_batch_fixture "$event_id" "$archive_key"
  done < <(jq -r --arg prefix "e2e-security-batch-${RUN_ID}-" '
    .Items[]
    | select(.action.S == "grant.revoke")
    | . as $item
    | (.envelope.S | fromjson) as $event
    | select($event.subject.id | startswith($prefix))
    | [$event.event_id, ($item.archive_key.S // "")]
    | @tsv
  ' "$output")
}

create_real_fallback_event() {
  local started missing_table fault_environment status encoded_user event_id key item
  seed_large_grant_batch
  started="$(date +%s)"
  LARGE_BATCH_FROM="$started"
  missing_table="e2e-missing-security-events-${RUN_ID//[^a-zA-Z0-9-]/-}"
  fault_environment="$WORK/$CURRENT_STACK.auth-environment-fault.json"
  jq --arg table "$missing_table" \
    '.Variables.SECURITY_EVENTS_TABLE = $table' \
    "$WORK/$CURRENT_STACK.auth-environment.json" >"$fault_environment"

  AUTH_CONFIG_MUTATED=1
  "${AWS[@]}" lambda update-function-configuration --function-name "$AUTH_FN" \
    --environment "file://$fault_environment" >/dev/null
  "${AWS[@]}" lambda wait function-updated-v2 --function-name "$AUTH_FN"
  [[ "$("${AWS[@]}" lambda get-function-configuration --function-name "$AUTH_FN" \
    --query 'Environment.Variables.SECURITY_EVENTS_TABLE' --output text)" == "$missing_table" ]] ||
    fail "$CURRENT_STACK could not activate the controlled security-event storage failure"

  encoded_user="$(jq -rn --arg value "$USER_ID" '$value|@uri')"
  LARGE_BATCH_TRIGGERED=1
  status="$(curl -sS -o "$WORK/$CURRENT_STACK.disable.json" -w '%{http_code}' \
    -X POST "$API_URL/admin/users/$encoded_user/disable" \
    -H "authorization: Bearer $ADMIN_TOKEN")"
  restore_auth_environment ||
    fail "$CURRENT_STACK could not restore Auth Lambda after fallback injection"
  [[ "$status" == "200" ]] ||
    fail "$CURRENT_STACK controlled user disable returned HTTP $status"

  event_id="$(find_user_event "$USER_ID" "$started" user.disable)" ||
    fail "$CURRENT_STACK Auth Lambda fallback did not deliver user.disable"
  FIXTURE_IDS+=("$event_id")
  key="$(assert_archived "$event_id")"
  FIXTURE_KEYS+=("$key")
  item="$WORK/$CURRENT_STACK.$event_id.item.json"
  jq -e '
    [.Item.delivery_history.L[].M.status.S] as $history
    | ($history | index("failed") != null)
      and ((.Item.source_delivery_attempts.N | tonumber) >= 2)
  ' "$item" >/dev/null ||
    fail "$CURRENT_STACK fallback event did not retain the Auth storage failure"
  assert_large_grant_batch "$started"
  pass "$CURRENT_STACK Auth Lambda used the real DynamoDB-to-SQS fallback for $event_id"
}

create_emergency_recovery_event() {
  local started missing_table missing_queue fault_environment status encoded_user
  local user_plan="" break_glass_plan="" replay_output="" replay_end
  local user_event_id="" break_glass_event_id="" event_id="" key item
  local -a user_candidate_ids=() break_glass_candidate_ids=() replayed_ids=()
  started="$(date +%s)"
  missing_table="e2e-missing-security-events-${RUN_ID//[^a-zA-Z0-9-]/-}"
  missing_queue="${INGRESS_QUEUE%/*}/e2e-missing-security-events-${RUN_ID//[^a-zA-Z0-9-]/-}"
  fault_environment="$WORK/$CURRENT_STACK.auth-environment-dual-fault.json"
  jq --arg table "$missing_table" --arg queue "$missing_queue" '
    .Variables.SECURITY_EVENTS_TABLE = $table
    | .Variables.SECURITY_EVENT_INGRESS_QUEUE_URL = $queue
  ' "$WORK/$CURRENT_STACK.auth-environment.json" >"$fault_environment"

  AUTH_CONFIG_MUTATED=1
  "${AWS[@]}" lambda update-function-configuration --function-name "$AUTH_FN" \
    --environment "file://$fault_environment" >/dev/null
  "${AWS[@]}" lambda wait function-updated-v2 --function-name "$AUTH_FN"
  "${AWS[@]}" lambda get-function-configuration --function-name "$AUTH_FN" \
    --query 'Environment.Variables.{table:SECURITY_EVENTS_TABLE,queue:SECURITY_EVENT_INGRESS_QUEUE_URL}' \
    --output json >"$WORK/$CURRENT_STACK.dual-fault-effective.json"
  jq -e --arg table "$missing_table" --arg queue "$missing_queue" '
    .table == $table and .queue == $queue
  ' "$WORK/$CURRENT_STACK.dual-fault-effective.json" >/dev/null ||
    fail "$CURRENT_STACK could not activate the controlled dual storage failure"

  encoded_user="$(jq -rn --arg value "$USER_ID" '$value|@uri')"
  status="$(curl -sS -o "$WORK/$CURRENT_STACK.enable.json" -w '%{http_code}' \
    -X POST "$API_URL/admin/users/$encoded_user/enable" \
    -H "authorization: Bearer $ADMIN_TOKEN")"
  restore_auth_environment ||
    fail "$CURRENT_STACK could not restore Auth Lambda after dual failure injection"
  [[ "$status" == "200" ]] ||
    fail "$CURRENT_STACK controlled user enable returned HTTP $status"

  for _ in $(seq 1 30); do
    replay_end="$(( $(date +%s) + 1 ))"
    if ! user_plan="$(
      "$ROOT/scripts/replay_security_event_emergency.sh" \
        --stack "$CURRENT_STACK" --profile "$PROFILE" --region "$REGION" \
        --start-time "$started" --end-time "$replay_end" \
        --tenant-id "$TENANT" --action user.enable \
        --subject-id "$USER_ID" 2>&1
    )"; then
      user_plan=""
    fi
    if ! break_glass_plan="$(
      "$ROOT/scripts/replay_security_event_emergency.sh" \
        --stack "$CURRENT_STACK" --profile "$PROFILE" --region "$REGION" \
        --start-time "$started" --end-time "$replay_end" \
        --tenant-id "$TENANT" --action admin.break_glass.use \
        --subject-id "$TENANT" 2>&1
    )"; then
      break_glass_plan=""
    fi
    mapfile -t user_candidate_ids < <(
      awk '$1 == "READY" {print $2}' <<<"$user_plan" | sort -u
    )
    mapfile -t break_glass_candidate_ids < <(
      awk '$1 == "READY" {print $2}' <<<"$break_glass_plan" | sort -u
    )
    ((${#user_candidate_ids[@]} <= 1)) || {
      printf '%s\n' "$user_plan" >&2
      fail "$CURRENT_STACK dual-outage window contains multiple user.enable candidates"
    }
    if ((${#user_candidate_ids[@]} == 1 &&
      ${#break_glass_candidate_ids[@]} >= 1)); then
      break
    fi
    sleep 2
  done
  ((${#user_candidate_ids[@]} == 1)) || {
    printf '%s\n' "$user_plan" >&2
    fail "$CURRENT_STACK did not isolate the dual-outage user.enable ingress"
  }
  ((${#break_glass_candidate_ids[@]} >= 1)) || {
    printf '%s\n' "$break_glass_plan" >&2
    fail "$CURRENT_STACK did not isolate the dual-outage break-glass ingress"
  }
  user_event_id="${user_candidate_ids[0]}"
  for _ in $(seq 1 10); do
    if break_glass_event_id="$(
      same_invocation_candidate "$user_event_id" "$started" "$replay_end" \
        "${break_glass_candidate_ids[@]}" 2>/dev/null
    )"; then
      break
    fi
    sleep 1
  done
  [[ -n "$break_glass_event_id" ]] ||
    fail "$CURRENT_STACK could not bind break-glass to the user.enable invocation"
  register_fixture "$user_event_id"
  register_fixture "$break_glass_event_id"
  replay_output="$(
    "$ROOT/scripts/replay_security_event_emergency.sh" \
      --stack "$CURRENT_STACK" --profile "$PROFILE" --region "$REGION" \
      --start-time "$started" --end-time "$replay_end" \
      --tenant-id "$TENANT" --event-id "$user_event_id" --execute
  )" || fail "$CURRENT_STACK could not replay the isolated user.enable ingress"
  grep -Fx "REPLAYED $user_event_id marker=SECURITY_EVENT_EMERGENCY tenant=$TENANT action=user.enable subject=$USER_ID" \
    <<<"$replay_output" >/dev/null ||
    fail "$CURRENT_STACK replay output changed the isolated user.enable ingress"
  key="$(assert_archived "$user_event_id")"
  register_fixture "$user_event_id" "$key"
  replay_output="$(
    "$ROOT/scripts/replay_security_event_emergency.sh" \
      --stack "$CURRENT_STACK" --profile "$PROFILE" --region "$REGION" \
      --start-time "$started" --end-time "$replay_end" \
      --tenant-id "$TENANT" --event-id "$break_glass_event_id" --execute
  )" || fail "$CURRENT_STACK could not replay the isolated break-glass ingress"
  grep -Fx "REPLAYED $break_glass_event_id marker=SECURITY_EVENT_EMERGENCY tenant=$TENANT action=admin.break_glass.use subject=$TENANT" \
    <<<"$replay_output" >/dev/null ||
    fail "$CURRENT_STACK replay output changed the isolated break-glass ingress"
  key="$(assert_archived "$break_glass_event_id")"
  register_fixture "$break_glass_event_id" "$key"
  replayed_ids=("$user_event_id" "$break_glass_event_id")
  for event_id in "${replayed_ids[@]}"; do
    item="$WORK/$CURRENT_STACK.$event_id.item.json"
    jq -e '
      [.Item.delivery_history.L[].M.status.S] as $history
      | ($history | index("failed") != null)
        and ((.Item.source_delivery_attempts.N | tonumber) >= 4)
    ' "$item" >/dev/null ||
      fail "$CURRENT_STACK replayed emergency event lost its failed delivery history"
  done
  pass "$CURRENT_STACK replayed ${#replayed_ids[@]} dual-outage emergency events into the archive"
}

create_ingress_event() {
  local now event_id payload late_payload key item archive_body ledger_attempts ledger_history
  local versions
  now="$(date +%s)"
  event_id="evt_e2e_ingress_$(openssl rand -hex 8)"
  payload="$WORK/$CURRENT_STACK.$event_id.ingress.json"
  jq -n --arg id "$event_id" --arg tenant "$TENANT" --arg run "$RUN_ID" \
    --argjson now "$now" '{
      event: {
        schema_version: "1.0",
        event_id: $id,
        occurred_at: $now,
        tenant_id: $tenant,
        actor: {kind: "system", id: "e2e-security-events"},
        subject: {kind: "tenant", id: $tenant},
        category: "delivery",
        action: "e2e.fallback_ingress",
        outcome: "success",
        correlation: {operation_id: $run}
      },
      delivery: {
        status: "retrying",
        attempts: 2,
        last_attempt_at: $now,
        history: [
          {status: "pending", occurred_at: $now},
          {status: "retrying", occurred_at: $now},
          {status: "failed", occurred_at: $now},
          {status: "retrying", occurred_at: $now}
        ]
      },
      ingress_attempts: 0
    }' >"$payload"
  "${AWS[@]}" sqs send-message --queue-url "$INGRESS_QUEUE" \
    --message-body "file://$payload" >/dev/null
  FIXTURE_IDS+=("$event_id")
  key="$(assert_archived "$event_id")"
  FIXTURE_KEYS+=("$key")
  item="$WORK/$CURRENT_STACK.$event_id.item.json"
  jq -e '
    [.Item.delivery_history.L[].M.status.S] as $history
    | ($history | index("failed") != null)
      and ($history | index("retrying") != null)
      and (.Item.delivery_attempts.N | tonumber) >= 3
  ' "$item" >/dev/null ||
    fail "$CURRENT_STACK ingress delivery history was not preserved"

  # Re-submit a newer source-delivery snapshot after the INSERT was archived.
  # No second stream INSERT occurs, so the ingress handler must refresh S3.
  late_payload="$WORK/$CURRENT_STACK.$event_id.late-ingress.json"
  jq --argjson observed "$(date +%s)" '
    .delivery.status = "pending"
    | .delivery.attempts = 3
    | .delivery.last_attempt_at = $observed
    | .delivery.history += [{status: "pending", occurred_at: $observed}]
    | .ingress_attempts = 1
  ' "$payload" >"$late_payload"
  "${AWS[@]}" sqs send-message --queue-url "$INGRESS_QUEUE" \
    --message-body "file://$late_payload" >/dev/null
  for _ in $(seq 1 30); do
    "${AWS[@]}" dynamodb get-item --table-name "$SECURITY_TABLE" \
      --key "$(jq -cn --arg id "$event_id" '{event_id:{S:$id}}')" \
      --consistent-read >"$item"
    if jq -e '(.Item.source_delivery_attempts.N | tonumber) >= 4' \
      "$item" >/dev/null 2>&1; then
      break
    fi
    sleep 2
  done
  jq -e '(.Item.source_delivery_attempts.N | tonumber) >= 4' "$item" >/dev/null ||
    fail "$CURRENT_STACK late ingress duplicate did not reconcile the hot ledger"
  ledger_attempts="$(jq -er '.Item.delivery_attempts.N | tonumber' "$item")"
  ledger_history="$(jq -er '.Item.delivery_history.L | length' "$item")"
  archive_body="$WORK/$CURRENT_STACK.$event_id.archive-refreshed.json"
  for _ in $(seq 1 30); do
    "${AWS[@]}" s3api get-object --bucket "$ARCHIVE_BUCKET" --key "$key" \
      "$archive_body" >/dev/null
    if jq -e --argjson attempts "$ledger_attempts" --argjson history "$ledger_history" '
      .delivery.status == "archived"
      and .delivery.attempts == $attempts
      and (.delivery.history | length) == $history
    ' "$archive_body" >/dev/null 2>&1; then
      break
    fi
    sleep 2
  done
  jq -e --argjson attempts "$ledger_attempts" --argjson history "$ledger_history" '
    .delivery.status == "archived"
    and .delivery.attempts == $attempts
    and (.delivery.history | length) == $history
  ' "$archive_body" >/dev/null ||
    fail "$CURRENT_STACK late ingress duplicate left a stale S3 archive snapshot"
  versions="$("${AWS[@]}" s3api list-object-versions \
    --bucket "$ARCHIVE_BUCKET" --prefix "$key" --output json)"
  jq -e --arg key "$key" '
    [.Versions[]? | select(.Key == $key)] | length >= 2
  ' <<<"$versions" >/dev/null ||
    fail "$CURRENT_STACK archive refresh did not retain both S3 object versions"
  pass "$CURRENT_STACK SQS fallback preserved and refreshed delivery history for $event_id"
  RESULT_EVENT_ID="$event_id"
}

create_terminal_event() {
  local now expires event_id event envelope item key response receipt invoke_payload
  now="$(date +%s)"
  expires="$((now + 34560000))"
  event_id="evt_e2e_terminal_$(openssl rand -hex 8)"
  event="$WORK/$CURRENT_STACK.$event_id.event.json"
  item="$WORK/$CURRENT_STACK.$event_id.put-item.json"
  jq -n --arg id "$event_id" --arg tenant "$TENANT" --arg run "$RUN_ID" \
    --argjson now "$now" '{
      schema_version: "1.0",
      event_id: $id,
      occurred_at: $now,
      tenant_id: $tenant,
      actor: {kind: "system", id: "e2e-security-events"},
      subject: {kind: "tenant", id: $tenant},
      category: "delivery",
      action: "e2e.archive_terminal",
      outcome: "failure",
      correlation: {operation_id: $run}
    }' >"$event"
  envelope="$(jq -c . "$event")"
  jq -n --arg id "$event_id" --arg tenant "$TENANT" \
    --arg now "$now" --arg expires "$expires" --arg envelope "$envelope" '{
      event_id:{S:$id},
      tenant_id:{S:$tenant},
      occurred_at:{N:$now},
      schema_version:{S:"1.0"},
      category:{S:"delivery"},
      action:{S:"e2e.archive_terminal"},
      outcome:{S:"failure"},
      envelope:{S:$envelope},
      delivery_status:{S:"dead_letter_pending"},
      delivery_attempts:{N:"4"},
      delivery_history:{L:[
        {M:{status:{S:"pending"},occurred_at:{N:$now}}},
        {M:{status:{S:"retrying"},occurred_at:{N:$now}}},
        {M:{status:{S:"failed"},occurred_at:{N:$now}}},
        {M:{status:{S:"dead_letter_pending"},occurred_at:{N:$now}}}
      ]},
      last_delivery_at:{N:$now},
      expires_at:{N:$expires}
    }' >"$item"
  "${AWS[@]}" dynamodb put-item --table-name "$SECURITY_TABLE" \
    --item "file://$item" --condition-expression 'attribute_not_exists(event_id)' >/dev/null
  FIXTURE_IDS+=("$event_id")
  wait_for_item_status "$event_id" dead_lettered ||
    fail "$CURRENT_STACK did not complete the durable terminal transition"
  jq -e --argjson minimum "$((now + 2555 * 86400 - 60))" '
    (.Item.expires_at.N | tonumber) >= $minimum
  ' "$WORK/$CURRENT_STACK.$event_id.item.json" >/dev/null ||
    fail "$CURRENT_STACK dead-letter row is not retained for seven years"

  key="$(python3 - "$TENANT" "$now" "$event_id" <<'PY'
import datetime
import sys

tenant, timestamp, event_id = sys.argv[1:]
date = datetime.datetime.fromtimestamp(int(timestamp), datetime.timezone.utc)
print(
    f"security-events/tenant_id={tenant}/year={date:%Y}/month={date:%m}/"
    f"day={date:%d}/{event_id}.json"
)
PY
)"
  if "${AWS[@]}" s3api head-object --bucket "$ARCHIVE_BUCKET" --key "$key" \
    >/dev/null 2>&1; then
    fail "$CURRENT_STACK terminal outbox unexpectedly rewrote S3"
  fi

  receipt=""
  for _ in $(seq 1 12); do
    response="$("${AWS[@]}" sqs receive-message --queue-url "$ARCHIVE_DLQ" \
      --max-number-of-messages 10 --wait-time-seconds 5 --visibility-timeout 30 \
      --output json)"
    receipt="$(jq -er --arg id "$event_id" '
      .Messages[]?
      | select((.Body | fromjson).event_id == $id)
      | .ReceiptHandle
    ' <<<"$response" 2>/dev/null | head -n 1 || true)"
    if [[ -n "$receipt" ]]; then
      jq -e --arg id "$event_id" --arg tenant "$TENANT" '
        .Messages[]?
        | select((.Body | fromjson).event_id == $id)
        | .Body
        | fromjson
        | .schema_version == "1.0"
          and .event_id == $id
          and .tenant_id == $tenant
          and .delivery.status == "dead_letter_pending"
          and (.delivery.attempts >= 4)
          and (.delivery.history[-1].status == "dead_letter_pending")
      ' <<<"$response" >/dev/null ||
        fail "$CURRENT_STACK terminal DLQ payload is incomplete"
      break
    fi
  done
  [[ -n "$receipt" ]] || fail "$CURRENT_STACK terminal DLQ did not receive $event_id"
  "${AWS[@]}" sqs delete-message --queue-url "$ARCHIVE_DLQ" \
    --receipt-handle "$receipt" >/dev/null
  pass "$CURRENT_STACK retained dead_letter row and complete FIFO incident payload"

  invoke_payload="$WORK/$CURRENT_STACK.redrive.json"
  printf '{"source":"aws.events"}\n' >"$invoke_payload"
  "${AWS[@]}" lambda invoke --function-name "$ARCHIVE_FN" \
    --payload "fileb://$invoke_payload" "$WORK/$CURRENT_STACK.redrive-response.json" \
    >"$WORK/$CURRENT_STACK.redrive-invoke.json"
  jq -e '.FunctionError == null' "$WORK/$CURRENT_STACK.redrive-invoke.json" >/dev/null ||
    fail "$CURRENT_STACK scheduled redrive invocation failed"
  key="$(assert_archived "$event_id")"
  FIXTURE_KEYS+=("$key")
  jq -e '
    [.Item.delivery_history.L[].M.status.S][-3:]
      == ["dead_letter_pending", "dead_lettered", "archived"]
    and (.Item.delivery_attempts.N | tonumber) == 5
  ' "$WORK/$CURRENT_STACK.$event_id.item.json" >/dev/null ||
    fail "$CURRENT_STACK scheduled redrive history/count is inconsistent"
  pass "$CURRENT_STACK scheduled dead-letter redrive archived $event_id"
}

create_poison_ingress() {
  local payload response receipt message_id key artifact
  payload="$(jq -cn --arg run "$RUN_ID-$CURRENT_STACK" \
    '{e2e_invalid_security_event_ingress:$run}')"
  message_id="$("${AWS[@]}" sqs send-message --queue-url "$INGRESS_QUEUE" \
    --message-body "$payload" --query MessageId --output text)"
  receipt=""
  for _ in $(seq 1 12); do
    response="$("${AWS[@]}" sqs receive-message --queue-url "$INGRESS_DLQ" \
      --max-number-of-messages 10 --wait-time-seconds 5 --visibility-timeout 30 \
      --output json)"
    receipt="$(jq -er --arg payload "$payload" '
      .Messages[]?
      | select(.Body == $payload)
      | .ReceiptHandle
    ' <<<"$response" 2>/dev/null | head -n 1 || true)"
    [[ -n "$receipt" ]] && break
  done
  [[ -n "$receipt" ]] ||
    fail "$CURRENT_STACK invalid ingress payload did not reach the terminal DLQ"
  key="security-event-ingress-failures/$message_id.json"
  "${AWS[@]}" s3api head-object --bucket "$INGRESS_FAILURE_BUCKET" --key "$key" >/dev/null ||
    fail "$CURRENT_STACK invalid ingress payload lacks its seven-year S3 artifact"
  artifact="$WORK/$CURRENT_STACK.poison-ingress.json"
  "${AWS[@]}" s3api get-object --bucket "$INGRESS_FAILURE_BUCKET" --key "$key" \
    "$artifact" >/dev/null
  [[ "$(cat "$artifact")" == "$payload" ]] ||
    fail "$CURRENT_STACK ingress failure artifact changed the original body"
  "${AWS[@]}" sqs delete-message --queue-url "$INGRESS_DLQ" \
    --receipt-handle "$receipt" >/dev/null
  "${AWS[@]}" s3api delete-object --bucket "$INGRESS_FAILURE_BUCKET" --key "$key" >/dev/null
  pass "$CURRENT_STACK poison ingress retained exact FIFO and seven-year S3 copies"
}

assert_admin_export() {
  local from="${1:?from required}" first="${2:?event required}" second="${3:?event required}"
  local through status output="$WORK/$CURRENT_STACK.admin-export.json" cursor page2
  through="$(( $(date +%s) + 60 ))"
  status="$(curl -sS -o "$output" -w '%{http_code}' \
    "$API_URL/admin/security-events?from=$from&through=$through&limit=1" \
    -H "authorization: Bearer $ADMIN_TOKEN")"
  [[ "$status" == "200" ]] ||
    fail "$CURRENT_STACK security-event export returned HTTP $status"
  jq -e --arg tenant "$TENANT" --arg first "$first" --arg second "$second" '
    .schema_version == "1.0"
    and .tenant_id == $tenant
    and .hot_retention_days == 400
    and .total == (.events | length)
    and (all(.events[]; .event.tenant_id == $tenant))
    and ([.events[].event.occurred_at] as $times
      | $times == ($times | sort | reverse))
    and (.events | length) == 1
    and (.next_cursor | type == "string" and length > 0)
  ' "$output" >/dev/null ||
    fail "$CURRENT_STACK tenant export first page is not scoped or paginated"
  cursor="$(jq -er '.next_cursor | @uri' "$output")"
  page2="$WORK/$CURRENT_STACK.admin-export-page2.json"
  status="$(curl -sS -o "$page2" -w '%{http_code}' \
    "$API_URL/admin/security-events?from=$from&through=$through&limit=500&cursor=$cursor" \
    -H "authorization: Bearer $ADMIN_TOKEN")"
  [[ "$status" == "200" ]] ||
    fail "$CURRENT_STACK security-event continuation returned HTTP $status"
  jq -e --arg tenant "$TENANT" --arg first "$first" --arg second "$second" \
    --slurpfile page1 "$output" '
    .tenant_id == $tenant
    and (all(.events[]; .event.tenant_id == $tenant))
    and (([$page1[0].events[].event.event_id] + [.events[].event.event_id]) as $ids
      | ($ids | index($first) != null) and ($ids | index($second) != null))
    and (([$page1[0].events[].event.occurred_at] + [.events[].event.occurred_at]) as $times
      | $times == ($times | sort | reverse))
  ' "$page2" >/dev/null ||
    fail "$CURRENT_STACK continuation is incomplete or not newest-first"
  pass "$CURRENT_STACK Admin export is authenticated, tenant-scoped, newest-first, and complete"
}

assert_athena() {
  local event_id="${1:?event required}"
  local item="$WORK/$CURRENT_STACK.$event_id.item.json"
  local timestamp year month day query_id state reason output
  timestamp="$(jq -er '.Item.occurred_at.N' "$item")"
  read -r year month day < <(
    python3 - "$timestamp" <<'PY'
import datetime
import sys

date = datetime.datetime.fromtimestamp(int(sys.argv[1]), datetime.timezone.utc)
print(date.strftime("%Y %m %d"))
PY
  )
  "${AWS[@]}" glue get-table --database-name "$GLUE_DATABASE" \
    --name security_events >"$WORK/$CURRENT_STACK.glue-table.json"
  jq -e --arg bucket "$ARCHIVE_BUCKET" '
    .Table.Parameters["projection.enabled"] == "true"
    and .Table.Parameters["projection.tenant_id.type"] == "injected"
    and .Table.StorageDescriptor.Location == ("s3://" + $bucket + "/security-events/")
  ' "$WORK/$CURRENT_STACK.glue-table.json" >/dev/null ||
    fail "$CURRENT_STACK Glue table does not expose the projected archive"

  ATHENA_PREFIX="athena-results/e2e/$RUN_ID/$CURRENT_STACK/"
  query_id="$(
    "${AWS[@]}" athena start-query-execution \
      --query-string \
        "SELECT event_id FROM security_events WHERE tenant_id='$TENANT' AND year='$year' AND month='$month' AND day='$day' AND event_id='$event_id' LIMIT 1" \
      --query-execution-context "Database=$GLUE_DATABASE" \
      --result-configuration "OutputLocation=s3://$ARCHIVE_BUCKET/$ATHENA_PREFIX" \
      --query QueryExecutionId --output text
  )"
  state=""
  for _ in $(seq 1 30); do
    state="$("${AWS[@]}" athena get-query-execution --query-execution-id "$query_id" \
      --query 'QueryExecution.Status.State' --output text)"
    [[ "$state" == "SUCCEEDED" ]] && break
    if [[ "$state" == "FAILED" || "$state" == "CANCELLED" ]]; then
      reason="$("${AWS[@]}" athena get-query-execution --query-execution-id "$query_id" \
        --query 'QueryExecution.Status.StateChangeReason' --output text)"
      fail "$CURRENT_STACK Athena query ended in $state: $reason"
    fi
    sleep 2
  done
  [[ "$state" == "SUCCEEDED" ]] ||
    fail "$CURRENT_STACK Athena query did not complete"
  output="$("${AWS[@]}" athena get-query-results --query-execution-id "$query_id" \
    --output json)"
  jq -e --arg id "$event_id" '
    [.ResultSet.Rows[].Data[0].VarCharValue] | index($id) != null
  ' <<<"$output" >/dev/null ||
    fail "$CURRENT_STACK Athena did not return archived event $event_id"
  pass "$CURRENT_STACK Glue/Athena projection returned $event_id"
}

assert_deployed_infrastructure() {
  local mappings alarms queue bucket notification_queue_arn notification_dlq_arn
  "${AWS[@]}" lambda get-function-configuration --function-name "$ARCHIVE_FN" \
    >"$WORK/$CURRENT_STACK.archive-fn.json"
  jq -e --arg table "$SECURITY_TABLE" --arg bucket "$ARCHIVE_BUCKET" '
    .Architectures == ["arm64"]
    and .Environment.Variables.SECURITY_EVENTS_TABLE == $table
    and .Environment.Variables.SECURITY_EVENT_ARCHIVE_BUCKET == $bucket
  ' "$WORK/$CURRENT_STACK.archive-fn.json" >/dev/null ||
    fail "$CURRENT_STACK archive Lambda configuration is inconsistent"

  mappings="$("${AWS[@]}" lambda list-event-source-mappings \
    --function-name "$ARCHIVE_FN" --output json)"
  notification_queue_arn="$("${AWS[@]}" sqs get-queue-attributes \
    --queue-url "$STREAM_FAILURE_NOTIFICATION_QUEUE" \
    --attribute-names QueueArn --query 'Attributes.QueueArn' --output text)"
  notification_dlq_arn="$("${AWS[@]}" sqs get-queue-attributes \
    --queue-url "$STREAM_FAILURE_NOTIFICATION_DLQ" \
    --attribute-names QueueArn --query 'Attributes.QueueArn' --output text)"
  jq -e --arg notification_queue_arn "$notification_queue_arn" '
    any(.EventSourceMappings[];
      .StartingPosition == "TRIM_HORIZON"
      and .BisectBatchOnFunctionError == true
      and .MaximumRetryAttempts == 3)
    and any(.EventSourceMappings[]; .BatchSize == 1 and .StartingPosition == null)
    and any(.EventSourceMappings[];
      .EventSourceArn == $notification_queue_arn and .BatchSize == 1)
  ' <<<"$mappings" >/dev/null ||
    fail "$CURRENT_STACK archive event-source mappings are incomplete"

  for queue in "$ARCHIVE_DLQ" "$INGRESS_DLQ"; do
    "${AWS[@]}" sqs get-queue-attributes --queue-url "$queue" \
      --attribute-names FifoQueue MessageRetentionPeriod \
        ApproximateNumberOfMessages ApproximateNumberOfMessagesNotVisible \
        ApproximateNumberOfMessagesDelayed --output json |
      jq -e '.Attributes.FifoQueue == "true"
        and .Attributes.MessageRetentionPeriod == "1209600"
        and (.Attributes.ApproximateNumberOfMessages | tonumber) == 0
        and (.Attributes.ApproximateNumberOfMessagesNotVisible | tonumber) == 0
        and (.Attributes.ApproximateNumberOfMessagesDelayed | tonumber) == 0' >/dev/null ||
      fail "$CURRENT_STACK terminal queue is misconfigured or contains an unresolved incident"
  done
  "${AWS[@]}" sqs get-queue-attributes \
    --queue-url "$STREAM_FAILURE_NOTIFICATION_QUEUE" \
    --attribute-names MessageRetentionPeriod RedrivePolicy --output json |
    jq -e --arg dlq_arn "$notification_dlq_arn" '
      .Attributes.MessageRetentionPeriod == "1209600"
      and (.Attributes.RedrivePolicy | fromjson
        | .maxReceiveCount == 4 and .deadLetterTargetArn == $dlq_arn)
    ' >/dev/null ||
    fail "$CURRENT_STACK stream-failure notification queue lacks durable redrive"
  "${AWS[@]}" sqs get-queue-attributes \
    --queue-url "$STREAM_FAILURE_NOTIFICATION_DLQ" \
    --attribute-names MessageRetentionPeriod ApproximateNumberOfMessages \
      ApproximateNumberOfMessagesNotVisible ApproximateNumberOfMessagesDelayed --output json |
    jq -e '.Attributes.MessageRetentionPeriod == "1209600"
      and (.Attributes.ApproximateNumberOfMessages | tonumber) == 0
      and (.Attributes.ApproximateNumberOfMessagesNotVisible | tonumber) == 0
      and (.Attributes.ApproximateNumberOfMessagesDelayed | tonumber) == 0' >/dev/null ||
    fail "$CURRENT_STACK stream-failure notification DLQ contains an unresolved incident"
  for bucket in "$ARCHIVE_BUCKET" "$FAILURE_BUCKET" "$INGRESS_FAILURE_BUCKET"; do
    "${AWS[@]}" s3api head-bucket --bucket "$bucket"
    "${AWS[@]}" s3api get-bucket-lifecycle-configuration --bucket "$bucket" |
      jq -e 'any(.Rules[]; .Expiration.Days == 2555 and .Status == "Enabled")' >/dev/null ||
      fail "$CURRENT_STACK retained bucket $bucket lacks seven-year expiration"
  done
  "${AWS[@]}" s3api get-bucket-versioning --bucket "$ARCHIVE_BUCKET" |
    jq -e '.Status == "Enabled"' >/dev/null ||
    fail "$CURRENT_STACK archive bucket versioning is not enabled"
  "${AWS[@]}" s3api get-bucket-lifecycle-configuration \
    --bucket "$ARCHIVE_BUCKET" |
    jq -e 'any(.Rules[];
      .Expiration.Days == 2555
      and .NoncurrentVersionExpiration.NoncurrentDays == 2555
      and .Status == "Enabled"
    )' >/dev/null ||
    fail "$CURRENT_STACK archive versions lack seven-year expiration"

  alarms="$("${AWS[@]}" cloudwatch describe-alarms \
    --alarm-name-prefix "$CURRENT_STACK-" --output json)"
  jq -e --arg stack "$CURRENT_STACK" \
    --arg namespace "AgentAuth/Security/$CURRENT_STACK" '
    def alarm($suffix):
      first(.MetricAlarms[]? | select(.AlarmName == ($stack + "-" + $suffix)));
    def metric($alarm; $namespace; $name):
      any($alarm.Metrics[]?;
        .MetricStat.Metric.Namespace == $namespace
        and .MetricStat.Metric.MetricName == $name
        and .MetricStat.Period == 300);
    ["AuthenticationFailures","InfrastructureErrors","CrossTenantDenials",
     "ArchiveBacklog","ArchiveDeadLetters"] as $suffixes
    | ([$suffixes[] as $suffix
        | alarm($suffix).TreatMissingData == "notBreaching"] | all)
      and (alarm("AuthenticationFailures") as $alarm
        | $alarm.Namespace == $namespace
          and $alarm.MetricName == "AuthenticationFailures"
          and $alarm.Period == 300 and $alarm.Threshold == 5)
      and (alarm("CrossTenantDenials") as $alarm
        | $alarm.Namespace == $namespace
          and $alarm.MetricName == "CrossTenantDenials"
          and $alarm.Period == 300 and $alarm.Threshold == 1)
      and (alarm("InfrastructureErrors") as $alarm
        | any($alarm.Metrics[]?;
            .Expression == "custom + auth + archive + reclaim + recompute")
          and metric($alarm; $namespace; "InfrastructureErrors")
          and ([ $alarm.Metrics[]?
            | select(.MetricStat.Metric.Namespace == "AWS/Lambda"
              and .MetricStat.Metric.MetricName == "Errors") ] | length) == 4
          and $alarm.Threshold == 1)
      and (alarm("ArchiveBacklog") as $alarm
        | any($alarm.Metrics[]?;
            .Expression == "MAX([stream, ingress * 1000, failureNotifications * 1000])")
          and metric($alarm; "AWS/Lambda"; "IteratorAge")
          and ([ $alarm.Metrics[]?
            | select(.MetricStat.Metric.Namespace == "AWS/SQS"
              and .MetricStat.Metric.MetricName
                == "ApproximateAgeOfOldestMessage") ] | length) == 2
          and $alarm.Threshold == 60000)
      and (alarm("ArchiveDeadLetters") as $alarm
        | any($alarm.Metrics[]?;
            .Expression == "transitions + archive + ingress + failureNotifications")
          and metric($alarm; $namespace; "ArchiveDeadLetters")
          and ([ $alarm.Metrics[]?
            | select(.MetricStat.Metric.Namespace == "AWS/SQS"
              and .MetricStat.Metric.MetricName
                == "ApproximateNumberOfMessagesVisible") ] | length) == 3
          and $alarm.Threshold == 1)
  ' <<<"$alarms" >/dev/null ||
    fail "$CURRENT_STACK does not expose the five expected metric paths"
  pass "$CURRENT_STACK deployed archive, retention, FIFO DLQs, and five alarms are wired"
}

wait_for_fresh_metric_window() {
  local now phase sleep_for
  now="$(date +%s)"
  phase="$((now % 300))"
  if ((phase > 15)); then
    sleep_for="$((305 - phase))"
    printf 'Waiting %ss for a fresh CloudWatch metric window...\n' "$sleep_for"
    sleep "$sleep_for"
  fi
}

wait_all_alarm_states() {
  local expected="${1:?state required}"
  local output="$WORK/$CURRENT_STACK.alarms-$expected.json"
  for _ in $(seq 1 90); do
    "${AWS[@]}" cloudwatch describe-alarms --alarm-name-prefix "$CURRENT_STACK-" \
      --output json >"$output"
    if jq -e --arg stack "$CURRENT_STACK" --arg expected "$expected" '
      ["AuthenticationFailures","InfrastructureErrors","CrossTenantDenials",
       "ArchiveBacklog","ArchiveDeadLetters"] as $suffixes
      | ([$suffixes[] as $suffix
          | any(.MetricAlarms[];
              .AlarmName == ($stack + "-" + $suffix)
              and .StateValue == $expected)] | all)
    ' "$output" >/dev/null; then
      return 0
    fi
    sleep 10
  done
  return 1
}

wait_alarm_state() {
  local suffix="${1:?alarm suffix required}" expected="${2:?state required}"
  local output="$WORK/$CURRENT_STACK.alarm-$suffix-$expected.json"
  for _ in $(seq 1 90); do
    "${AWS[@]}" cloudwatch describe-alarms --alarm-names "$CURRENT_STACK-$suffix" \
      --output json >"$output"
    if jq -e --arg expected "$expected" '
      .MetricAlarms[0].StateValue == $expected
    ' "$output" >/dev/null; then
      return 0
    fi
    sleep 10
  done
  return 1
}

wait_alarm_transitions() {
  local expected="${1:?state required}" suffix output
  shift
  local -a suffixes=("$@")
  local -a alarm_names=()
  local -A observed=()
  output="$WORK/$CURRENT_STACK.alarm-transitions-$expected.json"
  for suffix in "${suffixes[@]}"; do
    alarm_names+=("$CURRENT_STACK-$suffix")
  done
  for _ in $(seq 1 90); do
    "${AWS[@]}" cloudwatch describe-alarms --alarm-names "${alarm_names[@]}" \
      --output json >"$output"
    for suffix in "${suffixes[@]}"; do
      if jq -e --arg name "$CURRENT_STACK-$suffix" --arg expected "$expected" '
        any(.MetricAlarms[];
          .AlarmName == $name and .StateValue == $expected)
      ' "$output" >/dev/null; then
        observed["$suffix"]=1
      fi
    done
    ((${#observed[@]} == ${#suffixes[@]})) && return 0
    sleep 10
  done
  for suffix in "${suffixes[@]}"; do
    [[ -n "${observed[$suffix]:-}" ]] ||
      printf 'Missing %s transition for %s-%s\n' \
        "$expected" "$CURRENT_STACK" "$suffix" >&2
  done
  return 1
}

exercise_alarm_transitions() {
  local now event_id payload key status foreign_tenant queued attributes current
  wait_all_alarm_states OK ||
    fail "$CURRENT_STACK alarms did not reach a clean OK baseline"
  create_terminal_event

  ARCHIVE_RESERVED_CONCURRENCY="$("${AWS[@]}" lambda get-function-concurrency \
    --function-name "$ARCHIVE_FN" --query ReservedConcurrentExecutions --output text)"
  [[ "$ARCHIVE_RESERVED_CONCURRENCY" == "None" ]] && ARCHIVE_RESERVED_CONCURRENCY=""
  ARCHIVE_CONCURRENCY_BLOCKED=1
  "${AWS[@]}" lambda put-function-concurrency --function-name "$ARCHIVE_FN" \
    --reserved-concurrent-executions 0 >/dev/null ||
    fail "$CURRENT_STACK could not block archive concurrency for backlog test"
  current="$("${AWS[@]}" lambda get-function-concurrency \
    --function-name "$ARCHIVE_FN" --query ReservedConcurrentExecutions --output text)"
  [[ "$current" == "0" ]] ||
    fail "$CURRENT_STACK archive reserved concurrency did not reach zero"

  now="$(date +%s)"
  event_id="evt_e2e_alarm_$(openssl rand -hex 8)"
  payload="$WORK/$CURRENT_STACK.$event_id.alarm-ingress.json"
  jq -n --arg id "$event_id" --arg tenant "$TENANT" --arg run "$RUN_ID" \
    --argjson now "$now" '{
      event: {
        schema_version: "1.0",
        event_id: $id,
        occurred_at: $now,
        tenant_id: $tenant,
        actor: {kind: "system", id: "e2e-security-events"},
        subject: {kind: "tenant", id: $tenant},
        category: "delivery",
        action: "e2e.alarm_backlog",
        outcome: "failure",
        correlation: {operation_id: $run}
      },
      delivery: {
        status: "pending",
        attempts: 0,
        history: [{status: "pending", occurred_at: $now}]
      },
      ingress_attempts: 0
    }' >"$payload"
  "${AWS[@]}" sqs send-message --queue-url "$INGRESS_QUEUE" \
    --message-body "file://$payload" >/dev/null
  FIXTURE_IDS+=("$event_id")

  queued=0
  for _ in $(seq 1 12); do
    attributes="$("${AWS[@]}" sqs get-queue-attributes --queue-url "$INGRESS_QUEUE" \
      --attribute-names ApproximateNumberOfMessages ApproximateNumberOfMessagesNotVisible \
      --output json)"
    queued="$(jq -r '
      (.Attributes.ApproximateNumberOfMessages | tonumber)
      + (.Attributes.ApproximateNumberOfMessagesNotVisible | tonumber)
    ' <<<"$attributes")"
    ((queued > 0)) && break
    sleep 5
  done
  ((queued > 0)) ||
    fail "$CURRENT_STACK backlog fixture was deleted while archive concurrency was zero"

  wait_alarm_state ArchiveBacklog ALARM ||
    fail "$CURRENT_STACK real ingress backlog did not enter ALARM"
  pass "$CURRENT_STACK real ingress backlog entered ALARM"

  # Start the remaining producer signals near a five-minute boundary while the
  # backlog is still breaching, then restore the worker before poison ingress.
  wait_for_fresh_metric_window
  restore_archive_concurrency ||
    fail "$CURRENT_STACK archive reserved concurrency did not restore"
  key="$(assert_archived "$event_id")"
  FIXTURE_KEYS+=("$key")

  create_real_fallback_event
  create_emergency_recovery_event

  for _ in $(seq 1 5); do
    status="$(curl -sS -o /dev/null -w '%{http_code}' \
      "$API_URL/admin/security-events?from=0&through=1" \
      -H "authorization: Bearer e2e-invalid-$RUN_ID")"
    [[ "$status" == "401" ]] ||
      fail "$CURRENT_STACK invalid Admin authentication returned HTTP $status"
  done

  foreign_tenant="e2e-foreign"
  [[ "$foreign_tenant" == "$TENANT" ]] && foreign_tenant="e2e-other"
  status="$(curl -sS -o /dev/null -w '%{http_code}' \
    "$API_URL/admin/workload-trust/$foreign_tenant" \
    -H "authorization: Bearer $ADMIN_TOKEN")"
  [[ "$status" == "403" ]] ||
    fail "$CURRENT_STACK cross-tenant Admin query returned HTTP $status"

  create_poison_ingress

  wait_alarm_transitions ALARM \
    AuthenticationFailures InfrastructureErrors CrossTenantDenials ArchiveDeadLetters ||
    fail "$CURRENT_STACK producer alarms did not each enter ALARM"
  pass "$CURRENT_STACK five deployed alarms each entered ALARM from real producer paths"

  wait_all_alarm_states OK ||
    fail "$CURRENT_STACK five alarms did not return to OK after metrics cleared"
  pass "$CURRENT_STACK five deployed alarms returned to OK"
}

for stack in $STACKS; do
  printf '\n== %s security-event acceptance ==\n' "$stack"
  load_stack "$stack"
  assert_deployed_infrastructure
  STARTED="$(date +%s)"
  create_auth_event
  AUTH_EVENT="$RESULT_EVENT_ID"
  create_ingress_event
  INGRESS_EVENT="$RESULT_EVENT_ID"
  assert_admin_export "$STARTED" "$AUTH_EVENT" "$INGRESS_EVENT"
  assert_athena "$AUTH_EVENT"
  exercise_alarm_transitions
  cleanup_current
done

printf '\nAll requested security-event stacks passed live acceptance.\n'
