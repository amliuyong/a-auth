#!/usr/bin/env bash
# Restart-safe passing restore-cutover gate for C12.7.
#
# This harness restores the 12 recoverable business-authority tables from one
# current PITR cutoff, runs the deployed commit's read-only governance verifier,
# and deletes every isolated table before publishing PASS evidence. It never
# changes a production table or traffic reference.
#
# Usage:
#   CONFIRM_GOVERNANCE_CUTOVER=post-offboarding-current-authority \
#   AWS_PROFILE=default REGION=us-east-1 \
#   ./e2e/governance_restore_cutover_live.sh
#
# Resume an interrupted run with the printed RUN_ID. Cleanup can also be
# invoked independently:
#   ACTION=cleanup RUN_ID=<run-id> AWS_PROFILE=default REGION=us-east-1 \
#   ./e2e/governance_restore_cutover_live.sh
set -euo pipefail
set +x

ACTION="${ACTION:-run}"
ROLE="${ROLE:-}"
STACK="${STACK:-AgentAuthSaas}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
CONFIRM_GOVERNANCE_CUTOVER="${CONFIRM_GOVERNANCE_CUTOVER:-}"
CONFIRM_AMBIGUOUS_ABSENCE="${CONFIRM_AMBIGUOUS_ABSENCE:-}"
RUN_ID_INPUT="${RUN_ID:-}"
STATE_ROOT="${STATE_ROOT:-$HOME/.agent-auth-governance-cutover-live}"
POLL_SECS="${POLL_SECS:-10}"
POLL_TIMEOUT_SECS="${POLL_TIMEOUT_SECS:-3600}"
ABSENCE_STABLE_SECS="${ABSENCE_STABLE_SECS:-30}"
CLOUDTRAIL_LOOKUP_SECS="${CLOUDTRAIL_LOOKUP_SECS:-900}"
RPO_TARGET_SECS="${RPO_TARGET_SECS:-600}"
REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ID="${RUN_ID_INPUT:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
STATE_DIR="$STATE_ROOT/$RUN_ID"
CONTEXT="$STATE_DIR/context.json"
TABLE_MAP="$STATE_DIR/restored-tables.json"
SOURCES="$STATE_DIR/sources.json"
INNER_EVIDENCE="$STATE_DIR/verifier-evidence.json"
FINAL_EVIDENCE="$STATE_DIR/final-evidence.json"
STACK_POLICY_STATE="$STATE_DIR/stack-policy-state.json"
AWSQ=(aws --profile "$PROFILE" --region "$REGION")

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}
pass() { printf 'PASS: %s\n' "$*"; }
info() { printf 'INFO: %s\n' "$*"; }
now_epoch() { date -u +%s; }
sha256_text() {
  printf '%s' "$1" | sha256sum | cut -d' ' -f1
}

intent_path() {
  printf '%s/restore-intent-%s.json\n' "$STATE_DIR" "$1"
}

receipt_path() {
  printf '%s/restore-receipt-%s.json\n' "$STATE_DIR" "$1"
}

resolution_path() {
  printf '%s/restore-absence-resolution-%s.json\n' "$STATE_DIR" "$1"
}

case "$ACTION" in
  run | cleanup | resolve-absent) ;;
  *) fail "ACTION must be run, cleanup, or resolve-absent" ;;
esac
if [[ ! "$RUN_ID" =~ ^[A-Za-z0-9._-]{1,64}$ ]] ||
  [[ "$RUN_ID" == "." || "$RUN_ID" == ".." ]]; then
  fail "invalid RUN_ID"
fi
[[ "$REGION" == "us-east-1" ]] ||
  fail "qualifying gate requires REGION=us-east-1"
[[ "$STACK" == "AgentAuthSaas" ]] ||
  fail "qualifying gate requires STACK=AgentAuthSaas"
[[ "$POLL_SECS" =~ ^[1-9][0-9]*$ ]] ||
  fail "POLL_SECS must be a positive integer"
[[ "$POLL_TIMEOUT_SECS" =~ ^[1-9][0-9]*$ ]] ||
  fail "POLL_TIMEOUT_SECS must be a positive integer"
[[ "$ABSENCE_STABLE_SECS" =~ ^[1-9][0-9]*$ ]] ||
  fail "ABSENCE_STABLE_SECS must be a positive integer"
[[ "$CLOUDTRAIL_LOOKUP_SECS" =~ ^[1-9][0-9]*$ ]] ||
  fail "CLOUDTRAIL_LOOKUP_SECS must be a positive integer"
[[ "$RPO_TARGET_SECS" =~ ^[1-9][0-9]*$ ]] ||
  fail "RPO_TARGET_SECS must be a positive integer"
if [[ "$ACTION" == "run" ]]; then
  [[ "$CONFIRM_GOVERNANCE_CUTOVER" == \
    "post-offboarding-current-authority" ]] ||
    fail "set CONFIRM_GOVERNANCE_CUTOVER=post-offboarding-current-authority"
fi
if [[ "$ACTION" == "resolve-absent" ]]; then
  [[ "$CONFIRM_AMBIGUOUS_ABSENCE" == \
    "restore-not-accepted-after-cloudtrail-review" ]] ||
    fail "set CONFIRM_AMBIGUOUS_ABSENCE=restore-not-accepted-after-cloudtrail-review"
  [[ "$ROLE" =~ ^[a-z_]{3,64}$ ]] || fail "ROLE is required for resolve-absent"
fi

for command in \
  aws bash cat cmp cp cut date find flock git grep jq mktemp mv rm rmdir \
  python3 sha256sum sleep sort tee wc; do
  command -v "$command" >/dev/null || fail "missing command: $command"
done
python3 -c 'import boto3' >/dev/null ||
  fail "Python boto3 is required for stack-policy request receipts"

umask 077
mkdir -p "$STATE_ROOT" "$STATE_DIR"
chmod 700 "$STATE_ROOT" "$STATE_DIR"
exec 9>"$STATE_ROOT/.$RUN_ID.lock"
chmod 600 "$STATE_ROOT/.$RUN_ID.lock"
flock -n 9 || fail "another process owns RUN_ID=$RUN_ID"
touch "$STATE_DIR/gate.log"
chmod 600 "$STATE_DIR/gate.log"
exec > >(tee -a "$STATE_DIR/gate.log") 2>&1

WORK="$(mktemp -d)"
chmod 700 "$WORK"
DEPLOYED_TREE="$WORK/deployed"
DEPLOYED_TREE_ADDED=0
RESTORED_TABLES_CLEANED=0
STACK_FREEZE_ACQUIRED=0

atomic_write() {
  local destination="$1"
  local temporary="$destination.current.$$"
  cat >"$temporary"
  chmod 600 "$temporary"
  mv "$temporary" "$destination"
}

context_value() {
  jq -er "$1" "$CONTEXT"
}

describe_table() {
  local table="$1" output="$2" error="$3"
  if "${AWSQ[@]}" dynamodb describe-table \
    --table-name "$table" --output json >"$output" 2>"$error"; then
    chmod 600 "$output"
    return 0
  fi
  if grep -q 'ResourceNotFoundException' "$error"; then
    return 1
  fi
  cat "$error" >&2
  return 2
}

stack_role_map_from_file() {
  jq -cer '
    .Stacks[0].Outputs
    | map(select(.OutputKey == "ReplicatedAuthorityTableNames"))
    | if length == 1 then .[0].OutputValue | fromjson
      else error("ReplicatedAuthorityTableNames")
      end
  ' "$1"
}

stack_business_role_map_from_file() {
  stack_role_map_from_file "$1" | jq -cer '
    with_entries(select(.key | IN(
      "admin_auth", "clients", "domain_map", "federation_config",
      "grants", "passkeys", "password_credentials", "scim_groups",
      "security_events", "tenant_keys", "users", "workload_trust"
    )))
  '
}

validate_current_stack_context() {
  local current="$WORK/current-stack.json"
  local current_map persisted_map role table description
  local current_creation_epoch expected_creation_epoch
  "${AWSQ[@]}" cloudformation describe-stacks \
    --stack-name "$STACK" --output json >"$current"
  jq -e '
    .Stacks[0].StackStatus == "CREATE_COMPLETE" or
    .Stacks[0].StackStatus == "UPDATE_COMPLETE"
  ' "$current" >/dev/null ||
    fail "$STACK changed or is not stable during the cutover run"
  [[ "$(jq -er '.Stacks[0].StackId' "$current")" == \
    "$(context_value '.stack_id')" ]] ||
    fail "current stack identity differs from the persisted cutover context"
  [[ "$(
    jq -er '
      .Stacks[0].Outputs
      | map(select(.OutputKey == "DeploymentCommit"))
      | if length == 1 then .[0].OutputValue else error("DeploymentCommit") end
    ' "$current"
  )" == "$(context_value '.deployed_commit')" ]] ||
    fail "current stack deployment differs from the persisted cutover context"
  current_map="$(stack_business_role_map_from_file "$current")"
  persisted_map="$(jq -cS 'with_entries(.value = .value.table)' "$SOURCES")"
  [[ "$(jq -cS . <<<"$current_map")" == "$persisted_map" ]] ||
    fail "current authority table set differs from the persisted source set"
  while IFS=$'\t' read -r role table; do
    description="$WORK/current-source-$role.json"
    "${AWSQ[@]}" dynamodb describe-table \
      --table-name "$table" --output json >"$description"
    current_creation_epoch=$(
      date -u -d "$(jq -er '.Table.CreationDateTime' "$description")" +%s
    )
    expected_creation_epoch=$(
      jq -er --arg role "$role" '.[$role].creation_epoch' "$SOURCES"
    )
    jq -e \
      --arg role "$role" \
      --arg arn "$(jq -er --arg role "$role" '.[$role].table_arn' "$SOURCES")" \
      --arg table_id "$(jq -er --arg role "$role" '.[$role].table_id' "$SOURCES")" '
        .Table.TableArn == $arn and
        .Table.TableId == $table_id
      ' "$description" >/dev/null ||
      fail "current source table identity changed for role $role"
    ((current_creation_epoch == expected_creation_epoch)) ||
      fail "current source table creation changed for role $role"
  done < <(jq -r 'to_entries[] | [.key, .value.table] | @tsv' "$SOURCES")
}

write_stack_policy_files() {
  jq -n '{
    Statement: [{
      Effect: "Deny",
      Principal: "*",
      Action: "Update:*",
      Resource: "*"
    }]
  }' >"$WORK/stack-freeze-policy.json"
  jq -n '{
    Statement: [{
      Effect: "Allow",
      Principal: "*",
      Action: "Update:*",
      Resource: "*"
    }]
  }' >"$WORK/stack-default-policy.json"
}

current_stack_policy() {
  local raw
  raw=$("${AWSQ[@]}" cloudformation get-stack-policy \
    --stack-name "$STACK" --query StackPolicyBody --output text)
  if [[ -z "$raw" || "$raw" == "None" ]]; then
    printf 'null\n'
  else
    jq -cS . <<<"$raw"
  fi
}

set_stack_policy_with_receipt() {
  local policy_file="$1"
  AWS_PROFILE="$PROFILE" AWS_REGION="$REGION" STACK_NAME="$STACK" \
    POLICY_FILE="$policy_file" python3 - <<'PY'
import os
from pathlib import Path

import boto3

session = boto3.Session(
    profile_name=os.environ["AWS_PROFILE"],
    region_name=os.environ["AWS_REGION"],
)
response = session.client("cloudformation").set_stack_policy(
    StackName=os.environ["STACK_NAME"],
    StackPolicyBody=Path(os.environ["POLICY_FILE"]).read_text(encoding="utf-8"),
)
request_id = response.get("ResponseMetadata", {}).get("RequestId", "")
if not request_id:
    raise SystemExit("SetStackPolicy did not return a request ID")
print(request_id, end="")
PY
}

verify_single_stack_policy_event() {
  local started_at="$1" request_id="$2" phase="$3"
  local deadline events count matching
  deadline=$(( $(now_epoch) + CLOUDTRAIL_LOOKUP_SECS ))
  events="$WORK/stack-policy-events-$phase.json"
  while true; do
    "${AWSQ[@]}" cloudtrail lookup-events \
      --lookup-attributes AttributeKey=EventName,AttributeValue=SetStackPolicy \
      --start-time "$(date -u -d "@$((started_at - 60))" +%Y-%m-%dT%H:%M:%SZ)" \
      --end-time "$(date -u -d "@$(( $(now_epoch) + 60 ))" +%Y-%m-%dT%H:%M:%SZ)" \
      --output json >"$WORK/stack-policy-events.json"
    jq \
      --arg stack "$STACK" \
      --arg stack_id "$(context_value '.stack_id')" \
      --arg region "$REGION" \
      --arg account "$(context_value '.account_id')" \
      --argjson started_at "$started_at" '
        def event_epoch:
          if type == "number" then floor
          elif type == "string" and test("^[0-9]+([.][0-9]+)?$")
          then tonumber | floor
          elif type == "string" then try fromdateiso8601 catch null
          else null
          end;
        [
          .Events[]
          | try (.CloudTrailEvent | fromjson) catch empty
          | (.eventTime | event_epoch) as $event_epoch
          | select(
              .eventSource == "cloudformation.amazonaws.com" and
              .eventName == "SetStackPolicy" and
              .awsRegion == $region and
              .recipientAccountId == $account and
              (.errorCode // null) == null and
              (.errorMessage // null) == null and
              $event_epoch != null and
              $event_epoch >= $started_at and
              (
                .requestParameters.stackName == $stack or
                .requestParameters.stackName == $stack_id or
                ([.resources[]?.ARN] | index($stack_id) != null)
              )
            )
        ]
      ' "$WORK/stack-policy-events.json" >"$events"
    count=$(jq -er 'length' "$events")
    ((count <= 1)) ||
      fail "concurrent CloudFormation stack-policy changes detected"
    matching=$(jq -er --arg request_id "$request_id" \
      '[.[] | select(.requestID == $request_id)] | length' "$events")
    if ((count == 1 && matching == 1)); then
      break
    fi
    (( $(now_epoch) < deadline )) ||
      fail "CloudTrail did not confirm the $phase stack-policy change"
    sleep "$POLL_SECS"
  done
  jq -er --arg request_id "$request_id" '
    .[0]
    | select(.requestID == $request_id)
    | .eventID
    | select(type == "string" and length > 0)
  ' "$events" ||
    fail "CloudTrail stack-policy event is malformed"
}

acquire_stack_freeze() {
  ((STACK_FREEZE_ACQUIRED == 0)) || return 0
  write_stack_policy_files
  local current second_read freeze original original_present default_allow
  local freeze_started_at freeze_request_id freeze_event_id
  freeze_started_at=$(now_epoch)
  current="$(current_stack_policy)"
  freeze="$(jq -cS . "$WORK/stack-freeze-policy.json")"
  default_allow="$(jq -cS . "$WORK/stack-default-policy.json")"
  if [[ ! -s "$STACK_POLICY_STATE" ]]; then
    if [[ "$current" == "null" ]]; then
      original_present=false
      original=null
    else
      original_present=true
      original="$current"
    fi
    jq -n \
      --argjson original_present "$original_present" \
      --argjson original_policy "$original" \
      --arg freeze_sha256 "$(sha256sum "$WORK/stack-freeze-policy.json" | cut -d' ' -f1)" \
      --argjson freeze_started_at "$freeze_started_at" '{
        schema_version: 1,
        original_present: $original_present,
        original_policy: $original_policy,
        freeze_sha256: $freeze_sha256,
        freeze_started_at: $freeze_started_at,
        freeze_event_verified: false,
        restored: false
      }' | atomic_write "$STACK_POLICY_STATE"
  else
    jq -e '
      .schema_version == 1 and
      (.original_present | type == "boolean") and
      (
        if .original_present then (.original_policy | type == "object")
        else .original_policy == null
        end
      ) and
      (.freeze_sha256 | test("^[0-9a-f]{64}$"))
    ' "$STACK_POLICY_STATE" >/dev/null ||
      fail "persisted stack-policy state is malformed"
    [[ "$(jq -er '.freeze_sha256' "$STACK_POLICY_STATE")" == \
      "$(sha256sum "$WORK/stack-freeze-policy.json" | cut -d' ' -f1)" ]] ||
      fail "persisted deployment freeze policy differs from this harness"
    original_present=$(jq -er '.original_present' "$STACK_POLICY_STATE")
    if [[ "$original_present" == "true" ]]; then
      original=$(jq -cS '.original_policy' "$STACK_POLICY_STATE")
    else
      original=null
    fi
    if [[ "$original_present" == "false" &&
      "$current" == "$default_allow" ]]; then
      :
    elif [[ "$current" != "$freeze" && "$current" != "$original" ]]; then
      fail "stack policy changed outside this cutover run"
    fi
    if [[ "$current" == "$freeze" &&
      "$(jq -er '.freeze_event_verified // false' "$STACK_POLICY_STATE")" == "true" ]]; then
      validate_current_stack_context
      STACK_FREEZE_ACQUIRED=1
      return 0
    fi
    jq --argjson freeze_started_at "$freeze_started_at" '
      .freeze_started_at = $freeze_started_at |
      .freeze_event_verified = false |
      .restored = false |
      del(.restored_at)
    ' "$STACK_POLICY_STATE" | atomic_write "$STACK_POLICY_STATE"
  fi
  second_read="$(current_stack_policy)"
  [[ "$second_read" == "$current" ]] ||
    fail "stack policy changed while acquiring the deployment freeze"
  freeze_request_id=$(set_stack_policy_with_receipt \
    "$WORK/stack-freeze-policy.json")
  [[ "$freeze_request_id" =~ ^[A-Za-z0-9-]{8,128}$ ]] ||
    fail "SetStackPolicy returned a malformed request ID"
  jq --arg freeze_request_id "$freeze_request_id" \
    '.freeze_request_id = $freeze_request_id' \
    "$STACK_POLICY_STATE" | atomic_write "$STACK_POLICY_STATE"
  [[ "$(current_stack_policy)" == "$freeze" ]] ||
    fail "could not verify the deployment freeze policy"
  freeze_event_id=$(verify_single_stack_policy_event \
    "$freeze_started_at" "$freeze_request_id" freeze)
  jq --arg freeze_event_id "$freeze_event_id" '
    .freeze_event_verified = true |
    .freeze_event_id = $freeze_event_id |
    .freeze_event_verified_at = now
  ' "$STACK_POLICY_STATE" | atomic_write "$STACK_POLICY_STATE"
  validate_current_stack_context
  STACK_FREEZE_ACQUIRED=1
}

stack_freeze_is_active() {
  write_stack_policy_files
  [[ "$(current_stack_policy)" == \
    "$(jq -cS . "$WORK/stack-freeze-policy.json")" ]]
}

restore_stack_policy() {
  [[ -s "$STACK_POLICY_STATE" ]] || return 0
  write_stack_policy_files
  local current freeze expected target original_present restore_started_at
  local restore_request_id restore_event_id restore_event_verified
  local freeze_event_verified restored restore_pending
  current="$(current_stack_policy)" || return 1
  freeze="$(jq -cS . "$WORK/stack-freeze-policy.json")"
  original_present=$(jq -er '.original_present' "$STACK_POLICY_STATE")
  if [[ "$original_present" == "true" ]]; then
    jq '.original_policy' "$STACK_POLICY_STATE" >"$WORK/stack-restore-policy.json"
  else
    cp "$WORK/stack-default-policy.json" "$WORK/stack-restore-policy.json"
  fi
  expected="$(jq -cS . "$WORK/stack-restore-policy.json")"
  if [[ "$original_present" == "false" && "$current" == "null" ]]; then
    expected=null
  fi
  restored=$(jq -er '.restored // false' "$STACK_POLICY_STATE")
  if [[ "$restored" == "true" ]]; then
    [[ "$current" == "$expected" ]] || {
      printf 'FAIL: restored stack policy changed after verification\n' >&2
      return 1
    }
    return 0
  fi

  freeze_event_verified=$(
    jq -er '.freeze_event_verified // false' "$STACK_POLICY_STATE"
  )
  if [[ "$freeze_event_verified" != "true" ]]; then
    if [[ "$current" == "$expected" ]]; then
      jq --argjson restored_at "$(now_epoch)" '
        .restored = true |
        .restored_at = $restored_at |
        .restore_not_required = true
      ' "$STACK_POLICY_STATE" | atomic_write "$STACK_POLICY_STATE"
      return 0
    fi
    printf 'FAIL: deployment freeze lacks a unique CloudTrail receipt\n' >&2
    return 1
  fi
  if [[ "$current" != "$freeze" && "$current" != "$expected" ]]; then
    printf 'FAIL: refusing to overwrite a concurrently changed stack policy\n' >&2
    return 1
  fi

  restore_pending=$(jq -er '.restore_pending // false' "$STACK_POLICY_STATE")
  restore_request_id=$(jq -er '.restore_request_id // ""' "$STACK_POLICY_STATE")
  restore_event_verified=$(
    jq -er '.restore_event_verified // false' "$STACK_POLICY_STATE"
  )
  if [[ "$restore_event_verified" != "true" ]]; then
    if [[ -z "$restore_request_id" ]]; then
      if [[ "$restore_pending" == "true" ]]; then
        # Separate a replacement idempotent request from an accepted request
        # whose response was lost before its RequestId could be persisted.
        sleep 2
      fi
      restore_started_at=$(now_epoch)
      jq --argjson restore_started_at "$restore_started_at" '
        .restore_pending = true |
        .restore_started_at = $restore_started_at |
        .restore_event_verified = false |
        del(
          .restore_request_id,
          .restore_event_id,
          .restore_event_verified_at
        )
      ' "$STACK_POLICY_STATE" | atomic_write "$STACK_POLICY_STATE"
      restore_request_id=$(set_stack_policy_with_receipt \
        "$WORK/stack-restore-policy.json") || return 1
      [[ "$restore_request_id" =~ ^[A-Za-z0-9-]{8,128}$ ]] || return 1
      jq --arg restore_request_id "$restore_request_id" '
        .restore_request_id = $restore_request_id
      ' "$STACK_POLICY_STATE" | atomic_write "$STACK_POLICY_STATE"
    else
      restore_started_at=$(jq -er '.restore_started_at' "$STACK_POLICY_STATE")
    fi
    restore_event_id=$(verify_single_stack_policy_event \
      "$restore_started_at" "$restore_request_id" restore) || return 1
    jq \
      --arg restore_event_id "$restore_event_id" \
      --argjson restore_event_verified_at "$(now_epoch)" '
        .restore_event_verified = true |
        .restore_event_id = $restore_event_id |
        .restore_event_verified_at = $restore_event_verified_at
      ' "$STACK_POLICY_STATE" | atomic_write "$STACK_POLICY_STATE"
  fi

  target="$(current_stack_policy)" || return 1
  [[ "$target" == "$expected" ]] || return 1
  jq --argjson restored_at "$(now_epoch)" \
    '.restored = true | .restored_at = $restored_at | .restore_pending = false' \
    "$STACK_POLICY_STATE" | atomic_write "$STACK_POLICY_STATE"
  STACK_FREEZE_ACQUIRED=0
}

assert_safe_delete() {
  local target="$1" current="$WORK/delete-stack.json" current_map
  stack_freeze_is_active ||
    fail "refusing cleanup without the deployment freeze policy"
  "${AWSQ[@]}" cloudformation describe-stacks \
    --stack-name "$STACK" --output json >"$current"
  jq -e '
    .Stacks[0].StackStatus == "CREATE_COMPLETE" or
    .Stacks[0].StackStatus == "UPDATE_COMPLETE"
  ' "$current" >/dev/null ||
    fail "refusing cleanup while $STACK is changing"
  [[ "$(jq -er '.Stacks[0].StackId' "$current")" == \
    "$(context_value '.stack_id')" ]] ||
    fail "refusing cleanup after stack identity changed"
  [[ "$(
    jq -er '
      .Stacks[0].Outputs
      | map(select(.OutputKey == "DeploymentCommit"))
      | if length == 1 then .[0].OutputValue else error("DeploymentCommit") end
    ' "$current"
  )" == "$(context_value '.deployed_commit')" ]] ||
    fail "refusing cleanup after the deployed commit changed"
  current_map="$(stack_role_map_from_file "$current")"
  jq -e --arg target "$target" 'all(.[]; . != $target)' \
    <<<"$current_map" >/dev/null ||
    fail "refusing to delete a table referenced by the current stack"
}

write_restore_intent() {
  local role="$1" target="$2" source_arn="$3"
  local path
  path="$(intent_path "$role")"
  rm -f "$(resolution_path "$role")"
  jq -n \
    --arg role "$role" \
    --arg target "$target" \
    --arg source_arn "$source_arn" \
    --arg restore_cutoff "$(context_value '.restore_cutoff')" \
    --argjson restore_cutoff_epoch "$(context_value '.restore_cutoff_epoch')" \
    --argjson started_at "$(now_epoch)" '{
      schema_version: 1,
      role: $role,
      target: $target,
      source_arn: $source_arn,
      restore_cutoff: $restore_cutoff,
      restore_cutoff_epoch: $restore_cutoff_epoch,
      started_at: $started_at
    }' | atomic_write "$path"
}

persist_restore_receipt() {
  local role="$1" target="$2" description="$3" provenance="$4"
  local event_id="${5:-}" event_time="${6:-}" source_arn cutoff
  local restored_epoch
  local path
  path="$(receipt_path "$role")"
  source_arn=$(jq -er --arg role "$role" '.[$role].table_arn' "$SOURCES")
  cutoff="$(context_value '.restore_cutoff')"
  jq -e \
    --arg target "$target" \
    --arg target_arn \
      "arn:aws:dynamodb:$REGION:$(context_value '.account_id'):table/$target" '
      .TableName == $target and
      .TableArn == $target_arn and
      (.TableId | type == "string" and length > 0) and
      (.CreationDateTime | type == "string" and length > 0)
    ' "$description" >/dev/null ||
    fail "isolated table identity is malformed for role $role"
  if [[ "$provenance" != "cloudtrail" ]]; then
    jq -e --arg source_arn "$source_arn" \
      '.RestoreSummary.SourceTableArn == $source_arn' \
      "$description" >/dev/null ||
      fail "restore response source mismatch for role $role"
    restored_epoch=$(
      date -u -d "$(jq -er '.RestoreSummary.RestoreDateTime' "$description")" +%s
    )
    [[ "$restored_epoch" == "$(context_value '.restore_cutoff_epoch')" ]] ||
      fail "restore response cutoff mismatch for role $role"
  fi
  jq -n \
    --arg role "$role" \
    --arg target "$target" \
    --arg source_arn "$source_arn" \
    --arg target_arn "$(jq -er '.TableArn' "$description")" \
    --arg table_id "$(jq -er '.TableId' "$description")" \
    --arg creation_time "$(jq -er '.CreationDateTime' "$description")" \
    --arg restore_cutoff "$cutoff" \
    --arg provenance "$provenance" \
    --arg event_id "$event_id" \
    --arg event_time "$event_time" '
      {
        schema_version: 1,
        role: $role,
        target: $target,
        source_arn: $source_arn,
        target_arn: $target_arn,
        table_id: $table_id,
        creation_time: $creation_time,
        restore_cutoff: $restore_cutoff,
        provenance: $provenance
      }
      + if $event_id == "" then {}
        else {cloudtrail_event_id: $event_id, cloudtrail_event_time: $event_time}
        end
    ' | atomic_write "$path"
}

validate_restore_receipt() {
  local role="$1" target="$2" description="$3" path
  local expected_epoch receipt_epoch description_epoch
  path="$(receipt_path "$role")"
  [[ -s "$path" ]] || fail "missing restore receipt for role $role"
  jq -e \
    --arg role "$role" \
    --arg target "$target" \
    --arg source_arn "$(jq -er --arg role "$role" '.[$role].table_arn' "$SOURCES")" \
    --arg target_arn "$(jq -er '.TableArn' "$description")" \
    --arg table_id "$(jq -er '.TableId' "$description")" '
      .schema_version == 1 and
      .role == $role and
      .target == $target and
      .source_arn == $source_arn and
      .target_arn == $target_arn and
      .table_id == $table_id and
      (
        .provenance == "restore_api" or
        .provenance == "restore_summary" or
        .provenance == "cloudtrail"
      )
    ' "$path" >/dev/null ||
    fail "isolated table no longer matches its restore receipt for role $role"
  receipt_epoch=$(date -u -d "$(jq -er '.creation_time' "$path")" +%s)
  description_epoch=$(date -u -d "$(jq -er '.CreationDateTime' "$description")" +%s)
  ((receipt_epoch == description_epoch)) ||
    fail "isolated table was replaced after receipt creation for role $role"
  expected_epoch="$(context_value '.restore_cutoff_epoch')"
  [[ "$(date -u -d "$(jq -er '.restore_cutoff' "$path")" +%s)" == \
    "$expected_epoch" ]] ||
    fail "restore receipt cutoff differs for role $role"
}

lookup_restore_events() {
  local role="$1" target="$2" output="$3"
  local intent source_arn target_arn lookup_start lookup_end
  intent="$(intent_path "$role")"
  [[ -s "$intent" ]] || fail "missing restore intent for role $role"
  source_arn=$(jq -er '.source_arn' "$intent")
  target_arn="arn:aws:dynamodb:$REGION:$(context_value '.account_id'):table/$target"
  lookup_start=$(date -u -d "@$(( $(jq -er '.started_at' "$intent") - 60 ))" \
    +%Y-%m-%dT%H:%M:%SZ)
  lookup_end=$(date -u -d "@$(( $(now_epoch) + 60 ))" +%Y-%m-%dT%H:%M:%SZ)
  "${AWSQ[@]}" cloudtrail lookup-events \
    --lookup-attributes \
      AttributeKey=EventName,AttributeValue=RestoreTableToPointInTime \
    --start-time "$lookup_start" \
    --end-time "$lookup_end" \
    --output json >"$WORK/cloudtrail-$role.json"
  jq \
    --arg source_arn "$source_arn" \
    --arg target "$target" \
    --arg target_arn "$target_arn" \
    --arg region "$REGION" \
    --arg account "$(context_value '.account_id')" \
    --argjson cutoff_epoch "$(context_value '.restore_cutoff_epoch')" \
    --argjson started_at "$(jq -er '.started_at' "$intent")" '
      def event_epoch:
        if type == "number" then floor
        elif type == "string" and test("^[0-9]+([.][0-9]+)?$")
        then tonumber | floor
        elif type == "string" then try fromdateiso8601 catch null
        else null
        end;
      [
        .Events[]
        | try (.CloudTrailEvent | fromjson) catch empty
        | (.eventTime | event_epoch) as $event_epoch
        | select(
            .eventSource == "dynamodb.amazonaws.com" and
            .eventName == "RestoreTableToPointInTime" and
            .awsRegion == $region and
            .recipientAccountId == $account and
            (.errorCode // null) == null and
            (.errorMessage // null) == null and
            .requestParameters.sourceTableArn == $source_arn and
            .requestParameters.targetTableName == $target and
            (.requestParameters.restoreDateTime | event_epoch) == $cutoff_epoch and
            $event_epoch != null and
            $event_epoch >= $started_at and
            (
              [.resources[]?.ARN]
              | index($source_arn) != null and index($target_arn) != null
            )
          )
      ]
    ' "$WORK/cloudtrail-$role.json" >"$output"
  chmod 600 "$output"
}

recover_restore_receipt_from_cloudtrail() {
  local role="$1" target="$2" description="$3"
  local deadline candidates count event_epoch creation_epoch delta
  candidates="$WORK/cloudtrail-candidates-$role.json"
  deadline=$(( $(now_epoch) + CLOUDTRAIL_LOOKUP_SECS ))
  while true; do
    lookup_restore_events "$role" "$target" "$candidates"
    count=$(jq -er 'length' "$candidates")
    ((count <= 1)) ||
      fail "multiple CloudTrail restore events match role $role"
    ((count == 0)) || break
    (( $(now_epoch) < deadline )) ||
      fail "CloudTrail has no matching restore event for role $role"
    sleep "$POLL_SECS"
  done
  event_epoch=$(date -u -d "$(jq -er '.[0].eventTime' "$candidates")" +%s)
  creation_epoch=$(date -u -d "$(jq -er '.CreationDateTime' "$description")" +%s)
  delta=$((creation_epoch - event_epoch))
  ((delta >= 0)) || delta=$((-delta))
  ((delta <= 5)) ||
    fail "isolated table creation does not match its CloudTrail event for role $role"
  persist_restore_receipt \
    "$role" "$target" "$description" "cloudtrail" \
    "$(jq -er '.[0].eventID' "$candidates")" \
    "$(jq -er '.[0].eventTime' "$candidates")"
}

restore_intent_pending() {
  local role="$1" target="$2" intent candidates count started now resolution
  intent="$(intent_path "$role")"
  [[ -s "$intent" && ! -s "$(receipt_path "$role")" ]] || return 1
  resolution="$(resolution_path "$role")"
  if [[ -s "$resolution" ]]; then
    jq -e \
      --arg role "$role" \
      --arg target "$target" \
      --arg intent_sha256 "$(sha256sum "$intent" | cut -d' ' -f1)" '
        .schema_version == 1 and
        .role == $role and
        .target == $target and
        .intent_sha256 == $intent_sha256 and
        (.resolved_at | type == "number")
      ' "$resolution" >/dev/null ||
      fail "ambiguous restore resolution is malformed for role $role"
    return 1
  fi
  candidates="$WORK/cloudtrail-candidates-$role.json"
  lookup_restore_events "$role" "$target" "$candidates"
  count=$(jq -er 'length' "$candidates")
  ((count <= 1)) ||
    fail "multiple CloudTrail restore events match role $role"
  started=$(jq -er '.started_at' "$intent")
  now=$(now_epoch)
  if ((count == 1)); then
    ((now - started <= POLL_TIMEOUT_SECS)) ||
      fail "accepted restore did not become visible for role $role"
    return 0
  fi
  if ((now - started < CLOUDTRAIL_LOOKUP_SECS)); then
    return 0
  fi
  fail "ambiguous restore for role $role needs explicit ACTION=resolve-absent"
}

expected_target_name() {
  local role="$1" run_hash
  run_hash="$(sha256_text "$RUN_ID")"
  printf 'aa-gc-%s-%s\n' "${run_hash:0:16}" "${role//_/-}"
}

validate_context() {
  [[ -s "$CONTEXT" && -s "$TABLE_MAP" && -s "$SOURCES" ]] ||
    fail "incomplete persisted cutover context"
  jq -e \
    --arg run_id "$RUN_ID" \
    --arg stack "$STACK" \
    --arg region "$REGION" '
      .schema_version == 1 and
      .run_id == $run_id and
      .stack == $stack and
      .region == $region and
      (.stack_id | type == "string" and startswith("arn:aws:cloudformation:")) and
      (.account_id | test("^[0-9]{12}$")) and
      (.deployed_commit | test("^[0-9a-f]{40}$")) and
      (.harness_commit | test("^[0-9a-f]{40}$")) and
      (.created_at | type == "number") and
      (.restore_cutoff_epoch | type == "number") and
      (.pitr_lag_seconds | type == "number" and . >= 0)
    ' "$CONTEXT" >/dev/null ||
    fail "persisted cutover context is malformed"
  local account
  account=$("${AWSQ[@]}" sts get-caller-identity \
    --query Account --output text)
  [[ "$account" == "$(context_value '.account_id')" ]] ||
    fail "current AWS account differs from persisted context"
  jq -e '
    type == "object" and length == 12 and
    (keys | sort) == ([
      "admin_auth", "clients", "domain_map", "federation_config",
      "grants", "passkeys", "password_credentials", "scim_groups",
      "security_events", "tenant_keys", "users", "workload_trust"
    ] | sort) and
    all(.[]; type == "string" and test("^aa-gc-[0-9a-f]{16}-[a-z-]+$")) and
    ([.[]] | length == (unique | length))
  ' "$TABLE_MAP" >/dev/null ||
    fail "persisted restored-table map is malformed"
  jq -e '
    type == "object" and length == 12 and
    all(.[];
      (.table | type == "string" and length > 0) and
      (.table_arn | type == "string" and startswith("arn:aws:dynamodb:")) and
      (.table_id | type == "string" and length > 0) and
      (.creation_epoch | type == "number") and
      (.latest | type == "string" and length > 0) and
      (.latest_epoch | type == "number")
    )
  ' "$SOURCES" >/dev/null ||
    fail "persisted source-table identity is malformed"
  while IFS=$'\t' read -r role target; do
    [[ "$target" == "$(expected_target_name "$role")" ]] ||
      fail "persisted target name is not deterministic for role $role"
  done < <(jq -r 'to_entries[] | [.key, .value] | @tsv' "$TABLE_MAP")
}

validate_target_provenance() {
  local role="$1" target="$2"
  local description="$WORK/describe-$role.json"
  local table_description="$WORK/table-$role.json"
  local error="$WORK/describe-$role.err"
  local source_arn expected_arn restore_source restore_epoch creation_epoch
  local describe_status
  describe_table "$target" "$description" "$error" || {
    describe_status=$?
    return "$describe_status"
  }
  source_arn=$(jq -er --arg role "$role" '.[$role].table_arn' "$SOURCES")
  expected_arn="arn:aws:dynamodb:$REGION:$(context_value '.account_id'):table/$target"
  jq -e --arg arn "$expected_arn" '.Table.TableArn == $arn' \
    "$description" >/dev/null ||
    fail "isolated table ARN mismatch for role $role"
  jq -e '.Table | (.TableId | type == "string" and length > 0)' \
    "$description" >/dev/null ||
    fail "isolated table ID is missing for role $role"
  creation_epoch=$(date -u -d \
    "$(jq -er '.Table.CreationDateTime' "$description")" +%s)
  ((creation_epoch >= $(context_value '.created_at'))) ||
    fail "isolated table predates this run for role $role"
  jq '.Table' "$description" >"$table_description"
  if [[ ! -s "$(receipt_path "$role")" ]]; then
    [[ -s "$(intent_path "$role")" ]] ||
      fail "isolated table has no persisted restore intent for role $role"
    if jq -e '.RestoreSummary != null' "$table_description" >/dev/null; then
      restore_source=$(jq -er '.RestoreSummary.SourceTableArn' "$table_description")
      [[ "$restore_source" == "$source_arn" ]] ||
        fail "isolated table source mismatch for role $role"
      restore_epoch=$(date -u -d \
        "$(jq -er '.RestoreSummary.RestoreDateTime' "$table_description")" +%s)
      [[ "$restore_epoch" == "$(context_value '.restore_cutoff_epoch')" ]] ||
        fail "isolated table cutoff mismatch for role $role"
      persist_restore_receipt \
        "$role" "$target" "$table_description" "restore_summary"
    else
      recover_restore_receipt_from_cloudtrail \
        "$role" "$target" "$table_description"
    fi
  fi
  validate_restore_receipt "$role" "$target" "$table_description"
  return 0
}

wait_table_active() {
  local role="$1" target="$2" started status target_status
  started=$(now_epoch)
  while true; do
    if validate_target_provenance "$role" "$target"; then
      :
    else
      target_status=$?
      case "$target_status" in
        1) fail "isolated table disappeared while restoring role $role" ;;
        2)
          info "retrying ambiguous table status for role $role"
          (( $(now_epoch) - started <= POLL_TIMEOUT_SECS )) ||
            fail "isolated table status remained ambiguous for role $role"
          sleep "$POLL_SECS"
          continue
          ;;
        *) fail "unexpected table status result for role $role" ;;
      esac
    fi
    status=$(jq -er '.Table.TableStatus' "$WORK/describe-$role.json")
    case "$status" in
      ACTIVE) return 0 ;;
      CREATING | UPDATING | RESTORING) ;;
      *) fail "isolated table entered unexpected state $status for role $role" ;;
    esac
    (( $(now_epoch) - started <= POLL_TIMEOUT_SECS )) ||
      fail "isolated table timed out for role $role"
    sleep "$POLL_SECS"
  done
}

cleanup_restored_tables() {
  [[ -s "$CONTEXT" ]] || return 0
  validate_context
  validate_current_stack_context
  local role target status target_status
  local started absent_since=0 present now
  started=$(now_epoch)
  while true; do
    present=0
    while IFS=$'\t' read -r role target; do
      if validate_target_provenance "$role" "$target"; then
        present=1
        absent_since=0
        status=$(jq -er '.Table.TableStatus' "$WORK/describe-$role.json")
        case "$status" in
          ACTIVE)
            acquire_stack_freeze
            assert_safe_delete "$target"
            jq -n \
              --arg role "$role" \
              --arg target "$target" \
              --arg table_id "$(jq -er '.Table.TableId' "$WORK/describe-$role.json")" \
              --argjson started_at "$(now_epoch)" '{
                schema_version: 1,
                role: $role,
                target: $target,
                table_id: $table_id,
                started_at: $started_at
              }' | atomic_write "$STATE_DIR/delete-intent-$role.json"
            "${AWSQ[@]}" dynamodb delete-table \
              --table-name "$target" >/dev/null ||
              return 1
            ;;
          CREATING | UPDATING | RESTORING | DELETING) ;;
          *)
            printf 'FAIL: isolated table has unexpected cleanup state %s for role %s\n' \
              "$status" "$role" >&2
            return 1
            ;;
        esac
        continue
      else
        target_status=$?
      fi
      case "$target_status" in
        1)
          if [[ -s "$(receipt_path "$role")" &&
            ! -s "$STATE_DIR/delete-intent-$role.json" ]]; then
            if (( $(now_epoch) - \
              $(jq -er '.started_at' "$(intent_path "$role")") >
              POLL_TIMEOUT_SECS )); then
              printf 'FAIL: restored table never became visible for role %s\n' \
                "$role" >&2
              return 1
            fi
            present=1
            absent_since=0
          elif restore_intent_pending "$role" "$target"; then
            present=1
            absent_since=0
          fi
          ;;
        *)
          printf 'FAIL: could not prove isolated table state for role %s\n' \
            "$role" >&2
          return 1
          ;;
      esac
    done < <(jq -r 'to_entries[] | [.key, .value] | @tsv' "$TABLE_MAP")

    now=$(now_epoch)
    if ((present == 0)); then
      if ((absent_since == 0)); then
        absent_since=$now
      elif ((now - absent_since >= ABSENCE_STABLE_SECS)); then
        return 0
      fi
    fi
    ((now - started <= POLL_TIMEOUT_SECS)) || {
      printf 'FAIL: isolated table cleanup did not converge\n' >&2
      return 1
    }
    sleep "$POLL_SECS"
  done
}

cleanup_process() {
  local status=$?
  trap - EXIT INT TERM
  if ((status != 0)); then
    rm -f "$FINAL_EVIDENCE" "$FINAL_EVIDENCE.current"
  fi
  if ((RESTORED_TABLES_CLEANED == 0)) &&
    [[ -s "$CONTEXT" ]] &&
    ! (cleanup_restored_tables); then
    status=1
    rm -f "$FINAL_EVIDENCE" "$FINAL_EVIDENCE.current"
  fi
  if ! restore_stack_policy; then
    status=1
    rm -f "$FINAL_EVIDENCE" "$FINAL_EVIDENCE.current"
  fi
  if ((DEPLOYED_TREE_ADDED == 1)); then
    if ! git -C "$REPO_ROOT" worktree remove --force "$DEPLOYED_TREE"; then
      status=1
    fi
  fi
  if [[ -d "$WORK" ]]; then
    find "$WORK" -mindepth 1 -delete
    rmdir "$WORK" 2>/dev/null || status=1
  fi
  exit "$status"
}
trap cleanup_process EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ "$ACTION" == "resolve-absent" ]]; then
  validate_context
  validate_current_stack_context
  target=$(jq -er --arg role "$ROLE" '.[$role]' "$TABLE_MAP") ||
    fail "ROLE is not part of the persisted cutover"
  [[ -s "$(intent_path "$ROLE")" ]] ||
    fail "ROLE has no unresolved restore intent"
  [[ ! -s "$(receipt_path "$ROLE")" ]] ||
    fail "ROLE already has a positive restore receipt"
  if validate_target_provenance "$ROLE" "$target"; then
    fail "ROLE has a visible restored table and cannot be resolved absent"
  else
    target_status=$?
  fi
  [[ "$target_status" == "1" ]] ||
    fail "could not prove the ambiguous target is currently absent"
  started_at=$(jq -er '.started_at' "$(intent_path "$ROLE")")
  (( $(now_epoch) - started_at >= CLOUDTRAIL_LOOKUP_SECS )) ||
    fail "CloudTrail review window has not elapsed for ROLE"
  candidates="$WORK/cloudtrail-candidates-$ROLE.json"
  lookup_restore_events "$ROLE" "$target" "$candidates"
  [[ "$(jq -er 'length' "$candidates")" == "0" ]] ||
    fail "CloudTrail contains a matching accepted restore for ROLE"
  jq -n \
    --arg role "$ROLE" \
    --arg target "$target" \
    --arg intent_sha256 "$(
      sha256sum "$(intent_path "$ROLE")" | cut -d' ' -f1
    )" \
    --arg account_sha256 "$(sha256_text "$(context_value '.account_id')")" \
    --argjson resolved_at "$(now_epoch)" '{
      schema_version: 1,
      role: $role,
      target: $target,
      intent_sha256: $intent_sha256,
      account_sha256: $account_sha256,
      resolved_at: $resolved_at,
      resolution: "operator-confirmed-not-accepted"
    }' | atomic_write "$(resolution_path "$ROLE")"
  RESTORED_TABLES_CLEANED=1
  pass "recorded explicit ambiguous-restore absence for ROLE=$ROLE"
  exit 0
fi

if [[ "$ACTION" == "cleanup" ]]; then
  validate_context
  cleanup_restored_tables ||
    fail "one or more isolated tables could not be cleaned"
  RESTORED_TABLES_CLEANED=1
  restore_stack_policy ||
    fail "could not restore the pre-run CloudFormation stack policy"
  pass "isolated restored tables are absent for RUN_ID=$RUN_ID"
  exit 0
fi

[[ ! -e "$FINAL_EVIDENCE" ]] ||
  fail "RUN_ID already has final evidence; use a new RUN_ID"

HARNESS_COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD)"
[[ "$HARNESS_COMMIT" =~ ^[0-9a-f]{40}$ ]] ||
  fail "local harness commit is not exact"
[[ -z "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=normal)" ]] ||
  fail "qualifying gate requires a clean exact-commit checkout"

"${AWSQ[@]}" sts get-caller-identity --output json >"$WORK/caller.json"
ACCOUNT="$(jq -er '.Account | select(test("^[0-9]{12}$"))' "$WORK/caller.json")"
"${AWSQ[@]}" cloudformation describe-stacks \
  --stack-name "$STACK" --output json >"$WORK/stack.json"
jq -e '.Stacks[0].StackStatus == "CREATE_COMPLETE" or
  .Stacks[0].StackStatus == "UPDATE_COMPLETE"' "$WORK/stack.json" >/dev/null ||
  fail "$STACK is not stable"
STACK_ID="$(jq -er '.Stacks[0].StackId' "$WORK/stack.json")"
DEPLOYED_COMMIT="$(
  jq -er '
    .Stacks[0].Outputs
    | map(select(.OutputKey == "DeploymentCommit"))
    | if length == 1 then .[0].OutputValue else error("DeploymentCommit") end
  ' "$WORK/stack.json"
)"
[[ "$DEPLOYED_COMMIT" =~ ^[0-9a-f]{40}$ ]] ||
  fail "deployed stack does not expose an exact commit"
git -C "$REPO_ROOT" merge-base --is-ancestor \
  "$DEPLOYED_COMMIT" "$HARNESS_COMMIT" ||
  fail "harness commit is not a descendant of the deployed commit"
git -C "$REPO_ROOT" diff --quiet \
  "$DEPLOYED_COMMIT..$HARNESS_COMMIT" -- \
  e2e/governance_restore_cutover_verify.sh \
  scripts/governance_restore_cutover_verify.py ||
  fail "deployed verifier differs from the reviewed harness verifier"

ROLE_MAP="$(
  jq -er '
    .Stacks[0].Outputs
    | map(select(.OutputKey == "ReplicatedAuthorityTableNames"))
    | if length == 1 then .[0].OutputValue | fromjson
      else error("ReplicatedAuthorityTableNames")
      end
    | with_entries(select(.key | IN(
        "admin_auth", "clients", "domain_map", "federation_config",
        "grants", "passkeys", "password_credentials", "scim_groups",
        "security_events", "tenant_keys", "users", "workload_trust"
      )))
  ' "$WORK/stack.json"
)"
jq -e 'length == 12 and ([.[]] | length == (unique | length))' \
  <<<"$ROLE_MAP" >/dev/null ||
  fail "deployed recovery role map is incomplete or duplicated"

if [[ ! -s "$CONTEXT" ]]; then
  printf '{}\n' >"$WORK/sources.json"
  while IFS=$'\t' read -r role table; do
    "${AWSQ[@]}" dynamodb describe-table \
      --table-name "$table" --output json >"$WORK/source-$role.json"
    "${AWSQ[@]}" dynamodb describe-continuous-backups \
      --table-name "$table" --output json >"$WORK/pitr-$role.json"
    jq -e '
      .ContinuousBackupsDescription.PointInTimeRecoveryDescription
      .PointInTimeRecoveryStatus == "ENABLED"
    ' "$WORK/pitr-$role.json" >/dev/null ||
      fail "PITR is not enabled for role $role"
    source_arn=$(jq -er '.Table.TableArn' "$WORK/source-$role.json")
    table_id=$(jq -er '.Table.TableId' "$WORK/source-$role.json")
    creation_epoch=$(
      date -u -d \
        "$(jq -er '.Table.CreationDateTime' "$WORK/source-$role.json")" +%s
    )
    latest=$(
      jq -er '
        .ContinuousBackupsDescription.PointInTimeRecoveryDescription
        .LatestRestorableDateTime
      ' "$WORK/pitr-$role.json"
    )
    latest_epoch=$(date -u -d "$latest" +%s)
    jq \
      --arg role "$role" \
      --arg table "$table" \
      --arg table_arn "$source_arn" \
      --arg table_id "$table_id" \
      --arg latest "$latest" \
      --argjson creation_epoch "$creation_epoch" \
      --argjson latest_epoch "$latest_epoch" '
        . + {($role): {
          table: $table,
          table_arn: $table_arn,
          table_id: $table_id,
          creation_epoch: $creation_epoch,
          latest: $latest,
          latest_epoch: $latest_epoch
        }}
      ' "$WORK/sources.json" >"$WORK/sources.next.json"
    mv "$WORK/sources.next.json" "$WORK/sources.json"
  done < <(jq -r 'to_entries[] | [.key, .value] | @tsv' <<<"$ROLE_MAP")

  RESTORE_CUTOFF_EPOCH="$(jq -er '[.[].latest_epoch] | min' "$WORK/sources.json")"
  RPO_LAG=$(( $(now_epoch) - RESTORE_CUTOFF_EPOCH ))
  ((RPO_LAG >= 0 && RPO_LAG <= RPO_TARGET_SECS)) ||
    fail "common PITR cutoff lag ${RPO_LAG}s exceeds ${RPO_TARGET_SECS}s"
  RESTORE_CUTOFF="$(date -u -d "@$RESTORE_CUTOFF_EPOCH" +%Y-%m-%dT%H:%M:%SZ)"

  printf '{}\n' >"$WORK/table-map.json"
  while IFS= read -r role; do
    target="$(expected_target_name "$role")"
    jq --arg role "$role" --arg target "$target" \
      '. + {($role): $target}' "$WORK/table-map.json" \
      >"$WORK/table-map.next.json"
    mv "$WORK/table-map.next.json" "$WORK/table-map.json"
  done < <(jq -r 'keys[]' "$WORK/sources.json")

  cp "$WORK/sources.json" "$SOURCES"
  cp "$WORK/table-map.json" "$TABLE_MAP"
  chmod 600 "$SOURCES" "$TABLE_MAP"
  jq -n \
    --arg run_id "$RUN_ID" \
    --arg stack "$STACK" \
    --arg stack_id "$STACK_ID" \
    --arg region "$REGION" \
    --arg account_id "$ACCOUNT" \
    --arg deployed_commit "$DEPLOYED_COMMIT" \
    --arg harness_commit "$HARNESS_COMMIT" \
    --arg verifier_shell_sha256 \
      "$(git -C "$REPO_ROOT" show \
        "$DEPLOYED_COMMIT:e2e/governance_restore_cutover_verify.sh" |
        sha256sum | cut -d' ' -f1)" \
    --arg verifier_core_sha256 \
      "$(git -C "$REPO_ROOT" show \
        "$DEPLOYED_COMMIT:scripts/governance_restore_cutover_verify.py" |
        sha256sum | cut -d' ' -f1)" \
    --arg restore_cutoff "$RESTORE_CUTOFF" \
    --argjson restore_cutoff_epoch "$RESTORE_CUTOFF_EPOCH" \
    --argjson pitr_lag_seconds "$RPO_LAG" \
    --argjson created_at "$(now_epoch)" '{
      schema_version: 1,
      run_id: $run_id,
      stack: $stack,
      stack_id: $stack_id,
      region: $region,
      account_id: $account_id,
      deployed_commit: $deployed_commit,
      harness_commit: $harness_commit,
      verifier_shell_sha256: $verifier_shell_sha256,
      verifier_core_sha256: $verifier_core_sha256,
      restore_cutoff: $restore_cutoff,
      restore_cutoff_epoch: $restore_cutoff_epoch,
      pitr_lag_seconds: $pitr_lag_seconds,
      created_at: $created_at
    }' | atomic_write "$CONTEXT"
else
  validate_context
  [[ "$(context_value '.deployed_commit')" == "$DEPLOYED_COMMIT" ]] ||
    fail "deployed commit changed during the persisted run"
  [[ "$(context_value '.harness_commit')" == "$HARNESS_COMMIT" ]] ||
    fail "harness commit changed during the persisted run"
fi

validate_context
validate_current_stack_context
info "run_id=$RUN_ID"
info "deployed_commit=$DEPLOYED_COMMIT"
info "harness_commit=$HARNESS_COMMIT"
info "restore_cutoff=$(context_value '.restore_cutoff')"

while IFS=$'\t' read -r role target; do
  resume_existing=0
  if validate_target_provenance "$role" "$target"; then
    info "resuming isolated restore for role $role"
    continue
  else
    target_status=$?
  fi
  case "$target_status" in
    1) ;;
    *) fail "could not inspect isolated target for role $role" ;;
  esac
  if [[ -s "$(intent_path "$role")" &&
    ! -s "$(receipt_path "$role")" ]]; then
    while restore_intent_pending "$role" "$target"; do
      sleep "$POLL_SECS"
      if validate_target_provenance "$role" "$target"; then
        resume_existing=1
        break
      else
        target_status=$?
      fi
      [[ "$target_status" == "1" ]] ||
        fail "could not inspect pending restore for role $role"
    done
    if ((resume_existing == 1)); then
      info "recovered accepted restore for role $role"
      continue
    fi
  fi
  source_arn=$(jq -er --arg role "$role" '.[$role].table_arn' "$SOURCES")
  write_restore_intent "$role" "$target" "$source_arn"
  if "${AWSQ[@]}" dynamodb restore-table-to-point-in-time \
    --source-table-arn "$source_arn" \
    --target-table-name "$target" \
    --restore-date-time "$(context_value '.restore_cutoff')" \
    --output json >"$STATE_DIR/restore-$role.current.json"; then
    chmod 600 "$STATE_DIR/restore-$role.current.json"
    jq -e '.TableDescription | type == "object"' \
      "$STATE_DIR/restore-$role.current.json" >/dev/null ||
      fail "restore response is malformed for role $role"
    jq '.TableDescription' "$STATE_DIR/restore-$role.current.json" \
      >"$WORK/restore-response-$role.json"
    persist_restore_receipt \
      "$role" "$target" "$WORK/restore-response-$role.json" "restore_api"
    mv "$STATE_DIR/restore-$role.current.json" \
      "$STATE_DIR/restore-$role.json"
  else
    fail "restore request returned an ambiguous error for role $role"
  fi
  info "started isolated restore for role $role"
done < <(jq -r 'to_entries[] | [.key, .value] | @tsv' "$TABLE_MAP")

while IFS=$'\t' read -r role target; do
  wait_table_active "$role" "$target"
done < <(jq -r 'to_entries[] | [.key, .value] | @tsv' "$TABLE_MAP")
pass "all 12 isolated restore targets are ACTIVE with verified provenance"

acquire_stack_freeze
pass "CloudFormation deployment freeze is active"

git -C "$REPO_ROOT" worktree add --detach \
  "$DEPLOYED_TREE" "$DEPLOYED_COMMIT" >/dev/null
DEPLOYED_TREE_ADDED=1
[[ -z "$(git -C "$DEPLOYED_TREE" status --porcelain --untracked-files=normal)" ]] ||
  fail "deployed verifier worktree is not clean"
cmp -s \
  "$REPO_ROOT/e2e/governance_restore_cutover_verify.sh" \
  "$DEPLOYED_TREE/e2e/governance_restore_cutover_verify.sh" ||
  fail "verifier shell differs from deployed commit"
cmp -s \
  "$REPO_ROOT/scripts/governance_restore_cutover_verify.py" \
  "$DEPLOYED_TREE/scripts/governance_restore_cutover_verify.py" ||
  fail "verifier core differs from deployed commit"

STACK="$STACK" AWS_PROFILE="$PROFILE" REGION="$REGION" \
  RESTORED_AUTHORITY_TABLES_FILE="$TABLE_MAP" \
  EVIDENCE_FILE="$INNER_EVIDENCE.current" \
  "$DEPLOYED_TREE/e2e/governance_restore_cutover_verify.sh"
chmod 600 "$INNER_EVIDENCE.current"
jq -e '.result == "passed"' "$INNER_EVIDENCE.current" >/dev/null ||
  fail "governance verifier did not publish a passing result"
mv "$INNER_EVIDENCE.current" "$INNER_EVIDENCE"

cleanup_restored_tables ||
  fail "one or more isolated tables could not be cleaned"
RESTORED_TABLES_CLEANED=1
restore_stack_policy ||
  fail "could not restore the pre-run CloudFormation stack policy"
pass "all 12 isolated restore targets are absent"

ACCOUNT_SHA256="$(sha256_text "$ACCOUNT")"
STACK_ID_SHA256="$(sha256_text "$(context_value '.stack_id')")"
SOURCE_MAP_SHA256="$(jq -Sc . "$SOURCES" | sha256sum | cut -d' ' -f1)"
TABLE_MAP_SHA256="$(jq -Sc . "$TABLE_MAP" | sha256sum | cut -d' ' -f1)"
RESTORE_RECEIPTS_SHA256="$(
  while IFS= read -r role; do
    jq -Sc . "$(receipt_path "$role")"
  done < <(jq -r 'keys[]' "$TABLE_MAP") |
    sha256sum | cut -d' ' -f1
)"
STACK_POLICY_STATE_SHA256="$(
  jq -Sc . "$STACK_POLICY_STATE" | sha256sum | cut -d' ' -f1
)"
INNER_EVIDENCE_SHA256="$(sha256sum "$INNER_EVIDENCE" | cut -d' ' -f1)"
COMPLETED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
jq -n \
  --arg run_id_sha256 "$(sha256_text "$RUN_ID")" \
  --arg deployed_commit "$DEPLOYED_COMMIT" \
  --arg harness_commit "$HARNESS_COMMIT" \
  --arg account_sha256 "$ACCOUNT_SHA256" \
  --arg stack_id_sha256 "$STACK_ID_SHA256" \
  --arg region "$REGION" \
  --arg restore_cutoff "$(context_value '.restore_cutoff')" \
  --arg source_map_sha256 "$SOURCE_MAP_SHA256" \
  --arg table_map_sha256 "$TABLE_MAP_SHA256" \
  --arg restore_receipts_sha256 "$RESTORE_RECEIPTS_SHA256" \
  --arg stack_policy_state_sha256 "$STACK_POLICY_STATE_SHA256" \
  --arg verifier_shell_sha256 "$(context_value '.verifier_shell_sha256')" \
  --arg verifier_core_sha256 "$(context_value '.verifier_core_sha256')" \
  --arg verifier_evidence_sha256 "$INNER_EVIDENCE_SHA256" \
  --arg completed_at "$COMPLETED_AT" \
  --argjson pitr_lag_seconds "$(context_value '.pitr_lag_seconds')" '{
    schema_version: "1.0",
    result: "passed",
    run_id_sha256: $run_id_sha256,
    deployed_commit: $deployed_commit,
    harness_commit: $harness_commit,
    account_sha256: $account_sha256,
    stack_id_sha256: $stack_id_sha256,
    region: $region,
    restore_cutoff: $restore_cutoff,
    pitr_lag_seconds: $pitr_lag_seconds,
    restored_table_count: 12,
    source_map_sha256: $source_map_sha256,
    table_map_sha256: $table_map_sha256,
    restore_receipt_count: 12,
    restore_receipts_sha256: $restore_receipts_sha256,
    deployment_freeze_restored: true,
    stack_policy_state_sha256: $stack_policy_state_sha256,
    verifier_shell_sha256: $verifier_shell_sha256,
    verifier_core_sha256: $verifier_core_sha256,
    verifier_evidence_sha256: $verifier_evidence_sha256,
    isolated_tables_cleaned: true,
    completed_at: $completed_at
  }' >"$FINAL_EVIDENCE.current"
chmod 600 "$FINAL_EVIDENCE.current"
mv "$FINAL_EVIDENCE.current" "$FINAL_EVIDENCE"
pass "governance restore-cutover gate completed: $FINAL_EVIDENCE"
