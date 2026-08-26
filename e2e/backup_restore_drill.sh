#!/usr/bin/env bash
# Production single-region backup/restore drill (spec 030 / issue #28).
#
# The drill:
#   1. validates the deployed AWS Backup plan and exact durable-table selection;
#   2. completes one on-demand AWS Backup job for the Users table;
#   3. restores every durable table to an isolated name from DynamoDB PITR;
#   4. verifies issuers, tenant partitions, active/revoked Grant authority,
#      tenant signing-key references, secret availability, and audit continuity;
#   5. records only counts, timings, and hashes in evidence, then deletes the
#      isolated restored tables.
#
# It never reads a Secrets Manager value and never cuts production traffic over.
# Resume an interrupted run by passing the printed RUN_ID again.
# Delete isolated restored tables without resuming the drill with:
#   ACTION=cleanup RUN_ID=<printed-run-id> AWS_PROFILE=default ./e2e/backup_restore_drill.sh
#
# Usage:
#   STACK=AgentAuthSaas \
#   ISSUER_T1=https://t1.example.com ISSUER_T2=https://t2.example.com \
#   AWS_PROFILE=default REGION=us-east-1 ./e2e/backup_restore_drill.sh
set -euo pipefail

ACTION="${ACTION:-run}"
STACK="${STACK:-AgentAuthSaas}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
JQ_LIB_DIR="$SCRIPT_DIR"
RUN_ID_INPUT="${RUN_ID:-}"
if [[ "$ACTION" == "cleanup" && -z "$RUN_ID_INPUT" ]]; then
  printf 'FAIL: ACTION=cleanup requires the original RUN_ID\n' >&2
  exit 1
fi
RUN_ID="${RUN_ID_INPUT:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
if [[ ! "$RUN_ID" =~ ^[A-Za-z0-9._-]{1,64}$ ]] ||
    [[ "$RUN_ID" == "." || "$RUN_ID" == ".." ]]; then
  printf 'FAIL: RUN_ID must contain only A-Z, a-z, 0-9, dot, underscore, or hyphen\n' >&2
  exit 1
fi
STATE_ROOT="${STATE_ROOT:-$HOME/.agent-auth-drills}"
STATE_DIR="$STATE_ROOT/$RUN_ID"
EVIDENCE_FILE="$STATE_DIR/evidence.json"
RPO_TARGET_SECS=600
RTO_TARGET_SECS=14400
POLL_SECS="${POLL_SECS:-20}"
CLOUDTRAIL_LOOKUP_SECS="${CLOUDTRAIL_LOOKUP_SECS:-900}"
AWSQ=(aws --profile "$PROFILE" --region "$REGION")

command -v flock >/dev/null || {
  printf 'FAIL: missing command: flock\n' >&2
  exit 1
}
mkdir -p "$STATE_ROOT"
chmod 700 "$STATE_ROOT"
LOCK_FILE="$STATE_ROOT/.$RUN_ID.lock"
exec 9>"$LOCK_FILE"
chmod 600 "$LOCK_FILE"
if ! flock -n 9; then
  printf 'FAIL: another drill process is active for RUN_ID=%s\n' "$RUN_ID" >&2
  exit 1
fi

case "$ACTION" in
  run|cleanup) ;;
  *)
    printf 'FAIL: ACTION must be run or cleanup\n' >&2
    exit 1
    ;;
esac
if [[ "$ACTION" == "cleanup" && ! -d "$STATE_DIR" ]]; then
  printf 'FAIL: drill state directory does not exist: %s\n' "$STATE_DIR" >&2
  exit 1
fi
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"
touch "$STATE_DIR/drill.log"
chmod 600 "$STATE_DIR/drill.log"
exec > >(tee -a "$STATE_DIR/drill.log") 2>&1

pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
info() { printf 'INFO: %s\n' "$*"; }

for command in aws date jq sha256sum; do
  command -v "$command" >/dev/null || fail "missing command: $command"
done
[[ "$REGION" == "us-east-1" ]] ||
  fail "production drill requires REGION=us-east-1 (got $REGION)"
[[ "$POLL_SECS" =~ ^[1-9][0-9]*$ ]] ||
  fail "POLL_SECS must be a positive integer"
[[ "$CLOUDTRAIL_LOOKUP_SECS" =~ ^[1-9][0-9]*$ ]] ||
  fail "CLOUDTRAIL_LOOKUP_SECS must be a positive integer"
if [[ "$ACTION" == "run" && -e "$EVIDENCE_FILE" ]]; then
  fail "RUN_ID=$RUN_ID already has evidence; use a new RUN_ID for a new drill"
fi

sha256_text() {
  printf '%s' "$1" | sha256sum | cut -d' ' -f1
}

verify_secret_dependency() {
  local secret_id="$1" label="$2" metadata key_id key_metadata
  metadata=$("${AWSQ[@]}" secretsmanager describe-secret \
    --secret-id "$secret_id" --output json)
  jq -e '
    (.DeletedDate == null) and
    (
      [
        (.VersionIdsToStages // {})
        | to_entries[]
        | select(.value | index("AWSCURRENT"))
      ]
      | length == 1
    )
  ' <<<"$metadata" >/dev/null ||
    fail "$label is pending deletion or lacks exactly one AWSCURRENT version"
  key_id=$(jq -r '.KmsKeyId // "alias/aws/secretsmanager"' <<<"$metadata")
  key_metadata=$("${AWSQ[@]}" kms describe-key --key-id "$key_id" --output json)
  [[ "$(jq -er '.KeyMetadata.KeyState' <<<"$key_metadata")" == "Enabled" ]] ||
    fail "$label encryption key $key_id is not Enabled"
}

verify_runtime_identity_policy_access() {
  local secret_id="$1" metadata secret_arn key_id key_metadata key_arn key_manager
  local decision
  metadata=$("${AWSQ[@]}" secretsmanager describe-secret \
    --secret-id "$secret_id" --output json)
  secret_arn=$(jq -er '.ARN' <<<"$metadata")
  decision=$("${AWSQ[@]}" iam simulate-principal-policy \
    --policy-source-arn "$AUTH_ROLE_ARN" \
    --action-names secretsmanager:GetSecretValue \
    --resource-arns "$secret_arn" \
    --query 'EvaluationResults[0].EvalDecision' --output text)
  [[ "$decision" == "allowed" ]] ||
    fail "Auth runtime identity policy does not allow secretsmanager:GetSecretValue for $secret_arn"

  key_id=$(jq -r '.KmsKeyId // "alias/aws/secretsmanager"' <<<"$metadata")
  key_metadata=$("${AWSQ[@]}" kms describe-key --key-id "$key_id" --output json)
  key_arn=$(jq -er '.KeyMetadata.Arn' <<<"$key_metadata")
  key_manager=$(jq -er '.KeyMetadata.KeyManager' <<<"$key_metadata")
  if [[ "$key_manager" == "CUSTOMER" ]]; then
    decision=$("${AWSQ[@]}" iam simulate-principal-policy \
      --policy-source-arn "$AUTH_ROLE_ARN" \
      --action-names kms:Decrypt \
      --resource-arns "$key_arn" \
      --query 'EvaluationResults[0].EvalDecision' --output text)
    [[ "$decision" == "allowed" ]] ||
      fail "Auth runtime identity policy does not allow kms:Decrypt for secret key $key_arn"
  fi
}

target_table_name() {
  local source="$1"
  printf 'aa-dr-%s-%s\n' "$RUN_ID" "$(sha256_text "$source")"
}

write_expected_table_map() {
  local output="$1" source
  : >"$output"
  while IFS= read -r source; do
    printf '%s\t%s\n' "$source" "$(target_table_name "$source")" >>"$output"
  done < <(jq -er '.durable_tables[]' "$STATE_DIR/run-context.json")
  chmod 600 "$output"
}

validate_table_action_state() {
  local required expected_account actual_account stack_id expected_stack_prefix
  local expected_sources actual_sources expected_map source latest lag source_arn extra
  for required in run-context.json pitr.tsv restore-cutoff-epoch table-map.tsv; do
    [[ -s "$STATE_DIR/$required" ]] ||
      fail "cannot act on restored tables without complete state: $required"
  done

  jq -e '
    (.account_id | type == "string" and test("^[0-9]{12}$")) and
    (.stack_id | type == "string" and length > 0) and
    (
      .durable_tables
      | type == "array" and
        length == 12 and
        length == (unique | length) and
        all(.[]; type == "string" and test("^[A-Za-z0-9_.-]{3,255}$"))
    )
  ' "$STATE_DIR/run-context.json" >/dev/null ||
    fail "persisted run context is malformed"
  expected_account=$(jq -er '.account_id' "$STATE_DIR/run-context.json")
  stack_id=$(jq -er '.stack_id' "$STATE_DIR/run-context.json")
  expected_stack_prefix="arn:aws:cloudformation:$REGION:$expected_account:stack/$STACK/"
  [[ "$stack_id" == "$expected_stack_prefix"* ]] ||
    fail "persisted stack identity is outside $STACK in $REGION"

  "${AWSQ[@]}" sts get-caller-identity --output json \
    >"$STATE_DIR/table-action-caller.json"
  chmod 600 "$STATE_DIR/table-action-caller.json"
  actual_account=$(jq -er '.Account' "$STATE_DIR/table-action-caller.json")
  [[ "$actual_account" == "$expected_account" ]] ||
    fail "current AWS account does not own RUN_ID=$RUN_ID"

  expected_sources="$STATE_DIR/table-sources.expected"
  actual_sources="$STATE_DIR/table-sources.actual"
  jq -er '.durable_tables[]' "$STATE_DIR/run-context.json" |
    LC_ALL=C sort >"$expected_sources"
  cut -f1 "$STATE_DIR/pitr.tsv" | LC_ALL=C sort >"$actual_sources"
  if ! cmp -s "$expected_sources" "$actual_sources"; then
    fail "persisted PITR sources differ from the deployment context"
  fi

  while IFS=$'\t' read -r source latest lag source_arn extra; do
    [[ -n "$source" && -n "$latest" && "$lag" =~ ^[0-9]+$ &&
      -n "$source_arn" && -z "$extra" ]] ||
      fail "persisted PITR source metadata is malformed"
    [[ "$source_arn" == \
      "arn:aws:dynamodb:$REGION:$expected_account:table/$source" ]] ||
      fail "persisted source ARN is outside the drill account: $source"
  done <"$STATE_DIR/pitr.tsv"

  expected_map="$STATE_DIR/table-map.expected.tsv"
  write_expected_table_map "$expected_map"
  if ! cmp -s "$expected_map" "$STATE_DIR/table-map.tsv"; then
    fail "persisted table map is not the deterministic RUN_ID/source mapping"
  fi
  rm -f "$expected_sources" "$actual_sources" "$expected_map"
}

DESCRIBED_TABLE_STATUS=""
describe_table_status() {
  local table="$1" error
  if DESCRIBED_TABLE_STATUS=$("${AWSQ[@]}" dynamodb describe-table \
      --table-name "$table" --query 'Table.TableStatus' --output text \
      2>"$STATE_DIR/describe-table-error"); then
    return 0
  fi
  error=$(<"$STATE_DIR/describe-table-error")
  if [[ "$error" == *ResourceNotFoundException* ]]; then
    return 1
  fi
  fail "unable to determine whether isolated table $table exists: $error"
}

restore_receipt_path() {
  local source="$1"
  printf '%s/restore-receipt-%s.json\n' \
    "$STATE_DIR" "$(sha256_text "$source")"
}

write_restore_receipt() {
  local source="$1" target="$2" table_description="$3"
  local provenance_source="$4" restore_date_time="$5"
  local event_id="${6:-}" event_time="${7:-}"
  local source_arn expected_account receipt current
  source_arn=$(awk -F $'\t' -v table="$source" \
    '$1 == table { print $4 }' "$STATE_DIR/pitr.tsv")
  [[ -n "$source_arn" ]] ||
    fail "no persisted source ARN exists for $source"
  expected_account=$(jq -er '.account_id' "$STATE_DIR/run-context.json")
  receipt=$(restore_receipt_path "$source")
  current="$receipt.current"
  jq -n \
    --arg provenance_source "$provenance_source" \
    --arg source_table_arn "$source_arn" \
    --arg target_table_name "$target" \
    --arg target_table_arn "$(jq -er '.TableArn' <<<"$table_description")" \
    --arg target_table_id "$(jq -er '.TableId' <<<"$table_description")" \
    --arg target_created_at \
      "$(jq -er '.CreationDateTime' <<<"$table_description")" \
    --arg restore_date_time "$restore_date_time" \
    --arg region "$REGION" \
    --arg account_id "$expected_account" \
    --arg event_id "$event_id" \
    --arg event_time "$event_time" '
      {
        schema_version: 1,
        provenance_source: $provenance_source,
        source_table_arn: $source_table_arn,
        target_table_name: $target_table_name,
        target_table_arn: $target_table_arn,
        target_table_id: $target_table_id,
        target_created_at: $target_created_at,
        restore_date_time: $restore_date_time,
        region: $region,
        account_id: $account_id
      }
      + if $event_id == "" then {}
        else {
          cloudtrail_event_id: $event_id,
          cloudtrail_event_time: $event_time
        }
        end
    ' >"$current"
  chmod 600 "$current"
  mv "$current" "$receipt"
}

validate_restore_receipt() {
  local source="$1" target="$2" table_description="$3" receipt="$4"
  local source_arn expected_account expected_epoch restored_at restored_epoch
  local created_at created_epoch receipt_created_at receipt_created_epoch
  source_arn=$(awk -F $'\t' -v table="$source" \
    '$1 == table { print $4 }' "$STATE_DIR/pitr.tsv")
  [[ -n "$source_arn" ]] ||
    fail "no persisted source ARN exists for $source"
  expected_account=$(jq -er '.account_id' "$STATE_DIR/run-context.json")
  expected_epoch=$(<"$STATE_DIR/restore-cutoff-epoch")
  [[ "$expected_epoch" =~ ^[0-9]+$ ]] ||
    fail "persisted restore cutoff is malformed"

  jq -e \
    --arg source_arn "$source_arn" \
    --arg target "$target" \
    --arg target_arn \
      "arn:aws:dynamodb:$REGION:$expected_account:table/$target" \
    --arg region "$REGION" \
    --arg account "$expected_account" \
    --arg table_id "$(jq -er '.TableId' <<<"$table_description")" \
    --arg table_arn "$(jq -er '.TableArn' <<<"$table_description")" '
      .schema_version == 1 and
      (
        .provenance_source == "restore_api" or
        .provenance_source == "restore_summary" or
        .provenance_source == "cloudtrail"
      ) and
      .source_table_arn == $source_arn and
      .target_table_name == $target and
      .target_table_arn == $target_arn and
      .target_table_id == $table_id and
      .target_table_arn == $table_arn and
      .region == $region and
      .account_id == $account
    ' "$receipt" >/dev/null ||
    fail "isolated table $target does not match the persisted restore source"

  restored_at=$(jq -er '.restore_date_time' "$receipt")
  restored_epoch=$(date -d "$restored_at" +%s 2>/dev/null) ||
    fail "restore receipt has a malformed PITR cutoff"
  (( restored_epoch == expected_epoch )) ||
    fail "isolated table $target used a different PITR cutoff"

  created_at=$(jq -er '.CreationDateTime' <<<"$table_description")
  receipt_created_at=$(jq -er '.target_created_at' "$receipt")
  created_epoch=$(date -d "$created_at" +%s 2>/dev/null) ||
    fail "isolated table $target has a malformed creation time"
  receipt_created_epoch=$(date -d "$receipt_created_at" +%s 2>/dev/null) ||
    fail "restore receipt has a malformed creation time"
  (( created_epoch == receipt_created_epoch )) ||
    fail "isolated table $target was replaced after its restore receipt"
}

persist_restore_summary_receipt() {
  local source="$1" target="$2" table_description="$3" provenance_source="$4"
  local source_arn expected_account expected_epoch restored_at restored_epoch
  source_arn=$(awk -F $'\t' -v table="$source" \
    '$1 == table { print $4 }' "$STATE_DIR/pitr.tsv")
  [[ -n "$source_arn" ]] ||
    fail "no persisted source ARN exists for $source"
  expected_account=$(jq -er '.account_id' "$STATE_DIR/run-context.json")
  expected_epoch=$(<"$STATE_DIR/restore-cutoff-epoch")
  [[ "$expected_epoch" =~ ^[0-9]+$ ]] ||
    fail "persisted restore cutoff is malformed"

  jq -e \
    --arg source_arn "$source_arn" \
    --arg target "$target" \
    --arg target_arn \
      "arn:aws:dynamodb:$REGION:$expected_account:table/$target" '
      .TableName == $target and
      .TableArn == $target_arn and
      (.TableId | type == "string" and length > 0) and
      (.CreationDateTime | type == "string" and length > 0) and
      .RestoreSummary.SourceTableArn == $source_arn and
      (.RestoreSummary.RestoreInProgress | type == "boolean")
    ' <<<"$table_description" >/dev/null ||
    fail "isolated table $target does not match the persisted restore source"
  restored_at=$(jq -er '.RestoreSummary.RestoreDateTime' \
    <<<"$table_description")
  restored_epoch=$(date -d "$restored_at" +%s 2>/dev/null) ||
    fail "DynamoDB restore summary has a malformed PITR cutoff"
  (( restored_epoch == expected_epoch )) ||
    fail "isolated table $target used a different PITR cutoff"

  write_restore_receipt \
    "$source" "$target" "$table_description" "$provenance_source" "$restored_at"
}

recover_restore_receipt_from_cloudtrail() {
  local source="$1" target="$2" table_description="$3"
  local source_arn expected_account expected_epoch expected_cutoff target_arn
  local restore_start lookup_start lookup_end deadline candidates count
  local event_time event_epoch created_at created_epoch delta
  [[ -s "$STATE_DIR/restore-start-epoch" ]] ||
    fail "cannot recover restore provenance without restore-start-epoch"
  restore_start=$(<"$STATE_DIR/restore-start-epoch")
  [[ "$restore_start" =~ ^[0-9]+$ ]] ||
    fail "persisted restore start time is malformed"
  source_arn=$(awk -F $'\t' -v table="$source" \
    '$1 == table { print $4 }' "$STATE_DIR/pitr.tsv")
  [[ -n "$source_arn" ]] ||
    fail "no persisted source ARN exists for $source"
  expected_account=$(jq -er '.account_id' "$STATE_DIR/run-context.json")
  expected_epoch=$(<"$STATE_DIR/restore-cutoff-epoch")
  [[ "$expected_epoch" =~ ^[0-9]+$ ]] ||
    fail "persisted restore cutoff is malformed"
  expected_cutoff=$(date -u -d "@$expected_epoch" +%Y-%m-%dT%H:%M:%SZ)
  target_arn="arn:aws:dynamodb:$REGION:$expected_account:table/$target"
  created_at=$(jq -er '.CreationDateTime' <<<"$table_description")
  created_epoch=$(date -d "$created_at" +%s 2>/dev/null) ||
    fail "isolated table $target has a malformed creation time"
  lookup_start=$(date -u -d "@$(( restore_start - 60 ))" \
    +%Y-%m-%dT%H:%M:%SZ)
  deadline=$(( $(date +%s) + CLOUDTRAIL_LOOKUP_SECS ))
  candidates="$STATE_DIR/cloudtrail-restore-candidates.current.json"

  while :; do
    lookup_end=$(date -u -d "@$(( $(date +%s) + 60 ))" \
      +%Y-%m-%dT%H:%M:%SZ)
    "${AWSQ[@]}" cloudtrail lookup-events \
      --lookup-attributes \
        AttributeKey=EventName,AttributeValue=RestoreTableToPointInTime \
      --start-time "$lookup_start" \
      --end-time "$lookup_end" \
      --output json >"$STATE_DIR/cloudtrail-restore-events.current.json"
    chmod 600 "$STATE_DIR/cloudtrail-restore-events.current.json"
    jq -c \
      --arg source_arn "$source_arn" \
      --arg target "$target" \
      --arg target_arn "$target_arn" \
      --arg region "$REGION" \
      --arg account "$expected_account" \
      --argjson cutoff_epoch "$expected_epoch" \
      --argjson restore_start "$restore_start" \
      --argjson created_epoch "$created_epoch" '
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
              (
                .requestParameters.restoreDateTime
                | event_epoch
              ) == $cutoff_epoch and
              $event_epoch != null and
              $event_epoch >= $restore_start and
              ($event_epoch - $created_epoch) >= -2 and
              ($event_epoch - $created_epoch) <= 2 and
              (
                [.resources[]?.ARN]
                | index($source_arn) != null and index($target_arn) != null
              )
            )
        ]
      ' "$STATE_DIR/cloudtrail-restore-events.current.json" >"$candidates"
    chmod 600 "$candidates"
    count=$(jq -er 'length' "$candidates")
    (( count <= 1 )) ||
      fail "multiple CloudTrail restore events match isolated table $target"
    (( count == 0 )) || break
    (( $(date +%s) < deadline )) ||
      fail "CloudTrail has no matching restore event for isolated table $target"
    sleep "$POLL_SECS"
  done

  event_time=$(jq -er '.[0].eventTime' "$candidates")
  event_epoch=$(date -d "$event_time" +%s 2>/dev/null) ||
    fail "CloudTrail restore event has a malformed event time"
  (( event_epoch >= restore_start )) ||
    fail "CloudTrail restore event predates this drill"
  delta=$(( created_epoch - event_epoch ))
  (( delta >= 0 )) || delta=$(( -delta ))
  (( delta <= 2 )) ||
    fail "isolated table $target creation time does not match its restore event"

  write_restore_receipt \
    "$source" "$target" "$table_description" "cloudtrail" "$expected_cutoff" \
    "$(jq -er '.[0].eventID' "$candidates")" "$event_time"
  rm -f "$STATE_DIR/cloudtrail-restore-events.current.json" "$candidates"
}

validate_restore_provenance() {
  local source="$1" target="$2"
  local table_description receipt restore_summary
  table_description=$("${AWSQ[@]}" dynamodb describe-table \
    --table-name "$target" --query 'Table' --output json)
  receipt=$(restore_receipt_path "$source")
  if [[ ! -s "$receipt" ]]; then
    restore_summary=$(jq -c '.RestoreSummary // null' <<<"$table_description")
    if [[ "$restore_summary" != "null" ]]; then
      persist_restore_summary_receipt \
        "$source" "$target" "$table_description" "restore_summary"
    else
      recover_restore_receipt_from_cloudtrail \
        "$source" "$target" "$table_description"
    fi
  fi
  validate_restore_receipt \
    "$source" "$target" "$table_description" "$receipt"
}

wait_table_active() {
  local table="$1" deadline=$(( $(date +%s) + RTO_TARGET_SECS ))
  while :; do
    local state
    describe_table_status "$table" ||
      fail "restored table $table disappeared before becoming ACTIVE"
    state="$DESCRIBED_TABLE_STATUS"
    case "$state" in
      ACTIVE) return 0 ;;
      CREATING|UPDATING) ;;
      ARCHIVED|ARCHIVING|DELETING|INACCESSIBLE_ENCRYPTION_CREDENTIALS|REPLICATION_NOT_AUTHORIZED)
        fail "restored table $table entered terminal state $state"
        ;;
      *) fail "restored table $table returned unknown state $state" ;;
    esac
    (( $(date +%s) < deadline )) ||
      fail "restored table $table exceeded ${RTO_TARGET_SECS}s"
    sleep "$POLL_SECS"
  done
}

cleanup_restored_tables() {
  if [[ ! -e "$STATE_DIR/table-map.tsv" ]]; then
    if [[ -s "$STATE_DIR/run-context.json" ]]; then
      for required in run-context.json pitr.tsv restore-cutoff-epoch; do
        [[ -s "$STATE_DIR/$required" ]] ||
          fail "cannot reconstruct a missing table map: $required is incomplete"
      done
      write_expected_table_map "$STATE_DIR/table-map.current.tsv"
      mv "$STATE_DIR/table-map.current.tsv" "$STATE_DIR/table-map.tsv"
      info "reconstructed deterministic table map for RUN_ID=$RUN_ID"
    elif [[ -e "$STATE_DIR/pitr.tsv" ||
      -e "$STATE_DIR/restore-cutoff-epoch" ||
      -e "$STATE_DIR/restore-start-epoch" ||
      -e "$STATE_DIR/anchors-complete" ||
      -e "$STATE_DIR/backup-job-id" ]]; then
      fail "restore progress exists without a deployment context"
    else
      fail "no restore context exists; cleanup cannot confirm isolated deletion"
    fi
  fi
  [[ -s "$STATE_DIR/table-map.tsv" ]] ||
    fail "persisted table map is empty"
  validate_table_action_state
  local source target
  while IFS=$'\t' read -r source target; do
    if describe_table_status "$target"; then
      if [[ "$DESCRIBED_TABLE_STATUS" != "DELETING" ]]; then
        if [[ "$DESCRIBED_TABLE_STATUS" != "ACTIVE" ]]; then
          validate_restore_provenance "$source" "$target"
          info "waiting for isolated table $target before deletion"
          wait_table_active "$target"
        fi
        validate_restore_provenance "$source" "$target"
        "${AWSQ[@]}" dynamodb delete-table --table-name "$target" >/dev/null
        info "deleting isolated table $target (source $source)"
      else
        validate_restore_provenance "$source" "$target"
        info "isolated table $target is already deleting"
      fi
    fi
  done <"$STATE_DIR/table-map.tsv"
  while IFS=$'\t' read -r _ target; do
    if describe_table_status "$target"; then
      "${AWSQ[@]}" dynamodb wait table-not-exists --table-name "$target"
    fi
  done <"$STATE_DIR/table-map.tsv"
  while IFS=$'\t' read -r _ target; do
    if describe_table_status "$target"; then
      fail "isolated table still exists after cleanup: $target"
    fi
  done <"$STATE_DIR/table-map.tsv"
}

if [[ "$ACTION" == "cleanup" ]]; then
  cleanup_restored_tables
  pass "isolated restored tables deleted for RUN_ID=$RUN_ID"
  exit 0
fi

for command in base64 cargo curl git python3; do
  command -v "$command" >/dev/null || fail "missing command: $command"
done
python3 -c 'import cryptography' >/dev/null 2>&1 ||
  fail "Python cryptography package is required for KMS/JWK verification"
[[ "$STACK" == "AgentAuthSaas" ]] ||
  fail "production drill requires STACK=AgentAuthSaas (got $STACK)"

ISSUER_T1="${ISSUER_T1:?ISSUER_T1 is required}"
ISSUER_T2="${ISSUER_T2:?ISSUER_T2 is required}"

ISSUER_T1="${ISSUER_T1%/}"
ISSUER_T2="${ISSUER_T2%/}"
[[ "$ISSUER_T1" != "$ISSUER_T2" ]] || fail "tenant issuers must differ"

stack_output() {
  local key="$1"
  jq -er --arg key "$key" \
    '.Stacks[0].Outputs[] | select(.OutputKey == $key) | .OutputValue' \
    "$STATE_DIR/stack.json"
}

table_target() {
  local source="$1"
  awk -F $'\t' -v source="$source" '$1 == source { print $2 }' \
    "$STATE_DIR/table-map.tsv"
}

stack_table_by_prefix() {
  local prefix="$1"
  local -a matches
  mapfile -t matches < <(jq -r --arg prefix "$prefix" '
    .StackResourceSummaries[]
    | select(
        .ResourceType == "AWS::DynamoDB::Table" and
        (.LogicalResourceId | startswith($prefix))
      )
    | .PhysicalResourceId
  ' "$STATE_DIR/stack-resources.json")
  (( ${#matches[@]} == 1 )) ||
    fail "expected exactly one deployed DynamoDB table with logical prefix $prefix"
  printf '%s\n' "${matches[0]}"
}

stack_lambda_by_prefix() {
  local prefix="$1"
  local -a matches
  mapfile -t matches < <(jq -r --arg prefix "$prefix" '
    .StackResourceSummaries[]
    | select(
        .ResourceType == "AWS::Lambda::Function" and
        (.LogicalResourceId | startswith($prefix))
      )
    | .PhysicalResourceId
  ' "$STATE_DIR/stack-resources.json")
  (( ${#matches[@]} == 1 )) ||
    fail "expected exactly one deployed Lambda with logical prefix $prefix"
  printf '%s\n' "${matches[0]}"
}

write_configuration_snapshot() {
  local kind="$1" table="$2" output="$3"
  local -a projection=()
  if [[ "$kind" == "clients" ]]; then
    projection=(
      --projection-expression
      'client_id,redirect_uris,token_endpoint_auth_method,client_secret_credentials_version,jwks,jwks_uri,token_endpoint_auth_signing_alg,default_resource,introspect_enabled,resource_ids,post_logout_redirect_uris,registration_token_credentials_version,client_type,id_token_signed_response_alg,oidc_sector_identifier,allowed_resources,allowed_scopes,redirect_mode,created_at,last_used_day,tombstoned_at,backchannel_token_delivery_mode,backchannel_client_notification_endpoint,require_dpop,prm_domains,audit_of,hard_deleted_at,last_used_day_audit'
    )
  fi
  "${AWSQ[@]}" dynamodb scan \
    --table-name "$table" \
    --consistent-read \
    "${projection[@]}" \
    --output json |
    jq -L "$JQ_LIB_DIR" -Sc \
      --arg kind "$kind" \
      'include "backup_restore_filters"; canonical_configuration_items($kind)' \
      >"$output"
  chmod 600 "$output"
}

write_identity_snapshot() {
  local kind="$1" table="$2" output="$3"
  local -a projection
  case "$kind" in
    users)
      projection=(
        --projection-expression
        'user_id,email,created_at,updated_at,last_login_at,#status,credential_epoch,revocation_pending,scim_external_id,scim_user_name,scim_display_name,attributes,scim_tenant,record_type,alias_kind,alias_value,canonical_user_id,initial_lifecycle_epoch'
        --expression-attribute-names '{"#status":"status"}'
      )
      ;;
    passkeys)
      projection=(
        --projection-expression
        'credential_id,user_id,sign_count'
      )
      ;;
    password_credentials)
      projection=(
        --projection-expression
        'user_id,must_change,revocation_pending,#version,updated_at'
        --expression-attribute-names '{"#version":"version"}'
      )
      ;;
    *)
      fail "unknown identity snapshot kind: $kind"
      ;;
  esac
  "${AWSQ[@]}" dynamodb scan \
    --table-name "$table" \
    --consistent-read \
    "${projection[@]}" \
    --output json |
    jq -L "$JQ_LIB_DIR" -Sc \
      --arg kind "$kind" \
      'include "backup_restore_filters"; canonical_identity_items($kind)' \
      >"$output"
  chmod 600 "$output"
}

verify_user_tenant_ownership() {
  local snapshot="$1" phase="$2"
  jq -e -L "$JQ_LIB_DIR" \
    --argjson tenants "$TENANT_IDS_JSON" \
    'include "backup_restore_filters";
     user_tenant_ownership_is_valid($tenants)' \
    "$snapshot" >/dev/null ||
    fail "$phase Users authority has an invalid tenant or canonical reference"
  python3 "$SCRIPT_DIR/verify_scim_user_keys.py" \
    --users "$snapshot" \
    --tenants-json "$TENANT_IDS_JSON" ||
    fail "$phase Users authority has a non-canonical SCIM physical key"
}

verify_identity_tenant_integrity() {
  local phase="$1" users="$2" passkeys="$3" passwords="$4"
  jq -e -n -L "$JQ_LIB_DIR" \
    --argjson tenants "$TENANT_IDS_JSON" \
    --slurpfile users "$users" \
    --slurpfile passkeys "$passkeys" \
    --slurpfile passwords "$passwords" \
    'include "backup_restore_filters";
     ($passkeys[0]
       | credential_tenant_ownership_is_valid(
           $users[0]; "passkeys"; $tenants
         )) and
     ($passwords[0]
       | credential_tenant_ownership_is_valid(
           $users[0]; "password_credentials"; $tenants
         ))' >/dev/null ||
    fail "$phase credential authority has a cross-tenant or dangling User reference"
}

write_grant_snapshot() {
  local table="$1" output="$2" phase="$3"
  "${AWSQ[@]}" dynamodb scan \
    --table-name "$table" \
    --consistent-read \
    --projection-expression \
      'grant_id,user_id,gv_tenant,effective_pv,revision,credential_epoch,grant_json,policy_version,policy_text,policy_digest' \
    --output json |
    jq -e -L "$JQ_LIB_DIR" -Sc \
      --argjson tenants "$TENANT_IDS_JSON" \
      'include "backup_restore_filters"; canonical_grant_items($tenants)' \
      >"$output" ||
    fail "$phase Grant authority has an invalid tenant or physical/logical reference"
  chmod 600 "$output"
}

verify_client_credential_shape() {
  local table="$1" phase="$2" invalid_count
  invalid_count=$("${AWSQ[@]}" dynamodb scan \
    --table-name "$table" \
    --consistent-read \
    --select COUNT \
    --filter-expression \
      'attribute_exists(client_secret) OR attribute_exists(reg_token_hash) OR (attribute_exists(client_secret_credentials) AND (attribute_not_exists(client_secret_credentials_version) OR NOT attribute_type(client_secret_credentials, :string_type))) OR (attribute_exists(client_secret_credentials_version) AND (attribute_not_exists(client_secret_credentials) OR NOT attribute_type(client_secret_credentials_version, :number_type))) OR (attribute_exists(registration_token_credentials) AND (attribute_not_exists(registration_token_credentials_version) OR NOT attribute_type(registration_token_credentials, :string_type))) OR (attribute_exists(registration_token_credentials_version) AND (attribute_not_exists(registration_token_credentials) OR NOT attribute_type(registration_token_credentials_version, :number_type))) OR (attribute_exists(audit_of) AND (NOT attribute_type(audit_of, :string_type) OR attribute_not_exists(hard_deleted_at) OR NOT attribute_type(hard_deleted_at, :number_type))) OR (attribute_exists(hard_deleted_at) AND attribute_not_exists(audit_of)) OR (attribute_exists(last_used_day_audit) AND (attribute_not_exists(audit_of) OR NOT attribute_type(last_used_day_audit, :number_type))) OR (attribute_exists(audit_of) AND (attribute_exists(client_secret_credentials) OR attribute_exists(registration_token_credentials)))' \
    --expression-attribute-values \
      '{":string_type":{"S":"S"},":number_type":{"S":"N"}}' \
    --output json |
    jq -er '.Count')
  (( invalid_count == 0 )) ||
    fail "$phase Clients table contains legacy or malformed credential/audit state"
}

verify_identity_credential_shape() {
  local kind="$1" table="$2" phase="$3" invalid_count filter values
  local -a names=()
  case "$kind" in
    passkeys)
      filter='attribute_not_exists(credential_id) OR NOT attribute_type(credential_id, :string_type) OR attribute_not_exists(user_id) OR NOT attribute_type(user_id, :string_type) OR attribute_not_exists(sign_count) OR NOT attribute_type(sign_count, :number_type) OR attribute_not_exists(cred_json) OR NOT attribute_type(cred_json, :string_type)'
      values='{":string_type":{"S":"S"},":number_type":{"S":"N"}}'
      ;;
    password_credentials)
      filter='attribute_not_exists(user_id) OR NOT attribute_type(user_id, :string_type) OR attribute_not_exists(password_hash) OR NOT attribute_type(password_hash, :string_type) OR attribute_not_exists(must_change) OR NOT attribute_type(must_change, :boolean_type) OR attribute_not_exists(#version) OR NOT attribute_type(#version, :number_type) OR attribute_not_exists(updated_at) OR NOT attribute_type(updated_at, :number_type)'
      names=(--expression-attribute-names '{"#version":"version"}')
      values='{":string_type":{"S":"S"},":number_type":{"S":"N"},":boolean_type":{"S":"BOOL"}}'
      ;;
    *)
      fail "unknown protected credential shape kind: $kind"
      ;;
  esac
  invalid_count=$("${AWSQ[@]}" dynamodb scan \
    --table-name "$table" \
    --consistent-read \
    --select COUNT \
    --filter-expression "$filter" \
    "${names[@]}" \
    --expression-attribute-values "$values" \
    --output json |
    jq -er '.Count')
  (( invalid_count == 0 )) ||
    fail "$phase $kind table contains malformed credential state"
}

wait_backup_job() {
  local job_id="$1" deadline=$(( $(date +%s) + RTO_TARGET_SECS ))
  while :; do
    local state
    state=$("${AWSQ[@]}" backup describe-backup-job \
      --backup-job-id "$job_id" --query State --output text)
    case "$state" in
      COMPLETED) return 0 ;;
      ABORTED|EXPIRED|FAILED|PARTIAL)
        fail "AWS Backup job $job_id ended in $state"
        ;;
    esac
    (( $(date +%s) < deadline )) ||
      fail "AWS Backup job $job_id exceeded ${RTO_TARGET_SECS}s"
    sleep "$POLL_SECS"
  done
}

issuer_snapshot() {
  local issuer="$1" label="$2"
  local discovery jwks_uri jwks
  discovery=$(curl --fail --silent --show-error \
    "$issuer/.well-known/openid-configuration")
  jq -e --arg issuer "$issuer" '.issuer == $issuer' <<<"$discovery" >/dev/null ||
    fail "$label discovery issuer mismatch"
  jwks_uri=$(jq -er '.jwks_uri' <<<"$discovery")
  [[ "$jwks_uri" == "$issuer/jwks.json" ]] ||
    fail "$label jwks_uri is not issuer-bound"
  jwks=$(curl --fail --silent --show-error "$jwks_uri")
  jq -e '
    .keys
    | length >= 2 and
      all(.[]; (.kid | type == "string" and length > 0)) and
      ((map(.kid) | length) == (map(.kid) | unique | length))
  ' <<<"$jwks" >/dev/null ||
    fail "$label JWKS must publish uniquely identified EC and RSA keys"
  jq -Sc '.keys | sort_by(.kid)' <<<"$jwks" \
    >"$STATE_DIR/$label.jwks.json"
  chmod 600 "$STATE_DIR/$label.jwks.json"
}

verify_issuers() {
  local phase="$1"
  issuer_snapshot "$ISSUER_T1" "${phase}-t1"
  issuer_snapshot "$ISSUER_T2" "${phase}-t2"
  if ! jq -e -n \
      --slurpfile left "$STATE_DIR/${phase}-t1.jwks.json" \
      --slurpfile right "$STATE_DIR/${phase}-t2.jwks.json" '
        ($left[0] | map(.kid)) as $left_kids
        | ($right[0] | map(.kid)) as $right_kids
        | all(
            $left_kids[];
            . as $kid | ($right_kids | index($kid)) == null
          )
      ' >/dev/null; then
    fail "tenant JWKS sets overlap during $phase verification"
  fi
  pass "$phase issuers and tenant-disjoint JWKS"
}

info "run_id=$RUN_ID state=$STATE_DIR"
"${AWSQ[@]}" sts get-caller-identity --output json >"$STATE_DIR/caller.json"
chmod 600 "$STATE_DIR/caller.json"
"${AWSQ[@]}" cloudformation describe-stacks --stack-name "$STACK" \
  --output json >"$STATE_DIR/stack.json"
chmod 600 "$STATE_DIR/stack.json"
"${AWSQ[@]}" cloudformation list-stack-resources --stack-name "$STACK" \
  --output json >"$STATE_DIR/stack-resources.json"
chmod 600 "$STATE_DIR/stack-resources.json"
"${AWSQ[@]}" cloudformation get-template --stack-name "$STACK" \
  --template-stage Processed --output json >"$STATE_DIR/stack-template.json"
chmod 600 "$STATE_DIR/stack-template.json"

VAULT=$(stack_output RecoveryBackupVaultName)
PLAN_ID=$(stack_output RecoveryBackupPlanId)
BACKUP_ROLE=$(stack_output RecoveryBackupRoleArn)
DEPLOYED_COMMIT=$(stack_output RecoveryDeploymentCommit)
TABLES_JSON=$(stack_output RecoveryAuthorityTableNames)
TENANT_ISSUERS_JSON=$(stack_output RecoveryTenantIssuers)
CLIENTS_TABLE=$(stack_output ClientsTableName)
WORKLOAD_TRUST_TABLE=$(stack_output WorkloadTrustTableName)
FEDERATION_CONFIG_TABLE=$(stack_table_by_prefix FederationConfigTable)
SCIM_GROUPS_TABLE=$(stack_output ScimGroupsTableName)
DOMAIN_MAP_TABLE=$(stack_output DomainMapTableName)
USERS_TABLE=$(stack_output UsersTableName)
PASSKEY_TABLE=$(stack_table_by_prefix PasskeyTable)
PASSWORD_CREDENTIALS_TABLE=$(stack_output PasswordCredentialsTableName)
GRANTS_TABLE=$(stack_output GrantsTableName)
SECURITY_EVENTS_TABLE=$(stack_output SecurityEventsTableName)
TENANT_KEYS_TABLE=$(stack_output TenantKeysTableName)
ADMIN_AUTH_TABLE=$(stack_output AdminAuthTableName)
ARCHIVE_BUCKET=$(stack_output SecurityEventArchiveBucketName)
AUTH_FUNCTION=$(stack_lambda_by_prefix AuthFn)
AUTH_ROLE_ARN=$("${AWSQ[@]}" lambda get-function-configuration \
  --function-name "$AUTH_FUNCTION" --query Role --output text)
[[ "$AUTH_ROLE_ARN" == arn:aws:iam::*:role/* ]] ||
  fail "deployed Auth runtime role is missing"
CONFIGURATION_TABLES=(
  "clients"$'\t'"$CLIENTS_TABLE"
  "workload_trust"$'\t'"$WORKLOAD_TRUST_TABLE"
  "federation"$'\t'"$FEDERATION_CONFIG_TABLE"
  "scim_groups"$'\t'"$SCIM_GROUPS_TABLE"
  "domain_map"$'\t'"$DOMAIN_MAP_TABLE"
)
IDENTITY_TABLES=(
  "users"$'\t'"$USERS_TABLE"
  "passkeys"$'\t'"$PASSKEY_TABLE"
  "password_credentials"$'\t'"$PASSWORD_CREDENTIALS_TABLE"
)
jq -e '
  type == "object" and
  keys == ["t1", "t2"] and
  all(.[]; type == "string" and startswith("https://"))
' <<<"$TENANT_ISSUERS_JSON" >/dev/null ||
  fail "deployed recovery issuer map must contain exactly HTTPS t1 and t2 issuers"
TENANT_IDS_JSON=$(jq -c 'keys' <<<"$TENANT_ISSUERS_JSON")
EXPECTED_ISSUER_T1=$(jq -er '.t1' <<<"$TENANT_ISSUERS_JSON")
EXPECTED_ISSUER_T2=$(jq -er '.t2' <<<"$TENANT_ISSUERS_JSON")
[[ "$ISSUER_T1" == "$EXPECTED_ISSUER_T1" ]] ||
  fail "ISSUER_T1 does not match the deployed AgentAuthSaas t1 issuer"
[[ "$ISSUER_T2" == "$EXPECTED_ISSUER_T2" ]] ||
  fail "ISSUER_T2 does not match the deployed AgentAuthSaas t2 issuer"
mapfile -t DURABLE_TABLES < <(jq -er '.[]' <<<"$TABLES_JSON")
[[ "${#DURABLE_TABLES[@]}" -eq 12 ]] ||
  fail "durable recovery selection must contain exactly 12 tables"
RECOVERABLE_TABLE_PREFIXES=(
  ClientsTable
  WorkloadTrustTable
  GrantsTable
  FederationConfigTable
  AdminAuthTable
  PasskeyTable
  SecurityEventsTable
  UsersTable
  ScimGroupsTable
  PasswordCredentialsTable
  DomainMapTable
  TenantKeysTable
)
for prefix in "${RECOVERABLE_TABLE_PREFIXES[@]}"; do
  stack_table_by_prefix "$prefix"
done | LC_ALL=C sort >"$STATE_DIR/expected-deployed-tables"
printf '%s\n' "${DURABLE_TABLES[@]}" | LC_ALL=C sort \
  >"$STATE_DIR/output-deployed-tables"
if ! cmp -s "$STATE_DIR/expected-deployed-tables" \
    "$STATE_DIR/output-deployed-tables"; then
  fail "recovery output differs from the reviewed durable authority classes"
fi
chmod 600 "$STATE_DIR/expected-deployed-tables" \
  "$STATE_DIR/output-deployed-tables"

REPO_ROOT=$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)
LOCAL_COMMIT=$(git -C "$REPO_ROOT" rev-parse HEAD)
[[ "$LOCAL_COMMIT" == "$DEPLOYED_COMMIT" ]] ||
  fail "local drill commit $LOCAL_COMMIT differs from deployed commit $DEPLOYED_COMMIT"
[[ -z "$(git -C "$REPO_ROOT" status --porcelain)" ]] ||
  fail "qualifying drill requires a clean checkout of the deployed commit"

current_context="$STATE_DIR/run-context.current.json"
durable_tables_json=$(printf '%s\n' "${DURABLE_TABLES[@]}" |
  LC_ALL=C sort | jq -Rsc 'split("\n")[:-1]')
jq -n \
  --arg account_id "$(jq -er '.Account' "$STATE_DIR/caller.json")" \
  --arg stack_id "$(jq -er '.Stacks[0].StackId' "$STATE_DIR/stack.json")" \
  --arg deployment_commit "$DEPLOYED_COMMIT" \
  --arg issuer_t1 "$ISSUER_T1" \
  --arg issuer_t2 "$ISSUER_T2" \
  --argjson durable_tables "$durable_tables_json" \
  '{
    account_id: $account_id,
    stack_id: $stack_id,
    deployment_commit: $deployment_commit,
    issuer_t1: $issuer_t1,
    issuer_t2: $issuer_t2,
    durable_tables: $durable_tables
  }' >"$current_context"
chmod 600 "$current_context"
if [[ -s "$STATE_DIR/run-context.json" ]]; then
  cmp -s "$STATE_DIR/run-context.json" "$current_context" ||
    fail "RUN_ID=$RUN_ID belongs to a different deployment context"
  rm -f "$current_context"
else
  mv "$current_context" "$STATE_DIR/run-context.json"
fi

"${AWSQ[@]}" backup get-backup-plan --backup-plan-id "$PLAN_ID" \
  --output json >"$STATE_DIR/backup-plan.json"
jq -e --arg vault "$VAULT" '
  .BackupPlan.Rules
  | length == 1 and
    .[0].RuleName == "DailyDurableAuthority" and
    .[0].TargetBackupVaultName == $vault and
    .[0].ScheduleExpression == "cron(0 5 * * ? *)" and
    .[0].StartWindowMinutes == 60 and
    .[0].CompletionWindowMinutes == 240 and
    .[0].Lifecycle.DeleteAfterDays == 35 and
    ((.[0].Lifecycle.MoveToColdStorageAfterDays // null) == null) and
    ((.[0].CopyActions // []) | length == 0) and
    .[0].RecoveryPointTags["agent-auth-data-class"] == "durable-authority"
' "$STATE_DIR/backup-plan.json" >/dev/null ||
  fail "deployed backup plan does not match the daily / 35-day policy"

backup_selections=$("${AWSQ[@]}" backup list-backup-selections \
  --backup-plan-id "$PLAN_ID" --output json)
jq -e '
  .BackupSelectionsList
  | length == 1 and .[0].SelectionName == "DurableAuthorityTables"
' <<<"$backup_selections" >/dev/null ||
  fail "backup plan must contain exactly the DurableAuthorityTables selection"
SELECTION_ID=$(jq -er '.BackupSelectionsList[0].SelectionId' \
  <<<"$backup_selections")
[[ -n "$SELECTION_ID" && "$SELECTION_ID" != "None" ]] ||
  fail "DurableAuthorityTables backup selection is missing"
"${AWSQ[@]}" backup get-backup-selection --backup-plan-id "$PLAN_ID" \
  --selection-id "$SELECTION_ID" --output json \
  >"$STATE_DIR/backup-selection.json"
for table in "${DURABLE_TABLES[@]}"; do
  table_arn=$("${AWSQ[@]}" dynamodb describe-table --table-name "$table" \
    --query 'Table.TableArn' --output text)
  jq -e --arg arn "$table_arn" \
    '.BackupSelection.Resources | index($arn) != null' \
    "$STATE_DIR/backup-selection.json" >/dev/null ||
    fail "$table is absent from the deployed backup selection"
done
selection_count=$(jq -er '.BackupSelection.Resources | length' \
  "$STATE_DIR/backup-selection.json")
(( selection_count == ${#DURABLE_TABLES[@]} )) ||
  fail "backup selection contains resources outside the recoverable authority set"
jq -e '
  ((.BackupSelection.NotResources // []) | length == 0) and
  ((.BackupSelection.ListOfTags // []) | length == 0) and
  (
    .BackupSelection.Conditions // {}
    | [
        (.StringEquals // []),
        (.StringNotEquals // []),
        (.StringLike // []),
        (.StringNotLike // [])
      ]
    | add
    | length == 0
  )
' "$STATE_DIR/backup-selection.json" >/dev/null ||
  fail "backup selection has tag conditions or exclusions"
jq -e --arg role "$BACKUP_ROLE" \
  '.BackupSelection.IamRoleArn == $role' \
  "$STATE_DIR/backup-selection.json" >/dev/null ||
  fail "backup selection does not use the reviewed backup role"
pass "deployed daily backup plan selects all ${#DURABLE_TABLES[@]} durable tables"

verify_issuers before

# Secrets are verified only through metadata. GetSecretValue is intentionally absent.
mapfile -t SECRET_IDS < <(jq -r '
  .StackResourceSummaries[]
  | select(.ResourceType == "AWS::SecretsManager::Secret")
  | .PhysicalResourceId
' "$STATE_DIR/stack-resources.json")
mapfile -t RUNTIME_STACK_SECRET_IDS < <(jq -r '
  .StackResourceSummaries[]
  | select(
      .ResourceType == "AWS::SecretsManager::Secret" and
      (
        (.LogicalResourceId | startswith("AdminCredentialSet")) or
        (.LogicalResourceId | startswith("TenantAdminCredentialSet")) or
        (.LogicalResourceId | startswith("ScimCredentialSet"))
      )
    )
  | .PhysicalResourceId
' "$STATE_DIR/stack-resources.json")
[[ "${#SECRET_IDS[@]}" -ge 8 ]] ||
  fail "expected stack-managed server/admin/SCIM secrets"
(( ${#RUNTIME_STACK_SECRET_IDS[@]} >= 5 )) ||
  fail "expected runtime platform/tenant Admin and SCIM credential secrets"
template_secret_count=$(jq -er '
  [
    .TemplateBody.Resources[]
    | select(.Type == "AWS::SecretsManager::Secret")
  ] | length
' "$STATE_DIR/stack-template.json")
(( template_secret_count == ${#SECRET_IDS[@]} )) ||
  fail "deployed template Secret set differs from stack resources"
jq -e '
  [
    .TemplateBody.Resources[]
    | select(.Type == "AWS::SecretsManager::Secret")
    | .DeletionPolicy == "Retain" and .UpdateReplacePolicy == "Retain"
  ] | length > 0 and all
' "$STATE_DIR/stack-template.json" >/dev/null ||
  fail "every stack-managed Secret must retain on delete and replacement"
for secret_id in "${SECRET_IDS[@]}"; do
  verify_secret_dependency "$secret_id" "stack-managed secret $secret_id"
done
pass "${#SECRET_IDS[@]} required secret dependencies have one AWSCURRENT version without reading values"

mapfile -t STACK_KMS_KEY_IDS < <(jq -r '
  .StackResourceSummaries[]
  | select(.ResourceType == "AWS::KMS::Key")
  | .PhysicalResourceId
' "$STATE_DIR/stack-resources.json")
[[ "${#STACK_KMS_KEY_IDS[@]}" -ge 4 ]] ||
  fail "expected stack-managed signing, grace, and backup KMS keys"
template_kms_key_count=$(jq -er '
  [.TemplateBody.Resources[] | select(.Type == "AWS::KMS::Key")] | length
' "$STATE_DIR/stack-template.json")
(( template_kms_key_count == ${#STACK_KMS_KEY_IDS[@]} )) ||
  fail "deployed template KMS key set differs from stack resources"
jq -e '
  [
    .TemplateBody.Resources[]
    | select(.Type == "AWS::KMS::Key")
    | .DeletionPolicy == "Retain" and .UpdateReplacePolicy == "Retain"
  ] | length > 0 and all
' "$STATE_DIR/stack-template.json" >/dev/null ||
  fail "every stack-managed KMS key must retain on delete and replacement"
for key_id in "${STACK_KMS_KEY_IDS[@]}"; do
  state=$("${AWSQ[@]}" kms describe-key --key-id "$key_id" \
    --query 'KeyMetadata.KeyState' --output text)
  [[ "$state" == "Enabled" ]] ||
    fail "stack-managed KMS key $key_id is not Enabled"
done
pass "${#STACK_KMS_KEY_IDS[@]} retained stack-managed KMS key dependencies are Enabled"

# Capture stable, non-secret verification anchors exactly once. A resumed run
# reuses the same authority snapshot and common restore cutoff.
if [[ ! -f "$STATE_DIR/anchors-complete" ]]; then
  for entry in "${IDENTITY_TABLES[@]}"; do
    IFS=$'\t' read -r kind table <<<"$entry"
    if [[ "$kind" != "users" ]]; then
      verify_identity_credential_shape "$kind" "$table" "source"
    fi
    write_identity_snapshot \
      "$kind" "$table" "$STATE_DIR/identity-$kind-source.json"
    if [[ "$kind" == "users" ]]; then
      verify_user_tenant_ownership \
        "$STATE_DIR/identity-$kind-source.json" "source"
    fi
  done
  verify_identity_tenant_integrity \
    "source" \
    "$STATE_DIR/identity-users-source.json" \
    "$STATE_DIR/identity-passkeys-source.json" \
    "$STATE_DIR/identity-password_credentials-source.json"
  verify_client_credential_shape "$CLIENTS_TABLE" "source"
  for entry in "${CONFIGURATION_TABLES[@]}"; do
    IFS=$'\t' read -r kind table <<<"$entry"
    write_configuration_snapshot \
      "$kind" "$table" "$STATE_DIR/config-$kind-source.json"
  done
  for tenant in t1 t2; do
    partition=$(printf '%s\037scim-users' "$tenant")
    values=$(jq -cn --arg value "$partition" '{":tenant":{S:$value}}')
    "${AWSQ[@]}" dynamodb query --table-name "$USERS_TABLE" \
      --index-name scim_tenant-index \
      --key-condition-expression 'scim_tenant = :tenant' \
      --expression-attribute-values "$values" \
      --output json >"$STATE_DIR/users-$tenant.json"
    jq -e --arg prefix "$(printf '%s\037' "$tenant")" '
      .Count > 0 and all(.Items[]; .user_id.S | startswith($prefix))
    ' "$STATE_DIR/users-$tenant.json" >/dev/null ||
      fail "source Users table lacks an isolated $tenant partition"
    jq -Sc '.Items | sort_by(.user_id.S)' "$STATE_DIR/users-$tenant.json" |
      sha256sum | cut -d' ' -f1 >"$STATE_DIR/users-$tenant.sha256"
    chmod 600 "$STATE_DIR/users-$tenant.json" \
      "$STATE_DIR/users-$tenant.sha256"
  done

  for tenant in t1 t2; do
    "${AWSQ[@]}" dynamodb get-item --table-name "$TENANT_KEYS_TABLE" \
      --key "$(jq -cn --arg tenant "$tenant" '{tenant_id:{S:$tenant}}')" \
      --projection-expression 'tenant_id,record_json' --output json \
      >"$STATE_DIR/tenant-keys-$tenant.json"
    jq -e '.Item.record_json.S | fromjson | .served_snapshot.ec.active.key_arn and
      .served_snapshot.rsa.active.key_arn' "$STATE_DIR/tenant-keys-$tenant.json" \
      >/dev/null || fail "source tenant key record is incomplete for $tenant"
    chmod 600 "$STATE_DIR/tenant-keys-$tenant.json"
  done

  admin_config_values='{":config":{"S":"config"}}'
  "${AWSQ[@]}" dynamodb scan --table-name "$ADMIN_AUTH_TABLE" \
    --consistent-read \
    --filter-expression 'record_type = :config' \
    --expression-attribute-values "$admin_config_values" \
    --output json >"$STATE_DIR/admin-config-source.json"
  jq -e '
    .Count > 0 and all(
      .Items[];
      . as $item
      | ($item.record_json.S | fromjson) as $config
      | $item.key.S == ("config#" + $config.tenant_id) and
        $item.record_type.S == "config" and
        ($item.expires_at == null) and
        $item.tenant_id.S == $config.tenant_id and
        ($item.revision.N | tonumber) == $config.revision and
        (
          [
            $config.tenant_id,
            $config.binding_id,
            $config.issuer,
            $config.client_id,
            $config.client_secret_ref,
            $config.authorization_endpoint,
            $config.token_endpoint,
            $config.jwks_uri,
            $config.redirect_uri,
            $config.identity_claim
          ]
          | all(.[]; type == "string" and length > 0)
        ) and
        (
          $config.scopes
          | type == "array" and
            length > 0 and
            all(.[]; type == "string")
        ) and
        (
          ($config | has("strong_acr_values") | not) or
          (
            $config.strong_acr_values
            | type == "array" and all(.[]; type == "string")
          )
        ) and
        ($config.identity_field == "user_id" or
          $config.identity_field == "user_name") and
        ($config.revision | type == "number" and floor == . and . >= 1) and
        ($config.updated_at | type == "number" and floor == . and . >= 0) and
        $config.client_secret_ref ==
          ("agent-auth/admin-oidc/" + $config.tenant_id)
    )
  ' "$STATE_DIR/admin-config-source.json" >/dev/null ||
    fail "source AdminAuth table has no valid configuration"
  jq -Sc '.Items | sort_by(.key.S)' "$STATE_DIR/admin-config-source.json" |
    sha256sum | cut -d' ' -f1 >"$STATE_DIR/admin-config-source.sha256"
  chmod 600 "$STATE_DIR/admin-config-source.json" \
    "$STATE_DIR/admin-config-source.sha256"

  write_grant_snapshot \
    "$GRANTS_TABLE" "$STATE_DIR/grants-source.json" "source"
  source_now=$(date +%s)
  jq -ce --argjson valid_until "$(( source_now + RTO_TARGET_SECS ))" '
    map(select(
        .grant_json.S != null and
        ((.grant_json.S | fromjson) |
          .status == "active" and .constraints.expires_at > $valid_until)
      ))
    | sort_by(.grant_id.S)
    | first
  ' "$STATE_DIR/grants-source.json" >"$STATE_DIR/grant-active-source.json" ||
    fail "source Grants table needs an active Grant valid beyond the RTO target"
  jq -ce '
    map(select(
        .grant_json.S != null and
        ((.grant_json.S | fromjson).status == "revoked")
      ))
    | sort_by(.grant_id.S)
    | first
  ' "$STATE_DIR/grants-source.json" >"$STATE_DIR/grant-revoked-source.json" ||
    fail "source Grants table needs a revoked Grant"
  chmod 600 "$STATE_DIR/grants-source.json" \
    "$STATE_DIR/grant-active-source.json" \
    "$STATE_DIR/grant-revoked-source.json"

  # Use the minimum latest-restorable time as one coherent cutoff for every table.
  : >"$STATE_DIR/pitr.tsv"
  MAX_RPO_LAG=0
  MIN_RESTORE_EPOCH=0
  RESTORE_CUTOFF=""
  for table in "${DURABLE_TABLES[@]}"; do
    pitr=$("${AWSQ[@]}" dynamodb describe-continuous-backups \
      --table-name "$table" --output json)
    observed_at=$(date +%s)
    status=$(jq -r \
      '.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus' \
      <<<"$pitr")
    [[ "$status" == "ENABLED" ]] || fail "PITR is not enabled for $table"
    recovery_period=$(jq -r \
      '.ContinuousBackupsDescription.PointInTimeRecoveryDescription.RecoveryPeriodInDays' \
      <<<"$pitr")
    [[ "$recovery_period" == "35" ]] ||
      fail "$table PITR recovery period is ${recovery_period} days instead of 35"
    latest=$(jq -r \
      '.ContinuousBackupsDescription.PointInTimeRecoveryDescription.LatestRestorableDateTime' \
      <<<"$pitr")
    latest_epoch=$(date -d "$latest" +%s)
    lag=$(( observed_at - latest_epoch ))
    (( lag >= 0 )) || fail "PITR clock moved backwards for $table"
    (( lag <= RPO_TARGET_SECS )) ||
      fail "$table PITR lag ${lag}s exceeds ${RPO_TARGET_SECS}s"
    (( lag > MAX_RPO_LAG )) && MAX_RPO_LAG=$lag
    if (( MIN_RESTORE_EPOCH == 0 || latest_epoch < MIN_RESTORE_EPOCH )); then
      MIN_RESTORE_EPOCH=$latest_epoch
      RESTORE_CUTOFF=$latest
    fi
    table_arn=$("${AWSQ[@]}" dynamodb describe-table --table-name "$table" \
      --query 'Table.TableArn' --output text)
    printf '%s\t%s\t%s\t%s\n' \
      "$table" "$latest" "$lag" "$table_arn" >>"$STATE_DIR/pitr.tsv"
  done
  common_cutoff_observed_at=$(date +%s)
  MAX_RPO_LAG=$(( common_cutoff_observed_at - MIN_RESTORE_EPOCH ))
  (( MAX_RPO_LAG >= 0 )) || fail "PITR common-cutoff clock moved backwards"
  (( MAX_RPO_LAG <= RPO_TARGET_SECS )) ||
    fail "PITR common-cutoff lag ${MAX_RPO_LAG}s exceeds ${RPO_TARGET_SECS}s"
  printf '%s\n' "$MAX_RPO_LAG" >"$STATE_DIR/max-rpo-lag"
  printf '%s\n' "$RESTORE_CUTOFF" >"$STATE_DIR/restore-cutoff"
  printf '%s\n' "$MIN_RESTORE_EPOCH" >"$STATE_DIR/restore-cutoff-epoch"

  for tenant in t1 t2; do
    jq -e --argjson cutoff "$MIN_RESTORE_EPOCH" '
      all(
        .Items[];
        (.created_at.N | tonumber) <= $cutoff and
        ((.updated_at.N // .created_at.N) | tonumber) <= $cutoff
      )
    ' "$STATE_DIR/users-$tenant.json" >/dev/null ||
      fail "source $tenant identity snapshot changed after the common PITR cutoff"
    jq -e --argjson cutoff "$MIN_RESTORE_EPOCH" '
      (.Item.record_json.S | fromjson | .updated_at) <= $cutoff
    ' "$STATE_DIR/tenant-keys-$tenant.json" >/dev/null ||
      fail "source $tenant key registry changed after the common PITR cutoff"
  done
  jq -e --argjson cutoff "$MIN_RESTORE_EPOCH" '
    all(
      .Items[];
      (.record_json.S | fromjson | .updated_at) <= $cutoff
    )
  ' "$STATE_DIR/admin-config-source.json" >/dev/null ||
    fail "source Admin OIDC configuration changed after the common PITR cutoff"

  "${AWSQ[@]}" dynamodb scan --table-name "$SECURITY_EVENTS_TABLE" \
    --projection-expression 'event_id,occurred_at,archive_key' --output json \
    >"$STATE_DIR/audit-source.json"
  jq -ce --argjson cutoff "$MIN_RESTORE_EPOCH" '
    .Items
    | map(select(
        (.occurred_at.N | tonumber) <= $cutoff and
        (.archive_key.S // "") != ""
      ))
    | sort_by(.occurred_at.N | tonumber)
    | last
  ' "$STATE_DIR/audit-source.json" >"$STATE_DIR/audit-sample.json" ||
    fail "no archived security event exists before the common PITR cutoff"
  chmod 600 "$STATE_DIR/pitr.tsv" "$STATE_DIR/max-rpo-lag" \
    "$STATE_DIR/restore-cutoff" "$STATE_DIR/restore-cutoff-epoch" \
    "$STATE_DIR/audit-source.json" "$STATE_DIR/audit-sample.json"
  touch "$STATE_DIR/anchors-complete"
  chmod 600 "$STATE_DIR/anchors-complete"
else
  for anchor in max-rpo-lag restore-cutoff restore-cutoff-epoch pitr.tsv \
      users-t1.sha256 users-t2.sha256 tenant-keys-t1.json tenant-keys-t2.json \
      admin-config-source.json admin-config-source.sha256 \
      grant-active-source.json grant-revoked-source.json audit-sample.json \
      config-clients-source.json config-workload_trust-source.json \
      config-federation-source.json config-scim_groups-source.json \
      config-domain_map-source.json identity-users-source.json \
      identity-passkeys-source.json identity-password_credentials-source.json; do
    [[ -s "$STATE_DIR/$anchor" ]] ||
      fail "incomplete persisted anchor state for RUN_ID=$RUN_ID: $anchor"
  done
  MAX_RPO_LAG=$(<"$STATE_DIR/max-rpo-lag")
  RESTORE_CUTOFF=$(<"$STATE_DIR/restore-cutoff")
  MIN_RESTORE_EPOCH=$(<"$STATE_DIR/restore-cutoff-epoch")
  info "reusing authority anchors and restore cutoff for RUN_ID=$RUN_ID"
fi
verify_user_tenant_ownership "$STATE_DIR/identity-users-source.json" "source"
verify_identity_tenant_integrity \
  "persisted source" \
  "$STATE_DIR/identity-users-source.json" \
  "$STATE_DIR/identity-passkeys-source.json" \
  "$STATE_DIR/identity-password_credentials-source.json"
pass "PITR worst observed lag ${MAX_RPO_LAG}s (target <= ${RPO_TARGET_SECS}s)"

admin_config_source_hash=$(jq -Sc \
  '.Items | sort_by(.key.S)' "$STATE_DIR/admin-config-source.json" |
  sha256sum | cut -d' ' -f1)
[[ "$(<"$STATE_DIR/admin-config-source.sha256")" == \
  "$admin_config_source_hash" ]] ||
  fail "persisted Admin OIDC configuration anchor is inconsistent"
jq -r '
  .Items[]
  | .record_json.S
  | fromjson
  | .client_secret_ref
' "$STATE_DIR/admin-config-source.json" | LC_ALL=C sort -u \
  >"$STATE_DIR/admin-oidc-secret-refs.current"
[[ -s "$STATE_DIR/admin-oidc-secret-refs.current" ]] ||
  fail "source Admin OIDC configuration has no client secret references"
chmod 600 "$STATE_DIR/admin-oidc-secret-refs.current"
mv "$STATE_DIR/admin-oidc-secret-refs.current" \
  "$STATE_DIR/admin-oidc-secret-refs"
mapfile -t ADMIN_OIDC_SECRET_REFS <"$STATE_DIR/admin-oidc-secret-refs"
(( ${#ADMIN_OIDC_SECRET_REFS[@]} > 0 )) ||
  fail "persisted Admin OIDC client secret references are empty"
for secret_id in "${ADMIN_OIDC_SECRET_REFS[@]}"; do
  verify_secret_dependency "$secret_id" \
    "Admin OIDC client secret dependency $secret_id"
done
pass "${#ADMIN_OIDC_SECRET_REFS[@]} Admin OIDC client secret dependencies have one AWSCURRENT version without reading values"

jq -e '
  all(
    .[];
    (.config_json.S | fromjson) as $config
    | ($config.oidc == null) or
      (
        ($config.oidc.client_secret_ref | type == "string") and
        ($config.oidc.client_secret_ref | length > 0)
      )
  )
' "$STATE_DIR/config-federation-source.json" >/dev/null ||
  fail "source Federation configuration has an invalid client secret reference"
jq -r '
  .[]
  | .config_json.S
  | fromjson
  | .oidc.client_secret_ref? // empty
' "$STATE_DIR/config-federation-source.json" | LC_ALL=C sort -u \
  >"$STATE_DIR/federation-secret-refs.current"
chmod 600 "$STATE_DIR/federation-secret-refs.current"
mv "$STATE_DIR/federation-secret-refs.current" \
  "$STATE_DIR/federation-secret-refs"
mapfile -t FEDERATION_SECRET_REFS <"$STATE_DIR/federation-secret-refs"
for secret_id in "${FEDERATION_SECRET_REFS[@]}"; do
  verify_secret_dependency "$secret_id" \
    "Federation client secret dependency $secret_id"
done
mapfile -t RUNTIME_SECRET_REFS < <(
  printf '%s\n' \
    "${RUNTIME_STACK_SECRET_IDS[@]}" \
    "${ADMIN_OIDC_SECRET_REFS[@]}" \
    "${FEDERATION_SECRET_REFS[@]}" |
    sed '/^$/d' | LC_ALL=C sort -u
)
for secret_id in "${RUNTIME_SECRET_REFS[@]}"; do
  verify_runtime_identity_policy_access "$secret_id"
done
pass "Auth runtime identity-policy simulation allows GetSecretValue and required customer-key Decrypt for ${#RUNTIME_SECRET_REFS[@]} exact secret dependencies"
SECRET_DEPENDENCY_COUNT=$((
  ${#SECRET_IDS[@]} +
  ${#ADMIN_OIDC_SECRET_REFS[@]} +
  ${#FEDERATION_SECRET_REFS[@]}
))
pass "${#FEDERATION_SECRET_REFS[@]} Federation client secret dependencies have one AWSCURRENT version without reading values"

archive_key=$(jq -er '.archive_key.S' "$STATE_DIR/audit-sample.json")
"${AWSQ[@]}" s3api head-object --bucket "$ARCHIVE_BUCKET" --key "$archive_key" \
  >/dev/null || fail "security-event archive object is missing"

users_arn=$("${AWSQ[@]}" dynamodb describe-table --table-name "$USERS_TABLE" \
  --query 'Table.TableArn' --output text)
if [[ ! -s "$STATE_DIR/backup-job-id" ]]; then
  backup_job=$("${AWSQ[@]}" backup start-backup-job \
    --backup-vault-name "$VAULT" \
    --resource-arn "$users_arn" \
    --iam-role-arn "$BACKUP_ROLE" \
    --idempotency-token "$(sha256_text "$RUN_ID-users-backup")" \
    --lifecycle DeleteAfterDays=35 \
    --recovery-point-tags "agent-auth-drill=$RUN_ID" \
    --query BackupJobId --output text)
  printf '%s\n' "$backup_job" >"$STATE_DIR/backup-job-id"
  chmod 600 "$STATE_DIR/backup-job-id"
fi
backup_job=$(<"$STATE_DIR/backup-job-id")
wait_backup_job "$backup_job"
backup_job_details=$("${AWSQ[@]}" backup describe-backup-job \
  --backup-job-id "$backup_job" --output json)
jq -e \
  --arg resource "$users_arn" \
  --arg vault "$VAULT" \
  --arg role "$BACKUP_ROLE" '
    .State == "COMPLETED" and
    .ResourceArn == $resource and
    .BackupVaultName == $vault and
    .IamRoleArn == $role
  ' <<<"$backup_job_details" >/dev/null ||
  fail "persisted backup job does not match this drill's Users table, vault, and role"
recovery_point=$(jq -er '.RecoveryPointArn' <<<"$backup_job_details")
[[ "$recovery_point" == arn:* ]] ||
  fail "completed backup job has no recovery point"
recovery_point_details=$("${AWSQ[@]}" backup describe-recovery-point \
  --backup-vault-name "$VAULT" \
  --recovery-point-arn "$recovery_point" --output json)
jq -e \
  --arg resource "$users_arn" \
  --arg role "$BACKUP_ROLE" '
    .Status == "COMPLETED" and
    .ResourceArn == $resource and
    .IamRoleArn == $role and
    .Lifecycle.DeleteAfterDays == 35
  ' <<<"$recovery_point_details" >/dev/null ||
  fail "on-demand recovery point metadata differs from the drill contract"
recovery_point_tags=$("${AWSQ[@]}" backup list-tags \
  --resource-arn "$recovery_point" --output json)
jq -e --arg run "$RUN_ID" '.Tags["agent-auth-drill"] == $run' \
  <<<"$recovery_point_tags" >/dev/null ||
  fail "on-demand recovery point is not tagged for RUN_ID=$RUN_ID"
printf '%s\n' "$recovery_point" >"$STATE_DIR/recovery-point-arn"
chmod 600 "$STATE_DIR/recovery-point-arn"
pass "on-demand AWS Backup recovery point completed"

if [[ ! -e "$STATE_DIR/table-map.tsv" ]]; then
  write_expected_table_map "$STATE_DIR/table-map.current.tsv"
  mv "$STATE_DIR/table-map.current.tsv" "$STATE_DIR/table-map.tsv"
elif [[ ! -s "$STATE_DIR/table-map.tsv" ]]; then
  fail "persisted table map is empty"
fi
validate_table_action_state

if [[ -e "$STATE_DIR/restore-start-epoch" ]]; then
  [[ -s "$STATE_DIR/restore-start-epoch" ]] ||
    fail "persisted restore start time is empty"
  restore_start_epoch=$(<"$STATE_DIR/restore-start-epoch")
  [[ "$restore_start_epoch" =~ ^[0-9]+$ ]] ||
    fail "persisted restore start time is malformed"
else
  if compgen -G "$STATE_DIR/restore-receipt-*.json" >/dev/null; then
    fail "restore receipts exist without the original RTO start time"
  fi
  while IFS=$'\t' read -r _ target; do
    if describe_table_status "$target"; then
      fail "isolated restore target exists without the original RTO start time"
    fi
  done <"$STATE_DIR/table-map.tsv"
  printf '%s\n' "$(date +%s)" >"$STATE_DIR/restore-start-epoch.current"
  chmod 600 "$STATE_DIR/restore-start-epoch.current"
  mv "$STATE_DIR/restore-start-epoch.current" \
    "$STATE_DIR/restore-start-epoch"
fi
while IFS=$'\t' read -r source target; do
  if ! describe_table_status "$target"; then
    source_arn=$(awk -F $'\t' -v table="$source" \
      '$1 == table { print $4 }' "$STATE_DIR/pitr.tsv")
    [[ -n "$source_arn" ]] ||
      fail "no persisted source ARN exists for $source"
    restore_response=$("${AWSQ[@]}" dynamodb restore-table-to-point-in-time \
      --source-table-arn "$source_arn" \
      --target-table-name "$target" \
      --restore-date-time "$RESTORE_CUTOFF" \
      --output json)
    restore_description=$(jq -ce '.TableDescription' <<<"$restore_response")
    persist_restore_summary_receipt \
      "$source" "$target" "$restore_description" "restore_api"
    info "started PITR restore $source -> $target"
  else
    info "resuming existing restore $target"
  fi
done <"$STATE_DIR/table-map.tsv"

while IFS=$'\t' read -r source target; do
  wait_table_active "$target"
  validate_restore_provenance "$source" "$target"
done <"$STATE_DIR/table-map.tsv"
pass "all ${#DURABLE_TABLES[@]} isolated tables restored at one cutoff and ACTIVE"

USERS_RESTORED=$(table_target "$USERS_TABLE")
GRANTS_RESTORED=$(table_target "$GRANTS_TABLE")
SECURITY_EVENTS_RESTORED=$(table_target "$SECURITY_EVENTS_TABLE")
TENANT_KEYS_RESTORED=$(table_target "$TENANT_KEYS_TABLE")
ADMIN_AUTH_RESTORED=$(table_target "$ADMIN_AUTH_TABLE")

identity_item_count=0
identity_manifest=""
for entry in "${IDENTITY_TABLES[@]}"; do
  IFS=$'\t' read -r kind source_table <<<"$entry"
  restored_table=$(table_target "$source_table")
  if [[ "$kind" != "users" ]]; then
    verify_identity_credential_shape "$kind" "$restored_table" "restored"
  fi
  write_identity_snapshot \
    "$kind" "$restored_table" "$STATE_DIR/identity-$kind-restored.json"
  if [[ "$kind" == "users" ]]; then
    verify_user_tenant_ownership \
      "$STATE_DIR/identity-$kind-restored.json" "restored"
  fi
  cmp -s \
    "$STATE_DIR/identity-$kind-source.json" \
    "$STATE_DIR/identity-$kind-restored.json" ||
    fail "restored $kind identity authority differs from the persisted source anchor"
  identity_manifest+="$kind"$'\t'
  identity_manifest+="$(sha256sum "$STATE_DIR/identity-$kind-source.json" |
    cut -d' ' -f1)"$'\n'
  identity_item_count=$((identity_item_count +
    $(jq -er 'length' "$STATE_DIR/identity-$kind-restored.json")))
done
verify_identity_tenant_integrity \
  "restored" \
  "$STATE_DIR/identity-users-restored.json" \
  "$STATE_DIR/identity-passkeys-restored.json" \
  "$STATE_DIR/identity-password_credentials-restored.json"
identity_manifest_hash=$(sha256_text "$identity_manifest")
pass "restored complete identity authority and credential metadata match source"

configuration_item_count=0
configuration_manifest=""
for entry in "${CONFIGURATION_TABLES[@]}"; do
  IFS=$'\t' read -r kind source_table <<<"$entry"
  restored_table=$(table_target "$source_table")
  if [[ "$kind" == "clients" ]]; then
    verify_client_credential_shape "$restored_table" "restored"
  fi
  write_configuration_snapshot \
    "$kind" "$restored_table" "$STATE_DIR/config-$kind-restored.json"
  cmp -s \
    "$STATE_DIR/config-$kind-source.json" \
    "$STATE_DIR/config-$kind-restored.json" ||
    fail "restored $kind configuration differs from the persisted source anchor"
  configuration_manifest+="$kind"$'\t'
  configuration_manifest+="$(sha256sum "$STATE_DIR/config-$kind-source.json" |
    cut -d' ' -f1)"$'\n'
  configuration_item_count=$((configuration_item_count +
    $(jq -er 'length' "$STATE_DIR/config-$kind-restored.json")))
done
configuration_manifest_hash=$(sha256_text "$configuration_manifest")
pass "restored client/workload/federation/Group/domain configuration matches source authority"

for tenant in t1 t2; do
  partition=$(printf '%s\037scim-users' "$tenant")
  prefix=$(printf '%s\037' "$tenant")
  values=$(jq -cn --arg value "$partition" '{":tenant":{S:$value}}')
  result=$("${AWSQ[@]}" dynamodb query --table-name "$USERS_RESTORED" \
    --index-name scim_tenant-index \
    --key-condition-expression 'scim_tenant = :tenant' \
    --expression-attribute-values "$values" \
    --output json)
  jq -e --arg prefix "$prefix" '
    .Count > 0 and all(.Items[]; .user_id.S | startswith($prefix))
  ' <<<"$result" >/dev/null ||
    fail "restored Users table broke $tenant physical isolation"
  restored_identity_hash=$(jq -Sc \
    '.Items | sort_by(.user_id.S)' <<<"$result" |
    sha256sum | cut -d' ' -f1)
  [[ "$(<"$STATE_DIR/users-$tenant.sha256")" == "$restored_identity_hash" ]] ||
    fail "restored Users table differs from the source $tenant identity set"
done
pass "restored t1/t2 identity sets match and remain physically isolated"

write_grant_snapshot \
  "$GRANTS_RESTORED" "$STATE_DIR/grants-restored.json" "restored"
cmp -s "$STATE_DIR/grants-source.json" "$STATE_DIR/grants-restored.json" ||
  fail "restored complete Grant authority differs from the persisted source anchor"
grant_authority_hash=$(sha256sum "$STATE_DIR/grants-source.json" | cut -d' ' -f1)
grant_item_count=$(jq -er 'length' "$STATE_DIR/grants-restored.json")
pass "restored all $grant_item_count Grant-table rows with validated projections"

grant_id=$(jq -er '.grant_id.S' "$STATE_DIR/grant-active-source.json")
grant_source_json=$(jq -er '.grant_json.S' \
  "$STATE_DIR/grant-active-source.json")
grant_source_hash=$(sha256_text "$grant_source_json")
grant_restored=$("${AWSQ[@]}" dynamodb get-item \
  --table-name "$GRANTS_RESTORED" \
  --key "$(jq -cn --arg id "$grant_id" '{grant_id:{S:$id}}')" \
  --projection-expression 'grant_json' --output json)
now_epoch=$(date +%s)
jq -e --argjson now "$now_epoch" '
  .Item.grant_json.S
  | fromjson
  | .status == "active" and .constraints.expires_at > $now
' <<<"$grant_restored" >/dev/null ||
  fail "restored Grant sample is no longer active"
grant_restored_json=$(jq -er '.Item.grant_json.S' <<<"$grant_restored")
grant_restored_hash=$(sha256_text "$grant_restored_json")
[[ "$grant_source_hash" == "$grant_restored_hash" ]] ||
  fail "restored active Grant differs from the persisted source anchor"
pass "restored active authorization Grant matches the persisted source anchor"

revoked_grant_id=$(jq -er '.grant_id.S' \
  "$STATE_DIR/grant-revoked-source.json")
revoked_grant_source_json=$(jq -er '.grant_json.S' \
  "$STATE_DIR/grant-revoked-source.json")
revoked_grant_source_hash=$(sha256_text "$revoked_grant_source_json")
revoked_grant_restored=$("${AWSQ[@]}" dynamodb get-item \
  --table-name "$GRANTS_RESTORED" \
  --key "$(jq -cn --arg id "$revoked_grant_id" '{grant_id:{S:$id}}')" \
  --projection-expression 'grant_json' --output json)
jq -e '.Item.grant_json.S | fromjson | .status == "revoked"' \
  <<<"$revoked_grant_restored" >/dev/null ||
  fail "restored Grant authority lost the sampled revocation"
revoked_grant_restored_json=$(jq -er '.Item.grant_json.S' \
  <<<"$revoked_grant_restored")
revoked_grant_restored_hash=$(sha256_text "$revoked_grant_restored_json")
[[ "$revoked_grant_source_hash" == "$revoked_grant_restored_hash" ]] ||
  fail "restored revoked Grant differs from the persisted source anchor"
pass "restored Grant revocation matches the persisted source anchor"

verify_issuers after
for tenant in t1 t2; do
  cmp -s "$STATE_DIR/before-$tenant.jwks.json" \
    "$STATE_DIR/after-$tenant.jwks.json" ||
    fail "$tenant issuer JWKS changed during the isolated restore drill"
done

printf 'agent-auth-dr-kms-probe:%s' "$RUN_ID" \
  >"$STATE_DIR/kms-signing-probe"
chmod 600 "$STATE_DIR/kms-signing-probe"
ALL_RESTORED_KEY_ARNS=()
for tenant in t1 t2; do
  source_record=$(jq -er '.Item.record_json.S' \
    "$STATE_DIR/tenant-keys-$tenant.json")
  restored_record=$("${AWSQ[@]}" dynamodb get-item \
    --table-name "$TENANT_KEYS_RESTORED" \
    --key "$(jq -cn --arg tenant "$tenant" '{tenant_id:{S:$tenant}}')" \
    --projection-expression 'record_json' --output json |
    jq -er '.Item.record_json.S')
  [[ "$(sha256_text "$source_record")" == "$(sha256_text "$restored_record")" ]] ||
    fail "restored tenant key registry differs for $tenant"

  jq -L "$JQ_LIB_DIR" -Sc \
    'include "backup_restore_filters"; tenant_record_jwks' \
    <<<"$restored_record" >"$STATE_DIR/restored-$tenant.jwks.json"
  chmod 600 "$STATE_DIR/restored-$tenant.jwks.json"
  cmp -s "$STATE_DIR/restored-$tenant.jwks.json" \
    "$STATE_DIR/after-$tenant.jwks.json" ||
    fail "restored $tenant key registry does not reproduce the live issuer JWKS"

  restored_key_arns=$(jq -L "$JQ_LIB_DIR" -r \
    'include "backup_restore_filters"; tenant_record_key_arns' \
    <<<"$restored_record")
  [[ -n "$restored_key_arns" ]] ||
    fail "restored $tenant key registry contains no KMS key references"
  mapfile -t RESTORED_KEY_ARNS <<<"$restored_key_arns"
  (( ${#RESTORED_KEY_ARNS[@]} >= 2 )) ||
    fail "restored $tenant key registry lacks EC/RSA KMS key references"
  ALL_RESTORED_KEY_ARNS+=("${RESTORED_KEY_ARNS[@]}")
  for key_arn in "${RESTORED_KEY_ARNS[@]}"; do
    state=$("${AWSQ[@]}" kms describe-key --key-id "$key_arn" \
      --query 'KeyMetadata.KeyState' --output text)
    [[ "$state" == "Enabled" ]] ||
      fail "referenced KMS key for $tenant is not Enabled"
  done

  restored_signing_keys_json=$(jq -L "$JQ_LIB_DIR" -c \
    'include "backup_restore_filters"; tenant_record_signing_keys' \
    <<<"$restored_record")
  jq -e '
    length >= 2 and
    (map(.key_arn) | length == (unique | length)) and
    any(.[]; .signing_algorithm == "ECDSA_SHA_256") and
    any(.[]; .signing_algorithm == "RSASSA_PKCS1_V1_5_SHA_256")
  ' <<<"$restored_signing_keys_json" >/dev/null ||
    fail "restored $tenant key registry has duplicate or incomplete signing metadata"
  restored_signing_keys=$(jq -c '.[]' <<<"$restored_signing_keys_json")
  [[ -n "$restored_signing_keys" ]] ||
    fail "restored $tenant key registry contains no signing key metadata"
  mapfile -t RESTORED_SIGNING_KEYS <<<"$restored_signing_keys"
  (( ${#RESTORED_SIGNING_KEYS[@]} == ${#RESTORED_KEY_ARNS[@]} )) ||
    fail "restored $tenant signing key metadata is inconsistent"
  for signing_key in "${RESTORED_SIGNING_KEYS[@]}"; do
    signing_algorithm=$(jq -er '.signing_algorithm' <<<"$signing_key")
    key_arn=$(jq -er '.key_arn' <<<"$signing_key")
    jq -e '.public_jwk' <<<"$signing_key" \
      >"$STATE_DIR/kms-probe-jwk.current"
    chmod 600 "$STATE_DIR/kms-probe-jwk.current"
    "${AWSQ[@]}" kms sign \
      --key-id "$key_arn" \
      --message "fileb://$STATE_DIR/kms-signing-probe" \
      --message-type RAW \
      --signing-algorithm "$signing_algorithm" \
      --query Signature --output text |
      base64 --decode >"$STATE_DIR/kms-probe-signature.current"
    [[ -s "$STATE_DIR/kms-probe-signature.current" ]] ||
      fail "referenced KMS key for $tenant returned no signature"
    chmod 600 "$STATE_DIR/kms-probe-signature.current"
    python3 "$SCRIPT_DIR/verify_kms_jwk_signature.py" \
      --algorithm "$signing_algorithm" \
      --jwk "$STATE_DIR/kms-probe-jwk.current" \
      --signature "$STATE_DIR/kms-probe-signature.current" \
      --message "$STATE_DIR/kms-signing-probe" ||
      fail "referenced KMS key for $tenant does not match its published JWK"
  done

  issuer=$(jq -er --arg tenant "$tenant" '.[$tenant]' \
    <<<"$TENANT_ISSUERS_JSON")
  runtime_probe="$STATE_DIR/restored-$tenant-runtime-signer.json"
  AWS_PROFILE="$PROFILE" AWS_REGION="$REGION" AWS_DEFAULT_REGION="$REGION" \
    cargo run --quiet --locked --features aws \
      --manifest-path "$REPO_ROOT/Cargo.toml" \
      --bin agent-auth-restored-tenant-signer-probe -- \
      "$TENANT_KEYS_RESTORED" "$tenant" "$issuer" >"$runtime_probe"
  chmod 600 "$runtime_probe"
  jq -e --arg tenant "$tenant" --arg issuer "$issuer" '
    .tenant == $tenant and
    .issuer == $issuer and
    .ec.jwk.alg == "ES256" and
    .rsa.jwk.alg == "RS256" and
    (.ec.signing_input | type == "string" and length > 0) and
    (.rsa.signing_input | type == "string" and length > 0) and
    (.ec.signature | type == "string" and length > 0) and
    (.rsa.signature | type == "string" and length > 0)
  ' "$runtime_probe" >/dev/null ||
    fail "restored runtime signer probe returned malformed evidence for $tenant"
  for algorithm in ec rsa; do
    if [[ "$algorithm" == "ec" ]]; then
      kms_algorithm=ECDSA_SHA_256
      signature_format=jose
      jws_algorithm=ES256
    else
      kms_algorithm=RSASSA_PKCS1_V1_5_SHA_256
      signature_format=der
      jws_algorithm=RS256
    fi
    jq ".${algorithm}.jwk" "$runtime_probe" \
      >"$STATE_DIR/runtime-probe-$tenant-$algorithm.jwk.json"
    jq -jer ".${algorithm}.signing_input" "$runtime_probe" \
      >"$STATE_DIR/runtime-probe-$tenant-$algorithm.message"
    runtime_signature=$(jq -er ".${algorithm}.signature" "$runtime_probe")
    chmod 600 \
      "$STATE_DIR/runtime-probe-$tenant-$algorithm.jwk.json" \
      "$STATE_DIR/runtime-probe-$tenant-$algorithm.message"
    python3 "$SCRIPT_DIR/verify_kms_jwk_signature.py" \
      --algorithm "$kms_algorithm" \
      --signature-format "$signature_format" \
      --jwk "$STATE_DIR/runtime-probe-$tenant-$algorithm.jwk.json" \
      --signature-base64url="$runtime_signature" \
      --message "$STATE_DIR/runtime-probe-$tenant-$algorithm.message" \
      --expected-issuer "$issuer" \
      --expected-subject "dr-probe:$tenant" \
      --expected-jws-alg "$jws_algorithm" ||
      fail "restored runtime signer produced an invalid $algorithm token signature for $tenant"
  done
done
restored_key_arn_count=${#ALL_RESTORED_KEY_ARNS[@]}
restored_unique_key_arn_count=$(printf '%s\n' "${ALL_RESTORED_KEY_ARNS[@]}" |
  LC_ALL=C sort -u | wc -l)
(( restored_key_arn_count == restored_unique_key_arn_count )) ||
  fail "restored tenant registries share a KMS key reference"
rm -f "$STATE_DIR/kms-signing-probe" \
  "$STATE_DIR/kms-probe-jwk.current" \
  "$STATE_DIR/kms-probe-signature.current"
pass "restored tenant registries resolve through the runtime signer and produce valid issuer-bound ES256/RS256 signatures"

"${AWSQ[@]}" dynamodb scan --table-name "$ADMIN_AUTH_RESTORED" \
  --consistent-read \
  --projection-expression '#key,record_type,expires_at' \
  --expression-attribute-names '{"#key":"key"}' --output json \
  >"$STATE_DIR/admin-auth-restored.json"
jq -e '
  all(
    .Items[];
    (
      (.key.S | startswith("config#")) and
      .record_type.S == "config" and
      (.expires_at == null)
    ) or (
      (
        (.key.S | startswith("flow#")) and .record_type.S == "flow"
      ) or (
        (.key.S | startswith("session#")) and .record_type.S == "session"
      )
    ) and (.expires_at.N != null)
  )
' "$STATE_DIR/admin-auth-restored.json" >/dev/null ||
  fail "restored AdminAuth table contains an unknown or malformed record class"
mapfile -t ADMIN_TRANSIENT_KEYS < <(jq -r '
  .Items[]
  | select(.record_type.S == "flow" or .record_type.S == "session")
  | .key.S
' "$STATE_DIR/admin-auth-restored.json")
for key in "${ADMIN_TRANSIENT_KEYS[@]}"; do
  "${AWSQ[@]}" dynamodb delete-item --table-name "$ADMIN_AUTH_RESTORED" \
    --key "$(jq -cn --arg key "$key" '{key:{S:$key}}')" >/dev/null
done
"${AWSQ[@]}" dynamodb scan --table-name "$ADMIN_AUTH_RESTORED" \
  --consistent-read --output json \
  >"$STATE_DIR/admin-auth-sanitized.json"
admin_config_count=$(jq -er '
  [.Items[] | select(
    (.key.S | startswith("config#")) and
    .record_type.S == "config" and
    (.expires_at == null)
  )] | length
' "$STATE_DIR/admin-auth-sanitized.json")
admin_remaining_count=$(jq -er '.Items | length' \
  "$STATE_DIR/admin-auth-sanitized.json")
(( admin_config_count > 0 && admin_remaining_count == admin_config_count )) ||
  fail "restored AdminAuth table has no required configuration"
restored_admin_config_hash=$(jq -Sc \
  '.Items | sort_by(.key.S)' "$STATE_DIR/admin-auth-sanitized.json" |
  sha256sum | cut -d' ' -f1)
[[ "$(<"$STATE_DIR/admin-config-source.sha256")" == \
    "$restored_admin_config_hash" ]] ||
  fail "restored Admin OIDC configuration differs from source authority"
admin_transient_removed=${#ADMIN_TRANSIENT_KEYS[@]}
pass "restored Admin configuration matches source; removed $admin_transient_removed flow/session rows"

audit_event_id=$(jq -er '.event_id.S' "$STATE_DIR/audit-sample.json")
audit_archive_key=$(jq -er '.archive_key.S' "$STATE_DIR/audit-sample.json")
audit_restored=$("${AWSQ[@]}" dynamodb get-item \
  --table-name "$SECURITY_EVENTS_RESTORED" \
  --key "$(jq -cn --arg id "$audit_event_id" '{event_id:{S:$id}}')" \
  --projection-expression 'event_id,archive_key' --output json)
jq -e --arg key "$audit_archive_key" '.Item.archive_key.S == $key' \
  <<<"$audit_restored" >/dev/null ||
  fail "restored audit ledger lost the archived event anchor"
"${AWSQ[@]}" s3api head-object --bucket "$ARCHIVE_BUCKET" \
  --key "$audit_archive_key" >/dev/null ||
  fail "retained audit archive lost the restored event object"
pass "hot audit ledger and retained archive remain continuous"

for entry in "${IDENTITY_TABLES[@]}"; do
  IFS=$'\t' read -r kind source_table <<<"$entry"
  if [[ "$kind" != "users" ]]; then
    verify_identity_credential_shape "$kind" "$source_table" "final source"
  fi
  write_identity_snapshot \
    "$kind" "$source_table" "$STATE_DIR/identity-$kind-final.json"
  if [[ "$kind" == "users" ]]; then
    verify_user_tenant_ownership \
      "$STATE_DIR/identity-$kind-final.json" "final source"
  fi
  cmp -s \
    "$STATE_DIR/identity-$kind-source.json" \
    "$STATE_DIR/identity-$kind-final.json" ||
    fail "source $kind identity authority changed during the drill"
done
verify_identity_tenant_integrity \
  "final source" \
  "$STATE_DIR/identity-users-final.json" \
  "$STATE_DIR/identity-passkeys-final.json" \
  "$STATE_DIR/identity-password_credentials-final.json"
pass "source identity authority remained stable through final verification"

write_grant_snapshot \
  "$GRANTS_TABLE" "$STATE_DIR/grants-final.json" "final source"
cmp -s "$STATE_DIR/grants-source.json" "$STATE_DIR/grants-final.json" ||
  fail "source complete Grant authority changed during the drill"
pass "source complete Grant authority remained stable through final verification"

for entry in "${CONFIGURATION_TABLES[@]}"; do
  IFS=$'\t' read -r kind source_table <<<"$entry"
  if [[ "$kind" == "clients" ]]; then
    verify_client_credential_shape "$source_table" "final source"
  fi
  write_configuration_snapshot \
    "$kind" "$source_table" "$STATE_DIR/config-$kind-final.json"
  cmp -s \
    "$STATE_DIR/config-$kind-source.json" \
    "$STATE_DIR/config-$kind-final.json" ||
    fail "source $kind configuration changed during the drill"
done
pass "source configuration remained stable through final verification"

cleanup_restored_tables
cleanup_complete=true
pass "isolated restored tables deleted"

# Evidence is published only after every source anchor and external dependency
# is still current following potentially lengthy table deletion.
for entry in "${IDENTITY_TABLES[@]}"; do
  IFS=$'\t' read -r kind source_table <<<"$entry"
  if [[ "$kind" != "users" ]]; then
    verify_identity_credential_shape "$kind" "$source_table" "post-cleanup source"
  fi
  write_identity_snapshot \
    "$kind" "$source_table" "$STATE_DIR/identity-$kind-post-cleanup.json"
  if [[ "$kind" == "users" ]]; then
    verify_user_tenant_ownership \
      "$STATE_DIR/identity-$kind-post-cleanup.json" "post-cleanup source"
  fi
  cmp -s \
    "$STATE_DIR/identity-$kind-source.json" \
    "$STATE_DIR/identity-$kind-post-cleanup.json" ||
    fail "source $kind identity authority changed during cleanup"
done
verify_identity_tenant_integrity \
  "post-cleanup source" \
  "$STATE_DIR/identity-users-post-cleanup.json" \
  "$STATE_DIR/identity-passkeys-post-cleanup.json" \
  "$STATE_DIR/identity-password_credentials-post-cleanup.json"

for entry in "${CONFIGURATION_TABLES[@]}"; do
  IFS=$'\t' read -r kind source_table <<<"$entry"
  if [[ "$kind" == "clients" ]]; then
    verify_client_credential_shape "$source_table" "post-cleanup source"
  fi
  write_configuration_snapshot \
    "$kind" "$source_table" "$STATE_DIR/config-$kind-post-cleanup.json"
  cmp -s \
    "$STATE_DIR/config-$kind-source.json" \
    "$STATE_DIR/config-$kind-post-cleanup.json" ||
    fail "source $kind configuration changed during cleanup"
done

write_grant_snapshot \
  "$GRANTS_TABLE" "$STATE_DIR/grants-post-cleanup.json" "post-cleanup source"
cmp -s "$STATE_DIR/grants-source.json" "$STATE_DIR/grants-post-cleanup.json" ||
  fail "source complete Grant authority changed during cleanup"

grant_final=$("${AWSQ[@]}" dynamodb get-item \
  --table-name "$GRANTS_TABLE" \
  --key "$(jq -cn --arg id "$grant_id" '{grant_id:{S:$id}}')" \
  --projection-expression 'grant_json' --consistent-read --output json)
grant_final_json=$(jq -er '.Item.grant_json.S' <<<"$grant_final")
[[ "$grant_source_hash" == "$(sha256_text "$grant_final_json")" ]] ||
  fail "source active Grant changed during the drill"
revoked_grant_final=$("${AWSQ[@]}" dynamodb get-item \
  --table-name "$GRANTS_TABLE" \
  --key "$(jq -cn --arg id "$revoked_grant_id" '{grant_id:{S:$id}}')" \
  --projection-expression 'grant_json' --consistent-read --output json)
revoked_grant_final_json=$(jq -er '.Item.grant_json.S' \
  <<<"$revoked_grant_final")
[[ "$revoked_grant_source_hash" == \
  "$(sha256_text "$revoked_grant_final_json")" ]] ||
  fail "source revoked Grant changed during the drill"

FINAL_TENANT_KEY_ARNS=()
for tenant in t1 t2; do
  source_record=$(jq -er '.Item.record_json.S' \
    "$STATE_DIR/tenant-keys-$tenant.json")
  final_record=$("${AWSQ[@]}" dynamodb get-item \
    --table-name "$TENANT_KEYS_TABLE" \
    --key "$(jq -cn --arg tenant "$tenant" '{tenant_id:{S:$tenant}}')" \
    --projection-expression 'record_json' --consistent-read --output json |
    jq -er '.Item.record_json.S')
  [[ "$(sha256_text "$source_record")" == "$(sha256_text "$final_record")" ]] ||
    fail "source tenant key registry changed for $tenant during the drill"
  final_signing_keys=$(jq -L "$JQ_LIB_DIR" -c \
    'include "backup_restore_filters"; tenant_record_signing_keys' \
    <<<"$final_record")
  jq -e '
    length >= 2 and
    (map(.key_arn) | length == (unique | length))
  ' <<<"$final_signing_keys" >/dev/null ||
    fail "source tenant key registry has duplicate KMS references for $tenant"
  final_key_arns=$(jq -r '.[].key_arn' <<<"$final_signing_keys")
  mapfile -t CURRENT_TENANT_KEY_ARNS <<<"$final_key_arns"
  FINAL_TENANT_KEY_ARNS+=("${CURRENT_TENANT_KEY_ARNS[@]}")
done
final_key_arn_count=${#FINAL_TENANT_KEY_ARNS[@]}
final_unique_key_arn_count=$(printf '%s\n' "${FINAL_TENANT_KEY_ARNS[@]}" |
  LC_ALL=C sort -u | wc -l)
(( final_key_arn_count == final_unique_key_arn_count )) ||
  fail "source tenant registries share a KMS key reference"

"${AWSQ[@]}" dynamodb scan --table-name "$ADMIN_AUTH_TABLE" \
  --consistent-read \
  --filter-expression 'record_type = :config' \
  --expression-attribute-values "$admin_config_values" \
  --output json >"$STATE_DIR/admin-config-post-cleanup.json"
chmod 600 "$STATE_DIR/admin-config-post-cleanup.json"
admin_config_final_hash=$(jq -Sc \
  '.Items | sort_by(.key.S)' "$STATE_DIR/admin-config-post-cleanup.json" |
  sha256sum | cut -d' ' -f1)
[[ "$admin_config_source_hash" == "$admin_config_final_hash" ]] ||
  fail "source Admin OIDC configuration changed during the drill"

audit_final=$("${AWSQ[@]}" dynamodb get-item \
  --table-name "$SECURITY_EVENTS_TABLE" \
  --key "$(jq -cn --arg id "$audit_event_id" '{event_id:{S:$id}}')" \
  --projection-expression 'event_id,occurred_at,archive_key' \
  --consistent-read --output json)
audit_source_hash=$(jq -Sc '.' "$STATE_DIR/audit-sample.json" |
  sha256sum | cut -d' ' -f1)
audit_final_hash=$(jq -Sc '.Item' <<<"$audit_final" |
  sha256sum | cut -d' ' -f1)
[[ "$audit_source_hash" == "$audit_final_hash" ]] ||
  fail "source audit anchor changed during the drill"
"${AWSQ[@]}" s3api head-object --bucket "$ARCHIVE_BUCKET" \
  --key "$audit_archive_key" >/dev/null ||
  fail "retained audit archive changed during cleanup"

recovery_point=$(<"$STATE_DIR/recovery-point-arn")
recovery_point_final=$("${AWSQ[@]}" backup describe-recovery-point \
  --backup-vault-name "$VAULT" \
  --recovery-point-arn "$recovery_point" --output json)
jq -e \
  --arg resource "$users_arn" \
  --arg role "$BACKUP_ROLE" '
    .Status == "COMPLETED" and
    .ResourceArn == $resource and
    .IamRoleArn == $role and
    .Lifecycle.DeleteAfterDays == 35
  ' <<<"$recovery_point_final" >/dev/null ||
  fail "on-demand recovery point changed during the drill"
recovery_point_tags_final=$("${AWSQ[@]}" backup list-tags \
  --resource-arn "$recovery_point" --output json)
jq -e --arg run "$RUN_ID" '.Tags["agent-auth-drill"] == $run' \
  <<<"$recovery_point_tags_final" >/dev/null ||
  fail "on-demand recovery point lost its drill tag"

verify_issuers final
for tenant in t1 t2; do
  cmp -s "$STATE_DIR/before-$tenant.jwks.json" \
    "$STATE_DIR/final-$tenant.jwks.json" ||
    fail "$tenant issuer JWKS changed before evidence publication"
done

for secret_id in "${SECRET_IDS[@]}" \
  "${ADMIN_OIDC_SECRET_REFS[@]}" "${FEDERATION_SECRET_REFS[@]}"; do
  verify_secret_dependency "$secret_id" \
    "post-cleanup required secret dependency $secret_id"
done
for key_id in "${STACK_KMS_KEY_IDS[@]}" "${FINAL_TENANT_KEY_ARNS[@]}"; do
  state=$("${AWSQ[@]}" kms describe-key --key-id "$key_id" \
    --query 'KeyMetadata.KeyState' --output text)
  [[ "$state" == "Enabled" ]] ||
    fail "required KMS key became unavailable during the drill"
done
pass "post-cleanup source anchors and external dependencies remained stable"

RESTORE_START=$(<"$STATE_DIR/restore-start-epoch")
VERIFIED_AT=$(date +%s)
RTO_SECS=$(( VERIFIED_AT - RESTORE_START ))
(( RTO_SECS >= 0 )) ||
  fail "measured RTO is negative; wall clock moved backward"
(( RTO_SECS <= RTO_TARGET_SECS )) ||
  fail "measured RTO ${RTO_SECS}s exceeds ${RTO_TARGET_SECS}s"
pass "measured restore RTO ${RTO_SECS}s (target <= ${RTO_TARGET_SECS}s)"

identity_t1_hash=$(<"$STATE_DIR/users-t1.sha256")
identity_t2_hash=$(<"$STATE_DIR/users-t2.sha256")
recovery_point_hash=""
if [[ -s "$STATE_DIR/recovery-point-arn" ]]; then
  recovery_point_hash=$(sha256_text "$(<"$STATE_DIR/recovery-point-arn")")
fi
jq -n \
  --arg run_id "$RUN_ID" \
  --arg stack "$STACK" \
  --arg region "$REGION" \
  --arg source_commit "$DEPLOYED_COMMIT" \
  --arg completed_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg restore_cutoff "$RESTORE_CUTOFF" \
  --arg issuer_t1 "$ISSUER_T1" \
  --arg issuer_t2 "$ISSUER_T2" \
  --arg identity_t1_sha256 "$identity_t1_hash" \
  --arg identity_t2_sha256 "$identity_t2_hash" \
  --arg identity_authority_sha256 "$identity_manifest_hash" \
  --arg required_configuration_sha256 "$configuration_manifest_hash" \
  --arg grant_authority_sha256 "$grant_authority_hash" \
  --arg grant_sha256 "$grant_source_hash" \
  --arg revoked_grant_sha256 "$revoked_grant_source_hash" \
  --arg audit_event_sha256 "$(sha256_text "$audit_event_id")" \
  --arg recovery_point_sha256 "$recovery_point_hash" \
  --argjson durable_table_count "${#DURABLE_TABLES[@]}" \
  --argjson secret_dependency_count "$SECRET_DEPENDENCY_COUNT" \
  --argjson stack_kms_key_count "${#STACK_KMS_KEY_IDS[@]}" \
  --argjson pitr_max_lag_seconds "$MAX_RPO_LAG" \
  --argjson rpo_target_seconds "$RPO_TARGET_SECS" \
  --argjson rto_seconds "$RTO_SECS" \
  --argjson rto_target_seconds "$RTO_TARGET_SECS" \
  --argjson restored_identity_items "$identity_item_count" \
  --argjson restored_grant_items "$grant_item_count" \
  --argjson admin_config_items "$admin_config_count" \
  --argjson restored_configuration_items "$configuration_item_count" \
  --argjson admin_transient_items_removed "$admin_transient_removed" \
  --argjson cleanup_complete "$cleanup_complete" \
  '{
    schema_version: "1.0",
    run_id: $run_id,
    stack: $stack,
    region: $region,
    source_commit: $source_commit,
    completed_at: $completed_at,
    targets: {
      rpo_seconds: $rpo_target_seconds,
      rto_seconds: $rto_target_seconds
    },
    measured: {
      restore_cutoff: $restore_cutoff,
      pitr_max_lag_seconds: $pitr_max_lag_seconds,
      rto_seconds: $rto_seconds
    },
    coverage: {
      durable_table_count: $durable_table_count,
      secret_dependency_count: $secret_dependency_count,
      stack_kms_key_count: $stack_kms_key_count,
      restored_identity_items: $restored_identity_items,
      restored_grant_items: $restored_grant_items,
      admin_config_items: $admin_config_items,
      restored_configuration_items: $restored_configuration_items,
      admin_transient_items_removed: $admin_transient_items_removed,
      issuers: [$issuer_t1, $issuer_t2]
    },
    verification_hashes: {
      identity_t1_sha256: $identity_t1_sha256,
      identity_t2_sha256: $identity_t2_sha256,
      identity_authority_sha256: $identity_authority_sha256,
      required_configuration_sha256: $required_configuration_sha256,
      grant_authority_sha256: $grant_authority_sha256,
      grant_sha256: $grant_sha256,
      revoked_grant_sha256: $revoked_grant_sha256,
      audit_event_sha256: $audit_event_sha256,
      recovery_point_sha256: $recovery_point_sha256
    },
    checks: {
      backup_plan: "passed",
      on_demand_backup: "passed",
      replay_state_excluded: "passed",
      ssf_rollback_state_excluded: "passed",
      identity_authority: "passed",
      identity_tenant_isolation: "passed",
      credential_metadata: "passed",
      authorization_state: "passed",
      revocation_state: "passed",
      key_references: "passed",
      secret_metadata_only: "passed",
      required_configuration: "passed",
      admin_ephemeral_state_purged: "passed",
      audit_continuity: "passed",
      live_issuer_continuity: "passed",
      restored_issuer_runtime_signing: "passed",
      post_cleanup_source_stability: "passed",
      cleanup_complete: $cleanup_complete
    }
  }' >"$EVIDENCE_FILE.current"
chmod 600 "$EVIDENCE_FILE.current"
mv "$EVIDENCE_FILE.current" "$EVIDENCE_FILE"

info "evidence=$EVIDENCE_FILE"
pass "production backup/restore drill completed"
