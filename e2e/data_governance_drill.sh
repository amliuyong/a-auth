#!/usr/bin/env bash
# Restart-safe live data-governance drill (spec 030 / issue #30).
#
# This is intentionally destructive. It erases one t1 fixture and permanently
# offboards the explicitly disposable t2 tenant. A qualifying run requires:
#
#   AWS_PROFILE=default REGION=us-east-1 \
#   CONFIRM_DISPOSABLE_TENANT=t2 \
#   ./e2e/data_governance_drill.sh
#
# The default run injects one idempotent retry and exits with status 75 after
# queueing user erasure. Resume after a process/host restart with:
#
#   RUN_ID=<printed-run-id> AWS_PROFILE=default REGION=us-east-1 \
#   CONFIRM_DISPOSABLE_TENANT=t2 ./e2e/data_governance_drill.sh
#
# State contains identifiers and evidence only. Bearers and the HMAC key are
# loaded into a 0700 process-local directory, never printed, and deleted on exit.
#
# Other actions:
#   ACTION=status  RUN_ID=<id> ... ./e2e/data_governance_drill.sh
#   ACTION=adopt-deployment RUN_ID=<id> DEPLOYMENT_TRANSITION_REASON=<reason> \
#     ... ./e2e/data_governance_drill.sh
#   ACTION=cleanup RUN_ID=<id> ... ./e2e/data_governance_drill.sh
#
# adopt-deployment is the only way to continue a RUN_ID after both stacks have
# advanced. It requires an ancestry-preserving deployment with unchanged
# resource outputs and writes a separate append-only lineage record.
#
# cleanup uses product APIs only for fixture IDs recorded by this script. It
# never directly deletes cloud resources and cannot reverse tenant offboarding.
set -euo pipefail
set +x

ACTION="${ACTION:-run}"
STACK="${STACK:-AgentAuthSaas}"
STANDBY_STACK="${STANDBY_STACK:-AgentAuthSaasStandby}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
STANDBY_REGION="${STANDBY_REGION:-us-west-2}"
OFFBOARD_TENANT="t2"
CONFIRM_DISPOSABLE_TENANT="${CONFIRM_DISPOSABLE_TENANT:-}"
INJECT_RETRY_INTERRUPTION="${INJECT_RETRY_INTERRUPTION:-1}"
POLL_SECS="${POLL_SECS:-10}"
POLL_TIMEOUT_SECS="${POLL_TIMEOUT_SECS:-1800}"
RUN_ID_INPUT="${RUN_ID:-}"
STATE_ROOT="${STATE_ROOT:-$HOME/.agent-auth-data-governance-drills}"
DEPLOYMENT_TRANSITION_REASON="${DEPLOYMENT_TRANSITION_REASON:-}"
REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

case "$ACTION" in
  run) ;;
  status|adopt-deployment|cleanup)
    [[ -n "$RUN_ID_INPUT" ]] || {
      printf 'FAIL: ACTION=%s requires RUN_ID\n' "$ACTION" >&2
      exit 1
    }
    ;;
  *)
    printf 'FAIL: ACTION must be run, status, adopt-deployment, or cleanup\n' >&2
    exit 1
    ;;
esac

RUN_ID="${RUN_ID_INPUT:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
if [[ ! "$RUN_ID" =~ ^[A-Za-z0-9._-]{1,64}$ ]] ||
  [[ "$RUN_ID" == "." || "$RUN_ID" == ".." ]]; then
  printf 'FAIL: invalid RUN_ID\n' >&2
  exit 1
fi

STATE_DIR="$STATE_ROOT/$RUN_ID"
CONTEXT="$STATE_DIR/context.json"
FIXTURES="$STATE_DIR/fixtures.json"
SSF_FIXTURE="$STATE_DIR/ssf-fixture.json"
RESPONSES="$STATE_DIR/responses"
CLOUD_DIR="$STATE_DIR/cloud"
SERVICE_EVIDENCE_DIR="$STATE_DIR/service-evidence"
FINAL_EVIDENCE="$STATE_DIR/final-evidence.json"
DEPLOYMENT_TRANSITIONS="$STATE_DIR/deployment-transitions.json"
AWSQ=(aws --profile "$PROFILE" --region "$REGION")
STANDBY_AWSQ=(aws --profile "$PROFILE" --region "$STANDBY_REGION")

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}
pass() { printf 'PASS: %s\n' "$*"; }
info() { printf 'INFO: %s\n' "$*"; }
now_epoch() { date -u +%s; }

for command in \
  awk aws bash cmp curl cut date find flock git grep jq mktemp paste \
  python3 sha256sum sleep sort tee wc; do
  command -v "$command" >/dev/null || fail "missing command: $command"
done
[[ "$REGION" == "us-east-1" ]] ||
  fail "qualifying drill requires REGION=us-east-1"
[[ "$STACK" == "AgentAuthSaas" ]] ||
  fail "qualifying drill requires STACK=AgentAuthSaas"
[[ "$STANDBY_STACK" == "AgentAuthSaasStandby" ]] ||
  fail "qualifying drill requires STANDBY_STACK=AgentAuthSaasStandby"
[[ "$STANDBY_REGION" == "us-west-2" ]] ||
  fail "qualifying drill requires STANDBY_REGION=us-west-2"
[[ "$INJECT_RETRY_INTERRUPTION" == "0" ||
  "$INJECT_RETRY_INTERRUPTION" == "1" ]] ||
  fail "INJECT_RETRY_INTERRUPTION must be 0 or 1"
[[ "$POLL_SECS" =~ ^[1-9][0-9]*$ ]] ||
  fail "POLL_SECS must be a positive integer"
[[ "$POLL_TIMEOUT_SECS" =~ ^[1-9][0-9]*$ ]] ||
  fail "POLL_TIMEOUT_SECS must be a positive integer"

umask 077
mkdir -p "$STATE_ROOT"
chmod 700 "$STATE_ROOT"
exec 9>"$STATE_ROOT/.$RUN_ID.lock"
chmod 600 "$STATE_ROOT/.$RUN_ID.lock"
flock -n 9 || fail "another process owns RUN_ID=$RUN_ID"

if [[ "$ACTION" != "run" && ! -s "$CONTEXT" ]]; then
  fail "no persisted context for RUN_ID=$RUN_ID"
fi
mkdir -p "$STATE_DIR" "$RESPONSES" "$CLOUD_DIR" "$SERVICE_EVIDENCE_DIR"
chmod 700 "$STATE_DIR" "$RESPONSES" "$CLOUD_DIR" "$SERVICE_EVIDENCE_DIR"
touch "$STATE_DIR/drill.log"
chmod 600 "$STATE_DIR/drill.log"
exec > >(tee -a "$STATE_DIR/drill.log") 2>&1

WORK="$(mktemp -d)"
chmod 700 "$WORK"
ACTIVE_VISIBILITY_QUEUE=""
ACTIVE_VISIBILITY_HANDLES=""
cleanup_process_files() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n "$ACTIVE_VISIBILITY_QUEUE" &&
    -s "$ACTIVE_VISIBILITY_HANDLES" ]] &&
    declare -F restore_tenant_key_dlq_visibility >/dev/null; then
    if ! restore_tenant_key_dlq_visibility \
      "$ACTIVE_VISIBILITY_QUEUE" "$ACTIVE_VISIBILITY_HANDLES"; then
      printf 'FAIL: tenant-key DLQ visibility restoration failed during process cleanup\n' >&2
      [[ "$status" != "0" ]] || status=1
    fi
  fi
  rm -rf "$WORK"
  exit "$status"
}
trap cleanup_process_files EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

atomic_write() {
  local destination="$1"
  local temporary="$destination.tmp.$$"
  cat >"$temporary"
  chmod 600 "$temporary"
  mv "$temporary" "$destination"
}

mark_done() {
  local marker="$1"
  printf '%s\n' "$(now_epoch)" | atomic_write "$STATE_DIR/$marker.done"
}

is_done() {
  [[ -s "$STATE_DIR/$1.done" ]]
}

context_value() {
  jq -er "$1" "$CONTEXT"
}

hash_file() {
  sha256sum "$1" | awk '{print $1}'
}

stack_outputs_json() {
  jq -cS '
    .Stacks[0].Outputs
    | map({key: .OutputKey, value: .OutputValue})
    | from_entries
  ' "$1"
}

hash_canonical_outputs() {
  sha256sum | awk '{print $1}'
}

active_deployment_commit() {
  if [[ -s "$DEPLOYMENT_TRANSITIONS" ]]; then
    jq -er 'last.to_commit' "$DEPLOYMENT_TRANSITIONS"
  else
    context_value '.deployment_commit'
  fi
}

active_primary_outputs_hash() {
  if [[ -s "$DEPLOYMENT_TRANSITIONS" ]]; then
    jq -er 'last.primary_outputs_sha256' "$DEPLOYMENT_TRANSITIONS"
  else
    context_value '.outputs_sha256'
  fi
}

active_standby_outputs_hash() {
  if [[ -s "$DEPLOYMENT_TRANSITIONS" ]]; then
    jq -er 'last.standby_outputs_sha256' "$DEPLOYMENT_TRANSITIONS"
  else
    context_value '.standby_outputs_sha256'
  fi
}

deployment_transitions_json() {
  if [[ -s "$DEPLOYMENT_TRANSITIONS" ]]; then
    cat "$DEPLOYMENT_TRANSITIONS"
  else
    printf '[]\n'
  fi
}

validate_deployment_transitions() {
  local transitions_file="${1:-$DEPLOYMENT_TRANSITIONS}"
  local expected_commit expected_primary_hash expected_standby_hash
  local sequence from_commit to_commit primary_hash standby_hash
  local expected_sequence=0
  local primary_file="$WORK/transition-primary.json"
  local standby_file="$WORK/transition-standby.json"
  local previous_primary="$WORK/validated-previous-primary.json"
  local previous_standby="$WORK/validated-previous-standby.json"
  local previous_stable="$WORK/validated-previous-stable.json"
  local current_stable="$WORK/validated-current-stable.json"
  local reconstructed="$WORK/reconstructed-legacy-standby.json"
  local validation_scope

  [[ -e "$transitions_file" ]] || return 0
  [[ -s "$transitions_file" ]] ||
    fail "deployment transition record is empty"
  jq -e \
    --arg run_id "$RUN_ID" \
    --arg primary_stack_id "$(context_value '.stack_id')" \
    --arg standby_stack_id "$(context_value '.standby_stack_id')" '
    type == "array" and length > 0 and
    all(.[];
      .schema_version == 1 and
      .run_id == $run_id and
      .primary_stack_id == $primary_stack_id and
      .standby_stack_id == $standby_stack_id and
      (.sequence | type == "number" and . >= 1 and floor == .) and
      (.from_commit | test("^[0-9a-f]{40}$")) and
      (.to_commit | test("^[0-9a-f]{40}$")) and
      (.from_commit != .to_commit) and
      (.previous_primary_outputs_sha256 | test("^[0-9a-f]{64}$")) and
      (.previous_standby_outputs_sha256 | test("^[0-9a-f]{64}$")) and
      (.primary_outputs_sha256 | test("^[0-9a-f]{64}$")) and
      (.standby_outputs_sha256 | test("^[0-9a-f]{64}$")) and
      (.primary_outputs | type == "object") and
      (.standby_outputs | type == "object") and
      (.validation_scope == "full_outputs" or
        .validation_scope == "legacy_schema3_hash_reconstruction") and
      (.reason | type == "string" and length >= 1 and length <= 200) and
      (.recorded_at | type == "number")
    )
  ' "$transitions_file" >/dev/null ||
    fail "deployment transition record is malformed"

  expected_commit="$(context_value '.deployment_commit')"
  expected_primary_hash="$(context_value '.outputs_sha256')"
  expected_standby_hash="$(context_value '.standby_outputs_sha256')"
  jq -cS '.outputs' "$CONTEXT" >"$previous_primary"
  if jq -e '.schema_version == 4' "$CONTEXT" >/dev/null; then
    jq -cS '.standby_outputs' "$CONTEXT" >"$previous_standby"
  else
    rm -f "$previous_standby"
  fi
  while IFS=$'\t' read -r sequence from_commit to_commit primary_hash standby_hash validation_scope; do
    [[ "$sequence" =~ ^[1-9][0-9]*$ ]] ||
      fail "deployment transition sequence is malformed"
    [[ "$sequence" == "$(( expected_sequence + 1 ))" ]] ||
      fail "deployment transition sequence is not contiguous"
    expected_sequence="$sequence"
    [[ "$from_commit" == "$expected_commit" ]] ||
      fail "deployment transition commit chain is broken"
    [[ "$(jq -er --argjson index "$((sequence - 1))" \
      '.[$index].previous_primary_outputs_sha256' "$transitions_file")" == "$expected_primary_hash" ]] ||
      fail "deployment transition primary output hash chain is broken"
    [[ "$(jq -er --argjson index "$((sequence - 1))" \
      '.[$index].previous_standby_outputs_sha256' "$transitions_file")" == "$expected_standby_hash" ]] ||
      fail "deployment transition standby output hash chain is broken"
    jq -cS --argjson index "$((sequence - 1))" \
      '.[$index].primary_outputs' "$transitions_file" >"$primary_file"
    jq -cS --argjson index "$((sequence - 1))" \
      '.[$index].standby_outputs' "$transitions_file" >"$standby_file"
    [[ "$(hash_canonical_outputs <"$primary_file")" == "$primary_hash" ]] ||
      fail "deployment transition primary output snapshot hash is invalid"
    [[ "$(hash_canonical_outputs <"$standby_file")" == "$standby_hash" ]] ||
      fail "deployment transition standby output snapshot hash is invalid"
    jq -e --arg commit "$to_commit" '
      .DeploymentCommit == $commit and
      .RecoveryDeploymentCommit == $commit
    ' "$primary_file" >/dev/null ||
      fail "deployment transition primary commit outputs are invalid"
    jq -e --arg commit "$to_commit" \
      '.DeploymentCommit == $commit' "$standby_file" >/dev/null ||
      fail "deployment transition standby commit output is invalid"
    jq -cS 'del(.DeploymentCommit, .RecoveryDeploymentCommit)' \
      "$previous_primary" >"$previous_stable"
    jq -cS 'del(.DeploymentCommit, .RecoveryDeploymentCommit)' \
      "$primary_file" >"$current_stable"
    cmp -s "$previous_stable" "$current_stable" ||
      fail "deployment transition primary resource outputs are not stable"
    if [[ -s "$previous_standby" ]]; then
      [[ "$validation_scope" == "full_outputs" ]] ||
        fail "deployment transition validation scope is inconsistent"
      jq -cS 'del(.DeploymentCommit)' "$previous_standby" >"$previous_stable"
      jq -cS 'del(.DeploymentCommit)' "$standby_file" >"$current_stable"
      cmp -s "$previous_stable" "$current_stable" ||
        fail "deployment transition standby resource outputs are not stable"
    else
      [[ "$validation_scope" == "legacy_schema3_hash_reconstruction" ]] ||
        fail "legacy deployment transition validation scope is inconsistent"
      jq -cS --arg commit "$from_commit" \
        '.DeploymentCommit = $commit' "$standby_file" >"$reconstructed"
      [[ "$(hash_canonical_outputs <"$reconstructed")" == "$expected_standby_hash" ]] ||
        fail "legacy standby output hash cannot be reconstructed"
    fi
    git -C "$REPO_ROOT" merge-base --is-ancestor "$from_commit" "$to_commit" ||
      fail "deployment transition is not ancestry-preserving"
    jq -cS . "$primary_file" >"$previous_primary"
    jq -cS . "$standby_file" >"$previous_standby"
    expected_commit="$to_commit"
    expected_primary_hash="$primary_hash"
    expected_standby_hash="$standby_hash"
  done < <(
    jq -r '.[] | [
      .sequence,
      .from_commit,
      .to_commit,
      .primary_outputs_sha256,
      .standby_outputs_sha256,
      .validation_scope
    ] | @tsv' "$transitions_file"
  )
}

seven_day_deletion_epoch() {
  local label="$1" value="$2" deletion_epoch created_at current
  deletion_epoch="$(date -u -d "$value" +%s 2>/dev/null)" ||
    fail "$label returned an invalid deletion date"
  created_at="$(context_value '.created_at')"
  current="$(now_epoch)"
  (( deletion_epoch >= created_at + 7 * 24 * 60 * 60 - 600 )) ||
    fail "$label deletion deadline is earlier than the seven-day window"
  (( deletion_epoch <= current + 7 * 24 * 60 * 60 + 600 )) ||
    fail "$label deletion deadline is later than the seven-day window"
  printf '%s\n' "$deletion_epoch"
}

secret_deletion_epoch() {
  local label="$1" arn="$2" region="$3" deleted_date="$4"
  local deleted_epoch created_at current start_time end_time events event
  local event_time deletion_date event_epoch deletion_epoch
  deleted_epoch="$(date -u -d "$deleted_date" +%s 2>/dev/null)" ||
    fail "$label returned an invalid DescribeSecret DeletedDate"
  created_at="$(context_value '.created_at')"
  current="$(now_epoch)"
  (( deleted_epoch >= created_at - 600 && deleted_epoch <= current + 600 )) ||
    fail "$label DescribeSecret DeletedDate is outside the RUN_ID window"

  start_time="$(date -u -d "@$((deleted_epoch - 900))" +%Y-%m-%dT%H:%M:%SZ)"
  end_time="$(date -u -d "@$current" +%Y-%m-%dT%H:%M:%SZ)"
  events="$WORK/secret-cloudtrail-$(printf '%s' "$arn" | sha256sum | awk '{print $1}').json"
  aws --profile "$PROFILE" --region "$region" cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteSecret \
    --start-time "$start_time" --end-time "$end_time" --output json >"$events"
  sleep 1
  event="$(jq -cer --arg arn "$arn" '
    [
      .Events[].CloudTrailEvent
      | fromjson
      | select(
          .eventSource == "secretsmanager.amazonaws.com" and
          .eventName == "DeleteSecret" and
          .requestParameters.secretId == $arn and
          .requestParameters.recoveryWindowInDays == 7 and
          .responseElements.arn == $arn and
          (.responseElements.deletionDate | type == "string") and
          (.errorCode == null)
        )
      | {
          event_time: .eventTime,
          deletion_date: .responseElements.deletionDate
        }
    ]
    | if length == 1 then .[0]
      else error("missing or duplicate exact DeleteSecret event")
      end
  ' "$events")" ||
    fail "$label lacks one exact successful seven-day DeleteSecret event"
  event_time="$(jq -er '.event_time | select(type == "string")' <<<"$event")"
  deletion_date="$(
    jq -er '.deletion_date | select(type == "string")' <<<"$event"
  )"
  event_epoch="$(date -u -d "$event_time" +%s 2>/dev/null)" ||
    fail "$label CloudTrail eventTime is invalid"
  deletion_epoch="$(date -u -d "$deletion_date" +%s 2>/dev/null)" ||
    fail "$label CloudTrail deletionDate is invalid"
  (( event_epoch >= deleted_epoch - 600 &&
    event_epoch <= deleted_epoch + 600 )) ||
    fail "$label DeleteSecret event does not match DescribeSecret DeletedDate"
  (( deletion_epoch >= event_epoch + 7 * 24 * 60 * 60 - 600 &&
    deletion_epoch <= event_epoch + 7 * 24 * 60 * 60 + 600 )) ||
    fail "$label CloudTrail deletion deadline does not match seven days"
  (( deletion_epoch >= created_at + 7 * 24 * 60 * 60 - 600 &&
    deletion_epoch <= current + 7 * 24 * 60 * 60 + 600 )) ||
    fail "$label deletion deadline is outside the RUN_ID seven-day window"
  printf '%s\n' "$deletion_epoch"
}

stack_output_from_file() {
  local stack_file="$1" key="$2"
  jq -er --arg key "$key" '
    .Stacks[0].Outputs
    | map(select(.OutputKey == $key))
    | if length == 1 then .[0].OutputValue
      else error("missing or duplicate stack output: " + $key)
      end
  ' "$stack_file"
}

require_clean_exact_commit() {
  local local_commit="$1" deployed_commit="$2"
  [[ "$local_commit" =~ ^[0-9a-f]{40}$ ]] ||
    fail "local HEAD is not a full lowercase Git commit"
  [[ "$deployed_commit" == "$local_commit" ]] ||
    fail "deployed commit $deployed_commit does not equal local HEAD $local_commit"
  if [[ -n "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=normal)" ]]; then
    fail "qualifying drill requires a clean worktree at the deployed commit"
  fi
}

discover_tenant_kms_keys() {
  local tenant="$1" regions_json="$2" output="$3"
  local region page="$WORK/kms-page.json"
  : >"$output"
  while IFS= read -r region; do
    aws --profile "$PROFILE" --region "$region" \
      resourcegroupstaggingapi get-resources \
      --resource-type-filters kms:key \
      --tag-filters \
      "Key=agent-auth-managed,Values=true" \
      "Key=agent-auth-tenant,Values=$tenant" \
      --output json >"$page"
    jq -r '.ResourceTagMappingList[].ResourceARN' "$page" >>"$output"
  done < <(jq -r '.[]' <<<"$regions_json")
  LC_ALL=C sort -u -o "$output" "$output"
}

initialize_context() {
  local stack_file="$WORK/stack.json"
  local standby_stack_file="$WORK/standby-stack.json"
  local resources_file="$WORK/resources.json"
  local auth_config="$WORK/auth-config.json"
  local outputs_json standby_outputs_json replicated_tables region_local_tables
  local recovery_tables
  local standby_region_local_tables standby_outputs_hash standby_stack_id
  local runtime_secrets residency scim_arns auth_fn local_commit deployed_commit
  local bootstrap_config tenant_secret_dependencies
  local account stack_id stack_status standby_status regions_json kms_file
  local outputs_hash standby_commit standby_region_output standby_imported
  local primary_imported

  "${AWSQ[@]}" sts get-caller-identity --output json >"$WORK/caller.json"
  account="$(jq -er '.Account | select(test("^[0-9]{12}$"))' "$WORK/caller.json")"
  "${AWSQ[@]}" cloudformation describe-stacks \
    --stack-name "$STACK" --output json >"$stack_file"
  stack_status="$(jq -er '.Stacks[0].StackStatus' "$stack_file")"
  [[ "$stack_status" == "CREATE_COMPLETE" ||
    "$stack_status" == "UPDATE_COMPLETE" ]] ||
    fail "$STACK must be CREATE_COMPLETE or UPDATE_COMPLETE, got $stack_status"
  stack_id="$(jq -er '.Stacks[0].StackId' "$stack_file")"
  [[ "$stack_id" == "arn:aws:cloudformation:$REGION:$account:stack/$STACK/"* ]] ||
    fail "stack identity is outside the selected account/Region"

  deployed_commit="$(stack_output_from_file "$stack_file" DeploymentCommit)"
  [[ "$(stack_output_from_file "$stack_file" RecoveryDeploymentCommit)" == "$deployed_commit" ]] ||
    fail "deployment and recovery commit outputs differ"
  local_commit="$(git -C "$REPO_ROOT" rev-parse HEAD)"
  require_clean_exact_commit "$local_commit" "$deployed_commit"

  outputs_json="$(stack_outputs_json "$stack_file")"
  outputs_hash="$(printf '%s\n' "$outputs_json" | hash_canonical_outputs)"
  replicated_tables="$(stack_output_from_file "$stack_file" ReplicatedAuthorityTableNames)"
  region_local_tables="$(stack_output_from_file "$stack_file" RegionLocalTableNames)"
  recovery_tables="$(stack_output_from_file "$stack_file" RecoveryAuthorityTableNames)"
  runtime_secrets="$(stack_output_from_file "$stack_file" ReplicatedRuntimeSecretArns)"
  residency="$(stack_output_from_file "$stack_file" TenantResidency)"
  scim_arns="$(stack_output_from_file "$stack_file" ScimSecretArns)"

  jq -e '
    (keys | sort) == ["t1", "t2"] and
    all(.[]; .governance_region == "us-east-1") and
    (.t1.allowed_regions == .t2.allowed_regions) and
    (.t1.allowed_regions | index("us-east-1") != null)
  ' <<<"$residency" >/dev/null ||
    fail "TenantResidency must contain only t1/t2 with us-east-1 governance"
  regions_json="$(jq -c '.t1.allowed_regions | sort' <<<"$residency")"
  [[ "$regions_json" == '["us-east-1","us-west-2"]' ]] ||
    fail "TenantResidency must configure exactly us-east-1 and us-west-2"
  jq -e '
    (keys | sort) == ["t1", "t2"] and
    all(.[]; test("^arn:aws[^:]*:secretsmanager:us-east-1:[0-9]{12}:secret:"))
  ' <<<"$scim_arns" >/dev/null ||
    fail "ScimSecretArns is not an exact t1/t2 ARN map"
  jq -e '
    (.platform_admin | type == "string") and
    (.governance_hmac | type == "string") and
    (.tenant_admin | keys | sort) == ["t1", "t2"] and
    (.scim | keys | sort) == ["t1", "t2"]
  ' <<<"$runtime_secrets" >/dev/null ||
    fail "ReplicatedRuntimeSecretArns is incomplete"
  [[ "$(jq -cS '.scim' <<<"$runtime_secrets")" == "$(jq -cS . <<<"$scim_arns")" ]] ||
    fail "SCIM output and replicated runtime Secret maps differ"

  "${STANDBY_AWSQ[@]}" cloudformation describe-stacks \
    --stack-name "$STANDBY_STACK" --output json >"$standby_stack_file"
  standby_status="$(jq -er '.Stacks[0].StackStatus' "$standby_stack_file")"
  [[ "$standby_status" == "CREATE_COMPLETE" ||
    "$standby_status" == "UPDATE_COMPLETE" ]] ||
    fail "$STANDBY_STACK must be CREATE_COMPLETE or UPDATE_COMPLETE, got $standby_status"
  standby_stack_id="$(jq -er '.Stacks[0].StackId' "$standby_stack_file")"
  [[ "$standby_stack_id" == "arn:aws:cloudformation:$STANDBY_REGION:$account:stack/$STANDBY_STACK/"* ]] ||
    fail "standby stack identity is outside the selected account/Region"
  standby_commit="$(stack_output_from_file "$standby_stack_file" DeploymentCommit)"
  [[ "$standby_commit" == "$deployed_commit" ]] ||
    fail "primary and standby deployment commits differ"
  standby_region_output="$(stack_output_from_file "$standby_stack_file" RegionId)"
  [[ "$standby_region_output" == "$STANDBY_REGION" ]] ||
    fail "standby Region output differs from $STANDBY_REGION"
  standby_imported="$(stack_output_from_file "$standby_stack_file" \
    ImportedAuthorityTableNames)"
  standby_imported="$(jq -cS . <<<"$standby_imported")"
  primary_imported="$(jq -cS . <<<"$replicated_tables")"
  [[ "$standby_imported" == "$primary_imported" ]] ||
    fail "standby imported authority tables differ from primary outputs"
  standby_region_local_tables="$(
    stack_output_from_file "$standby_stack_file" RegionLocalTableNames
  )"
  jq -e '
    (keys | sort) == ([
      "adminAuthRuntime","authzSessions","ciba","clientAuthorityRefs","codes",
      "device","federationFlow","grace","initialAccessTokens","invitations",
      "jti","magicLinks","messages","par","passkeyChallenges","rateLimit",
      "recovery","refresh","sessions","ssfDeliveries"
    ] | sort) and
    all(.[]; type == "string" and test("^[A-Za-z0-9_.-]{3,255}$")) and
    ([.[]] | unique | length) == 20
  ' <<<"$standby_region_local_tables" >/dev/null ||
    fail "standby Region-local table output is malformed"
  standby_outputs_json="$(stack_outputs_json "$standby_stack_file")"
  standby_outputs_hash="$(
    printf '%s\n' "$standby_outputs_json" | hash_canonical_outputs
  )"

  "${AWSQ[@]}" cloudformation list-stack-resources \
    --stack-name "$STACK" --output json >"$resources_file"
  auth_fn="$(
    jq -er '
      [
        .StackResourceSummaries[]
        | select(
            .ResourceType == "AWS::Lambda::Function" and
            (.LogicalResourceId | startswith("AuthFn"))
          )
        | .PhysicalResourceId
      ]
      | unique
      | if length == 1 then .[0] else error("expected exactly one AuthFn") end
    ' "$resources_file"
  )"
  "${AWSQ[@]}" lambda get-function-configuration \
    --function-name "$auth_fn" \
    --query 'Environment.Variables.{form:AGENT_AUTH_FORM,zone:AGENT_AUTH_ZONE,control_host:AGENT_AUTH_CONTROL_HOST,bootstrap:AGENT_AUTH_BOOTSTRAP_CONFIG_SECRET_ARN}' \
    --output json >"$auth_config"
  bootstrap_config="$WORK/runtime-bootstrap.json"
  "${AWSQ[@]}" secretsmanager get-secret-value \
    --secret-id "$(jq -er '.bootstrap' "$auth_config")" \
    --query SecretString --output text >"$bootstrap_config"
  jq -e \
    --argjson expected_residency "$residency" \
    --argjson expected_admin "$(jq -c '.tenant_admin' <<<"$runtime_secrets")" \
    --argjson expected_scim "$(jq -c '.scim' <<<"$runtime_secrets")" \
    --arg expected_account "$account" \
    --arg expected_region "$REGION" '
      .tenant_secret_dependencies as $dependencies |
      .schema_version == 1 and
      .saas_tenants == ["t1", "t2"] and
      .tenant_admin_secret_arns == $expected_admin and
      .tenant_residency == $expected_residency and
      ($dependencies | keys | sort) == ["t1", "t2"] and
      (["t1", "t2"] | all(.[];
        . as $tenant |
          ($dependencies[$tenant] | length) == 4 and
          ([$dependencies[$tenant][].purpose] | sort) == [
            "scim",
            "scim_legacy_source",
            "tenant_admin",
            "tenant_admin_legacy_source"
          ] and
          any($dependencies[$tenant][];
            .purpose == "tenant_admin" and
            .secret_ref == $expected_admin[$tenant]) and
          any($dependencies[$tenant][];
            .purpose == "scim" and
            .secret_ref == $expected_scim[$tenant]) and
          all($dependencies[$tenant][];
            .resource_account == $expected_account and
            .resource_region == $expected_region and
            (.secret_ref | startswith(
              "arn:aws:secretsmanager:" + $expected_region + ":" +
              $expected_account + ":secret:"
            )) and
            (if .purpose == "tenant_admin_legacy_source"
             then .ownership == "external" and .ownership_revision == 0
             else .ownership == "product_managed" and .ownership_revision == 1
             end)
          )
      ))
    ' "$bootstrap_config" >/dev/null ||
    fail "deployed AuthFn bootstrap tenant/credential/residency/ownership configuration is inconsistent"
  tenant_secret_dependencies="$(
    jq -cS '.tenant_secret_dependencies' "$bootstrap_config"
  )"
  jq -e '
      .form == "saas" and
      (.zone | type == "string" and test("^[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)+$")) and
      (.control_host == ("c." + .zone))
    ' "$auth_config" >/dev/null ||
    fail "deployed AuthFn SaaS host configuration is inconsistent"

  kms_file="$WORK/t2-kms-keys"
  discover_tenant_kms_keys "$OFFBOARD_TENANT" "$regions_json" "$kms_file"
  [[ "$(wc -l <"$kms_file")" -ge 2 ]] ||
    fail "could not discover both managed t2 signing key algorithms"

  jq -n \
    --arg schema_version "4" \
    --arg run_id "$RUN_ID" \
    --arg stack "$STACK" \
    --arg stack_id "$stack_id" \
    --arg region "$REGION" \
    --arg standby_stack "$STANDBY_STACK" \
    --arg standby_stack_id "$standby_stack_id" \
    --arg standby_region "$STANDBY_REGION" \
    --arg account_id "$account" \
    --arg deployment_commit "$deployed_commit" \
    --arg outputs_sha256 "$outputs_hash" \
    --arg standby_outputs_sha256 "$standby_outputs_hash" \
    --arg auth_fn "$auth_fn" \
    --arg zone "$(jq -er '.zone' "$auth_config")" \
    --arg control_host "$(jq -er '.control_host' "$auth_config")" \
    --argjson outputs "$outputs_json" \
    --argjson standby_outputs "$standby_outputs_json" \
    --argjson residency "$residency" \
    --argjson regions "$regions_json" \
    --argjson replicated_tables "$replicated_tables" \
    --argjson region_local_tables "$region_local_tables" \
    --argjson standby_region_local_tables "$standby_region_local_tables" \
    --argjson recovery_tables "$recovery_tables" \
    --argjson runtime_secrets "$runtime_secrets" \
    --argjson scim_arns "$scim_arns" \
    --argjson tenant_secret_dependencies "$tenant_secret_dependencies" \
    --rawfile t2_kms_keys "$kms_file" '
      {
        schema_version: ($schema_version | tonumber),
        run_id: $run_id,
        stack: $stack,
        stack_id: $stack_id,
        region: $region,
        standby_stack: $standby_stack,
        standby_stack_id: $standby_stack_id,
        standby_region: $standby_region,
        account_id: $account_id,
        deployment_commit: $deployment_commit,
        outputs_sha256: $outputs_sha256,
        standby_outputs_sha256: $standby_outputs_sha256,
        auth_fn: $auth_fn,
        zone: $zone,
        control_host: $control_host,
        tenants: ["t1", "t2"],
        erasure_tenant: "t1",
        offboard_tenant: "t2",
        outputs: $outputs,
        standby_outputs: $standby_outputs,
        residency: $residency,
        configured_regions: $regions,
        replicated_tables: $replicated_tables,
        region_local_tables: $region_local_tables,
        standby_region_local_tables: $standby_region_local_tables,
        recovery_tables: $recovery_tables,
        runtime_secret_arns: $runtime_secrets,
        scim_secret_arns: $scim_arns,
        tenant_secret_dependencies: $tenant_secret_dependencies,
        t2_kms_key_arns: (
          $t2_kms_keys
          | split("\n")
          | map(select(length > 0))
          | sort
        ),
        created_at: now | floor
      }
    ' | atomic_write "$CONTEXT"
  pass "bound RUN_ID=$RUN_ID to deployed commit $deployed_commit"
}

record_deployment_transition() {
  local stack_file="$1" standby_stack_file="$2"
  local previous_primary="$WORK/previous-primary-outputs.json"
  local previous_standby="$WORK/previous-standby-outputs.json"
  local current_primary="$WORK/current-primary-outputs.json"
  local current_standby="$WORK/current-standby-outputs.json"
  local previous_stable="$WORK/previous-stable-outputs.json"
  local current_stable="$WORK/current-stable-outputs.json"
  local transition="$WORK/deployment-transition.json"
  local current_transitions="$WORK/deployment-transitions.json"
  local candidate_transitions="$WORK/candidate-deployment-transitions.json"
  local from_commit to_commit standby_commit local_commit validation_scope
  local previous_primary_hash previous_standby_hash primary_hash standby_hash
  local sequence

  [[ -n "$DEPLOYMENT_TRANSITION_REASON" &&
    ${#DEPLOYMENT_TRANSITION_REASON} -le 200 &&
    "$DEPLOYMENT_TRANSITION_REASON" != *$'\n'* &&
    "$DEPLOYMENT_TRANSITION_REASON" != *$'\r'* ]] ||
    fail "ACTION=adopt-deployment requires a single-line DEPLOYMENT_TRANSITION_REASON (1-200 characters)"

  from_commit="$(active_deployment_commit)"
  to_commit="$(stack_output_from_file "$stack_file" DeploymentCommit)"
  standby_commit="$(stack_output_from_file "$standby_stack_file" DeploymentCommit)"
  [[ "$(stack_output_from_file "$stack_file" RecoveryDeploymentCommit)" == "$to_commit" ]] ||
    fail "deployment and recovery commit outputs differ"
  [[ "$standby_commit" == "$to_commit" ]] ||
    fail "primary and standby deployment commits differ"
  [[ "$from_commit" != "$to_commit" ]] ||
    fail "ACTION=adopt-deployment requires a new deployment commit"
  git -C "$REPO_ROOT" merge-base --is-ancestor "$from_commit" "$to_commit" ||
    fail "new deployment commit is not a descendant of the active RUN_ID commit"
  local_commit="$(git -C "$REPO_ROOT" rev-parse HEAD)"
  require_clean_exact_commit "$local_commit" "$to_commit"

  if [[ -s "$DEPLOYMENT_TRANSITIONS" ]]; then
    jq -cS 'last.primary_outputs' "$DEPLOYMENT_TRANSITIONS" >"$previous_primary"
    jq -cS 'last.standby_outputs' "$DEPLOYMENT_TRANSITIONS" >"$previous_standby"
    validation_scope="full_outputs"
  else
    jq -cS '.outputs' "$CONTEXT" >"$previous_primary"
    if jq -e '.schema_version == 4' "$CONTEXT" >/dev/null; then
      jq -cS '.standby_outputs' "$CONTEXT" >"$previous_standby"
      validation_scope="full_outputs"
    else
      validation_scope="legacy_schema3_hash_reconstruction"
    fi
  fi
  stack_outputs_json "$stack_file" >"$current_primary"
  stack_outputs_json "$standby_stack_file" >"$current_standby"

  jq -cS 'del(.DeploymentCommit, .RecoveryDeploymentCommit)' \
    "$previous_primary" >"$previous_stable"
  jq -cS 'del(.DeploymentCommit, .RecoveryDeploymentCommit)' \
    "$current_primary" >"$current_stable"
  cmp -s "$previous_stable" "$current_stable" ||
    fail "primary stack resource outputs changed; refusing deployment transition"

  if [[ "$validation_scope" == "full_outputs" ]]; then
    jq -cS 'del(.DeploymentCommit)' "$previous_standby" >"$previous_stable"
    jq -cS 'del(.DeploymentCommit)' "$current_standby" >"$current_stable"
    cmp -s "$previous_stable" "$current_stable" ||
      fail "standby stack resource outputs changed; refusing deployment transition"
  else
    jq -cS --arg commit "$from_commit" \
      '.DeploymentCommit = $commit' "$current_standby" >"$previous_stable"
    [[ "$(hash_canonical_outputs <"$previous_stable")" == "$(active_standby_outputs_hash)" ]] ||
      fail "legacy standby output hash cannot be reconstructed"
    jq -e \
      --arg region "$STANDBY_REGION" \
      --argjson imported "$(context_value '.replicated_tables')" \
      --argjson region_local "$(context_value '.standby_region_local_tables')" '
        .RegionId == $region and
        (.ImportedAuthorityTableNames | fromjson) == $imported and
        (.RegionLocalTableNames | fromjson) == $region_local
      ' "$current_standby" >/dev/null ||
      fail "legacy standby identity outputs changed; refusing deployment transition"
  fi

  previous_primary_hash="$(active_primary_outputs_hash)"
  previous_standby_hash="$(active_standby_outputs_hash)"
  primary_hash="$(hash_canonical_outputs <"$current_primary")"
  standby_hash="$(hash_canonical_outputs <"$current_standby")"
  sequence="$(
    if [[ -s "$DEPLOYMENT_TRANSITIONS" ]]; then
      jq -er 'length + 1' "$DEPLOYMENT_TRANSITIONS"
    else
      printf '1\n'
    fi
  )"
  jq -n \
    --arg run_id "$RUN_ID" \
    --arg primary_stack_id "$(context_value '.stack_id')" \
    --arg standby_stack_id "$(context_value '.standby_stack_id')" \
    --argjson sequence "$sequence" \
    --arg from_commit "$from_commit" \
    --arg to_commit "$to_commit" \
    --arg previous_primary_outputs_sha256 "$previous_primary_hash" \
    --arg previous_standby_outputs_sha256 "$previous_standby_hash" \
    --arg primary_outputs_sha256 "$primary_hash" \
    --arg standby_outputs_sha256 "$standby_hash" \
    --arg validation_scope "$validation_scope" \
    --arg reason "$DEPLOYMENT_TRANSITION_REASON" \
    --argjson recorded_at "$(now_epoch)" \
    --slurpfile primary "$current_primary" \
    --slurpfile standby "$current_standby" '{
      schema_version: 1,
      run_id: $run_id,
      primary_stack_id: $primary_stack_id,
      standby_stack_id: $standby_stack_id,
      sequence: $sequence,
      from_commit: $from_commit,
      to_commit: $to_commit,
      previous_primary_outputs_sha256: $previous_primary_outputs_sha256,
      previous_standby_outputs_sha256: $previous_standby_outputs_sha256,
      primary_outputs_sha256: $primary_outputs_sha256,
      standby_outputs_sha256: $standby_outputs_sha256,
      primary_outputs: $primary[0],
      standby_outputs: $standby[0],
      validation_scope: $validation_scope,
      reason: $reason,
      recorded_at: $recorded_at
    }' >"$transition"
  deployment_transitions_json >"$current_transitions"
  jq --argjson transition "$(cat "$transition")" \
    '. + [$transition]' "$current_transitions" >"$candidate_transitions"
  validate_deployment_transitions "$candidate_transitions"
  atomic_write "$DEPLOYMENT_TRANSITIONS" <"$candidate_transitions"
  pass "adopted ancestry-preserving deployment $from_commit -> $to_commit"
}

validate_context() {
  local caller account local_commit stack_file="$WORK/current-stack.json"
  local standby_stack_file="$WORK/current-standby-stack.json"
  local current_hash standby_current_hash stack_id standby_stack_id
  local deployed_commit recovery_commit standby_commit active_commit
  local stack_status standby_status context_outputs="$WORK/context-outputs.json"
  local context_standby_outputs="$WORK/context-standby-outputs.json"
  jq -e \
    --arg run "$RUN_ID" \
    --arg stack "$STACK" \
    --arg region "$REGION" \
    --arg standby_stack "$STANDBY_STACK" \
    --arg standby_region "$STANDBY_REGION" '
      (.schema_version == 3 or .schema_version == 4) and
      .run_id == $run and
      .stack == $stack and
      .region == $region and
      .standby_stack == $standby_stack and
      .standby_region == $standby_region and
      .tenants == ["t1", "t2"] and
      .erasure_tenant == "t1" and
      .offboard_tenant == "t2" and
      (.tenant_secret_dependencies | keys | sort) == ["t1", "t2"] and
      all(.tenant_secret_dependencies[];
        length == 4 and
        all(.[];
          (.purpose | type == "string" and length > 0) and
          (.secret_ref | type == "string" and
            startswith("arn:aws:secretsmanager:")) and
          (.ownership == "product_managed" or .ownership == "external")
        )
      ) and
      (.outputs | type == "object") and
      (.outputs_sha256 | test("^[0-9a-f]{64}$")) and
      (.standby_outputs_sha256 | test("^[0-9a-f]{64}$")) and
      (if .schema_version == 4
       then (.standby_outputs | type == "object")
       else (has("standby_outputs") | not)
       end) and
      (.deployment_commit | test("^[0-9a-f]{40}$"))
    ' "$CONTEXT" >/dev/null ||
    fail "persisted context is malformed"

  jq -cS '.outputs' "$CONTEXT" >"$context_outputs"
  [[ "$(hash_canonical_outputs <"$context_outputs")" == "$(context_value '.outputs_sha256')" ]] ||
    fail "persisted primary output snapshot hash is invalid"
  if jq -e '.schema_version == 4' "$CONTEXT" >/dev/null; then
    jq -cS '.standby_outputs' "$CONTEXT" >"$context_standby_outputs"
    [[ "$(hash_canonical_outputs <"$context_standby_outputs")" == "$(context_value '.standby_outputs_sha256')" ]] ||
      fail "persisted standby output snapshot hash is invalid"
  fi
  validate_deployment_transitions

  caller="$("${AWSQ[@]}" sts get-caller-identity --output json)"
  account="$(jq -er '.Account' <<<"$caller")"
  [[ "$account" == "$(context_value '.account_id')" ]] ||
    fail "current AWS account differs from persisted context"
  "${AWSQ[@]}" cloudformation describe-stacks \
    --stack-name "$STACK" --output json >"$stack_file"
  stack_status="$(jq -er '.Stacks[0].StackStatus' "$stack_file")"
  [[ "$stack_status" == "CREATE_COMPLETE" ||
    "$stack_status" == "UPDATE_COMPLETE" ]] ||
    fail "$STACK must be CREATE_COMPLETE or UPDATE_COMPLETE, got $stack_status"
  stack_id="$(jq -er '.Stacks[0].StackId' "$stack_file")"
  [[ "$stack_id" == "$(context_value '.stack_id')" ]] ||
    fail "stack identity changed since RUN_ID initialization"
  current_hash="$(stack_outputs_json "$stack_file" | hash_canonical_outputs)"
  "${STANDBY_AWSQ[@]}" cloudformation describe-stacks \
    --stack-name "$STANDBY_STACK" --output json >"$standby_stack_file"
  standby_status="$(jq -er '.Stacks[0].StackStatus' "$standby_stack_file")"
  [[ "$standby_status" == "CREATE_COMPLETE" ||
    "$standby_status" == "UPDATE_COMPLETE" ]] ||
    fail "$STANDBY_STACK must be CREATE_COMPLETE or UPDATE_COMPLETE, got $standby_status"
  standby_stack_id="$(jq -er '.Stacks[0].StackId' "$standby_stack_file")"
  [[ "$standby_stack_id" == "$(context_value '.standby_stack_id')" ]] ||
    fail "standby stack identity changed since RUN_ID initialization"
  standby_current_hash="$(
    stack_outputs_json "$standby_stack_file" | hash_canonical_outputs
  )"
  deployed_commit="$(stack_output_from_file "$stack_file" DeploymentCommit)"
  recovery_commit="$(stack_output_from_file "$stack_file" RecoveryDeploymentCommit)"
  standby_commit="$(stack_output_from_file "$standby_stack_file" DeploymentCommit)"
  [[ "$deployed_commit" == "$recovery_commit" ]] ||
    fail "deployment and recovery commit outputs differ"
  [[ "$deployed_commit" == "$standby_commit" ]] ||
    fail "primary and standby deployment commits differ"
  active_commit="$(active_deployment_commit)"
  if [[ "$current_hash" != "$(active_primary_outputs_hash)" ||
    "$standby_current_hash" != "$(active_standby_outputs_hash)" ||
    "$deployed_commit" != "$active_commit" ]]; then
    if [[ "$ACTION" == "adopt-deployment" ]]; then
      record_deployment_transition "$stack_file" "$standby_stack_file"
      active_commit="$(active_deployment_commit)"
    elif [[ "$current_hash" != "$(active_primary_outputs_hash)" ]]; then
      fail "stack outputs changed since RUN_ID initialization or the last adopted deployment; use ACTION=adopt-deployment"
    else
      fail "standby stack outputs changed since RUN_ID initialization or the last adopted deployment; use ACTION=adopt-deployment"
    fi
  elif [[ "$ACTION" == "adopt-deployment" ]]; then
    fail "ACTION=adopt-deployment found no new deployment"
  fi
  [[ "$current_hash" == "$(active_primary_outputs_hash)" &&
    "$standby_current_hash" == "$(active_standby_outputs_hash)" &&
    "$deployed_commit" == "$active_commit" ]] ||
    fail "adopted deployment does not match current stack outputs"
  local_commit="$(git -C "$REPO_ROOT" rev-parse HEAD)"
  require_clean_exact_commit "$local_commit" "$active_commit"
}

if [[ ! -s "$CONTEXT" ]]; then
  [[ "$ACTION" == "run" ]] || fail "only ACTION=run may initialize state"
  initialize_context
fi
validate_context

issuer() {
  local tenant="$1"
  printf 'https://%s.%s\n' "$tenant" "$(context_value '.zone')"
}

control_url() {
  printf 'https://%s\n' "$(context_value '.control_host')"
}

load_secret_token() {
  local arn="$1" output="$2"
  "${AWSQ[@]}" secretsmanager get-secret-value \
    --secret-id "$arn" --query SecretString --output text |
    jq -er '
      .current.secret
      | select(type == "string" and length >= 16)
    ' >"$output"
  chmod 600 "$output"
  [[ -s "$output" ]] || fail "credential Secret did not contain a current bearer"
}

load_raw_secret() {
  local arn="$1" output="$2"
  "${AWSQ[@]}" secretsmanager get-secret-value \
    --secret-id "$arn" --query SecretString --output text >"$output"
  chmod 600 "$output"
  [[ "$(wc -c <"$output")" -ge 32 ]] ||
    fail "dedicated HMAC Secret is unexpectedly short"
}

admin_token() {
  local owner="$1"
  local output="$WORK/admin-$owner.token" arn
  if [[ ! -s "$output" ]]; then
    if [[ "$owner" == "platform" ]]; then
      arn="$(context_value '.runtime_secret_arns.platform_admin')"
    else
      arn="$(context_value ".runtime_secret_arns.tenant_admin.$owner")"
    fi
    load_secret_token "$arn" "$output"
  fi
  printf '%s\n' "$output"
}

prepare_offboarding_intent() {
  local intent="$STATE_DIR/offboarding-intent.json"
  local key="$WORK/governance-hmac.key" job_id
  if [[ -s "$intent" ]]; then
    jq -e '
      .tenant_id == "t2" and
      .kind == "tenant_offboarding" and
      (.job_id | type == "string" and length == 43)
    ' "$intent" >/dev/null ||
      fail "persisted offboarding intent is malformed"
    return
  fi
  load_raw_secret "$(context_value '.runtime_secret_arns.governance_hmac')" "$key"
  job_id="$(
    python3 - "$key" <<'PY'
import base64
import hashlib
import hmac
import pathlib
import struct
import sys

key = pathlib.Path(sys.argv[1]).read_bytes().rstrip(b"\n")
tenant = b"t2"
target = b"t2"
message = b"".join(
    (
        b"governance-job:v1\0",
        struct.pack(">Q", len(tenant)),
        tenant,
        b"\x02",
        struct.pack(">Q", len(target)),
        target,
        struct.pack(">Q", 1),
    )
)
print(base64.urlsafe_b64encode(hmac.new(key, message, hashlib.sha256).digest()).rstrip(b"=").decode())
PY
  )"
  [[ "$job_id" =~ ^[A-Za-z0-9_-]{43}$ ]] ||
    fail "could not derive the stable t2 offboarding job ID"
  jq -n \
    --arg tenant t2 \
    --arg kind tenant_offboarding \
    --arg job_id "$job_id" '{
      tenant_id: $tenant,
      kind: $kind,
      job_id: $job_id
    }' | atomic_write "$intent"
}

offboarding_job_exists() {
  local job_id="$1" platform body="$WORK/recover-offboarding.json"
  local output="$WORK/recover-offboarding-response.json"
  platform="$(admin_token platform)"
  jq -n '{action:"status"}' >"$body"
  http_request recover-offboarding POST \
    "$(control_url)/admin/control/data-governance/tenants/t2/jobs/$job_id/continuation-tokens" \
    "$platform" governance "$body" "$output"
  case "$HTTP_STATUS" in
    201)
      rm -f "$output"
      return 0
      ;;
    404)
      rm -f "$output"
      return 1
      ;;
    *)
      fail "offboarding recovery probe returned HTTP $HTTP_STATUS"
      ;;
  esac
}

scim_token() {
  local tenant="$1"
  local output="$WORK/scim-$tenant.token" arn
  if [[ ! -s "$output" ]]; then
    arn="$(context_value ".scim_secret_arns.$tenant")"
    load_secret_token "$arn" "$output"
  fi
  printf '%s\n' "$output"
}

http_request() {
  local label="$1" method="$2" url="$3" token_file="$4"
  local mode="$5" body_file="$6" output="$7"
  local headers="$WORK/$label.headers"
  local status_file="$WORK/$label.status"
  local -a args=(
    -sS --proto '=https' --connect-timeout 5 --max-time 45
    -X "$method" -H "@$headers" -o "$output" -w '%{http_code}'
  )
  [[ "$label" =~ ^[A-Za-z0-9._-]+$ ]] || fail "unsafe request label"
  : >"$headers"
  printf 'authorization: Bearer %s\n' "$(<"$token_file")" >>"$headers"
  case "$mode" in
    governance)
      printf 'x-agent-auth-purpose: privacy-request:%s\n' "$RUN_ID" >>"$headers"
      printf 'x-agent-auth-confirm: true\n' >>"$headers"
      printf 'content-type: application/json\n' >>"$headers"
      ;;
    scim)
      printf 'content-type: application/scim+json\n' >>"$headers"
      ;;
    json)
      printf 'content-type: application/json\n' >>"$headers"
      ;;
    bearer) ;;
    *) fail "unknown request mode: $mode" ;;
  esac
  if [[ -n "$body_file" ]]; then
    args+=(--data-binary "@$body_file")
  fi
  args+=("$url")
  curl "${args[@]}" >"$status_file"
  jq -e . "$output" >/dev/null ||
    fail "$label returned non-JSON HTTP $(<"$status_file")"
  HTTP_STATUS="$(<"$status_file")"
}

expect_status() {
  local label="$1" actual="$2"
  shift 2
  local expected
  for expected in "$@"; do
    [[ "$actual" == "$expected" ]] && return 0
  done
  fail "$label expected HTTP $*, got $actual; response retained without printing"
}

assert_no_bearer_in_responses() {
  local token_file response
  while IFS= read -r token_file; do
    [[ -s "$token_file" ]] || continue
    while IFS= read -r response; do
      if python3 - "$token_file" "$response" <<'PY'
import pathlib
import sys
secret = pathlib.Path(sys.argv[1]).read_bytes().strip()
body = pathlib.Path(sys.argv[2]).read_bytes()
raise SystemExit(0 if secret and secret in body else 1)
PY
      then
        fail "a persisted response contains a bearer"
      fi
    done < <(find "$RESPONSES" -type f -name '*.json' -print)
  done < <(find "$WORK" -type f -name '*.token' -print)
}

issue_governance_invitation() {
  local tenant="$1" user_id="$2"
  local label="invitation-$tenant" response="$WORK/invitation-$tenant.json"
  local user_path url token locator
  user_path="$(
    python3 - "$user_id" <<'PY'
import sys
import urllib.parse
print(urllib.parse.quote(sys.argv[1], safe=""))
PY
  )"
  http_request "$label" POST \
    "$(issuer "$tenant")/admin/users/$user_path/invitation" \
    "$(admin_token "$tenant")" json "" "$response"
  expect_status "issue $tenant invitation fixture" "$HTTP_STATUS" 201
  url="$(jq -er '.invitation_url | select(type == "string")' "$response")"
  token="${url##*#token=}"
  [[ "$url" == "$(issuer "$tenant")/invite#token=$token" ]] ||
    fail "$tenant invitation URL is not bound to its issuer fragment"
  [[ "$token" =~ ^([A-Za-z0-9_-]{43})\.([A-Za-z0-9_-]{43})$ ]] ||
    fail "$tenant invitation bearer has an invalid format"
  locator="${BASH_REMATCH[1]}"
  rm -f "$response" "$WORK/$label.headers" "$WORK/$label.status"
  printf '%s\n' "$locator"
}

create_fixtures() {
  local alias external body tenant token response user_id filter list matches
  local invitation_locator
  alias="governance-drill-$RUN_ID@example.invalid"
  external="governance-drill-$RUN_ID"
  body="$WORK/scim-user.json"
  jq -n \
    --arg external "$external" \
    --arg alias "$alias" '{
      schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
      externalId: $external,
      userName: $alias,
      displayName: "Agent Auth governance live drill",
      active: true
    }' >"$body"

  : >"$WORK/fixture-users.tsv"
  : >"$WORK/fixture-invitations.tsv"
  for tenant in t1 t2; do
    token="$(scim_token "$tenant")"
    response="$RESPONSES/scim-create-$tenant.json"
    list="$RESPONSES/scim-list-$tenant.json"
    filter="$(jq -rn \
      --arg filter "externalId eq \"$external\"" \
      '$filter | @uri')"
    http_request "scim-list-$tenant" GET \
      "$(issuer "$tenant")/scim/v2/Users?filter=$filter&count=2" \
      "$token" scim "" "$list"
    expect_status "SCIM recovery lookup $tenant" "$HTTP_STATUS" 200
    matches="$(
      jq -er --arg external "$external" '
        [.Resources[]? | select(.externalId == $external)] | length
      ' "$list"
    )"
    [[ "$matches" -le 1 ]] ||
      fail "$tenant has multiple fixtures for RUN_ID=$RUN_ID"
    if [[ "$matches" == "1" ]]; then
      jq --arg external "$external" '
        .Resources[]
        | select(.externalId == $external)
      ' "$list" | atomic_write "$response"
    else
      http_request "scim-create-$tenant" POST \
        "$(issuer "$tenant")/scim/v2/Users" \
        "$token" scim "$body" "$response"
      expect_status "SCIM create $tenant" "$HTTP_STATUS" 200 201
    fi
    user_id="$(jq -er '
      select(.active == true)
      | .id
      | select(type == "string" and length > 0)
    ' "$response")"
    printf '%s\t%s\n' "$tenant" "$user_id" >>"$WORK/fixture-users.tsv"
    invitation_locator="$(issue_governance_invitation "$tenant" "$user_id")"
    printf '%s\t%s\n' \
      "$tenant" "$invitation_locator" >>"$WORK/fixture-invitations.tsv"
  done
  [[ "$(cut -f2 "$WORK/fixture-users.tsv" | sort -u | wc -l)" -eq 2 ]] ||
    fail "tenant fixtures unexpectedly share a canonical user ID"
  jq -n \
    --arg alias "$alias" \
    --arg external_id "$external" \
    --arg t1_user "$(awk -F '\t' '$1 == "t1" {print $2}' "$WORK/fixture-users.tsv")" \
    --arg t2_user "$(awk -F '\t' '$1 == "t2" {print $2}' "$WORK/fixture-users.tsv")" \
    --arg t1_invitation "$(awk -F '\t' '$1 == "t1" {print $2}' "$WORK/fixture-invitations.tsv")" \
    --arg t2_invitation "$(awk -F '\t' '$1 == "t2" {print $2}' "$WORK/fixture-invitations.tsv")" '
      {
        alias: $alias,
        external_id: $external_id,
        users: {t1: $t1_user, t2: $t2_user},
        invitation_locators: {
          t1: $t1_invitation,
          t2: $t2_invitation
        }
      }
    ' | atomic_write "$FIXTURES"
  mark_done fixtures
  pass "created isolated t1/t2 users and locator-only invitation fixtures"
}

create_tenant_export() {
  local tenant="$1" token="$2" fixture_id="$3"
  local manifest="$RESPONSES/tenant-export-manifest-$tenant.json"
  local body="$WORK/export-$tenant.json"
  local page export_id cursor="" next_cursor encoded_cursor url
  local page_number=1 found=false
  jq -n '{
    purpose: "privacy-request:live-drill",
    sections: ["users", "security_events"]
  }' >"$body"
  http_request "tenant-export-$tenant" POST \
    "$(issuer "$tenant")/admin/data-governance/exports" \
    "$token" governance "$body" "$manifest"
  expect_status "tenant export manifest $tenant" "$HTTP_STATUS" 201
  export_id="$(jq -er --arg tenant "$tenant" '
    select(.tenant_id == $tenant)
    | .export_id
    | select(type == "string" and length > 0)
  ' "$manifest")"
  while (( page_number <= 100 )); do
    page="$RESPONSES/tenant-export-users-$tenant.json"
    (( page_number == 1 )) ||
      page="$RESPONSES/tenant-export-users-$tenant-page-$page_number.json"
    url="$(issuer "$tenant")/admin/data-governance/exports/$export_id?section=users&limit=500"
    if [[ -n "$cursor" ]]; then
      encoded_cursor="$(jq -rn --arg cursor "$cursor" '$cursor | @uri')"
      url="$url&cursor=$encoded_cursor"
    fi
    http_request "tenant-export-users-$tenant-page-$page_number" GET \
      "$url" "$token" governance "" "$page"
    expect_status "tenant users export $tenant page $page_number" "$HTTP_STATUS" 200
    jq -e --arg tenant "$tenant" '
      .tenant_id == $tenant and
      .section == "users" and
      (.records | type == "array")
    ' "$page" >/dev/null ||
      fail "$tenant users export page $page_number is malformed"
    if jq -e --arg user "$fixture_id" \
      'any(.records[]; .user_id == $user)' "$page" >/dev/null; then
      found=true
      break
    fi
    next_cursor="$(jq -r '.next_cursor // empty' "$page")"
    [[ -n "$next_cursor" ]] || break
    [[ "$next_cursor" != "$cursor" ]] ||
      fail "$tenant users export repeated its continuation cursor"
    cursor="$next_cursor"
    page_number=$(( page_number + 1 ))
  done
  [[ "$found" == "true" ]] ||
    fail "$tenant users export omitted its fixture"
}

validate_exports_and_isolation() {
  local t1_token t2_token t1_user t2_user tenant token user response
  t1_token="$(admin_token t1)"
  t2_token="$(admin_token t2)"
  t1_user="$(jq -er '.users.t1' "$FIXTURES")"
  t2_user="$(jq -er '.users.t2' "$FIXTURES")"

  for tenant in t1 t2; do
    token="$t1_token"
    user="$t1_user"
    [[ "$tenant" == "t2" ]] && token="$t2_token" && user="$t2_user"
    response="$RESPONSES/user-export-$tenant.json"
    http_request "user-export-$tenant" GET \
      "$(issuer "$tenant")/admin/data-governance/users/$user/export?event_limit=2" \
      "$token" governance "" "$response"
    expect_status "user export $tenant" "$HTTP_STATUS" 200
    jq -e --arg tenant "$tenant" --arg user "$user" '
      .tenant_id == $tenant and
      .identity.user_id == $user and
      (.credentials | type == "object") and
      (.security_events | type == "array")
    ' "$response" >/dev/null ||
      fail "$tenant user export is not tenant-scoped"
    create_tenant_export "$tenant" "$token" "$user"
  done

  http_request cross-path GET \
    "$(issuer t1)/admin/data-governance/users/$t2_user/export" \
    "$t1_token" governance "" "$RESPONSES/cross-path.json"
  expect_status "t1 path to t2 fixture" "$HTTP_STATUS" 404
  http_request cross-host GET \
    "$(issuer t2)/admin/data-governance/users/$t2_user/export" \
    "$t1_token" governance "" "$RESPONSES/cross-host.json"
  expect_status "t1 bearer on t2 host" "$HTTP_STATUS" 401
  assert_no_bearer_in_responses
  mark_done exports
  pass "tenant exports succeeded and cross-tenant paths were rejected"
}

read_policy() {
  local tenant="$1" token="$2" output="$3"
  http_request "policy-get-$tenant" GET \
    "$(issuer "$tenant")/admin/data-governance/policy" \
    "$token" governance "" "$output"
  expect_status "read $tenant governance policy" "$HTTP_STATUS" 200
  jq -e '
    .retention_exception_capability == "external_operator_managed"
  ' "$output" >/dev/null ||
    fail "$tenant governance policy has an unsupported retention exception capability"
}

put_hold() {
  local tenant="$1" token="$2" enabled="$3" expected_revision="$4"
  local output="$5" body="$WORK/hold-$tenant.json"
  jq -n \
    --argjson revision "$expected_revision" \
    --argjson enabled "$enabled" \
    --arg reason "live-drill-$RUN_ID" '
      {
        expected_revision: $revision,
        legal_hold: $enabled,
        reason: (if $enabled then $reason else null end)
      }
    ' >"$body"
  http_request "policy-put-$tenant-$enabled" PUT \
    "$(issuer "$tenant")/admin/data-governance/policy" \
    "$token" governance "$body" "$output"
  expect_status "update $tenant legal hold" "$HTTP_STATUS" 200
}

exercise_legal_hold_and_start_erasure() {
  local token user policy="$RESPONSES/t1-policy-before.json"
  local held="$RESPONSES/t1-policy-held.json"
  local blocked="$RESPONSES/t1-erasure-blocked.json"
  local released="$RESPONSES/t1-policy-released.json"
  local started="$RESPONSES/t1-erasure-started.json"
  local retry="$RESPONSES/t1-erasure-retry.json"
  local revision job_id
  token="$(admin_token t1)"
  user="$(jq -er '.users.t1' "$FIXTURES")"

  if ! is_done hold-released; then
    if is_done hold-owned &&
      jq -e '.legal_hold == "disabled"' "$released" >/dev/null 2>&1; then
      mark_done hold-released
    else
      read_policy t1 "$token" "$policy"
      if [[ "$(jq -er '.legal_hold' "$policy")" == "disabled" ]]; then
        revision="$(jq -er '.revision' "$policy")"
        put_hold t1 "$token" true "$revision" "$held"
      else
        jq -e --arg reason "live-drill-$RUN_ID" '
          (.legal_hold == "enabled" or .legal_hold == "enabling") and
          .legal_hold_reason == $reason
        ' "$policy" >/dev/null ||
          fail "t1 has a legal hold not owned by RUN_ID=$RUN_ID"
        cp "$policy" "$held"
      fi
      mark_done hold-owned

      http_request t1-erasure-blocked POST \
        "$(issuer t1)/admin/data-governance/users/$user/erasure" \
        "$token" governance "" "$blocked"
      expect_status "erasure under legal hold" "$HTTP_STATUS" 409
      jq -e '.state == "blocked_legal_hold"' "$blocked" >/dev/null ||
        fail "legal hold did not return a durable blocked job"

      revision="$(jq -er '.revision' "$held")"
      put_hold t1 "$token" false "$revision" "$released"
      jq -e '.legal_hold == "disabled"' "$released" >/dev/null ||
        fail "t1 legal hold did not settle disabled"
      mark_done hold-released
    fi
  fi

  job_id="$(jq -er '.job_id' "$blocked")"

  if ! jq -e --arg job "$job_id" '.job_id == $job' \
    "$started" >/dev/null 2>&1; then
    http_request t1-erasure-started POST \
      "$(issuer t1)/admin/data-governance/users/$user/erasure" \
      "$token" governance "" "$started"
    expect_status "start t1 erasure" "$HTTP_STATUS" 202
  fi
  jq -e --arg job "$job_id" '
    .job_id == $job and
    (.state == "queued" or .state == "running" or .state == "retryable")
  ' "$started" >/dev/null ||
    fail "released legal-hold job did not resume"
  if ! jq -e \
    --arg job "$job_id" \
    --argjson revision "$(jq -er '.revision' "$started")" '
      .job_id == $job and .revision == $revision
    ' "$retry" >/dev/null 2>&1; then
    http_request t1-erasure-retry POST \
      "$(issuer t1)/admin/data-governance/users/$user/erasure" \
      "$token" governance "" "$retry"
    expect_status "idempotent t1 erasure retry" "$HTTP_STATUS" 202
  fi
  jq -e \
    --arg job "$job_id" \
    --argjson revision "$(jq -er '.revision' "$started")" '
      .job_id == $job and .revision == $revision
    ' "$retry" >/dev/null ||
    fail "duplicate erasure request did not return the same durable revision"
  jq -n \
    --arg tenant t1 \
    --arg job_id "$job_id" \
    --arg user_id "$user" \
    --argjson revision "$(jq -er '.revision' "$started")" '
      {
        tenant_id: $tenant,
        job_id: $job_id,
        user_id: $user_id,
        queued_revision: $revision
      }
    ' | atomic_write "$STATE_DIR/user-erasure-job.json"
  mark_done user-erasure-started
  pass "legal hold blocked one durable job; release queued an idempotent retry"
}

ensure_wait_deadline() {
  local name="$1"
  local file="$STATE_DIR/$name.deadline"
  if [[ ! -s "$file" ]]; then
    printf '%s\n' "$(( $(now_epoch) + POLL_TIMEOUT_SECS ))" | atomic_write "$file"
  fi
  cat "$file"
}

poll_tenant_job() {
  local tenant="$1" job_id="$2" token="$3" label="$4"
  local deadline output="$RESPONSES/$label-status.json" state user
  user="$(jq -er --arg tenant "$tenant" '.users[$tenant]' "$FIXTURES")"
  deadline="$(ensure_wait_deadline "$label")"
  while :; do
    http_request "$label-status" GET \
      "$(issuer "$tenant")/admin/data-governance/jobs/$job_id" \
      "$token" governance "" "$output"
    expect_status "$label status" "$HTTP_STATUS" 200
    state="$(jq -er '.state' "$output")"
    case "$state" in
      retention_pending|completed)
        return 0
        ;;
      retryable)
        http_request "$label-resume" POST \
          "$(issuer "$tenant")/admin/data-governance/users/$user/erasure" \
          "$token" governance "" "$RESPONSES/$label-resume.json"
        expect_status "$label retry" "$HTTP_STATUS" 202
        ;;
      queued|running) ;;
      blocked_legal_hold)
        fail "$label unexpectedly returned to blocked_legal_hold"
        ;;
      *) fail "$label entered unexpected state $state" ;;
    esac
    (( $(now_epoch) < deadline )) ||
      fail "$label did not reach retention_pending before persisted deadline"
    sleep "$POLL_SECS"
  done
}

issue_continuation_token() {
  local tenant="$1" job_id="$2" action="$3" output="$4"
  local platform body="$WORK/continuation-$action.json"
  platform="$(admin_token platform)"
  jq -n --arg action "$action" '{action: $action}' >"$body"
  http_request "issue-$tenant-$action" POST \
    "$(control_url)/admin/control/data-governance/tenants/$tenant/jobs/$job_id/continuation-tokens" \
    "$platform" governance "$body" "$WORK/issued-$action.json"
  expect_status "issue $action continuation" "$HTTP_STATUS" 201
  jq -er '
    .continuation_token
    | select(type == "string" and length > 32)
  ' "$WORK/issued-$action.json" >"$output"
  chmod 600 "$output"
  rm -f "$WORK/issued-$action.json"
}

control_job_request() {
  local tenant="$1" job_id="$2" action="$3" method="$4" suffix="$5"
  local output="$6" token="$WORK/continuation-$action.token"
  issue_continuation_token "$tenant" "$job_id" "$action" "$token"
  http_request "control-$tenant-$action-$suffix" "$method" \
    "$(control_url)/admin/control/data-governance/tenants/$tenant/jobs/$job_id/$suffix" \
    "$token" bearer "" "$output"
}

poll_offboarding_job() {
  local job_id="$1" deadline state
  local output="$RESPONSES/t2-offboarding-status.json"
  deadline="$(ensure_wait_deadline t2-offboarding)"
  while :; do
    local token="$WORK/continuation-status.token"
    issue_continuation_token t2 "$job_id" status "$token"
    http_request control-t2-status GET \
      "$(control_url)/admin/control/data-governance/tenants/t2/jobs/$job_id" \
      "$token" bearer "" "$output"
    expect_status "t2 control status" "$HTTP_STATUS" 200
    state="$(jq -er '.state' "$output")"
    case "$state" in
      retention_pending|completed)
        return 0
        ;;
      retryable)
        control_job_request t2 "$job_id" resume POST resume \
          "$RESPONSES/t2-offboarding-resume.json"
        expect_status "t2 continuation resume" "$HTTP_STATUS" 202
        ;;
      queued|running) ;;
      blocked_legal_hold)
        fail "t2 offboarding is blocked by legal hold"
        ;;
      *) fail "t2 offboarding entered unexpected state $state" ;;
    esac
    (( $(now_epoch) < deadline )) ||
      fail "t2 offboarding did not reach retention_pending before persisted deadline"
    sleep "$POLL_SECS"
  done
}

create_ssf_fixture() {
  local token endpoint audience event body list response matches stream
  token="$(admin_token t2)"
  endpoint="https://governance-drill-$RUN_ID.example.invalid/ssf"
  audience="governance-drill-$RUN_ID"
  event="https://schemas.openid.net/secevent/caep/event-type/session-revoked"
  body="$WORK/t2-ssf-stream.json"
  list="$RESPONSES/t2-ssf-stream-list.json"
  response="$RESPONSES/t2-ssf-stream-create.json"
  jq -n \
    --arg endpoint "$endpoint" \
    --arg audience "$audience" \
    --arg event "$event" \
    '{endpoint:$endpoint,audience:$audience,event_types:[$event]}' >"$body"

  http_request t2-ssf-stream-list GET \
    "$(issuer t2)/admin/ssf/streams" \
    "$token" json "" "$list"
  expect_status "list t2 SSF streams" "$HTTP_STATUS" 200
  matches="$(
    jq -er \
      --arg endpoint "$endpoint" \
      --arg audience "$audience" \
      --arg event "$event" '
        [
          .streams[]
          | select(
              .tenant_id == "t2" and
              .endpoint == $endpoint and
              .audience == $audience and
              (.requested_events | index($event) != null)
            )
        ]
        | length
      ' "$list"
  )"
  [[ "$matches" -le 1 ]] ||
    fail "multiple t2 SSF streams match RUN_ID=$RUN_ID"
  if [[ "$matches" == "1" ]]; then
    jq \
      --arg endpoint "$endpoint" \
      --arg audience "$audience" \
      --arg event "$event" '
        .streams[]
        | select(
            .tenant_id == "t2" and
            .endpoint == $endpoint and
            .audience == $audience and
            (.requested_events | index($event) != null)
          )
      ' "$list" | atomic_write "$response"
  else
    http_request t2-ssf-stream-create POST \
      "$(issuer t2)/admin/ssf/streams" \
      "$token" json "$body" "$response"
    expect_status "create owned t2 SSF stream" "$HTTP_STATUS" 201
  fi
  stream="$(jq -er '
    select(.tenant_id == "t2" and .status == "enabled")
    | .stream_id
    | select(type == "string" and length > 0)
  ' "$response")"
  jq -n \
    --arg tenant t2 \
    --arg stream_id "$stream" \
    --argjson revision "$(jq -er '.revision' "$response")" \
    --arg endpoint_sha256 "$(printf '%s' "$endpoint" | sha256sum | awk '{print $1}')" '{
      tenant_id: $tenant,
      stream_id: $stream_id,
      revision: $revision,
      endpoint_sha256: $endpoint_sha256
    }' | atomic_write "$SSF_FIXTURE"
  mark_done ssf-fixture
  pass "created or recovered the RUN_ID-owned t2 SSF stream"
}

start_offboarding() {
  local token response="$RESPONSES/t2-offboarding-start.json" job_id expected_job
  [[ "$CONFIRM_DISPOSABLE_TENANT" == "$OFFBOARD_TENANT" ]] ||
    fail "set CONFIRM_DISPOSABLE_TENANT=t2 to acknowledge permanent t2 offboarding"
  prepare_offboarding_intent
  expected_job="$(jq -er '.job_id' "$STATE_DIR/offboarding-intent.json")"
  if ! jq -e '
    .tenant_id == "t2" and
    .kind == "tenant_offboarding" and
    (.job_id | type == "string" and length > 0)
  ' "$response" >/dev/null 2>&1; then
    if offboarding_job_exists "$expected_job"; then
      jq -n \
        --arg tenant t2 \
        --arg kind tenant_offboarding \
        --arg job_id "$expected_job" '{
          tenant_id: $tenant,
          kind: $kind,
          job_id: $job_id
        }' | atomic_write "$response"
    else
      token="$(admin_token t2)"
      http_request t2-offboarding-start POST \
        "$(issuer t2)/admin/data-governance/tenant/offboarding" \
        "$token" governance "" "$response"
      expect_status "start disposable t2 offboarding" "$HTTP_STATUS" 202
    fi
  fi
  job_id="$(jq -er '
    select(.tenant_id == "t2" and .kind == "tenant_offboarding")
    | .job_id
  ' "$response")"
  [[ "$job_id" == "$expected_job" ]] ||
    fail "offboarding response does not match the persisted stable job ID"
  jq -n --arg tenant t2 --arg job_id "$job_id" '{
    tenant_id: $tenant,
    job_id: $job_id
  }' | atomic_write "$STATE_DIR/offboarding-job.json"
  mark_done offboarding-started
  pass "permanently froze explicitly confirmed disposable tenant t2"
}

tenant_count() {
  local region="$1" table="$2" tenant="$3"
  local page
  page="$WORK/tenant-count-$(printf '%s' "$region:$table:$tenant" | sha256sum | cut -d' ' -f1).json"
  local start_key='{}' count total=0
  local -a scan
  while true; do
    scan=(aws --profile "$PROFILE" --region "$region" dynamodb scan
      --table-name "$table" --consistent-read --no-paginate --output json)
    [[ "$start_key" == '{}' ]] ||
      scan+=(--exclusive-start-key "$start_key")
    "${scan[@]}" >"$page"
    count="$(jq -er --arg tenant "$tenant" --arg prefix "$tenant"$'\x1f' '
      [
        .Items[]
        | select(any(.. | strings;
            . == $tenant or startswith($prefix) or
            contains("\"tenant\":\"" + $tenant + "\"") or
            contains("\"tenant_id\":\"" + $tenant + "\"")
          ))
      ] | length
    ' "$page")"
    total=$(( total + count ))
    start_key="$(jq -c '.LastEvaluatedKey // {}' "$page")"
    [[ "$start_key" == '{}' ]] && break
  done
  printf '%s\n' "$total"
}

target_count() {
  local region="$1" table="$2" target="$3"
  local page
  page="$WORK/target-count-$(printf '%s' "$region:$table:$target" | sha256sum | cut -d' ' -f1).json"
  local start_key='{}' count total=0
  local -a scan
  while true; do
    scan=(aws --profile "$PROFILE" --region "$region" dynamodb scan
      --table-name "$table" --consistent-read --no-paginate --output json)
    [[ "$start_key" == '{}' ]] ||
      scan+=(--exclusive-start-key "$start_key")
    "${scan[@]}" >"$page"
    count="$(jq -er --arg target "$target" '
      [
        .Items[]
        | select(any(.. | strings; contains($target)))
      ] | length
    ' "$page")"
    total=$(( total + count ))
    start_key="$(jq -c '.LastEvaluatedKey // {}' "$page")"
    [[ "$start_key" == '{}' ]] && break
  done
  printf '%s\n' "$total"
}

table_total_count() {
  local region="$1" table="$2"
  local page
  page="$WORK/table-total-$(printf '%s' "$region:$table" | sha256sum | cut -d' ' -f1).json"
  local start_key='{}' count total=0
  local -a scan
  while true; do
    scan=(aws --profile "$PROFILE" --region "$region" dynamodb scan
      --table-name "$table" --consistent-read --select COUNT
      --no-paginate --output json)
    [[ "$start_key" == '{}' ]] ||
      scan+=(--exclusive-start-key "$start_key")
    "${scan[@]}" >"$page"
    count="$(jq -er '.Count' "$page")"
    total=$(( total + count ))
    start_key="$(jq -c '.LastEvaluatedKey // {}' "$page")"
    [[ "$start_key" == '{}' ]] && break
  done
  printf '%s\n' "$total"
}

verify_dynamodb() {
  local role table region count user_count expected_regions retained t1_user
  local output="$CLOUD_DIR/dynamodb-counts.tsv"
  : >"$output"
  t1_user="$(jq -er '.users.t1' "$FIXTURES")"
  expected_regions="$(context_value '.configured_regions | sort | join(",")')"
  while IFS=$'\t' read -r role table; do
    local description="$WORK/table-$role.json" actual_regions
    "${AWSQ[@]}" dynamodb describe-table \
      --table-name "$table" --output json >"$description"
    actual_regions="$(
      jq -r \
        --arg primary "$REGION" '
          ([$primary] + [.Table.Replicas[]?.RegionName])
          | unique | sort | join(",")
        ' "$description"
    )"
    [[ "$actual_regions" == "$expected_regions" ]] ||
      fail "$role table Regions $actual_regions differ from $expected_regions"
    retained=0
    case "$role" in
      governance|governance_suppression|security_events|tenant_keys)
        retained=1
        ;;
    esac
    while IFS= read -r region; do
      count="$(tenant_count "$region" "$table" t2)"
      printf 'tenant\t%s\t%s\t%s\tt2\t%s\n' \
        "$role" "$table" "$region" "$count" >>"$output"
      if [[ "$retained" == "0" && "$count" != "0" ]]; then
        fail "$role retains $count live t2 records in $region"
      fi
      user_count="$(target_count "$region" "$table" "$t1_user")"
      printf 'user\t%s\t%s\t%s\tt1\t%s\n' \
        "$role" "$table" "$region" "$user_count" >>"$output"
      if [[ "$retained" == "0" && "$user_count" != "0" ]]; then
        fail "$role retains $user_count live t1 user references in $region"
      fi
    done < <(jq -r '.configured_regions[]' "$CONTEXT")
  done < <(jq -r '.replicated_tables | to_entries[] | [.key,.value] | @tsv' "$CONTEXT")

  while IFS= read -r table; do
    count="$(tenant_count "$REGION" "$table" t2)"
    printf 'region_local_tenant\t%s\t%s\tt2\t%s\n' \
      "$table" "$REGION" "$count" >>"$output"
    if [[ "$table" != "$(context_value '.outputs.SsfDeliveriesTableName')" &&
      "$count" != "0" ]]; then
      fail "Region-local table $table retains $count live t2 records"
    fi
    user_count="$(target_count "$REGION" "$table" "$t1_user")"
    printf 'region_local_user\t%s\t%s\tt1\t%s\n' \
      "$table" "$REGION" "$user_count" >>"$output"
    if [[ "$user_count" != "0" ]]; then
      fail "Region-local table $table retains $user_count live t1 user references"
    fi
  done < <(jq -r '.region_local_tables[]' "$CONTEXT")

  while IFS=$'\t' read -r role table; do
    count="$(table_total_count "$STANDBY_REGION" "$table")"
    printf 'standby_region_local\t%s\t%s\t%s\t%s\n' \
      "$role" "$table" "$STANDBY_REGION" "$count" >>"$output"
    if [[ "$count" != "0" ]]; then
      fail "Standby Region-local table $role retains $count deployment rows"
    fi
  done < <(jq -r '
    .standby_region_local_tables
    | to_entries | sort_by(.key)[] | [.key,.value] | @tsv
  ' "$CONTEXT")
  chmod 600 "$output"
  pass "DynamoDB Region and tenant live-count claims verified"
}

verify_invitations() {
  local table tenant locator key item output="$CLOUD_DIR/invitations.tsv"
  table="$(context_value '.outputs.InvitationsTableName')"
  : >"$output"
  for tenant in t1 t2; do
    locator="$(jq -er --arg tenant "$tenant" \
      '.invitation_locators[$tenant]' "$FIXTURES")"
    [[ "$locator" =~ ^[A-Za-z0-9_-]{43}$ ]] ||
      fail "$tenant persisted invitation locator is malformed"
    key="$WORK/invitation-key-$tenant.json"
    item="$WORK/invitation-item-$tenant.json"
    jq -n --arg tenant "$tenant" --arg locator "$locator" '{
      locator: {S: ($tenant + "\u001f" + $locator)}
    }' >"$key"
    "${AWSQ[@]}" dynamodb get-item \
      --table-name "$table" \
      --consistent-read \
      --key "file://$key" \
      --query '{Item: Item}' \
      --output json >"$item"
    jq -e \
      'type == "object" and has("Item") and .Item == null' \
      "$item" >/dev/null ||
      fail "$tenant invitation locator remains after governance cleanup"
    printf '%s\t%s\tabsent\n' \
      "$tenant" "$(printf '%s' "$locator" | sha256sum | awk '{print $1}')" \
      >>"$output"
  done
  chmod 600 "$output"
  pass "t1 erasure and t2 offboarding removed their invitation locators"
}

bucket_region() {
  local bucket="$1" location
  location="$("${AWSQ[@]}" s3api get-bucket-location \
    --bucket "$bucket" --query LocationConstraint --output text)"
  [[ "$location" == "None" || "$location" == "null" ]] &&
    location="us-east-1"
  printf '%s\n' "$location"
}

verify_s3() {
  local output="$CLOUD_DIR/s3.jsonl" key bucket region lifecycle count
  local lifecycle_days prefix scope
  local -a list_args
  : >"$output"
  while IFS=$'\t' read -r key lifecycle_days prefix; do
    bucket="$(context_value ".outputs.$key")"
    region="$(bucket_region "$bucket")"
    [[ "$region" == "$REGION" ]] ||
      fail "$key is in $region, expected $REGION"
    lifecycle="$WORK/lifecycle-$key.json"
    "${AWSQ[@]}" s3api get-bucket-lifecycle-configuration \
      --bucket "$bucket" --output json >"$lifecycle"
    jq -e --argjson days "$lifecycle_days" '
      any(.Rules[];
        .Status == "Enabled" and
        (
          .Expiration.Days == $days or
          .NoncurrentVersionExpiration.NoncurrentDays == $days
        )
      )
    ' "$lifecycle" >/dev/null ||
      fail "$key lacks its $lifecycle_days-day lifecycle"
    list_args=(s3api list-objects-v2 --bucket "$bucket")
    scope="all_objects"
    if [[ "$prefix" != "-" ]]; then
      list_args+=(--prefix "$prefix")
      scope="t2_archive"
    fi
    count="$("${AWSQ[@]}" "${list_args[@]}" \
      --output json | jq -er '(.Contents // []) | length')"
    jq -cn \
      --arg class "$key" \
      --arg bucket "$bucket" \
      --arg region "$region" \
      --arg scope "$scope" \
      --argjson count "$count" \
      --argjson lifecycle_days "$lifecycle_days" '{
        class:$class,
        bucket:$bucket,
        region:$region,
        count_scope:$scope,
        object_count:$count,
        lifecycle_days:$lifecycle_days
      }' \
      >>"$output"
  done <<'BUCKETS'
SecurityEventArchiveBucketName	2555	security-events/tenant_id=t2/
SecurityEventStreamFailureBucketName	2555	-
SecurityEventIngressFailureBucketName	2555	-
SsfStreamFailureBucketName	400	-
BUCKETS
  chmod 600 "$output"
  pass "S3 Region, scoped object count, and class lifecycle claims verified"
}

verify_backup() {
  local plan_id vault plan selections expected actual table arn recovery count
  local output="$CLOUD_DIR/backup.tsv"
  plan_id="$(context_value '.outputs.RecoveryBackupPlanId')"
  vault="$(context_value '.outputs.RecoveryBackupVaultName')"
  plan="$WORK/backup-plan.json"
  "${AWSQ[@]}" backup get-backup-plan \
    --backup-plan-id "$plan_id" --output json >"$plan"
  jq -e '
    any(.BackupPlan.Rules[];
      .RuleName == "DailyDurableAuthority" and
      .Lifecycle.DeleteAfterDays == 35
    )
  ' "$plan" >/dev/null ||
    fail "AWS Backup plan lacks the 35-day daily authority rule"

  "${AWSQ[@]}" backup list-backup-selections \
    --backup-plan-id "$plan_id" --output json >"$WORK/backup-selections.json"
  selections="$(
    jq -er '
      .BackupSelectionsList
      | if length == 1 then .[0].SelectionId
        else error("expected exactly one backup selection")
        end
    ' "$WORK/backup-selections.json"
  )"
  "${AWSQ[@]}" backup get-backup-selection \
    --backup-plan-id "$plan_id" \
    --selection-id "$selections" --output json >"$WORK/backup-selection.json"
  expected="$WORK/backup-expected"
  actual="$WORK/backup-actual"
  jq -r \
    --arg account "$(context_value '.account_id')" \
    --arg region "$REGION" '
      .recovery_tables[]
      | "arn:aws:dynamodb:\($region):\($account):table/\(.)"
    ' "$CONTEXT" | sort >"$expected"
  jq -r '.BackupSelection.Resources[]' "$WORK/backup-selection.json" |
    sort >"$actual"
  cmp -s "$expected" "$actual" ||
    fail "AWS Backup selection differs from RecoveryAuthorityTableNames"

  : >"$output"
  while IFS= read -r table; do
    arn="arn:aws:dynamodb:$REGION:$(context_value '.account_id'):table/$table"
    recovery="$WORK/recovery-$table.json"
    "${AWSQ[@]}" backup list-recovery-points-by-backup-vault \
      --backup-vault-name "$vault" \
      --by-resource-arn "$arn" --output json >"$recovery"
    count="$(jq '[.RecoveryPoints[] | select(.Status == "COMPLETED")] | length' "$recovery")"
    [[ "$count" -ge 1 ]] ||
      fail "no completed recovery point exists for $table"
    jq -e '
      all(
        .RecoveryPoints[] | select(.Status == "COMPLETED");
        (.Lifecycle.DeleteAfterDays == 35) and
        (.CalculatedLifecycle.DeleteAt | type == "string" and length > 0)
      )
    ' "$recovery" >/dev/null ||
      fail "$table recovery-point deadline does not match 35 days"
    printf '%s\t%s\t%s\n' "$table" "$count" \
      "$(jq -r '[.RecoveryPoints[] | select(.Status == "COMPLETED") | .CalculatedLifecycle.DeleteAt] | max' "$recovery")" \
      >>"$output"
  done < <(jq -r '.recovery_tables[]' "$CONTEXT")
  chmod 600 "$output"
  pass "AWS Backup selection, Region, count, and deletion deadlines verified"
}

verify_kms() {
  local arn region description state deletion deletion_epoch arn_hash
  local primary replica latest projected
  local -a pending_primaries=()
  declare -A key_state=()
  declare -A key_deletion=()
  local output="$CLOUD_DIR/kms.tsv"
  : >"$output"
  while IFS= read -r arn; do
    region="$(cut -d: -f4 <<<"$arn")"
    description="$WORK/kms-$(sha256sum <<<"$arn" | awk '{print $1}').json"
    aws --profile "$PROFILE" --region "$region" kms describe-key \
      --key-id "$arn" --output json >"$description"
    state="$(jq -er '.KeyMetadata.KeyState' "$description")"
    key_state["$arn"]="$state"
    case "$state" in
      PendingDeletion)
        deletion="$(jq -er '
          .KeyMetadata.DeletionDate
          | select(type == "string")
        ' "$description")"
        deletion_epoch="$(
          seven_day_deletion_epoch "KMS key in $region" "$deletion"
        )"
        key_deletion["$arn"]="$deletion_epoch"
        arn_hash="$(printf '%s' "$arn" | sha256sum | awk '{print $1}')"
        printf '%s\t%s\t%s\t%s\tdirect\n' \
          "$arn_hash" "$region" "$state" "$deletion_epoch" >>"$output"
        ;;
      PendingReplicaDeletion)
        jq -e '
          .KeyMetadata.MultiRegionConfiguration.MultiRegionKeyType == "PRIMARY" and
          (.KeyMetadata.MultiRegionConfiguration.ReplicaKeys | length > 0)
        ' "$description" >/dev/null ||
          fail "PendingReplicaDeletion key in $region lacks replica metadata"
        pending_primaries+=("$arn")
        ;;
      *)
        fail "t2 managed KMS key is not pending deletion in $region"
        ;;
    esac
  done < <(jq -r '.t2_kms_key_arns[]' "$CONTEXT")

  jq -e '
    .configured_regions as $configured
    | (.t2_kms_key_arns | length >= 2) and
      all(
        .t2_kms_key_arns[];
        (split(":")[3]) as $region
        | (($configured | index($region)) != null)
      )
  ' "$CONTEXT" >/dev/null ||
    fail "managed t2 KMS keys are incomplete or outside configured Regions"

  for primary in "${pending_primaries[@]}"; do
    description="$WORK/kms-$(sha256sum <<<"$primary" | awk '{print $1}').json"
    latest=0
    while IFS= read -r replica; do
      [[ -n "${key_state[$replica]:-}" ]] ||
        fail "KMS primary references an undiscovered replica"
      [[ "${key_state[$replica]}" == "PendingDeletion" ]] ||
        fail "KMS primary replica is not pending deletion"
      (( ${key_deletion[$replica]} > latest )) &&
        latest="${key_deletion[$replica]}"
    done < <(jq -r \
      '.KeyMetadata.MultiRegionConfiguration.ReplicaKeys[].Arn' \
      "$description")
    [[ "$latest" -gt 0 ]] ||
      fail "KMS primary has no verified replica deletion deadline"
    projected="$((latest + 7 * 24 * 60 * 60))"
    region="$(cut -d: -f4 <<<"$primary")"
    arn_hash="$(printf '%s' "$primary" | sha256sum | awk '{print $1}')"
    printf '%s\t%s\tPendingReplicaDeletion\t%s\treplica_then_7_days\n' \
      "$arn_hash" "$region" "$projected" >>"$output"
  done
  chmod 600 "$output"
  pass "KMS Region, count, state, and deletion deadlines verified"
}

verify_secrets() {
  local tenant purpose ownership arn resource_account resource_region
  local description deleted deleted_epoch outcome
  local product_count=0 external_count=0 control_count=0
  local output="$CLOUD_DIR/secrets.tsv"
  : >"$output"
  while IFS=$'\t' read -r \
    tenant purpose ownership arn resource_account resource_region; do
    [[ "$resource_account" == "$(context_value '.account_id')" ]] ||
      fail "$tenant $purpose Secret account differs from drill context"
    [[ "$resource_region" == "$REGION" ]] ||
      fail "$tenant $purpose Secret is outside the governance Region"
    description="$WORK/secret-$(printf '%s' "$arn" | sha256sum | awk '{print $1}').json"
    aws --profile "$PROFILE" --region "$resource_region" \
      secretsmanager describe-secret \
      --secret-id "$arn" --output json >"$description"
    deleted_epoch="-"
    if [[ "$tenant" == "$OFFBOARD_TENANT" &&
      "$ownership" == "product_managed" ]]; then
      deleted="$(jq -er '.DeletedDate | select(type == "string")' "$description")"
      deleted_epoch="$(
        secret_deletion_epoch \
          "$tenant $purpose Secret" "$arn" "$resource_region" "$deleted"
      )"
      outcome="pending_deletion"
      product_count=$((product_count + 1))
    else
      jq -e 'has("DeletedDate") | not' "$description" >/dev/null ||
        fail "$tenant $purpose $ownership Secret was unexpectedly scheduled for deletion"
      if [[ "$tenant" == "$OFFBOARD_TENANT" ]]; then
        [[ "$ownership" == "external" ]] ||
          fail "$tenant $purpose has an unsupported Secret ownership"
        outcome="external_retained"
        external_count=$((external_count + 1))
      else
        outcome="control_active"
        control_count=$((control_count + 1))
      fi
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$tenant" "$purpose" "$ownership" \
      "$(printf '%s' "$arn" | sha256sum | awk '{print $1}')" \
      "$outcome" "$deleted_epoch" >>"$output"
  done < <(jq -r '
    .tenant_secret_dependencies
    | to_entries | sort_by(.key)[]
    | .key as $tenant
    | .value | sort_by(.purpose)[]
    | [
        $tenant,
        .purpose,
        .ownership,
        .secret_ref,
        .resource_account,
        .resource_region
      ]
    | @tsv
  ' "$CONTEXT")
  [[ "$product_count" -eq 3 && "$external_count" -eq 1 &&
    "$control_count" -eq 4 ]] ||
    fail "Secret dependency ownership counts differ from the qualifying profile"
  chmod 600 "$output"
  pass "Secrets Manager ownership, Region, count, and deletion deadlines verified"
}

verify_logs() {
  local resources="$WORK/current-resources.json" output="$CLOUD_DIR/logs.tsv"
  local logical name described retention
  "${AWSQ[@]}" cloudformation list-stack-resources \
    --stack-name "$STACK" --output json >"$resources"
  : >"$output"
  for logical in \
    GovernanceWorkerLogGroup \
    SecurityEventArchiveLogGroup \
    SsfDeliveryLogGroup; do
    name="$(
      jq -er --arg logical "$logical" '
        .StackResourceSummaries[]
        | select(
            .ResourceType == "AWS::Logs::LogGroup" and
            (.LogicalResourceId | startswith($logical))
          )
        | .PhysicalResourceId
      ' "$resources"
    )"
    described="$WORK/log-$logical.json"
    "${AWSQ[@]}" logs describe-log-groups \
      --log-group-name-prefix "$name" --output json >"$described"
    retention="$(
      jq -er --arg name "$name" '
        .logGroups
        | map(select(.logGroupName == $name))
        | if length == 1 then .[0].retentionInDays
          else error("log group not found")
          end
      ' "$described"
    )"
    [[ "$retention" -ge 2555 ]] ||
      fail "$logical retention is shorter than seven years"
    printf '%s\t%s\t%s\t%s\n' "$logical" "$name" "$REGION" "$retention" >>"$output"
  done
  chmod 600 "$output"
  pass "CloudWatch Logs Region, count, and retention claims verified"
}

restore_tenant_key_dlq_visibility() {
  local queue_url="$1" handles="$2" receipt restored
  local restore_failed=0
  while IFS= read -r receipt; do
    restored=0
    for _ in 1 2 3; do
      if "${AWSQ[@]}" sqs change-message-visibility \
        --queue-url "$queue_url" \
        --receipt-handle "$receipt" \
        --visibility-timeout 0 >/dev/null; then
        restored=1
        break
      fi
      sleep 1
    done
    [[ "$restored" == "1" ]] || restore_failed=1
  done <"$handles"
  if [[ "$restore_failed" == "0" ]]; then
    if [[ "$ACTIVE_VISIBILITY_QUEUE" == "$queue_url" &&
      "$ACTIVE_VISIBILITY_HANDLES" == "$handles" ]]; then
      ACTIVE_VISIBILITY_QUEUE=""
      ACTIVE_VISIBILITY_HANDLES=""
    fi
    return 0
  fi
  return 1
}

receive_and_register_tenant_key_dlq_batch() {
  local queue_url="$1" max_messages="$2" response="$3"
  local handles="$4" batch_messages="$5" receive_pid receive_status
  (
    trap '' INT TERM
    if ! "${AWSQ[@]}" sqs receive-message \
      --queue-url "$queue_url" \
      --message-system-attribute-names \
      SentTimestamp DeadLetterQueueSourceArn \
      --max-number-of-messages "$max_messages" \
      --visibility-timeout 60 \
      --wait-time-seconds 10 \
      --output json >"$response"; then
      exit 70
    fi
    if ! jq -r '
      (.Messages // [])[]
      | if (.ReceiptHandle | type == "string" and length > 0) then
          .ReceiptHandle
        else
          error("missing receipt handle")
        end
    ' "$response" >>"$handles"; then
      exit 71
    fi
    if ! jq -c '
      if ((.Messages // []) | type) == "array" then
        (.Messages // [])[]
      else
        error("Messages is not an array")
      end
    ' "$response" >"$batch_messages"; then
      exit 72
    fi
  ) &
  receive_pid=$!
  while :; do
    if wait "$receive_pid"; then
      return 0
    fi
    receive_status=$?
    if [[ "$receive_status" == "130" || "$receive_status" == "143" ]] &&
      [[ "${deferred_signal:-0}" != "0" ]]; then
      continue
    fi
    if kill -0 "$receive_pid" 2>/dev/null; then
      continue
    fi
    return "$receive_status"
  done
}

inspect_tenant_key_dlq_messages() {
  local queue_url="$1" expected_visible="$2" source_arn="$3" evidence="$4"
  local captured="$WORK/tenant-key-dlq-messages.jsonl"
  local handles="$WORK/tenant-key-dlq-receipt-handles"
  local response="$WORK/tenant-key-dlq-receive.json"
  local batch_messages="$WORK/tenant-key-dlq-batch.jsonl"
  local received=0 batch_count max_messages remaining created_at empty_receives=0
  local deferred_signal=0 receive_status
  : >"$captured"
  : >"$handles"
  created_at="$(context_value '.created_at')"
  (( expected_visible <= 10 )) ||
    fail "retained tenant-key DLQ count exceeds the inspection bound"
  ACTIVE_VISIBILITY_QUEUE="$queue_url"
  ACTIVE_VISIBILITY_HANDLES="$handles"
  trap 'deferred_signal=130' INT
  trap 'deferred_signal=143' TERM

  while (( empty_receives < 2 )); do
    remaining=$(( expected_visible - received ))
    max_messages=10
    if (( remaining > 0 && remaining < max_messages )); then
      max_messages="$remaining"
    fi
    if receive_and_register_tenant_key_dlq_batch \
      "$queue_url" "$max_messages" "$response" \
      "$handles" "$batch_messages"; then
      receive_status=0
    else
      receive_status=$?
    fi
    if [[ "$receive_status" != "0" ]]; then
      restore_tenant_key_dlq_visibility "$queue_url" "$handles" ||
        fail "tenant-key DLQ receive failed and visibility restoration failed"
      case "$receive_status" in
        70) fail "tenant-key DLQ receive failed" ;;
        71) fail "tenant-key DLQ receipt handle was malformed" ;;
        72) fail "tenant-key DLQ response was malformed" ;;
        *) fail "tenant-key DLQ receive transaction failed" ;;
      esac
    fi
    if [[ "$deferred_signal" != "0" ]]; then
      restore_tenant_key_dlq_visibility "$queue_url" "$handles" ||
        fail "tenant-key DLQ visibility restoration failed after interruption"
      trap 'exit 130' INT
      trap 'exit 143' TERM
      return "$deferred_signal"
    fi
    if ! batch_count="$(jq -s 'length' "$batch_messages")"; then
      restore_tenant_key_dlq_visibility "$queue_url" "$handles" ||
        fail "tenant-key DLQ count failed and visibility restoration failed"
      fail "tenant-key DLQ count failed"
    fi
    if [[ "$batch_count" == "0" ]]; then
      empty_receives=$(( empty_receives + 1 ))
      continue
    fi
    empty_receives=0
    if ! cat "$batch_messages" >>"$captured"; then
      restore_tenant_key_dlq_visibility "$queue_url" "$handles" ||
        fail "tenant-key DLQ capture failed and visibility restoration failed"
      fail "tenant-key DLQ capture failed"
    fi
    received=$(( received + batch_count ))
    if (( received > expected_visible )); then
      restore_tenant_key_dlq_visibility "$queue_url" "$handles" ||
        fail "retained tenant-key DLQ count differs and visibility restoration failed"
      fail "retained tenant-key DLQ count differs from inspected messages"
    fi
  done

  restore_tenant_key_dlq_visibility "$queue_url" "$handles" ||
    fail "tenant-key DLQ visibility restoration failed"
  [[ "$received" == "$expected_visible" ]] ||
    fail "retained tenant-key DLQ count differs from inspected messages"

  jq -s -e -L "$REPO_ROOT/e2e" \
    --arg source "$source_arn" \
    --arg offboard "$OFFBOARD_TENANT" \
    --argjson created "$created_at" \
    --argjson expected "$expected_visible" '
      include "tenant_key_dlq_evidence";
      tenant_key_dlq_messages_qualify(
        $source; $offboard; $created; $expected
      )
    ' "$captured" >/dev/null ||
    fail "tenant-key DLQ contains an unqualified retained message"

  jq -sr -L "$REPO_ROOT/e2e" '
    include "tenant_key_dlq_evidence";
    tenant_key_dlq_canonical_rows
  ' "$captured" >>"$evidence" ||
    fail "tenant-key DLQ canonical evidence generation failed"
  trap 'exit 130' INT
  trap 'exit 143' TERM
  [[ "$deferred_signal" == "0" ]] || return "$deferred_signal"
}

verify_queues() {
  local key url attributes arn retention visible inflight delayed attempt
  local all_drained previous_drained=0
  local output="$CLOUD_DIR/queues.tsv"
  local candidate="$WORK/queues-candidate.tsv"
  local previous_candidate="$WORK/queues-previous-candidate.tsv"
  local tenant_key_source_arn
  for attempt in $(seq 1 60); do
    : >"$candidate"
    all_drained=1
    for key in \
      GovernanceWorkerQueueUrl GovernanceWorkerDlqUrl \
      TenantKeyOperationsQueueUrl TenantKeyOperationsDlqUrl \
      SecurityEventArchiveDlqUrl SecurityEventIngressQueueUrl \
      SecurityEventIngressDlqUrl \
      SecurityEventStreamFailureNotificationQueueUrl \
      SecurityEventStreamFailureNotificationDlqUrl \
      SsfStreamFailureReplayQueueUrl SsfStreamFailureReplayDlqUrl; do
      url="$(context_value ".outputs.$key")"
      attributes="$WORK/queue-$key.json"
      "${AWSQ[@]}" sqs get-queue-attributes \
        --queue-url "$url" --attribute-names \
        QueueArn MessageRetentionPeriod ApproximateNumberOfMessages \
        ApproximateNumberOfMessagesNotVisible \
        ApproximateNumberOfMessagesDelayed \
        --output json >"$attributes"
      arn="$(jq -er '.Attributes.QueueArn' "$attributes")"
      retention="$(jq -er '.Attributes.MessageRetentionPeriod | tonumber' "$attributes")"
      visible="$(jq -er '.Attributes.ApproximateNumberOfMessages | tonumber' "$attributes")"
      inflight="$(jq -er '.Attributes.ApproximateNumberOfMessagesNotVisible | tonumber' "$attributes")"
      delayed="$(jq -er '.Attributes.ApproximateNumberOfMessagesDelayed | tonumber' "$attributes")"
      [[ "$arn" == "arn:aws:sqs:$REGION:$(context_value '.account_id'):"* ]] ||
        fail "$key is outside the selected account/Region"
      [[ "$retention" == "1209600" ]] ||
        fail "$key does not retain messages for 14 days"
      printf '%s\t%s\t%s\t%s\t%s\n' \
        "$key" "$visible" "$inflight" "$delayed" "$retention" >>"$candidate"
      if [[ "$key" == "TenantKeyOperationsQueueUrl" ]]; then
        tenant_key_source_arn="$arn"
      fi
      if [[ "$key" == "TenantKeyOperationsDlqUrl" ]]; then
        [[ -n "$tenant_key_source_arn" ]] ||
          fail "tenant-key source queue ARN is unavailable"
        [[ "$inflight" == "0" && "$delayed" == "0" ]] ||
          all_drained=0
        inspect_tenant_key_dlq_messages \
          "$url" "$visible" "$tenant_key_source_arn" "$candidate"
      else
        [[ "$visible" == "0" && "$inflight" == "0" && "$delayed" == "0" ]] ||
          all_drained=0
      fi
    done
    if [[ "$all_drained" == "1" && "$previous_drained" == "1" ]]; then
      cmp -s "$previous_candidate" "$candidate" ||
        fail "retained queue evidence changed between qualifying samples"
      mv "$candidate" "$output"
      chmod 600 "$output"
      pass "SQS Region, count, retained-message baseline, and 14-day retention claims verified"
      return
    fi
    if [[ "$all_drained" == "1" ]]; then
      cp "$candidate" "$previous_candidate"
      chmod 600 "$previous_candidate"
      previous_drained=1
    else
      rm -f "$previous_candidate"
      previous_drained=0
    fi
    [[ "$attempt" -lt 60 ]] ||
      fail "retained queues did not remain drained after governance convergence"
    sleep 10
  done
}

verify_ssf() {
  local table count stream item output="$CLOUD_DIR/ssf.json"
  table="$(context_value '.outputs.SsfDeliveriesTableName')"
  stream="$(jq -er '.stream_id' "$SSF_FIXTURE")"
  count="$(tenant_count "$REGION" "$table" t2)"
  [[ "$count" -ge 1 ]] ||
    fail "t2 offboarding did not retain an SSF revoke tombstone"
  item="$WORK/ssf-owned-stream.json"
  "${AWSQ[@]}" dynamodb get-item \
    --table-name "$table" \
    --consistent-read \
    --key "$(jq -cn \
      --arg tenant t2 \
      --arg record "stream#$stream" \
      '{tenant_id:{S:$tenant},record_key:{S:$record}}')" \
    --output json >"$item"
  jq -e --arg stream "$stream" '
    .Item.entity_type.S == "stream" and
    .Item.stream_id.S == $stream and
    .Item.status.S == "revoked"
  ' "$item" >/dev/null ||
    fail "RUN_ID-owned t2 SSF stream is not a permanent revoke tombstone"
  jq -n \
    --arg table "$table" \
    --arg region "$REGION" \
    --arg stream_sha256 "$(printf '%s' "$stream" | sha256sum | awk '{print $1}')" \
    --argjson retained_tenant_records "$count" '{
      table: $table,
      region: $region,
      owned_stream_sha256: $stream_sha256,
      retained_tenant_records: $retained_tenant_records,
      expected_class: "ssf_revoke_tombstones"
    }' | atomic_write "$output"
  pass "SSF Region/count claim and permanent revoke tombstone verified"
}

verify_cloud_resources() {
  verify_dynamodb
  verify_invitations
  verify_s3
  verify_backup
  verify_kms
  verify_secrets
  verify_logs
  verify_ssf
  mark_done cloud-verified
}

verify_evidence_hash() {
  local file="$1"
  python3 - "$file" <<'PY'
import base64
import hashlib
import json
import pathlib
import sys

record = json.loads(pathlib.Path(sys.argv[1]).read_text())
payload = json.dumps(
    record["payload"],
    ensure_ascii=False,
    separators=(",", ":"),
).encode()
actual = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()
if actual != record.get("payload_sha256"):
    raise SystemExit("service evidence SHA-256 mismatch")
PY
}

fetch_service_evidence() {
  local user_job offboard_job t1_token evidence_token
  user_job="$(jq -er '.job_id' "$STATE_DIR/user-erasure-job.json")"
  offboard_job="$(jq -er '.job_id' "$STATE_DIR/offboarding-job.json")"
  t1_token="$(admin_token t1)"
  http_request t1-evidence GET \
    "$(issuer t1)/admin/data-governance/jobs/$user_job/evidence" \
    "$t1_token" governance "" "$SERVICE_EVIDENCE_DIR/t1.json"
  expect_status "t1 immutable evidence" "$HTTP_STATUS" 200

  evidence_token="$WORK/continuation-evidence.token"
  issue_continuation_token t2 "$offboard_job" evidence "$evidence_token"
  http_request t2-evidence GET \
    "$(control_url)/admin/control/data-governance/tenants/t2/jobs/$offboard_job/evidence" \
    "$evidence_token" bearer "" "$SERVICE_EVIDENCE_DIR/t2.json"
  expect_status "t2 immutable evidence" "$HTTP_STATUS" 200
}

verify_evidence_deployment_lineage() {
  local file="$1" tenant="$2" evidence_commit initial_commit current_commit
  evidence_commit="$(jq -er '
    .payload.deployment_commit
    | select(type == "string" and test("^[0-9a-f]{40}$"))
  ' "$file")" ||
    fail "$tenant evidence has an invalid deployment commit"
  initial_commit="$(context_value '.deployment_commit')"
  current_commit="$(active_deployment_commit)"
  git -C "$REPO_ROOT" cat-file -e "$evidence_commit^{commit}" 2>/dev/null ||
    fail "$tenant evidence deployment commit is absent from the repository"
  git -C "$REPO_ROOT" merge-base --is-ancestor \
    "$initial_commit" "$evidence_commit" ||
    fail "$tenant evidence predates the RUN_ID deployment lineage"
  git -C "$REPO_ROOT" merge-base --is-ancestor \
    "$evidence_commit" "$current_commit" ||
    fail "$tenant evidence is outside the adopted deployment lineage"
}

verify_service_evidence() {
  local tenant kind job file required_token
  local expected_regions
  expected_regions="$(context_value '.configured_regions | sort | join(",")')"
  for tenant in t1 t2; do
    kind="user_erasure"
    job="$(jq -er '.job_id' "$STATE_DIR/user-erasure-job.json")"
    [[ "$tenant" == "t2" ]] &&
      kind="tenant_offboarding" &&
      job="$(jq -er '.job_id' "$STATE_DIR/offboarding-job.json")"
    file="$SERVICE_EVIDENCE_DIR/$tenant.json"
    verify_evidence_hash "$file"
    verify_evidence_deployment_lineage "$file" "$tenant"
    jq -e \
      --arg tenant "$tenant" \
      --arg kind "$kind" \
      --arg job "$job" \
      --arg region "$REGION" \
      --arg regions "$expected_regions" '
        .payload.tenant_id == $tenant and
        .payload.job_id == $job and
        .payload.job_kind == $kind and
        .payload.active_writer_region == $region and
        ((.payload.configured_regions | sort | join(",")) == $regions) and
        (.payload.live_counts | type == "object") and
        all(.payload.live_counts[]; . == 0) and
        (.payload.replica_live_counts | type == "object") and
        ((.payload.replica_live_counts | keys | sort | join(",")) == $regions) and
        all(.payload.replica_live_counts[];
          .verification_state == "provider_strong_read" and
          (.verified_at | type == "number") and
          (.live_counts | type == "object") and
          all(.live_counts[]; . == 0)
        ) and
        (.payload.external_actions | type == "array") and
        all(.payload.external_actions[];
          .state == "verified" and
          (
            (.ownership == "product_managed" and
              (.outcome == "pending_deletion" or .outcome == "absent")) or
            (.ownership == "external" and
              (.outcome == "external_retained" or .outcome == "absent"))
          )
        ) and
        (
          $kind == "user_erasure" or
          (
            any(.payload.external_actions[];
              .kind == "secret_deletion" and
              .ownership == "external" and
              .outcome == "external_retained"
            ) and
            (
              .payload.retention_resources
              .secrets_manager_product_managed.retention_until
              ==
              ([
                .payload.external_actions[]
                | select(
                    .kind == "secret_deletion" and
                    .ownership == "product_managed"
                  )
                | .retention_until // empty
              ] | max)
            ) and
            (.payload.retention_resources.secrets_manager_external.state ==
              "verified")
          )
        ) and
        (.payload.primary_erasure_at | type == "number") and
        (.payload.retention_deadline >=
          (.payload.primary_erasure_at + 2555 * 24 * 60 * 60))
      ' "$file" >/dev/null ||
      fail "$tenant evidence does not bind replica reads, zero counts, and retention deadline"
    for required_token in \
      dynamodb security_event s3 backup kms secret cloudwatch sqs ssf; do
      jq -c '.payload' "$file" |
        grep -qi "$required_token" ||
        fail "$tenant evidence omits required $required_token lifecycle claims"
    done
  done
  mark_done service-evidence-verified
  pass "immutable service evidence hash, deployment lineage, Region, count, and deadline claims verified"
}

write_final_evidence() {
  local payload="$WORK/final-payload.json" digest account_hash
  local t1_user_hash t2_user_hash cloud_hashes="$WORK/cloud-hashes.json"
  local transitions="$WORK/final-deployment-transitions.json"
  account_hash="$(
    context_value '.account_id' | sha256sum | awk '{print $1}'
  )"
  t1_user_hash="$(
    printf '%s:%s' "$RUN_ID" "$(jq -er '.users.t1' "$FIXTURES")" |
      sha256sum | awk '{print $1}'
  )"
  t2_user_hash="$(
    printf '%s:%s' "$RUN_ID" "$(jq -er '.users.t2' "$FIXTURES")" |
      sha256sum | awk '{print $1}'
  )"
  jq -n \
    --arg dynamodb "$(hash_file "$CLOUD_DIR/dynamodb-counts.tsv")" \
    --arg invitations "$(hash_file "$CLOUD_DIR/invitations.tsv")" \
    --arg s3 "$(hash_file "$CLOUD_DIR/s3.jsonl")" \
    --arg backup "$(hash_file "$CLOUD_DIR/backup.tsv")" \
    --arg kms "$(hash_file "$CLOUD_DIR/kms.tsv")" \
    --arg secrets "$(hash_file "$CLOUD_DIR/secrets.tsv")" \
    --arg logs "$(hash_file "$CLOUD_DIR/logs.tsv")" \
    --arg queues "$(hash_file "$CLOUD_DIR/queues.tsv")" \
    --arg ssf "$(hash_file "$CLOUD_DIR/ssf.json")" '{
      "dynamodb-counts.tsv":$dynamodb,
      "invitations.tsv":$invitations,
      "s3.jsonl":$s3,
      "backup.tsv":$backup,
      "kms.tsv":$kms,
      "secrets.tsv":$secrets,
      "logs.tsv":$logs,
      "queues.tsv":$queues,
      "ssf.json":$ssf
    }' >"$cloud_hashes"
  deployment_transitions_json >"$transitions"
  jq -n \
    --arg schema_version "2" \
    --arg run_id "$RUN_ID" \
    --arg deployment_commit "$(active_deployment_commit)" \
    --arg initial_deployment_commit "$(context_value '.deployment_commit')" \
    --arg account_sha256 "$account_hash" \
    --arg region "$REGION" \
    --arg t1_user_sha256 "$t1_user_hash" \
    --arg t2_user_sha256 "$t2_user_hash" \
    --arg completed_at "$(now_epoch)" \
    --slurpfile cloud_hashes "$cloud_hashes" \
    --slurpfile context "$CONTEXT" \
    --slurpfile transitions "$transitions" \
    --slurpfile t1 "$SERVICE_EVIDENCE_DIR/t1.json" \
    --slurpfile t2 "$SERVICE_EVIDENCE_DIR/t2.json" '
      {
        schema_version: ($schema_version | tonumber),
        run_id: $run_id,
        deployment_commit: $deployment_commit,
        initial_deployment_commit: $initial_deployment_commit,
        deployment_transitions: $transitions[0],
        account_sha256: $account_sha256,
        region: $region,
        configured_regions: $context[0].configured_regions,
        fixture_user_ids_sha256: {
          t1: $t1_user_sha256,
          t2: $t2_user_sha256
        },
        retry_interruption_injected: true,
        service_evidence_sha256: {
          t1: $t1[0].payload_sha256,
          t2: $t2[0].payload_sha256
        },
        service_evidence_deployment_commits: {
          t1: $t1[0].payload.deployment_commit,
          t2: $t2[0].payload.deployment_commit
        },
        cloud_evidence_sha256: $cloud_hashes[0],
        completed_at: ($completed_at | tonumber)
      }
    ' >"$payload"
  digest="$(hash_file "$payload")"
  jq -n \
    --argjson payload "$(cat "$payload")" \
    --arg sha256 "$digest" \
    '{payload:$payload,payload_sha256:$sha256}' |
    atomic_write "$FINAL_EVIDENCE"
  mark_done complete
  pass "qualifying live drill completed; evidence: $FINAL_EVIDENCE"
}

show_status() {
  local marker
  printf 'RUN_ID=%s\n' "$RUN_ID"
  printf 'initial_deployment_commit=%s\n' "$(context_value '.deployment_commit')"
  printf 'active_deployment_commit=%s\n' "$(active_deployment_commit)"
  printf 'deployment_transitions=%s\n' "$(
    if [[ -s "$DEPLOYMENT_TRANSITIONS" ]]; then
      jq -er 'length' "$DEPLOYMENT_TRANSITIONS"
    else
      printf '0\n'
    fi
  )"
  for marker in \
    fixtures exports hold-owned hold-released user-erasure-started \
    retry-interruption-injected user-erasure-primary ssf-fixture \
    offboarding-started offboarding-primary cloud-verified \
    service-evidence-verified queues-verified complete; do
    if is_done "$marker"; then
      printf '%-30s complete\n' "$marker"
    else
      printf '%-30s pending\n' "$marker"
    fi
  done
  [[ ! -s "$STATE_DIR/user-erasure-job.json" ]] ||
    jq '{tenant_id,job_id,queued_revision}' "$STATE_DIR/user-erasure-job.json"
  [[ ! -s "$STATE_DIR/offboarding-job.json" ]] ||
    jq '{tenant_id,job_id}' "$STATE_DIR/offboarding-job.json"
}

cleanup_owned_fixtures() {
  local tenant token user response job stream revision body
  info "cleanup uses product APIs only; no direct cloud-resource deletion"
  if is_done hold-owned && ! is_done hold-released; then
    token="$(admin_token t1)"
    read_policy t1 "$token" "$RESPONSES/cleanup-t1-policy.json"
    if jq -e --arg reason "live-drill-$RUN_ID" '
      (.legal_hold == "enabled" or .legal_hold == "enabling") and
      .legal_hold_reason == $reason
    ' "$RESPONSES/cleanup-t1-policy.json" >/dev/null; then
      put_hold t1 "$token" false \
        "$(jq -er '.revision' "$RESPONSES/cleanup-t1-policy.json")" \
        "$RESPONSES/cleanup-t1-policy-released.json"
      mark_done hold-released
    else
      fail "refusing to alter a legal hold not owned by this RUN_ID"
    fi
  fi
  [[ -s "$FIXTURES" ]] || {
    pass "no recorded fixtures require cleanup"
    return
  }
  if [[ -s "$SSF_FIXTURE" && ! -s "$STATE_DIR/offboarding-job.json" ]]; then
    token="$(admin_token t2)"
    stream="$(jq -er '.stream_id' "$SSF_FIXTURE")"
    response="$RESPONSES/cleanup-t2-ssf-get.json"
    http_request cleanup-t2-ssf-get GET \
      "$(issuer t2)/admin/ssf/streams/$stream" \
      "$token" json "" "$response"
    expect_status "inspect owned t2 SSF stream" "$HTTP_STATUS" 200
    if [[ "$(jq -er '.status' "$response")" != "revoked" ]]; then
      revision="$(jq -er '.revision' "$response")"
      body="$WORK/cleanup-t2-ssf-revoke.json"
      jq -n --argjson expected_revision "$revision" \
        '{expected_revision:$expected_revision}' >"$body"
      http_request cleanup-t2-ssf-revoke POST \
        "$(issuer t2)/admin/ssf/streams/$stream/revoke" \
        "$token" json "$body" "$RESPONSES/cleanup-t2-ssf-revoke.json"
      expect_status "revoke owned t2 SSF stream" "$HTTP_STATUS" 200
    fi
  fi
  for tenant in t1 t2; do
    if [[ "$tenant" == "t2" && -s "$STATE_DIR/offboarding-job.json" ]]; then
      job="$(jq -er '.job_id' "$STATE_DIR/offboarding-job.json")"
      poll_offboarding_job "$job"
      continue
    fi
    token="$(admin_token "$tenant")"
    user="$(jq -er ".users.$tenant" "$FIXTURES")"
    response="$RESPONSES/cleanup-$tenant-user.json"
    http_request "cleanup-$tenant-user" GET \
      "$(issuer "$tenant")/admin/data-governance/users/$user/export" \
      "$token" governance "" "$response"
    if [[ "$HTTP_STATUS" == "404" ]]; then
      continue
    fi
    expect_status "inspect owned $tenant fixture" "$HTTP_STATUS" 200
    http_request "cleanup-$tenant-erasure" POST \
      "$(issuer "$tenant")/admin/data-governance/users/$user/erasure" \
      "$token" governance "" "$RESPONSES/cleanup-$tenant-erasure.json"
    expect_status "erase owned $tenant fixture" "$HTTP_STATUS" 202
    poll_tenant_job "$tenant" \
      "$(jq -er '.job_id' "$RESPONSES/cleanup-$tenant-erasure.json")" \
      "$token" "cleanup-$tenant"
  done
  mark_done cleanup
  pass "owned fixtures reached durable erasure/offboarding state"
}

case "$ACTION" in
  status|adopt-deployment)
    show_status
    exit 0
    ;;
  cleanup)
    cleanup_owned_fixtures
    exit 0
    ;;
esac

info "RUN_ID=$RUN_ID"
is_done cleanup &&
  fail "RUN_ID=$RUN_ID was cleaned up and cannot resume a destructive run"
if ! is_done fixtures; then
  create_fixtures
fi
if ! is_done exports; then
  validate_exports_and_isolation
fi
if ! is_done user-erasure-started; then
  exercise_legal_hold_and_start_erasure
fi
if [[ "$INJECT_RETRY_INTERRUPTION" == "1" ]] &&
  ! is_done retry-interruption-injected; then
  mark_done retry-interruption-injected
  info "injected idempotent retry and process interruption"
  info "resume with RUN_ID=$RUN_ID and the same profile/Region/confirmation"
  exit 75
fi
is_done retry-interruption-injected ||
  fail "qualifying drill requires INJECT_RETRY_INTERRUPTION=1"

if ! is_done user-erasure-primary; then
  poll_tenant_job t1 \
    "$(jq -er '.job_id' "$STATE_DIR/user-erasure-job.json")" \
    "$(admin_token t1)" t1-erasure
  mark_done user-erasure-primary
  pass "t1 user erasure reached durable retention state after restart"
fi
if ! is_done ssf-fixture; then
  [[ ! -s "$STATE_DIR/offboarding-job.json" ]] ||
    fail "offboarding started before the RUN_ID-owned SSF fixture was persisted"
  create_ssf_fixture
fi
if ! is_done offboarding-started; then
  start_offboarding
fi
if ! is_done offboarding-primary; then
  poll_offboarding_job "$(jq -er '.job_id' "$STATE_DIR/offboarding-job.json")"
  mark_done offboarding-primary
  pass "t2 offboarding reached durable retention state"
fi
if ! is_done cloud-verified; then
  verify_cloud_resources
fi
if ! is_done service-evidence-verified; then
  fetch_service_evidence
  verify_service_evidence
fi
if ! is_done queues-verified; then
  verify_queues
  mark_done queues-verified
fi
if ! is_done complete; then
  write_final_evidence
fi
show_status
