#!/usr/bin/env bash
# Real AWS acceptance for issue #16 admin break-glass credential rotation.
#
# Default mode verifies the deployed source-to-target migration, IAM source deny,
# Secrets Manager stages, and the platform/t1/t2 Host matrix without changing a
# credential. MUTATE=1 additionally performs disposable Secrets Manager CAS
# fault injection, live overlap, checkpoint interruption/concurrency, rollback,
# retirement, delayed-activation rejection, cold-start recovery, and redaction.
#
# Deployed rotation acceptance:
#   set -a; source .env; set +a
#   MUTATE=1 ./e2e/admin_credential_rotation.sh
set -euo pipefail
set +x

PROFILE="${PROFILE:-default}"
REGION="${REGION:-us-east-1}"
DEV_STACK="${DEV_STACK:-AgentAuthDev}"
SAAS_STACK="${SAAS_STACK:-AgentAuthSaas}"
CACHE_TTL="${CACHE_TTL:-30}"
NEXT_LIFETIME_SECS="${NEXT_LIFETIME_SECS:-7776000}"
MUTATE="${MUTATE:-0}"
CONCURRENT_REQUESTS="${CONCURRENT_REQUESTS:-16}"
EXPECTED_TENANTS="${EXPECTED_TENANTS:-t1,t2}"
LEGACY_TENANT_SOURCE_ARNS_JSON="${LEGACY_TENANT_SOURCE_ARNS_JSON:-}"
if [[ -z "$LEGACY_TENANT_SOURCE_ARNS_JSON" ]]; then
  if [[ -n "${SAAS_TENANT_ADMIN_SECRET_ARNS:-}" ]]; then
    LEGACY_TENANT_SOURCE_ARNS_JSON="$SAAS_TENANT_ADMIN_SECRET_ARNS"
  else
    LEGACY_TENANT_SOURCE_ARNS_JSON='{}'
  fi
fi

umask 077
WORK="$(mktemp -d)"
MUTATION_STARTED=0
DISPOSABLE_SECRET=""
COLD_FUNCTION=""
COLD_VERSION=""
COLD_DESCRIPTION=""
COLD_ORIGINAL_DESCRIPTION=""
COLD_SOURCE_CODE_SHA256=""
COLD_SOURCE_MARKER=""
COLD_DESCRIPTION_CHANGED=0
LAST_TEMP_STAGE_INDEX=""
NEXT_TEMP_STAGE_INDEX=0
declare -a ACTIVE_PIDS=()
declare -a TEMP_STAGE_SECRETS=()
declare -a TEMP_STAGE_NAMES=()
declare -a TEMP_STAGE_VERSIONS=()

cleanup() {
  local status="$?"
  local cleanup_failed=0
  trap - EXIT INT TERM
  set +e
  if (( ${#ACTIVE_PIDS[@]} > 0 )); then
    wait "${ACTIVE_PIDS[@]}" >/dev/null 2>&1 || true
    ACTIVE_PIDS=()
  fi
  if (( ${#TEMP_STAGE_SECRETS[@]} > 0 )); then
    cleanup_tracked_temp_stages || cleanup_failed=1
  fi
  if [[ "$status" -ne 0 && "$MUTATION_STARTED" == "1" ]]; then
    printf 'RECOVERY: finalizing every unfinished owner to its generated next credential\n' >&2
    local owner checkpoint_state recovered_at recovery_one recovery_two
    local recovery_failed=0 recovered_any=0
    recovered_at="$(date +%s)"
    for owner in platform t1 t2; do
      if [[ "${OWNER_FINAL[$owner]:-0}" == "1" ]]; then
        remove_stage_if_present "$owner" AGENTAUTH_ROLLBACK_PENDING ||
          recovery_failed=1
        continue
      fi
      owner_has_committed_single_current "$owner"
      checkpoint_state="$?"
      if [[ "$checkpoint_state" == "0" ]]; then
        remove_stage_if_present "$owner" AGENTAUTH_ROLLBACK_PENDING ||
          recovery_failed=1
        OWNER_FINAL["$owner"]=1
        continue
      elif [[ "$checkpoint_state" == "2" ]]; then
        recovery_failed=1
        continue
      fi
      if ! freeze_owner_checkpoint "$owner"; then
        recovery_failed=1
        continue
      fi
      owner_has_committed_single_current "$owner"
      checkpoint_state="$?"
      if [[ "$checkpoint_state" == "0" ]]; then
        remove_stage_if_present "$owner" AGENTAUTH_ROLLBACK_PENDING ||
          recovery_failed=1
        OWNER_FINAL["$owner"]=1
        continue
      elif [[ "$checkpoint_state" == "2" ]]; then
        recovery_failed=1
        continue
      fi
      recovery_one="$(prepare_promotion "$owner" "$recovered_at" 1000)"
      recovery_two="$(prepare_promotion "$owner" "$recovered_at" 1001)"
      if put_current_document "$owner" "$recovery_one" >/dev/null &&
        put_current_document "$owner" "$recovery_two" >/dev/null; then
        RECOVERED_OWNER["$owner"]=1
        recovered_any=1
      else
        recovery_failed=1
      fi
    done
    if [[ "$recovered_any" == "1" ]]; then
      for owner in platform t1 t2; do
        if [[ "${RECOVERED_OWNER[$owner]:-0}" == "1" ]]; then
          remove_stage_if_present "$owner" AGENTAUTH_ROLLBACK_PENDING ||
            recovery_failed=1
        fi
      done
      sleep_for_cache
      for owner in platform t1 t2; do
        if [[ "${RECOVERED_OWNER[$owner]:-0}" == "1" ]]; then
          if [[ "$(request_status "$owner" "${NEXT_TOKEN[$owner]}")" != "200" ]]; then
            printf 'RECOVERY FAILED: %s next credential is not accepted\n' "$owner" >&2
            recovery_failed=1
          fi
          if [[ "$(request_status "$owner" "${CURRENT_TOKEN[$owner]}")" != "401" ]]; then
            printf 'RECOVERY FAILED: %s old credential is still accepted\n' "$owner" >&2
            recovery_failed=1
          fi
        fi
      done
    fi
    if [[ "$recovery_failed" == "1" ]]; then
      printf 'RECOVERY INCOMPLETE: inspect platform/t1/t2 targets before retrying\n' >&2
    fi
  fi
  if (( ${#TEMP_STAGE_SECRETS[@]} > 0 )); then
    cleanup_tracked_temp_stages || cleanup_failed=1
  fi
  if [[ "$COLD_DESCRIPTION_CHANGED" == "1" ]]; then
    restore_cold_source_description || cleanup_failed=1
  fi
  if [[ -n "$COLD_FUNCTION" && -n "$COLD_DESCRIPTION" ]]; then
    delete_cold_versions || cleanup_failed=1
  fi
  if [[ -n "$DISPOSABLE_SECRET" ]]; then
    delete_disposable_secret || cleanup_failed=1
  fi
  if [[ "$cleanup_failed" == "1" ]]; then
    printf 'CLEANUP FAILED: inspect disposable Secret/Lambda version resources\n' >&2
    [[ "$status" -ne 0 ]] || status=1
  fi
  rm -rf "$WORK"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
require() { command -v "$1" >/dev/null || fail "missing command: $1"; }
for command in aws curl jq openssl sha256sum date tr awk grep; do
  require "$command"
done

[[ "$CACHE_TTL" =~ ^[1-9][0-9]*$ ]] || fail "CACHE_TTL must be a positive integer"
[[ "$CONCURRENT_REQUESTS" =~ ^[1-9][0-9]*$ ]] ||
  fail "CONCURRENT_REQUESTS must be a positive integer"
(( CONCURRENT_REQUESTS >= 2 && CONCURRENT_REQUESTS <= 64 )) ||
  fail "CONCURRENT_REQUESTS must be between 2 and 64"
[[ "$NEXT_LIFETIME_SECS" =~ ^[1-9][0-9]*$ ]] ||
  fail "NEXT_LIFETIME_SECS must be a positive integer"
(( NEXT_LIFETIME_SECS <= 400 * 24 * 60 * 60 )) ||
  fail "NEXT_LIFETIME_SECS must not exceed 400 days"
jq -e 'type == "object"' <<<"$LEGACY_TENANT_SOURCE_ARNS_JSON" >/dev/null ||
  fail "LEGACY_TENANT_SOURCE_ARNS_JSON must be a JSON object"

declare -A ARN BASE PATH_PART RESPONSE DOC CURRENT_TOKEN NEXT_TOKEN VERSION
declare -A ROTATION_DOC ROTATION_VERSION ATTACK_VERSION OWNER_FINAL RECOVERED_OWNER
LAST_VERSION=""

stack_output() {
  local stack="$1" key="$2"
  aws cloudformation describe-stacks \
    --stack-name "$stack" --profile "$PROFILE" --region "$REGION" \
    --query "Stacks[0].Outputs[?OutputKey=='$key'].OutputValue | [0]" \
    --output text
}

request_status() {
  local endpoint_owner="$1" token_file="$2"
  local header_file="$WORK/header-${endpoint_owner}-${RANDOM}"
  printf 'authorization: Bearer %s\n' "$(<"$token_file")" >"$header_file"
  curl -sS -o /dev/null -w '%{http_code}' \
    --connect-timeout 5 --max-time 20 \
    -H "@$header_file" "${BASE[$endpoint_owner]}${PATH_PART[$endpoint_owner]}"
  rm -f "$header_file"
}

request_body() {
  local endpoint_owner="$1" token_file="$2" output="$3"
  local header_file="$WORK/header-${endpoint_owner}-${RANDOM}"
  printf 'authorization: Bearer %s\n' "$(<"$token_file")" >"$header_file"
  curl -fsS --connect-timeout 5 --max-time 20 -H "@$header_file" \
    "${BASE[$endpoint_owner]}${PATH_PART[$endpoint_owner]}" >"$output"
  rm -f "$header_file"
}

expect_status() {
  local endpoint_owner="$1" token_file="$2" expected="$3" label="$4"
  local actual
  actual="$(request_status "$endpoint_owner" "$token_file")"
  [[ "$actual" == "$expected" ]] ||
    fail "$label expected HTTP $expected, got $actual"
}

expect_eventual_status() {
  local endpoint_owner="$1" token_file="$2" expected="$3" label="$4"
  local actual attempt
  for ((attempt = 1; attempt <= 15; attempt++)); do
    if actual="$(request_status "$endpoint_owner" "$token_file")"; then
      [[ "$actual" == "$expected" ]] && return 0
      [[ "$actual" == "503" ]] ||
        fail "$label expected HTTP $expected or transient 503, got $actual"
    fi
    sleep 2
  done
  fail "$label did not converge to HTTP $expected within 30 seconds"
}

created_epoch() {
  local value="$1"
  if [[ "$value" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    printf '%s\n' "${value%%.*}"
  else
    date -u -d "$value" +%s
  fi
}

load_owner() {
  local owner="$1" arn="$2" base="$3" path="$4"
  local response="$WORK/${owner}-secret.json"
  local raw_doc="$WORK/${owner}-raw.json"
  local expanded="$WORK/${owner}-current.json"
  local token="$WORK/${owner}-current-token"

  aws secretsmanager get-secret-value \
    --secret-id "$arn" --profile "$PROFILE" --region "$REGION" \
    --output json >"$response"
  jq -er '.SecretString | fromjson' "$response" >"$raw_doc"
  local created
  created="$(created_epoch "$(jq -er '.CreatedDate' "$response")")"
  jq --argjson created "$created" '
    if .revision == 1 and (.current.ttl_seconds | type == "number") then
      .current |= (
        .created_at = $created
        | .not_before = $created
        | .expires_at = ($created + .ttl_seconds)
        | del(.ttl_seconds)
      )
    else
      .
    end
  ' "$raw_doc" >"$expanded"
  jq -jr '.current.secret' "$expanded" >"$token"
  chmod 0600 "$response" "$raw_doc" "$expanded" "$token"

  ARN["$owner"]="$arn"
  BASE["$owner"]="${base%/}"
  PATH_PART["$owner"]="$path"
  RESPONSE["$owner"]="$response"
  DOC["$owner"]="$expanded"
  CURRENT_TOKEN["$owner"]="$token"
  VERSION["$owner"]="$(jq -er '.VersionId' "$response")"
}

current_version_id() {
  aws secretsmanager get-secret-value \
    --secret-id "${ARN[$1]}" --profile "$PROFILE" --region "$REGION" \
    --query VersionId --output text
}

remove_stage_if_present() {
  local owner="$1" stage="$2"
  local description="$WORK/${owner}-${stage}.json"
  local version
  aws secretsmanager describe-secret \
    --secret-id "${ARN[$owner]}" --profile "$PROFILE" --region "$REGION" \
    --output json >"$description" || return 1
  version="$(jq -r --arg stage "$stage" '
    .VersionIdsToStages
    | to_entries[]
    | select(.value | index($stage))
    | .key
  ' "$description" | head -n 1)"
  if [[ -n "$version" ]]; then
    aws secretsmanager update-secret-version-stage \
      --secret-id "${ARN[$owner]}" \
      --version-stage "$stage" \
      --remove-from-version-id "$version" \
      --profile "$PROFILE" --region "$REGION" >/dev/null
  fi
}

freeze_owner_checkpoint() {
  local owner="$1"
  local before="$WORK/${owner}-freeze-before.json"
  local after="$WORK/${owner}-freeze-after.json"
  local current previous validated pending lock
  aws secretsmanager describe-secret \
    --secret-id "${ARN[$owner]}" --profile "$PROFILE" --region "$REGION" \
    --output json >"$before" || return 1
  current="$(jq -er '
    [.VersionIdsToStages | to_entries[] | select(.value | index("AWSCURRENT")) | .key]
    | select(length == 1) | .[0]
  ' "$before")" || return 1
  previous="$(jq -r '
    [.VersionIdsToStages | to_entries[] | select(.value | index("AWSPREVIOUS")) | .key]
    | if length == 1 then .[0] else "" end
  ' "$before")" || return 1
  validated="$(jq -er '
    [
      .VersionIdsToStages
      | to_entries[]
      | select(.value | index("AGENTAUTH_VALIDATED"))
      | .key
    ]
    | select(length == 1)
    | .[0]
  ' "$before")" || return 1
  pending="$(jq -r '
    [
      .VersionIdsToStages
      | to_entries[]
      | select(.value | index("AGENTAUTH_ROLLBACK_PENDING"))
      | .key
    ]
    | if length == 1 then .[0] else "" end
  ' "$before")" || return 1
  if [[ "$validated" != "$current" ]]; then
    lock="$validated"
  elif [[ -n "$previous" && "$previous" != "$current" ]]; then
    lock="$previous"
  else
    return 1
  fi
  if [[ "$pending" != "$lock" ]]; then
    if [[ -n "$pending" ]]; then
      aws secretsmanager update-secret-version-stage \
        --secret-id "${ARN[$owner]}" \
        --version-stage AGENTAUTH_ROLLBACK_PENDING \
        --move-to-version-id "$lock" \
        --remove-from-version-id "$pending" \
        --profile "$PROFILE" --region "$REGION" >/dev/null 2>&1 || true
    else
      attach_stage "${ARN[$owner]}" AGENTAUTH_ROLLBACK_PENDING "$lock" ||
        return 1
    fi
  fi
  [[ "$(stage_version_id "${ARN[$owner]}" AGENTAUTH_ROLLBACK_PENDING)" == "$lock" ]] ||
    return 1
  sleep 12
  aws secretsmanager describe-secret \
    --secret-id "${ARN[$owner]}" --profile "$PROFILE" --region "$REGION" \
    --output json >"$after" || return 1
  jq -e --arg current "$current" --arg lock "$lock" '
    [
      .VersionIdsToStages
      | to_entries[]
      | select(.value | index("AWSCURRENT"))
      | .key
    ] == [$current]
    and [
      .VersionIdsToStages
      | to_entries[]
      | select(.value | index("AGENTAUTH_ROLLBACK_PENDING"))
      | .key
    ] == [$lock]
  ' "$after" >/dev/null
}

owner_has_committed_single_current() {
  local owner="$1"
  local description="$WORK/${owner}-cleanup-checkpoint.json"
  local response="$WORK/${owner}-cleanup-current-response.json"
  local document="$WORK/${owner}-cleanup-current.json"
  local created current validated shape
  aws secretsmanager describe-secret \
    --secret-id "${ARN[$owner]}" --profile "$PROFILE" --region "$REGION" \
    --output json >"$description" || return 2
  current="$(jq -er '
    [
      .VersionIdsToStages
      | to_entries[]
      | select(.value | index("AWSCURRENT"))
      | .key
    ]
    | select(length == 1)
    | .[0]
  ' "$description")" || return 2
  validated="$(jq -er '
    [
      .VersionIdsToStages
      | to_entries[]
      | select(.value | index("AGENTAUTH_VALIDATED"))
      | .key
    ]
    | select(length == 1)
    | .[0]
  ' "$description")" || return 2
  [[ "$current" == "$validated" ]] || return 1
  aws secretsmanager get-secret-value \
    --secret-id "${ARN[$owner]}" --version-id "$current" \
    --profile "$PROFILE" --region "$REGION" \
    --output json >"$response" || return 2
  jq -er '.SecretString | fromjson' "$response" >"$document" || return 2
  created="$(created_epoch "$(jq -er '.CreatedDate' "$response")")" || return 2
  shape="$(jq -er '
    if .next == null and .rotation == null then
      "single"
    elif .next != null and .rotation != null then
      "rotating"
    else
      error("inconsistent next/rotation")
    end
  ' "$document")" || return 2
  [[ "$shape" == "single" ]] || return 1
  if jq -e --argjson now "$(date +%s)" --argjson created "$created" '
      (.current | type) == "object"
      and (
        if (.current.expires_at | type) == "number" then
          (.current.not_before | type) == "number"
          and .current.not_before <= $now
          and $now < .current.expires_at
        else
          (.current.ttl_seconds | type) == "number"
          and .current.ttl_seconds > 0
          and $created <= $now
          and $now < ($created + .current.ttl_seconds)
        end
      )
    ' "$document" >/dev/null; then
    return 0
  fi
  return 2
}

stage_version_id() {
  local secret_id="$1" stage="$2"
  aws secretsmanager describe-secret \
    --secret-id "$secret_id" --profile "$PROFILE" --region "$REGION" \
    --query VersionIdsToStages --output json |
    jq -er --arg stage "$stage" '
      [
        to_entries[]
        | select(.value | index($stage))
        | .key
      ]
      | select(length == 1)
      | .[0]
    '
}

expect_stage_version() {
  local secret_id="$1" stage="$2" expected="$3" label="$4"
  local actual
  actual="$(stage_version_id "$secret_id" "$stage")" ||
    fail "$label has no unique $stage stage"
  [[ "$actual" == "$expected" ]] ||
    fail "$label expected $stage on $expected, got $actual"
}

expect_stage_absent() {
  local secret_id="$1" stage="$2" label="$3"
  local count
  count="$(aws secretsmanager describe-secret \
    --secret-id "$secret_id" --profile "$PROFILE" --region "$REGION" \
    --query VersionIdsToStages --output json |
    jq -r --arg stage "$stage" '
      [
        to_entries[]
        | select(.value | index($stage))
      ]
      | length
    ')"
  [[ "$count" == "0" ]] || fail "$label still has $stage"
}

attach_stage() {
  local secret_id="$1" stage="$2" version="$3"
  aws secretsmanager update-secret-version-stage \
    --secret-id "$secret_id" \
    --version-stage "$stage" \
    --move-to-version-id "$version" \
    --profile "$PROFILE" --region "$REGION" >/dev/null
}

expect_current_validated() {
  local owner="$1"
  local description="$WORK/${owner}-description.json"
  local version
  version="$(current_version_id "$owner")"
  aws secretsmanager describe-secret \
    --secret-id "${ARN[$owner]}" --profile "$PROFILE" --region "$REGION" \
    --output json >"$description"
  jq -e --arg version "$version" '
    (.VersionIdsToStages[$version] // []) as $stages
    | ($stages | index("AWSCURRENT")) != null
      and ($stages | index("AGENTAUTH_VALIDATED")) != null
      and (
        [
          .VersionIdsToStages[]
          | select(index("AGENTAUTH_ROLLBACK_PENDING"))
        ]
        | length == 0
      )
  ' "$description" >/dev/null ||
    fail "$owner current version is not finalized AWSCURRENT + AGENTAUTH_VALIDATED"
}

discover_legacy_platform_source() {
  local stack="$1"
  local resources="$WORK/${stack}-resources.json"
  aws cloudformation list-stack-resources \
    --stack-name "$stack" --profile "$PROFILE" --region "$REGION" \
    --output json >"$resources"
  local secret description
  while IFS= read -r secret; do
    description="$(aws secretsmanager describe-secret \
      --secret-id "$secret" --profile "$PROFILE" --region "$REGION" \
      --query Description --output text)"
    if [[ "$description" == *"rollback source"* ]]; then
      printf '%s\n' "$secret"
      return 0
    fi
  done < <(
    jq -r '.StackResourceSummaries[]
      | select(.ResourceType == "AWS::SecretsManager::Secret")
      | .PhysicalResourceId' "$resources"
  )
  return 1
}

auth_function_name() {
  local stack="$1"
  local resources="$WORK/${stack}-lambda-resources.json"
  aws cloudformation list-stack-resources \
    --stack-name "$stack" --profile "$PROFILE" --region "$REGION" \
    --output json >"$resources"
  jq -er '.StackResourceSummaries[]
    | select(
        .ResourceType == "AWS::Lambda::Function"
        and (.LogicalResourceId | startswith("AuthFn"))
      )
    | .PhysicalResourceId' "$resources" | head -n 1
}

auth_role_arn() {
  local stack="$1"
  local function_name
  function_name="$(auth_function_name "$stack")"
  aws lambda get-function-configuration \
    --function-name "$function_name" --profile "$PROFILE" --region "$REGION" \
    --query Role --output text
}

expect_explicit_source_deny() {
  local role_arn="$1" source_arn="$2" label="$3"
  local decision
  decision="$(aws iam simulate-principal-policy \
    --policy-source-arn "$role_arn" \
    --action-names secretsmanager:GetSecretValue secretsmanager:DescribeSecret \
    --resource-arns "$source_arn" \
    --profile "$PROFILE" --region "$REGION" \
    --query 'EvaluationResults[].EvalDecision' --output text)"
  [[ "$decision" == *"explicitDeny"* ]] ||
    fail "$label is not explicitly denied to the current AuthFn role"
}

expect_concurrent_statuses() {
  local endpoint_owner="$1" token_file="$2" allowed="$3" label="$4"
  local i pid status failure=""
  ACTIVE_PIDS=()
  for ((i = 0; i < CONCURRENT_REQUESTS; i++)); do
    (
      request_status "$endpoint_owner" "$token_file" \
        >"$WORK/concurrent-${endpoint_owner}-${i}.status"
    ) &
    ACTIVE_PIDS+=("$!")
  done
  for i in "${!ACTIVE_PIDS[@]}"; do
    pid="${ACTIVE_PIDS[$i]}"
    if ! wait "$pid"; then
      unset 'ACTIVE_PIDS[i]'
      failure="${failure}${label} request ${i} failed before returning an HTTP status; "
      continue
    fi
    unset 'ACTIVE_PIDS[i]'
    status="$(<"$WORK/concurrent-${endpoint_owner}-${i}.status")"
    case " $allowed " in
      *" $status "*) ;;
      *)
        failure="${failure}${label} request ${i} returned HTTP ${status}; allowed: ${allowed}; "
        ;;
    esac
  done
  ACTIVE_PIDS=()
  [[ -z "$failure" ]] || fail "$failure"
}

stage_is_absent() {
  local secret_id="$1" stage="$2"
  aws secretsmanager describe-secret \
    --secret-id "$secret_id" --profile "$PROFILE" --region "$REGION" \
    --query VersionIdsToStages --output json |
    jq -e --arg stage "$stage" '
      [
        to_entries[]
        | select(.value | index($stage))
      ]
      | length == 0
    ' >/dev/null
}

remove_exact_stage() {
  local secret_id="$1" stage="$2" version="$3"
  local attempt
  for attempt in 1 2 3; do
    aws secretsmanager update-secret-version-stage \
      --secret-id "$secret_id" \
      --version-stage "$stage" \
      --remove-from-version-id "$version" \
      --profile "$PROFILE" --region "$REGION" >/dev/null 2>&1 || true
    stage_is_absent "$secret_id" "$stage" && return 0
    sleep 1
  done
  return 1
}

track_temp_stage() {
  LAST_TEMP_STAGE_INDEX="$NEXT_TEMP_STAGE_INDEX"
  NEXT_TEMP_STAGE_INDEX=$((NEXT_TEMP_STAGE_INDEX + 1))
  TEMP_STAGE_SECRETS["$LAST_TEMP_STAGE_INDEX"]="$1"
  TEMP_STAGE_NAMES["$LAST_TEMP_STAGE_INDEX"]="$2"
  TEMP_STAGE_VERSIONS["$LAST_TEMP_STAGE_INDEX"]="$3"
}

remove_tracked_temp_stage() {
  local index="$1"
  [[ -n "${TEMP_STAGE_SECRETS[$index]+present}" ]] || return 0
  remove_exact_stage \
    "${TEMP_STAGE_SECRETS[$index]}" \
    "${TEMP_STAGE_NAMES[$index]}" \
    "${TEMP_STAGE_VERSIONS[$index]}" || return 1
  unset 'TEMP_STAGE_SECRETS[index]'
  unset 'TEMP_STAGE_NAMES[index]'
  unset 'TEMP_STAGE_VERSIONS[index]'
}

cleanup_tracked_temp_stages() {
  local index failed=0
  for index in "${!TEMP_STAGE_SECRETS[@]}"; do
    remove_tracked_temp_stage "$index" || failed=1
  done
  [[ "$failed" == "0" ]]
}

delete_disposable_secret() {
  local deleted_at state
  if deleted_at="$(aws secretsmanager delete-secret \
    --secret-id "$DISPOSABLE_SECRET" --force-delete-without-recovery \
    --profile "$PROFILE" --region "$REGION" \
    --query DeletionDate --output text 2>"$WORK/disposable-delete.err")"; then
    [[ -n "$deleted_at" && "$deleted_at" != "None" ]] || return 1
  else
    state="$(aws secretsmanager list-secrets \
      --include-planned-deletion \
      --filters Key=name,Values="$DISPOSABLE_SECRET" \
      --profile "$PROFILE" --region "$REGION" \
      --query "SecretList[?Name=='$DISPOSABLE_SECRET'].{Name:Name,DeletedDate:DeletedDate}" \
      --output json)" || return 1
    jq -e 'length == 0 or all(.DeletedDate != null)' <<<"$state" >/dev/null || return 1
  fi
  DISPOSABLE_SECRET=""
}

restore_cold_source_description() {
  local current current_description current_revision current_code restored
  current="$(aws lambda get-function-configuration \
    --function-name "$COLD_FUNCTION" \
    --profile "$PROFILE" --region "$REGION" \
    --query '{Description:Description,RevisionId:RevisionId,CodeSha256:CodeSha256}' \
    --output json)" || return 1
  current_description="$(jq -r '.Description // ""' <<<"$current")"
  current_revision="$(jq -er '.RevisionId' <<<"$current")" || return 1
  current_code="$(jq -er '.CodeSha256' <<<"$current")" || return 1
  if [[ "$current_description" == "$COLD_ORIGINAL_DESCRIPTION" ]]; then
    COLD_DESCRIPTION_CHANGED=0
    [[ "$current_code" == "$COLD_SOURCE_CODE_SHA256" ]]
    return
  fi
  if [[ "$current_description" != "$COLD_SOURCE_MARKER" ||
    "$current_code" != "$COLD_SOURCE_CODE_SHA256" ]]; then
    COLD_DESCRIPTION_CHANGED=0
    return 1
  fi
  aws lambda update-function-configuration \
    --function-name "$COLD_FUNCTION" \
    --description "$COLD_ORIGINAL_DESCRIPTION" \
    --revision-id "$current_revision" \
    --profile "$PROFILE" --region "$REGION" \
    --query RevisionId --output text >/dev/null || return 1
  aws lambda wait function-active-v2 \
    --function-name "$COLD_FUNCTION" \
    --profile "$PROFILE" --region "$REGION" || return 1
  restored="$(aws lambda get-function-configuration \
    --function-name "$COLD_FUNCTION" \
    --profile "$PROFILE" --region "$REGION" \
    --query '{Description:Description,CodeSha256:CodeSha256}' \
    --output json)" || return 1
  [[ "$(jq -r '.Description // ""' <<<"$restored")" == "$COLD_ORIGINAL_DESCRIPTION" &&
    "$(jq -er '.CodeSha256' <<<"$restored")" == "$COLD_SOURCE_CODE_SHA256" ]] ||
    return 1
  COLD_DESCRIPTION_CHANGED=0
}

delete_cold_versions() {
  local versions remaining version
  versions="$(aws lambda list-versions-by-function \
    --function-name "$COLD_FUNCTION" \
    --profile "$PROFILE" --region "$REGION" \
    --query "Versions[?Description=='$COLD_DESCRIPTION'].Version" \
    --output text)" || return 1
  for version in $versions; do
    [[ "$version" == '$LATEST' ]] && continue
    if ! aws lambda delete-function \
      --function-name "$COLD_FUNCTION" --qualifier "$version" \
      --profile "$PROFILE" --region "$REGION" \
      >"$WORK/cold-delete-${version}.out" 2>"$WORK/cold-delete-${version}.err"; then
      remaining="$(aws lambda list-versions-by-function \
        --function-name "$COLD_FUNCTION" \
        --profile "$PROFILE" --region "$REGION" \
        --query "length(Versions[?Version=='$version'])" \
        --output text)" || return 1
      [[ "$remaining" == "0" ]] || return 1
    fi
  done
  remaining="$(aws lambda list-versions-by-function \
    --function-name "$COLD_FUNCTION" \
    --profile "$PROFILE" --region "$REGION" \
    --query "length(Versions[?Description=='$COLD_DESCRIPTION' && Version!='\$LATEST'])" \
    --output text)" || return 1
  [[ "$remaining" == "0" ]] || return 1
  COLD_VERSION=""
  COLD_DESCRIPTION=""
}

prepare_cold_version() {
  local run_id source source_revision marker marker_revision marker_code
  run_id="$(date +%s)-$$-$RANDOM"
  COLD_FUNCTION="$(auth_function_name "$SAAS_STACK")"
  COLD_DESCRIPTION="Disposable issue 16 cold-start acceptance $run_id"
  COLD_SOURCE_MARKER="agent-auth issue 16 acceptance source $run_id"
  source="$(aws lambda get-function-configuration \
    --function-name "$COLD_FUNCTION" \
    --profile "$PROFILE" --region "$REGION" \
    --query '{Description:Description,RevisionId:RevisionId,CodeSha256:CodeSha256}' \
    --output json)" || return 1
  COLD_ORIGINAL_DESCRIPTION="$(jq -r '.Description // ""' <<<"$source")"
  source_revision="$(jq -er '.RevisionId' <<<"$source")" || return 1
  COLD_SOURCE_CODE_SHA256="$(jq -er '.CodeSha256' <<<"$source")" || return 1
  if COLD_VERSION="$(aws lambda publish-version \
    --function-name "$COLD_FUNCTION" \
    --description "$COLD_DESCRIPTION" \
    --code-sha256 "$COLD_SOURCE_CODE_SHA256" \
    --revision-id "$source_revision" \
    --profile "$PROFILE" --region "$REGION" \
    --query Version --output text \
    2>"$WORK/cold-publish-initial.err")"; then
    :
  else
    grep -Fq 'are not changed from the last published version' \
      "$WORK/cold-publish-initial.err" || return 1
    COLD_DESCRIPTION_CHANGED=1
    marker_revision="$(aws lambda update-function-configuration \
      --function-name "$COLD_FUNCTION" \
      --description "$COLD_SOURCE_MARKER" \
      --revision-id "$source_revision" \
      --profile "$PROFILE" --region "$REGION" \
      --query RevisionId --output text)" || return 1
    aws lambda wait function-active-v2 \
      --function-name "$COLD_FUNCTION" \
      --profile "$PROFILE" --region "$REGION" || return 1
    marker="$(aws lambda get-function-configuration \
      --function-name "$COLD_FUNCTION" \
      --profile "$PROFILE" --region "$REGION" \
      --query '{Description:Description,RevisionId:RevisionId,CodeSha256:CodeSha256}' \
      --output json)" || return 1
    [[ "$(jq -r '.Description // ""' <<<"$marker")" == "$COLD_SOURCE_MARKER" ]] ||
      return 1
    marker_revision="$(jq -er '.RevisionId' <<<"$marker")" || return 1
    marker_code="$(jq -er '.CodeSha256' <<<"$marker")" || return 1
    [[ "$marker_code" == "$COLD_SOURCE_CODE_SHA256" ]] || return 1
    COLD_VERSION="$(aws lambda publish-version \
      --function-name "$COLD_FUNCTION" \
      --description "$COLD_DESCRIPTION" \
      --code-sha256 "$marker_code" \
      --revision-id "$marker_revision" \
      --profile "$PROFILE" --region "$REGION" \
      --query Version --output text)" || return 1
    restore_cold_source_description || return 1
  fi
  [[ "$COLD_VERSION" =~ ^[1-9][0-9]*$ ]] || return 1
  aws lambda wait function-active-v2 \
    --function-name "$COLD_FUNCTION" --qualifier "$COLD_VERSION" \
    --profile "$PROFILE" --region "$REGION"
}

run_disposable_cas_acceptance() {
  local name initial candidate_a candidate_b winner loser
  local token_a token_b pid_a pid_b status_a status_b successes
  name="agent-auth/e2e/admin-credential-cas-$(date +%s)-$RANDOM"
  printf '{"fixture":"initial"}' >"$WORK/disposable-initial.json"
  printf '{"fixture":"candidate-a"}' >"$WORK/disposable-a.json"
  printf '{"fixture":"candidate-b"}' >"$WORK/disposable-b.json"
  token_a="$(openssl rand -hex 32)"
  token_b="$(openssl rand -hex 32)"

  DISPOSABLE_SECRET="$name"
  initial="$(aws secretsmanager create-secret \
    --name "$name" \
    --description "Disposable agent-auth issue 16 CAS acceptance" \
    --secret-string "file://$WORK/disposable-initial.json" \
    --tags Key=agent-auth-e2e,Value=admin-credential-cas \
    --profile "$PROFILE" --region "$REGION" \
    --query VersionId --output text)"
  candidate_a="$(aws secretsmanager put-secret-value \
    --secret-id "$DISPOSABLE_SECRET" \
    --secret-string "file://$WORK/disposable-a.json" \
    --client-request-token "$token_a" --version-stages E2E_CANDIDATE_A \
    --profile "$PROFILE" --region "$REGION" \
    --query VersionId --output text)"
  candidate_b="$(aws secretsmanager put-secret-value \
    --secret-id "$DISPOSABLE_SECRET" \
    --secret-string "file://$WORK/disposable-b.json" \
    --client-request-token "$token_b" --version-stages E2E_CANDIDATE_B \
    --profile "$PROFILE" --region "$REGION" \
    --query VersionId --output text)"
  attach_stage "$DISPOSABLE_SECRET" AGENTAUTH_VALIDATED "$initial"

  aws secretsmanager update-secret-version-stage \
    --secret-id "$DISPOSABLE_SECRET" --version-stage AWSCURRENT \
    --move-to-version-id "$candidate_a" --remove-from-version-id "$initial" \
    --cli-connect-timeout 5 --cli-read-timeout 20 \
    --profile "$PROFILE" --region "$REGION" \
    >"$WORK/disposable-race-a.out" 2>"$WORK/disposable-race-a.err" &
  pid_a="$!"
  aws secretsmanager update-secret-version-stage \
    --secret-id "$DISPOSABLE_SECRET" --version-stage AWSCURRENT \
    --move-to-version-id "$candidate_b" --remove-from-version-id "$initial" \
    --cli-connect-timeout 5 --cli-read-timeout 20 \
    --profile "$PROFILE" --region "$REGION" \
    >"$WORK/disposable-race-b.out" 2>"$WORK/disposable-race-b.err" &
  pid_b="$!"
  ACTIVE_PIDS=("$pid_a" "$pid_b")
  if wait "$pid_a"; then status_a=0; else status_a="$?"; fi
  unset 'ACTIVE_PIDS[0]'
  if wait "$pid_b"; then status_b=0; else status_b="$?"; fi
  unset 'ACTIVE_PIDS[1]'
  ACTIVE_PIDS=()
  successes=0
  [[ "$status_a" == "0" ]] && successes=$((successes + 1))
  [[ "$status_b" == "0" ]] && successes=$((successes + 1))
  [[ "$successes" == "1" ]] ||
    fail "disposable AWSCURRENT CAS race expected one winner, got $successes"

  winner="$(stage_version_id "$DISPOSABLE_SECRET" AWSCURRENT)"
  if [[ "$winner" == "$candidate_a" ]]; then
    loser="$candidate_b"
  elif [[ "$winner" == "$candidate_b" ]]; then
    loser="$candidate_a"
  else
    fail "disposable AWSCURRENT CAS race selected an unknown version"
  fi
  expect_stage_version "$DISPOSABLE_SECRET" AWSPREVIOUS "$initial" "disposable CAS"
  attach_stage "$DISPOSABLE_SECRET" AGENTAUTH_ROLLBACK_PENDING "$winner"
  aws secretsmanager update-secret-version-stage \
    --secret-id "$DISPOSABLE_SECRET" --version-stage AWSCURRENT \
    --move-to-version-id "$initial" --remove-from-version-id "$winner" \
    --profile "$PROFILE" --region "$REGION" >/dev/null
  aws secretsmanager update-secret-version-stage \
    --secret-id "$DISPOSABLE_SECRET" --version-stage AWSCURRENT \
    --move-to-version-id "$winner" --remove-from-version-id "$initial" \
    --profile "$PROFILE" --region "$REGION" >/dev/null
  expect_stage_version "$DISPOSABLE_SECRET" AWSCURRENT "$winner" "disposable ABA"
  expect_stage_version "$DISPOSABLE_SECRET" AWSPREVIOUS "$initial" "disposable ABA"
  expect_stage_version \
    "$DISPOSABLE_SECRET" AGENTAUTH_VALIDATED "$initial" "disposable ABA"
  aws secretsmanager update-secret-version-stage \
    --secret-id "$DISPOSABLE_SECRET" \
    --version-stage AGENTAUTH_VALIDATED \
    --move-to-version-id "$winner" \
    --remove-from-version-id "$initial" \
    --profile "$PROFILE" --region "$REGION" >/dev/null
  if aws secretsmanager update-secret-version-stage \
    --secret-id "$DISPOSABLE_SECRET" \
    --version-stage AGENTAUTH_VALIDATED \
    --move-to-version-id "$loser" \
    --remove-from-version-id "$initial" \
    --profile "$PROFILE" --region "$REGION" \
    >"$WORK/disposable-stale.out" 2>"$WORK/disposable-stale.err"; then
    fail "stale validated CAS unexpectedly replaced the committed checkpoint"
  fi
  expect_stage_version "$DISPOSABLE_SECRET" AWSCURRENT "$winner" "disposable checkpoint"
  expect_stage_version \
    "$DISPOSABLE_SECRET" AGENTAUTH_VALIDATED "$winner" "disposable checkpoint"
  expect_stage_version \
    "$DISPOSABLE_SECRET" AGENTAUTH_ROLLBACK_PENDING "$winner" "disposable checkpoint"
  aws secretsmanager update-secret-version-stage \
    --secret-id "$DISPOSABLE_SECRET" \
    --version-stage AGENTAUTH_ROLLBACK_PENDING \
    --remove-from-version-id "$winner" \
    --profile "$PROFILE" --region "$REGION" >/dev/null
  expect_stage_absent \
    "$DISPOSABLE_SECRET" AGENTAUTH_ROLLBACK_PENDING "disposable checkpoint"
  pass "disposable Secrets Manager current and validated CAS conflicts"
}

cold_request_status() {
  local endpoint_owner="$1" token_file="$2"
  local host payload response metadata
  host="${BASE[$endpoint_owner]#*://}"
  host="${host%%/*}"
  payload="$WORK/cold-${endpoint_owner}-${RANDOM}-payload.json"
  response="$WORK/cold-${endpoint_owner}-${RANDOM}-response.json"
  metadata="$WORK/cold-${endpoint_owner}-${RANDOM}-metadata.json"
  jq -n \
    --arg host "$host" \
    --arg path "${PATH_PART[$endpoint_owner]}" \
    --rawfile token "$token_file" \
    --argjson now "$(( $(date +%s) * 1000 ))" '
      {
        version: "2.0",
        routeKey: "$default",
        rawPath: $path,
        rawQueryString: "",
        headers: {
          authorization: ("Bearer " + $token),
          host: $host,
          "x-forwarded-proto": "https"
        },
        requestContext: {
          accountId: "e2e",
          apiId: "e2e",
          domainName: $host,
          domainPrefix: ($host | split(".")[0]),
          http: {
            method: "GET",
            path: $path,
            protocol: "HTTP/1.1",
            sourceIp: "127.0.0.1",
            userAgent: "agent-auth-admin-credential-e2e"
          },
          requestId: "e2e-cold-start",
          routeKey: "$default",
          stage: "$default",
          time: "28/Jul/2026:00:00:00 +0000",
          timeEpoch: $now
        },
        isBase64Encoded: false
      }
    ' >"$payload"
  chmod 0600 "$payload"
  aws lambda invoke \
    --function-name "$COLD_FUNCTION" --qualifier "$COLD_VERSION" \
    --cli-binary-format raw-in-base64-out \
    --payload "fileb://$payload" \
    --profile "$PROFILE" --region "$REGION" \
    "$response" >"$metadata"
  jq -e '.FunctionError == null' "$metadata" >/dev/null ||
    fail "cold-start invocation returned a Lambda function error"
  jq -er '.statusCode' "$response"
}

expect_cold_status() {
  local endpoint_owner="$1" token_file="$2" expected="$3" label="$4"
  local actual
  actual="$(cold_request_status "$endpoint_owner" "$token_file")"
  [[ "$actual" == "$expected" ]] ||
    fail "$label expected cold-start HTTP $expected, got $actual"
}

secret_hash() {
  aws secretsmanager get-secret-value \
    --secret-id "$1" --profile "$PROFILE" --region "$REGION" \
    --output json |
    jq -jr '.SecretString' |
    sha256sum | awk '{print $1}'
}

file_hash() {
  sha256sum "$1" | awk '{print $1}'
}

expect_source_in_target_history() {
  local owner="$1" source_arn="$2" label="$3"
  local source_hash current_hash
  source_hash="$(secret_hash "$source_arn")"
  current_hash="$(file_hash "${CURRENT_TOKEN[$owner]}")"
  if [[ "$source_hash" == "$current_hash" ]]; then
    return 0
  fi
  jq -e --arg hash "$source_hash" \
    '.retired | any(.secret_sha256 == $hash)' "${DOC[$owner]}" >/dev/null ||
    fail "$label source bearer is absent from target current and retired history"
}

put_current_document() {
  local owner="$1" document="$2"
  local expected="${VERSION[$owner]}"
  local client_token pending_stage version temp_stage_index
  client_token="$(openssl rand -hex 32)"
  pending_stage="E2E_PENDING_${client_token}"
  version="$(aws secretsmanager put-secret-value \
    --secret-id "${ARN[$owner]}" \
    --secret-string "file://$document" \
    --client-request-token "$client_token" \
    --version-stages "$pending_stage" \
    --profile "$PROFILE" --region "$REGION" \
    --query VersionId --output text)" || return 1
  track_temp_stage "${ARN[$owner]}" "$pending_stage" "$version"
  temp_stage_index="$LAST_TEMP_STAGE_INDEX"
  if ! aws secretsmanager update-secret-version-stage \
    --secret-id "${ARN[$owner]}" \
    --version-stage AWSCURRENT \
    --move-to-version-id "$version" \
    --remove-from-version-id "$expected" \
    --profile "$PROFILE" --region "$REGION" >/dev/null; then
    if [[ "$(current_version_id "$owner")" == "$version" ]]; then
      VERSION["$owner"]="$version"
      LAST_VERSION="$version"
      remove_tracked_temp_stage "$temp_stage_index" || return 1
      return 0
    fi
    remove_tracked_temp_stage "$temp_stage_index" || true
    return 1
  fi
  VERSION["$owner"]="$version"
  LAST_VERSION="$version"
  remove_tracked_temp_stage "$temp_stage_index" || return 1
}

put_current_document_with_checkpoint() {
  local owner="$1" document="$2"
  local expected="${VERSION[$owner]}"
  local client_token pending_stage version temp_stage_index
  client_token="$(openssl rand -hex 32)"
  pending_stage="E2E_PENDING_${client_token}"
  version="$(aws secretsmanager put-secret-value \
    --secret-id "${ARN[$owner]}" \
    --secret-string "file://$document" \
    --client-request-token "$client_token" \
    --version-stages "$pending_stage" \
    --profile "$PROFILE" --region "$REGION" \
    --query VersionId --output text)" || return 1
  track_temp_stage "${ARN[$owner]}" "$pending_stage" "$version"
  temp_stage_index="$LAST_TEMP_STAGE_INDEX"
  if ! attach_stage "${ARN[$owner]}" AGENTAUTH_ROLLBACK_PENDING "$version"; then
    remove_tracked_temp_stage "$temp_stage_index" || true
    return 1
  fi
  if ! aws secretsmanager update-secret-version-stage \
    --secret-id "${ARN[$owner]}" \
    --version-stage AWSCURRENT \
    --move-to-version-id "$version" \
    --remove-from-version-id "$expected" \
    --profile "$PROFILE" --region "$REGION" >/dev/null; then
    if [[ "$(current_version_id "$owner")" == "$version" ]]; then
      VERSION["$owner"]="$version"
      LAST_VERSION="$version"
      remove_tracked_temp_stage "$temp_stage_index" || return 1
      return 0
    fi
    remove_exact_stage \
      "${ARN[$owner]}" AGENTAUTH_ROLLBACK_PENDING "$version" || true
    remove_tracked_temp_stage "$temp_stage_index" || true
    return 1
  fi
  VERSION["$owner"]="$version"
  LAST_VERSION="$version"
  remove_tracked_temp_stage "$temp_stage_index" || return 1
}

put_staged_document() {
  local owner="$1" document="$2" stage="$3"
  local version
  version="$(aws secretsmanager put-secret-value \
    --secret-id "${ARN[$owner]}" \
    --secret-string "file://$document" \
    --client-request-token "$(openssl rand -hex 32)" \
    --version-stages "$stage" \
    --profile "$PROFILE" --region "$REGION" \
    --query VersionId --output text)" || return 1
  track_temp_stage "${ARN[$owner]}" "$stage" "$version"
  LAST_VERSION="$version"
}

sleep_for_cache() {
  sleep "$((CACHE_TTL + 5))"
}

verify_matrix() {
  local suffix="$1"
  local endpoint token_owner token_file expected
  for token_owner in platform t1 t2; do
    token_file="${CURRENT_TOKEN[$token_owner]}"
    [[ "$suffix" == "next" ]] && token_file="${NEXT_TOKEN[$token_owner]}"
    for endpoint in platform t1 t2; do
      expected=401
      [[ "$endpoint" == "$token_owner" ]] && expected=200
      expect_status "$endpoint" "$token_file" "$expected" \
        "$token_owner $suffix credential on $endpoint endpoint"
    done
  done
}

prepare_rotation() {
  local owner="$1" now="$2" cutover="$3" retirement="$4"
  local next_token="$WORK/${owner}-next-token"
  local next_doc="$WORK/${owner}-rotation.json"
  local next_id="e2e-${owner}-${now}-next"
  openssl rand -hex 32 | tr -d '\n' >"$next_token"
  chmod 0600 "$next_token"
  jq -e --argjson retirement "$retirement" \
    '.next == null and .rotation == null and .current.expires_at > $retirement' \
    "${DOC[$owner]}" >/dev/null ||
    fail "$owner is already rotating or current expires before the test retirement"
  jq \
    --rawfile secret "$next_token" \
    --arg id "$next_id" \
    --argjson now "$now" \
    --argjson cutover "$cutover" \
    --argjson retirement "$retirement" \
    --argjson lifetime "$NEXT_LIFETIME_SECS" '
      .revision += 1
      | .next = {
          credential_id: $id,
          secret: $secret,
          created_at: $now,
          not_before: $now,
          expires_at: ($now + $lifetime)
        }
      | .rotation = {
          overlap_starts_at: $now,
          cutover_at: $cutover,
          retire_current_at: $retirement
        }
    ' "${DOC[$owner]}" >"$next_doc"
  NEXT_TOKEN["$owner"]="$next_token"
  ROTATION_DOC["$owner"]="$next_doc"
}

prepare_rollback() {
  local owner="$1" retired_at="$2" revision_delta="${3:-1}"
  local output="$WORK/${owner}-rollback-${revision_delta}.json"
  local next_hash
  next_hash="$(file_hash "${NEXT_TOKEN[$owner]}")"
  jq \
    --arg hash "$next_hash" \
    --argjson retired_at "$retired_at" \
    --argjson revision_delta "$revision_delta" '
      .next as $removed
      | .revision += $revision_delta
      | .retired += [{
          credential_id: $removed.credential_id,
          secret_sha256: $hash,
          retired_at: $retired_at
        }]
      | del(.next, .rotation)
    ' "${ROTATION_DOC[$owner]}" >"$output"
  printf '%s\n' "$output"
}

prepare_promotion() {
  local owner="$1" retired_at="$2" revision_delta="${3:-1}"
  local output="$WORK/${owner}-promotion-${revision_delta}.json"
  local current_hash
  current_hash="$(file_hash "${CURRENT_TOKEN[$owner]}")"
  jq \
    --arg hash "$current_hash" \
    --argjson retired_at "$retired_at" \
    --argjson revision_delta "$revision_delta" '
      .current as $removed
      | .next as $promoted
      | .revision += $revision_delta
      | .current = $promoted
      | .retired += [{
          credential_id: $removed.credential_id,
          secret_sha256: $hash,
          retired_at: $retired_at
        }]
      | del(.next, .rotation)
    ' "${ROTATION_DOC[$owner]}" >"$output"
  printf '%s\n' "$output"
}

printf '== Initial migration and IAM checks ==\n'

DEV_BASE="$(stack_output "$DEV_STACK" AdminUrl)"
DEV_BASE="${DEV_BASE%/admin}"
DEV_TARGET="$(stack_output "$DEV_STACK" AdminSecretArn)"
load_owner dev "$DEV_TARGET" "$DEV_BASE" "/admin/overview"
expect_status dev "${CURRENT_TOKEN[dev]}" 200 "Dev platform current credential"
expect_current_validated dev
DEV_SOURCE="$(discover_legacy_platform_source "$DEV_STACK")" ||
  fail "cannot discover Dev legacy platform source"
expect_source_in_target_history dev "$DEV_SOURCE" "Dev"
expect_explicit_source_deny "$(auth_role_arn "$DEV_STACK")" "$DEV_SOURCE" "Dev source"
pass "Dev source-to-target migration, stage, and runtime source deny"

CONTROL_BASE="$(stack_output "$SAAS_STACK" AdminUrl)"
CONTROL_BASE="${CONTROL_BASE%/admin}"
PLATFORM_TARGET="$(stack_output "$SAAS_STACK" AdminSecretArn)"
load_owner platform "$PLATFORM_TARGET" "$CONTROL_BASE" "/admin/control/tenants"
CONTROL_BODY="$WORK/control-tenants.json"
request_body platform "${CURRENT_TOKEN[platform]}" "$CONTROL_BODY"

IFS=',' read -r -a tenant_ids <<<"$EXPECTED_TENANTS"
[[ "${#tenant_ids[@]}" -eq 2 ]] || fail "EXPECTED_TENANTS must contain exactly two tenants"
for tenant in "${tenant_ids[@]}"; do
  [[ "$tenant" == "t1" || "$tenant" == "t2" ]] ||
    fail "deployed issue #16 acceptance requires EXPECTED_TENANTS=t1,t2"
  issuer="$(jq -er --arg tenant "$tenant" \
    '.tenants[] | select(.tenant_id == $tenant) | .issuer' "$CONTROL_BODY")"
  target="$(jq -er --arg tenant "$tenant" \
    '.tenants[] | select(.tenant_id == $tenant) | .admin_secret_arn' "$CONTROL_BODY")"
  load_owner "$tenant" "$target" "$issuer" "/admin/overview"
done

verify_matrix current
for owner in platform t1 t2; do
  expect_current_validated "$owner"
done

SAAS_SOURCE="$(discover_legacy_platform_source "$SAAS_STACK")" ||
  fail "cannot discover SaaS legacy platform source"
expect_source_in_target_history platform "$SAAS_SOURCE" "SaaS platform"
SAAS_ROLE="$(auth_role_arn "$SAAS_STACK")"
expect_explicit_source_deny "$SAAS_ROLE" "$SAAS_SOURCE" "SaaS platform source"
for tenant in t1 t2; do
  source_arn="$(jq -er --arg tenant "$tenant" '.[$tenant]' \
    <<<"$LEGACY_TENANT_SOURCE_ARNS_JSON")" ||
    fail "missing legacy source ARN for $tenant"
  expect_source_in_target_history "$tenant" "$source_arn" "$tenant"
  expect_explicit_source_deny "$SAAS_ROLE" "$source_arn" "$tenant source"
done
pass "SaaS platform/t1/t2 migration, stages, Host matrix, and runtime source denies"

if [[ "$MUTATE" != "1" ]]; then
  pass "read-only acceptance complete; set MUTATE=1 for live rotation state transitions"
  exit 0
fi

printf '== Disposable Secrets Manager concurrency fault injection ==\n'
run_disposable_cas_acceptance
printf '== Prepare an unrouted Lambda version before credential mutation ==\n'
prepare_cold_version

START_MS=$(( $(date +%s) * 1000 ))
ROTATE_NOW="$(date +%s)"
CUTOVER_AT=$((ROTATE_NOW + CACHE_TTL + 10))
# The rollback is observed only after a second cache wait. Keep more than the
# runtime's 50-second marker-cleanup/commit reserve after that refresh starts.
RETIRE_AT=$((ROTATE_NOW + 3 * CACHE_TTL + 90))

printf '== Publish current/next overlap ==\n'
for owner in platform t1 t2; do
  prepare_rotation "$owner" "$ROTATE_NOW" "$CUTOVER_AT" "$RETIRE_AT"
done
MUTATION_STARTED=1
INITIAL_PLATFORM_VERSION="${VERSION[platform]}"
INITIAL_T1_VERSION="${VERSION[t1]}"
INITIAL_T2_VERSION="${VERSION[t2]}"
put_current_document_with_checkpoint platform "${ROTATION_DOC[platform]}"
ROTATION_VERSION[platform]="$LAST_VERSION"
for owner in t1 t2; do
  put_current_document "$owner" "${ROTATION_DOC[$owner]}"
  ROTATION_VERSION["$owner"]="$LAST_VERSION"
done
expect_stage_version \
  "${ARN[platform]}" AGENTAUTH_VALIDATED "$INITIAL_PLATFORM_VERSION" \
  "pre-commit platform checkpoint"
expect_stage_version \
  "${ARN[t1]}" AGENTAUTH_VALIDATED "$INITIAL_T1_VERSION" \
  "pre-commit t1 checkpoint"
expect_stage_version \
  "${ARN[t2]}" AGENTAUTH_VALIDATED "$INITIAL_T2_VERSION" \
  "pre-commit t2 checkpoint"
sleep_for_cache
expect_concurrent_statuses \
  platform "${NEXT_TOKEN[platform]}" "200 503" "pre-commit pending convergence"
expect_eventual_status platform "${NEXT_TOKEN[platform]}" 200 "platform converged checkpoint"
for owner in platform t1 t2; do
  expect_current_validated "$owner"
done
verify_matrix current
verify_matrix next
pass "concurrent pre-commit retry converged, with overlap only on each owner Host"

printf '== Pre-stage a rollback, then perform a valid t1 rollback ==\n'
ATTACK_DOC="$(prepare_rollback t2 "$(date +%s)" 1)"
put_staged_document t2 "$ATTACK_DOC" E2E_PRESTAGED_ROLLBACK
ATTACK_VERSION[t2]="$LAST_VERSION"
ATTACK_TEMP_STAGE_INDEX="$LAST_TEMP_STAGE_INDEX"

T1_ROLLBACK="$(prepare_rollback t1 "$(date +%s)" 1)"
put_current_document t1 "$T1_ROLLBACK" >/dev/null
sleep_for_cache
expect_eventual_status t1 "${CURRENT_TOKEN[t1]}" 200 "t1 validated rollback current"
OWNER_FINAL[t1]=1
expect_status t1 "${NEXT_TOKEN[t1]}" 401 "t1 retired rollback next"
expect_status platform "${CURRENT_TOKEN[platform]}" 200 "platform overlap current"
expect_status platform "${NEXT_TOKEN[platform]}" 200 "platform overlap next"
expect_status t2 "${CURRENT_TOKEN[t2]}" 200 "t2 overlap current"
expect_status t2 "${NEXT_TOKEN[t2]}" 200 "t2 overlap next"
pass "t1 rollback was validated before retirement and retired its next value"

now="$(date +%s)"
if (( now <= RETIRE_AT )); then
  sleep "$((RETIRE_AT - now + 1))"
fi
expect_status platform "${CURRENT_TOKEN[platform]}" 401 "platform retired current"
expect_status platform "${NEXT_TOKEN[platform]}" 200 "platform post-retirement next"
expect_status t2 "${CURRENT_TOKEN[t2]}" 401 "t2 retired current"
expect_status t2 "${NEXT_TOKEN[t2]}" 200 "t2 post-retirement next"
expect_status t1 "${CURRENT_TOKEN[t1]}" 200 "t1 trusted rollback after old deadline"
expect_status t1 "${NEXT_TOKEN[t1]}" 401 "t1 retired next after old deadline"
pass "retirement rejects old values while the previously validated rollback remains valid"

printf '== Reject delayed activation of the pre-staged rollback ==\n'
aws secretsmanager update-secret-version-stage \
  --secret-id "${ARN[t2]}" \
  --version-stage AWSCURRENT \
  --move-to-version-id "${ATTACK_VERSION[t2]}" \
  --remove-from-version-id "${ROTATION_VERSION[t2]}" \
  --profile "$PROFILE" --region "$REGION" >/dev/null
VERSION[t2]="${ATTACK_VERSION[t2]}"
attach_stage \
  "${ARN[t2]}" AGENTAUTH_ROLLBACK_PENDING "${ATTACK_VERSION[t2]}"
sleep_for_cache
printf '== Verify cold-start rejection of the interrupted rollback ==\n'
expect_cold_status t2 "${CURRENT_TOKEN[t2]}" 503 "cold interrupted t2 rollback"
expect_concurrent_statuses \
  t2 "${CURRENT_TOKEN[t2]}" "503" "deadline-expired pending rollback"
expect_stage_version \
  "${ARN[t2]}" AGENTAUTH_VALIDATED "${ROTATION_VERSION[t2]}" \
  "deadline-expired t2 checkpoint"
expect_stage_version \
  "${ARN[t2]}" AGENTAUTH_ROLLBACK_PENDING "${ATTACK_VERSION[t2]}" \
  "deadline-expired t2 checkpoint"

T2_RECOVERY_AT="$(date +%s)"
RECOVERY_ONE="$(prepare_promotion t2 "$T2_RECOVERY_AT" 2)"
put_current_document t2 "$RECOVERY_ONE" >/dev/null
expect_status t2 "${NEXT_TOKEN[t2]}" 503 "first recovery behind invalid AWSPREVIOUS"
RECOVERY_TWO="$(prepare_promotion t2 "$T2_RECOVERY_AT" 3)"
put_current_document t2 "$RECOVERY_TWO" >/dev/null
remove_stage_if_present t2 AGENTAUTH_ROLLBACK_PENDING
remove_tracked_temp_stage "$ATTACK_TEMP_STAGE_INDEX" ||
  fail "failed to remove E2E_PRESTAGED_ROLLBACK"
expect_eventual_status t2 "${NEXT_TOKEN[t2]}" 200 "second monotonic t2 recovery"
OWNER_FINAL[t2]=1
pass "deadline-expired pending rollback failed closed and recovered monotonically"

printf '== Resume a post-commit checkpoint and verify final matrix ==\n'
PLATFORM_PROMOTION="$(prepare_promotion platform "$(date +%s)" 1)"
put_current_document platform "$PLATFORM_PROMOTION" >/dev/null
attach_stage \
  "${ARN[platform]}" AGENTAUTH_ROLLBACK_PENDING "${VERSION[platform]}"
if ! aws secretsmanager update-secret-version-stage \
  --secret-id "${ARN[platform]}" \
  --version-stage AGENTAUTH_VALIDATED \
  --move-to-version-id "${VERSION[platform]}" \
  --remove-from-version-id "${ROTATION_VERSION[platform]}" \
  --profile "$PROFILE" --region "$REGION" >/dev/null; then
  [[ "$(stage_version_id "${ARN[platform]}" AGENTAUTH_VALIDATED)" == "${VERSION[platform]}" ]] ||
    fail "platform validated checkpoint did not commit"
fi
OWNER_FINAL[platform]=1
sleep_for_cache
expect_concurrent_statuses \
  platform "${NEXT_TOKEN[platform]}" "200 503" "post-commit pending cleanup"
expect_eventual_status platform "${NEXT_TOKEN[platform]}" 200 "platform post-commit convergence"

expect_status platform "${CURRENT_TOKEN[platform]}" 401 "final platform old"
expect_status platform "${NEXT_TOKEN[platform]}" 200 "final platform new"
expect_status t1 "${CURRENT_TOKEN[t1]}" 200 "final t1 rollback current"
expect_status t1 "${NEXT_TOKEN[t1]}" 401 "final t1 retired next"
expect_status t2 "${CURRENT_TOKEN[t2]}" 401 "final t2 old"
expect_status t2 "${NEXT_TOKEN[t2]}" 200 "final t2 new"

for endpoint in t1 t2; do
  expect_status "$endpoint" "${NEXT_TOKEN[platform]}" 401 \
    "platform final credential on $endpoint"
done
expect_status platform "${CURRENT_TOKEN[t1]}" 401 "t1 final credential on control"
expect_status t2 "${CURRENT_TOKEN[t1]}" 401 "t1 final credential on t2"
expect_status platform "${NEXT_TOKEN[t2]}" 401 "t2 final credential on control"
expect_status t1 "${NEXT_TOKEN[t2]}" 401 "t2 final credential on t1"

for owner in platform t1 t2; do
  expect_current_validated "$owner"
done
pass "final platform/t1/t2 matrix and validated stages"

printf '== Verify isolated-version recovery and final history ==\n'
expect_cold_status platform "${CURRENT_TOKEN[platform]}" 401 "cold platform retired old"
expect_cold_status platform "${NEXT_TOKEN[platform]}" 200 "cold platform current"
expect_cold_status t1 "${CURRENT_TOKEN[t1]}" 200 "cold t1 rollback current"
expect_cold_status t1 "${NEXT_TOKEN[t1]}" 401 "cold t1 retired rollback next"
expect_cold_status t2 "${CURRENT_TOKEN[t2]}" 401 "cold t2 retired old"
expect_cold_status t2 "${NEXT_TOKEN[t2]}" 200 "cold t2 current"
delete_cold_versions || fail "failed to delete the disposable Lambda version"
pass "fresh Lambda runtime preserved validated and retired credential history"

printf '== Verify CloudWatch audit scope and redaction ==\n'
STACK_RESOURCES="$WORK/saas-final-resources.json"
aws cloudformation list-stack-resources \
  --stack-name "$SAAS_STACK" --profile "$PROFILE" --region "$REGION" \
  --output json >"$STACK_RESOURCES"
AUDIT_TEXT="$WORK/audit.txt"
collect_audit_logs() {
  : >"$AUDIT_TEXT"
  local function_name log_group existing audit_json
  while IFS= read -r function_name; do
    log_group="/aws/lambda/$function_name"
    existing="$(aws logs describe-log-groups \
      --log-group-name-prefix "$log_group" \
      --profile "$PROFILE" --region "$REGION" \
      --query "logGroups[?logGroupName=='$log_group'].logGroupName | [0]" \
      --output text)"
    [[ "$existing" == "$log_group" ]] || continue
    audit_json="$WORK/audit-${function_name}.json"
    aws logs filter-log-events \
      --log-group-name "$log_group" \
      --start-time "$START_MS" \
      --profile "$PROFILE" --region "$REGION" \
      --output json >"$audit_json"
    jq -r '.events[].message' "$audit_json" >>"$AUDIT_TEXT"
  done < <(
    jq -r '.StackResourceSummaries[]
      | select(.ResourceType == "AWS::Lambda::Function")
      | .PhysicalResourceId' "$STACK_RESOURCES"
  )
}
for _ in 1 2 3 4 5 6; do
  collect_audit_logs
  if grep -Fq 'ADMIN_BREAK_GLASS_USE priority=high tenant=platform' "$AUDIT_TEXT" &&
    grep -Fq 'ADMIN_BREAK_GLASS_USE priority=high tenant=t1' "$AUDIT_TEXT" &&
    grep -Fq 'ADMIN_BREAK_GLASS_USE priority=high tenant=t2' "$AUDIT_TEXT"; then
    break
  fi
  sleep 5
done
grep -Fq 'ADMIN_BREAK_GLASS_USE priority=high tenant=platform' "$AUDIT_TEXT" ||
  fail "missing platform break-glass audit"
grep -Fq 'ADMIN_BREAK_GLASS_USE priority=high tenant=t1' "$AUDIT_TEXT" ||
  fail "missing t1 break-glass audit"
grep -Fq 'ADMIN_BREAK_GLASS_USE priority=high tenant=t2' "$AUDIT_TEXT" ||
  fail "missing t2 break-glass audit"
for owner in platform t1 t2; do
  grep -Fq -f "${CURRENT_TOKEN[$owner]}" "$AUDIT_TEXT" &&
    fail "audit leaked $owner current credential"
  grep -Fq -f "${NEXT_TOKEN[$owner]}" "$AUDIT_TEXT" &&
    fail "audit leaked $owner next credential"
done
pass "tenant-scoped high-priority audit events contain no bearer values"

printf '== Verify API and CloudFormation redaction ==\n'
REDACTION_TEXT="$WORK/redaction.txt"
: >"$REDACTION_TEXT"
request_body platform "${NEXT_TOKEN[platform]}" "$WORK/platform-final-body.json"
request_body t1 "${CURRENT_TOKEN[t1]}" "$WORK/t1-final-body.json"
request_body t2 "${NEXT_TOKEN[t2]}" "$WORK/t2-final-body.json"
cat "$WORK/platform-final-body.json" "$WORK/t1-final-body.json" \
  "$WORK/t2-final-body.json" >>"$REDACTION_TEXT"
for stack in "$DEV_STACK" "$SAAS_STACK"; do
  aws cloudformation describe-stacks \
    --stack-name "$stack" --profile "$PROFILE" --region "$REGION" \
    --output json >>"$REDACTION_TEXT"
  aws cloudformation get-template \
    --stack-name "$stack" --profile "$PROFILE" --region "$REGION" \
    --output json >>"$REDACTION_TEXT"
done
for owner in platform t1 t2; do
  grep -Fq -f "${CURRENT_TOKEN[$owner]}" "$REDACTION_TEXT" &&
    fail "API or CloudFormation data leaked $owner current credential"
  grep -Fq -f "${NEXT_TOKEN[$owner]}" "$REDACTION_TEXT" &&
    fail "API or CloudFormation data leaked $owner next credential"
done
pass "API responses and CloudFormation outputs/templates contain no bearer values"

pass "issue #16 deployed AWS admin credential rotation acceptance complete"
