#!/usr/bin/env bash
# C3.4 pre-deploy gate: disable the legacy grace/CIBA key and drain old ciphertext.
set -euo pipefail
set +x

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="${AWS_PROFILE:-default}"
PRIMARY_REGION="${REGION:-us-east-1}"
STANDBY_REGION="${STANDBY_REGION:-us-west-2}"
DEV_STACK="${DEV_STACK:-AgentAuthDev}"
SAAS_STACK="${SAAS_STACK:-AgentAuthSaas}"
STANDBY_STACK="${STANDBY_STACK:-AgentAuthSaasStandby}"
TARGET_COMMIT="${TARGET_COMMIT:-$(git -C "$ROOT" rev-parse HEAD)}"
STATE_FILE="${STATE_FILE:-/var/tmp/agent-auth-c3-4-cutover-$TARGET_COMMIT.json}"
PREFLIGHT_ONLY="${PREFLIGHT_ONLY:-0}"

for command in aws chmod date find git install jq mktemp mv seq sleep; do
  command -v "$command" >/dev/null || {
    printf 'missing required command: %s\n' "$command" >&2
    exit 1
  }
done
[[ "$TARGET_COMMIT" =~ ^[0-9a-f]{40}$ ]] || {
  echo "TARGET_COMMIT must be a full lowercase Git SHA" >&2
  exit 1
}
[[ "$PREFLIGHT_ONLY" == "0" || "$PREFLIGHT_ONLY" == "1" ]] || {
  echo "PREFLIGHT_ONLY must be 0 or 1" >&2
  exit 1
}
[[ -z "$(git -C "$ROOT" status --porcelain)" ]] || {
  echo "cutover requires a clean worktree" >&2
  exit 1
}
[[ "$(git -C "$ROOT" rev-parse HEAD)" == "$TARGET_COMMIT" ]] || {
  echo "worktree HEAD does not match TARGET_COMMIT" >&2
  exit 1
}

umask 077
WORK="$(mktemp -d)"
trap 'find "$WORK" -type f -delete; rmdir "$WORK"' EXIT

stack_output_optional() {
  local file="$1" key="$2"
  jq -er --arg key "$key" '
    [.Stacks[0].Outputs[]? | select(.OutputKey == $key) | .OutputValue]
    | if length == 0 then "" elif length == 1 then .[0]
      else error("duplicate stack output") end
  ' "$file"
}

physical_table() {
  local stack="$1" region="$2" prefix="$3" output="$4"
  aws cloudformation describe-stack-resources \
    --profile "$PROFILE" --region "$region" --stack-name "$stack" \
    --output json >"$output"
  jq -er --arg prefix "$prefix" '
    [.StackResources[]
     | select(
         .ResourceType == "AWS::DynamoDB::Table"
         or .ResourceType == "AWS::DynamoDB::GlobalTable"
       )
     | select(.LogicalResourceId | startswith($prefix))
     | .PhysicalResourceId]
    | if length == 1 then .[0] else error("expected one table") end
  ' "$output"
}

physical_legacy_key() {
  local stack="$1" region="$2" output="$3"
  aws cloudformation describe-stack-resources \
    --profile "$PROFILE" --region "$region" --stack-name "$stack" \
    --output json >"$output"
  jq -er '
    [.StackResources[]
     | select(.ResourceType == "AWS::KMS::Key")
     | select(.LogicalResourceId | startswith("GraceEnvelopeKey"))
     | .PhysicalResourceId]
    | if length == 1 then .[0] else error("expected one legacy grace key") end
  ' "$output"
}

resolve_table() {
  local stack_file="$1" stack="$2" region="$3" output_key="$4" prefix="$5"
  local label="$6" table
  table="$(stack_output_optional "$stack_file" "$output_key")"
  if [[ -z "$table" ]]; then
    table="$(physical_table \
      "$stack" "$region" "$prefix" "$WORK/$label-resources.json")"
  fi
  aws dynamodb describe-table \
    --profile "$PROFILE" --region "$region" --table-name "$table" \
    --output json >"$WORK/$label-table.json"
  jq -e --arg table "$table" '
    .Table.TableName == $table and .Table.TableStatus == "ACTIVE"
  ' "$WORK/$label-table.json" >/dev/null || {
    printf '%s table is missing or not ACTIVE\n' "$label" >&2
    return 1
  }
  printf '%s\n' "$table"
}

describe_stack_identity() {
  local stack="$1" region="$2" label="$3" output="$4"
  aws cloudformation describe-stacks \
    --profile "$PROFILE" --region "$region" --stack-name "$stack" \
    --output json >"$output"
  jq -e '.Stacks[0].StackStatus == "UPDATE_COMPLETE"' "$output" >/dev/null ||
    { printf '%s is not UPDATE_COMPLETE\n' "$stack" >&2; return 1; }
  local legacy_key
  legacy_key="$(stack_output_optional "$output" LegacyGraceEnvelopeKeyId)"
  if [[ -z "$legacy_key" ]]; then
    legacy_key="$(stack_output_optional "$output" GraceEnvelopeKeyId)"
  fi
  if [[ -z "$legacy_key" ]]; then
    legacy_key="$(physical_legacy_key \
      "$stack" "$region" "$WORK/$label-key-resources.json")"
  fi
  [[ -n "$legacy_key" ]] || {
    printf '%s has no grace key output\n' "$stack" >&2
    return 1
  }
  aws kms describe-key \
    --profile "$PROFILE" --region "$region" --key-id "$legacy_key" \
    --output json >"$WORK/$label-key.json"
  jq -e '
    .KeyMetadata.KeyState == "Enabled" or .KeyMetadata.KeyState == "Disabled"
  ' "$WORK/$label-key.json" >/dev/null || {
    printf '%s legacy grace key is not available\n' "$label" >&2
    return 1
  }
  local grace_table ciba_table
  grace_table="$(resolve_table \
    "$output" "$stack" "$region" GraceTableName GraceTable "$label-grace")"
  ciba_table="$(resolve_table \
    "$output" "$stack" "$region" CibaTableName CibaTable "$label-ciba")"
  jq -n \
    --arg label "$label" \
    --arg region "$region" \
    --arg stack_id "$(jq -er '.Stacks[0].StackId' "$output")" \
    --arg deployment_commit "$(stack_output_optional "$output" DeploymentCommit)" \
    --arg legacy_key_id "$legacy_key" \
    --arg grace_table "$grace_table" \
    --arg ciba_table "$ciba_table" '{
      label:$label,
      region:$region,
      stack_id:$stack_id,
      deployment_commit:$deployment_commit,
      legacy_key_id:$legacy_key_id,
      grace_table:$grace_table,
      ciba_table:$ciba_table
    }'
}

describe_stack_identity "$DEV_STACK" "$PRIMARY_REGION" dev \
  "$WORK/dev-stack.json" >"$WORK/dev-identity.json"
describe_stack_identity "$SAAS_STACK" "$PRIMARY_REGION" saas \
  "$WORK/saas-stack.json" >"$WORK/saas-identity.json"
describe_stack_identity "$STANDBY_STACK" "$STANDBY_REGION" standby \
  "$WORK/standby-stack.json" >"$WORK/standby-identity.json"
jq -s --arg target "$TARGET_COMMIT" '{
  schema:"agent-auth-c3-4-cutover-v1",
  target_commit:$target,
  status:"intent",
  stacks:sort_by(.label)
}' "$WORK/dev-identity.json" "$WORK/saas-identity.json" \
  "$WORK/standby-identity.json" >"$WORK/intent.json"

if [[ "$PREFLIGHT_ONLY" == "1" ]]; then
  jq '{target_commit,status:"preflight-pass",stacks:[.stacks[].label]}' \
    "$WORK/intent.json"
  exit 0
fi

if [[ -f "$STATE_FILE" ]]; then
  jq -e --slurpfile expected "$WORK/intent.json" '
    .schema == $expected[0].schema
    and .target_commit == $expected[0].target_commit
    and .stacks == $expected[0].stacks
  ' "$STATE_FILE" >/dev/null || {
    echo "existing cutover state does not match current stack identity" >&2
    exit 1
  }
else
  install -m 0600 "$WORK/intent.json" "$STATE_FILE"
fi

scan_active() {
  local table="$1" region="$2" kind="$3" now="$4"
  local count=0 page=0 start_key=""
  while :; do
    local output="$WORK/scan-$kind-$region-$page.json"
    local filter='expires_at > :now'
    [[ "$kind" == "ciba" ]] &&
      filter='expires_at > :now AND attribute_exists(cnt_ct)'
    local args=(
      dynamodb scan --profile "$PROFILE" --region "$region"
      --table-name "$table" --consistent-read --select COUNT
      --filter-expression "$filter"
      --expression-attribute-values
      "$(jq -cn --arg now "$now" '{":now":{N:$now}}')"
      --output json
    )
    [[ -n "$start_key" ]] && args+=(--exclusive-start-key "$start_key")
    aws "${args[@]}" >"$output"
    count=$((count + $(jq -er '.Count' "$output")))
    if jq -e '(.LastEvaluatedKey // {}) | length > 0' "$output" >/dev/null; then
      start_key="$(jq -c '.LastEvaluatedKey' "$output")"
      page=$((page + 1))
    else
      break
    fi
  done
  printf '%s' "$count"
}

disable_legacy_key() {
  local region="$1" key_id="$2"
  local state
  state="$(aws kms describe-key \
    --profile "$PROFILE" --region "$region" --key-id "$key_id" \
    --query 'KeyMetadata.KeyState' --output text)"
  case "$state" in
    Disabled) return 0 ;;
    Enabled)
      aws kms disable-key \
        --profile "$PROFILE" --region "$region" --key-id "$key_id" \
        >/dev/null
      ;;
    *)
      printf 'legacy key is not safely disableable (state=%s)\n' "$state" >&2
      return 1
      ;;
  esac
  [[ "$(aws kms describe-key \
    --profile "$PROFILE" --region "$region" --key-id "$key_id" \
    --query 'KeyMetadata.KeyState' --output text)" == "Disabled" ]]
}

# Persist the destructive intent before the first control-plane write.
jq '.status = "disabling"' "$STATE_FILE" >"$WORK/state.json"
mv "$WORK/state.json" "$STATE_FILE"
chmod 0600 "$STATE_FILE"
while IFS=$'\t' read -r region key_id; do
  disable_legacy_key "$region" "$key_id"
done < <(jq -r '.stacks[] | [.region,.legacy_key_id] | @tsv' "$STATE_FILE")

jq --arg disabled_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '
  .status = "draining" | .disabled_at = $disabled_at
' "$STATE_FILE" >"$WORK/state.json"
mv "$WORK/state.json" "$STATE_FILE"
chmod 0600 "$STATE_FILE"

# A request accepted just before DisableKey may write after the first scan.
# Keep the legacy key disabled and require 15 consecutive empty observations.
stable=0
for _ in $(seq 1 900); do
  now="$(date +%s)"
  active=0
  while IFS=$'\t' read -r region grace_table ciba_table; do
    active=$((active + $(scan_active "$grace_table" "$region" grace "$now")))
    active=$((active + $(scan_active "$ciba_table" "$region" ciba "$now")))
  done < <(
    jq -r '.stacks[] | [.region,.grace_table,.ciba_table] | @tsv' "$STATE_FILE"
  )
  if ((active == 0)); then
    stable=$((stable + 1))
    ((stable >= 15)) && break
  else
    stable=0
  fi
  sleep 1
done
((stable >= 15)) || {
  echo "legacy ciphertext did not drain; keys remain disabled" >&2
  exit 1
}

jq --arg prepared_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '
  .status = "prepared"
  | .prepared_at = $prepared_at
  | .legacy_keys_disabled = true
  | .active_legacy_ciphertext = 0
' "$STATE_FILE" >"$WORK/state.json"
mv "$WORK/state.json" "$STATE_FILE"
chmod 0600 "$STATE_FILE"
jq -e '
  .status == "prepared"
  and .legacy_keys_disabled == true
  and .active_legacy_ciphertext == 0
' "$STATE_FILE" >/dev/null
printf 'C3.4 cutover prepared: %s\n' "$STATE_FILE"
