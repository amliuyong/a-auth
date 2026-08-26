#!/usr/bin/env bash
# Backfill the two tenant-scoped DynamoDB projections introduced after early
# Grant rows were written. The default plan action is read-only.
set -euo pipefail

ACTION="${ACTION:-plan}"
STACK="${STACK:-AgentAuthSaas}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
AWSQ=(aws --profile "$PROFILE" --region "$REGION")

case "$ACTION" in
  plan|apply) ;;
  *)
    printf 'FAIL: ACTION must be plan or apply\n' >&2
    exit 1
    ;;
esac
if [[ "$ACTION" == "apply" ]]; then
  if [[ "${CONFIRM_STACK:-}" != "$STACK" ]]; then
    printf 'FAIL: ACTION=apply requires CONFIRM_STACK=%s\n' "$STACK" >&2
    exit 1
  fi
  if [[ "$REGION" != "us-east-1" ]]; then
    printf 'FAIL: ACTION=apply requires REGION=us-east-1\n' >&2
    exit 1
  fi
fi
for command in aws flock jq; do
  command -v "$command" >/dev/null || {
    printf 'FAIL: missing command: %s\n' "$command" >&2
    exit 1
  }
done

lock_name=$(printf '%s-%s-%s' "$PROFILE" "$REGION" "$STACK" |
  tr -c 'A-Za-z0-9._-' '_')
lock_file="${XDG_RUNTIME_DIR:-/tmp}/agent-auth-grant-projection-${UID}-${lock_name}.lock"
exec 9>"$lock_file"
if ! flock -n 9; then
  printf 'FAIL: another Grant projection migration is active for %s\n' "$STACK" >&2
  exit 1
fi

work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT
chmod 700 "$work_dir"

stack_output() {
  local key="$1" value
  value=$("${AWSQ[@]}" cloudformation describe-stacks \
    --stack-name "$STACK" \
    --query "Stacks[0].Outputs[?OutputKey=='$key'].OutputValue | [0]" \
    --output text)
  [[ -n "$value" && "$value" != "None" ]] || {
    printf 'FAIL: stack output is missing: %s\n' "$key" >&2
    exit 1
  }
  printf '%s\n' "$value"
}

scan_grants() {
  local output="$1"
  "${AWSQ[@]}" dynamodb scan \
    --table-name "$GRANTS_TABLE" \
    --consistent-read \
    --projection-expression \
      'grant_id,user_id,gv_tenant,effective_pv,revision,credential_epoch,grant_json,policy_version,policy_text,policy_digest' \
    --output json >"$output"
  chmod 600 "$output"
}

GRANTS_TABLE=$(stack_output GrantsTableName)
TENANT_ISSUERS_JSON=$(stack_output RecoveryTenantIssuers)
TENANT_IDS_JSON=$(jq -ce '
  if type == "object" and length > 0 and
      all(.[]; type == "string" and startswith("https://"))
  then keys
  else error("RecoveryTenantIssuers is not a non-empty HTTPS issuer map")
  end
' <<<"$TENANT_ISSUERS_JSON")

scan_grants "$work_dir/before.json"
jq -e -L "$SCRIPT_DIR" -Sc \
  --argjson tenants "$TENANT_IDS_JSON" \
  'include "backup_restore_filters";
   grant_projection_migration_candidates($tenants)' \
  "$work_dir/before.json" >"$work_dir/candidates.json" || {
    printf 'FAIL: Grant table preflight found an unknown row or invalid projection\n' >&2
    exit 1
  }

table_items=$(jq -er '.Items | length' "$work_dir/before.json")
candidate_count=$(jq -er 'length' "$work_dir/candidates.json")
printf 'PASS: preflight validated %s Grant-table rows; migration candidates=%s\n' \
  "$table_items" "$candidate_count"

if [[ "$ACTION" == "plan" ]]; then
  printf 'PLAN: no writes performed; rerun with ACTION=apply CONFIRM_STACK=%s\n' \
    "$STACK"
  exit 0
fi

updated=0
while IFS= read -r candidate; do
  key=$(jq -cn --argjson candidate "$candidate" \
    '{grant_id:{S:$candidate.grant_id}}')
  values=$(jq -cn --argjson candidate "$candidate" '
    {
      ":grant_json": {S: $candidate.grant_json},
      ":user_id": {S: $candidate.user_id},
      ":gv_tenant": {S: $candidate.gv_tenant},
      ":effective_pv": {N: $candidate.effective_pv}
    }
    + if $candidate.revision == null then {}
      else {":revision": {N: $candidate.revision}}
      end
  ')
  condition='attribute_exists(grant_id) AND grant_json = :grant_json AND user_id = :user_id AND attribute_not_exists(gv_tenant) AND attribute_not_exists(effective_pv)'
  if [[ "$(jq -r '.revision == null' <<<"$candidate")" == "true" ]]; then
    condition+=' AND attribute_not_exists(revision)'
  else
    condition+=' AND revision = :revision'
  fi

  if ! "${AWSQ[@]}" dynamodb update-item \
      --table-name "$GRANTS_TABLE" \
      --key "$key" \
      --update-expression \
        'SET gv_tenant = :gv_tenant, effective_pv = :effective_pv' \
      --condition-expression "$condition" \
      --expression-attribute-values "$values" \
      --output json >/dev/null; then
    printf 'FAIL: conditional migration lost a race; rerun from a fresh plan\n' >&2
    exit 1
  fi
  updated=$((updated + 1))
done < <(jq -c '.[]' "$work_dir/candidates.json")

scan_grants "$work_dir/after.json"
jq -e -L "$SCRIPT_DIR" \
  --argjson tenants "$TENANT_IDS_JSON" \
  'include "backup_restore_filters";
   canonical_grant_items($tenants) | length >= 0' \
  "$work_dir/after.json" >/dev/null || {
    printf 'FAIL: post-migration Grant projection validation failed\n' >&2
    exit 1
  }
remaining=$(jq -e -L "$SCRIPT_DIR" -c \
  --argjson tenants "$TENANT_IDS_JSON" \
  'include "backup_restore_filters";
   grant_projection_migration_candidates($tenants) | length' \
  "$work_dir/after.json")
[[ "$remaining" == "0" ]] || {
  printf 'FAIL: %s Grant projection candidates remain\n' "$remaining" >&2
  exit 1
}
printf 'PASS: conditionally migrated %s Grant rows; strict postflight passed\n' \
  "$updated"
