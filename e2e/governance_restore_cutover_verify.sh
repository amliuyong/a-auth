#!/usr/bin/env bash
# Read-only cutover gate for authority restored under isolated DynamoDB names.
#
# RESTORED_AUTHORITY_TABLES_FILE must contain the 12 business-authority roles:
# {
#   "clients": "...", "workload_trust": "...", "grants": "...",
#   "federation_config": "...", "admin_auth": "...", "passkeys": "...",
#   "security_events": "...", "users": "...", "scim_groups": "...",
#   "password_credentials": "...", "domain_map": "...", "tenant_keys": "..."
# }
#
# Governance and suppression are always read from the current deployed stack.
# This verifier never mutates a table. A rejected candidate must be reconciled
# by a recovery runtime using the fenced governance data plane, then rechecked.
set -euo pipefail
set +x

STACK="${STACK:-AgentAuthSaas}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
RESTORED_AUTHORITY_TABLES_FILE="${RESTORED_AUTHORITY_TABLES_FILE:-}"
EVIDENCE_FILE="${EVIDENCE_FILE:-$PWD/governance-restore-cutover-evidence.json}"
REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
VERIFY_CORE="$REPO_ROOT/scripts/governance_restore_cutover_verify.py"
AWSQ=(aws --profile "$PROFILE" --region "$REGION")

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}
pass() { printf 'PASS: %s\n' "$*"; }

for command in aws cmp date git jq mktemp python3 sha256sum sort wc; do
  command -v "$command" >/dev/null || fail "missing command: $command"
done
[[ "$REGION" == "us-east-1" ]] ||
  fail "qualifying cutover verification requires REGION=us-east-1"
[[ "$STACK" == "AgentAuthSaas" ]] ||
  fail "qualifying cutover verification requires STACK=AgentAuthSaas"
[[ -n "$RESTORED_AUTHORITY_TABLES_FILE" &&
  -s "$RESTORED_AUTHORITY_TABLES_FILE" ]] ||
  fail "RESTORED_AUTHORITY_TABLES_FILE is required"
[[ -x "$VERIFY_CORE" || -f "$VERIFY_CORE" ]] ||
  fail "restore verifier core is missing"

umask 077
WORK="$(mktemp -d)"
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  rm -rf "$WORK"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

stack_output() {
  local key="$1"
  jq -er --arg key "$key" '
    .Stacks[0].Outputs
    | map(select(.OutputKey == $key))
    | if length == 1 then .[0].OutputValue
      else error("missing or duplicate stack output: " + $key)
      end
  ' "$WORK/stack.json"
}

scan_projection() {
  local region="$1" table="$2" fields="$3" output="$4"
  local names projection
  names="$(
    jq -cn --arg fields "$fields" '
      $fields
      | split(",")
      | to_entries
      | map({key: ("#f" + (.key | tostring)), value: .value})
      | from_entries
    '
  )"
  projection="$(
    jq -nr --arg fields "$fields" '
      $fields
      | split(",")
      | to_entries
      | map("#f" + (.key | tostring))
      | join(",")
    '
  )"
  aws --profile "$PROFILE" --region "$region" dynamodb scan \
    --table-name "$table" \
    --consistent-read \
    --projection-expression "$projection" \
    --expression-attribute-names "$names" \
    --output json >"$output"
  chmod 600 "$output"
}

canonical_control_scan() {
  local input="$1" output="$2"
  jq -Sc '
    .Items
    | sort_by(
        (.pk.S // ""),
        (.sk.S // ""),
        ((.epoch.N // "0") | tonumber)
      )
  ' "$input" >"$output"
  chmod 600 "$output"
}

"${AWSQ[@]}" sts get-caller-identity --output json >"$WORK/caller.json"
ACCOUNT="$(jq -er '.Account | select(test("^[0-9]{12}$"))' "$WORK/caller.json")"
"${AWSQ[@]}" cloudformation describe-stacks \
  --stack-name "$STACK" --output json >"$WORK/stack.json"
STACK_STATUS="$(jq -er '.Stacks[0].StackStatus' "$WORK/stack.json")"
[[ "$STACK_STATUS" == "CREATE_COMPLETE" || "$STACK_STATUS" == "UPDATE_COMPLETE" ]] ||
  fail "$STACK is not in a stable deployed state"

DEPLOYED_COMMIT="$(stack_output DeploymentCommit)"
[[ "$DEPLOYED_COMMIT" =~ ^[0-9a-f]{40}$ ]] ||
  fail "DeploymentCommit is not an exact Git revision"
LOCAL_COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD)"
[[ "$LOCAL_COMMIT" == "$DEPLOYED_COMMIT" ]] ||
  fail "local verifier commit differs from the deployed runtime"
[[ -z "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=normal)" ]] ||
  fail "qualifying cutover verification requires a clean exact-commit checkout"

CURRENT_TABLES="$(stack_output ReplicatedAuthorityTableNames)"
RUNTIME_SECRETS="$(stack_output ReplicatedRuntimeSecretArns)"
RESIDENCY="$(stack_output TenantResidency)"
CURRENT_GOVERNANCE="$(jq -er '.governance' <<<"$CURRENT_TABLES")"
CURRENT_SUPPRESSION="$(jq -er '.governance_suppression' <<<"$CURRENT_TABLES")"
GOVERNANCE_HMAC_SECRET="$(jq -er '.governance_hmac' <<<"$RUNTIME_SECRETS")"
TENANTS="$(jq -c 'keys | sort' <<<"$RESIDENCY")"
REGIONS="$(
  jq -c '
    [to_entries[].value.allowed_regions[]]
    | unique
    | sort
  ' <<<"$RESIDENCY"
)"
jq -e --arg region "$REGION" '
  length > 0 and
  all(.[]; .governance_region == $region) and
  all(.[]; .allowed_regions | index($region) != null)
' <<<"$RESIDENCY" >/dev/null ||
  fail "selected Region is not the configured governance authority"

EXPECTED_ROLES='[
  "admin_auth",
  "clients",
  "domain_map",
  "federation_config",
  "grants",
  "passkeys",
  "password_credentials",
  "scim_groups",
  "security_events",
  "tenant_keys",
  "users",
  "workload_trust"
]'
jq -e --argjson roles "$EXPECTED_ROLES" '
  type == "object" and
  (keys | sort) == ($roles | sort) and
  all(.[]; type == "string" and test("^[A-Za-z0-9_.-]{3,255}$")) and
  ([.[]] | length == (unique | length))
' "$RESTORED_AUTHORITY_TABLES_FILE" >/dev/null ||
  fail "restored authority map has missing, duplicate, or unknown roles"
jq -e \
  --arg governance "$CURRENT_GOVERNANCE" \
  --arg suppression "$CURRENT_SUPPRESSION" \
  --argjson current "$CURRENT_TABLES" '
    all(
      to_entries[];
      .value != $governance and
      .value != $suppression and
      .value != $current[.key]
    )
  ' "$RESTORED_AUTHORITY_TABLES_FILE" >/dev/null ||
  fail "candidate business authority aliases current or non-rollback control tables"

while IFS=$'\t' read -r role table; do
  description="$WORK/describe-$role.json"
  "${AWSQ[@]}" dynamodb describe-table \
    --table-name "$table" --output json >"$description"
  jq -e \
    --arg region "$REGION" \
    --arg account "$ACCOUNT" \
    --arg table "$table" '
      .Table.TableStatus == "ACTIVE" and
      .Table.TableArn == "arn:aws:dynamodb:\($region):\($account):table/\($table)"
    ' "$description" >/dev/null ||
    fail "candidate table for $role is not an ACTIVE isolated table"
done < <(jq -r 'to_entries[] | [.key, .value] | @tsv' \
  "$RESTORED_AUTHORITY_TABLES_FILE")

PRIMARY_GOVERNANCE_SCAN=""
PRIMARY_SUPPRESSION_SCAN=""
REFERENCE_GOVERNANCE=""
REFERENCE_SUPPRESSION=""
while IFS= read -r replica_region; do
  governance_scan="$WORK/governance-$replica_region.json"
  suppression_scan="$WORK/suppression-$replica_region.json"
  governance_repeat="$WORK/governance-$replica_region.repeat.json"
  suppression_repeat="$WORK/suppression-$replica_region.repeat.json"
  governance_canonical="$WORK/governance-$replica_region.canonical.json"
  suppression_canonical="$WORK/suppression-$replica_region.canonical.json"
  governance_repeat_canonical="$WORK/governance-$replica_region.repeat.canonical.json"
  suppression_repeat_canonical="$WORK/suppression-$replica_region.repeat.canonical.json"
  scan_projection "$replica_region" "$CURRENT_GOVERNANCE" \
    "pk,sk,record_type,record" "$governance_scan"
  scan_projection "$replica_region" "$CURRENT_SUPPRESSION" \
    "pk,epoch,record_type,record" "$suppression_scan"
  scan_projection "$replica_region" "$CURRENT_GOVERNANCE" \
    "pk,sk,record_type,record" "$governance_repeat"
  scan_projection "$replica_region" "$CURRENT_SUPPRESSION" \
    "pk,epoch,record_type,record" "$suppression_repeat"
  canonical_control_scan "$governance_scan" "$governance_canonical"
  canonical_control_scan "$suppression_scan" "$suppression_canonical"
  canonical_control_scan "$governance_repeat" "$governance_repeat_canonical"
  canonical_control_scan "$suppression_repeat" "$suppression_repeat_canonical"
  cmp -s "$governance_canonical" "$governance_repeat_canonical" ||
    fail "Governance authority changed during strong verification"
  cmp -s "$suppression_canonical" "$suppression_repeat_canonical" ||
    fail "suppression authority changed during strong verification"
  if [[ -z "$REFERENCE_GOVERNANCE" ]]; then
    REFERENCE_GOVERNANCE="$governance_canonical"
    REFERENCE_SUPPRESSION="$suppression_canonical"
  else
    cmp -s "$REFERENCE_GOVERNANCE" "$governance_canonical" ||
      fail "Governance authority has not converged across configured replicas"
    cmp -s "$REFERENCE_SUPPRESSION" "$suppression_canonical" ||
      fail "suppression authority has not converged across configured replicas"
  fi
  if [[ "$replica_region" == "$REGION" ]]; then
    PRIMARY_GOVERNANCE_SCAN="$governance_scan"
    PRIMARY_SUPPRESSION_SCAN="$suppression_scan"
  fi
done < <(jq -r '.[]' <<<"$REGIONS")
[[ -n "$PRIMARY_GOVERNANCE_SCAN" && -n "$PRIMARY_SUPPRESSION_SCAN" ]] ||
  fail "selected governance Region was not scanned"

declare -A ROLE_FIELDS=(
  [clients]="client_id,audit_of,tombstoned_at,hard_deleted_at"
  [workload_trust]="binding_id,tenant_id"
  [grants]="grant_id,user_id,grant_json"
  [federation_config]="tenant_id,upstream_idp_id"
  [admin_auth]="key,tenant_id,record_type"
  [passkeys]="credential_id,user_id"
  [security_events]="event_id,tenant_id"
  [users]="user_id,email,record_type,canonical_user_id,scim_external_id,scim_user_name"
  [scim_groups]="pk,sk,record_type,members,tenant_kind,tenant_role,deleted"
  [password_credentials]="user_id"
  [domain_map]="domain,tenant_id,client_id,resource_id"
  [tenant_keys]="tenant_id,record_json"
)

RESTORED_SCANS="$WORK/restored-scans.json"
printf '{}\n' >"$RESTORED_SCANS"
while IFS=$'\t' read -r role table; do
  output="$WORK/restored-$role.json"
  scan_projection "$REGION" "$table" "${ROLE_FIELDS[$role]}" "$output"
  jq --arg role "$role" --arg path "$output" \
    '. + {($role): $path}' "$RESTORED_SCANS" >"$RESTORED_SCANS.current"
  mv "$RESTORED_SCANS.current" "$RESTORED_SCANS"
done < <(jq -r 'to_entries[] | [.key, .value] | @tsv' \
  "$RESTORED_AUTHORITY_TABLES_FILE")

HMAC_KEY="$WORK/governance-hmac-v1.key"
"${AWSQ[@]}" secretsmanager get-secret-value \
  --secret-id "$GOVERNANCE_HMAC_SECRET" \
  --query SecretString --output text >"$HMAC_KEY"
chmod 600 "$HMAC_KEY"
[[ "$(wc -c <"$HMAC_KEY")" -ge 32 ]] ||
  fail "governance suppression HMAC key is unavailable"

MANIFEST="$WORK/manifest.json"
jq -n \
  --argjson tenants "$TENANTS" \
  --arg governance "$PRIMARY_GOVERNANCE_SCAN" \
  --arg suppression "$PRIMARY_SUPPRESSION_SCAN" \
  --slurpfile restored "$RESTORED_SCANS" '{
    schema_version: 1,
    tenants: $tenants,
    governance_scan: $governance,
    suppression_scan: $suppression,
    restored_scans: $restored[0]
  }' >"$MANIFEST"
chmod 600 "$MANIFEST"

CORE_EVIDENCE="$WORK/core-evidence.json"
python3 "$VERIFY_CORE" \
  --manifest "$MANIFEST" \
  --hmac-key "1=$HMAC_KEY" \
  --output "$CORE_EVIDENCE"

# Close the control-plane race across candidate scanning and pure verification.
# Any suppression, lifecycle, job, or policy change invalidates this run.
while IFS= read -r replica_region; do
  governance_final="$WORK/governance-$replica_region.final.json"
  suppression_final="$WORK/suppression-$replica_region.final.json"
  governance_final_canonical="$WORK/governance-$replica_region.final.canonical.json"
  suppression_final_canonical="$WORK/suppression-$replica_region.final.canonical.json"
  scan_projection "$replica_region" "$CURRENT_GOVERNANCE" \
    "pk,sk,record_type,record" "$governance_final"
  scan_projection "$replica_region" "$CURRENT_SUPPRESSION" \
    "pk,epoch,record_type,record" "$suppression_final"
  canonical_control_scan "$governance_final" "$governance_final_canonical"
  canonical_control_scan "$suppression_final" "$suppression_final_canonical"
  cmp -s \
    "$WORK/governance-$replica_region.canonical.json" \
    "$governance_final_canonical" ||
    fail "Governance authority changed after candidate verification"
  cmp -s \
    "$WORK/suppression-$replica_region.canonical.json" \
    "$suppression_final_canonical" ||
    fail "suppression authority changed after candidate verification"
done < <(jq -r '.[]' <<<"$REGIONS")
CONTROL_STABLE_THROUGH="$(date -u +%s)"

mkdir -p "$(dirname -- "$EVIDENCE_FILE")"
TABLE_MAP_SHA256="$(jq -Sc . "$RESTORED_AUTHORITY_TABLES_FILE" |
  sha256sum | cut -d' ' -f1)"
ACCOUNT_SHA256="$(printf '%s' "$ACCOUNT" | sha256sum | cut -d' ' -f1)"
jq \
  --arg deployment_commit "$DEPLOYED_COMMIT" \
  --arg account_sha256 "$ACCOUNT_SHA256" \
  --arg region "$REGION" \
  --argjson configured_regions "$REGIONS" \
  --arg table_map_sha256 "$TABLE_MAP_SHA256" \
  --argjson control_stable_through "$CONTROL_STABLE_THROUGH" \
  --argjson verified_at "$(date -u +%s)" '
    . + {
      deployment_commit: $deployment_commit,
      account_sha256: $account_sha256,
      governance_region: $region,
      configured_regions: $configured_regions,
      restored_table_map_sha256: $table_map_sha256,
      control_stable_through: $control_stable_through,
      verified_at: $verified_at
    }
  ' "$CORE_EVIDENCE" >"$EVIDENCE_FILE.current"
chmod 600 "$EVIDENCE_FILE.current"
mv "$EVIDENCE_FILE.current" "$EVIDENCE_FILE"
pass "governance restore cutover candidate verified: $EVIDENCE_FILE"
