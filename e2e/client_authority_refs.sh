#!/usr/bin/env bash
# Issue #162 live gate for strongly consistent per-client Code/Refresh references.
set -euo pipefail
set +x
umask 077

EXPECTED_COMMIT="${EXPECTED_COMMIT:?EXPECTED_COMMIT is required}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
STACK="${STACK_NAME:-AgentAuthDev}"
MIGRATION_STACK="${MIGRATION_STACK_NAME:-AgentAuthDevAuthorityReferenceMigration}"
EVIDENCE_FILE="${EVIDENCE_FILE:-/tmp/agent-auth-authority-refs-$(date -u +%Y%m%dT%H%M%SZ).json}"

pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

for command in aws cargo cmp curl cut date find git grep jq mktemp python3 rm sed seq sha256sum sleep stat unzip; do
  command -v "$command" >/dev/null ||
    fail "missing required command: $command"
done
[[ "$EXPECTED_COMMIT" =~ ^[0-9a-f]{40}$ ]] ||
  fail "EXPECTED_COMMIT must be a full lowercase Git SHA"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
[[ "$(git -C "$REPO_ROOT" rev-parse HEAD)" == "$EXPECTED_COMMIT" ]] ||
  fail "local HEAD must equal EXPECTED_COMMIT"
[[ -z "$(git -C "$REPO_ROOT" status --porcelain \
  --untracked-files=normal --ignore-submodules=dirty)" ]] ||
  fail "live evidence requires a clean worktree"

LOCAL_ASSET="$REPO_ROOT/target/lambda/agent-auth-lambda"
LOCAL_BOOTSTRAP="$LOCAL_ASSET/bootstrap"
LOCAL_PROVENANCE="$LOCAL_ASSET/deployment-provenance.json"
LOCAL_MIGRATION_ASSET="$REPO_ROOT/target/lambda/agent-auth-migrate-credentials"
LOCAL_MIGRATION_BOOTSTRAP="$LOCAL_MIGRATION_ASSET/bootstrap"
LOCAL_MIGRATION_PROVENANCE="$LOCAL_MIGRATION_ASSET/deployment-provenance.json"
LOCAL_GOVERNANCE_ASSET="$REPO_ROOT/target/lambda/agent-auth-governance-worker"
LOCAL_GOVERNANCE_BOOTSTRAP="$LOCAL_GOVERNANCE_ASSET/bootstrap"
LOCAL_GOVERNANCE_PROVENANCE="$LOCAL_GOVERNANCE_ASSET/deployment-provenance.json"
[[ -f "$LOCAL_BOOTSTRAP" && -f "$LOCAL_PROVENANCE" &&
  -f "$LOCAL_MIGRATION_BOOTSTRAP" && -f "$LOCAL_MIGRATION_PROVENANCE" &&
  -f "$LOCAL_GOVERNANCE_BOOTSTRAP" && -f "$LOCAL_GOVERNANCE_PROVENANCE" ]] ||
  fail "build exact-commit Lambda artifacts before running live acceptance"
LOCAL_BOOTSTRAP_SHA256="$(sha256sum "$LOCAL_BOOTSTRAP" | cut -d' ' -f1)"
LOCAL_MIGRATION_BOOTSTRAP_SHA256="$(
  sha256sum "$LOCAL_MIGRATION_BOOTSTRAP" | cut -d' ' -f1
)"
LOCAL_GOVERNANCE_BOOTSTRAP_SHA256="$(
  sha256sum "$LOCAL_GOVERNANCE_BOOTSTRAP" | cut -d' ' -f1
)"

validate_provenance() {
  local manifest="$1" sha="$2" label="$3"
  jq -e --arg commit "$EXPECTED_COMMIT" --arg sha "$sha" '
    (keys | sort) == (["bootstrap_sha256", "commit", "schema"] | sort)
    and .schema == "agent-auth-lambda-provenance-v1"
    and .commit == $commit
    and .bootstrap_sha256 == $sha
  ' "$manifest" >/dev/null ||
    fail "$label provenance does not bind EXPECTED_COMMIT and bootstrap"
}

validate_provenance "$LOCAL_PROVENANCE" "$LOCAL_BOOTSTRAP_SHA256" "local Auth"
validate_provenance \
  "$LOCAL_MIGRATION_PROVENANCE" "$LOCAL_MIGRATION_BOOTSTRAP_SHA256" "local migration"
validate_provenance \
  "$LOCAL_GOVERNANCE_PROVENANCE" "$LOCAL_GOVERNANCE_BOOTSTRAP_SHA256" "local governance"

WORK="$(mktemp -d)"
chmod 700 "$WORK"
CLEANUP_MANIFEST="$WORK/live-tables.json"

cleanup_live_tables() {
  [[ -f "$CLEANUP_MANIFEST" ]] || return 0
  [[ "$(stat -c '%a' "$CLEANUP_MANIFEST")" == "600" ]] || return 1
  jq -e '
    (keys == ["tables"])
    and (.tables | length == 4)
    and all(.tables[]; type == "string" and startswith("aa162-"))
  ' "$CLEANUP_MANIFEST" >/dev/null || return 1

  local index=0 table describe error_file absent status
  while IFS= read -r table; do
    describe="$WORK/cleanup-describe-${index}.json"
    error_file="$WORK/cleanup-error-${index}.txt"
    absent=0
    for _ in $(seq 1 180); do
      if aws dynamodb describe-table \
        --table-name "$table" --profile "$PROFILE" --region "$REGION" \
        --output json >"$describe" 2>"$error_file"; then
        status="$(jq -er '.Table.TableStatus' "$describe")" || return 1
        if [[ "$status" != "DELETING" ]]; then
          if ! aws dynamodb delete-table \
            --table-name "$table" --profile "$PROFILE" --region "$REGION" \
            --output json >"$WORK/cleanup-delete-${index}.json" \
            2>"$error_file" &&
            ! grep -q 'ResourceInUseException' "$error_file"; then
            return 1
          fi
        fi
        sleep 1
      elif grep -q 'ResourceNotFoundException' "$error_file"; then
        absent=1
        break
      else
        return 1
      fi
    done
    [[ "$absent" -eq 1 ]] || return 1
    index=$((index + 1))
  done < <(jq -r '.tables[]' "$CLEANUP_MANIFEST")
  rm -f "$CLEANUP_MANIFEST"
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if ! cleanup_live_tables; then
    status=1
  fi
  find "$WORK" -type f -delete
  find "$WORK" -depth -type d -empty -delete
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

describe_stack() {
  local stack="$1" output="$2"
  aws cloudformation describe-stacks \
    --stack-name "$stack" --profile "$PROFILE" --region "$REGION" \
    --output json >"$output"
  jq -e '
    .Stacks[0].StackStatus == "CREATE_COMPLETE"
    or .Stacks[0].StackStatus == "UPDATE_COMPLETE"
  ' "$output" >/dev/null || fail "$stack is not in a stable complete state"
}

stack_output() {
  local file="$1" key="$2"
  jq -er --arg key "$key" '
    [.Stacks[0].Outputs[] | select(.OutputKey == $key) | .OutputValue]
    | if length == 1 then .[0] else error("missing stack output " + $key) end
  ' "$file"
}

describe_stack "$STACK" "$WORK/stack.json"
describe_stack "$MIGRATION_STACK" "$WORK/migration-stack.json"
aws cloudformation get-template \
  --stack-name "$MIGRATION_STACK" --profile "$PROFILE" --region "$REGION" \
  --template-stage Original --output json >"$WORK/migration-template.json"
jq -e --arg version "client-authority-refs-v1:$EXPECTED_COMMIT" '
  [
    .TemplateBody.Resources[]
    | select(.Type == "AWS::CloudFormation::CustomResource")
    | .Properties.MigrationVersion
  ] == [$version]
' "$WORK/migration-template.json" >/dev/null ||
  fail "migration stack is not bound to the exact deployed commit"
DEPLOYED_COMMIT="$(stack_output "$WORK/stack.json" DeploymentCommit)"
[[ "$DEPLOYED_COMMIT" == "$EXPECTED_COMMIT" ]] ||
  fail "deployed commit does not match EXPECTED_COMMIT"
AUTH_FN="$(stack_output "$WORK/stack.json" AuthFnName)"
MIGRATION_FN="$(stack_output "$WORK/stack.json" AuthorityReferenceMigrationFnName)"
GOVERNANCE_FN="$(stack_output "$WORK/stack.json" GovernanceWorkerFnName)"
REFS_TABLE="$(stack_output "$WORK/stack.json" ClientAuthorityRefsTableName)"

aws lambda get-function \
  --function-name "$AUTH_FN" --profile "$PROFILE" --region "$REGION" \
  --output json >"$WORK/function.json"
jq -e --arg commit "$EXPECTED_COMMIT" --arg table "$REFS_TABLE" '
  .Configuration.State == "Active"
  and .Configuration.LastUpdateStatus == "Successful"
  and .Configuration.Environment.Variables.AGENT_AUTH_DEPLOYMENT_COMMIT == $commit
  and .Configuration.Environment.Variables.AUTH_REFS_TABLE == $table
' "$WORK/function.json" >/dev/null ||
  fail "deployed Auth Lambda is not bound to the reviewed reference table and commit"
curl -fsS --proto '=https' --connect-timeout 10 --max-time 120 \
  "$(jq -er '.Code.Location' "$WORK/function.json")" \
  -o "$WORK/function.zip"
DOWNLOADED_CODE_SHA256="$(python3 - "$WORK/function.zip" <<'PY'
import base64
import hashlib
import pathlib
import sys

print(base64.b64encode(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).digest()).decode())
PY
)"
[[ "$DOWNLOADED_CODE_SHA256" == \
  "$(jq -er '.Configuration.CodeSha256' "$WORK/function.json")" ]] ||
  fail "downloaded Lambda package does not match AWS CodeSha256"
unzip -p "$WORK/function.zip" bootstrap >"$WORK/deployed-bootstrap" ||
  fail "deployed Lambda package is missing bootstrap"
unzip -p "$WORK/function.zip" deployment-provenance.json \
  >"$WORK/deployed-provenance.json" ||
  fail "deployed Lambda package is missing provenance"
DEPLOYED_BOOTSTRAP_SHA256="$(sha256sum "$WORK/deployed-bootstrap" | cut -d' ' -f1)"
[[ "$DEPLOYED_BOOTSTRAP_SHA256" == "$LOCAL_BOOTSTRAP_SHA256" ]] ||
  fail "deployed Auth bootstrap differs from the exact local artifact"
validate_provenance \
  "$WORK/deployed-provenance.json" "$DEPLOYED_BOOTSTRAP_SHA256" "deployed Auth"

aws lambda get-function \
  --function-name "$MIGRATION_FN" --profile "$PROFILE" --region "$REGION" \
  --output json >"$WORK/migration-function.json"
jq -e --arg commit "$EXPECTED_COMMIT" --arg table "$REFS_TABLE" '
  .Configuration.State == "Active"
  and .Configuration.LastUpdateStatus == "Successful"
  and .Configuration.Environment.Variables.CREDENTIAL_MIGRATION_MODE == "authority_refs"
  and .Configuration.Environment.Variables.AUTH_REFS_TABLE == $table
  and .Configuration.Environment.Variables.AGENT_AUTH_DEPLOYMENT_COMMIT == $commit
' "$WORK/migration-function.json" >/dev/null ||
  fail "deployed migration Lambda has unexpected commit, mode, or table binding"
curl -fsS --proto '=https' --connect-timeout 10 --max-time 120 \
  "$(jq -er '.Code.Location' "$WORK/migration-function.json")" \
  -o "$WORK/migration-function.zip"
MIGRATION_DOWNLOADED_CODE_SHA256="$(
  python3 - "$WORK/migration-function.zip" <<'PY'
import base64
import hashlib
import pathlib
import sys

print(base64.b64encode(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).digest()).decode())
PY
)"
[[ "$MIGRATION_DOWNLOADED_CODE_SHA256" == \
  "$(jq -er '.Configuration.CodeSha256' "$WORK/migration-function.json")" ]] ||
  fail "downloaded migration package does not match AWS CodeSha256"
unzip -p "$WORK/migration-function.zip" bootstrap \
  >"$WORK/deployed-migration-bootstrap" ||
  fail "deployed migration package is missing bootstrap"
unzip -p "$WORK/migration-function.zip" deployment-provenance.json \
  >"$WORK/deployed-migration-provenance.json" ||
  fail "deployed migration package is missing provenance"
DEPLOYED_MIGRATION_BOOTSTRAP_SHA256="$(
  sha256sum "$WORK/deployed-migration-bootstrap" | cut -d' ' -f1
)"
[[ "$DEPLOYED_MIGRATION_BOOTSTRAP_SHA256" == \
  "$LOCAL_MIGRATION_BOOTSTRAP_SHA256" ]] ||
  fail "deployed migration bootstrap differs from the exact local artifact"
validate_provenance \
  "$WORK/deployed-migration-provenance.json" \
  "$DEPLOYED_MIGRATION_BOOTSTRAP_SHA256" "deployed migration"

aws lambda get-function \
  --function-name "$GOVERNANCE_FN" --profile "$PROFILE" --region "$REGION" \
  --output json >"$WORK/governance-function.json"
jq -e --arg commit "$EXPECTED_COMMIT" --arg table "$REFS_TABLE" '
  .Configuration.State == "Active"
  and .Configuration.LastUpdateStatus == "Successful"
  and .Configuration.Environment.Variables.AGENT_AUTH_DEPLOYMENT_COMMIT == $commit
  and .Configuration.Environment.Variables.AUTH_REFS_TABLE == $table
' "$WORK/governance-function.json" >/dev/null ||
  fail "deployed Governance Lambda is not bound to the reviewed reference table and commit"
curl -fsS --proto '=https' --connect-timeout 10 --max-time 120 \
  "$(jq -er '.Code.Location' "$WORK/governance-function.json")" \
  -o "$WORK/governance-function.zip"
GOVERNANCE_DOWNLOADED_CODE_SHA256="$(
  python3 - "$WORK/governance-function.zip" <<'PY'
import base64
import hashlib
import pathlib
import sys

print(base64.b64encode(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).digest()).decode())
PY
)"
[[ "$GOVERNANCE_DOWNLOADED_CODE_SHA256" == \
  "$(jq -er '.Configuration.CodeSha256' "$WORK/governance-function.json")" ]] ||
  fail "downloaded Governance package does not match AWS CodeSha256"
unzip -p "$WORK/governance-function.zip" bootstrap \
  >"$WORK/deployed-governance-bootstrap" ||
  fail "deployed Governance package is missing bootstrap"
unzip -p "$WORK/governance-function.zip" deployment-provenance.json \
  >"$WORK/deployed-governance-provenance.json" ||
  fail "deployed Governance package is missing provenance"
DEPLOYED_GOVERNANCE_BOOTSTRAP_SHA256="$(
  sha256sum "$WORK/deployed-governance-bootstrap" | cut -d' ' -f1
)"
[[ "$DEPLOYED_GOVERNANCE_BOOTSTRAP_SHA256" == \
  "$LOCAL_GOVERNANCE_BOOTSTRAP_SHA256" ]] ||
  fail "deployed Governance bootstrap differs from the exact local artifact"
validate_provenance \
  "$WORK/deployed-governance-provenance.json" \
  "$DEPLOYED_GOVERNANCE_BOOTSTRAP_SHA256" "deployed governance"

coverage_item() {
  local kind="$1" output="$2"
  aws dynamodb get-item \
    --table-name "$REFS_TABLE" --consistent-read \
    --key "$(jq -cn \
      --arg client_key $'meta\x1fcoverage' \
      --arg reference_key "${kind}"$'\x1fclient-authority-refs-v1' '
        {
          client_key:{S:$client_key},
          reference_key:{S:$reference_key}
        }
      ')" \
    --profile "$PROFILE" --region "$REGION" --output json >"$output"
  jq -e --arg migration_version "client-authority-refs-v1:$EXPECTED_COMMIT" '
    .Item.schema_version.S == "client-authority-refs-v1"
    and .Item.migration_version.S == $migration_version
  ' "$output" >/dev/null
}

migration_metadata() {
  local suffix="$1"
  coverage_item code "$WORK/code-coverage-${suffix}.json" ||
    fail "authorization-code reference coverage is incomplete"
  coverage_item refresh "$WORK/refresh-coverage-${suffix}.json" ||
    fail "refresh reference coverage is incomplete"
  aws dynamodb get-item \
    --table-name "$REFS_TABLE" --consistent-read \
    --key "$(jq -cn \
      --arg client_key $'meta\x1fmigration' \
      --arg reference_key $'state\x1fclient-authority-refs-v1' '
        {
          client_key:{S:$client_key},
          reference_key:{S:$reference_key}
        }
      ')" \
    --profile "$PROFILE" --region "$REGION" --output json \
    >"$WORK/migration-state-${suffix}.json"
  jq -e --arg migration_id "client-authority-refs-v1:$EXPECTED_COMMIT" '
    .Item.migration_id.S == $migration_id
    and .Item.phase.S == "complete"
    and (.Item.checkpoint_version.N | test("^[0-9]+$"))
  ' "$WORK/migration-state-${suffix}.json" >/dev/null ||
    fail "durable authority-reference migration checkpoint is incomplete"
  aws dynamodb query \
    --table-name "$REFS_TABLE" --consistent-read \
    --key-condition-expression "#client_key = :client_key" \
    --expression-attribute-names '{"#client_key":"client_key"}' \
    --expression-attribute-values "$(jq -cn \
      --arg client_key $'meta\x1fmigration-request' '
        {":client_key":{S:$client_key}}
      ')" \
    --projection-expression "reference_key,migration_id,schema_version" \
    --profile "$PROFILE" --region "$REGION" --output json \
    >"$WORK/migration-requests-${suffix}.json"
  jq -e --arg migration_id "client-authority-refs-v1:$EXPECTED_COMMIT" '
    [
      .Items[]
      | select(
          .migration_id.S == $migration_id
          and .schema_version.S == "client-authority-refs-v1"
          and (.reference_key.S | startswith("request\u001f"))
        )
    ]
    | length >= 1
  ' "$WORK/migration-requests-${suffix}.json" >/dev/null ||
    fail "current deployment has no durable CloudFormation migration request marker"
  jq -S -n \
    --slurpfile code "$WORK/code-coverage-${suffix}.json" \
    --slurpfile refresh "$WORK/refresh-coverage-${suffix}.json" \
    --slurpfile state "$WORK/migration-state-${suffix}.json" \
    --slurpfile requests "$WORK/migration-requests-${suffix}.json" \
    '{
      code:$code[0].Item,
      refresh:$refresh[0].Item,
      state:$state[0].Item,
      requests:($requests[0].Items | sort_by(.reference_key.S))
    }' \
    >"$WORK/migration-metadata-${suffix}.json"
}

migration_metadata before

(
  cd "$REPO_ROOT"
  AGENT_AUTH_AUTHORITY_REFS_LIVE=1 \
    AGENT_AUTH_AUTHORITY_REFS_CLEANUP_MANIFEST="$CLEANUP_MANIFEST" \
    AWS_PROFILE="$PROFILE" \
    AWS_REGION="$REGION" \
    cargo test -p agent-auth-http \
      --test authority_refs_live --features aws \
      -- --ignored --nocapture
) >"$WORK/live-test.log" 2>&1 ||
  {
    sed -n '1,240p' "$WORK/live-test.log" >&2
    fail "real AWS authority-reference adapter test failed"
  }
cleanup_live_tables ||
  fail "real AWS authority-reference temporary tables were not removed"
migration_metadata after
cmp -s \
  "$WORK/migration-metadata-before.json" \
  "$WORK/migration-metadata-after.json" ||
  fail "authority-reference migration metadata changed during live acceptance"
python3 - "$WORK/live-test.log" "$WORK/live-result.json" <<'PY'
import json
import pathlib
import sys

prefix = "AUTHORITY_REFS_LIVE "
matches = [
    line[len(prefix):]
    for line in pathlib.Path(sys.argv[1]).read_text().splitlines()
    if line.startswith(prefix)
]
if len(matches) != 1:
    raise SystemExit("expected exactly one authority-reference live result")
value = json.loads(matches[0])
expected = {
    "result": "pass",
    "legacy_backfill": True,
    "immediate_reference_visibility": True,
    "multiple_active_references": True,
    "expiry_exclusion": True,
    "cross_tenant_collision_isolation": True,
    "concurrent_revoke_create": True,
    "tombstone_creation_fence": True,
    "same_day_code_revision_fence": True,
    "same_day_refresh_revision_fence": True,
    "terminal_orphan_cleanup": True,
    "governance_adapter_cleanup": True,
    "temporary_tables_deleted": True,
}
if value != expected:
    raise SystemExit("authority-reference live result is incomplete")
pathlib.Path(sys.argv[2]).write_text(json.dumps(value, sort_keys=True))
PY

SCRIPT_SHA256="$(sha256sum "$SCRIPT_DIR/client_authority_refs.sh" | cut -d' ' -f1)"
EXECUTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
jq -n \
  --arg executed_at "$EXECUTED_AT" \
  --arg deployed_commit "$DEPLOYED_COMMIT" \
  --arg script_sha256 "$SCRIPT_SHA256" \
  --arg bootstrap_sha256 "$DEPLOYED_BOOTSTRAP_SHA256" \
  --arg migration_bootstrap_sha256 "$DEPLOYED_MIGRATION_BOOTSTRAP_SHA256" \
  --arg governance_bootstrap_sha256 "$DEPLOYED_GOVERNANCE_BOOTSTRAP_SHA256" \
  --arg stack "$STACK" \
  --arg migration_stack "$MIGRATION_STACK" \
  '{
    schema_version:1,
    result:"pass",
    issue:162,
    executed_at:$executed_at,
    deployed_commit:$deployed_commit,
    script_sha256:$script_sha256,
    deployed_bootstrap_sha256:$bootstrap_sha256,
    deployed_migration_bootstrap_sha256:$migration_bootstrap_sha256,
    deployed_governance_bootstrap_sha256:$governance_bootstrap_sha256,
    stack:$stack,
    migration_stack:$migration_stack,
    assertions:{
      exact_deployed_artifact:true,
      post_deploy_migration_complete:true,
      code_coverage_marker:true,
      refresh_coverage_marker:true,
      durable_complete_checkpoint:true,
      cloudformation_request_marker:true,
      migration_metadata_stable_during_live:true,
      legacy_backfill:true,
      immediate_reference_visibility:true,
      multiple_active_references:true,
      expiry_exclusion:true,
      cross_tenant_collision_isolation:true,
      concurrent_revoke_create:true,
      tombstone_creation_fence:true,
      same_day_code_revision_fence:true,
      same_day_refresh_revision_fence:true,
      terminal_orphan_cleanup:true,
      governance_adapter_cleanup:true,
      temporary_tables_deleted:true
    }
  }' >"$EVIDENCE_FILE"
chmod 0600 "$EVIDENCE_FILE"
EVIDENCE_SHA256="$(sha256sum "$EVIDENCE_FILE" | cut -d' ' -f1)"
pass "legacy backfill, atomic lifecycle, bounded reads, and tenant isolation"
printf 'Issue #162 live acceptance passed.\n'
printf 'Evidence: %s\n' "$EVIDENCE_FILE"
printf 'Evidence SHA-256: %s\n' "$EVIDENCE_SHA256"
