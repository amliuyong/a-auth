#!/usr/bin/env bash
# C10.5 live gate: persistent client reclamation on real DynamoDB and Lambda.
#
# The gate publishes a disposable immutable Lambda version whose reclamation is
# scoped to three uniquely owned clients. It restores $LATEST before seeding any
# rows, leaves the daily schedule untouched, and invokes only that version.
# PASS requires:
# - idle/no-reference client -> tombstone;
# - idle/newly-created active-refresh client -> retained without waiting for GSI projection;
# - expired tombstone -> hard delete with an independently stored audit row;
# - an idempotent second pass;
# - exact $LATEST restoration and unchanged schedule/target configuration;
# - disposable Lambda-version deletion and verified temporary-state removal.
set -euo pipefail
set +x

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
STACK="${STACK_NAME:-AgentAuthDev}"
EXPECTED_DEPLOYED_COMMIT="${EXPECTED_DEPLOYED_COMMIT:?set EXPECTED_DEPLOYED_COMMIT to the full deployed SHA}"
EVIDENCE_FILE="${EVIDENCE_FILE:-/tmp/agent-auth-c10-5-evidence-$(date -u +%Y%m%dT%H%M%SZ).json}"
NEGATIVE_CUTOFF=-100
TEST_LAST_USED_DAY=-101
MAX_ACCESS_TTL_SECS=86400

for command in aws cmp git grep jq python3 sha256sum; do
  command -v "$command" >/dev/null ||
    { echo "missing required command: $command" >&2; exit 1; }
done

pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

WORK="$(mktemp -d)"
RUN_ID="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
CLIENT_PREFIX="c10-5-$RUN_ID-"
CLIENT_IDLE="${CLIENT_PREFIX}idle"
CLIENT_BUSY="${CLIENT_PREFIX}busy"
CLIENT_DEAD="${CLIENT_PREFIX}dead"
FAMILY_ID="c10-5-$RUN_ID-family"
AUDIT_KEY="reclaim-audit#$CLIENT_DEAD"
VERSION_DESCRIPTION="agent-auth C10.5 live gate $RUN_ID"
RECLAIM_FN=""
RECLAIM_RULE=""
CLIENTS_TABLE=""
REFRESH_TABLE=""
AUTH_REFS_TABLE=""
AUTH_REF_CLIENT_KEY=""
AUTH_REF_REFERENCE_KEY=""
LAMBDA_ENV_CHANGED=0
VERSION_PUBLISH_ATTEMPTED=0
TEST_VERSION=""
CLEANUP_RECOVERY_REQUIRED=0
CLEANUP_STATE_UNVERIFIED=0
CLEANED=0

stack_output() {
  local key="$1"
  jq -er --arg key "$key" '
    .Stacks[0].Outputs[]
    | select(.OutputKey == $key)
    | .OutputValue
  ' "$WORK/stack.json"
}

canonical_environment() {
  local config_file="$1" output_file="$2"
  jq -S '.Environment' "$config_file" >"$output_file"
}

receipt_environment_matches() {
  local receipt_file="$1" expected_env="$2" rendered_env="$3"
  canonical_environment "$receipt_file" "$rendered_env" || return 1
  cmp -s "$rendered_env" "$expected_env"
}

dynamo_item_absent() {
  local response_file="$1"
  [[ ! -s "$response_file" ]] ||
    jq -e 'has("Item") | not' "$response_file" >/dev/null
}

get_item() {
  local table="$1" key_name="$2" key_value="$3" output="$4"
  aws dynamodb get-item \
    --table-name "$table" --consistent-read \
    --key "$(jq -cn --arg name "$key_name" --arg value "$key_value" \
      '{($name):{S:$value}}')" \
    --profile "$PROFILE" --region "$REGION" --output json >"$output"
}

get_authority_ref() {
  local client_key="$1" reference_key="$2" output="$3"
  aws dynamodb get-item \
    --table-name "$AUTH_REFS_TABLE" --consistent-read \
    --key "$(jq -cn \
      --arg client_key "$client_key" \
      --arg reference_key "$reference_key" '
        {
          client_key:{S:$client_key},
          reference_key:{S:$reference_key}
        }
      ')" \
    --profile "$PROFILE" --region "$REGION" --output json >"$output"
}

scoped_candidate_count() {
  aws dynamodb scan \
    --table-name "$CLIENTS_TABLE" --consistent-read \
    --filter-expression 'begins_with(client_id, :prefix)' \
    --expression-attribute-values \
      "$(jq -cn --arg prefix "$CLIENT_PREFIX" \
        '{":prefix":{S:$prefix}}')" \
    --select COUNT --profile "$PROFILE" --region "$REGION" --output json |
    jq -er '.Count'
}

gsi_scoped_candidate_count() {
  aws dynamodb scan \
    --table-name "$CLIENTS_TABLE" --index-name last_used_day-index \
    --filter-expression 'begins_with(client_id, :prefix) AND last_used_day <= :cutoff' \
    --expression-attribute-values \
      "$(jq -cn --arg prefix "$CLIENT_PREFIX" --arg cutoff "$NEGATIVE_CUTOFF" \
        '{":prefix":{S:$prefix},":cutoff":{N:$cutoff}}')" \
    --select COUNT --profile "$PROFILE" --region "$REGION" --output json |
    jq -er '.Count'
}

restore_lambda_environment() {
  local current_config="$WORK/reclaim.current.json"
  local current_env="$WORK/env.current.json"
  local current_revision

  aws lambda wait function-updated \
    --function-name "$RECLAIM_FN" --profile "$PROFILE" --region "$REGION" \
    >/dev/null 2>&1 || return 1
  aws lambda get-function-configuration \
    --function-name "$RECLAIM_FN" --profile "$PROFILE" --region "$REGION" \
    --output json >"$current_config" || return 1
  jq -e '.State == "Active" and .LastUpdateStatus == "Successful"' \
    "$current_config" >/dev/null || return 1
  canonical_environment "$current_config" "$current_env"
  current_revision="$(jq -er '.RevisionId' "$current_config")" || return 1

  if cmp -s "$current_env" "$WORK/env.before.json"; then
    LAMBDA_ENV_CHANGED=0
    return 0
  fi
  cmp -s "$current_env" "$WORK/env.test.json" || return 1
  if [[ -s "$WORK/reclaim.test.update.json" ]]; then
    receipt_environment_matches \
      "$WORK/reclaim.test.update.json" "$WORK/env.test.json" \
      "$WORK/env.test-receipt.json" || return 1
  fi

  aws lambda update-function-configuration \
    --function-name "$RECLAIM_FN" --profile "$PROFILE" --region "$REGION" \
    --revision-id "$current_revision" \
    --environment "file://$WORK/env.before.json" \
    --output json >"$WORK/reclaim.restore.update.pending.json" || return 1
  mv "$WORK/reclaim.restore.update.pending.json" \
    "$WORK/reclaim.restore.update.json"
  receipt_environment_matches \
    "$WORK/reclaim.restore.update.json" "$WORK/env.before.json" \
    "$WORK/env.restore-receipt.json" || return 1
  aws lambda wait function-updated \
    --function-name "$RECLAIM_FN" --profile "$PROFILE" --region "$REGION" ||
    return 1
  aws lambda get-function-configuration \
    --function-name "$RECLAIM_FN" --profile "$PROFILE" --region "$REGION" \
    --output json >"$current_config" || return 1
  jq -e '.State == "Active" and .LastUpdateStatus == "Successful"' \
    "$current_config" >/dev/null || return 1
  canonical_environment "$current_config" "$current_env"
  cmp -s "$current_env" "$WORK/env.before.json" || return 1
  LAMBDA_ENV_CHANGED=0
}

delete_test_versions() {
  [[ "$VERSION_PUBLISH_ATTEMPTED" == "1" ]] || return 0
  local known_version="$TEST_VERSION"
  local version remaining versions

  version_absent() {
    local candidate="$1"
    if aws lambda get-function-configuration \
      --function-name "$RECLAIM_FN" --qualifier "$candidate" \
      --profile "$PROFILE" --region "$REGION" \
      >"$WORK/version-$candidate-present.json" \
      2>"$WORK/version-$candidate-present.err"; then
      return 1
    fi
    grep -q 'ResourceNotFoundException' \
      "$WORK/version-$candidate-present.err"
  }

  delete_version() {
    local candidate="$1"
    if ! aws lambda delete-function \
      --function-name "$RECLAIM_FN" --qualifier "$candidate" \
      --profile "$PROFILE" --region "$REGION" \
      >"$WORK/version-delete-$candidate.out" \
      2>"$WORK/version-delete-$candidate.err"; then
      version_absent "$candidate" || return 1
    fi
    for _ in $(seq 1 15); do
      version_absent "$candidate" && return 0
      sleep 1
    done
    return 1
  }

  if [[ -n "$known_version" ]]; then
    delete_version "$known_version" || return 1
    version_absent "$known_version" || return 1
  else
    # Description discovery is only a recovery path for an accepted publish
    # whose numeric response was not captured.
    versions="$(aws lambda list-versions-by-function \
      --function-name "$RECLAIM_FN" --profile "$PROFILE" --region "$REGION" \
      --query "Versions[?Description=='$VERSION_DESCRIPTION'].Version" \
      --output text)" || return 1
    for version in $versions; do
      [[ "$version" == "\$LATEST" ]] && continue
      delete_version "$version" || return 1
    done
    remaining="$(aws lambda list-versions-by-function \
      --function-name "$RECLAIM_FN" --profile "$PROFILE" --region "$REGION" \
      --query "length(Versions[?Description=='$VERSION_DESCRIPTION' && Version!='\$LATEST'])" \
      --output text)" || return 1
    [[ "$remaining" == "0" ]] || return 1
  fi
  VERSION_PUBLISH_ATTEMPTED=0
  TEST_VERSION=""
}

snapshot_schedule() {
  local label="$1"
  aws events describe-rule \
    --name "$RECLAIM_RULE" --profile "$PROFILE" --region "$REGION" \
    --output json >"$WORK/rule.$label.raw.json" || return 1
  jq -S 'del(.ResponseMetadata)' \
    "$WORK/rule.$label.raw.json" >"$WORK/rule.$label.json" || return 1

  aws events list-targets-by-rule \
    --rule "$RECLAIM_RULE" --profile "$PROFILE" --region "$REGION" \
    --output json >"$WORK/rule-targets.$label.raw.json" || return 1
  jq -S '{
    Targets: ((.Targets // []) | sort_by(.Id))
  }' "$WORK/rule-targets.$label.raw.json" \
    >"$WORK/rule-targets.$label.json" || return 1
}

schedule_matches_baseline() {
  local label="$1"
  snapshot_schedule "$label" || return 1
  cmp -s "$WORK/rule.$label.json" "$WORK/rule.before.json" &&
    cmp -s \
      "$WORK/rule-targets.$label.json" \
      "$WORK/rule-targets.before.json"
}

verify_control_plane_unchanged() {
  aws cloudformation describe-stacks \
    --stack-name "$STACK" --profile "$PROFILE" --region "$REGION" \
    --output json >"$WORK/stack.after.json" || return 1
  [[ "$(jq -er '.Stacks[0].StackStatus' "$WORK/stack.after.json")" == "UPDATE_COMPLETE" ]] ||
    return 1
  [[ "$(jq -er --arg key DeploymentCommit '
    .Stacks[0].Outputs[]
    | select(.OutputKey == $key)
    | .OutputValue
  ' "$WORK/stack.after.json")" == "$DEPLOYED_COMMIT" ]] || return 1

  aws lambda get-function-configuration \
    --function-name "$RECLAIM_FN" --profile "$PROFILE" --region "$REGION" \
    --output json >"$WORK/reclaim.after.json" || return 1
  jq -e --arg code "$ORIGINAL_CODE_SHA256" '
    .State == "Active"
    and .LastUpdateStatus == "Successful"
    and .CodeSha256 == $code
  ' "$WORK/reclaim.after.json" >/dev/null || return 1
  canonical_environment "$WORK/reclaim.after.json" "$WORK/env.after.json"
  cmp -s "$WORK/env.after.json" "$WORK/env.before.json" || return 1

  schedule_matches_baseline after
}

delete_test_state() {
  [[ -n "$CLIENTS_TABLE" && -n "$REFRESH_TABLE" &&
    -n "$AUTH_REFS_TABLE" ]] || return 0
  aws dynamodb transact-write-items \
    --transact-items "$(jq -cn \
      --arg refresh_table "$REFRESH_TABLE" \
      --arg refs_table "$AUTH_REFS_TABLE" \
      --arg family "$FAMILY_ID" \
      --arg client_key "$AUTH_REF_CLIENT_KEY" \
      --arg reference_key "$AUTH_REF_REFERENCE_KEY" '
        [
          {
            Delete:{
              TableName:$refresh_table,
              Key:{family_id:{S:$family}}
            }
          },
          {
            Delete:{
              TableName:$refs_table,
              Key:{
                client_key:{S:$client_key},
                reference_key:{S:$reference_key}
              }
            }
          }
        ]
      ')" \
    --profile "$PROFILE" --region "$REGION" >/dev/null || return 1
  for client in "$CLIENT_IDLE" "$CLIENT_BUSY" "$CLIENT_DEAD" "$AUDIT_KEY"; do
    aws dynamodb delete-item \
      --table-name "$CLIENTS_TABLE" \
      --key "$(jq -cn --arg value "$client" \
        '{client_id:{S:$value}}')" \
      --profile "$PROFILE" --region "$REGION" >/dev/null || return 1
  done
}

verify_test_state_absent() {
  local stable=0
  for _ in $(seq 1 30); do
    get_item "$REFRESH_TABLE" family_id "$FAMILY_ID" "$WORK/refresh.absent.json" ||
      return 1
    get_authority_ref \
      "$AUTH_REF_CLIENT_KEY" "$AUTH_REF_REFERENCE_KEY" \
      "$WORK/authority-ref.absent.json" || return 1
    get_item "$CLIENTS_TABLE" client_id "$CLIENT_IDLE" \
      "$WORK/idle.absent.json" || return 1
    get_item "$CLIENTS_TABLE" client_id "$CLIENT_BUSY" \
      "$WORK/busy.absent.json" || return 1
    get_item "$CLIENTS_TABLE" client_id "$CLIENT_DEAD" \
      "$WORK/dead.absent.json" || return 1
    get_item "$CLIENTS_TABLE" client_id "$AUDIT_KEY" \
      "$WORK/audit.absent.json" || return 1
    if dynamo_item_absent "$WORK/refresh.absent.json" &&
      dynamo_item_absent "$WORK/authority-ref.absent.json" &&
      dynamo_item_absent "$WORK/idle.absent.json" &&
      dynamo_item_absent "$WORK/busy.absent.json" &&
      dynamo_item_absent "$WORK/dead.absent.json" &&
      dynamo_item_absent "$WORK/audit.absent.json" &&
      [[ "$(scoped_candidate_count)" == "0" ]] &&
      [[ "$(gsi_scoped_candidate_count)" == "0" ]]; then
      stable=$((stable + 1))
    else
      stable=0
    fi
    [[ "$stable" -ge 3 ]] && return 0
    sleep 2
  done
  return 1
}

best_effort_cleanup() {
  local restored=0 versions_deleted=0
  set +e
  if [[ "$LAMBDA_ENV_CHANGED" == "1" ]]; then
    for _ in $(seq 1 6); do
      if restore_lambda_environment; then
        restored=1
        break
      fi
      sleep 5
    done
    [[ "$restored" == "1" ]] || CLEANUP_RECOVERY_REQUIRED=1
  fi
  if [[ "$VERSION_PUBLISH_ATTEMPTED" == "1" ]]; then
    if delete_test_versions; then
      versions_deleted=1
    fi
    [[ "$versions_deleted" == "1" ]] || CLEANUP_RECOVERY_REQUIRED=1
  fi
  delete_test_state || CLEANUP_STATE_UNVERIFIED=1
  set -e
}

cleanup() {
  if [[ "$CLEANED" != "1" ]]; then
    best_effort_cleanup
  fi
  if [[ "$CLEANUP_RECOVERY_REQUIRED" == "1" ||
    "$CLEANUP_STATE_UNVERIFIED" == "1" ]]; then
    printf 'FAIL: C10.5 cleanup requires manual verification; protected snapshot retained at %s\n' \
      "$WORK" >&2
  else
    find "$WORK" -type f -delete
    find "$WORK" -depth -type d -empty -delete
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

aws cloudformation describe-stacks \
  --stack-name "$STACK" --profile "$PROFILE" --region "$REGION" \
  --output json >"$WORK/stack.json"
[[ "$(jq -er '.Stacks[0].StackStatus' "$WORK/stack.json")" == "UPDATE_COMPLETE" ]] ||
  fail "$STACK is not UPDATE_COMPLETE"

DEPLOYED_COMMIT="$(stack_output DeploymentCommit)"
[[ "$DEPLOYED_COMMIT" == "$EXPECTED_DEPLOYED_COMMIT" &&
  "$DEPLOYED_COMMIT" =~ ^[0-9a-f]{40}$ ]] ||
  fail "deployed commit does not match EXPECTED_DEPLOYED_COMMIT"

HARNESS_COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD)"
[[ -z "$(git -C "$REPO_ROOT" status --porcelain)" ]] ||
  fail "live evidence requires a clean worktree"
git -C "$REPO_ROOT" merge-base --is-ancestor \
  "$DEPLOYED_COMMIT" "$HARNESS_COMMIT" ||
  fail "deployed commit is not an ancestor of the harness commit"
git -C "$REPO_ROOT" diff --quiet "$DEPLOYED_COMMIT..$HARNESS_COMMIT" -- \
  crates/infra-core/src/client_reclaim.rs \
  crates/http/src/reclaim.rs \
  crates/http/src/bin/reclaim.rs \
  crates/http/src/adapters/aws/clients.rs \
  crates/http/src/adapters/aws/credential_authority.rs \
  crates/http/src/adapters/aws/authority_refs.rs \
  crates/http/src/state.rs \
  crates/http/src/ports.rs ||
  fail "client-reclamation runtime changed after the deployed commit"

RECLAIM_FN="$(stack_output ReclaimFnName)"
CLIENTS_TABLE="$(stack_output ClientsTableName)"
REFRESH_TABLE="$(stack_output RefreshTableName)"
AUTH_REFS_TABLE="$(stack_output ClientAuthorityRefsTableName)"
AUTH_REF_CLIENT_KEY="$(python3 -c '
import sys
tenant = ""
client = sys.argv[1]
print(f"client#{len(tenant.encode()):08x}{tenant}{len(client.encode()):08x}{client}", end="")
' "$CLIENT_BUSY")"
AUTH_REF_REFERENCE_KEY="$(python3 -c '
import base64
import hashlib
import sys
digest = base64.urlsafe_b64encode(hashlib.sha256(sys.argv[1].encode()).digest())
print("r#" + digest.rstrip(b"=").decode(), end="")
' "$FAMILY_ID")"

get_authority_ref \
  $'meta\x1fcoverage' \
  $'refresh\x1fclient-authority-refs-v1' \
  "$WORK/refresh-coverage.json"
jq -e --arg migration_version "client-authority-refs-v1:$DEPLOYED_COMMIT" '
  .Item.schema_version.S == "client-authority-refs-v1"
  and .Item.migration_version.S == $migration_version
' "$WORK/refresh-coverage.json" >/dev/null ||
  fail "refresh authority-reference coverage is incomplete or belongs to another deployment"

aws lambda get-function-configuration \
  --function-name "$RECLAIM_FN" --profile "$PROFILE" --region "$REGION" \
  --output json >"$WORK/reclaim.before.json"
jq -e --arg commit "$DEPLOYED_COMMIT" '
  .State == "Active"
  and .LastUpdateStatus == "Successful"
  and .Environment.Variables.AGENT_AUTH_DEPLOYMENT_COMMIT == $commit
  and (.Environment.Variables.AGENT_AUTH_RECLAIM_ENABLED // "") == ""
  and .Environment.Variables.RECLAIM_IDLE_DAYS == "90"
  and .Environment.Variables.RECLAIM_MAX_ACCESS_TTL_SECS == "86400"
' "$WORK/reclaim.before.json" >/dev/null ||
  fail "ReclaimFn is not in the expected dry-run deployed state"
canonical_environment "$WORK/reclaim.before.json" "$WORK/env.before.json"
ORIGINAL_REVISION="$(jq -er '.RevisionId' "$WORK/reclaim.before.json")"
ORIGINAL_CODE_SHA256="$(jq -er '.CodeSha256' "$WORK/reclaim.before.json")"
FUNCTION_ARN="$(jq -er '.FunctionArn' "$WORK/reclaim.before.json")"

aws events list-rule-names-by-target \
  --target-arn "$FUNCTION_ARN" --profile "$PROFILE" --region "$REGION" \
  --output json >"$WORK/rules.json"
RECLAIM_RULE="$(jq -er '
  .RuleNames
  | if length == 1 then .[0] else error("expected one reclaim schedule") end
' "$WORK/rules.json")"
snapshot_schedule before ||
  fail "failed to capture the reclaim schedule baseline"
[[ "$(jq -er '.State' "$WORK/rule.before.json")" == "ENABLED" ]] ||
  fail "reclaim schedule is not enabled before the gate"

[[ "$(scoped_candidate_count)" == "0" ]] ||
  fail "unique test-client scope is not empty before the gate"

NOW="$(date +%s)"
TODAY=$((NOW / 86400))
IDLE_DAYS=$((TODAY - NEGATIVE_CUTOFF))
OLD_TOMBSTONE=$((NOW - 2 * MAX_ACCESS_TTL_SECS))

jq -S --arg enabled "1" --arg idle "$IDLE_DAYS" \
  --arg prefix "$CLIENT_PREFIX" \
  --arg ttl "$MAX_ACCESS_TTL_SECS" '
    .Variables += {
      AGENT_AUTH_RECLAIM_ENABLED:$enabled,
      AGENT_AUTH_RECLAIM_TEST_CLIENT_PREFIX:$prefix,
      RECLAIM_IDLE_DAYS:$idle,
      RECLAIM_MAX_ACCESS_TTL_SECS:$ttl
    }
' "$WORK/env.before.json" >"$WORK/env.test.json"

LAMBDA_ENV_CHANGED=1
aws lambda update-function-configuration \
  --function-name "$RECLAIM_FN" --profile "$PROFILE" --region "$REGION" \
  --revision-id "$ORIGINAL_REVISION" \
  --environment "file://$WORK/env.test.json" \
  --output json >"$WORK/reclaim.test.update.pending.json"
mv "$WORK/reclaim.test.update.pending.json" "$WORK/reclaim.test.update.json"
receipt_environment_matches \
  "$WORK/reclaim.test.update.json" "$WORK/env.test.json" \
  "$WORK/env.test-receipt.json" ||
  fail "ReclaimFn update receipt does not contain the exact test environment"
aws lambda wait function-updated \
  --function-name "$RECLAIM_FN" --profile "$PROFILE" --region "$REGION"
aws lambda get-function-configuration \
  --function-name "$RECLAIM_FN" --profile "$PROFILE" --region "$REGION" \
  --output json >"$WORK/reclaim.test.json"
jq -e '.State == "Active" and .LastUpdateStatus == "Successful"' \
  "$WORK/reclaim.test.json" >/dev/null ||
  fail "ReclaimFn test update did not reach a stable successful state"
canonical_environment "$WORK/reclaim.test.json" "$WORK/env.current.json"
cmp -s "$WORK/env.current.json" "$WORK/env.test.json" ||
  fail "ReclaimFn did not enter the exact test environment"

TEST_REVISION="$(jq -er '.RevisionId' "$WORK/reclaim.test.json")"
[[ "$(jq -er '.CodeSha256' "$WORK/reclaim.test.json")" == "$ORIGINAL_CODE_SHA256" ]] ||
  fail "ReclaimFn code changed while preparing the live gate"
VERSION_PUBLISH_ATTEMPTED=1
aws lambda publish-version \
  --function-name "$RECLAIM_FN" \
  --description "$VERSION_DESCRIPTION" \
  --code-sha256 "$ORIGINAL_CODE_SHA256" \
  --revision-id "$TEST_REVISION" \
  --profile "$PROFILE" --region "$REGION" \
  --output json >"$WORK/reclaim.version.json"
TEST_VERSION="$(jq -er '.Version | select(test("^[1-9][0-9]*$"))' \
  "$WORK/reclaim.version.json")"
aws lambda get-function-configuration \
  --function-name "$RECLAIM_FN" --qualifier "$TEST_VERSION" \
  --profile "$PROFILE" --region "$REGION" \
  --output json >"$WORK/reclaim.version.config.json"
canonical_environment \
  "$WORK/reclaim.version.config.json" "$WORK/env.version.json"
cmp -s "$WORK/env.version.json" "$WORK/env.test.json" ||
  fail "published ReclaimFn version does not contain the exact test environment"
[[ "$(jq -er '.CodeSha256' "$WORK/reclaim.version.config.json")" == "$ORIGINAL_CODE_SHA256" ]] ||
  fail "published ReclaimFn version does not contain the reviewed code"

# Restore the mutable schedule target before any test row exists. All subsequent
# mutations are performed only by the immutable, uniquely scoped version.
restore_lambda_environment ||
  fail "ReclaimFn \$LATEST environment did not restore before seeding test state"

schedule_matches_baseline prepared ||
  fail "reclaim schedule changed while preparing the immutable test version"

seed_client() {
  local client="$1" tombstone="$2"
  local item
  item="$(jq -cn \
    --arg client "$client" \
    --arg day "$TEST_LAST_USED_DAY" \
    --arg tombstone "$tombstone" '
      {
        client_id:{S:$client},
        created_at:{N:"1"},
        token_endpoint_auth_method:{S:"none"},
        last_used_day:{N:$day}
      }
      + if $tombstone == "" then {}
        else {tombstoned_at:{N:$tombstone}} end
    ')"
  aws dynamodb put-item \
    --table-name "$CLIENTS_TABLE" --item "$item" \
    --condition-expression 'attribute_not_exists(client_id)' \
    --profile "$PROFILE" --region "$REGION" >/dev/null
}

seed_client "$CLIENT_IDLE" ""
seed_client "$CLIENT_BUSY" ""
seed_client "$CLIENT_DEAD" "$OLD_TOMBSTONE"
aws dynamodb transact-write-items \
  --transact-items "$(jq -cn \
    --arg refresh_table "$REFRESH_TABLE" \
    --arg refs_table "$AUTH_REFS_TABLE" \
    --arg family "$FAMILY_ID" \
    --arg client "$CLIENT_BUSY" \
    --arg client_key "$AUTH_REF_CLIENT_KEY" \
    --arg reference_key "$AUTH_REF_REFERENCE_KEY" '
      [
        {
          Put:{
            TableName:$refresh_table,
            Item:{
              family_id:{S:$family},
              client_id:{S:$client},
              user_id:{S:"c10-5-live"},
              current_version:{N:"0"},
              revoked:{BOOL:false}
            },
            ConditionExpression:"attribute_not_exists(family_id)"
          }
        },
        {
          Put:{
            TableName:$refs_table,
            Item:{
              client_key:{S:$client_key},
              reference_key:{S:$reference_key},
              source_id:{S:$family},
              kind:{S:"refresh"},
              tenant_id:{S:""},
              client_id:{S:$client}
            },
            ConditionExpression:
              "attribute_not_exists(client_key) AND attribute_not_exists(reference_key)"
          }
        }
      ]
    ')" \
  --profile "$PROFILE" --region "$REGION" >/dev/null

candidate_count=0
for _ in $(seq 1 30); do
  candidate_count="$(gsi_scoped_candidate_count)"
  [[ "$candidate_count" == "3" ]] && break
  sleep 2
done
[[ "$candidate_count" == "3" ]] ||
  fail "the three scoped clients did not become visible to the reclaim candidate index"

invoke_reclaim() {
  local payload="$1" receipt="$2"
  aws lambda invoke \
    --function-name "$RECLAIM_FN" --qualifier "$TEST_VERSION" \
    --cli-binary-format raw-in-base64-out --payload '{"source":"c10-5-live"}' \
    --profile "$PROFILE" --region "$REGION" \
    --output json "$payload" >"$receipt"
  jq -e '.StatusCode == 200 and (.FunctionError | not)' \
    "$receipt" >/dev/null || return 1
  jq -e 'type == "object"' "$payload" >/dev/null
}

invoke_reclaim "$WORK/pass1.json" "$WORK/pass1.receipt.json" ||
  fail "first reclaim invocation failed"
jq -e '
  .enabled == true
  and .test_scope_enabled == true
  and .scanned == 3
  and .tombstoned == 1
  and .hard_deleted == 1
  and .kept == 1
  and .errored == 0
' "$WORK/pass1.json" >/dev/null ||
  fail "first reclaim pass did not produce the exact 3/1/1/1/0 result"

get_item "$CLIENTS_TABLE" client_id "$CLIENT_IDLE" "$WORK/idle.after.json"
jq -e '.Item.tombstoned_at.N | tonumber > 0' \
  "$WORK/idle.after.json" >/dev/null ||
  fail "idle client was not converted to tombstone"

get_item "$CLIENTS_TABLE" client_id "$CLIENT_BUSY" "$WORK/busy.after.json"
jq -e '.Item.client_id.S and (.Item | has("tombstoned_at") | not)' \
  "$WORK/busy.after.json" >/dev/null ||
  fail "active-refresh client was reclaimed"

get_item "$CLIENTS_TABLE" client_id "$CLIENT_DEAD" "$WORK/dead.after.json"
dynamo_item_absent "$WORK/dead.after.json" ||
  fail "expired tombstone client was not hard deleted"

get_item "$CLIENTS_TABLE" client_id "$AUDIT_KEY" "$WORK/audit.after.json"
jq -e --arg client "$CLIENT_DEAD" --arg day "$TEST_LAST_USED_DAY" '
  .Item.audit_of.S == $client
  and (.Item.hard_deleted_at.N | tonumber > 0)
  and .Item.last_used_day_audit.N == $day
  and (.Item | has("last_used_day") | not)
' "$WORK/audit.after.json" >/dev/null ||
  fail "hard delete audit row is missing or malformed"

get_item "$REFRESH_TABLE" family_id "$FAMILY_ID" "$WORK/refresh.after.json"
jq -e --arg client "$CLIENT_BUSY" '
  .Item.client_id.S == $client and .Item.revoked.BOOL == false
' "$WORK/refresh.after.json" >/dev/null ||
  fail "active refresh family was mutated"
get_authority_ref \
  "$AUTH_REF_CLIENT_KEY" "$AUTH_REF_REFERENCE_KEY" \
  "$WORK/authority-ref.after.json"
jq -e --arg client "$CLIENT_BUSY" '
  .Item.kind.S == "refresh"
  and .Item.client_id.S == $client
' "$WORK/authority-ref.after.json" >/dev/null ||
  fail "active refresh authority reference was mutated"

invoke_reclaim "$WORK/pass2.json" "$WORK/pass2.receipt.json" ||
  fail "second reclaim invocation failed"
jq -e '
  .enabled == true
  and .test_scope_enabled == true
  and .scanned == 2
  and .tombstoned == 0
  and .hard_deleted == 0
  and .kept == 2
  and .errored == 0
' "$WORK/pass2.json" >/dev/null ||
  fail "second reclaim pass was not idempotent"

verify_control_plane_unchanged ||
  fail "stack, ReclaimFn \$LATEST, or schedule changed during the immutable-version gate"
delete_test_versions ||
  fail "disposable ReclaimFn version deletion failed"
delete_test_state ||
  fail "temporary reclaim state deletion failed"
verify_test_state_absent ||
  fail "temporary reclaim state did not converge to verified absence"
CLEANED=1
pass "idle, active-refresh, hard-delete audit, and idempotent reclaim scenarios passed"
pass "immutable version deleted; \$LATEST, schedule, clients, refresh family, and audit state restored"

SCRIPT_SHA256="$(sha256sum "$SCRIPT_DIR/reclaim.sh" | awk '{print $1}')"
EXECUTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
jq -n \
  --arg executed_at "$EXECUTED_AT" \
  --arg deployed_commit "$DEPLOYED_COMMIT" \
  --arg harness_commit "$HARNESS_COMMIT" \
  --arg script_sha256 "$SCRIPT_SHA256" \
  --arg stack "$STACK" \
  '{
    schema_version:1,
    result:"pass",
    requirement:"C10.5",
    executed_at:$executed_at,
    deployed_commit:$deployed_commit,
    harness_commit:$harness_commit,
    script_sha256:$script_sha256,
    stack:$stack,
    assertions:{
      strict_test_client_scope:true,
      immutable_lambda_version:true,
      first_pass_scanned:3,
      idle_client_tombstoned:true,
      newly_created_active_refresh_client_retained:true,
      active_refresh_reference_observed:true,
      authority_reference_coverage_verified:true,
      expired_tombstone_hard_deleted:true,
      independent_hard_delete_audit_row_observed:true,
      second_pass_idempotent:true,
      latest_environment_restored_before_seed:true,
      schedule_unchanged:true,
      disposable_version_deleted:true,
      temporary_state_cleanup_verified:true
    }
  }' >"$EVIDENCE_FILE"
chmod 0600 "$EVIDENCE_FILE"
EVIDENCE_SHA256="$(sha256sum "$EVIDENCE_FILE" | awk '{print $1}')"
printf 'C10.5 live acceptance passed.\n'
printf 'Evidence: %s\n' "$EVIDENCE_FILE"
printf 'Evidence SHA-256: %s\n' "$EVIDENCE_SHA256"
