#!/usr/bin/env bash
# One-time Issue #176 reconciliation for the exact historical SaaS test residue.
#
# The gate proves the six-client/twelve-Grant fingerprint before any mutation,
# then calls the deployed Admin DELETE lifecycle for each client. A private,
# restart-safe manifest retains raw IDs until reconciliation completes; final
# evidence contains only counts and an irreversible selection digest.
set -euo pipefail
set +x
umask 077

EXPECTED_COMMIT="${EXPECTED_COMMIT:?EXPECTED_COMMIT is required}"
CONFIRM="${CONFIRM_ISSUE_176_RECONCILE:-}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
STACK="${STACK_NAME:-AgentAuthSaas}"
TENANT="t1"
EXPECTED_CONFIRMATION="issue-176-exact-6-clients-12-grants"
STATE_DIR="${STATE_DIR:-/var/tmp/agent-auth-issue-176-reconcile-state}"
EVIDENCE_FILE="${EVIDENCE_FILE:-/tmp/agent-auth-issue-176-$(date -u +%Y%m%dT%H%M%SZ).json}"
EXPECTED_CREATED_AT='[1783963683,1783963810,1784018027,1784023852,1784027140,1785070397]'

pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

for command in aws base64 chmod cmp curl cut date find git jq mkdir mktemp mv python3 rm rmdir sha256sum stat unzip; do
  command -v "$command" >/dev/null || fail "missing required command: $command"
done
[[ "$EXPECTED_COMMIT" =~ ^[0-9a-f]{40}$ ]] ||
  fail "EXPECTED_COMMIT must be a full lowercase Git SHA"
[[ "$CONFIRM" == "$EXPECTED_CONFIRMATION" ]] ||
  fail "set CONFIRM_ISSUE_176_RECONCILE=$EXPECTED_CONFIRMATION"
[[ "$STACK" == "AgentAuthSaas" ]] || fail "reconciliation is restricted to AgentAuthSaas"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
[[ "$(git -C "$REPO_ROOT" rev-parse HEAD)" == "$EXPECTED_COMMIT" ]] ||
  fail "local HEAD must equal EXPECTED_COMMIT"
[[ -z "$(git -C "$REPO_ROOT" status --porcelain \
  --untracked-files=normal --ignore-submodules=dirty)" ]] ||
  fail "reconciliation requires a clean worktree"

LOCAL_ASSET="$REPO_ROOT/target/lambda/agent-auth-lambda"
LOCAL_BOOTSTRAP="$LOCAL_ASSET/bootstrap"
LOCAL_PROVENANCE="$LOCAL_ASSET/deployment-provenance.json"
[[ -x "$LOCAL_BOOTSTRAP" && -f "$LOCAL_PROVENANCE" ]] ||
  fail "build exact-commit Auth Lambda artifacts before reconciliation"
LOCAL_BOOTSTRAP_SHA256="$(sha256sum "$LOCAL_BOOTSTRAP" | cut -d' ' -f1)"
jq -e --arg commit "$EXPECTED_COMMIT" --arg sha "$LOCAL_BOOTSTRAP_SHA256" '
  (keys | sort) == (["bootstrap_sha256","commit","schema"] | sort)
  and .schema == "agent-auth-lambda-provenance-v1"
  and .commit == $commit
  and .bootstrap_sha256 == $sha
' "$LOCAL_PROVENANCE" >/dev/null ||
  fail "local Auth provenance does not bind EXPECTED_COMMIT"

mkdir -p "$STATE_DIR"
chmod 0700 "$STATE_DIR"
[[ "$(stat -c '%a' "$STATE_DIR")" == "700" ]] ||
  fail "STATE_DIR must have mode 0700"
WORK="$(mktemp -d)"
chmod 0700 "$WORK"
MANIFEST="$STATE_DIR/manifest.json"
ADMIN_HEADER="$WORK/admin.headers"
SUCCESS=0

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  find "$WORK" -type f -delete
  find "$WORK" -depth -type d -empty -delete
  rmdir "$WORK" 2>/dev/null || true
  if [[ "$status" -ne 0 || "$SUCCESS" != "1" ]]; then
    rm -f "$EVIDENCE_FILE"
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

stack_output() {
  local key="$1"
  jq -er --arg key "$key" '
    [.Stacks[0].Outputs[] | select(.OutputKey == $key) | .OutputValue]
    | if length == 1 then .[0] else error("missing stack output " + $key) end
  ' "$WORK/stack.json"
}

tpk() {
  printf '%s\x1f%s' "$TENANT" "$1"
}

ddb_item_absent() {
  local table="$1" key="$2" output
  if ! output="$(aws dynamodb get-item \
    --profile "$PROFILE" --region "$REGION" --table-name "$table" \
    --consistent-read --key "$key" --output json)"; then
    return 1
  fi
  [[ -z "$output" ]] && return 0
  jq -e 'has("Item") | not' <<<"$output" >/dev/null
}

scan_tables() {
  aws dynamodb scan \
    --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
    --consistent-read --output json >"$WORK/clients.json"
  aws dynamodb scan \
    --profile "$PROFILE" --region "$REGION" --table-name "$GRANTS_TABLE" \
    --consistent-read --projection-expression 'grant_id,grant_json' \
    --output json >"$WORK/grants.json"
}

matching_grants() {
  local clients_json="$1" output="$2" prefix
  prefix="$(printf '%s\x1f' "$TENANT")"
  jq -cS --arg prefix "$prefix" --argjson clients "$clients_json" '
    [
      .Items[]?
      | select(.grant_id.S | startswith($prefix))
      | . as $item
      | ($item.grant_json.S | fromjson) as $grant
      | select($clients | index($grant.client_id))
      | {
          physical_grant_id: $item.grant_id.S,
          grant_json: $item.grant_json.S,
          grant_id: ($item.grant_id.S | ltrimstr($prefix)),
          client_id: $grant.client_id,
          user_id: $grant.user_id,
          status: $grant.status,
          expires_at: $grant.constraints.expires_at
        }
    ]
    | sort_by(.client_id, .grant_id)
  ' "$WORK/grants.json" >"$output"
}

prepare_manifest() {
  local prefix selected now
  prefix="$(printf '%s\x1f' "$TENANT")"
  scan_tables
  jq -cS --arg prefix "$prefix" --argjson expected "$EXPECTED_CREATED_AT" '
    [
      .Items[]?
      | select(.client_id.S | startswith($prefix))
      | select((.redirect_uris.L | map(.S)) == ["https://app.example.com/cb"])
      | select(.token_endpoint_auth_method.S == "none")
      | select(.oidc_sector_identifier.S == "app.example.com")
      | select((.registration_token_credentials.S | length) > 0)
      | select(has("client_secret") | not)
      | select(has("client_secret_credentials") | not)
      | select(has("tombstoned_at") | not)
      | select((.created_at.N | tonumber) as $created | $expected | index($created))
      | {
          client_id: (.client_id.S | ltrimstr($prefix)),
          created_at: (.created_at.N | tonumber),
          authority_revision: ((.authority_revision.N // "0") | tonumber)
        }
    ]
    | sort_by(.created_at)
    | select(length == 6)
    | select((map(.created_at)) == $expected)
  ' "$WORK/clients.json" >"$WORK/selected-clients.json" ||
    fail "production rows do not match the exact six-client historical fingerprint"
  [[ -s "$WORK/selected-clients.json" ]] ||
    fail "production rows do not match the exact six-client historical fingerprint"

  selected="$(jq -c 'map(.client_id)' "$WORK/selected-clients.json")"
  matching_grants "$selected" "$WORK/selected-grants.json"
  now="$(date -u +%s)"
  jq -e --argjson clients "$selected" --argjson now "$now" '
    length == 12
    and all(.[];
      .user_id == "alice"
      and .status == "active"
      and .expires_at > $now
      and (.client_id as $client_id | ($clients | index($client_id)))
    )
    and (
      group_by(.client_id)
      | length == 6
      and all(.[]; length == 2)
    )
  ' "$WORK/selected-grants.json" >/dev/null ||
    fail "selected clients do not own exactly twelve active alice Grants"
  jq -cS --arg prefix "$prefix" '
    [
      .Items[]?
      | select(.grant_id.S | startswith($prefix))
      | . as $item
      | ($item.grant_json.S | fromjson) as $grant
      | select($grant.user_id == "alice")
      | {
          physical_grant_id: $item.grant_id.S,
          grant_json: $item.grant_json.S,
          grant_id: ($item.grant_id.S | ltrimstr($prefix)),
          client_id: $grant.client_id,
          user_id: $grant.user_id,
          status: $grant.status,
          expires_at: $grant.constraints.expires_at
        }
    ]
    | sort_by(.client_id, .grant_id)
  ' "$WORK/grants.json" >"$WORK/all-alice-grants.json"
  cmp -s "$WORK/selected-grants.json" "$WORK/all-alice-grants.json" ||
    fail "t1/alice owns a Grant outside the exact twelve-row historical fingerprint"

  ddb_item_absent "$USERS_TABLE" \
    "$(jq -cn --arg id "$(tpk alice)" '{user_id:{S:$id}}')" ||
    fail "canonical t1/alice exists; reconciliation fingerprint is no longer valid"

  jq -n --arg schema "issue-176-reconciliation-v2" \
    --arg stack_id "$STACK_ID" --arg commit "$EXPECTED_COMMIT" \
    --arg clients_table "$CLIENTS_TABLE" --arg grants_table "$GRANTS_TABLE" \
    --arg users_table "$USERS_TABLE" --arg refresh_table "$REFRESH_TABLE" \
    --slurpfile clients "$WORK/selected-clients.json" \
    --slurpfile grants "$WORK/selected-grants.json" '
      {
        schema:$schema,
        stack_id:$stack_id,
        deployment_commit:$commit,
        tables:{
          clients:$clients_table,
          grants:$grants_table,
          users:$users_table,
          refresh:$refresh_table
        },
        clients:$clients[0],
        grants:$grants[0],
        completed_clients:[]
      }
    ' >"$MANIFEST"
  chmod 0600 "$MANIFEST"
}

validate_manifest() {
  [[ -s "$MANIFEST" && "$(stat -c '%a' "$MANIFEST")" == "600" ]] ||
    fail "restart manifest is missing or has unsafe permissions"
  jq -e --arg stack_id "$STACK_ID" --arg commit "$EXPECTED_COMMIT" \
    --arg tenant_prefix "$(printf '%s\x1f' "$TENANT")" \
    --arg clients "$CLIENTS_TABLE" --arg grants "$GRANTS_TABLE" \
    --arg users "$USERS_TABLE" --arg refresh "$REFRESH_TABLE" '
      .schema == "issue-176-reconciliation-v2"
      and .stack_id == $stack_id
      and .deployment_commit == $commit
      and .tables == {
        clients:$clients,
        grants:$grants,
        users:$users,
        refresh:$refresh
      }
      and (.clients | length) == 6
      and (.grants | length) == 12
      and all(.clients[];
        (.client_id | type) == "string"
        and (.created_at | type) == "number"
        and (.authority_revision | type) == "number"
      )
      and all(.grants[];
        . as $entry
        | ($entry.grant_json | fromjson) as $grant
        | $entry.physical_grant_id == ($tenant_prefix + $entry.grant_id)
        and $grant.grant_id == $entry.grant_id
        and $grant.client_id == $entry.client_id
        and $grant.user_id == $entry.user_id
        and $grant.status == $entry.status
        and $grant.constraints.expires_at == $entry.expires_at
      )
      and (.completed_clients | type) == "array"
    ' "$MANIFEST" >/dev/null ||
    fail "restart manifest does not match the current deployment"
}

client_absent() {
  local client_id="$1"
  ddb_item_absent "$CLIENTS_TABLE" \
    "$(jq -cn --arg id "$(tpk "$client_id")" '{client_id:{S:$id}}')"
}

remaining_attributable_grant_count() {
  local client_id="$1"
  aws dynamodb scan \
    --profile "$PROFILE" --region "$REGION" --table-name "$GRANTS_TABLE" \
    --consistent-read --projection-expression 'grant_id,grant_json' \
    --output json >"$WORK/grants-current.json" || return 1
  jq -er --arg client "$client_id" --argjson expected "$(
    jq -c --arg client "$client_id" \
      '[.grants[] | select(.client_id == $client)]' "$MANIFEST"
  )" '
    [
      .Items[]?
      | . as $item
      | ($item.grant_json.S | fromjson) as $grant
      | select(
          ($item.grant_id.S as $key
            | $expected | any(.physical_grant_id == $key))
          or ($grant.grant_id as $id
            | $expected | any(.grant_id == $id))
          or $grant.client_id == $client
        )
    ]
    | length
  ' "$WORK/grants-current.json"
}

remaining_alice_grant_count() {
  aws dynamodb scan \
    --profile "$PROFILE" --region "$REGION" --table-name "$GRANTS_TABLE" \
    --consistent-read --projection-expression 'grant_id,grant_json' \
    --output json >"$WORK/grants-current.json" || return 1
  jq -er --arg prefix "$(printf '%s\x1f' "$TENANT")" '
    [
      .Items[]?
      | select(.grant_id.S | startswith($prefix))
      | select((.grant_json.S | fromjson).user_id == "alice")
    ]
    | length
  ' "$WORK/grants-current.json"
}

validate_current_alice_manifest_subset() {
  local expected
  expected="$(jq -cS '
    [.grants[] | {physical_grant_id,grant_json}] | sort_by(.physical_grant_id)
  ' "$MANIFEST")"
  jq -cS --arg prefix "$(printf '%s\x1f' "$TENANT")" '
    [
      .Items[]?
      | select(.grant_id.S | startswith($prefix))
      | select((.grant_json.S | fromjson).user_id == "alice")
      | {physical_grant_id:.grant_id.S,grant_json:.grant_json.S}
    ]
    | sort_by(.physical_grant_id)
  ' "$WORK/grants.json" >"$WORK/alice-grants-current.json"
  jq -e --argjson expected "$expected" '
    all(.[]; . as $current | any($expected[]; . == $current))
  ' "$WORK/alice-grants-current.json" >/dev/null ||
    fail "current t1/alice Grants are not an exact subset of the proven manifest"
}

active_refresh_count() {
  local clients_json="$1"
  aws dynamodb scan \
    --profile "$PROFILE" --region "$REGION" --table-name "$REFRESH_TABLE" \
    --consistent-read --projection-expression 'family_id,client_id,revoked' \
    --output json >"$WORK/refresh-current.json" || return 1
  jq -er --arg prefix "$(printf '%s\x1f' "$TENANT")" --argjson clients "$clients_json" '
    [
      .Items[]?
      | select(.family_id.S | startswith($prefix))
      | select(.client_id.S | startswith($prefix))
      | (.client_id.S | ltrimstr($prefix)) as $client_id
      | select($clients | index($client_id))
      | select((.revoked.BOOL // false) == false)
    ]
    | length
  ' "$WORK/refresh-current.json"
}

mark_completed() {
  local client_id="$1"
  jq --arg client "$client_id" '
    .completed_clients = ((.completed_clients + [$client]) | unique | sort)
  ' "$MANIFEST" >"$STATE_DIR/manifest.next.json"
  chmod 0600 "$STATE_DIR/manifest.next.json"
  mv "$STATE_DIR/manifest.next.json" "$MANIFEST"
}

revalidate_unfinished_client() {
  local client_id="$1" expected_client expected_grants expected_exact tombstoned
  expected_client="$(jq -c --arg client "$client_id" \
    '.clients[] | select(.client_id == $client)' "$MANIFEST")"
  [[ -n "$expected_client" ]] || fail "manifest is missing an unfinished client"
  aws dynamodb get-item \
    --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
    --consistent-read \
    --key "$(jq -cn --arg id "$(tpk "$client_id")" '{client_id:{S:$id}}')" \
    --output json >"$WORK/client-current.json"
  jq -e --argjson expected "$expected_client" --arg expected_key "$(tpk "$client_id")" '
    .Item as $item
    | $item.client_id.S == $expected_key
    and ($item.created_at.N | tonumber) == $expected.created_at
    and (($item.authority_revision.N // "0") | tonumber) == $expected.authority_revision
    and ($item.redirect_uris.L | map(.S)) == ["https://app.example.com/cb"]
    and $item.token_endpoint_auth_method.S == "none"
    and $item.oidc_sector_identifier.S == "app.example.com"
    and (($item.registration_token_credentials.S // "") | length) > 0
    and ($item | has("client_secret") | not)
    and ($item | has("client_secret_credentials") | not)
  ' "$WORK/client-current.json" >/dev/null ||
    fail "an unfinished client no longer matches the proven fingerprint"
  tombstoned="$(jq -r '.Item | has("tombstoned_at")' "$WORK/client-current.json")"

  aws dynamodb scan \
    --profile "$PROFILE" --region "$REGION" --table-name "$GRANTS_TABLE" \
    --consistent-read --projection-expression 'grant_id,grant_json' \
    --output json >"$WORK/grants.json"
  expected_grants="$(jq -cS --arg client "$client_id" \
    '[.grants[] | select(.client_id == $client)] | sort_by(.grant_id)' "$MANIFEST")"
  expected_exact="$(jq -cn --argjson expected "$expected_grants" '
    [$expected[] | {physical_grant_id,grant_json}] | sort_by(.physical_grant_id)
  ')"
  jq -cS --arg client "$client_id" --argjson expected "$expected_grants" '
    [
      .Items[]?
      | . as $item
      | ($item.grant_json.S | fromjson) as $grant
      | select(
          ($item.grant_id.S as $key
            | $expected | any(.physical_grant_id == $key))
          or ($grant.grant_id as $id
            | $expected | any(.grant_id == $id))
          or $grant.client_id == $client
        )
      | {physical_grant_id:$item.grant_id.S,grant_json:$item.grant_json.S}
    ]
    | sort_by(.physical_grant_id)
  ' "$WORK/grants.json" >"$WORK/client-grants-current.json"
  validate_current_alice_manifest_subset
  if [[ "$tombstoned" == "true" ]]; then
    jq -e --argjson expected "$expected_exact" '
      length <= 2
      and all(.[]; . as $current | any($expected[]; . == $current))
    ' "$WORK/client-grants-current.json" >/dev/null ||
      fail "a tombstoned client owns a Grant outside its proven manifest subset"
  else
    jq -e --argjson expected "$expected_exact" '
      . == $expected and length == 2
    ' "$WORK/client-grants-current.json" >/dev/null ||
      fail "an active unfinished client no longer owns exactly its two proven Grants"
  fi
  jq -n --argjson tombstoned "$tombstoned" \
    --argjson remaining "$(jq -r 'length' "$WORK/client-grants-current.json")" \
    '{tombstoned:$tombstoned,remaining_grants:$remaining}' \
    >"$WORK/client-revalidation.json"
}

aws cloudformation describe-stacks \
  --profile "$PROFILE" --region "$REGION" --stack-name "$STACK" \
  --output json >"$WORK/stack.json"
jq -e '.Stacks[0].StackStatus == "UPDATE_COMPLETE"' "$WORK/stack.json" >/dev/null ||
  fail "$STACK must be UPDATE_COMPLETE"
STACK_ID="$(jq -er '.Stacks[0].StackId' "$WORK/stack.json")"
DEPLOYED_COMMIT="$(stack_output DeploymentCommit)"
[[ "$DEPLOYED_COMMIT" == "$EXPECTED_COMMIT" ]] ||
  fail "deployed commit does not match EXPECTED_COMMIT"
AUTH_FN="$(stack_output AuthFnName)"
CLIENTS_TABLE="$(stack_output ClientsTableName)"
GRANTS_TABLE="$(stack_output GrantsTableName)"
USERS_TABLE="$(stack_output UsersTableName)"
REFRESH_TABLE="$(stack_output RefreshTableName)"

aws lambda get-function \
  --profile "$PROFILE" --region "$REGION" --function-name "$AUTH_FN" \
  --output json >"$WORK/auth-function.json"
jq -e --arg commit "$EXPECTED_COMMIT" '
  .Configuration.State == "Active"
  and .Configuration.LastUpdateStatus == "Successful"
  and .Configuration.Environment.Variables.AGENT_AUTH_DEPLOYMENT_COMMIT == $commit
  and .Configuration.Environment.Variables.AGENT_AUTH_FORM == "saas"
  and (.Configuration.Environment.Variables.AGENT_AUTH_ZONE | length > 0)
  and (.Configuration.Environment.Variables.AGENT_AUTH_BOOTSTRAP_CONFIG_SECRET_ARN | length > 0)
' "$WORK/auth-function.json" >/dev/null ||
  fail "deployed Auth runtime does not match the exact SaaS commit"

curl -fsS --proto '=https' --connect-timeout 10 --max-time 120 \
  "$(jq -er '.Code.Location' "$WORK/auth-function.json")" -o "$WORK/auth.zip"
AWS_CODE_SHA256="$(
  python3 - "$WORK/auth.zip" <<'PY'
import base64
import hashlib
import pathlib
import sys
print(base64.b64encode(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).digest()).decode())
PY
)"
[[ "$AWS_CODE_SHA256" == "$(jq -er '.Configuration.CodeSha256' "$WORK/auth-function.json")" ]] ||
  fail "downloaded Auth package does not match AWS CodeSha256"
unzip -p "$WORK/auth.zip" bootstrap >"$WORK/deployed-bootstrap"
unzip -p "$WORK/auth.zip" deployment-provenance.json >"$WORK/deployed-provenance.json"
DEPLOYED_BOOTSTRAP_SHA256="$(sha256sum "$WORK/deployed-bootstrap" | cut -d' ' -f1)"
[[ "$DEPLOYED_BOOTSTRAP_SHA256" == "$LOCAL_BOOTSTRAP_SHA256" ]] ||
  fail "deployed Auth bootstrap differs from the exact local artifact"
jq -e --arg commit "$EXPECTED_COMMIT" --arg sha "$DEPLOYED_BOOTSTRAP_SHA256" '
  .schema == "agent-auth-lambda-provenance-v1"
  and .commit == $commit
  and .bootstrap_sha256 == $sha
' "$WORK/deployed-provenance.json" >/dev/null ||
  fail "deployed Auth provenance is invalid"

ZONE="$(jq -er '.Configuration.Environment.Variables.AGENT_AUTH_ZONE' \
  "$WORK/auth-function.json")"
BOOTSTRAP_ARN="$(jq -er \
  '.Configuration.Environment.Variables.AGENT_AUTH_BOOTSTRAP_CONFIG_SECRET_ARN' \
  "$WORK/auth-function.json")"
API_URL="https://$TENANT.$ZONE"
aws secretsmanager get-secret-value \
  --profile "$PROFILE" --region "$REGION" --secret-id "$BOOTSTRAP_ARN" \
  --query SecretString --output text >"$WORK/bootstrap.json"
ADMIN_ARN="$(jq -er --arg tenant "$TENANT" \
  '.tenant_admin_secret_arns[$tenant]' "$WORK/bootstrap.json")"
aws secretsmanager get-secret-value \
  --profile "$PROFILE" --region "$REGION" --secret-id "$ADMIN_ARN" \
  --query SecretString --output text |
  jq -jer '"authorization: Bearer " + (.current.secret
    | select(type == "string" and length >= 16))' >"$ADMIN_HEADER"
printf '\n' >>"$ADMIN_HEADER"
chmod 0600 "$ADMIN_HEADER"
rm -f "$WORK/bootstrap.json"

if [[ ! -s "$MANIFEST" ]]; then
  prepare_manifest
fi
validate_manifest
pass "exact six-client/twelve-Grant historical fingerprint is bound to a private manifest"

while IFS= read -r client_id; do
  if jq -e --arg client "$client_id" \
    '.completed_clients | index($client)' "$MANIFEST" >/dev/null; then
    continue
  fi
  if client_absent "$client_id"; then
    [[ "$(remaining_attributable_grant_count "$client_id")" == "0" ]] ||
      fail "an absent historical client still owns Grants"
    mark_completed "$client_id"
    continue
  fi
  revalidate_unfinished_client "$client_id"
  REMAINING_GRANTS="$(jq -er '.remaining_grants' "$WORK/client-revalidation.json")"
  EXPECTED_REVISION="$(jq -er --arg client "$client_id" \
    '.clients[] | select(.client_id == $client) | .authority_revision' "$MANIFEST")"
  DELETE_STATUS="$(curl -sS --proto '=https' --connect-timeout 5 --max-time 60 \
    -o "$WORK/delete.body" -w '%{http_code}' -X DELETE \
    -H "@$ADMIN_HEADER" \
    -H "x-agent-auth-expected-authority-revision: $EXPECTED_REVISION" \
    "$API_URL/admin/clients/$client_id")"
  [[ "$DELETE_STATUS" == "200" ]] ||
    fail "Admin DELETE did not converge for a selected historical client"
  jq -e --argjson expected_deleted "$REMAINING_GRANTS" '
    .deleted == true
    and .deleted_grants == $expected_deleted
    and (.refresh_families | type) == "number"
  ' "$WORK/delete.body" >/dev/null ||
    fail "Admin DELETE did not prove deletion of the remaining manifest Grants"
  client_absent "$client_id" ||
    fail "selected historical client remains after Admin DELETE"
  [[ "$(remaining_attributable_grant_count "$client_id")" == "0" ]] ||
    fail "selected historical client still owns Grants after Admin DELETE"
  mark_completed "$client_id"
done < <(jq -r '.clients[].client_id' "$MANIFEST")

[[ "$(jq -r '.completed_clients | length' "$MANIFEST")" == "6" ]] ||
  fail "not all selected historical clients were reconciled"
while IFS= read -r client_id; do
  client_absent "$client_id" || fail "selected client remains after reconciliation"
  [[ "$(remaining_attributable_grant_count "$client_id")" == "0" ]] ||
    fail "selected client still owns Grants after reconciliation"
done < <(jq -r '.clients[].client_id' "$MANIFEST")
[[ "$(remaining_alice_grant_count)" == "0" ]] ||
  fail "t1/alice still owns a Grant after reconciliation"
CLIENTS_JSON="$(jq -c '.clients | map(.client_id)' "$MANIFEST")"
[[ "$(active_refresh_count "$CLIENTS_JSON")" == "0" ]] ||
  fail "a selected historical client retains an active refresh family"

SELECTION_DIGEST="$(
  jq -cS '{clients,grants}' "$MANIFEST" | sha256sum | cut -d' ' -f1
)"
jq -n --arg schema "agent-auth-issue-176-evidence-v1" \
  --arg deployment_commit "$EXPECTED_COMMIT" \
  --arg harness_commit "$(git -C "$REPO_ROOT" rev-parse HEAD)" \
  --arg auth_bootstrap_sha256 "$DEPLOYED_BOOTSTRAP_SHA256" \
  --arg selection_sha256 "$SELECTION_DIGEST" '
    {
      schema:$schema,
      result:"pass",
      deployment_commit:$deployment_commit,
      harness_commit:$harness_commit,
      deployed_auth_bootstrap_sha256:$auth_bootstrap_sha256,
      selected_clients:6,
      selected_active_grants:12,
      selected_active_refresh_families_after_reconciliation:0,
      selection_sha256:$selection_sha256,
      client_tombstone_cascade_verified:true,
      raw_identifiers_recorded:false
    }
  ' >"$EVIDENCE_FILE"

rm -f "$MANIFEST"
rmdir "$STATE_DIR" 2>/dev/null || true
SUCCESS=1
pass "six historical clients and twelve active Grants were reconciled through Admin DELETE"
printf 'Evidence: %s\n' "$EVIDENCE_FILE"
