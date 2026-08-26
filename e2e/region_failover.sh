#!/usr/bin/env bash
# Replay-safe Agent Auth regional failover/failback drill (issue #29).
#
# A qualifying run performs two 330-second quiescence windows. Each deadline is
# persisted after both RegionControlTable replicas confirm source shutdown, so
# RUN_ID can resume after a host restart without shortening either window.
#
# Usage:
#   AWS_PROFILE=default SAAS_ZONE=example.com ./e2e/region_failover.sh
#   ACTION=status RUN_ID=<id> AWS_PROFILE=default ./e2e/region_failover.sh
#   ACTION=rollback RUN_ID=<id> AWS_PROFILE=default ./e2e/region_failover.sh
set -euo pipefail
set +x

ACTION="${ACTION:-run}"
PROFILE="${AWS_PROFILE:-default}"
PRIMARY_REGION="${PRIMARY_REGION:-us-east-1}"
STANDBY_REGION="${STANDBY_REGION:-us-west-2}"
PRIMARY_STACK="${PRIMARY_STACK:-AgentAuthSaas}"
STANDBY_STACK="${STANDBY_STACK:-AgentAuthSaasStandby}"
TENANT="${TENANT:-t1}"
SAAS_ZONE="${SAAS_ZONE:-}"
ISSUER="${ISSUER:-${SAAS_ZONE:+https://$TENANT.$SAAS_ZONE}}"
RUN_ID_INPUT="${RUN_ID:-}"
QUIESCENCE_SECS=330
RTO_TARGET_SECS=900
RPO_TARGET_SECS=60
POLL_SECS="${POLL_SECS:-5}"
STATE_ROOT="${STATE_ROOT:-$HOME/.agent-auth-failover-drills}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "$ACTION" in
  run) ;;
  status|rollback)
    [[ -n "$RUN_ID_INPUT" ]] || {
      printf 'FAIL: ACTION=%s requires RUN_ID\n' "$ACTION" >&2
      exit 1
    }
    ;;
  *)
    printf 'FAIL: ACTION must be run, status, or rollback\n' >&2
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
SECRETS_DIR="$STATE_DIR/secrets"
EVIDENCE="$STATE_DIR/evidence.json"
PRIMARY_AWS=(aws --profile "$PROFILE" --region "$PRIMARY_REGION")
STANDBY_AWS=(aws --profile "$PROFILE" --region "$STANDBY_REGION")

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf 'PASS: %s\n' "$*"; }
info() { printf 'INFO: %s\n' "$*"; }
now_epoch() { date -u +%s; }
hash_text() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }

assert_supported_region_pair() {
  [[ "$PRIMARY_REGION" == "us-east-1" && "$STANDBY_REGION" == "us-west-2" ]] ||
    fail "qualifying failover supports only us-east-1 primary and us-west-2 standby"
}

validated_issuer_host() {
  local distribution_config="$1" issuer="$2" tenant="$3" host
  host="$(python3 - "$issuer" "$tenant" <<'PY'
import sys
from urllib.parse import urlsplit

issuer, tenant = sys.argv[1:]
try:
    parsed = urlsplit(issuer)
    port = parsed.port
except ValueError:
    raise SystemExit(1)
host = parsed.hostname
valid = (
    parsed.scheme == "https"
    and host is not None
    and parsed.netloc == host
    and port is None
    and parsed.path == ""
    and parsed.query == ""
    and parsed.fragment == ""
    and host.partition(".")[0] == tenant
    and bool(host.partition(".")[2])
)
if not valid:
    raise SystemExit(1)
print(host, end="")
PY
  )" || fail "ISSUER must be an exact HTTPS tenant origin without path, query, fragment, credentials, or port"
  jq -e --arg host "$host" '
    (.DistributionConfig.Aliases.Items // []) | index($host) != null
  ' "$distribution_config" >/dev/null ||
    fail "ISSUER host is not an exact alias on the deployed CloudFront distribution"
  printf '%s' "$host"
}

for command in aws date flock jq; do
  command -v "$command" >/dev/null || fail "missing command: $command"
done
if [[ "$ACTION" != "status" ]]; then
  for command in curl git python3 sha256sum unzip; do
    command -v "$command" >/dev/null || fail "missing command: $command"
  done
fi
if [[ "$ACTION" == "run" ]]; then
  python3 -c \
    'from jwt import algorithms; raise SystemExit(0 if algorithms.has_crypto else 1)' \
    >/dev/null 2>&1 ||
    fail "Python PyJWT and cryptography packages are required"
fi
assert_supported_region_pair
[[ "$POLL_SECS" =~ ^[1-9][0-9]*$ ]] || fail "POLL_SECS must be positive"
[[ "$RTO_TARGET_SECS" =~ ^[1-9][0-9]*$ ]] ||
  fail "RTO_TARGET_SECS must be positive"
[[ "$RPO_TARGET_SECS" =~ ^[1-9][0-9]*$ ]] ||
  fail "RPO_TARGET_SECS must be positive"

umask 077
mkdir -p "$STATE_ROOT"
chmod 700 "$STATE_ROOT"
exec 9>"$STATE_ROOT/.$RUN_ID.lock"
chmod 600 "$STATE_ROOT/.$RUN_ID.lock"
flock -n 9 || fail "another process owns RUN_ID=$RUN_ID"
if [[ "$ACTION" != "run" && ! -s "$CONTEXT" ]]; then
  fail "no persisted context for RUN_ID=$RUN_ID"
fi
mkdir -p "$STATE_DIR" "$SECRETS_DIR"
chmod 700 "$STATE_DIR" "$SECRETS_DIR"
touch "$STATE_DIR/drill.log"
chmod 600 "$STATE_DIR/drill.log"
exec > >(tee -a "$STATE_DIR/drill.log") 2>&1
WORK="$(mktemp -d)"
chmod 700 "$WORK"
cleanup_process_files() {
  local status=$?
  trap - EXIT INT TERM
  rm -rf "$WORK"
  exit "$status"
}
trap cleanup_process_files EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

stack_output() {
  local stack_file="$1" key="$2"
  jq -er --arg key "$key" \
    '.Stacks[0].Outputs[] | select(.OutputKey == $key) | .OutputValue' \
    "$stack_file"
}

context_value() {
  jq -er "$1" "$CONTEXT"
}

validate_local_auth_artifact() {
  local expected_commit="$1"
  local asset="$REPO_ROOT/target/lambda/agent-auth-lambda"
  local bootstrap="$asset/bootstrap"
  local manifest="$asset/deployment-provenance.json"
  local bootstrap_sha256
  [[ -f "$bootstrap" && -f "$manifest" ]] ||
    fail "build exact-commit Lambda artifacts before running the drill"
  bootstrap_sha256="$(sha256sum "$bootstrap" | cut -d' ' -f1)"
  jq -e --arg commit "$expected_commit" --arg sha "$bootstrap_sha256" '
    (keys | sort) == (["bootstrap_sha256", "commit", "schema"] | sort)
    and .schema == "agent-auth-lambda-provenance-v1"
    and .commit == $commit
    and .bootstrap_sha256 == $sha
  ' "$manifest" >/dev/null ||
    fail "local Lambda provenance does not bind the clean deployment commit"
  printf '%s' "$bootstrap_sha256"
}

auth_function_name() {
  local region="$1" stack_id="$2"
  aws --profile "$PROFILE" --region "$region" cloudformation \
    list-stack-resources --stack-name "$stack_id" --output json |
    jq -er '
      [.StackResourceSummaries[]
       | select(
           .ResourceType == "AWS::Lambda::Function"
           and (.LogicalResourceId | startswith("AuthFn"))
         )
       | .PhysicalResourceId]
      | unique
      | if length == 1 then .[0] else error("expected exactly one AuthFn") end
    '
}

validate_deployed_auth_artifact() {
  local region="$1" stack_id="$2" expected_commit="$3" label="$4"
  local expected_bootstrap_sha256 function_name function_json zip_file
  local manifest bootstrap downloaded_code_sha256 deployed_code_sha256
  local deployed_bootstrap_sha256
  expected_bootstrap_sha256="$(validate_local_auth_artifact "$expected_commit")"
  function_name="$(auth_function_name "$region" "$stack_id")"
  function_json="$WORK/$label-auth-function.json"
  zip_file="$WORK/$label-auth-function.zip"
  manifest="$WORK/$label-auth-provenance.json"
  bootstrap="$WORK/$label-auth-bootstrap"
  aws --profile "$PROFILE" --region "$region" lambda get-function \
    --function-name "$function_name" --output json >"$function_json"
  curl -fsS --proto '=https' --connect-timeout 10 --max-time 120 \
    "$(jq -er '.Code.Location' "$function_json")" -o "$zip_file"
  downloaded_code_sha256="$(
    python3 - "$zip_file" <<'PY'
import base64
import hashlib
import pathlib
import sys

print(base64.b64encode(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).digest()).decode())
PY
  )"
  deployed_code_sha256="$(jq -er '.Configuration.CodeSha256' "$function_json")"
  [[ "$downloaded_code_sha256" == "$deployed_code_sha256" ]] ||
    fail "$label downloaded Auth package does not match AWS CodeSha256"
  unzip -p "$zip_file" deployment-provenance.json >"$manifest" ||
    fail "$label Auth package is missing deployment provenance"
  unzip -p "$zip_file" bootstrap >"$bootstrap" ||
    fail "$label Auth package is missing bootstrap"
  deployed_bootstrap_sha256="$(sha256sum "$bootstrap" | cut -d' ' -f1)"
  [[ "$deployed_bootstrap_sha256" == "$expected_bootstrap_sha256" ]] ||
    fail "$label deployed Auth bootstrap differs from the exact local commit artifact"
  jq -e --arg commit "$expected_commit" --arg sha "$deployed_bootstrap_sha256" '
    (keys | sort) == (["bootstrap_sha256", "commit", "schema"] | sort)
    and .schema == "agent-auth-lambda-provenance-v1"
    and .commit == $commit
    and .bootstrap_sha256 == $sha
  ' "$manifest" >/dev/null ||
    fail "$label deployed Auth provenance does not bind the reviewed artifact"
  jq -cn \
    --arg function_name "$function_name" \
    --arg code_sha256 "$deployed_code_sha256" \
    --arg bootstrap_sha256 "$deployed_bootstrap_sha256" \
    '{
      function_name:$function_name,
      code_sha256:$code_sha256,
      bootstrap_sha256:$bootstrap_sha256
    }'
}

load_context_settings() {
  [[ -s "$CONTEXT" ]] || return 0
  PRIMARY_REGION="$(context_value '.primary_region')"
  STANDBY_REGION="$(context_value '.standby_region')"
  TENANT="$(context_value '.tenant')"
  ISSUER="$(context_value '.issuer')"
  PRIMARY_AWS=(aws --profile "$PROFILE" --region "$PRIMARY_REGION")
  STANDBY_AWS=(aws --profile "$PROFILE" --region "$STANDBY_REGION")
  assert_supported_region_pair
}

read_control_row() {
  local region="$1" key="$2" output="$3"
  local table response
  table="$(context_value '.region_control_table')"
  if ! response="$(aws --profile "$PROFILE" --region "$region" dynamodb get-item \
    --table-name "$table" --consistent-read \
    --key "$(jq -cn --arg key "$key" '{region_id:{S:$key}}')" \
    --output json)"; then
    fail "failed to read Region control row $key in $region"
  fi
  [[ -n "$response" ]] || response='{}'
  printf '%s\n' "$response" >"$output"
}

assert_region_fence_matches() {
  local row="$1" fence="$2"
  jq -e --slurpfile fence "$fence" '
    .Item.active.BOOL == $fence[0].Item.active.BOOL and
    .Item.activation_not_before.N == $fence[0].Item.activation_not_before.N and
    .Item.revision.N == $fence[0].Item.revision.N
  ' "$row" >/dev/null
}

control_revision() {
  local region="$1"
  local output="$STATE_DIR/control-$region.json"
  read_control_row "$region" control "$output"
  jq -er '.Item.revision.N | tonumber' "$output"
}

coordinator_field() {
  local region="$1" field="$2"
  local output="$STATE_DIR/control-$region.json"
  read_control_row "$region" control "$output"
  jq -er --arg field "$field" '.Item[$field].S' "$output"
}

assert_coordinated_writer() {
  local expected="$1" deadline=$(( $(now_epoch) + 120 ))
  local region coordinator coordinator_revision source target
  source="$(context_value '.primary_region')"
  target="$(context_value '.standby_region')"
  while (( $(now_epoch) < deadline )); do
    local all_ok=1
    for region in "$source" "$target"; do
      read_control_row "$region" control "$STATE_DIR/control-$region.json"
      read_control_row "$region" "$source" "$STATE_DIR/source-$region.json"
      read_control_row "$region" "$target" "$STATE_DIR/target-$region.json"
      read_control_row "$region" "fence#$expected" \
        "$STATE_DIR/fence-$expected-$region.json"
      coordinator="$(jq -r '
        [.Item.state.S, .Item.active_region.S, .Item.revision.N] | @tsv
      ' "$STATE_DIR/control-$region.json")"
      if [[ "$coordinator" != $'active\t'"$expected"$'\t'* ]]; then
        all_ok=0
        break
      fi
      coordinator_revision="$(jq -er '.Item.revision.N' \
        "$STATE_DIR/control-$region.json")"
      if [[ "$expected" == "$source" ]]; then
        jq -e --arg revision "$coordinator_revision" '
          .Item.active.BOOL == true and .Item.revision.N == $revision
        ' "$STATE_DIR/source-$region.json" >/dev/null || all_ok=0
        assert_region_fence_matches "$STATE_DIR/source-$region.json" \
          "$STATE_DIR/fence-$expected-$region.json" || all_ok=0
        jq -e '(.Item.active.BOOL // false) == false' \
          "$STATE_DIR/target-$region.json" >/dev/null || all_ok=0
      else
        jq -e --arg revision "$coordinator_revision" '
          .Item.active.BOOL == true and .Item.revision.N == $revision
        ' "$STATE_DIR/target-$region.json" >/dev/null || all_ok=0
        assert_region_fence_matches "$STATE_DIR/target-$region.json" \
          "$STATE_DIR/fence-$expected-$region.json" || all_ok=0
        jq -e '(.Item.active.BOOL // false) == false' \
          "$STATE_DIR/source-$region.json" >/dev/null || all_ok=0
      fi
    done
    if [[ "$all_ok" == "1" ]]; then
      pass "both replicas show exactly one coordinated writer: $expected"
      return
    fi
    sleep "$POLL_SECS"
  done
  fail "Region control replicas did not converge to writer $expected"
}

desired_quiesced() {
  local region="$1" source="$2" revision="$3"
  read_control_row "$region" control "$STATE_DIR/check-control.json"
  read_control_row "$region" "$source" "$STATE_DIR/check-source.json"
  read_control_row "$region" "fence#$source" "$STATE_DIR/check-source-fence.json"
  jq -e --arg source "$source" --arg revision "$revision" --arg run "$RUN_ID" '
    .Item.state.S == "quiescing" and
    .Item.active_region.S == $source and
    .Item.revision.N == $revision and
    .Item.operation_id.S == $run
  ' "$STATE_DIR/check-control.json" >/dev/null &&
    jq -e --arg revision "$revision" '
      .Item.active.BOOL == false and .Item.revision.N == $revision
    ' "$STATE_DIR/check-source.json" >/dev/null &&
    assert_region_fence_matches "$STATE_DIR/check-source.json" \
      "$STATE_DIR/check-source-fence.json"
}

assert_quiesced() {
  local source="$1" revision="$2"
  local region primary standby deadline=$(( $(now_epoch) + 120 ))
  primary="$(context_value '.primary_region')"
  standby="$(context_value '.standby_region')"
  while (( $(now_epoch) < deadline )); do
    local all_ok=1
    for region in "$primary" "$standby"; do
      if ! desired_quiesced "$region" "$source" "$revision"; then
        all_ok=0
        break
      fi
    done
    if [[ "$all_ok" == "1" ]]; then
      pass "both replicas confirm $source quiesced at revision $revision"
      return
    fi
    sleep "$POLL_SECS"
  done
  fail "Region control replicas did not confirm $source quiescence"
}

persist_quiesce_started() {
  local source="$1" revision="$2"
  local marker="$STATE_DIR/quiesce-$revision.started"
  [[ -s "$marker" ]] && return
  local control="$STATE_DIR/control-quiesced-$revision.json" changed_at
  read_control_row "$(context_value '.primary_region')" control "$control"
  jq -e --arg source "$source" --arg revision "$revision" --arg run "$RUN_ID" '
    .Item.state.S == "quiescing" and
    .Item.active_region.S == $source and
    .Item.revision.N == $revision and
    .Item.operation_id.S == $run and
    (.Item.changed_at.N | test("^[0-9]+$"))
  ' "$control" >/dev/null ||
    fail "cannot recover quiescence start for revision $revision"
  changed_at="$(jq -er '.Item.changed_at.N | tonumber' "$control")"
  printf '%s\n' "$changed_at" >"$marker"
  chmod 600 "$marker"
}

quiesce_region() {
  local source="$1" expected_revision="$2" revision="$3"
  local changed_at control_region request="$STATE_DIR/quiesce-$revision.json"
  control_region="$(context_value '.primary_region')"
  changed_at="$(now_epoch)"
  jq -n \
    --arg table "$(context_value '.region_control_table')" \
    --arg source "$source" \
    --arg run "$RUN_ID" \
    --arg expected "$expected_revision" \
    --arg revision "$revision" \
    --arg now "$changed_at" '
    [
      {Update:{
        TableName:$table,
        Key:{region_id:{S:"control"}},
        UpdateExpression:"SET #state = :quiescing, active_region = :source, revision = :revision, changed_at = :now, operation_id = :run REMOVE standby_region_local_purge_revision, standby_region_local_purge_completed_at",
        ConditionExpression:"#state = :active_state AND active_region = :source AND revision = :expected",
        ExpressionAttributeNames:{"#state":"state"},
        ExpressionAttributeValues:{
          ":quiescing":{S:"quiescing"},":active_state":{S:"active"},
          ":source":{S:$source},":run":{S:$run},":revision":{N:$revision},
          ":expected":{N:$expected},":now":{N:$now}
        }
      }},
      {Update:{
        TableName:$table,
        Key:{region_id:{S:$source}},
        UpdateExpression:"SET #active = :false, activation_not_before = :zero, revision = :revision, changed_at = :now",
        ConditionExpression:"#active = :true AND revision = :expected",
        ExpressionAttributeNames:{"#active":"active"},
        ExpressionAttributeValues:{
          ":false":{BOOL:false},":true":{BOOL:true},":zero":{N:"0"},
          ":revision":{N:$revision},":expected":{N:$expected},":now":{N:$now}
        }
      }},
      {Update:{
        TableName:$table,
        Key:{region_id:{S:("fence#" + $source)}},
        UpdateExpression:"SET #active = :false, activation_not_before = :zero, revision = :revision, changed_at = :now",
        ConditionExpression:"#active = :true AND revision = :expected",
        ExpressionAttributeNames:{"#active":"active"},
        ExpressionAttributeValues:{
          ":false":{BOOL:false},":true":{BOOL:true},":zero":{N:"0"},
          ":revision":{N:$revision},":expected":{N:$expected},":now":{N:$now}
        }
      }}
    ]' >"$request"
  if ! aws --profile "$PROFILE" --region "$control_region" dynamodb \
    transact-write-items --transact-items "file://$request" >/dev/null 2>&1; then
    desired_quiesced "$control_region" "$source" "$revision" ||
      fail "quiesce CAS failed for $source at revision $revision"
  fi
  persist_quiesce_started "$source" "$revision"
  info "quiesced $source revision=$revision changed_at=$(<"$STATE_DIR/quiesce-$revision.started")"
}

wait_quiescence() {
  local source="$1" revision="$2" observed_at deadline remaining
  local observed_file="$STATE_DIR/quiesce-$revision.observed"
  assert_quiesced "$source" "$revision"
  persist_quiesce_started "$source" "$revision"
  if [[ ! -s "$observed_file" ]]; then
    now_epoch >"$observed_file"
    chmod 600 "$observed_file"
  fi
  observed_at="$(<"$observed_file")"
  [[ "$observed_at" =~ ^[0-9]+$ ]] ||
    fail "invalid persisted quiescence observation for revision $revision"
  read_control_row "$(context_value '.primary_region')" control \
    "$STATE_DIR/control-wait.json"
  jq -e --arg revision "$revision" --arg run "$RUN_ID" '
    .Item.state.S == "quiescing" and .Item.revision.N == $revision and
    .Item.operation_id.S == $run
  ' "$STATE_DIR/control-wait.json" >/dev/null ||
    fail "cannot wait: coordinator is not quiescing at revision $revision"
  deadline=$(( observed_at + QUIESCENCE_SECS ))
  while (( $(now_epoch) < deadline )); do
    remaining=$(( deadline - $(now_epoch) ))
    info "quiescence revision=$revision remaining=${remaining}s"
    sleep "$(( remaining < POLL_SECS ? remaining : POLL_SECS ))"
  done
  pass "quiescence revision=$revision completed (${QUIESCENCE_SECS}s)"
}

purge_region_local_table() {
  local region="$1" role="$2" table="$3"
  local description="$WORK/purge-$role-description.json"
  local page="$WORK/purge-$role-page.json"
  local request="$WORK/purge-$role-request.json"
  local response="$WORK/purge-$role-response.json"
  local key_names projection names count remaining deadline
  local deleted=0
  [[ "$role" =~ ^[A-Za-z][A-Za-z0-9]*$ ]] ||
    fail "invalid standby Region-local table role"
  [[ "$table" =~ ^[A-Za-z0-9_.-]{3,255}$ ]] ||
    fail "invalid standby Region-local table name for $role"
  aws --profile "$PROFILE" --region "$region" dynamodb describe-table \
    --table-name "$table" --output json >"$description"
  jq -e --arg table "$table" --arg region "$region" '
    .Table.TableName == $table and
    .Table.TableStatus == "ACTIVE" and
    (.Table.TableArn | split(":")[3]) == $region and
    (.Table.KeySchema | length >= 1 and length <= 2) and
    ([.Table.KeySchema[].KeyType] | sort) ==
      (if (.Table.KeySchema | length) == 1
       then ["HASH"] else ["HASH","RANGE"] end)
  ' "$description" >/dev/null ||
    fail "standby Region-local table $role is not an active table in $region"
  key_names="$(jq -c '[.Table.KeySchema[].AttributeName]' "$description")"
  projection="$(jq -r '
    to_entries | map("#k" + (.key | tostring)) | join(",")
  ' <<<"$key_names")"
  names="$(jq -cn --argjson keys "$key_names" '
    $keys
    | to_entries
    | map({key: ("#k" + (.key | tostring)), value: .value})
    | from_entries
  ')"
  deadline=$(( $(now_epoch) + RTO_TARGET_SECS ))
  while true; do
    (( $(now_epoch) < deadline )) ||
      fail "timed out purging standby Region-local table $role"
    aws --profile "$PROFILE" --region "$region" dynamodb scan \
      --table-name "$table" --consistent-read --no-paginate --limit 25 \
      --projection-expression "$projection" \
      --expression-attribute-names "$names" --output json >"$page"
    count="$(jq -er '.Items | length' "$page")"
    if [[ "$count" == "0" ]]; then
      break
    fi
    jq --arg table "$table" --argjson keys "$key_names" '
      {
        RequestItems: {
          ($table): [
            .Items[] |
            {DeleteRequest: {
              Key: with_entries(select(.key as $key | $keys | index($key)))
            }}
          ]
        }
      }
    ' "$page" >"$request"
    while true; do
      (( $(now_epoch) < deadline )) ||
        fail "timed out retrying standby Region-local deletes for $role"
      aws --profile "$PROFILE" --region "$region" dynamodb batch-write-item \
        --request-items "file://$request" --output json >"$response"
      remaining="$(jq -er --arg table "$table" \
        '.UnprocessedItems[$table] // [] | length' "$response")"
      [[ "$remaining" == "0" ]] && break
      jq '{RequestItems: .UnprocessedItems}' "$response" >"$request"
      sleep 1
    done
    deleted=$(( deleted + count ))
  done
  TABLE_PURGED_COUNT="$deleted"
  pass "standby Region-local table $role is empty (deleted $deleted rows)"
}

purge_standby_region_local_tables() {
  local standby table_count deleted_total=0 role table
  local receipt="$STATE_DIR/standby-region-local-purge.json"
  local temporary="$receipt.tmp.$$"
  standby="$(context_value '.standby_region')"
  table_count="$(context_value '.standby_region_local_tables | length')"
  [[ "$table_count" == "20" ]] ||
    fail "persisted standby Region-local table inventory is incomplete"
  while IFS=$'\t' read -r role table; do
    purge_region_local_table "$standby" "$role" "$table"
    deleted_total=$(( deleted_total + TABLE_PURGED_COUNT ))
  done < <(jq -r '
    .standby_region_local_tables
    | to_entries | sort_by(.key)[] | [.key,.value] | @tsv
  ' "$CONTEXT")
  jq -n --arg region "$standby" \
    --argjson table_count "$table_count" \
    --argjson deleted_items "$deleted_total" \
    --argjson completed_at "$(now_epoch)" '{
      region:$region,table_count:$table_count,deleted_items:$deleted_items,
      completed_at:$completed_at,verified_empty:true
    }' >"$temporary"
  chmod 600 "$temporary"
  mv "$temporary" "$receipt"
  pass "all standby Region-local tables are empty"
}

desired_standby_region_local_purge() {
  local region="$1" source="$2" revision="$3"
  read_control_row "$region" control "$STATE_DIR/check-control.json"
  jq -e --arg source "$source" --arg revision "$revision" --arg run "$RUN_ID" '
    .Item.state.S == "quiescing" and
    .Item.active_region.S == $source and
    .Item.revision.N == $revision and
    .Item.operation_id.S == $run and
    .Item.standby_region_local_purge_revision.N == $revision
  ' "$STATE_DIR/check-control.json" >/dev/null
}

record_standby_region_local_purge() {
  local source="$1" revision="$2"
  local control_region completed_at request
  request="$STATE_DIR/standby-region-local-purge-$revision.json"
  control_region="$(context_value '.primary_region')"
  completed_at="$(now_epoch)"
  [[ "$source" == "$(context_value '.standby_region')" ]] ||
    fail "Region-local purge gate can be recorded only for the standby"
  jq -n \
    --arg table "$(context_value '.region_control_table')" \
    --arg source "$source" --arg run "$RUN_ID" \
    --arg revision "$revision" --arg now "$completed_at" '{
      TableName:$table,
      Key:{region_id:{S:"control"}},
      UpdateExpression:"SET standby_region_local_purge_revision = :revision, standby_region_local_purge_completed_at = :now",
      ConditionExpression:"#state = :quiescing AND active_region = :source AND revision = :revision AND operation_id = :run",
      ExpressionAttributeNames:{"#state":"state"},
      ExpressionAttributeValues:{
        ":quiescing":{S:"quiescing"},":source":{S:$source},":run":{S:$run},
        ":revision":{N:$revision},":now":{N:$now}
      }
    }' >"$request"
  if ! aws --profile "$PROFILE" --region "$control_region" dynamodb update-item \
    --cli-input-json "file://$request" >/dev/null 2>&1; then
    desired_standby_region_local_purge "$control_region" "$source" "$revision" ||
      fail "could not persist standby Region-local purge gate"
  fi
  desired_standby_region_local_purge "$control_region" "$source" "$revision" ||
    fail "standby Region-local purge gate was not persisted"
  pass "persisted standby Region-local purge gate at revision $revision"
}

desired_active() {
  local region="$1" target="$2" revision="$3"
  read_control_row "$region" control "$STATE_DIR/check-control.json"
  read_control_row "$region" "$target" "$STATE_DIR/check-target.json"
  read_control_row "$region" "fence#$target" "$STATE_DIR/check-target-fence.json"
  jq -e --arg target "$target" --arg revision "$revision" --arg run "$RUN_ID" '
    .Item.state.S == "active" and
    .Item.active_region.S == $target and
    .Item.revision.N == $revision and
    .Item.operation_id.S == $run
  ' "$STATE_DIR/check-control.json" >/dev/null &&
    jq -e --arg revision "$revision" '
      .Item.active.BOOL == true and .Item.revision.N == $revision
    ' "$STATE_DIR/check-target.json" >/dev/null &&
    assert_region_fence_matches "$STATE_DIR/check-target.json" \
      "$STATE_DIR/check-target-fence.json"
}

activate_region() {
  local target="$1" source="$2" quiesce_revision="$3" revision="$4"
  local activated_at control_region deadline request="$STATE_DIR/activate-$revision.json"
  local target_row="$STATE_DIR/target-activated-$revision.json"
  control_region="$(context_value '.primary_region')"
  deadline=$(( $(now_epoch) + 120 ))
  while :; do
    activated_at="$(now_epoch)"
    jq -n \
      --arg table "$(context_value '.region_control_table')" \
      --arg source "$source" --arg target "$target" \
      --arg standby "$(context_value '.standby_region')" \
      --arg run "$RUN_ID" \
      --arg quiesce "$quiesce_revision" --arg revision "$revision" \
      --arg now "$activated_at" '
      [
        {Update:{
          TableName:$table,
          Key:{region_id:{S:"control"}},
          UpdateExpression:"SET #state = :active_state, active_region = :target, revision = :revision, changed_at = :now, operation_id = :run",
          ConditionExpression:(
            "#state = :quiescing AND active_region = :source AND revision = :quiesce AND operation_id = :run" +
            (if $source == $standby
             then " AND standby_region_local_purge_revision = :quiesce"
             else "" end)
          ),
          ExpressionAttributeNames:{"#state":"state"},
          ExpressionAttributeValues:{
            ":active_state":{S:"active"},":quiescing":{S:"quiescing"},
            ":source":{S:$source},":target":{S:$target},":run":{S:$run},
            ":revision":{N:$revision},":quiesce":{N:$quiesce},":now":{N:$now}
          }
        }},
        {Update:{
          TableName:$table,
          Key:{region_id:{S:$target}},
          UpdateExpression:"SET #active = :true, activation_not_before = :now, revision = :revision, changed_at = :now",
          ConditionExpression:"attribute_not_exists(region_id) OR (#active = :false AND (attribute_not_exists(revision) OR revision < :revision))",
          ExpressionAttributeNames:{"#active":"active"},
          ExpressionAttributeValues:{
            ":true":{BOOL:true},":false":{BOOL:false},
            ":revision":{N:$revision},":now":{N:$now}
          }
        }},
        {Update:{
          TableName:$table,
          Key:{region_id:{S:("fence#" + $target)}},
          UpdateExpression:"SET #active = :true, activation_not_before = :now, revision = :revision, changed_at = :now",
          ConditionExpression:"attribute_not_exists(region_id) OR (#active = :false AND (attribute_not_exists(revision) OR revision < :revision))",
          ExpressionAttributeNames:{"#active":"active"},
          ExpressionAttributeValues:{
            ":true":{BOOL:true},":false":{BOOL:false},
            ":revision":{N:$revision},":now":{N:$now}
          }
        }}
      ]' >"$request"
    if aws --profile "$PROFILE" --region "$control_region" dynamodb \
      transact-write-items --transact-items "file://$request" >/dev/null 2>&1; then
      break
    fi
    if desired_active "$control_region" "$target" "$revision"; then
      break
    fi
    (( $(now_epoch) < deadline )) ||
      fail "activation CAS failed for $target at revision $revision"
    sleep "$POLL_SECS"
  done
  read_control_row "$control_region" "$target" "$target_row"
  jq -e --arg revision "$revision" '
    .Item.active.BOOL == true and
    .Item.revision.N == $revision and
    (.Item.activation_not_before.N | test("^[0-9]+$"))
  ' "$target_row" >/dev/null ||
    fail "activated Region row is malformed at revision $revision"
  activated_at="$(jq -er '.Item.activation_not_before.N | tonumber' "$target_row")"
  printf '%s\n' "$activated_at" >"$STATE_DIR/activate-$revision.started"
  chmod 600 "$STATE_DIR/activate-$revision.started"
  info "activated $target revision=$revision not_before=$activated_at"
}

distribution_origin_host() {
  local config="$STATE_DIR/distribution-current.json"
  "${PRIMARY_AWS[@]}" cloudfront get-distribution-config \
    --id "$(context_value '.distribution_id')" >"$config"
  jq -er --arg id "$(context_value '.origin_id')" '
    .DistributionConfig.Origins.Items[] | select(.Id == $id) | .DomainName
  ' "$config"
}

switch_edge() {
  local host="$1" label="$2" current etag update
  current="$(distribution_origin_host)"
  if [[ "$current" == "$host" ]]; then
    pass "CloudFront origin already points to $label"
    return
  fi
  etag="$(jq -er '.ETag' "$STATE_DIR/distribution-current.json")"
  update="$STATE_DIR/distribution-$label.json"
  jq --arg id "$(context_value '.origin_id')" --arg host "$host" '
    .DistributionConfig
    | .Origins.Items |= map(if .Id == $id then .DomainName = $host else . end)
  ' "$STATE_DIR/distribution-current.json" >"$update"
  "${PRIMARY_AWS[@]}" cloudfront update-distribution \
    --id "$(context_value '.distribution_id')" --if-match "$etag" \
    --distribution-config "file://$update" >/dev/null
  "${PRIMARY_AWS[@]}" cloudfront wait distribution-deployed \
    --id "$(context_value '.distribution_id')"
  [[ "$(distribution_origin_host)" == "$host" ]] ||
    fail "CloudFront did not switch to $host"
  pass "CloudFront origin switched to $label"
}

curl_base() {
  local base="$1" forwarded_host="$2"
  shift 2
  if [[ -n "$forwarded_host" ]]; then
    curl -sS --proto '=https' --connect-timeout 5 --max-time 60 \
      -H "X-Forwarded-Host: $forwarded_host" \
      -H "@$SECRETS_DIR/origin-auth.headers" "$@" "$base"
  else
    curl -sS --proto '=https' --connect-timeout 5 --max-time 60 "$@" "$base"
  fi
}

wait_region_header() {
  local base="$1" forwarded_host="$2" expected="$3"
  local deadline=$(( $(now_epoch) + RTO_TARGET_SECS )) headers status observed
  while (( $(now_epoch) < deadline )); do
    headers="$STATE_DIR/region-headers"
    if [[ -n "$forwarded_host" ]]; then
      status="$(curl -sS -o /dev/null -D "$headers" -w '%{http_code}' \
        --proto '=https' --connect-timeout 5 --max-time 30 \
        -H "X-Forwarded-Host: $forwarded_host" \
        -H "@$SECRETS_DIR/origin-auth.headers" \
        "$base/.well-known/openid-configuration" || true)"
    else
      status="$(curl -sS -o /dev/null -D "$headers" -w '%{http_code}' \
        --proto '=https' --connect-timeout 5 --max-time 30 \
        "$base/.well-known/openid-configuration" || true)"
    fi
    observed="$(awk 'tolower($1)=="x-agent-auth-region:" {gsub("\r","",$2); print $2}' \
      "$headers" | tail -1)"
    if [[ "$status" == "200" && "$observed" == "$expected" ]]; then
      pass "$base serves Region $expected"
      return
    fi
    sleep "$POLL_SECS"
  done
  fail "$base did not serve Region $expected within ${RTO_TARGET_SECS}s"
}

jwks_hash() {
  local base="$1" forwarded_host="$2" output="$3"
  if [[ -n "$forwarded_host" ]]; then
    curl -fsS --proto '=https' -H "X-Forwarded-Host: $forwarded_host" \
      -H "@$SECRETS_DIR/origin-auth.headers" \
      "$base/jwks.json" |
      jq -Sc '.keys | sort_by(.kid)' >"$output"
  else
    curl -fsS --proto '=https' "$base/jwks.json" |
      jq -Sc '.keys | sort_by(.kid)' >"$output"
  fi
  sha256sum "$output" | cut -d' ' -f1
}

verify_token_pair() {
  local tokens="$1" jwks="$2" label="$3"
  python3 - "$tokens" "$jwks" "$ISSUER" \
    "$(context_value '.probe.client_id')" <<'PY'
import json
import pathlib
import sys

import jwt
from jwt import algorithms

tokens = json.loads(pathlib.Path(sys.argv[1]).read_text())
keys = json.loads(pathlib.Path(sys.argv[2]).read_text())
issuer, client = sys.argv[3], sys.argv[4]

def matching_key(token, kty, alg):
    header = jwt.get_unverified_header(token)
    matches = [
        key for key in keys
        if key.get("kid") == header.get("kid")
        and key.get("kty") == kty
        and key.get("alg") == alg
    ]
    if header.get("alg") != alg or len(matches) != 1:
        raise ValueError(
            f"no unique {alg} key for header {header!r}; "
            f"published kids={[key.get('kid') for key in keys]!r}"
        )
    return matches[0]

access = tokens["access_token"]
access_key = algorithms.ECAlgorithm.from_jwk(json.dumps(
    matching_key(access, "EC", "ES256")
))
access_claims = jwt.decode(
    access,
    key=access_key,
    algorithms=["ES256"],
    audience=issuer + "/userinfo",
    issuer=issuer,
)

identity = tokens["id_token"]
identity_key = algorithms.RSAAlgorithm.from_jwk(json.dumps(
    matching_key(identity, "RSA", "RS256")
))
identity_claims = jwt.decode(
    identity,
    key=identity_key,
    algorithms=["RS256"],
    audience=client,
    issuer=issuer,
)
if access_claims["sub"] != identity_claims["sub"]:
    raise ValueError("access and ID token subjects differ")
PY
  pass "$label ES256 access token and RS256 ID token verify against issuer JWKS"
}

assert_oauth_rejected() {
  local base="$1" forwarded_host="$2" label="$3" expected_description="$4"
  shift 4
  local body="$STATE_DIR/reject-$label.json" status
  if [[ -n "$forwarded_host" ]]; then
    status="$(curl -sS -o "$body" -w '%{http_code}' --proto '=https' \
      --connect-timeout 5 --max-time 60 \
      -H "X-Forwarded-Host: $forwarded_host" \
      -H "@$SECRETS_DIR/origin-auth.headers" "$@" "$base/token")"
  else
    status="$(curl -sS -o "$body" -w '%{http_code}' --proto '=https' \
      --connect-timeout 5 --max-time 60 "$@" "$base/token")"
  fi
  if [[ "$status" != "400" ]] ||
    ! jq -e '.error == "invalid_grant"' "$body" >/dev/null; then
    fail "$label was not rejected: HTTP $status $(<"$body")"
  fi
  jq -e --arg expected "$expected_description" '
    .error_description == $expected
  ' "$body" >/dev/null ||
    fail "$label rejection did not prove the expected reason: $(<"$body")"
  pass "$label rejected"
}

invitation_email() {
  printf 'issue29-%s-%s@example.com\n' "$RUN_ID" "$1"
}

issue_invitation() {
  local base="$1" forwarded_host="$2" label="$3"
  local email request response status url
  email="$(invitation_email "$label")"
  request="$STATE_DIR/$label-invitation-request.json"
  response="$STATE_DIR/$label-invitation-response.json"
  jq -n --arg email "$email" \
    '{email:$email,issue_invitation:true}' >"$request"
  if [[ -n "$forwarded_host" ]]; then
    status="$(curl -sS -o "$response" -w '%{http_code}' --proto '=https' \
      --connect-timeout 5 --max-time 60 -X POST \
      -H "X-Forwarded-Host: $forwarded_host" \
      -H "@$SECRETS_DIR/origin-auth.headers" \
      -H "@$SECRETS_DIR/admin.headers" \
      -H 'content-type: application/json' --data-binary "@$request" \
      "$base/admin/users")"
  else
    status="$(curl -sS -o "$response" -w '%{http_code}' --proto '=https' \
      --connect-timeout 5 --max-time 60 -X POST \
      -H "@$SECRETS_DIR/admin.headers" \
      -H 'content-type: application/json' --data-binary "@$request" \
      "$base/admin/users")"
  fi
  [[ "$status" == "201" ]] ||
    fail "$label invitation issuance failed: HTTP $status $(<"$response")"
  url="$(jq -er '.invitation.invitation_url' "$response")"
  [[ "$url" == "$ISSUER/invite#token="* ]] ||
    fail "$label invitation URL is not bound to the public issuer"
  printf '%s' "${url#*#token=}" >"$SECRETS_DIR/$label.invitation"
}

accept_invitation() {
  local base="$1" forwarded_host="$2" label="$3"
  local request="$STATE_DIR/$label-invitation-accept.json"
  local response="$STATE_DIR/$label-invitation-accept-response.json" status
  jq -n --rawfile token "$SECRETS_DIR/$label.invitation" \
    '{token:($token | rtrimstr("\n"))}' >"$request"
  if [[ -n "$forwarded_host" ]]; then
    status="$(curl -sS -o "$response" -w '%{http_code}' --proto '=https' \
      --connect-timeout 5 --max-time 60 -c "$SECRETS_DIR/$label.cookies" \
      -X POST -H "X-Forwarded-Host: $forwarded_host" \
      -H "@$SECRETS_DIR/origin-auth.headers" \
      -H 'content-type: application/json' --data-binary "@$request" \
      "$base/login/invitation")"
  else
    status="$(curl -sS -o "$response" -w '%{http_code}' --proto '=https' \
      --connect-timeout 5 --max-time 60 -c "$SECRETS_DIR/$label.cookies" \
      -X POST -H 'content-type: application/json' \
      --data-binary "@$request" "$base/login/invitation")"
  fi
  if [[ "$status" != "200" ]] ||
    ! jq -e '.authenticated == true and .redirect_to == "/account"' \
      "$response" >/dev/null; then
    fail "$label invitation acceptance failed: HTTP $status $(<"$response")"
  fi
}

assert_invitation_rejected() {
  local base="$1" forwarded_host="$2" prefix="$3" label="$4"
  local request="$STATE_DIR/$label-invitation-replay.json"
  local response="$STATE_DIR/$label-invitation-replay-response.json" status
  jq -n --rawfile token "$SECRETS_DIR/$prefix.invitation" \
    '{token:($token | rtrimstr("\n"))}' >"$request"
  if [[ -n "$forwarded_host" ]]; then
    status="$(curl -sS -o "$response" -w '%{http_code}' --proto '=https' \
      --connect-timeout 5 --max-time 60 -X POST \
      -H "X-Forwarded-Host: $forwarded_host" \
      -H "@$SECRETS_DIR/origin-auth.headers" \
      -H 'content-type: application/json' --data-binary "@$request" \
      "$base/login/invitation")"
  else
    status="$(curl -sS -o "$response" -w '%{http_code}' --proto '=https' \
      --connect-timeout 5 --max-time 60 -X POST \
      -H 'content-type: application/json' --data-binary "@$request" \
      "$base/login/invitation")"
  fi
  if [[ "$status" != "400" ]] ||
    ! jq -e '.message == "invalid invitation"' "$response" >/dev/null; then
    fail "$label invitation was not rejected: HTTP $status $(<"$response")"
  fi
  pass "$label invitation rejected"
}

assert_old_jti_rejected() {
  local base="$1" forwarded_host="$2" token_file="$3" label="$4"
  local require_region_owner="$5"
  local id_token_file="$SECRETS_DIR/$label.id-token-hint"
  local body="$STATE_DIR/jti-$label.json" status
  jq -erj '.id_token' "$token_file" >"$id_token_file"
  if [[ -n "$forwarded_host" ]]; then
    status="$(curl -sS -o "$body" -w '%{http_code}' --proto '=https' \
      --connect-timeout 5 --max-time 60 -X POST \
      -H "X-Forwarded-Host: $forwarded_host" \
      -H "@$SECRETS_DIR/origin-auth.headers" \
      -H 'content-type: application/x-www-form-urlencoded' \
      --data-urlencode "client_id=$(context_value '.probe.client_id')" \
      --data-urlencode 'scope=openid' \
      --data-urlencode "id_token_hint@$id_token_file" "$base/bc-authorize")"
  else
    status="$(curl -sS -o "$body" -w '%{http_code}' --proto '=https' \
      --connect-timeout 5 --max-time 60 -X POST \
      -H 'content-type: application/x-www-form-urlencoded' \
      --data-urlencode "client_id=$(context_value '.probe.client_id')" \
      --data-urlencode 'scope=openid' \
      --data-urlencode "id_token_hint@$id_token_file" "$base/bc-authorize")"
  fi
  if [[ "$status" != "400" ]] ||
    ! jq -e '.error == "invalid_request"' "$body" >/dev/null; then
    fail "$label JTI was not rejected: HTTP $status $(<"$body")"
  fi
  if [[ "$require_region_owner" == "1" ]] &&
    ! jq -e '
      .error_description == "id_token_hint 属于其他区域"
    ' "$body" >/dev/null; then
    fail "$label JTI rejection did not prove Region ownership: $(<"$body")"
  fi
  pass "$label JTI rejected"
}

password_login_status() {
  local base="$1" forwarded_host="$2" jar="$3"
  local body="$STATE_DIR/login.json" request="$STATE_DIR/login-request.json" status
  jq -n --arg email "$(context_value '.probe.email')" \
    --arg password "$(<"$SECRETS_DIR/password")" \
    '{email:$email,password:$password,authorize_query:""}' >"$request"
  if [[ -n "$forwarded_host" ]]; then
    status="$(curl -sS -o "$body" -w '%{http_code}' -c "$jar" \
      --proto '=https' --connect-timeout 5 --max-time 60 -X POST \
      -H "X-Forwarded-Host: $forwarded_host" \
      -H "@$SECRETS_DIR/origin-auth.headers" \
      -H 'content-type: application/json' --data-binary "@$request" \
      "$base/login/password")"
  else
    status="$(curl -sS -o "$body" -w '%{http_code}' -c "$jar" \
      --proto '=https' --connect-timeout 5 --max-time 60 -X POST \
      -H 'content-type: application/json' --data-binary "@$request" \
      "$base/login/password")"
  fi
  printf '%s\n' "$status"
}

login_password() {
  local base="$1" forwarded_host="$2" jar="$3" status
  status="$(password_login_status "$base" "$forwarded_host" "$jar")"
  [[ "$status" == "200" ]] ||
    fail "password login failed: HTTP $status $(<"$STATE_DIR/login.json")"
}

mint_code() {
  local base="$1" forwarded_host="$2" jar="$3" label="$4"
  local verifier challenge query context_body csrf decision redirect code
  verifier="0123456789012345678901234567890123456789abc"
  challenge="$(VERIFIER="$verifier" python3 -c \
    'import base64,hashlib,os; print(base64.urlsafe_b64encode(hashlib.sha256(os.environ["VERIFIER"].encode()).digest()).rstrip(b"=").decode())')"
  query="$(python3 - "$(context_value '.probe.client_id')" "$challenge" \
    "$(context_value '.probe.redirect_uri')" <<'PY'
import sys
import urllib.parse
print(urllib.parse.urlencode({
    "client_id": sys.argv[1],
    "redirect_uri": sys.argv[3],
    "scope": "openid",
    "state": "issue29",
    "code_challenge": sys.argv[2],
    "code_challenge_method": "S256",
    "nonce": "issue29",
}))
PY
  )"
  context_body="$STATE_DIR/$label-consent-context.json"
  if [[ -n "$forwarded_host" ]]; then
    curl -fsS --proto '=https' -b "$jar" \
      -H "X-Forwarded-Host: $forwarded_host" \
      -H "@$SECRETS_DIR/origin-auth.headers" \
      "$base/consent/context?$query" >"$context_body"
  else
    curl -fsS --proto '=https' -b "$jar" \
      "$base/consent/context?$query" >"$context_body"
  fi
  csrf="$(jq -er '.csrf_token' "$context_body")"
  decision="$STATE_DIR/$label-consent-decision.json"
  jq -n --arg csrf "$csrf" --arg query "$query" \
    '{decision:"approve",csrf:$csrf,authorize_query:$query}' >"$decision"
  if [[ -n "$forwarded_host" ]]; then
    redirect="$(curl -fsS --proto '=https' -b "$jar" -X POST \
      -H "X-Forwarded-Host: $forwarded_host" \
      -H "@$SECRETS_DIR/origin-auth.headers" \
      -H 'content-type: application/json' --data-binary "@$decision" \
      "$base/consent/decision" | jq -er '.redirect')"
  else
    redirect="$(curl -fsS --proto '=https' -b "$jar" -X POST \
      -H 'content-type: application/json' --data-binary "@$decision" \
      "$base/consent/decision" | jq -er '.redirect')"
  fi
  code="$(REDIRECT="$redirect" python3 -c \
    'import os,urllib.parse; print(urllib.parse.parse_qs(urllib.parse.urlparse(os.environ["REDIRECT"]).query).get("code",[""])[0])')"
  [[ -n "$code" ]] || fail "$label did not issue a code"
  printf '%s' "$code" >"$SECRETS_DIR/$label.code"
}

exchange_code() {
  local base="$1" forwarded_host="$2" label="$3"
  local status output="$SECRETS_DIR/$label.tokens.json"
  if [[ -n "$forwarded_host" ]]; then
    status="$(curl -sS -o "$output" -w '%{http_code}' --proto '=https' \
      --connect-timeout 5 --max-time 60 -X POST \
      -H "X-Forwarded-Host: $forwarded_host" \
      -H "@$SECRETS_DIR/origin-auth.headers" \
      -H 'content-type: application/x-www-form-urlencoded' \
      --data-urlencode 'grant_type=authorization_code' \
      --data-urlencode "code@$SECRETS_DIR/$label.code" \
      --data-urlencode 'code_verifier=0123456789012345678901234567890123456789abc' \
      --data-urlencode "redirect_uri=$(context_value '.probe.redirect_uri')" \
      --data-urlencode "client_id=$(context_value '.probe.client_id')" \
      "$base/token")"
  else
    status="$(curl -sS -o "$output" -w '%{http_code}' --proto '=https' \
      --connect-timeout 5 --max-time 60 -X POST \
      -H 'content-type: application/x-www-form-urlencoded' \
      --data-urlencode 'grant_type=authorization_code' \
      --data-urlencode "code@$SECRETS_DIR/$label.code" \
      --data-urlencode 'code_verifier=0123456789012345678901234567890123456789abc' \
      --data-urlencode "redirect_uri=$(context_value '.probe.redirect_uri')" \
      --data-urlencode "client_id=$(context_value '.probe.client_id')" \
      "$base/token")"
  fi
  if [[ "$status" != "200" ]] ||
    ! jq -e '.access_token and .refresh_token and .id_token' "$output" >/dev/null; then
    fail "$label exchange failed: HTTP $status $(<"$output")"
  fi
  jq -erj '.refresh_token' "$output" >"$SECRETS_DIR/$label.refresh"
}

wait_client_replica() {
  local table client physical started deadline output
  table="$(context_value '.authority_tables.clients')"
  client="$(context_value '.probe.client_id')"
  physical="$(printf '%s\037%s' "$TENANT" "$client")"
  started="$(context_value '.probe.client_created_at')"
  deadline=$(( $(now_epoch) + RPO_TARGET_SECS ))
  output="$STATE_DIR/client-replica.json"
  while (( $(now_epoch) <= deadline )); do
    "${STANDBY_AWS[@]}" dynamodb get-item --table-name "$table" \
      --consistent-read \
      --key "$(jq -cn --arg client "$physical" '{client_id:{S:$client}}')" \
      --output json >"$output"
    if jq -e '.Item.client_id.S' "$output" >/dev/null; then
      local lag=$(( $(now_epoch) - started ))
      printf '%s\n' "$lag" >"$STATE_DIR/authority-rpo-secs"
      (( lag <= RPO_TARGET_SECS )) ||
        fail "authority replication lag ${lag}s exceeds RPO ${RPO_TARGET_SECS}s"
      pass "client authority replicated in ${lag}s"
      return
    fi
    sleep 1
  done
  fail "client authority did not replicate within ${RPO_TARGET_SECS}s"
}

initialize_context() {
  [[ -n "$ISSUER" ]] || fail "SAAS_ZONE or ISSUER is required"
  [[ "$ISSUER" == https://* ]] || fail "ISSUER must be HTTPS"
  local primary="$STATE_DIR/primary-stack.json"
  local standby="$STATE_DIR/standby-stack.json"
  "${PRIMARY_AWS[@]}" cloudformation describe-stacks \
    --stack-name "$PRIMARY_STACK" >"$primary"
  "${STANDBY_AWS[@]}" cloudformation describe-stacks \
    --stack-name "$STANDBY_STACK" >"$standby"
  local authority secrets control distribution primary_host standby_host
  local standby_region_local_tables
  local primary_commit standby_commit local_commit
  local primary_auth_artifact standby_auth_artifact
  authority="$(stack_output "$primary" ReplicatedAuthorityTableNames)"
  secrets="$(stack_output "$primary" ReplicatedRuntimeSecretArns)"
  control="$(stack_output "$primary" RegionControlTableName)"
  distribution="$(stack_output "$primary" FailoverDistributionId)"
  primary_host="$(stack_output "$primary" PrimaryApiHost)"
  standby_host="$(stack_output "$standby" ApiHost)"
  standby_region_local_tables="$(stack_output "$standby" RegionLocalTableNames)"
  primary_commit="$(stack_output "$primary" DeploymentCommit)"
  standby_commit="$(stack_output "$standby" DeploymentCommit)"
  local_commit="$(git -C "$REPO_ROOT" rev-parse HEAD)"
  [[ "$primary_commit" == "$standby_commit" && "$primary_commit" == "$local_commit" ]] ||
    fail "primary, standby, and local HEAD must use the same deployment commit"
  if [[ -n "$(git -C "$REPO_ROOT" status --porcelain \
    --untracked-files=normal --ignore-submodules=dirty)" ]]; then
    fail "qualifying failover requires a clean worktree"
  fi
  primary_auth_artifact="$(validate_deployed_auth_artifact \
    "$PRIMARY_REGION" "$(jq -er '.Stacks[0].StackId' "$primary")" \
    "$local_commit" primary)"
  standby_auth_artifact="$(validate_deployed_auth_artifact \
    "$STANDBY_REGION" "$(jq -er '.Stacks[0].StackId' "$standby")" \
    "$local_commit" standby)"
  jq -e '
    type == "object" and
    (keys | sort) == ([
      "admin_auth","attribute_namespaces","clients","domain_map",
      "federation_attribute_mappings","federation_config","governance",
      "governance_suppression","grants","passkeys","password_credentials",
      "scim_groups","security_events","tenant_keys","users","workload_trust"
    ] | sort)
  ' <<<"$authority" >/dev/null || fail "primary authority output is malformed"
  jq -e --arg tenant "$TENANT" '
    .server and .platform_admin and .tenant_admin[$tenant] and .scim[$tenant]
  ' <<<"$secrets" >/dev/null || fail "primary runtime Secret output is malformed"
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

  "${PRIMARY_AWS[@]}" cloudfront get-distribution-config --id "$distribution" \
    >"$STATE_DIR/distribution-original.json"
  local origin_id issuer_host
  issuer_host="$(validated_issuer_host "$STATE_DIR/distribution-original.json" \
    "$ISSUER" "$TENANT")"
  origin_id="$(jq -er --arg host "$primary_host" '
    [.DistributionConfig.Origins.Items[] | select(.DomainName == $host)]
    | select(length == 1) | .[0].Id
  ' "$STATE_DIR/distribution-original.json")"
  local control_item source_item revision
  control_item="$STATE_DIR/initial-control.json"
  source_item="$STATE_DIR/initial-source.json"
  aws --profile "$PROFILE" --region "$PRIMARY_REGION" dynamodb get-item \
    --table-name "$control" --consistent-read \
    --key '{"region_id":{"S":"control"}}' >"$control_item"
  aws --profile "$PROFILE" --region "$PRIMARY_REGION" dynamodb get-item \
    --table-name "$control" --consistent-read \
    --key "$(jq -cn --arg region "$PRIMARY_REGION" \
      '{region_id:{S:$region}}')" >"$source_item"
  jq -e --arg region "$PRIMARY_REGION" '
    .Item.state.S == "active" and .Item.active_region.S == $region
  ' "$control_item" >/dev/null || fail "primary is not the coordinated active Region"
  jq -e '.Item.active.BOOL == true' "$source_item" >/dev/null ||
    fail "primary Region row is not active"
  revision="$(jq -er '.Item.revision.N | tonumber' "$control_item")"
  [[ "$(jq -er '.Item.revision.N | tonumber' "$source_item")" == "$revision" ]] ||
    fail "initial coordinator/primary revisions differ"

  local primary_stack_name origin_auth_secret_name origin_auth_secondary_secret_name
  primary_stack_name="$(jq -er '.Stacks[0].StackName' "$primary")"
  origin_auth_secret_name="$primary_stack_name/cloudfront-origin-auth"
  origin_auth_secondary_secret_name="$primary_stack_name/cloudfront-origin-auth-secondary"
  jq -n \
    --arg run_id "$RUN_ID" --arg account "$(aws --profile "$PROFILE" sts \
      get-caller-identity --query Account --output text)" \
    --arg primary_stack_id "$(jq -er '.Stacks[0].StackId' "$primary")" \
    --arg standby_stack_id "$(jq -er '.Stacks[0].StackId' "$standby")" \
    --arg deployment_commit "$local_commit" \
    --arg primary_region "$PRIMARY_REGION" --arg standby_region "$STANDBY_REGION" \
    --arg issuer "$ISSUER" --arg issuer_host "$issuer_host" --arg tenant "$TENANT" \
    --arg region_control_table "$control" \
    --arg distribution_id "$distribution" --arg origin_id "$origin_id" \
    --arg primary_api_host "$primary_host" --arg standby_api_host "$standby_host" \
    --arg primary_api_url "$(stack_output "$primary" ApiUrl)" \
    --arg standby_api_url "$(stack_output "$standby" ApiUrl)" \
    --arg origin_auth_secret_name "$origin_auth_secret_name" \
    --arg origin_auth_secondary_secret_name "$origin_auth_secondary_secret_name" \
    --argjson authority_tables "$authority" \
    --argjson standby_region_local_tables "$standby_region_local_tables" \
    --argjson runtime_secret_arns "$secrets" \
    --argjson primary_auth_artifact "$primary_auth_artifact" \
    --argjson standby_auth_artifact "$standby_auth_artifact" \
    --argjson initial_revision "$revision" \
    '{
      run_id:$run_id,account_id:$account,
      primary_stack_id:$primary_stack_id,standby_stack_id:$standby_stack_id,
      deployment_commit:$deployment_commit,
      primary_region:$primary_region,standby_region:$standby_region,
      issuer:$issuer,issuer_host:$issuer_host,tenant:$tenant,
      region_control_table:$region_control_table,
      distribution_id:$distribution_id,origin_id:$origin_id,
      primary_api_host:$primary_api_host,standby_api_host:$standby_api_host,
      primary_api_url:$primary_api_url,standby_api_url:$standby_api_url,
      origin_auth_secret_name:$origin_auth_secret_name,
      origin_auth_secondary_secret_name:$origin_auth_secondary_secret_name,
      auth_artifacts:{
        primary:$primary_auth_artifact,
        standby:$standby_auth_artifact
      },
      authority_tables:$authority_tables,
      standby_region_local_tables:$standby_region_local_tables,
      runtime_secret_arns:$runtime_secret_arns,
      revisions:{
        initial:$initial_revision,
        failover_quiesce:($initial_revision+1),
        failover_active:($initial_revision+2),
        failback_quiesce:($initial_revision+3),
        failback_active:($initial_revision+4)
      }
    }' >"$CONTEXT"
  chmod 600 "$CONTEXT"
  assert_coordinated_writer "$PRIMARY_REGION"
  pass "captured immutable deployment context for RUN_ID=$RUN_ID"
}

validate_deployment_context() {
  local primary="$STATE_DIR/primary-stack-current.json"
  local standby="$STATE_DIR/standby-stack-current.json"
  local local_commit primary_commit standby_commit distribution_config issuer_host
  local primary_auth_artifact standby_auth_artifact
  "${PRIMARY_AWS[@]}" cloudformation describe-stacks \
    --stack-name "$(context_value '.primary_stack_id')" >"$primary"
  "${STANDBY_AWS[@]}" cloudformation describe-stacks \
    --stack-name "$(context_value '.standby_stack_id')" >"$standby"

  [[ "$(jq -er '.Stacks[0].StackId' "$primary")" == \
    "$(context_value '.primary_stack_id')" ]] ||
    fail "primary stack identity changed since RUN_ID initialization"
  [[ "$(jq -er '.Stacks[0].StackId' "$standby")" == \
    "$(context_value '.standby_stack_id')" ]] ||
    fail "standby stack identity changed since RUN_ID initialization"

  local_commit="$(git -C "$REPO_ROOT" rev-parse HEAD)"
  primary_commit="$(stack_output "$primary" DeploymentCommit)"
  standby_commit="$(stack_output "$standby" DeploymentCommit)"
  [[ "$primary_commit" == "$standby_commit" &&
    "$primary_commit" == "$(context_value '.deployment_commit')" &&
    "$primary_commit" == "$local_commit" ]] ||
    fail "persisted context, both stacks, and local HEAD must use the same deployment commit"
  if [[ -n "$(git -C "$REPO_ROOT" status --porcelain \
    --untracked-files=normal --ignore-submodules=dirty)" ]]; then
    fail "qualifying failover requires a clean worktree"
  fi
  primary_auth_artifact="$(validate_deployed_auth_artifact \
    "$PRIMARY_REGION" "$(context_value '.primary_stack_id')" \
    "$local_commit" primary-current)"
  standby_auth_artifact="$(validate_deployed_auth_artifact \
    "$STANDBY_REGION" "$(context_value '.standby_stack_id')" \
    "$local_commit" standby-current)"
  jq -e --argjson primary "$primary_auth_artifact" \
    --argjson standby "$standby_auth_artifact" '
      .auth_artifacts.primary == $primary
      and .auth_artifacts.standby == $standby
    ' "$CONTEXT" >/dev/null ||
    fail "deployed Auth artifacts changed since RUN_ID initialization"

  [[ "$(stack_output "$primary" RegionId)" == \
    "$(context_value '.primary_region')" &&
    "$(stack_output "$standby" RegionId)" == \
    "$(context_value '.standby_region')" ]] ||
    fail "stack Region outputs changed since RUN_ID initialization"
  [[ "$(stack_output "$primary" RegionControlTableName)" == \
    "$(context_value '.region_control_table')" &&
    "$(stack_output "$standby" RegionControlTableName)" == \
    "$(context_value '.region_control_table')" ]] ||
    fail "Region control table output changed since RUN_ID initialization"
  [[ "$(stack_output "$primary" FailoverDistributionId)" == \
    "$(context_value '.distribution_id')" ]] ||
    fail "CloudFront distribution output changed since RUN_ID initialization"
  distribution_config="$STATE_DIR/distribution-context-current.json"
  "${PRIMARY_AWS[@]}" cloudfront get-distribution-config \
    --id "$(context_value '.distribution_id')" >"$distribution_config"
  issuer_host="$(validated_issuer_host "$distribution_config" \
    "$(context_value '.issuer')" "$(context_value '.tenant')")"
  [[ "$issuer_host" == "$(context_value '.issuer_host')" ]] ||
    fail "issuer host changed since RUN_ID initialization"
  [[ "$(stack_output "$primary" PrimaryApiHost)" == \
    "$(context_value '.primary_api_host')" &&
    "$(stack_output "$standby" ApiHost)" == \
    "$(context_value '.standby_api_host')" &&
    "$(stack_output "$primary" ApiUrl)" == \
    "$(context_value '.primary_api_url')" &&
    "$(stack_output "$standby" ApiUrl)" == \
    "$(context_value '.standby_api_url')" ]] ||
    fail "API endpoint outputs changed since RUN_ID initialization"
  jq -e --argjson current "$(stack_output "$primary" \
    ReplicatedAuthorityTableNames)" '.authority_tables == $current' \
    "$CONTEXT" >/dev/null ||
    fail "authority table outputs changed since RUN_ID initialization"
  jq -e --argjson current "$(stack_output "$primary" \
    ReplicatedRuntimeSecretArns)" '.runtime_secret_arns == $current' \
    "$CONTEXT" >/dev/null ||
    fail "runtime Secret outputs changed since RUN_ID initialization"
  jq -e --argjson current "$(stack_output "$standby" \
    RegionLocalTableNames)" '.standby_region_local_tables == $current' \
    "$CONTEXT" >/dev/null ||
    fail "standby Region-local table outputs changed since RUN_ID initialization"
  [[ "$(context_value '.origin_auth_secret_name')" == \
    "$(jq -er '.Stacks[0].StackName' "$primary")/cloudfront-origin-auth" ]] ||
    fail "origin-auth Secret identity changed since RUN_ID initialization"
  [[ "$(context_value '.origin_auth_secondary_secret_name')" == \
    "$(jq -er '.Stacks[0].StackName' "$primary")/cloudfront-origin-auth-secondary" ]] ||
    fail "secondary origin-auth Secret identity changed since RUN_ID initialization"
  pass "deployment identity revalidated for RUN_ID=$RUN_ID"
}

ensure_origin_auth_header() {
  local primary_file="$WORK/origin-auth-primary.secret"
  local secondary_file="$WORK/origin-auth-secondary.secret"
  "${PRIMARY_AWS[@]}" secretsmanager get-secret-value \
    --secret-id "$(context_value '.origin_auth_secret_name')" \
    --query SecretString --output text >"$primary_file"
  "${PRIMARY_AWS[@]}" secretsmanager get-secret-value \
    --secret-id "$(context_value '.origin_auth_secondary_secret_name')" \
    --query SecretString --output text >"$secondary_file"
  python3 - "$primary_file" "$secondary_file" \
    "$SECRETS_DIR/origin-auth.headers" <<'PY'
import pathlib
import sys

primary = pathlib.Path(sys.argv[1]).read_text().rstrip("\n")
secondary = pathlib.Path(sys.argv[2]).read_text().rstrip("\n")
if len(primary) < 32 or len(secondary) < 32 or primary == secondary:
    raise SystemExit("managed origin credentials are invalid")
pathlib.Path(sys.argv[3]).write_text(
    f"X-Agent-Auth-Origin-Auth-Primary: {primary}\n"
    f"X-Agent-Auth-Origin-Auth-Secondary: {secondary}\n"
)
PY
  chmod 600 "$SECRETS_DIR/origin-auth.headers"
  rm -f "$primary_file" "$secondary_file"
}

ensure_admin_header() {
  [[ -s "$SECRETS_DIR/admin.headers" ]] && return
  local admin_arn admin
  admin_arn="$(jq -er --arg tenant "$TENANT" \
    '.runtime_secret_arns.tenant_admin[$tenant]' "$CONTEXT")"
  admin="$("${PRIMARY_AWS[@]}" secretsmanager get-secret-value \
    --secret-id "$admin_arn" --query SecretString --output text |
    jq -er '.current.secret')"
  printf 'authorization: Bearer %s\n' "$admin" >"$SECRETS_DIR/admin.headers"
}

setup_probe() {
  local email initial active request response status user_id
  local client_id created redirect_uri matches
  ensure_admin_header
  if ! jq -e '.probe.email and .probe.redirect_uri' "$CONTEXT" >/dev/null 2>&1; then
    email="issue29-${RUN_ID}@example.com"
    user_id="user:$email"
    redirect_uri="http://127.0.0.1/callback/$RUN_ID"
    initial="Init-$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
    active="Active-$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
    printf '%s\n' "$initial" >"$SECRETS_DIR/initial-password"
    printf '%s\n' "$active" >"$SECRETS_DIR/password"
    jq --arg email "$email" --arg user_id "$user_id" \
      --arg redirect_uri "$redirect_uri" \
      '.probe={
        email:$email,user_id:$user_id,redirect_uri:$redirect_uri,
        client_id:null,client_created_at:null
      }' "$CONTEXT" >"$CONTEXT.next"
    mv "$CONTEXT.next" "$CONTEXT"
    chmod 600 "$CONTEXT"
  fi
  [[ -s "$SECRETS_DIR/initial-password" && -s "$SECRETS_DIR/password" ]] ||
    fail "persisted probe password material is missing"
  email="$(context_value '.probe.email')"
  user_id="$(context_value '.probe.user_id')"
  redirect_uri="$(context_value '.probe.redirect_uri')"

  status="$(password_login_status "$ISSUER" "" "$SECRETS_DIR/source.cookies")"
  if [[ "$status" == "401" ]]; then
    request="$STATE_DIR/create-user.json"
    response="$STATE_DIR/create-user-response.json"
    jq -n --arg email "$email" --arg password "$(<"$SECRETS_DIR/initial-password")" \
      '{email:$email,initial_password:$password}' >"$request"
    status="$(curl -sS -o "$response" -w '%{http_code}' --proto '=https' \
      --connect-timeout 5 --max-time 60 -X POST \
      -H "@$SECRETS_DIR/admin.headers" -H 'content-type: application/json' \
      --data-binary "@$request" "$ISSUER/admin/users")"
    [[ "$status" == "201" ]] ||
      fail "probe user creation failed: HTTP $status $(<"$response")"
    [[ "$(jq -er '.user_id' "$response")" == "$user_id" ]] ||
      fail "probe user creation returned an unexpected user_id"

    request="$STATE_DIR/activate-password.json"
    jq -n --arg email "$email" \
      --arg current "$(<"$SECRETS_DIR/initial-password")" \
      --arg new "$(<"$SECRETS_DIR/password")" \
      '{email:$email,current_password:$current,new_password:$new}' >"$request"
    status="$(curl -sS -o "$STATE_DIR/activate-password-response.json" \
      -w '%{http_code}' -c "$SECRETS_DIR/source.cookies" --proto '=https' \
      --connect-timeout 5 --max-time 60 -X POST \
      -H 'content-type: application/json' --data-binary "@$request" \
      "$ISSUER/login/password/change")"
    [[ "$status" == "200" ]] || fail "probe password activation failed"
    login_password "$ISSUER" "" "$SECRETS_DIR/source.cookies"
  elif [[ "$status" != "200" ]]; then
    fail "probe login recovery failed: HTTP $status $(<"$STATE_DIR/login.json")"
  fi

  client_id="$(jq -r '.probe.client_id // empty' "$CONTEXT")"
  if [[ -z "$client_id" ]]; then
    response="$STATE_DIR/list-clients-response.json"
    status="$(curl -sS -o "$response" -w '%{http_code}' --proto '=https' \
      --connect-timeout 5 --max-time 60 \
      -H "@$SECRETS_DIR/admin.headers" "$ISSUER/admin/clients")"
    [[ "$status" == "200" ]] ||
      fail "probe client recovery failed: HTTP $status $(<"$response")"
    matches="$(jq -c --arg redirect "$redirect_uri" '
      [.clients[] | select(.redirect_uris == [$redirect])]
    ' "$response")"
    [[ "$(jq 'length' <<<"$matches")" -le 1 ]] ||
      fail "multiple probe clients use redirect URI $redirect_uri"
    client_id="$(jq -r '.[0].client_id // empty' <<<"$matches")"
  fi
  if [[ -z "$client_id" ]]; then
    request="$STATE_DIR/create-client.json"
    response="$STATE_DIR/create-client-response.json"
    jq -n --arg redirect "$redirect_uri" \
      '{redirect_uris:[$redirect],token_endpoint_auth_method:"none"}' >"$request"
    created="$(jq -r '.probe.client_created_at // empty' "$CONTEXT")"
    if [[ -z "$created" ]]; then
      created="$(now_epoch)"
      jq --argjson created "$created" \
        '.probe.client_created_at=$created' "$CONTEXT" >"$CONTEXT.next"
      mv "$CONTEXT.next" "$CONTEXT"
      chmod 600 "$CONTEXT"
    fi
    status="$(curl -sS -o "$response" -w '%{http_code}' --proto '=https' \
      --connect-timeout 5 --max-time 60 -X POST \
      -H "@$SECRETS_DIR/admin.headers" -H 'content-type: application/json' \
      --data-binary "@$request" "$ISSUER/admin/clients" || true)"
    client_id="$(jq -r '.client_id // empty' "$response" 2>/dev/null || true)"
    if [[ "$status" != "201" || -z "$client_id" ]]; then
      response="$STATE_DIR/list-clients-after-create.json"
      status="$(curl -sS -o "$response" -w '%{http_code}' --proto '=https' \
        --connect-timeout 5 --max-time 60 \
        -H "@$SECRETS_DIR/admin.headers" "$ISSUER/admin/clients")"
      [[ "$status" == "200" ]] ||
        fail "ambiguous client creation could not be recovered"
      matches="$(jq -c --arg redirect "$redirect_uri" '
        [.clients[] | select(.redirect_uris == [$redirect])]
      ' "$response")"
      [[ "$(jq 'length' <<<"$matches")" == "1" ]] ||
        fail "ambiguous client creation did not resolve to exactly one client"
      client_id="$(jq -er '.[0].client_id' <<<"$matches")"
    fi
  fi
  created="$(context_value '.probe.client_created_at')"
  jq --arg client_id "$client_id" \
    '.probe.client_id=$client_id' "$CONTEXT" >"$CONTEXT.next"
  mv "$CONTEXT.next" "$CONTEXT"
  chmod 600 "$CONTEXT"
  [[ -s "$STATE_DIR/authority-rpo-secs" ]] || wait_client_replica
  pass "created isolated failover probe identity and client"
}

capture_source_artifacts() {
  [[ -f "$STATE_DIR/source-artifacts.ready" ]] && return
  issue_invitation "$ISSUER" "" source-old
  issue_invitation "$ISSUER" "" source-pair
  accept_invitation "$ISSUER" "" source-pair
  assert_invitation_rejected "$ISSUER" "" source-pair \
    source-consumed-before-failover
  mint_code "$ISSUER" "" "$SECRETS_DIR/source.cookies" source-old
  mint_code "$ISSUER" "" "$SECRETS_DIR/source.cookies" source-pair
  exchange_code "$ISSUER" "" source-pair
  assert_oauth_rejected "$ISSUER" "" source-consumed-before-failover \
    "code 无效或已使用" \
    -X POST -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=authorization_code' \
    --data-urlencode "code@$SECRETS_DIR/source-pair.code" \
    --data-urlencode 'code_verifier=0123456789012345678901234567890123456789abc' \
    --data-urlencode "redirect_uri=$(context_value '.probe.redirect_uri')" \
    --data-urlencode "client_id=$(context_value '.probe.client_id')"
  jwks_hash "$ISSUER" "" "$STATE_DIR/jwks-before.json" \
    >"$STATE_DIR/jwks-before.sha256"
  verify_token_pair "$SECRETS_DIR/source-pair.tokens.json" \
    "$STATE_DIR/jwks-before.json" source
  touch "$STATE_DIR/source-artifacts.ready"
  pass "captured source replay artifacts, invitations, and verified JWT anchors"
}

validate_persisted_probe() {
  local expected_email="issue29-${RUN_ID}@example.com"
  local expected_redirect="http://127.0.0.1/callback/$RUN_ID"
  jq -e --arg run "$RUN_ID" --arg email "$expected_email" \
    --arg user_id "user:$expected_email" --arg redirect "$expected_redirect" '
    .run_id == $run and .probe.email == $email and
    .probe.user_id == $user_id and .probe.redirect_uri == $redirect and
    (.probe.client_id | type == "string" and length > 0) and
    (.probe.client_created_at | type == "number")
  ' "$CONTEXT" >/dev/null ||
    fail "persisted probe context is incomplete"
  local path
  for path in \
    "$SECRETS_DIR/admin.headers" \
    "$SECRETS_DIR/password" \
    "$SECRETS_DIR/source.cookies" \
    "$SECRETS_DIR/source-old.code" \
    "$SECRETS_DIR/source-pair.code" \
    "$SECRETS_DIR/source-pair.tokens.json" \
    "$SECRETS_DIR/source-pair.refresh" \
    "$SECRETS_DIR/source-old.invitation" \
    "$SECRETS_DIR/source-pair.invitation" \
    "$STATE_DIR/jwks-before.sha256" \
    "$STATE_DIR/authority-rpo-secs"; do
    [[ -s "$path" ]] || fail "persisted probe material is missing: $path"
  done
  [[ -f "$STATE_DIR/source-artifacts.ready" ]] ||
    fail "persisted source artifact marker is missing"
  local client_id prefix
  client_id="$(context_value '.probe.client_id')"
  prefix="r1_${PRIMARY_REGION}_$(context_value '.revisions.initial')_"
  [[ "$(<"$SECRETS_DIR/source-old.code")" == "$prefix"* ]] ||
    fail "persisted source code is not owned by the recorded activation"
  python3 - "$SECRETS_DIR/source-pair.tokens.json" "$client_id" "$prefix" <<'PY'
import base64
import json
import pathlib
import sys

def claims(token):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed JWT")
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))

tokens = json.loads(pathlib.Path(sys.argv[1]).read_text())
client_id = sys.argv[2]
prefix = sys.argv[3]
access = claims(tokens["access_token"])
id_token = claims(tokens["id_token"])
audience = id_token.get("aud")
if access.get("client_id") != client_id:
    raise ValueError("access token client mismatch")
if audience != client_id and audience != [client_id]:
    raise ValueError("ID token audience mismatch")
if not id_token.get("jti", "").startswith(prefix):
    raise ValueError("ID token activation mismatch")
family, _, version = tokens["refresh_token"].rpartition(".")
if not family.startswith(prefix) or not version.isdigit():
    raise ValueError("refresh token activation mismatch")
PY
  pass "persisted probe material is complete"
}

assert_artifact_set_rejected() {
  local base="$1" forwarded_host="$2" prefix="$3" label="$4"
  local require_region_owner="$5"
  assert_oauth_rejected "$base" "$forwarded_host" "$label-code" \
    "authorization code belongs to another Region" \
    -X POST -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=authorization_code' \
    --data-urlencode "code@$SECRETS_DIR/$prefix-old.code" \
    --data-urlencode 'code_verifier=0123456789012345678901234567890123456789abc' \
    --data-urlencode "redirect_uri=$(context_value '.probe.redirect_uri')" \
    --data-urlencode "client_id=$(context_value '.probe.client_id')"
  assert_oauth_rejected "$base" "$forwarded_host" "$label-consumed-code" \
    "authorization code belongs to another Region" \
    -X POST -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=authorization_code' \
    --data-urlencode "code@$SECRETS_DIR/$prefix-pair.code" \
    --data-urlencode 'code_verifier=0123456789012345678901234567890123456789abc' \
    --data-urlencode "redirect_uri=$(context_value '.probe.redirect_uri')" \
    --data-urlencode "client_id=$(context_value '.probe.client_id')"
  assert_oauth_rejected "$base" "$forwarded_host" "$label-refresh" \
    "refresh_token belongs to another Region" \
    -X POST -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=refresh_token' \
    --data-urlencode "refresh_token@$SECRETS_DIR/$prefix-pair.refresh" \
    --data-urlencode "client_id=$(context_value '.probe.client_id')"
  assert_old_jti_rejected "$base" "$forwarded_host" \
    "$SECRETS_DIR/$prefix-pair.tokens.json" "$label" "$require_region_owner"
  assert_invitation_rejected "$base" "$forwarded_host" "$prefix-old" \
    "$label-unconsumed"
  assert_invitation_rejected "$base" "$forwarded_host" "$prefix-pair" \
    "$label-consumed"
}

cleanup_probe() {
  [[ -f "$STATE_DIR/probe-cleanup.ready" ]] && return
  if ! jq -e '.probe.email and .probe.user_id and .probe.redirect_uri' \
      "$CONTEXT" >/dev/null 2>&1; then
    touch "$STATE_DIR/probe-cleanup.ready"
    pass "no probe resources were initialized"
    return
  fi
  local status user_path label user_id client_id redirect_uri response matches
  ensure_admin_header
  client_id="$(jq -r '.probe.client_id // empty' "$CONTEXT")"
  redirect_uri="$(context_value '.probe.redirect_uri')"
  if [[ -z "$client_id" ]]; then
    response="$STATE_DIR/list-clients-for-cleanup.json"
    status="$(curl -sS -o "$response" -w '%{http_code}' --proto '=https' \
      --connect-timeout 5 --max-time 60 \
      -H "@$SECRETS_DIR/admin.headers" "$ISSUER/admin/clients")"
    [[ "$status" == "200" ]] ||
      fail "probe client cleanup recovery failed: HTTP $status"
    matches="$(jq -c --arg redirect "$redirect_uri" '
      [.clients[] | select(.redirect_uris == [$redirect])]
    ' "$response")"
    [[ "$(jq 'length' <<<"$matches")" -le 1 ]] ||
      fail "multiple probe clients use redirect URI $redirect_uri"
    client_id="$(jq -r '.[0].client_id // empty' <<<"$matches")"
  fi
  if [[ -n "$client_id" ]]; then
    status="$(curl -sS -o "$STATE_DIR/delete-client-response.json" \
      -w '%{http_code}' --proto '=https' --connect-timeout 5 --max-time 60 \
      -X DELETE -H "@$SECRETS_DIR/admin.headers" \
      "$ISSUER/admin/clients/$client_id")"
    [[ "$status" == "200" || "$status" == "404" ]] ||
      fail "probe client cleanup failed: HTTP $status"
  fi
  for label in source-old source-pair target-old target-pair; do
    [[ -f "$STATE_DIR/$label-user-cleanup.ready" ]] && continue
    user_id="user:$(invitation_email "$label")"
    user_path="$(python3 - "$user_id" <<'PY'
import sys
import urllib.parse
print(urllib.parse.quote(sys.argv[1], safe=""))
PY
)"
    status="$(curl -sS -o "$STATE_DIR/delete-$label-user-response.json" \
      -w '%{http_code}' --proto '=https' --connect-timeout 5 --max-time 60 \
      -X DELETE -H "@$SECRETS_DIR/admin.headers" \
      "$ISSUER/admin/users/$user_path")"
    [[ "$status" == "200" || "$status" == "404" ]] ||
      fail "$label invitation-user cleanup failed: HTTP $status"
    touch "$STATE_DIR/$label-user-cleanup.ready"
  done
  user_path="$(python3 - "$(context_value '.probe.user_id')" <<'PY'
import sys
import urllib.parse
print(urllib.parse.quote(sys.argv[1], safe=""))
PY
)"
  status="$(curl -sS -o "$STATE_DIR/delete-user-response.json" \
    -w '%{http_code}' --proto '=https' --connect-timeout 5 --max-time 60 \
    -X DELETE -H "@$SECRETS_DIR/admin.headers" \
    "$ISSUER/admin/users/$user_path")"
  [[ "$status" == "200" || "$status" == "404" ]] ||
    fail "probe user cleanup failed: HTTP $status"
  touch "$STATE_DIR/probe-cleanup.ready"
  pass "probe client deleted and probe user tombstoned"
}

capture_target_artifacts_and_revoke() {
  [[ -f "$STATE_DIR/target-artifacts.ready" ]] && return
  local base host jar grant status started lag source_item
  base="$(context_value '.standby_api_url')"
  host="${ISSUER#https://}"
  jar="$SECRETS_DIR/target.cookies"
  issue_invitation "$base" "$host" target-old
  issue_invitation "$base" "$host" target-pair
  accept_invitation "$base" "$host" target-pair
  assert_invitation_rejected "$base" "$host" target-pair \
    target-consumed-before-failback
  login_password "$base" "$host" "$jar"
  mint_code "$base" "$host" "$jar" target-old
  mint_code "$base" "$host" "$jar" target-pair
  exchange_code "$base" "$host" target-pair
  assert_oauth_rejected "$base" "$host" target-consumed-before-failback \
    "code 无效或已使用" \
    -X POST -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=authorization_code' \
    --data-urlencode "code@$SECRETS_DIR/target-pair.code" \
    --data-urlencode 'code_verifier=0123456789012345678901234567890123456789abc' \
    --data-urlencode "redirect_uri=$(context_value '.probe.redirect_uri')" \
    --data-urlencode "client_id=$(context_value '.probe.client_id')"
  verify_token_pair "$SECRETS_DIR/target-pair.tokens.json" \
    "$STATE_DIR/jwks-standby.json" standby
  mint_code "$base" "$host" "$jar" revoke-pair
  exchange_code "$base" "$host" revoke-pair
  grant="$(python3 - "$SECRETS_DIR/revoke-pair.tokens.json" <<'PY'
import base64
import json
import pathlib
import sys
token = json.loads(pathlib.Path(sys.argv[1]).read_text())["access_token"]
payload = token.split(".")[1]
payload += "=" * (-len(payload) % 4)
claims = json.loads(base64.urlsafe_b64decode(payload))
print(claims["https://a-auth.com/c"]["auth_grant"])
PY
)"
  started="$(now_epoch)"
  status="$(curl -sS -o "$STATE_DIR/revoke-grant.json" -w '%{http_code}' \
    --proto '=https' --connect-timeout 5 --max-time 60 -b "$jar" -X DELETE \
    -H "X-Forwarded-Host: $host" \
    -H "@$SECRETS_DIR/origin-auth.headers" "$base/grants/$grant")"
  [[ "$status" == "204" ]] || fail "target Grant revoke failed: HTTP $status"
  local physical table deadline
  physical="$(printf '%s\037%s' "$TENANT" "$grant")"
  table="$(context_value '.authority_tables.grants')"
  deadline=$(( started + RPO_TARGET_SECS ))
  while (( $(now_epoch) <= deadline )); do
    "${PRIMARY_AWS[@]}" dynamodb get-item --table-name "$table" \
      --consistent-read \
      --key "$(jq -cn --arg grant "$physical" '{grant_id:{S:$grant}}')" \
      >"$STATE_DIR/revoked-grant-primary.json"
    source_item="$(jq -r '.Item.grant_json.S // "{}"' \
      "$STATE_DIR/revoked-grant-primary.json")"
    if jq -e '.status == "revoked"' <<<"$source_item" >/dev/null; then
      lag=$(( $(now_epoch) - started ))
      printf '%s\n' "$lag" >"$STATE_DIR/grant-rpo-secs"
      (( lag <= RPO_TARGET_SECS )) ||
        fail "Grant revoke replication exceeded RPO"
      pass "Grant revocation propagated target->primary in ${lag}s"
      assert_oauth_rejected "$base" "$host" "revoked-grant-refresh" \
        "源 Grant 已吊销或过期" \
        -X POST -H 'content-type: application/x-www-form-urlencoded' \
        --data-urlencode 'grant_type=refresh_token' \
        --data-urlencode "refresh_token@$SECRETS_DIR/revoke-pair.refresh" \
        --data-urlencode "client_id=$(context_value '.probe.client_id')"
      touch "$STATE_DIR/target-artifacts.ready"
      return
    fi
    sleep 1
  done
  fail "Grant revocation did not reach primary within ${RPO_TARGET_SECS}s"
}

write_evidence() {
  local failover_start failback_start completed rto_failover rto_failback rpo_a rpo_g
  failover_start="$(<"$STATE_DIR/quiesce-$(context_value \
    '.revisions.failover_quiesce').started")"
  failback_start="$(<"$STATE_DIR/quiesce-$(context_value \
    '.revisions.failback_quiesce').started")"
  completed="$(now_epoch)"
  rto_failover=$(( $(<"$STATE_DIR/failover-ready.epoch") - failover_start ))
  rto_failback=$(( $(<"$STATE_DIR/failback-ready.epoch") - failback_start ))
  rpo_a="$(<"$STATE_DIR/authority-rpo-secs")"
  rpo_g="$(<"$STATE_DIR/grant-rpo-secs")"
  jq -e '
    .table_count == 20 and .verified_empty == true and
    (.deleted_items | type == "number" and . >= 0)
  ' "$STATE_DIR/standby-region-local-purge.json" >/dev/null ||
    fail "standby Region-local purge evidence is missing or invalid"
  jq -n \
    --arg run_id "$RUN_ID" \
    --arg completed_at "$(date -u -d "@$completed" +%FT%TZ)" \
    --arg account_id "$(context_value '.account_id')" \
    --arg primary_region "$PRIMARY_REGION" --arg standby_region "$STANDBY_REGION" \
    --arg primary_stack_id_hash "$(hash_text "$(context_value '.primary_stack_id')")" \
    --arg standby_stack_id_hash "$(hash_text "$(context_value '.standby_stack_id')")" \
    --arg deployment_commit "$(context_value '.deployment_commit')" \
    --arg primary_auth_code_sha256 \
      "$(context_value '.auth_artifacts.primary.code_sha256')" \
    --arg primary_auth_bootstrap_sha256 \
      "$(context_value '.auth_artifacts.primary.bootstrap_sha256')" \
    --arg standby_auth_code_sha256 \
      "$(context_value '.auth_artifacts.standby.code_sha256')" \
    --arg standby_auth_bootstrap_sha256 \
      "$(context_value '.auth_artifacts.standby.bootstrap_sha256')" \
    --arg source_code_hash "$(hash_text "$(<"$SECRETS_DIR/source-old.code")")" \
    --arg target_code_hash "$(hash_text "$(<"$SECRETS_DIR/target-old.code")")" \
    --arg source_invitation_hash \
      "$(hash_text "$(<"$SECRETS_DIR/source-old.invitation")")" \
    --arg target_invitation_hash \
      "$(hash_text "$(<"$SECRETS_DIR/target-old.invitation")")" \
    --arg jwks_hash "$(<"$STATE_DIR/jwks-before.sha256")" \
    --argjson rto_failover "$rto_failover" --argjson rto_failback "$rto_failback" \
    --argjson rpo_authority "$rpo_a" --argjson rpo_grant "$rpo_g" \
    --argjson rto_target "$RTO_TARGET_SECS" --argjson rpo_target "$RPO_TARGET_SECS" \
    --argjson revisions "$(jq '.revisions' "$CONTEXT")" '
    {
      schema_version:"1.0",run_id:$run_id,completed_at:$completed_at,
      account_id:$account_id,primary_region:$primary_region,
      standby_region:$standby_region,
      deployment:{
        primary_stack_id_sha256:$primary_stack_id_hash,
        standby_stack_id_sha256:$standby_stack_id_hash,
        git_commit:$deployment_commit,
        primary_auth_code_sha256:$primary_auth_code_sha256,
        primary_auth_bootstrap_sha256:$primary_auth_bootstrap_sha256,
        standby_auth_code_sha256:$standby_auth_code_sha256,
        standby_auth_bootstrap_sha256:$standby_auth_bootstrap_sha256
      },
      revisions:$revisions,
      objectives:{
        rto_target_secs:$rto_target,rpo_target_secs:$rpo_target,
        failover_rto_secs:$rto_failover,failback_rto_secs:$rto_failback,
        authority_rpo_secs:$rpo_authority,grant_revoke_rpo_secs:$rpo_grant
      },
      assertions:{
        single_writer:true,source_artifacts_rejected_after_failover:true,
        source_artifacts_still_rejected_after_failback:true,
        target_artifacts_rejected_after_failback:true,
        jwks_stable:true,grant_revocation_replicated:true,
        grant_revocation_blocks_refresh:true,
        standby_region_local_tables_purged:true,
        consumed_codes_rejected:true,invitations_rejected:true,
        issuer_tokens_verified:true,
        cloudfront_restored_to_primary:true,probe_cleanup_complete:true
      },
      sanitized_anchors:{
        source_code_sha256:$source_code_hash,target_code_sha256:$target_code_hash,
        source_invitation_sha256:$source_invitation_hash,
        target_invitation_sha256:$target_invitation_hash,
        jwks_sha256:$jwks_hash,artifact_classes_tested:4,
        signature_stages_verified:3
      },
      qualified:
        ($rto_failover <= $rto_target and $rto_failback <= $rto_target and
         $rpo_authority <= $rpo_target and $rpo_grant <= $rpo_target)
    }' >"$EVIDENCE"
  chmod 600 "$EVIDENCE"
  jq -e '.qualified == true' "$EVIDENCE" >/dev/null ||
    fail "drill completed but exceeded RTO/RPO targets; see $EVIDENCE"
  pass "sanitized evidence written to $EVIDENCE"
}

show_status() {
  local primary active state revision origin purge
  primary="$(context_value '.primary_region')"
  active="$(coordinator_field "$primary" active_region)"
  state="$(coordinator_field "$primary" state)"
  revision="$(control_revision "$primary")"
  origin="$(distribution_origin_host)"
  purge="$([[ -s "$STATE_DIR/standby-region-local-purge.json" ]] &&
    printf complete || printf pending)"
  jq -n --arg run_id "$RUN_ID" --arg state "$state" --arg active "$active" \
    --arg origin "$origin" --argjson revision "$revision" \
    --arg standby_region_local_purge "$purge" \
    --arg evidence "$([[ -s "$EVIDENCE" ]] && printf complete || printf pending)" \
    '{run_id:$run_id,coordinator_state:$state,active_region:$active,
      revision:$revision,cloudfront_origin:$origin,
      standby_region_local_purge:$standby_region_local_purge,
      evidence:$evidence}'
}

rollback_to_primary() {
  local primary standby state active current qrev arev source
  primary="$(context_value '.primary_region')"
  standby="$(context_value '.standby_region')"
  state="$(coordinator_field "$primary" state)"
  active="$(coordinator_field "$primary" active_region)"
  current="$(control_revision "$primary")"
  if [[ "$state" == "active" && "$active" == "$primary" ]]; then
    assert_coordinated_writer "$primary"
    purge_standby_region_local_tables
    switch_edge "$(context_value '.primary_api_host')" primary
    wait_region_header "$(context_value '.issuer')" "" "$primary"
    pass "primary was already active"
    return
  fi
  source="$active"
  if [[ "$state" == "active" ]]; then
    qrev=$(( current + 1 ))
    quiesce_region "$source" "$current" "$qrev"
  elif [[ "$state" == "quiescing" ]]; then
    qrev="$current"
  else
    fail "unknown coordinator state $state"
  fi
  wait_quiescence "$source" "$qrev"
  purge_standby_region_local_tables
  if [[ "$source" == "$(context_value '.standby_region')" ]]; then
    record_standby_region_local_purge "$source" "$qrev"
  fi
  arev=$(( qrev + 1 ))
  activate_region "$primary" "$source" "$qrev" "$arev"
  assert_coordinated_writer "$primary"
  switch_edge "$(context_value '.primary_api_host')" primary
  wait_region_header "$(context_value '.issuer')" "" "$primary"
  pass "rollback restored the primary at revision $arev"
}

load_context_settings
info "run_id=$RUN_ID state=$STATE_DIR action=$ACTION"
if [[ "$ACTION" == "status" ]]; then
  show_status
  exit 0
fi
if [[ "$ACTION" == "rollback" ]]; then
  validate_deployment_context
  rollback_to_primary
  cleanup_probe
  exit 0
fi

[[ -s "$CONTEXT" ]] || initialize_context
load_context_settings
validate_deployment_context
ensure_origin_auth_header

FAILOVER_Q="$(context_value '.revisions.failover_quiesce')"
FAILOVER_A="$(context_value '.revisions.failover_active')"
FAILBACK_Q="$(context_value '.revisions.failback_quiesce')"
FAILBACK_A="$(context_value '.revisions.failback_active')"
INITIAL="$(context_value '.revisions.initial')"

CURRENT_REVISION="$(control_revision "$PRIMARY_REGION")"
CURRENT_STATE="$(coordinator_field "$PRIMARY_REGION" state)"
CURRENT_ACTIVE="$(coordinator_field "$PRIMARY_REGION" active_region)"
if (( CURRENT_REVISION == INITIAL )); then
  [[ "$CURRENT_STATE" == "active" && "$CURRENT_ACTIVE" == "$PRIMARY_REGION" ]] ||
    fail "unexpected initial Region control state"
  setup_probe
  capture_source_artifacts
  quiesce_region "$PRIMARY_REGION" "$INITIAL" "$FAILOVER_Q"
  CURRENT_REVISION="$FAILOVER_Q"
  CURRENT_STATE="quiescing"
else
  validate_persisted_probe
fi
if (( CURRENT_REVISION == FAILOVER_Q )); then
  [[ "$CURRENT_STATE" == "quiescing" ]] ||
    fail "failover quiesce revision is not quiescing"
  wait_quiescence "$PRIMARY_REGION" "$FAILOVER_Q"
  activate_region "$STANDBY_REGION" "$PRIMARY_REGION" "$FAILOVER_Q" "$FAILOVER_A"
  CURRENT_REVISION="$FAILOVER_A"
  CURRENT_STATE="active"
  CURRENT_ACTIVE="$STANDBY_REGION"
fi
if (( CURRENT_REVISION == FAILOVER_A )); then
  [[ "$CURRENT_STATE" == "active" && "$CURRENT_ACTIVE" == "$STANDBY_REGION" ]] ||
    fail "failover activation revision does not name standby"
  assert_coordinated_writer "$STANDBY_REGION"
  switch_edge "$(context_value '.standby_api_host')" standby
  wait_region_header "$ISSUER" "" "$STANDBY_REGION"
  [[ -s "$STATE_DIR/failover-ready.epoch" ]] ||
    now_epoch >"$STATE_DIR/failover-ready.epoch"
  assert_artifact_set_rejected "$(context_value '.standby_api_url')" \
    "${ISSUER#https://}" source "source-after-failover" 1
  TARGET_JWKS_HASH="$(jwks_hash "$(context_value '.standby_api_url')" \
    "${ISSUER#https://}" "$STATE_DIR/jwks-standby.json")"
  [[ "$TARGET_JWKS_HASH" == "$(<"$STATE_DIR/jwks-before.sha256")" ]] ||
    fail "standby JWKS differs from primary pre-failover JWKS"
  capture_target_artifacts_and_revoke
  quiesce_region "$STANDBY_REGION" "$FAILOVER_A" "$FAILBACK_Q"
  CURRENT_REVISION="$FAILBACK_Q"
  CURRENT_STATE="quiescing"
fi
if (( CURRENT_REVISION == FAILBACK_Q )); then
  [[ "$CURRENT_STATE" == "quiescing" ]] ||
    fail "failback quiesce revision is not quiescing"
  [[ -f "$STATE_DIR/target-artifacts.ready" ]] ||
    fail "failback started without completed target artifact evidence"
  wait_quiescence "$STANDBY_REGION" "$FAILBACK_Q"
  purge_standby_region_local_tables
  record_standby_region_local_purge "$STANDBY_REGION" "$FAILBACK_Q"
  activate_region "$PRIMARY_REGION" "$STANDBY_REGION" "$FAILBACK_Q" "$FAILBACK_A"
  CURRENT_REVISION="$FAILBACK_A"
  CURRENT_STATE="active"
  CURRENT_ACTIVE="$PRIMARY_REGION"
fi
if (( CURRENT_REVISION != FAILBACK_A )) ||
  [[ "$CURRENT_STATE" != "active" || "$CURRENT_ACTIVE" != "$PRIMARY_REGION" ]]; then
  fail "Region control revision/state is outside this drill state machine"
fi
assert_coordinated_writer "$PRIMARY_REGION"
switch_edge "$(context_value '.primary_api_host')" primary
wait_region_header "$ISSUER" "" "$PRIMARY_REGION"
[[ -s "$STATE_DIR/failback-ready.epoch" ]] ||
  now_epoch >"$STATE_DIR/failback-ready.epoch"
if [[ ! -f "$STATE_DIR/failback-assertions.ready" ]]; then
  assert_artifact_set_rejected "$(context_value '.primary_api_url')" \
    "${ISSUER#https://}" source "source-after-failback" 1
  assert_artifact_set_rejected "$(context_value '.primary_api_url')" \
    "${ISSUER#https://}" target "target-after-failback" 1
  PRIMARY_JWKS_HASH="$(jwks_hash "$ISSUER" "" "$STATE_DIR/jwks-after.json")"
  [[ "$PRIMARY_JWKS_HASH" == "$(<"$STATE_DIR/jwks-before.sha256")" ]] ||
    fail "failback JWKS differs from pre-failover JWKS"
  login_password "$ISSUER" "" "$SECRETS_DIR/failback.cookies"
  mint_code "$ISSUER" "" "$SECRETS_DIR/failback.cookies" failback-pair
  exchange_code "$ISSUER" "" failback-pair
  assert_oauth_rejected "$ISSUER" "" failback-consumed-code \
    "code 无效或已使用" \
    -X POST -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=authorization_code' \
    --data-urlencode "code@$SECRETS_DIR/failback-pair.code" \
    --data-urlencode 'code_verifier=0123456789012345678901234567890123456789abc' \
    --data-urlencode "redirect_uri=$(context_value '.probe.redirect_uri')" \
    --data-urlencode "client_id=$(context_value '.probe.client_id')"
  verify_token_pair "$SECRETS_DIR/failback-pair.tokens.json" \
    "$STATE_DIR/jwks-after.json" failback
  [[ "$(distribution_origin_host)" == "$(context_value '.primary_api_host')" ]] ||
    fail "CloudFront origin was not restored to primary"
  touch "$STATE_DIR/failback-assertions.ready"
fi
cleanup_probe
write_evidence
pass "regional failover and failback drill complete"
