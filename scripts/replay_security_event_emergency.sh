#!/usr/bin/env bash
# Replay retained security-event emergency envelopes after the normal ledger and
# ingress queue recover. Dry-run is the default; --execute sends matching events.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  replay_security_event_emergency.sh --stack STACK --start-time EPOCH_SECONDS \
    --end-time EPOCH_SECONDS (--tenant-id ID | --all-tenants) \
    [--event-id ID] [--action ACTION] [--subject-id ID] \
    [--marker emergency|batch-recovery|all] \
    [--profile PROFILE] [--region REGION] [--all-matches] [--execute]

At least one selector (--event-id, --action, --subject-id, or --all-matches) is
required. The command reads complete typed ingress envelopes from retained
runtime logs within a bounded incident window, rejects conflicting immutable
envelopes, and prints the planned work. A tenant selector is mandatory;
--all-tenants is an explicit acknowledgement of stack-wide scope. Existing hot
ledger rows are replayed only when the retained delivery snapshot contains newer
source attempts or extends the source history for the same attempt count. The
command only sends to the deployed ingress queue when --execute is set.
EOF
}

STACK=""
START_TIME=""
END_TIME=""
TENANT_ID=""
EVENT_ID=""
ACTION=""
SUBJECT_ID=""
MARKER="emergency"
PROFILE="${PROFILE:-${AWS_PROFILE:-}}"
REGION="${REGION:-${AWS_REGION:-us-east-1}}"
ALL_MATCHES=0
ALL_TENANTS=0
EXECUTE=0

while (($#)); do
  case "$1" in
    --stack)
      STACK="${2:?stack value required}"
      shift 2
      ;;
    --start-time)
      START_TIME="${2:?start-time value required}"
      shift 2
      ;;
    --end-time)
      END_TIME="${2:?end-time value required}"
      shift 2
      ;;
    --tenant-id)
      TENANT_ID="${2:?tenant-id value required}"
      shift 2
      ;;
    --all-tenants)
      ALL_TENANTS=1
      shift
      ;;
    --event-id)
      EVENT_ID="${2:?event-id value required}"
      shift 2
      ;;
    --action)
      ACTION="${2:?action value required}"
      shift 2
      ;;
    --subject-id)
      SUBJECT_ID="${2:?subject-id value required}"
      shift 2
      ;;
    --marker)
      MARKER="${2:?marker value required}"
      shift 2
      ;;
    --profile)
      PROFILE="${2:?profile value required}"
      shift 2
      ;;
    --region)
      REGION="${2:?region value required}"
      shift 2
      ;;
    --all-matches)
      ALL_MATCHES=1
      shift
      ;;
    --execute)
      EXECUTE=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ -n "$STACK" ]] || {
  printf '%s\n' '--stack is required' >&2
  exit 2
}
[[ "$START_TIME" =~ ^[0-9]+$ ]] || {
  printf '%s\n' '--start-time must be Unix epoch seconds' >&2
  exit 2
}
[[ -z "$END_TIME" || "$END_TIME" =~ ^[0-9]+$ ]] || {
  printf '%s\n' '--end-time must be Unix epoch seconds' >&2
  exit 2
}
if [[ -n "$END_TIME" && "$END_TIME" -lt "$START_TIME" ]]; then
  printf '%s\n' '--end-time must not precede --start-time' >&2
  exit 2
fi
case "$MARKER" in
  emergency | batch-recovery | all) ;;
  *)
    printf '%s\n' '--marker must be emergency, batch-recovery, or all' >&2
    exit 2
    ;;
esac
if [[ -z "$EVENT_ID" && -z "$ACTION" && -z "$SUBJECT_ID" &&
  "$ALL_MATCHES" != "1" ]]; then
  printf '%s\n' \
    'provide --event-id, --action, --subject-id, or explicit --all-matches' >&2
  exit 2
fi
if [[ "$ALL_MATCHES" == "1" && -z "$END_TIME" ]]; then
  printf '%s\n' '--all-matches requires a bounded --end-time' >&2
  exit 2
fi
if [[ -z "$END_TIME" ]]; then
  printf '%s\n' '--end-time is required to bound the incident window' >&2
  exit 2
fi
if [[ -n "$TENANT_ID" && "$ALL_TENANTS" == "1" ]]; then
  printf '%s\n' '--tenant-id and --all-tenants are mutually exclusive' >&2
  exit 2
fi
if [[ -z "$TENANT_ID" && "$ALL_TENANTS" != "1" ]]; then
  printf '%s\n' 'provide --tenant-id or explicit --all-tenants' >&2
  exit 2
fi
if [[ -n "$TENANT_ID" &&
  (${#TENANT_ID} -gt 63 || ! "$TENANT_ID" =~ ^[A-Za-z0-9-]+$) ]]; then
  printf '%s\n' '--tenant-id has invalid format' >&2
  exit 2
fi

for command in aws cmp jq python3 sort; do
  command -v "$command" >/dev/null || {
    printf 'missing command: %s\n' "$command" >&2
    exit 2
  }
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

AWS=(aws)
[[ -z "$PROFILE" ]] || AWS+=(--profile "$PROFILE")
AWS+=(--region "$REGION")

"${AWS[@]}" cloudformation describe-stacks --stack-name "$STACK" \
  --output json >"$WORK/stack.json"
"${AWS[@]}" cloudformation list-stack-resources --stack-name "$STACK" \
  --output json >"$WORK/resources.json"

stack_output() {
  local key="${1:?output key required}"
  jq -er --arg key "$key" '
    .Stacks[0].Outputs[]
    | select(.OutputKey == $key)
    | .OutputValue
  ' "$WORK/stack.json"
}

INGRESS_QUEUE="$(stack_output SecurityEventIngressQueueUrl)"
SECURITY_TABLE="$(stack_output SecurityEventsTableName)"
mapfile -t LOG_GROUPS < <(jq -r '
  .StackResourceSummaries[]
  | select(.ResourceType == "AWS::Logs::LogGroup")
  | select(.LogicalResourceId
      | test("^(AuthFn|ReclaimFn|RecomputeFn)LogGroup"))
  | .PhysicalResourceId
' "$WORK/resources.json" | sort -u)
if ((${#LOG_GROUPS[@]} == 0)); then
  printf 'no security-event producer log groups found in stack %s\n' "$STACK" >&2
  exit 3
fi

case "$MARKER" in
  emergency)
    MARKERS=(SECURITY_EVENT_EMERGENCY)
    ;;
  batch-recovery)
    MARKERS=(SECURITY_EVENT_BATCH_RECOVERY)
    ;;
  all)
    MARKERS=(SECURITY_EVENT_EMERGENCY SECURITY_EVENT_BATCH_RECOVERY)
    ;;
esac

: >"$WORK/candidates.tsv"
for group in "${LOG_GROUPS[@]}"; do
  for marker in "${MARKERS[@]}"; do
    query=(
      logs filter-log-events
      --log-group-name "$group"
      --start-time "$((START_TIME * 1000))"
      --filter-pattern "\"$marker\""
      --output json
    )
    if [[ -n "$END_TIME" ]]; then
      query+=(--end-time "$((END_TIME * 1000))")
    fi
    "${AWS[@]}" "${query[@]}" >"$WORK/log-events.json"
    jq -r --arg marker "$marker" '
      .events[]
      | . as $entry
      | $entry.message
      | capture(
          "^(?<marker>SECURITY_EVENT_(?:EMERGENCY|BATCH_RECOVERY)) " +
          "event_id=(?<event_id>[^ ]+) payload=(?<payload>[A-Za-z0-9_-]+)" +
          "[\\r\\n]*$"
        )
      | select(.marker == $marker)
      | [.marker, .event_id, ($entry.timestamp | tostring), .payload]
      | @tsv
    ' "$WORK/log-events.json" >>"$WORK/candidates.tsv"
  done
done
# Decode every copy before deduplicating. Delivery revision dominance decides
# between compatible snapshots; log time only breaks equivalent ties.
LC_ALL=C sort -t $'\t' -k2,2 -k3,3nr -k1,1r -k4,4 \
  "$WORK/candidates.tsv" -o "$WORK/candidates.tsv"

decode_payload() {
  local encoded="${1:?encoded payload required}"
  python3 - "$encoded" <<'PY'
import base64
import sys

encoded = sys.argv[1]
padding = "=" * (-len(encoded) % 4)
sys.stdout.buffer.write(base64.urlsafe_b64decode(encoded + padding))
PY
}

validate_ingress() {
  local logged_id="${1:?logged event ID required}"
  local body="${2:?ingress body required}"
  jq -e --arg id "$logged_id" '
    def enum($values): . as $value | $values | index($value) != null;
    def integer: type == "number" and floor == .;
    def identifier:
      type == "string"
      and utf8bytelength > 0
      and utf8bytelength <= 512
      and (test("[\u0000-\u001f\u007f]") | not);
    def delivery_status:
      enum([
        "in_memory",
        "pending",
        "retrying",
        "failed",
        "dead_letter_pending",
        "archive_refresh_pending",
        "archived",
        "dead_lettered"
      ]);
    type == "object"
    and (.event | type == "object")
    and .event.schema_version == "1.0"
    and (.event.event_id
      | type == "string"
      and . == $id
      and length <= 64
      and test("^[A-Za-z0-9._-]+$"))
    and (.event.occurred_at | integer and . > 0)
    and (.event.tenant_id
      | type == "string"
      and length > 0
      and length <= 63
      and test("^[A-Za-z0-9-]+$"))
    and (.event.actor | type == "object")
    and (.event.actor.kind | enum(["user", "admin", "client", "system"]))
    and (.event.actor.id | identifier)
    and (.event.subject | type == "object")
    and (.event.subject.kind
      | enum(["unknown", "user", "client", "grant", "credential", "tenant", "issuer"]))
    and (.event.subject.id | identifier)
    and (.event.category
      | enum([
          "authentication",
          "step_up",
          "user_lifecycle",
          "credential",
          "administration",
          "grant",
          "key_secret",
          "tenant_boundary",
          "infrastructure",
          "delivery"
        ]))
    and (.event.action
      | type == "string"
      and length > 0
      and length <= 128
      and test("^[a-z0-9._-]+$"))
    and (.event.outcome | enum(["success", "denied", "failure"]))
    and (.event.correlation | type == "object")
    and ([
      .event.correlation.request_id,
      .event.correlation.session_fingerprint,
      .event.correlation.authz_session_id,
      .event.correlation.client_id,
      .event.correlation.grant_id,
      .event.correlation.credential_id,
      .event.correlation.operation_id
    ] | all(.[]; . == null or identifier))
    and (.delivery | type == "object")
    and (.delivery.status | delivery_status)
    and (.delivery.attempts
      | integer and . >= 0 and . <= 4294967295)
    and (.delivery.last_attempt_at == null
      or (.delivery.last_attempt_at | integer))
    and (.delivery.archived_at == null
      or (.delivery.archived_at | integer))
    and (.delivery.dead_lettered_at == null
      or (.delivery.dead_lettered_at | integer))
    and (.delivery.archive_key == null
      or (.delivery.archive_key | type == "string"))
    and (.delivery.history | type == "array")
    and (all(.delivery.history[];
      type == "object"
      and (.status | delivery_status)
      and (.occurred_at | integer)))
    and (.ingress_attempts
      | integer and . >= 0 and . <= 4294967295)
  ' "$body" >/dev/null &&
    python3 - "$body" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    ingress = json.load(source)


def require_integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("integer outside the retained ingress type")


i64_min = -(2**63)
i64_max = 2**63 - 1
u32_max = 2**32 - 1
event = ingress["event"]
delivery = ingress["delivery"]
require_integer(event["occurred_at"], 1, i64_max)
require_integer(delivery["attempts"], 0, u32_max)
require_integer(ingress["ingress_attempts"], 0, u32_max)
for name in ("last_attempt_at", "archived_at", "dead_lettered_at"):
    value = delivery.get(name)
    if value is not None:
        require_integer(value, i64_min, i64_max)
for attempt in delivery["history"]:
    require_integer(attempt["occurred_at"], i64_min, i64_max)
PY
}

retained_snapshot_relation() {
  local existing="${1:?existing snapshot required}"
  local candidate="${2:?candidate snapshot required}"
  jq -nr --slurpfile existing "$existing" --slurpfile candidate "$candidate" '
    def prefix($left; $right):
      ($left | length) <= ($right | length)
      and all(range(0; ($left | length)); $left[.] == $right[.]);
    ($existing[0].delivery.attempts) as $existing_attempts
    | ($candidate[0].delivery.attempts) as $candidate_attempts
    | ([$existing[0].delivery.history[].status]) as $existing_history
    | ([$candidate[0].delivery.history[].status]) as $candidate_history
    | ($existing_attempts >= $candidate_attempts
       and prefix($candidate_history; $existing_history)) as $existing_dominates
    | ($candidate_attempts >= $existing_attempts
       and prefix($existing_history; $candidate_history)) as $candidate_dominates
    | if $existing_dominates and $candidate_dominates then "equivalent"
      elif $existing_dominates then "existing_dominates"
      elif $candidate_dominates then "candidate_dominates"
      else "divergent"
      end
  '
}

declare -A CANDIDATE_BODY=()
declare -A CANDIDATE_EVENT=()
declare -A CANDIDATE_MARKER=()
declare -A CANDIDATE_TIMESTAMP=()
index=0
while IFS=$'\t' read -r marker logged_id timestamp encoded; do
  [[ -n "$logged_id" ]] || continue
  index=$((index + 1))
  body="$WORK/ingress-$index.json"
  if ! decode_payload "$encoded" >"$body" ||
    ! validate_ingress "$logged_id" "$body"; then
    printf 'invalid retained ingress for event %s in %s\n' \
      "$logged_id" "$marker" >&2
    exit 3
  fi
  event="$WORK/event-$index.json"
  jq -cS '.event' "$body" >"$event"
  if [[ -n "${CANDIDATE_EVENT[$logged_id]:-}" ]]; then
    if ! cmp -s "${CANDIDATE_EVENT[$logged_id]}" "$event"; then
      printf 'event ID %s has conflicting retained envelopes\n' \
        "$logged_id" >&2
      exit 3
    fi
    relation="$(
      retained_snapshot_relation "${CANDIDATE_BODY[$logged_id]}" "$body"
    )"
    case "$relation" in
      candidate_dominates)
        CANDIDATE_BODY["$logged_id"]="$body"
        CANDIDATE_MARKER["$logged_id"]="$marker"
        CANDIDATE_TIMESTAMP["$logged_id"]="$timestamp"
        ;;
      existing_dominates) ;;
      equivalent)
        if [[ "$timestamp" -gt "${CANDIDATE_TIMESTAMP[$logged_id]}" ]]; then
          CANDIDATE_BODY["$logged_id"]="$body"
          CANDIDATE_MARKER["$logged_id"]="$marker"
          CANDIDATE_TIMESTAMP["$logged_id"]="$timestamp"
        fi
        ;;
      divergent)
        printf 'event ID %s has divergent retained delivery history\n' \
          "$logged_id" >&2
        exit 3
        ;;
    esac
    continue
  fi
  CANDIDATE_BODY["$logged_id"]="$body"
  CANDIDATE_EVENT["$logged_id"]="$event"
  CANDIDATE_MARKER["$logged_id"]="$marker"
  CANDIDATE_TIMESTAMP["$logged_id"]="$timestamp"
done <"$WORK/candidates.tsv"

matched=0
printf '%s\n' "${!CANDIDATE_BODY[@]}" | LC_ALL=C sort >"$WORK/candidate-ids.txt"
while IFS= read -r logged_id; do
  [[ -n "$logged_id" ]] || continue
  body="${CANDIDATE_BODY[$logged_id]}"
  marker="${CANDIDATE_MARKER[$logged_id]}"
  event_tenant="$(jq -r '.event.tenant_id' "$body")"
  event_action="$(jq -r '.event.action' "$body")"
  event_subject="$(jq -r '.event.subject.id' "$body")"
  [[ -z "$TENANT_ID" || "$event_tenant" == "$TENANT_ID" ]] || continue
  [[ -z "$EVENT_ID" || "$logged_id" == "$EVENT_ID" ]] || continue
  [[ -z "$ACTION" || "$event_action" == "$ACTION" ]] || continue
  [[ -z "$SUBJECT_ID" || "$event_subject" == "$SUBJECT_ID" ]] || continue
  matched=$((matched + 1))

  key="$(jq -cn --arg id "$logged_id" '{event_id:{S:$id}}')"
  "${AWS[@]}" dynamodb get-item --table-name "$SECURITY_TABLE" \
    --key "$key" --consistent-read \
    --projection-expression \
      'event_id,envelope,source_delivery_attempts,source_delivery_history' \
    --output json >"$WORK/existing.json"
  if jq -e '.Item.event_id.S? != null' "$WORK/existing.json" >/dev/null; then
    if ! jq -e --argjson event "$(jq -c '.event' "$body")" '
      (.Item.envelope.S | fromjson) == $event
    ' "$WORK/existing.json" >/dev/null; then
      printf 'event ID %s already exists with a different envelope\n' \
        "$logged_id" >&2
      exit 3
    fi
    retained_attempts="$(jq -r '.delivery.attempts' "$body")"
    existing_attempts="$(jq -r \
      '.Item.source_delivery_attempts.N? // "-1"' "$WORK/existing.json")"
    if [[ ! "$existing_attempts" =~ ^-1$|^[0-9]+$ ]]; then
      printf 'event ID %s has invalid source_delivery_attempts\n' \
        "$logged_id" >&2
      exit 3
    fi
    if [[ "$existing_attempts" != "-1" &&
      "$existing_attempts" -gt "$retained_attempts" ]]; then
      printf 'SKIPPED %s tenant=%s already-present attempts=%s\n' \
        "$logged_id" "$event_tenant" "$existing_attempts"
      continue
    fi
    if [[ "$existing_attempts" == "$retained_attempts" ]]; then
      existing_history="$(jq -cer '
        (.Item.source_delivery_history.L? // [])
        | map(.M.status.S)
        | if all(.[]; type == "string") then .
          else error("invalid source delivery history")
          end
      ' "$WORK/existing.json")" || {
        printf 'event ID %s has invalid source_delivery_history\n' \
          "$logged_id" >&2
        exit 3
      }
      retained_history="$(jq -c '[.delivery.history[].status]' "$body")"
      history_relation="$(jq -nr \
        --argjson existing "$existing_history" \
        --argjson retained "$retained_history" '
          def prefix($left; $right):
            ($left | length) <= ($right | length)
            and all(range(0; ($left | length)); $left[.] == $right[.]);
          if prefix($retained; $existing) then "covered"
          elif prefix($existing; $retained) then "extends"
          else "divergent"
          end
        ')"
      case "$history_relation" in
        covered)
          printf 'SKIPPED %s tenant=%s already-present attempts=%s\n' \
            "$logged_id" "$event_tenant" "$existing_attempts"
          continue
          ;;
        extends) ;;
        divergent)
          printf 'event ID %s has divergent source_delivery_history\n' \
            "$logged_id" >&2
          exit 3
          ;;
      esac
    fi
  fi

  if [[ "$EXECUTE" != "1" ]]; then
    printf 'READY %s marker=%s tenant=%s action=%s subject=%s\n' \
      "$logged_id" "$marker" "$event_tenant" "$event_action" "$event_subject"
    continue
  fi
  "${AWS[@]}" sqs send-message --queue-url "$INGRESS_QUEUE" \
    --message-body "file://$body" >/dev/null
  printf 'REPLAYED %s marker=%s tenant=%s action=%s subject=%s\n' \
    "$logged_id" "$marker" "$event_tenant" "$event_action" "$event_subject"
done <"$WORK/candidate-ids.txt"

if ((matched == 0)); then
  printf 'no matching retained security-event ingress found in stack %s\n' \
    "$STACK" >&2
  exit 4
fi
