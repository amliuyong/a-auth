#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

EVENT_ID="evt_replay_test"
PAYLOAD="$WORK/payload.json"
CAPTURE="$WORK/replayed.json"
FAKE_BIN="$WORK/bin"
mkdir -p "$FAKE_BIN"

jq -n --arg id "$EVENT_ID" '{
  event: {
    schema_version: "1.0",
    event_id: $id,
    occurred_at: 1785513600,
    tenant_id: "t1",
    actor: {kind: "system", id: "test"},
    subject: {kind: "user", id: "user:test@example.com"},
    category: "delivery",
    action: "user.enable",
    outcome: "success",
    correlation: {operation_id: "op-test"}
  },
  delivery: {
    status: "failed",
    attempts: 6,
    history: [{status: "failed", occurred_at: 1785513600}]
  },
  ingress_attempts: 0
}' >"$PAYLOAD"

encode_payload() {
  local payload="${1:?payload path required}"
  python3 - "$payload" <<'PY'
import base64
import pathlib
import sys

print(base64.urlsafe_b64encode(pathlib.Path(sys.argv[1]).read_bytes()).rstrip(b"=").decode())
PY
}

ENCODED="$(encode_payload "$PAYLOAD")"

write_log_events() {
  local target="${1:?target path required}"
  local marker="${2:?marker required}"
  shift 2
  jq -n --arg marker "$marker" --args '$ARGS.positional
    | to_entries
    | {
        events: [
          .[] | {
            timestamp: (1785513600000 + .key),
            message: (
              $marker + " event_id=evt_replay_test payload=" + .value
            )
          }
        ]
      }' "$@" >"$target"
}

cat >"$FAKE_BIN/aws" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

while [[ "${1:-}" == --* ]]; do
  case "$1" in
    --profile | --region)
      shift 2
      ;;
    *)
      break
      ;;
  esac
done

service="${1:?service required}"
operation="${2:?operation required}"
shift 2

case "$service/$operation" in
  cloudformation/describe-stacks)
    jq -n '{
      Stacks: [{
        Outputs: [
          {
            OutputKey: "SecurityEventIngressQueueUrl",
            OutputValue: "https://sqs.us-east-1.amazonaws.com/123/test"
          },
          {
            OutputKey: "SecurityEventsTableName",
            OutputValue: "SecurityEvents"
          }
        ]
      }]
    }'
    ;;
  cloudformation/list-stack-resources)
    jq -n '{
      StackResourceSummaries: [
        {
          ResourceType: "AWS::Logs::LogGroup",
          LogicalResourceId: "AuthFnLogGroup123",
          PhysicalResourceId: "auth-log"
        },
        {
          ResourceType: "AWS::Logs::LogGroup",
          LogicalResourceId: "ReclaimFnLogGroup123",
          PhysicalResourceId: "reclaim-log"
        }
      ]
    }'
    ;;
  logs/filter-log-events)
    marker="${FAKE_LOG_MARKER:-}"
    log_group=""
    while (($#)); do
      case "$1" in
        --filter-pattern)
          if [[ -z "$marker" ]]; then
            if [[ "$2" == *BATCH_RECOVERY* ]]; then
              marker="SECURITY_EVENT_BATCH_RECOVERY"
            else
              marker="SECURITY_EVENT_EMERGENCY"
            fi
          fi
          shift 2
          ;;
        --log-group-name)
          log_group="$2"
          shift 2
          ;;
        *)
          shift
          ;;
      esac
    done
    if [[ "$log_group" != "auth-log" ]]; then
      printf '{"events":[]}\n'
    elif [[ -n "${FAKE_LOG_EVENTS_FILE:-}" ]]; then
      jq --arg marker "$marker" '{
        events: [
          .events[]
          | select(.message | contains($marker + " "))
        ]
      }' "$FAKE_LOG_EVENTS_FILE"
    else
      jq -n --arg encoded "$FAKE_EMERGENCY_PAYLOAD" --arg id "$FAKE_EVENT_ID" \
        --arg marker "$marker" '{
        events: [{
          timestamp: 1785513600000,
          message: (
            $marker + " event_id=" + $id + " payload=" + $encoded
          )
        }]
      }'
    fi
    ;;
  dynamodb/get-item)
    if [[ -n "${FAKE_EXISTING_ENVELOPE:-}" ]]; then
      jq -n --arg id "$FAKE_EVENT_ID" --arg envelope "$FAKE_EXISTING_ENVELOPE" \
        --arg attempts "${FAKE_EXISTING_SOURCE_ATTEMPTS:-}" \
        --arg history "${FAKE_EXISTING_SOURCE_HISTORY:-}" '{
          Item: {
            event_id: {S: $id},
            envelope: {S: $envelope}
          }
        }
        | if $attempts == "" then .
          else .Item.source_delivery_attempts = {N: $attempts}
          end
        | if $history == "" then .
          else .Item.source_delivery_history = {
            L: [
              ($history | fromjson)[]
              | {M: {
                  status: {S: .status},
                  occurred_at: {N: (.occurred_at | tostring)}
                }}
            ]
          }
          end'
    else
      printf '{}\n'
    fi
    ;;
  sqs/send-message)
    body=""
    while (($#)); do
      case "$1" in
        --message-body)
          body="${2#file://}"
          shift 2
          ;;
        *)
          shift
          ;;
      esac
    done
    cp "$body" "$FAKE_AWS_CAPTURE"
    jq -n '{MessageId: "message-1"}'
    ;;
  *)
    printf 'unexpected fake AWS command: %s/%s\n' "$service" "$operation" >&2
    exit 2
    ;;
esac
SH
chmod +x "$FAKE_BIN/aws"

export PATH="$FAKE_BIN:$PATH"
export FAKE_AWS_CAPTURE="$CAPTURE"
export FAKE_EMERGENCY_PAYLOAD="$ENCODED"
export FAKE_EVENT_ID="$EVENT_ID"

if "$ROOT/scripts/replay_security_event_emergency.sh" \
  --stack TestStack --profile test --region us-east-1 \
  --start-time 1785513500 --all-matches >"$WORK/unbounded.out" 2>&1; then
  printf 'unbounded all-matches replay unexpectedly succeeded\n' >&2
  exit 1
fi
grep -F -- '--all-matches requires a bounded --end-time' \
  "$WORK/unbounded.out" >/dev/null

if "$ROOT/scripts/replay_security_event_emergency.sh" \
  --stack TestStack --profile test --region us-east-1 \
  --start-time 1785513500 --action user.enable \
  >"$WORK/unbounded-action.out" 2>&1; then
  printf 'unbounded action replay unexpectedly succeeded\n' >&2
  exit 1
fi
grep -F -- '--end-time is required' "$WORK/unbounded-action.out" >/dev/null

if "$ROOT/scripts/replay_security_event_emergency.sh" \
  --stack TestStack --profile test --region us-east-1 \
  --start-time 1785513500 --end-time 1785513700 --action user.enable \
  >"$WORK/missing-tenant.out" 2>&1; then
  printf 'tenant-unscoped replay unexpectedly succeeded\n' >&2
  exit 1
fi
grep -F -- 'provide --tenant-id or explicit --all-tenants' \
  "$WORK/missing-tenant.out" >/dev/null

dry_run="$(
  "$ROOT/scripts/replay_security_event_emergency.sh" \
    --stack TestStack --profile test --region us-east-1 \
    --start-time 1785513500 --end-time 1785513700 \
    --tenant-id t1 --event-id "$EVENT_ID"
)"
grep -Fx "READY $EVENT_ID marker=SECURITY_EVENT_EMERGENCY tenant=t1 action=user.enable subject=user:test@example.com" \
  <<<"$dry_run" >/dev/null
[[ ! -e "$CAPTURE" ]]

execute="$(
  "$ROOT/scripts/replay_security_event_emergency.sh" \
    --stack TestStack --profile test --region us-east-1 \
    --start-time 1785513500 --end-time 1785513700 \
    --tenant-id t1 --event-id "$EVENT_ID" --execute
)"
grep -Fx "REPLAYED $EVENT_ID marker=SECURITY_EVENT_EMERGENCY tenant=t1 action=user.enable subject=user:test@example.com" \
  <<<"$execute" >/dev/null
jq -e --arg id "$EVENT_ID" '.event.event_id == $id and .delivery.attempts == 6' \
  "$CAPTURE" >/dev/null

export FAKE_LOG_MARKER="SECURITY_EVENT_BATCH_RECOVERY"
batch_recovery="$(
  "$ROOT/scripts/replay_security_event_emergency.sh" \
    --stack TestStack --profile test --region us-east-1 \
    --start-time 1785513500 --end-time 1785513700 \
    --tenant-id t1 --event-id "$EVENT_ID" --marker batch-recovery
)"
grep -Fx "READY $EVENT_ID marker=SECURITY_EVENT_BATCH_RECOVERY tenant=t1 action=user.enable subject=user:test@example.com" \
  <<<"$batch_recovery" >/dev/null

unset FAKE_LOG_MARKER
all_markers="$(
  "$ROOT/scripts/replay_security_event_emergency.sh" \
    --stack TestStack --profile test --region us-east-1 \
    --start-time 1785513500 --end-time 1785513700 \
    --tenant-id t1 --event-id "$EVENT_ID" --marker all
)"
grep -Fx "READY $EVENT_ID marker=SECURITY_EVENT_EMERGENCY tenant=t1 action=user.enable subject=user:test@example.com" \
  <<<"$all_markers" >/dev/null

FAKE_EXISTING_ENVELOPE="$(jq -c '.event' "$PAYLOAD")"
export FAKE_EXISTING_ENVELOPE
export FAKE_EXISTING_SOURCE_ATTEMPTS=6
FAKE_EXISTING_SOURCE_HISTORY="$(jq -c '.delivery.history' "$PAYLOAD")"
export FAKE_EXISTING_SOURCE_HISTORY
already_present="$(
  "$ROOT/scripts/replay_security_event_emergency.sh" \
    --stack TestStack --profile test --region us-east-1 \
    --start-time 1785513500 --end-time 1785513700 \
    --tenant-id t1 --event-id "$EVENT_ID"
)"
grep -Fx "SKIPPED $EVENT_ID tenant=t1 already-present attempts=6" \
  <<<"$already_present" >/dev/null

export FAKE_EXISTING_SOURCE_ATTEMPTS=2
history_merge="$(
  "$ROOT/scripts/replay_security_event_emergency.sh" \
    --stack TestStack --profile test --region us-east-1 \
    --start-time 1785513500 --end-time 1785513700 \
    --tenant-id t1 --event-id "$EVENT_ID" --execute
)"
grep -Fx "REPLAYED $EVENT_ID marker=SECURITY_EVENT_EMERGENCY tenant=t1 action=user.enable subject=user:test@example.com" \
  <<<"$history_merge" >/dev/null
jq -e '.delivery.attempts == 6' "$CAPTURE" >/dev/null

EQUAL_ATTEMPT_PAYLOAD="$WORK/equal-attempt-payload.json"
LOG_EVENTS="$WORK/log-events.json"
jq '.delivery.history = [
  {status: "pending", occurred_at: 1785513599},
  {status: "failed", occurred_at: 1785513600}
]' "$PAYLOAD" >"$EQUAL_ATTEMPT_PAYLOAD"
write_log_events "$LOG_EVENTS" SECURITY_EVENT_EMERGENCY \
  "$(encode_payload "$EQUAL_ATTEMPT_PAYLOAD")"
export FAKE_LOG_EVENTS_FILE="$LOG_EVENTS"
export FAKE_EXISTING_SOURCE_ATTEMPTS=6
export FAKE_EXISTING_SOURCE_HISTORY='[{"status":"pending","occurred_at":1785513599}]'
equal_attempt_merge="$(
  "$ROOT/scripts/replay_security_event_emergency.sh" \
    --stack TestStack --profile test --region us-east-1 \
    --start-time 1785513500 --end-time 1785513700 \
    --tenant-id t1 --event-id "$EVENT_ID" --execute
)"
grep -Fx "REPLAYED $EVENT_ID marker=SECURITY_EVENT_EMERGENCY tenant=t1 action=user.enable subject=user:test@example.com" \
  <<<"$equal_attempt_merge" >/dev/null
jq -e '.delivery.attempts == 6 and (.delivery.history | length) == 2' \
  "$CAPTURE" >/dev/null

export FAKE_EXISTING_SOURCE_HISTORY='[
  {"status":"pending","occurred_at":1785513599},
  {"status":"retrying","occurred_at":1785513600}
]'
if "$ROOT/scripts/replay_security_event_emergency.sh" \
  --stack TestStack --profile test --region us-east-1 \
  --start-time 1785513500 --end-time 1785513700 \
  --tenant-id t1 --event-id "$EVENT_ID" \
  >"$WORK/divergent-history.out" 2>&1; then
  printf 'divergent source history unexpectedly succeeded\n' >&2
  exit 1
fi
grep -F "event ID $EVENT_ID has divergent source_delivery_history" \
  "$WORK/divergent-history.out" >/dev/null
unset FAKE_LOG_EVENTS_FILE

export FAKE_EXISTING_ENVELOPE='{"schema_version":"1.0","event_id":"evt_replay_test","tenant_id":"other"}'
if "$ROOT/scripts/replay_security_event_emergency.sh" \
  --stack TestStack --profile test --region us-east-1 \
  --start-time 1785513500 --end-time 1785513700 \
  --tenant-id t1 --event-id "$EVENT_ID" >"$WORK/collision.out" 2>&1; then
  printf 'collision replay unexpectedly succeeded\n' >&2
  exit 1
fi
grep -F "event ID $EVENT_ID already exists with a different envelope" \
  "$WORK/collision.out" >/dev/null

unset FAKE_EXISTING_ENVELOPE FAKE_EXISTING_SOURCE_ATTEMPTS \
  FAKE_EXISTING_SOURCE_HISTORY
CONFLICT_PAYLOAD="$WORK/conflict-payload.json"
jq '.event.action = "user.disable"' "$PAYLOAD" >"$CONFLICT_PAYLOAD"
CONFLICT_ENCODED="$(encode_payload "$CONFLICT_PAYLOAD")"
LOG_EVENTS="$WORK/log-events.json"
write_log_events "$LOG_EVENTS" SECURITY_EVENT_EMERGENCY \
  "$ENCODED" "$CONFLICT_ENCODED"
export FAKE_LOG_EVENTS_FILE="$LOG_EVENTS"
if "$ROOT/scripts/replay_security_event_emergency.sh" \
  --stack TestStack --profile test --region us-east-1 \
  --start-time 1785513500 --end-time 1785513700 \
  --tenant-id t1 --event-id "$EVENT_ID" >"$WORK/retained-collision.out" 2>&1; then
  printf 'retained collision replay unexpectedly succeeded\n' >&2
  exit 1
fi
grep -F "event ID $EVENT_ID has conflicting retained envelopes" \
  "$WORK/retained-collision.out" >/dev/null

DIVERGENT_RETAINED_PAYLOAD="$WORK/divergent-retained-payload.json"
jq '.delivery.history = [
  {status: "retrying", occurred_at: 1785513600}
]' "$PAYLOAD" >"$DIVERGENT_RETAINED_PAYLOAD"
write_log_events "$LOG_EVENTS" SECURITY_EVENT_EMERGENCY \
  "$ENCODED" "$(encode_payload "$DIVERGENT_RETAINED_PAYLOAD")"
if "$ROOT/scripts/replay_security_event_emergency.sh" \
  --stack TestStack --profile test --region us-east-1 \
  --start-time 1785513500 --end-time 1785513700 \
  --tenant-id t1 --event-id "$EVENT_ID" \
  >"$WORK/divergent-retained-history.out" 2>&1; then
  printf 'divergent retained history unexpectedly succeeded\n' >&2
  exit 1
fi
grep -F "event ID $EVENT_ID has divergent retained delivery history" \
  "$WORK/divergent-retained-history.out" >/dev/null

OLDER_PAYLOAD="$WORK/older-payload.json"
jq '.delivery.attempts = 2' "$PAYLOAD" >"$OLDER_PAYLOAD"
write_log_events "$LOG_EVENTS" SECURITY_EVENT_EMERGENCY \
  "$(encode_payload "$OLDER_PAYLOAD")" "$ENCODED"
jq '(.events[].timestamp) = 1785513600000' "$LOG_EVENTS" \
  >"$WORK/same-timestamp-log-events.json"
mv "$WORK/same-timestamp-log-events.json" "$LOG_EVENTS"
latest_snapshot="$(
  "$ROOT/scripts/replay_security_event_emergency.sh" \
    --stack TestStack --profile test --region us-east-1 \
    --start-time 1785513500 --end-time 1785513700 \
    --all-tenants --event-id "$EVENT_ID" --execute
)"
grep -Fx "REPLAYED $EVENT_ID marker=SECURITY_EVENT_EMERGENCY tenant=t1 action=user.enable subject=user:test@example.com" \
  <<<"$latest_snapshot" >/dev/null
jq -e '.delivery.attempts == 6' "$CAPTURE" >/dev/null

SAME_ATTEMPT_SHORT="$WORK/same-attempt-short.json"
SAME_ATTEMPT_LONG="$WORK/same-attempt-long.json"
jq '.delivery.status = "pending"
  | .delivery.history = [
      {status: "pending", occurred_at: 1785513599}
    ]' "$PAYLOAD" >"$SAME_ATTEMPT_SHORT"
jq -c '.delivery.history = [
  {status: "pending", occurred_at: 1785513599},
  {status: "failed", occurred_at: 1785513600}
]' "$PAYLOAD" >"$SAME_ATTEMPT_LONG"
write_log_events "$LOG_EVENTS" SECURITY_EVENT_EMERGENCY \
  "$(encode_payload "$SAME_ATTEMPT_SHORT")" \
  "$(encode_payload "$SAME_ATTEMPT_LONG")"
jq '(.events[].timestamp) = 1785513600000' "$LOG_EVENTS" \
  >"$WORK/same-attempt-log-events.json"
mv "$WORK/same-attempt-log-events.json" "$LOG_EVENTS"
same_attempt_snapshot="$(
  "$ROOT/scripts/replay_security_event_emergency.sh" \
    --stack TestStack --profile test --region us-east-1 \
    --start-time 1785513500 --end-time 1785513700 \
    --all-tenants --event-id "$EVENT_ID" --execute
)"
grep -Fx "REPLAYED $EVENT_ID marker=SECURITY_EVENT_EMERGENCY tenant=t1 action=user.enable subject=user:test@example.com" \
  <<<"$same_attempt_snapshot" >/dev/null
jq -e '
  .delivery.attempts == 6
  and .delivery.status == "failed"
  and [.delivery.history[].status] == ["pending", "failed"]
' "$CAPTURE" >/dev/null

PREFIXED_LOG_EVENTS="$WORK/prefixed-log-events.json"
jq '(.events[].message) |= ("NOTICE " + .)' \
  "$LOG_EVENTS" >"$PREFIXED_LOG_EVENTS"
export FAKE_LOG_EVENTS_FILE="$PREFIXED_LOG_EVENTS"
if "$ROOT/scripts/replay_security_event_emergency.sh" \
  --stack TestStack --profile test --region us-east-1 \
  --start-time 1785513500 --end-time 1785513700 \
  --all-tenants --event-id "$EVENT_ID" \
  >"$WORK/prefixed-marker.out" 2>&1; then
  printf 'prefixed marker replay unexpectedly succeeded\n' >&2
  exit 1
fi
grep -F 'no matching retained security-event ingress found' \
  "$WORK/prefixed-marker.out" >/dev/null
export FAKE_LOG_EVENTS_FILE="$LOG_EVENTS"

for mutation in missing_actor invalid_category invalid_status negative_attempts \
  oversized_actor_id out_of_range_timestamp; do
  invalid="$WORK/$mutation.json"
  case "$mutation" in
    missing_actor)
      jq 'del(.event.actor)' "$PAYLOAD" >"$invalid"
      ;;
    invalid_category)
      jq '.event.category = "invented"' "$PAYLOAD" >"$invalid"
      ;;
    invalid_status)
      jq '.delivery.status = "invented"' "$PAYLOAD" >"$invalid"
      ;;
    negative_attempts)
      jq '.delivery.attempts = -1' "$PAYLOAD" >"$invalid"
      ;;
    oversized_actor_id)
      jq '.event.actor.id = ("\u00e9" * 300)' "$PAYLOAD" >"$invalid"
      ;;
    out_of_range_timestamp)
      jq '.event.occurred_at = 9223372036854775808' "$PAYLOAD" >"$invalid"
      ;;
  esac
  write_log_events "$LOG_EVENTS" SECURITY_EVENT_EMERGENCY \
    "$(encode_payload "$invalid")"
  if "$ROOT/scripts/replay_security_event_emergency.sh" \
    --stack TestStack --profile test --region us-east-1 \
    --start-time 1785513500 --end-time 1785513700 \
    --all-tenants --event-id "$EVENT_ID" \
    >"$WORK/$mutation.out" 2>&1; then
    printf '%s retained ingress unexpectedly succeeded\n' "$mutation" >&2
    exit 1
  fi
  grep -F "invalid retained ingress for event $EVENT_ID" \
    "$WORK/$mutation.out" >/dev/null
done
unset FAKE_LOG_EVENTS_FILE

printf 'security event emergency replay tests passed\n'
