#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${OIDF_HTMLUNIT_PORT:-4178}"
BASE_URL="http://127.0.0.1:$PORT"
LOG="$(mktemp)"
FIXTURE_PID=""

cleanup() {
  if [[ -n "$FIXTURE_PID" ]]; then
    kill "$FIXTURE_PID" 2>/dev/null || true
    wait "$FIXTURE_PID" 2>/dev/null || true
  fi
  rm -f "$LOG"
}
trap cleanup EXIT

for command in curl java mvn node; do
  command -v "$command" >/dev/null || {
    printf 'missing command: %s\n' "$command" >&2
    exit 1
  }
done
test -f "$ROOT/dist/index.html" || {
  printf 'production bundle is missing; run npm run build first\n' >&2
  exit 1
}

OIDF_HTMLUNIT_PORT="$PORT" node "$ROOT/scripts/oidf-htmlunit-fixture.mjs" \
  >"$LOG" 2>&1 &
FIXTURE_PID=$!
for _ in {1..50}; do
  if curl --fail --silent "$BASE_URL/health" >/dev/null; then
    break
  fi
  if ! kill -0 "$FIXTURE_PID" 2>/dev/null; then
    cat "$LOG" >&2
    exit 1
  fi
  sleep 0.2
done
curl --fail --silent "$BASE_URL/health" >/dev/null || {
  cat "$LOG" >&2
  exit 1
}

mvn --batch-mode --no-transfer-progress \
  --file "$ROOT/htmlunit-smoke/pom.xml" \
  -Doidf.base-url="$BASE_URL" \
  test
