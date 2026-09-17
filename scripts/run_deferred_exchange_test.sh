#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
source ./scripts/rust_test_stack.sh

# Change the clock only in one test process, never in the host or the service.
test_dir="$(mktemp -d)"
trap 'rm -f "$test_dir/clock.so" "$test_dir/offset" "$test_dir/build.json"; rmdir "$test_dir"' EXIT
cc -shared -fPIC -Wall -Wextra -Werror \
  scripts/tests/deferred_exchange_clock.c -o "$test_dir/clock.so"
cargo test -p agent-auth-http --features aws --test workload_consent_e2e \
  --locked --no-run --message-format=json > "$test_dir/build.json"
test_binary="$(python3 - "$test_dir/build.json" <<'PY'
import json
import sys

executables = []
with open(sys.argv[1], encoding="utf-8") as source:
    for line in source:
        item = json.loads(line)
        if (
            item.get("reason") == "compiler-artifact"
            and item.get("target", {}).get("name") == "workload_consent_e2e"
            and item.get("executable")
        ):
            executables.append(item["executable"])
assert len(executables) == 1, executables
print(executables[0])
PY
)"
test_name="workload_consent_deferred_exchange_after_two_hours"
test_listing="$("$test_binary" "$test_name" --exact --list)"
if [[ "$test_listing" != *"$test_name: test"* ]]; then
  printf 'Missing deferred exchange acceptance test: %s\n' "$test_name" >&2
  exit 1
fi
printf '0\n' > "$test_dir/offset"
A_AUTH_TEST_CLOCK_FILE="$test_dir/offset" \
  LD_PRELOAD="$test_dir/clock.so" \
  "$test_binary" "$test_name" \
  --exact --ignored --nocapture --test-threads=1
