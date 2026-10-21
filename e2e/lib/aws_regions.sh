#!/usr/bin/env bash
# Shared deployment/operational inventory: standard AWS commercial partition.
# Region choice does not relax any caller's account, stack or receipt checks.
require_commercial_regions() {
  local inventory
  inventory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)/infra/config/commercial-regions.json"
  if ! python3 - "$inventory" "$@" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    regions = json.load(source)
requested = sys.argv[2:]
if not requested or len(set(requested)) != len(requested):
    raise SystemExit(1)
if any(region not in regions for region in requested):
    raise SystemExit(1)
PY
  then
    printf 'FAIL: requires distinct known AWS commercial Regions (aws partition)\n' >&2
    return 1
  fi
}
