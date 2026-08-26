#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

executed_exact_tests=0

run_pytest_exact() {
  local test_path="$1"
  local selector="$2"
  local report
  report="$(mktemp)"
  python3 -m pytest -q --import-mode=importlib --runxfail --junitxml="$report" \
    "${test_path}::${selector}"
  python3 - "$report" "$selector" <<'PY'
import sys
import xml.etree.ElementTree as ET

report_path, selector = sys.argv[1:]
root = ET.parse(report_path).getroot()
totals = {
    name: sum(int(suite.attrib.get(name, "0")) for suite in root.iter("testsuite"))
    for name in ("tests", "failures", "errors", "skipped")
}
if totals != {"tests": 1, "failures": 0, "errors": 0, "skipped": 0}:
    raise SystemExit(f"exact pytest selector {selector} executed unexpectedly: {totals}")
PY
  rm -f "$report"
  executed_exact_tests=$((executed_exact_tests + 1))
}

run_vitest_exact() {
  local test_path="$1"
  local selector="$2"
  local report
  report="$(mktemp)"
  (
    cd sdk/ts
    npx --no-install vitest run "${test_path#sdk/ts/}" -t "${selector}$" \
      --reporter=json --outputFile="$report"
  )
  node - "$report" "$selector" <<'NODE'
const fs = require("node:fs");
const [reportPath, selector] = process.argv.slice(2);
const report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
const assertions = (report.testResults ?? []).flatMap(
  (result) => result.assertionResults ?? [],
);
const selected = assertions.filter((assertion) => assertion.title === selector);
if (
  report.numPassedTests !== 1 ||
  report.numFailedTests !== 0 ||
  selected.length !== 1 ||
  selected[0].status !== "passed"
) {
  throw new Error(
    `exact Vitest selector ${selector} executed unexpectedly: ` +
      `passed=${report.numPassedTests}, failed=${report.numFailedTests}, ` +
      `selected=${JSON.stringify(selected.map((assertion) => assertion.status))}`,
  );
}
NODE
  rm -f "$report"
  executed_exact_tests=$((executed_exact_tests + 1))
}

run_pytest_exact sdk/python/tests/test_sdk.py test_c2_2b_offline_sdk_preserves_actor_types
run_pytest_exact sdk/python/tests/test_introspection.py test_c2_2b_introspection_sdk_preserves_actor_types
run_pytest_exact sdk/python/tests/test_sdk.py test_c8_2_audience_subject_and_scope_policy
run_pytest_exact sdk/python/tests/test_sdk.py test_c8_3_alg_key_pinning_and_none_rejection
run_pytest_exact sdk/python/tests/test_jwks_cache.py test_c8_4_unknown_kid_refetch_rate_limit_and_negative_cache
run_pytest_exact sdk/python/tests/test_rar.py test_c8_5a_builtin_vocabulary_enforces_all_constraints
run_pytest_exact sdk/python/tests/test_rar_evaluator.py test_c8_5b_policy_evaluator_is_deny_only_and_fail_closed
run_pytest_exact sdk/python/tests/test_sdk.py test_c8_5b_offline_evaluator_runs_only_after_signature_audience_and_scope
run_pytest_exact sdk/python/tests/test_introspection.py test_c8_5b_introspection_evaluator_runs_only_after_active_audience_and_scope
run_pytest_exact sdk/python/tests/test_sdk.py test_c8_8_prm_challenge_is_safe_exact_and_redacted
run_pytest_exact sdk/python/tests/test_sdk.py test_c8_8a_operation_scope_challenges_are_complete
run_pytest_exact sdk/python/tests/test_dpop.py test_c8_9_dpop_proof_binds_request_token_and_nonce
run_pytest_exact sdk/python/tests/test_sdk.py test_c8_10b_offline_sdk_rejects_grant_backed_rar_summary
run_vitest_exact sdk/ts/test/sdk.test.ts c2_2b_offline_sdk_preserves_actor_types
run_vitest_exact sdk/ts/test/introspection.test.ts c2_2b_introspection_sdk_preserves_actor_types
run_vitest_exact sdk/ts/test/sdk.test.ts c8_2_audience_subject_and_scope_policy
run_vitest_exact sdk/ts/test/sdk.test.ts c8_3_alg_key_pinning_and_none_rejection
run_vitest_exact sdk/ts/test/jwks-cache.test.ts c8_4_unknown_kid_refetch_rate_limit_and_negative_cache
run_vitest_exact sdk/ts/test/rar.test.ts c8_5a_builtin_vocabulary_enforces_all_constraints
run_vitest_exact sdk/ts/test/rar_evaluator.test.ts c8_5b_policy_evaluator_is_deny_only_and_fail_closed
run_vitest_exact sdk/ts/test/sdk.test.ts c8_5b_offline_evaluator_runs_only_after_signature_audience_and_scope
run_vitest_exact sdk/ts/test/introspection.test.ts c8_5b_introspection_evaluator_runs_only_after_active_audience_and_scope
run_vitest_exact sdk/ts/test/sdk.test.ts c8_8_prm_challenge_is_safe_exact_and_redacted
run_vitest_exact sdk/ts/test/sdk.test.ts c8_8a_operation_scope_challenges_are_complete
run_vitest_exact sdk/ts/test/dpop.test.ts c8_9_dpop_proof_binds_request_token_and_nonce
run_vitest_exact sdk/ts/test/sdk.test.ts c8_10b_offline_sdk_rejects_grant_backed_rar_summary
run_vitest_exact sdk/ts/test/mcp-interop.test.ts c8_8_and_c8_8a_official_mcp_discovery_and_step_up

expected_exact_tests="$(
  grep -Ec '^run_(pytest|vitest)_exact [^ ]+ [^ ]+$' "$0"
)"
if [[ "$executed_exact_tests" -ne "$expected_exact_tests" ]]; then
  printf 'SDK exact runner executed %s of %s registered selectors\n' \
    "$executed_exact_tests" "$expected_exact_tests" >&2
  exit 1
fi
