#!/usr/bin/env bash
set -euo pipefail

script_path="$(realpath "${BASH_SOURCE[0]}")"
cd "$(git rev-parse --show-toplevel)"

executed_exact_tests=0
web_server_log="$(mktemp)"
web_server_pid=""

cleanup() {
  local status=$?
  if [[ -n "$web_server_pid" ]]; then
    kill "$web_server_pid" 2>/dev/null || true
    wait "$web_server_pid" 2>/dev/null || true
  fi
  if [[ "$status" -ne 0 ]]; then
    printf '%s\n' '--- Web server log ---' >&2
    tail -n 200 "$web_server_log" >&2 || true
  fi
  rm -f "$web_server_log"
  exit "$status"
}
trap cleanup EXIT

if [[ ! -f web/dist/index.html ]]; then
  (
    cd web
    npm run build
  )
fi

(
  cd web
  npm run preview -- --host 127.0.0.1 --port 5173 >"$web_server_log" 2>&1
) &
web_server_pid=$!

for _ in {1..120}; do
  if curl --fail --silent http://127.0.0.1:5173/ >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$web_server_pid" 2>/dev/null; then
    printf '%s\n' 'Web server exited before becoming ready' >&2
    exit 1
  fi
  sleep 0.5
done
if ! curl --fail --silent --show-error http://127.0.0.1:5173/ >/dev/null; then
  printf '%s\n' 'Web server did not become ready within 60 seconds' >&2
  exit 1
fi
export PLAYWRIGHT_EXTERNAL_WEB_SERVER=1

run_playwright_exact() {
  local test_path="$1"
  local selector="$2"
  local report
  report="$(mktemp)"
  local playwright_status=0
  (
    cd web
    npx --no-install playwright test "${test_path#web/}" \
      --project=chromium \
      --grep "(^|\\s)${selector}$" \
      --reporter=json >"$report"
  ) || playwright_status=$?
  if [[ "$playwright_status" -ne 0 ]]; then
    node - "$report" "$selector" <<'NODE'
const fs = require("node:fs");
const [reportPath, selector] = process.argv.slice(2);
const raw = fs.readFileSync(reportPath, "utf8");
try {
  const report = JSON.parse(raw);
  const failures = [];
  const collect = (suites) => {
    for (const suite of suites ?? []) {
      for (const spec of suite.specs ?? []) {
        for (const test of spec.tests ?? []) {
          for (const result of test.results ?? []) {
            if (result.status !== "passed") {
              failures.push({
                file: spec.file,
                title: spec.title,
                status: result.status,
                error: result.error,
                errors: result.errors,
              });
            }
          }
        }
      }
      collect(suite.suites);
    }
  };
  collect(report.suites);
  console.error(
    JSON.stringify({ selector, errors: report.errors, failures }, null, 2),
  );
} catch (error) {
  console.error(`invalid Playwright JSON report for ${selector}: ${error}`);
  console.error(raw.slice(-20_000));
}
NODE
    return "$playwright_status"
  fi
  node - "$report" "$selector" <<'NODE'
const fs = require("node:fs");
const [reportPath, selector] = process.argv.slice(2);
const report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
const specs = [];
const collect = (suites) => {
  for (const suite of suites ?? []) {
    specs.push(...(suite.specs ?? []));
    collect(suite.suites);
  }
};
collect(report.suites);
const selected = specs.filter((spec) => spec.title === selector);
const tests = selected.flatMap((spec) => spec.tests ?? []);
const results = tests.flatMap((test) => test.results ?? []);
if (
  specs.length !== 1 ||
  selected.length !== 1 ||
  tests.length !== 1 ||
  tests[0].status !== "expected" ||
  results.length !== 1 ||
  results[0].status !== "passed"
) {
  throw new Error(
    `exact Playwright selector ${selector} executed unexpectedly: ` +
      `reportedSpecs=${specs.length}, selectedSpecs=${selected.length}, ` +
      `tests=${tests.length}, ` +
      `testStatus=${JSON.stringify(tests.map((test) => test.status))}, ` +
      `results=${JSON.stringify(results.map((result) => result.status))}`,
  );
}
NODE
  rm -f "$report"
  executed_exact_tests=$((executed_exact_tests + 1))
}

run_playwright_exact web/e2e/admin-attributes.spec.ts c8_12_namespace_registration_revisioned_lifecycle
run_playwright_exact web/e2e/admin-attributes.spec.ts c8_12_user_attribute_rmw_conflict_and_managed_purge
run_playwright_exact web/e2e/admin-attributes.spec.ts c8_12_federation_mapping_revisioned_crud_uses_active_canonical_targets
run_playwright_exact web/e2e/admin-users.spec.ts c10_23_users_deep_link_reload_and_browser_history
run_playwright_exact web/e2e/admin-users.spec.ts c10_23_invalid_admin_tab_falls_back_to_overview
run_playwright_exact web/e2e/admin-users.spec.ts c10_24_users_show_utc_login_and_never_logged_in
run_playwright_exact web/e2e/admin-users.spec.ts c10_25_users_hide_tombstones_and_persist_status_filters
run_playwright_exact web/e2e/admin-users.spec.ts c10_25_load_more_preserves_selected_status_filter
run_playwright_exact web/e2e/admin-users.spec.ts c10_25_delete_removes_user_from_default_view
run_playwright_exact web/e2e/admin-users.spec.ts c10_25_stale_status_response_cannot_overwrite_current_filter
run_playwright_exact web/e2e/admin-users.spec.ts c10_25_completed_mutation_reloads_latest_status_filter
run_playwright_exact web/e2e/admin-users.spec.ts c9_11_admin_show_once_invitation_survives_until_explicit_discard
run_playwright_exact web/e2e/admin-users.spec.ts c9_11_admin_serializes_concurrent_invitation_regeneration
run_playwright_exact web/e2e/invitation.spec.ts c9_11_invitation_bearer_leaves_history_and_redirects_only_to_account
run_playwright_exact web/e2e/invitation.spec.ts c9_11_failed_invitation_stays_memory_only_for_retry
run_playwright_exact web/e2e/recovery.spec.ts c9_3_recovery_reuses_ambiguous_operation_and_replaces_rejected_one
run_playwright_exact web/e2e/account-credentials.spec.ts c9_3_account_preserves_show_once_codes_until_explicit_discard
run_playwright_exact web/e2e/approve.spec.ts c7b_6_approval_page_shows_requester_and_optional_binding_without_deciding
run_playwright_exact web/e2e/consent.spec.ts c4_8_dynamic_client_is_unverified_and_external_logo_is_never_rendered
run_playwright_exact web/e2e/admin-tables.spec.ts c10_23_clients_deep_link_reload_and_complete_list_search
run_playwright_exact web/e2e/admin-tables.spec.ts c10_24_clients_show_utc_activity_and_never_used
run_playwright_exact web/e2e/admin-sso.spec.ts c12_3_enterprise_sso_navigation
run_playwright_exact web/e2e/admin-sso.spec.ts c12_3_oidc_session_displaces_stale_break_glass
run_playwright_exact web/e2e/admin-sso.spec.ts c12_3_auditor_denied_write_ux
run_playwright_exact web/e2e/account-sessions.spec.ts c12_5_account_lists_revokes_and_keeps_current_login_session
run_playwright_exact web/e2e/account-sessions.spec.ts c12_5_current_login_session_revocation_returns_to_login_gate
run_playwright_exact web/e2e/account-credentials.spec.ts c12_5_passkey_rename_and_password_enrollment
run_playwright_exact web/e2e/account-credentials.spec.ts c12_5_active_password_rotation
run_playwright_exact web/e2e/account-credentials.spec.ts c12_5_last_passkey_removal_requires_replacement_factor
run_playwright_exact web/e2e/account-credentials.spec.ts c12_5_credential_mutation_reauthentication_path
run_playwright_exact web/e2e/account-credentials.spec.ts c12_5_recovery_rotation_lockout_prevention

expected_exact_tests="$(
  grep -Ec '^run_playwright_exact [^ ]+ [^ ]+$' "$script_path"
)"
if [[ "$executed_exact_tests" -ne "$expected_exact_tests" ]]; then
  printf 'Web exact runner executed %s of %s registered selectors\n' \
    "$executed_exact_tests" "$expected_exact_tests" >&2
  exit 1
fi
