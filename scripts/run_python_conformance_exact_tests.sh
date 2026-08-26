#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

executed_exact_tests=0

run_unittest_exact() {
  local test_path="$1"
  local test_class="$2"
  local selector="$3"
  local module_name="${test_path%.py}"
  module_name="${module_name//\//.}"

  python3 - "$module_name" "$test_class" "$selector" <<'PY'
import sys
import unittest

module_name, test_class, selector = sys.argv[1:]
test_id = f"{module_name}.{test_class}.{selector}"
loader = unittest.TestLoader()
suite = loader.loadTestsFromName(test_id)
if loader.errors:
    raise SystemExit(
        f"exact unittest selector {test_id} could not be loaded: {loader.errors}"
    )

result = unittest.TextTestRunner(verbosity=2).run(suite)
unexpected = {
    "tests": result.testsRun,
    "failures": len(result.failures),
    "errors": len(result.errors),
    "skipped": len(result.skipped),
    "expected_failures": len(result.expectedFailures),
    "unexpected_successes": len(result.unexpectedSuccesses),
}
if unexpected != {
    "tests": 1,
    "failures": 0,
    "errors": 0,
    "skipped": 0,
    "expected_failures": 0,
    "unexpected_successes": 0,
}:
    raise SystemExit(
        f"exact unittest selector {test_id} executed unexpectedly: {unexpected}"
    )
PY
  executed_exact_tests=$((executed_exact_tests + 1))
}

run_unittest_exact scripts/tests/test_build_conformance_evidence.py BuildConformanceEvidenceCliTests test_combines_suite_results_with_deployment_identity
run_unittest_exact scripts/tests/test_oidf_basic_op_evidence.py OidfBasicOpEvidenceCliTests test_converts_complete_plan_and_preserves_upstream_results
run_unittest_exact scripts/tests/test_oidf_basic_op_evidence.py OidfBasicOpEvidenceCliTests test_fails_closed_on_untrusted_export_origin
run_unittest_exact scripts/tests/test_oidf_basic_op_evidence.py OidfBasicOpEvidenceCliTests test_fails_closed_when_export_signature_is_invalid
run_unittest_exact scripts/tests/test_conformance_gate.py ConformanceGateCliTests test_required_suites_pass_for_the_deployed_issuer
run_unittest_exact scripts/tests/test_conformance_gate.py ConformanceGateCliTests test_required_failure_blocks_and_is_reported
run_unittest_exact scripts/tests/test_conformance_gate.py ConformanceGateCliTests test_approved_unexpired_exception_waives_exact_failure
run_unittest_exact scripts/tests/test_conformance_gate.py ConformanceGateCliTests test_untrusted_or_incomplete_evidence_fails_closed
run_unittest_exact scripts/tests/test_conformance_gate.py ConformanceGateCliTests test_invalid_exception_records_fail_closed
run_unittest_exact scripts/tests/test_release_conformance.py ReleaseConformanceCliTests test_live_preflights_run_before_official_oidf_plan
run_unittest_exact scripts/tests/test_release_conformance.py ReleaseConformanceCliTests test_scheduled_workflow_requires_explicit_enablement
run_unittest_exact scripts/tests/test_release_conformance.py ReleaseConformanceCliTests test_promotion_accepts_exact_unexpired_gate_artifact
run_unittest_exact scripts/tests/test_release_conformance.py ReleaseConformanceCliTests test_promotion_rejects_stale_mismatched_or_overclaimed_artifact
run_unittest_exact scripts/tests/test_release_conformance.py ReleaseConformanceCliTests test_verifies_exception_is_an_open_issue_in_the_repository
run_unittest_exact scripts/tests/test_release_conformance.py ReleaseConformanceCliTests test_continuous_monitor_accepts_fresh_successful_schedule
run_unittest_exact scripts/tests/test_release_conformance.py ReleaseConformanceCliTests test_continuous_monitor_reports_missing_version_skipped_and_stale
run_unittest_exact scripts/tests/test_release_conformance.py ReleaseConformanceCliTests test_continuous_monitor_reports_unavailable_runner
run_unittest_exact scripts/tests/test_release_conformance.py ReleaseConformanceCliTests test_continuous_monitor_reports_missing_schedule
run_unittest_exact scripts/tests/test_release_conformance.py ReleaseConformanceCliTests test_continuous_monitor_creates_and_recovers_tracker_issue
run_unittest_exact scripts/tests/test_release_conformance.py ReleaseConformanceCliTests test_continuous_monitor_workflow_has_narrow_permissions
run_unittest_exact scripts/tests/test_conformance_evidence_map.py ConformanceEvidenceMapTests test_rejects_complete_requirement_without_exact_selector
run_unittest_exact scripts/tests/test_okta_scim_users.py OktaScimUsersHarnessTests test_provision_deprovision_reprovision_and_cleanup
run_unittest_exact scripts/tests/test_okta_scim_users.py OktaScimUsersHarnessTests test_cleanup_failure_prevents_success_evidence
run_unittest_exact scripts/tests/test_okta_scim_users.py OktaScimUsersHarnessTests test_rejects_unsafe_run_id_before_provider_calls
run_unittest_exact scripts/tests/test_okta_scim_users.py OktaScimUsersHarnessTests test_rejects_header_injection_in_secrets_manager_token
run_unittest_exact scripts/tests/test_okta_scim_users.py OktaScimUsersHarnessTests test_refuses_to_delete_a_preexisting_directory_user
run_unittest_exact scripts/tests/test_okta_scim_users.py OktaScimUsersHarnessTests test_refuses_to_overwrite_existing_evidence
run_unittest_exact scripts/tests/test_okta_scim_users.py OktaScimUsersHarnessTests test_create_collision_does_not_delete_an_unconfirmed_user
run_unittest_exact scripts/tests/test_okta_scim_users.py OktaScimUsersHarnessTests test_interrupt_after_create_deletes_confirmed_user_without_evidence
run_unittest_exact scripts/tests/test_okta_scim_users.py OktaScimUsersHarnessTests test_lock_contention_does_not_remove_the_existing_lock
run_unittest_exact scripts/tests/test_governance_restore_cutover_verify.py RestoreVerifierTest test_clean_candidate_passes_with_referential_integrity
run_unittest_exact scripts/tests/test_governance_restore_cutover_verify.py RestoreVerifierTest test_canonical_or_alias_suppression_rejects_restored_user
run_unittest_exact scripts/tests/test_governance_restore_cutover_verify.py RestoreVerifierTest test_tenant_suppression_or_lifecycle_rejects_live_authority
run_unittest_exact scripts/tests/test_governance_restore_cutover_verify.py RestoreVerifierTest test_retained_audit_and_offboarded_key_control_record_are_allowed
run_unittest_exact scripts/tests/test_governance_restore_cutover_verify.py RestoreVerifierTest test_dangling_user_reference_fails_closed
run_unittest_exact scripts/tests/test_governance_restore_cutover_verify.py RestoreVerifierTest test_unknown_suppression_key_version_fails_closed
run_unittest_exact scripts/tests/test_governance_restore_cutover_verify.py RestoreVerifierTest test_unknown_restored_tenant_fails_closed
run_unittest_exact scripts/tests/test_governance_restore_cutover_verify.py RestoreVerifierTest test_admin_transient_and_unknown_rows_fail_closed
run_unittest_exact scripts/tests/test_governance_restore_cutover_verify.py RestoreVerifierTest test_incomplete_scan_is_rejected
run_unittest_exact scripts/tests/test_governance_restore_cutover_verify.py RestoreVerifierTest test_malformed_retained_security_event_fails_closed

expected_exact_tests="$(
  grep -Ec '^run_unittest_exact [^ ]+ [^ ]+ [^ ]+$' "$0"
)"
if [[ "$executed_exact_tests" -ne "$expected_exact_tests" ]]; then
  printf 'Python exact runner executed %s of %s registered selectors\n' \
    "$executed_exact_tests" "$expected_exact_tests" >&2
  exit 1
fi
