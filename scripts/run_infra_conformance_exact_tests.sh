#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

executed_exact_tests=0

run_node_exact() {
  local test_path="$1"
  local selector="$2"
  local report
  report="$(mktemp)"
  (
    cd infra
    npm run build >/dev/null
    node --test \
      --test-name-pattern="^${selector}$" \
      --test-reporter=tap \
      "${test_path#infra/}" >"$report"
  )
  node scripts/validate_node_exact_report.cjs "$report" "$selector"
  rm -f "$report"
  executed_exact_tests=$((executed_exact_tests + 1))
}

run_node_exact infra/test/conformance-attributes-config.test.js c8_12_attribute_authority_tables_are_durable_without_ttl
run_node_exact infra/test/frontend-forward-host.test.js c8_1b_forward_host_overwrites_spoofed_viewer_header
run_node_exact infra/test/frontend-api-behavior.test.js c10_9b_interactive_page_behaviors_attach_clickjacking_policy
run_node_exact infra/test/frontend-api-behavior.test.js c10_16_jwks_cloudfront_ttl_matches_frozen_max_age
run_node_exact infra/test/kms-rotation-drill-script.test.js c10_12_emergency_revoke_is_independent_zero_overlap_and_invalidates_jwks
run_node_exact infra/test/tenant-keys-config.test.js c10_13_saas_uses_durable_per_tenant_key_control_plane_without_shared_fallback
run_node_exact infra/test/reclaim-config.test.js c10_5_persistent_identity_tables_are_durable_without_ttl
run_node_exact infra/test/token-runtime-isolation.test.js c3_4_primary_token_runtime_owns_grace_key_and_exact_routes
run_node_exact infra/test/token-runtime-isolation.test.js c3_4_standby_preserves_token_runtime_and_key_boundary
run_node_exact infra/test/invitation-config.test.js c9_11_invitation_uses_independent_encrypted_ttl_table_and_transaction_iam
run_node_exact infra/test/password-config.test.js c9_8_password_credentials_use_persistent_encrypted_non_ttl_table
run_node_exact infra/test/mtls-svid-config.test.js c5_7_mtls_svid_uses_independent_apigw_truststore_and_self_hosted_gate
run_node_exact infra/test/ema-config.test.js c13_1_ema_deployment_requires_and_injects_complete_runtime_configuration
run_node_exact infra/test/multi-region-failover-config.test.js c11_1_primary_replicates_only_durable_authority_and_fence
run_node_exact infra/test/multi-region-failover-config.test.js c11_1_runtime_fence_contract
run_node_exact infra/test/multi-region-failover-config.test.js c11_1_standby_region_local_contract
run_node_exact infra/test/region-failover-drill-script.test.js c11_1_failover_inventory_and_edge_routing_match_current_topology
run_node_exact infra/test/data-governance-drill-script.test.js c11_1_data_governance_drill_tracks_current_region_local_topology
run_node_exact infra/test/admin-output.test.js c12_1_admin_credentials_use_owner_bound_target_secrets
run_node_exact infra/test/dcr-login-config.test.js c12_1_irreversible_credential_migration_is_post_deploy
run_node_exact infra/test/scim-groups-config.test.js c12_3_scim_groups_persistence_and_runtime_ownership
run_node_exact infra/test/admin-sso-config.test.js c12_3_admin_oidc_durable_and_runtime_state_separation
run_node_exact infra/test/security-events-config.test.js c12_6_security_events_have_durable_hot_storage_and_tenant_time_export_index
run_node_exact infra/test/security-events-config.test.js c12_6_archive_worker_is_retryable_idempotent_dead_lettered_and_retained
run_node_exact infra/test/security-events-config.test.js c12_6_archive_iam_retained_logs_metrics_alarms_and_outputs_stay_complete
run_node_exact infra/test/ssf-config.test.js c12_6_ssf_table_is_tenant_partitioned_retained_and_due_indexed
run_node_exact infra/test/ssf-config.test.js c12_6_ssf_worker_consumes_retries_replays_and_is_alarmed
run_node_exact infra/test/data-governance-config.test.js c12_7_governance_authorities_are_retained_protected_global_tables
run_node_exact infra/test/data-governance-config.test.js c12_7_runtime_receives_dedicated_governance_key_and_read_only_suppression
run_node_exact infra/test/data-governance-config.test.js c12_7_durable_worker_advances_jobs_with_append_only_suppression_authority
run_node_exact infra/test/data-governance-config.test.js c12_7_ordinary_backup_excludes_non_rollback_governance_authority
run_node_exact infra/test/data-governance-config.test.js c12_7_background_authority_writers_receive_governance_fence_iam
run_node_exact infra/test/data-governance-config.test.js c12_7_residency_rejects_missing_tenants_and_undeployed_regions
run_node_exact infra/test/disaster-recovery-config.test.js c12_7_production_recovery_retains_safe_authority_and_excludes_replay_state
run_node_exact infra/test/disaster-recovery-config.test.js c12_7_production_recovery_creates_scoped_35_day_daily_backup
run_node_exact infra/test/data-governance-drill-script.test.js c12_7_backup_verification_uses_calculated_35_day_deadline
run_node_exact infra/test/data-governance-drill-script.test.js c12_7_tenant_export_follows_opaque_continuation_cursors
run_node_exact infra/test/data-governance-drill-script.test.js c12_7_offboarding_uses_strong_paginated_live_authority_counts
run_node_exact infra/test/data-governance-drill-script.test.js c12_7_service_evidence_proves_zero_counts_in_every_replica
run_node_exact infra/test/data-governance-drill-script.test.js c12_7_drill_declares_external_retention_exception_boundary
run_node_exact infra/test/data-governance-drill-script.test.js c12_7_secret_cleanup_binds_persisted_ownership_metadata
run_node_exact infra/test/governance-restore-cutover-script.test.js c12_7_restore_verifier_keeps_current_governance_authority
run_node_exact infra/test/governance-restore-cutover-script.test.js c12_7_restore_verifier_is_strong_read_and_mutation_free
run_node_exact infra/test/governance-restore-cutover-script.test.js c12_7_restore_verifier_scans_every_recoverable_business_role
run_node_exact infra/test/governance-restore-cutover-script.test.js c12_7_restore_evidence_is_atomic_and_excludes_key_material
run_node_exact infra/test/governance-restore-cutover-live-script.test.js c12_7_live_cutover_restores_exactly_twelve_roles
run_node_exact infra/test/governance-restore-cutover-live-script.test.js c12_7_live_cutover_binds_deployed_verifier_and_clean_commit
run_node_exact infra/test/governance-restore-cutover-live-script.test.js c12_7_live_cutover_cleanup_binds_receipts_and_target_absence
run_node_exact infra/test/governance-restore-cutover-live-script.test.js c12_7_live_cutover_publishes_only_after_verify_and_cleanup
run_node_exact infra/test/governance-restore-cutover-live-script.test.js c12_7_live_cutover_resume_rejects_context_drift
run_node_exact infra/test/governance-restore-cutover-live-script.test.js c12_7_live_cutover_fails_closed_on_ambiguous_control_plane_state

expected_exact_tests="$(
  grep -Ec '^run_node_exact [^ ]+ [^ ]+$' "$0"
)"
if [[ "$executed_exact_tests" -ne "$expected_exact_tests" ]]; then
  printf 'Infra exact runner executed %s of %s registered selectors\n' \
    "$executed_exact_tests" "$expected_exact_tests" >&2
  exit 1
fi
