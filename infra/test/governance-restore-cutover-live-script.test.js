const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const SCRIPT = path.resolve(
  __dirname,
  '../../e2e/governance_restore_cutover_live.sh',
);
const source = fs.readFileSync(SCRIPT, 'utf8');

test('c12_7_live_cutover_restores_exactly_twelve_roles', () => {
  assert.match(
    source,
    /CONFIRM_GOVERNANCE_CUTOVER.*post-offboarding-current-authority/s,
  );
  for (const role of [
    'admin_auth',
    'clients',
    'domain_map',
    'federation_config',
    'grants',
    'passkeys',
    'password_credentials',
    'scim_groups',
    'security_events',
    'tenant_keys',
    'users',
    'workload_trust',
  ]) {
    assert.match(source, new RegExp(`"${role}"`));
  }
  assert.match(source, /length == 12/);
  assert.match(source, /restore-table-to-point-in-time/);
  assert.match(source, /LatestRestorableDateTime/);
  assert.match(source, /\[\.\[\]\.latest_epoch\] \| min/);
});

test('c12_7_live_cutover_binds_deployed_verifier_and_clean_commit', () => {
  assert.match(source, /status --porcelain --untracked-files=normal/);
  assert.match(source, /merge-base --is-ancestor/);
  assert.match(
    source,
    /diff --quiet[\s\S]*governance_restore_cutover_verify\.sh[\s\S]*governance_restore_cutover_verify\.py/,
  );
  assert.match(source, /worktree add --detach/);
  assert.match(
    source,
    /cmp -s[\s\S]*DEPLOYED_TREE\/e2e\/governance_restore_cutover_verify\.sh/,
  );
  assert.match(
    source,
    /RESTORED_AUTHORITY_TABLES_FILE="\$TABLE_MAP"[\s\S]*EVIDENCE_FILE="\$INNER_EVIDENCE\.current"/,
  );
});

test('c12_7_live_cutover_cleanup_binds_receipts_and_target_absence', () => {
  assert.match(source, /expected_target_name/);
  assert.match(source, /RestoreSummary\.SourceTableArn/);
  assert.match(source, /RestoreSummary\.RestoreDateTime/);
  assert.match(source, /\.TableId == \$table_id/);
  assert.match(source, /CreationDateTime/);
  assert.match(source, /restore-intent-/);
  assert.match(source, /restore-receipt-/);
  assert.match(source, /cloudtrail lookup-events/);
  assert.match(source, /multiple CloudTrail restore events match/);
  assert.match(source, /needs explicit ACTION=resolve-absent/);
  assert.match(source, /CONFIRM_AMBIGUOUS_ABSENCE/);
  assert.doesNotMatch(source, /restore-not-accepted-\$role/);
  assert.match(source, /dynamodb delete-table/);
  assert.match(source, /assert_safe_delete "\$target"/);
  assert.match(source, /refusing to delete a table referenced by the current stack/);
  assert.match(source, /set_stack_policy_with_receipt/);
  assert.match(source, /SetStackPolicy did not return a request ID/);
  assert.match(source, /\.requestID == \$request_id/);
  assert.match(source, /concurrent CloudFormation stack-policy changes detected/);
  assert.match(source, /\.restore_pending = true/);
  assert.match(
    source,
    /\.restore_request_id = \$restore_request_id[\s\S]*?verify_single_stack_policy_event/,
  );
  assert.match(source, /\.restore_event_verified = true/);
  assert.match(
    source,
    /if \[\[ "\$restored" == "true" \]\]; then[\s\S]*?return 0/,
  );
  assert.match(source, /stack_freeze_is_active/);
  assert.match(source, /restore_stack_policy/);
  assert.match(source, /ResourceNotFoundException/);
  assert.match(source, /ABSENCE_STABLE_SECS/);
  assert.match(source, /now - absent_since >= ABSENCE_STABLE_SECS/);
  assert.match(source, /ACTION must be run, cleanup, or resolve-absent/);
  assert.match(source, /trap cleanup_process EXIT/);
  assert.match(
    source,
    /if validate_target_provenance "\$role" "\$target"; then[\s\S]*?else\s+target_status=\$\?\s+fi/,
  );
  assert.doesNotMatch(
    source,
    /if validate_target_provenance "\$role" "\$target"; then[\s\S]*?fi\s+target_status=\$\?/,
  );
  assert.match(source, /RESTORED_TABLES_CLEANED=1/);
  assert.match(
    source,
    /if \(\(RESTORED_TABLES_CLEANED == 0\)\)[\s\S]*?cleanup_restored_tables/,
  );
});

test('c12_7_live_cutover_publishes_only_after_verify_and_cleanup', () => {
  const verifier = source.indexOf(
    'jq -e \'.result == "passed"\' "$INNER_EVIDENCE.current"',
  );
  const cleanup = source.indexOf(
    'cleanup_restored_tables ||\n  fail "one or more isolated tables could not be cleaned"',
  );
  const publish = source.indexOf('mv "$FINAL_EVIDENCE.current" "$FINAL_EVIDENCE"');

  assert.ok(verifier > 0);
  assert.ok(cleanup > verifier);
  assert.ok(publish > cleanup);
  assert.match(source, /isolated_tables_cleaned: true/);
  assert.match(source, /account_sha256: \$account_sha256/);
  assert.match(source, /stack_id_sha256: \$stack_id_sha256/);
  assert.match(source, /source_map_sha256: \$source_map_sha256/);
  assert.match(source, /restore_receipts_sha256: \$restore_receipts_sha256/);
  assert.match(source, /deployment_freeze_restored: true/);
  assert.match(source, /stack_policy_state_sha256: \$stack_policy_state_sha256/);
  assert.match(source, /verifier_evidence_sha256/);
  assert.doesNotMatch(source, /account_id: \$ACCOUNT/);
});

test('c12_7_live_cutover_resume_rejects_context_drift', () => {
  assert.match(source, /validate_current_stack_context/);
  assert.match(source, /current stack identity differs/);
  assert.match(source, /current stack deployment differs/);
  assert.match(source, /current authority table set differs/);
  assert.match(source, /current source table identity changed/);
  assert.match(source, /current source table creation changed/);
  assert.match(
    source,
    /stack_business_role_map_from_file/,
  );
  assert.match(source, /with_entries\(\.value = \.value\.table\)/);
  assert.match(
    source,
    /\[\[ "\$\(jq -cS \. <<<"\$current_map"\)" == "\$persisted_map" \]\]/,
  );
});

test('c12_7_live_cutover_fails_closed_on_ambiguous_control_plane_state', () => {
  assert.match(
    source,
    /case "\$target_status" in[\s\S]*?1\) fail "isolated table disappeared[\s\S]*?2\)[\s\S]*?retrying ambiguous table status/,
  );
  assert.match(source, /status remained ambiguous/);
});
