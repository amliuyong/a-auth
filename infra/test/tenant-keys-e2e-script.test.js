const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const SCRIPT = fs.readFileSync(
  path.resolve(__dirname, '../../e2e/saas_tenant_keys.sh'),
  'utf8',
);

const helper = SCRIPT.match(
  /status_failure_is_terminal_for_operation\(\) \{[\s\S]*?^\}/m,
)?.[0];
const recovery = SCRIPT.match(
  /best_effort_rollback\(\) \{[\s\S]*?^\}/m,
)?.[0];

function evaluateStatus(status, operation) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'tenant-key-status-'));
  const statusPath = path.join(directory, 'status.json');
  fs.writeFileSync(statusPath, JSON.stringify(status));
  try {
    return spawnSync(
      'bash',
      ['-c', `${helper}\nstatus_failure_is_terminal_for_operation "$1" "$2"`,
        'bash', statusPath, operation],
      { encoding: 'utf8' },
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

test('tenant key gate ignores only historical failures during an active operation', () => {
  assert.ok(helper, 'status failure helper must remain independently testable');

  const active = evaluateStatus({
    lifecycle: 'provisioning',
    operation_id: 'op-current',
    last_failure: 'failure from op-previous',
    last_failure_operation_id: 'op-previous',
  }, 'op-current');
  assert.equal(active.status, 1, active.stderr);

  const queued = evaluateStatus({
    lifecycle: 'ready',
    operation_id: null,
    last_failure: 'failure from op-previous',
    last_failure_operation_id: 'op-previous',
  }, 'op-current');
  assert.equal(queued.status, 1, queued.stderr);

  const failed = evaluateStatus({
    lifecycle: 'ready',
    operation_id: null,
    last_failure: 'failure from op-current',
    last_failure_operation_id: 'op-current',
  }, 'op-current');
  assert.equal(failed.status, 0, failed.stderr);

  const healthy = evaluateStatus({
    lifecycle: 'provisioning',
    operation_id: 'op-current',
    last_failure: null,
  }, 'op-current');
  assert.equal(healthy.status, 1, healthy.stderr);
});

test('interrupted recovery uses operation-scoped failure attribution', () => {
  assert.ok(recovery, 'best-effort recovery function must remain testable');
  assert.match(
    recovery,
    /status_failure_is_terminal_for_operation "\$state" "\$OPERATION_ID"/,
  );
});

test('forward finish requires the persisted forward-retirement outcome', () => {
  assert.match(
    SCRIPT,
    /\.last_completed_outcome == "retired_forward"/,
  );
});
