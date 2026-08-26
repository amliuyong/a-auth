import assert from 'node:assert/strict';
import test from 'node:test';
import {
  AdminProbeError,
  classifyControlProbe,
  classifyTenantProbe,
} from '../src/adminProbe.ts';

test('tenant probe only falls through to control for mutually exclusive auth misses', () => {
  assert.equal(classifyTenantProbe(200), 'tenant');
  assert.equal(classifyTenantProbe(401), 'probe-control');
  assert.equal(classifyTenantProbe(404), 'probe-control');

  for (const status of [400, 403, 429, 500]) {
    assert.throws(
      () => classifyTenantProbe(status),
      (error) => error instanceof AdminProbeError && error.status === status,
    );
  }
});

test('control probe distinguishes control mode, auth misses, and service failures', () => {
  assert.equal(classifyControlProbe(200), 'control');
  assert.equal(classifyControlProbe(503), 'control');
  assert.equal(classifyControlProbe(401), null);
  assert.equal(classifyControlProbe(404), null);

  for (const status of [400, 403, 429, 500]) {
    assert.throws(
      () => classifyControlProbe(status),
      (error) => error instanceof AdminProbeError && error.status === status,
    );
  }
});
