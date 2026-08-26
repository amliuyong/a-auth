import assert from 'node:assert/strict';
import test from 'node:test';
import { adminStepUpPath } from '../src/adminStepUp.ts';

test('RFC 9470 challenge becomes an Admin SSO step-up URL', () => {
  assert.equal(
    adminStepUpPath(
      'Bearer error="insufficient_user_authentication", ' +
        'error_description="A different authentication level is required", ' +
        'acr_values="urn:agent-auth:assurance:strong", max_age="300"',
    ),
    '/admin/sso/start?acr_values=urn%3Aagent-auth%3Aassurance%3Astrong&max_age=300',
  );
});

test('ordinary bearer failures do not trigger Admin SSO', () => {
  assert.equal(adminStepUpPath(null), null);
  assert.equal(adminStepUpPath('Bearer error="invalid_token"'), null);
  assert.equal(
    adminStepUpPath('Bearer error="insufficient_user_authentication"'),
    null,
  );
});
