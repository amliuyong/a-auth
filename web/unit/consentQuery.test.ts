import assert from 'node:assert/strict';
import test from 'node:test';
import { consentContextQuery } from '../src/consentQuery.ts';

test('consent context query preserves every supported authorize field', () => {
  const authorizationDetails = JSON.stringify([
    { type: 'data_access', resource_subset: ['reports/2026'] },
  ]);
  const query = new URLSearchParams({
    client_id: 'registered-client',
    redirect_uri: 'https://client.example/callback',
    scope: 'openid profile',
    state: 'opaque state',
    code_challenge: 'challenge',
    code_challenge_method: 'S256',
    authorization_details: authorizationDetails,
    authz_session_id: 'session-1',
    cimd_digest: 'digest-1',
    cimd_binding: 'binding-1',
  });
  query.append('resource', 'https://resource-a.example');
  query.append('resource', 'https://resource-b.example');

  assert.deepEqual(consentContextQuery(query.toString()), {
    client_id: 'registered-client',
    redirect_uri: 'https://client.example/callback',
    scope: 'openid profile',
    resource: ['https://resource-a.example', 'https://resource-b.example'],
    state: 'opaque state',
    code_challenge: 'challenge',
    code_challenge_method: 'S256',
    authorization_details: authorizationDetails,
    authz_session_id: 'session-1',
    cimd_digest: 'digest-1',
    cimd_binding: 'binding-1',
  });
});

test('consent context query rejects missing required authorize fields', () => {
  assert.equal(consentContextQuery('redirect_uri=https%3A%2F%2Fclient.example%2Fcallback'), null);
  assert.equal(consentContextQuery('client_id=registered-client'), null);
});

test('consent context query rejects duplicate singleton fields', () => {
  assert.equal(
    consentContextQuery(
      'client_id=displayed-client&client_id=signed-client' +
        '&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback',
    ),
    null,
  );
  assert.equal(
    consentContextQuery(
      'client_id=registered-client&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback' +
        '&scope=openid&scope=openid%20admin',
    ),
    null,
  );
});
