import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import {
  federationTemplates,
  buildFederationDraft,
  inspectFederationMetadata,
} from '../src/federationTemplates.ts';

const input = {
  upstream_idp_id: 'enterprise',
  upstream_issuer: 'https://idp.example.com/tenant',
  client_id: 'registered-rp',
  client_secret_ref: 'agent-auth/federation/enterprise',
  authorization_endpoint: 'https://idp.example.com/tenant/authorize',
  token_endpoint: 'https://idp.example.com/tenant/token',
  jwks_uri: 'https://idp.example.com/tenant/keys',
  scopes: 'openid',
  strong_acr_values: '',
};

test('all three versioned templates produce the existing API configuration shape', () => {
  assert.deepEqual(federationTemplates.map((value) => value.id), ['okta', 'entra', 'oidc']);
  for (const template of federationTemplates) {
    assert.equal(template.version, 1);
    const fixtures = JSON.parse(readFileSync(
      new URL('../../tests/fixtures/federation-templates.json', import.meta.url), 'utf8',
    ));
    const fixture = fixtures.find((value: { template: string }) => value.template === template.id);
    const draft = buildFederationDraft('default', {
      ...fixture.config,
      scopes: fixture.config.scopes.join(' '),
      strong_acr_values: fixture.config.strong_acr_values.join(' '),
    });
    assert.deepEqual(draft, fixture.config);
    assert.equal(template.capabilities.idTokenSigningAlgorithm, 'RS256');
    assert.deepEqual(draft.strong_acr_values, []);
    assert.deepEqual(draft.scopes, ['openid']);
    assert.equal('roles' in draft, false);
    assert.equal('template' in draft, false);
  }
});

test('draft validation names the field and never silently repairs the trust anchor', () => {
  for (const [field, value] of [
    ['client_id', ''],
    ['client_secret_ref', ' '],
    ['upstream_issuer', ' https://idp.example.com'],
    ['authorization_endpoint', 'http://idp.example.com/authorize'],
    ['authorization_endpoint', 'HTTPS://idp.example.com/authorize'],
    ['authorization_endpoint', 'https://@idp.example.com/authorize'],
    ['authorization_endpoint', 'https://idp.example.com/authorize#'],
    ['authorization_endpoint', 'https://idp%2eexample.com/authorize'],
    ['token_endpoint', 'https://user:password@idp.example.com/token'],
    ['token_endpoint', 'https://idp.example.com:8443/token'],
    ['jwks_uri', 'https://127.0.0.1/keys'],
    ['jwks_uri', 'https://169.254.169.254/keys'],
    ['jwks_uri', 'https://function.lambda-url.us-east-1.on.aws/keys'],
    ['jwks_uri', 'https://function.lambda-url.us-east-1.on.aws./keys'],
    ['scopes', 'profile email'],
  ]) {
    assert.throws(() => buildFederationDraft('default', { ...input, [field]: value }),
      (error: unknown) => error instanceof Error && error.message.includes(field));
  }
});

test('discovery inspection binds all configured endpoints and keeps login untested', () => {
  const draft = buildFederationDraft('default', input);
  const metadata = {
    issuer: input.upstream_issuer,
    authorization_endpoint: input.authorization_endpoint,
    token_endpoint: input.token_endpoint,
    jwks_uri: input.jwks_uri,
    response_types_supported: ['code'],
  };
  assert.equal(inspectFederationMetadata(draft, metadata).status, 'PASS');
  for (const field of ['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri']) {
    const result = inspectFederationMetadata(draft, { ...metadata, [field]: 'https://other.example' });
    assert.equal(result.status, 'FAIL');
    assert.equal(result.field, field);
  }
  assert.equal(inspectFederationMetadata(draft, {}).status, 'FAIL');
});
