const assert = require('node:assert/strict');
const test = require('node:test');

const { requireWebBaseUrl } = require('../dist/lib/config');

test('WEB_BASE_URL is required and normalized to an HTTPS origin', () => {
  assert.equal(
    requireWebBaseUrl('WEB_BASE_URL', 'https://example.cloudfront.net/'),
    'https://example.cloudfront.net',
  );
  assert.equal(
    requireWebBaseUrl('WEB_BASE_URL', 'https://auth.example.com'),
    'https://auth.example.com',
  );
  assert.throws(() => requireWebBaseUrl('WEB_BASE_URL', undefined), /is required/);
  assert.throws(
    () => requireWebBaseUrl('WEB_BASE_URL', 'http://auth.example.com'),
    /HTTPS origin/,
  );
});

test('WEB_BASE_URL rejects raw API Gateway and URL paths', () => {
  assert.throws(
    () =>
      requireWebBaseUrl(
        'WEB_BASE_URL',
        'https://example.execute-api.us-east-1.amazonaws.com',
      ),
    /not API Gateway/,
  );
  assert.throws(
    () => requireWebBaseUrl('WEB_BASE_URL', 'https://auth.example.com/login'),
    /without path/,
  );
});
