import assert from 'node:assert/strict';

function assertExactAdminUrl(expected, candidate, label) {
  assert.equal(candidate.protocol, 'https:', `${label} must use HTTPS`);
  assert.equal(candidate.origin, expected.origin, `${label} changed origin`);
  assert.equal(candidate.pathname, expected.pathname, `${label} changed path`);
  assert.equal(candidate.search, '', `${label} added a query`);
  assert.equal(candidate.hash, '', `${label} added a fragment`);
}

export function assertSafeAdminNavigation(expectedUrl, finalUrl, redirectChain = []) {
  const expected = new URL(expectedUrl);
  assertExactAdminUrl(expected, expected, 'live Admin URL');
  redirectChain.forEach((url, index) => {
    assertExactAdminUrl(expected, new URL(url), `Admin redirect hop ${index + 1}`);
  });
  assertExactAdminUrl(expected, new URL(finalUrl), 'redirected Admin URL');
}
