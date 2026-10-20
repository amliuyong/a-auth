import { expect, test } from '@playwright/test';

test('template switching preserves trust and secret references and separates checks', async ({ page }) => {
  await page.addInitScript(() => {
    sessionStorage.setItem('agent-auth-admin-token', 'dev-admin-token-not-for-prod');
  });
  await page.route('**/admin/session', (route) => route.fulfill({ status: 401 }));
  await page.route('**/admin/overview', (route) => route.fulfill({
    contentType: 'application/json',
    body: JSON.stringify({ phase: 'P3', issuer: 'https://issuer.example', endpoints: [], client_count: 0, active_sessions: 0 }),
  }));
  await page.route('**/admin/federation', (route) => route.fulfill({
    contentType: 'application/json', body: JSON.stringify({ tenant_id: 'default', idps: [], total: 0 }),
  }));
  await page.goto('/admin?tab=federation');
  await page.getByRole('button', { name: 'Register IdP', exact: true }).click();
  const modal = page.getByRole('dialog');
  await modal.getByLabel('Issuer', { exact: true }).fill('https://idp.example.com/tenant');
  await modal.getByLabel('Client secret reference', { exact: true }).fill('agent-auth/federation/existing');
  await modal.getByLabel('Upstream ACR values trusted as strong (space-separated)', { exact: true }).fill('explicit-approved-acr');
  await modal.getByRole('combobox', { name: 'Provider template', exact: true }).press('ArrowDown');
  await page.getByText('Microsoft Entra ID · v1', { exact: true }).click();
  await expect(modal.getByLabel('Issuer', { exact: true })).toHaveValue('https://idp.example.com/tenant');
  await expect(modal.getByLabel('Client secret reference', { exact: true })).toHaveValue('agent-auth/federation/existing');
  await expect(modal.getByLabel('Upstream ACR values trusted as strong (space-separated)', { exact: true })).toHaveValue('explicit-approved-acr');
  await expect(modal.getByRole('link', { name: 'Official setup guide' })).toHaveAttribute('href', /learn.microsoft.com/);
  await expect(modal.getByText('Actual login: NOT_RUN', { exact: true })).toBeVisible();
});

test('registered-provider diagnostics show unknown network and untested login separately', async ({ page }) => {
  await page.addInitScript(() => sessionStorage.setItem('agent-auth-admin-token', 'dev-admin-token-not-for-prod'));
  await page.route('**/admin/session', (route) => route.fulfill({ status: 401 }));
  await page.route('**/admin/overview', (route) => route.fulfill({
    contentType: 'application/json',
    body: JSON.stringify({ phase: 'P3', issuer: 'https://issuer.example', endpoints: [], client_count: 0, active_sessions: 0 }),
  }));
  await page.route('**/admin/federation', (route) => route.fulfill({
    contentType: 'application/json', body: JSON.stringify({ tenant_id: 't1', idps: [{
      tenant_id: 't1', upstream_idp_id: 'controlled', upstream_issuer: 'https://idp.example.com',
      client_id: 'registered-rp', scopes: ['openid'], strong_acr_values: [],
      authorization_endpoint: 'https://idp.example.com/authorize',
      token_endpoint: 'https://idp.example.com/token', jwks_uri: 'https://idp.example.com/keys',
    }], total: 1 }),
  }));
  let attempts = 0;
  await page.route('**/admin/federation/t1/controlled/checks', (route) => {
    attempts += 1;
    if (attempts > 1) return route.fulfill({ status: 409 });
    return route.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({
        checked_at: 1792514400,
        format: { status: 'PASS', reason: 'valid_format' },
        discovery: { status: 'UNKNOWN', reason: 'network_unavailable' },
        jwks: { status: 'NOT_RUN', reason: 'previous_step_failed' },
        login: { status: 'NOT_RUN', reason: 'real_login_required' },
      }),
    });
  });
  await page.goto('/admin?tab=federation');
  await page.getByRole('button', { name: 'Check provider', exact: true }).click();
  const modal = page.getByRole('dialog');
  await expect(modal.getByText('UNKNOWN', { exact: true })).toBeVisible();
  await expect(modal.getByText('NOT_RUN', { exact: true })).toHaveCount(2);
  await expect(modal.getByText('Network or provider unavailable.', { exact: false })).toBeVisible();
  await expect(modal.getByText('Run a real authorization-code login', { exact: false })).toBeVisible();
  await modal.getByRole('button', { name: 'Close', exact: true }).click();
  await page.getByRole('button', { name: 'Check provider', exact: true }).click();
  await expect(modal.getByText('Configuration changed during checks.', { exact: false })).toBeVisible();
  await expect(modal.getByText('PASS', { exact: true })).toHaveCount(0);
});

test('new provider draft uses the authenticated tenant returned by the server', async ({ page }) => {
  await page.addInitScript(() => sessionStorage.setItem('agent-auth-admin-token', 'dev-admin-token-not-for-prod'));
  await page.route('**/admin/session', (route) => route.fulfill({ status: 401 }));
  await page.route('**/admin/overview', (route) => route.fulfill({
    contentType: 'application/json',
    body: JSON.stringify({ phase: 'P3', issuer: 'https://t1.aws.example.com', endpoints: [], client_count: 0, active_sessions: 0 }),
  }));
  const registrations: unknown[] = [];
  await page.route('**/admin/federation', (route) => {
    if (route.request().method() === 'PUT') {
      registrations.push(route.request().postDataJSON());
      return route.fulfill({ status: 201, contentType: 'application/json', body: '{}' });
    }
    return route.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({ tenant_id: 't1', idps: [], total: 0 }),
    });
  });
  await page.goto('/admin?tab=federation');
  await page.getByRole('button', { name: 'Register IdP', exact: true }).click();
  const modal = page.getByRole('dialog');
  for (const [label, value] of [
    ['IdP ID', 'enterprise'],
    ['Issuer', 'https://idp.example.com/tenant'],
    ['Client ID', 'registered-rp'],
    ['Client secret reference', 'agent-auth/federation/t1/enterprise'],
    ['Authorization endpoint', 'https://idp.example.com/tenant/authorize'],
    ['Token endpoint', 'https://idp.example.com/tenant/token'],
    ['JWKS URI', 'https://idp.example.com/tenant/keys'],
  ]) {
    await modal.getByLabel(label, { exact: true }).fill(value);
  }
  await modal.getByRole('button', { name: 'Save', exact: true }).click();
  await expect.poll(() => registrations.length).toBe(1);
  expect(registrations[0]).toMatchObject({ tenant_id: 't1', upstream_idp_id: 'enterprise', strong_acr_values: [] });
});
