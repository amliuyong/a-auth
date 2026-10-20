import { expect, test, type Page } from '@playwright/test';

const issuer = 'https://tenant.example';
const resource = 'https://mcp.example/mcp';
const clients = [
  { client_id: 'cli-current', client_type: 'standard', token_endpoint_auth_method: 'none',
    redirect_uris: ['http://127.0.0.1:8765/callback'], resource_ids: [], introspect_enabled: false },
  { client_id: 'rs-current', client_type: 'standard', token_endpoint_auth_method: 'client_secret_basic',
    redirect_uris: [], resource_ids: [resource], introspect_enabled: true },
  { client_id: 'actor-current', client_type: 'workload', token_endpoint_auth_method: 'none',
    redirect_uris: [], resource_ids: [], introspect_enabled: false },
];

async function setup(page: Page, grants = ['authorization_code', 'refresh_token']) {
  await page.addInitScript(() => sessionStorage.setItem('agent-auth-admin-token', 'test-admin'));
  await page.route('**/admin/session', (route) => route.fulfill({ status: 401 }));
  await page.route('**/admin/overview', (route) => route.fulfill({
    json: { phase: 'P3', issuer, endpoints: [], client_count: 3, active_sessions: 0 },
  }));
  await page.route('**/admin/clients', (route) => route.fulfill({
    json: { clients: clients.map((client) => ({ ...client, client_secret: 'must-not-copy' })), total: 3 },
  }));
  await page.route('**/.well-known/openid-configuration', (route) => route.fulfill({
    json: { issuer, authorization_endpoint: issuer + '/authorize', token_endpoint: issuer + '/token',
      jwks_uri: issuer + '/jwks.json', grant_types_supported: grants,
      code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: ['none'] },
  }));
}

test('onboarding injects selected non-secret tenant configuration and copies a usable config', async ({ page }) => {
  await setup(page);
  await page.goto('/admin?tab=onboarding');
  await expect(page.getByRole('tab', { name: 'Integration guides', exact: true })).toBeVisible();
  await page.getByLabel('Resource server', { exact: true }).click();
  await page.getByText('rs-current', { exact: true }).last().click();
  await page.getByLabel('Agent / CLI client', { exact: true }).click();
  await page.getByText('cli-current', { exact: true }).last().click();
  const code = page.getByTestId('onboarding-config');
  await expect(code).toContainText(issuer);
  await expect(code).toContainText(resource);
  await expect(code).toContainText('cli-current');
  await expect(code).toContainText('http://127.0.0.1:8765/callback');
  await expect(page.getByText('must-not-copy')).toHaveCount(0);
  await page.evaluate(() => {
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: {
      writeText: async (text: string) => { (window as unknown as { copied: string }).copied = text; },
    } });
  });
  await page.getByRole('button', { name: 'Copy configuration', exact: true }).click();
  const copied = await page.evaluate(() => (window as unknown as { copied: string }).copied);
  expect(JSON.parse(copied)).toMatchObject({ issuer, resource, client_id: 'cli-current' });
  expect(copied).not.toContain('must-not-copy');
});
