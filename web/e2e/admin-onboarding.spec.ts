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

async function setup(page: Page, grants = ['authorization_code', 'refresh_token'], methods = ['none']) {
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
      code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: methods,
      introspection_endpoint: issuer + '/introspect', device_authorization_endpoint: issuer + '/device_authorization' },
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

async function selectedClients(page: Page) {
  await page.getByLabel('Resource server', { exact: true }).click();
  await page.getByText('rs-current', { exact: true }).last().click();
  await page.getByLabel('Agent / CLI client', { exact: true }).click();
  await page.getByText('cli-current', { exact: true }).last().click();
}

async function scene(page: Page, name: string) {
  await page.getByLabel('Integration', { exact: true }).focus();
  await page.keyboard.press('ArrowDown');
  await page.getByText(name, { exact: true }).last().click();
}

test('only advertised device flow is offered and can run without code-flow capability', async ({ page }) => {
  await setup(page, ['urn:ietf:params:oauth:grant-type:device_code']);
  await page.goto('/admin?tab=onboarding');
  await selectedClients(page);
  await scene(page, 'Agent / CLI');
  await expect(page.getByText(/does not advertise public Authorization Code/)).toBeVisible();
  await expect(page.getByTestId('onboarding-config')).toHaveCount(0);
  await page.getByLabel('Authorization flow', { exact: true }).focus();
  await page.keyboard.press('ArrowDown');
  await page.getByText('Device flow', { exact: true }).last().click();
  await expect(page.getByTestId('onboarding-config')).toContainText('"authorization_flow": "device"');
  await expect(page.getByText(/Device flow is advertised/)).toBeVisible();
});

test('unadvertised device/workload and invalid resource do not produce runnable configuration', async ({ page }) => {
  await setup(page);
  await page.goto('/admin?tab=onboarding');
  await selectedClients(page);
  await scene(page, 'Agent / CLI');
  await expect(page.getByText(/Device flow is not advertised/)).toBeVisible();
  await page.getByLabel('Resource identifier (HTTPS)', { exact: true }).fill('http://insecure.example/mcp');
  await expect(page.getByTestId('onboarding-config')).toHaveCount(0);
  await scene(page, 'Workload on behalf of a user');
  await expect(page.getByText(/Required workload OIDC.*unavailable/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Copy configuration' })).toHaveCount(0);
});

test('Lambda Function URL cannot produce a runnable onboarding configuration', async ({ page }) => {
  await setup(page);
  await page.goto('/admin?tab=onboarding');
  await selectedClients(page);
  await page.getByLabel('Resource identifier (HTTPS)', { exact: true })
    .fill('https://unused.lambda-url.us-east-1.on.aws./mcp');
  await expect(page.getByTestId('onboarding-config')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Copy configuration' })).toHaveCount(0);
});

for (const status of [401, 403, 503]) {
  test(`reload ${status} clears copied tenant configuration`, async ({ page }) => {
    await setup(page);
    await page.goto('/admin?tab=onboarding');
    await selectedClients(page);
    await expect(page.getByTestId('onboarding-config')).toBeVisible();
    await page.route('**/admin/clients', (route) => route.fulfill({ status }));
    await page.getByRole('button', { name: 'Reload configuration', exact: true }).click();
    await expect(page.getByTestId('onboarding-config')).toHaveCount(0);
    if (status === 401) await expect(page.getByLabel('Admin token', { exact: true })).toBeVisible();
    else await expect(page.getByRole('alert')).toContainText(status === 403
      ? 'Admin read permission required' : 'Could not load current tenant configuration');
  });
}

test('issuer mismatch fails closed instead of combining configurations from different tenants', async ({ page }) => {
  await setup(page);
  await page.route('**/.well-known/openid-configuration', (route) => route.fulfill({
    json: { issuer: 'https://other-tenant.example' },
  }));
  await page.goto('/admin?tab=onboarding');
  await expect(page.getByRole('alert')).toContainText('Could not load current tenant configuration');
  await expect(page.getByTestId('onboarding-config')).toHaveCount(0);
});

test('workload requires matching tenant/actor OIDC trust and ignores an obsolete response', async ({ page }) => {
  await setup(page, ['authorization_code', 'urn:ietf:params:oauth:grant-type:token-exchange'], ['none', 'workload_oidc_jwt']);
  let release: (() => void) | undefined;
  await page.route('**/admin/workload-trust/**', async (route) => {
    const tenant = new URL(route.request().url()).pathname.split('/').at(-1);
    if (tenant === 'old-tenant') {
      await new Promise<void>((resolve) => { release = resolve; });
    }
    await route.fulfill({ json: { total: 1, bindings: [{
      tenant_id: tenant, mechanism: 'oidc', mapped_client_id: 'actor-current',
      subject_pattern: 'exact-platform-subject', trust_anchor: 'https://platform.example',
    }] } });
  });
  await page.goto('/admin?tab=onboarding');
  await selectedClients(page);
  await scene(page, 'Workload on behalf of a user');
  await page.getByLabel('Workload actor', { exact: true }).click();
  await page.getByText('actor-current', { exact: true }).last().click();
  await page.getByLabel('Your tenant identifier', { exact: true }).fill('old-tenant');
  await page.getByRole('button', { name: 'Check existing OIDC trust', exact: true }).click();
  await expect.poll(() => !!release).toBe(true);
  await page.getByLabel('Your tenant identifier', { exact: true }).fill('current-tenant');
  const oldResponse = page.waitForResponse('**/admin/workload-trust/old-tenant');
  release!();
  await oldResponse;
  await page.evaluate(() => new Promise<void>((resolve) =>
    requestAnimationFrame(() => requestAnimationFrame(() => resolve())),
  ));
  await expect(page.getByTestId('onboarding-config')).toHaveCount(0);
  await page.getByRole('button', { name: 'Check existing OIDC trust', exact: true }).click();
  await expect(page.getByTestId('onboarding-config')).toContainText('"workload_actor": "actor-current"');
  await expect(page.getByTestId('onboarding-config')).toContainText('"online": true');
  await expect(page.getByRole('button', { name: 'Check existing OIDC trust', exact: true }))
    .toHaveAttribute('aria-busy', 'false');
  await expect(page.getByText(/separately consent to delegation/)).toBeVisible();
  await page.route('**/admin/workload-trust/**', (route) => route.fulfill({ json: { total: 1, bindings: [{
    tenant_id: 'foreign-tenant', mechanism: 'oidc', mapped_client_id: 'actor-current',
    subject_pattern: 'wrong', trust_anchor: 'https://platform.example',
  }] } }));
  await page.getByRole('button', { name: 'Check existing OIDC trust', exact: true }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'Could not read tenant trust bindings' })).toBeVisible();
  await expect(page.getByTestId('onboarding-config')).toHaveCount(0);
});

test('Chinese mobile preserves selected configuration, contains overflow and explains clipboard failure', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await setup(page);
  await page.goto('/admin?tab=onboarding');
  await selectedClients(page);
  const before = await page.getByTestId('onboarding-config').textContent();
  await page.getByRole('banner').getByRole('button', { name: /中\s*文/ }).click();
  await expect(page.getByRole('tabpanel', { name: '场景接入指南', exact: true })).toBeVisible();
  await expect(page.getByTestId('onboarding-config')).toHaveText(before!);
  expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(1);
  await page.evaluate(() => Object.defineProperty(navigator, 'clipboard', {
    configurable: true, value: { writeText: async () => { throw new Error('Unavailable'); } },
  }));
  await page.getByRole('button', { name: '复制配置', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('剪贴板不可用');
});
