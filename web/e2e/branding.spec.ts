import { expect, test, type Page } from '@playwright/test';
import type { components } from '../src/api/schema';

async function mockAdmin(page: Page) {
  await page.addInitScript(() => sessionStorage.setItem('agent-auth-admin-token', 'test-admin'));
  await page.route('**/admin/session', (route) => route.fulfill({ status: 401 }));
  await page.route('**/admin/overview', (route) => route.fulfill({
    json: { phase: 'P3', issuer: 'https://issuer.example', endpoints: [], client_count: 0, active_sessions: 0 },
  }));
}

const stored: components['schemas']['AdminBrandingView'] = {
  status: 'ready', version: 1, revision: 4, can_manage: true,
  settings: { name: 'Demo Brand', logo: 'shield', primary: 'teal' },
};

async function expectReadableBrandHeader(page: Page) {
  const contrast = await page.getByRole('banner').evaluate((header) => {
    const text = header.querySelector('.ant-typography')!;
    const luminance = (color: string) => {
      const channels = color.match(/\d+/g)!.slice(0, 3).map((channel) => {
        const value = Number(channel) / 255;
        return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
      });
      return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
    };
    const foreground = luminance(getComputedStyle(text).color);
    const background = luminance(getComputedStyle(header).backgroundColor);
    return (Math.max(foreground, background) + 0.05) / (Math.min(foreground, background) + 0.05);
  });
  expect(contrast).toBeGreaterThanOrEqual(4.5);
}

test('a stored brand is rendered on the real login page without changing login controls', async ({ page }) => {
  await page.route('**/ui/branding', (route) => route.fulfill({
    json: {
      status: 'ready', version: 1, revision: 4,
      settings: { name: 'Demo Brand', logo: 'shield', primary: 'teal' },
    },
  }));
  await page.goto('/login');
  await expect(page.getByRole('banner')).toContainText('Demo Brand');
  await expectReadableBrandHeader(page);
  await expect(page.getByLabel('Email address', { exact: true })).toBeEnabled();
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeEnabled();
});

for (const language of ['en', 'zh']) {
  test(`${language} login retains edits and keyboard password visibility after delayed branding`, async ({ page }) => {
    await page.addInitScript((value) => localStorage.setItem('agent-auth-lang', value), language);
    let releaseBranding!: () => void;
    const brandingResponse = new Promise<void>((resolve) => { releaseBranding = resolve; });
    await page.route('**/ui/branding', async (route) => {
      await brandingResponse;
      await route.fulfill({ json: { status: 'ready', version: 1, revision: 1,
        settings: { name: 'Delayed Brand', logo: 'shield', primary: 'teal' } } });
    });
    let loginBody: unknown;
    await page.route('**/login/password', async (route) => {
      loginBody = route.request().postDataJSON();
      await route.fulfill({ json: { authenticated: true, password_change_required: false } });
    });
    await page.route('**/authorize?*', (route) => route.fulfill({ body: 'continued' }));
    await page.goto('/login?client_id=web-client');
    const email = page.locator('#agent-auth-login-email');
    const password = page.locator('#agent-auth-login-password');
    await email.fill('oidf-user@example.com');
    await password.fill('Replaceable password 123!');
    releaseBranding();
    await expect(page.getByRole('banner')).toContainText('Delayed Brand');
    await expect(email).toHaveValue('oidf-user@example.com');
    await expect(password).toHaveValue('Replaceable password 123!');
    const show = page.getByRole('button', { name: language === 'en' ? 'Show password' : '显示密码', exact: true });
    await show.focus();
    await page.keyboard.press('Space');
    await expect(password).toHaveAttribute('type', 'text');
    await expect(password).toHaveValue('Replaceable password 123!');
    await page.getByRole('button', { name: language === 'en' ? 'Hide password' : '隐藏密码', exact: true }).focus();
    await page.keyboard.press('Enter');
    await expect(password).toHaveAttribute('type', 'password');
    await expect(password).toHaveValue('Replaceable password 123!');
    await page.locator('#agent-auth-login-submit').click();
    await page.waitForURL(/\/authorize\?client_id=web-client$/);
    expect(loginBody).toEqual({ email: 'oidf-user@example.com', password: 'Replaceable password 123!',
      authorize_query: 'client_id=web-client' });
  });
}

for (const language of ['en', 'zh']) {
  test(`mobile ${language} consent retains long authority facts and escapes the brand name`, async ({ page }) => {
    await page.setViewportSize({ width: 360, height: 800 });
    await page.addInitScript((value) => localStorage.setItem('agent-auth-lang', value), language);
    const name = '<script>window.__brandInjected=1</script>';
    const actor = `server-validated-${'actor'.repeat(35)}`;
    const resource = `https://resource.example/${'segment'.repeat(30)}`;
    const scope = `records:read:${'x'.repeat(90)}`;
    const subset = `reports/${'record'.repeat(35)}`;
    await page.route('**/ui/branding', (route) => route.fulfill({
      json: { status: 'ready', version: 1, revision: 1,
        settings: { name, logo: 'key', primary: 'violet' } },
    }));
    await page.route('**/consent/context?*', (route) => route.fulfill({
      json: {
        client_id: 'synthetic-client', client_name: 'Synthetic application', client_source: 'registered',
        csrf_token: 'synthetic-csrf', scopes: [scope], resources: [resource], workload_actor: actor,
        authorization_details: [
          { type: 'agent_auth_rar_v1', locations: [resource], resource_subset: [subset], max_records: 777 },
          { type: 'agent_auth_payment_v1', intent_id: 'synthetic-intent', terms_digest: 'synthetic-terms' },
        ],
        payment: {
          actor, amount_minor: '12345', currency: 'USD', currency_exponent: 2,
          execute_before: 1893456000, intent_id: 'synthetic-intent', order_id: 'synthetic-order',
          resource, terms_digest: 'synthetic-terms',
          funding_source: { id: 'synthetic-funding', version: 1, label: 'Synthetic account' },
          payee: { id: 'synthetic-payee', version: 1, name: 'Synthetic Payee' },
        },
      },
    }));
    await page.goto('/consent?client_id=synthetic-client' +
      '&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback' +
      '&resource=https%3A%2F%2Funvalidated-query-resource.example' +
      '&workload_actor=unvalidated-query-actor');
    await expect(page.getByRole('banner')).toContainText(name);
    await expectReadableBrandHeader(page);
    await expect(page.locator('script').filter({ hasText: '__brandInjected' })).toHaveCount(0);
    expect(await page.evaluate(() => '__brandInjected' in window)).toBe(false);
    for (const fact of [
      actor, resource, scope, subset, '777', '123.45 USD', 'Synthetic Payee',
      'Synthetic account', 'synthetic-order', 'synthetic-intent',
    ]) {
      await expect(page.getByText(fact, { exact: true }).first()).toBeVisible();
    }
    await expect(page.locator('time')).toHaveAttribute('datetime', '2030-01-01T00:00:00.000Z');
    await expect(page.getByText('unvalidated-query-actor', { exact: true })).toHaveCount(0);
    await expect(page.getByText('https://unvalidated-query-resource.example', { exact: true })).toHaveCount(0);
    await expect(page.locator('#agent-auth-consent-approve')).toBeEnabled();
    await expect(page.locator('#agent-auth-consent-deny')).toBeEnabled();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(360);
  });
}

test('an owner can preview synthetic consent without performing an authorization action', async ({ page }, testInfo) => {
  await mockAdmin(page);
  await page.route('**/admin/branding', (route) => route.fulfill({ json: stored }));
  const actions: string[] = [];
  page.on('request', (request) => {
    if (/\/(?:consent\/|login\/|token(?:\?|$)|authorize(?:\?|$))/.test(new URL(request.url()).pathname)) {
      actions.push(request.url());
    }
  });
  await page.goto('/admin?tab=branding');
  await expect(page.getByRole('tab', { name: 'Branding', exact: true })).toBeVisible();
  await page.getByLabel('Display name', { exact: true }).fill('Preview Brand');
  const preview = page.getByTestId('branding-preview');
  await expect(preview.locator('#agent-auth-login-email')).toBeDisabled();
  await expect(preview.locator('#agent-auth-login-password')).toBeDisabled();
  await expect(preview.getByRole('button', { name: 'Show password', exact: true })).toBeDisabled();
  await expect(preview.getByRole('button', { name: 'Sign in', exact: true })).toBeDisabled();
  await expect(preview.locator('#agent-auth-login-ready')).toHaveCount(0);
  await page.getByRole('radio', { name: 'Consent', exact: true }).check();
  await expect(preview.getByText('Preview Brand', { exact: true })).toBeVisible();
  await expect(preview).toContainText('https://resource.example/mcp');
  await expect(preview).toContainText('synthetic-workload');
  await expect(preview).toContainText('Synthetic Payee');
  await expect(preview.getByRole('button', { name: 'Approve', exact: true })).toBeDisabled();
  await expect(preview.getByRole('button', { name: 'Deny', exact: true })).toBeDisabled();
  await expect(preview.locator('#agent-auth-consent-ready')).toHaveCount(0);
  const savedLanguage = await page.evaluate(() => localStorage.getItem('agent-auth-lang'));
  await page.getByRole('radio', { name: 'Mobile', exact: true }).check();
  await page.getByRole('combobox', { name: 'Preview language', exact: true }).focus();
  await page.keyboard.press('ArrowDown');
  await page.getByText('中文', { exact: true }).last().click();
  await expect(preview.getByRole('heading', { name: '授权访问', exact: true })).toBeVisible();
  await expect(page.getByRole('tab', { name: 'Branding', exact: true })).toBeVisible();
  expect(await page.evaluate(() => localStorage.getItem('agent-auth-lang'))).toBe(savedLanguage);
  expect((await preview.boundingBox())?.width).toBe(360);
  await expect(preview).toContainText('synthetic-workload');
  await expect(preview).toContainText('Synthetic Payee');
  await page.keyboard.press('Escape');
  await expect(page.locator('.ant-select-dropdown:visible')).toHaveCount(0);
  await preview.screenshot({ path: testInfo.outputPath('consent-mobile-zh.png') });
  expect(actions).toEqual([]);
});

test('saving and restoring defaults use the last verified revision and survive reload', async ({ page }) => {
  await mockAdmin(page);
  let current = structuredClone(stored);
  const writes: unknown[] = [];
  await page.route('**/admin/branding', async (route) => {
    if (route.request().method() === 'PUT') {
      const body = route.request().postDataJSON();
      writes.push(body);
      current = { ...current, revision: current.revision + 1, settings: body.settings };
    }
    await route.fulfill({ json: current });
  });
  await page.route('**/admin/branding/reset', async (route) => {
    writes.push(route.request().postDataJSON());
    current = { ...current, revision: current.revision + 1,
      settings: { name: null, logo: 'none', primary: 'blue' } };
    await route.fulfill({ json: current });
  });
  await page.goto('/admin?tab=branding');
  await page.getByLabel('Display name', { exact: true }).fill('Saved Brand');
  await page.getByRole('button', { name: 'Save branding', exact: true }).click();
  await expect(page.getByText('Branding saved.', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Restore defaults', exact: true }).click();
  await expect(page.getByLabel('Display name', { exact: true })).toHaveValue('');
  expect(writes).toEqual([
    { expected_revision: 4, settings: { name: 'Saved Brand', logo: 'shield', primary: 'teal' } },
    { expected_revision: 5 },
  ]);
  await page.reload();
  await expect(page.getByLabel('Display name', { exact: true })).toHaveValue('');
  await expect(page.getByTestId('branding-preview').getByText('Agent Auth', { exact: true })).toBeVisible();
});

test('read-only administrators can preview but cannot save or restore defaults', async ({ page }) => {
  await mockAdmin(page);
  const writes: string[] = [];
  await page.route('**/admin/branding**', async (route) => {
    if (route.request().method() !== 'GET') writes.push(route.request().method());
    await route.fulfill({ json: { ...stored, can_manage: false } });
  });
  await page.goto('/admin?tab=branding');
  await page.getByLabel('Display name', { exact: true }).fill('Local Preview');
  await expect(page.getByTestId('branding-preview').getByText('Local Preview', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Save branding', exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Restore defaults', exact: true })).toBeDisabled();
  expect(writes).toEqual([]);
});

for (const status of ['unsupported_deployment', 'unsupported_version']) {
  test(`${status} offers no editor or preview`, async ({ page }) => {
    await mockAdmin(page);
    await page.route('**/admin/branding', (route) => route.fulfill({
      json: { ...stored, status, version: status === 'unsupported_version' ? 2 : 1, can_manage: false },
    }));
    await page.goto('/admin?tab=branding');
    await expect(page.getByText(status === 'unsupported_deployment'
      ? 'Deployment branding is not supported in SaaS mode.'
      : 'These settings use a newer version. This application cannot edit or preview them.')).toBeVisible();
    await expect(page.getByLabel('Display name', { exact: true })).toHaveCount(0);
    await expect(page.getByTestId('branding-preview')).toHaveCount(0);
  });
}

test('a conflicting save requires fresh readback before editing again', async ({ page }) => {
  await mockAdmin(page);
  let writes = 0;
  await page.route('**/admin/branding', (route) => {
    if (route.request().method() === 'PUT') {
      writes += 1;
      return route.fulfill({ status: 409, json: { error: 'must-not-display-raw-response' } });
    }
    return route.fulfill({ json: stored });
  });
  await page.goto('/admin?tab=branding');
  await page.getByLabel('Display name', { exact: true }).fill('Stale Draft');
  await page.getByRole('button', { name: 'Save branding', exact: true }).click();
  await expect(page.getByText('Settings changed in another editor. Reload current settings before editing again.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Save branding', exact: true })).toHaveCount(0);
  await expect(page.getByText('must-not-display-raw-response')).toHaveCount(0);
  expect(writes).toBe(1);
  await page.getByRole('button', { name: 'Reload current settings', exact: true }).click();
  await expect(page.getByLabel('Display name', { exact: true })).toHaveValue('Demo Brand');
  expect(writes).toBe(1);
});

for (const [name, status, body] of [
  ['unavailable', 503, { error: 'must-not-display-raw-response' }],
  ['external logo', 200, { ...stored,
    settings: { ...stored.settings, logo: 'https://images.example/untrusted.svg' } }],
  ['directional control', 200, { ...stored,
    settings: { ...stored.settings, name: 'hidden\u061cfacts' } }],
] as const) {
  test(`${name} branding falls back without blocking real login`, async ({ page }) => {
    const externalRequests: string[] = [];
    await page.route('https://images.example/**', (route) => {
      externalRequests.push(route.request().url());
      return route.abort();
    });
    await page.route('**/ui/branding', (route) => route.fulfill({ status, json: body }));
    await page.goto('/login');
    await expect(page.getByRole('banner')).toContainText('Agent Auth');
    await expectReadableBrandHeader(page);
    await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeEnabled();
    await expect(page.getByText('must-not-display-raw-response')).toHaveCount(0);
    await expect(page.getByText('hidden\u061cfacts')).toHaveCount(0);
    expect(externalRequests).toEqual([]);
  });
}
