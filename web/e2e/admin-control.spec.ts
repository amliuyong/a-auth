import { expect, test, type Page } from '@playwright/test';

const PLATFORM_TOKEN = 'platform-admin-secret';
const T1_ARN =
  'arn:aws:secretsmanager:us-east-1:123456789012:secret:agent-auth/saas/tenant/t1/admin-token-AbCdEf';
const T2_ARN =
  'arn:aws:secretsmanager:us-east-1:123456789012:secret:agent-auth/saas/tenant/t2/admin-token-GhIjKl';
const ADMIN_VIEWPORTS = [
  { name: 'desktop', viewport: null },
  { name: 'mobile', viewport: { width: 390, height: 844 } },
] as const;
const PROBE_SETTLE_MS = 500;

async function mockControl(page: Page) {
  await page.route('**/admin/overview', (route) =>
    route.fulfill({
      status: 401,
      contentType: 'application/json',
      body: JSON.stringify({ status: 401, message: 'admin auth required' }),
    }),
  );
  await page.route('**/admin/control/tenants', (route) => {
    expect(route.request().headers().authorization).toBe(`Bearer ${PLATFORM_TOKEN}`);
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        tenants: [
          {
            tenant_id: 't1',
            issuer: 'https://t1.saas.example.com',
            admin_url: 'https://t1.saas.example.com/admin',
            admin_secret_arn: T1_ARN,
          },
          {
            tenant_id: 't2',
            issuer: 'https://t2.saas.example.com',
            admin_url: 'https://t2.saas.example.com/admin',
            admin_secret_arn: T2_ARN,
          },
        ],
      }),
    });
  });
}

test('platform login opens a read-only tenant directory', async ({ page }) => {
  await mockControl(page);
  await page.goto('/admin');
  await page.getByLabel(/admin token/i).fill(PLATFORM_TOKEN);
  await page.getByRole('button', { name: /connect|连接/i }).click();

  await expect(page.getByRole('heading', { name: /tenants|租户/i })).toBeVisible();
  await expect(page.getByText('t1', { exact: true })).toBeVisible();
  await expect(page.getByText('t2', { exact: true })).toBeVisible();
  await expect(page.getByText(T1_ARN, { exact: true })).toBeVisible();
  await expect(page.getByText(T2_ARN, { exact: true })).toBeVisible();
  await expect(page.getByRole('tab')).toHaveCount(0);
  await expect(page.getByRole('button', { name: /edit|delete|create|编辑|删除|创建/i })).toHaveCount(0);
  await expect(page.getByRole('button', { name: /copy|复制/i })).toHaveCount(2);
  await expect(page.locator('body')).not.toContainText(PLATFORM_TOKEN);
});

for (const scenario of ADMIN_VIEWPORTS) {
  test(`${scenario.name} tenant login stops after the tenant probe and never enters control mode`, async ({ page }) => {
    if (scenario.viewport) await page.setViewportSize(scenario.viewport);
    let controlRequests = 0;
    await page.route('**/admin/overview', (route) => {
      expect(route.request().headers().authorization).toBe('Bearer t1-admin-secret');
      return route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          phase: 'P3',
          issuer: 'https://t1.saas.example.com',
          endpoints: [],
          client_count: 0,
          active_sessions: 0,
        }),
      });
    });
    await page.route('**/admin/control/tenants', (route) => {
      controlRequests += 1;
      return route.fulfill({ status: 500, contentType: 'application/json', body: '{}' });
    });

    await page.goto('/admin');
    await page.getByLabel(/admin token/i).fill('t1-admin-secret');
    await page.getByRole('button', { name: /connect|连接/i }).click();

    await expect(page.getByRole('tab', { name: /dashboard|overview|仪表盘|概览/i })).toBeVisible();
    await expect(page.getByRole('heading', { name: /tenants|租户/i })).toHaveCount(0);
    await page.waitForTimeout(PROBE_SETTLE_MS);
    expect(controlRequests).toBe(0);
  });
}

for (const scenario of ADMIN_VIEWPORTS) {
  test(`${scenario.name} tenant credential rejected by the control host does not fall back to either mode`, async ({ page }) => {
    if (scenario.viewport) await page.setViewportSize(scenario.viewport);
    let overviewRequests = 0;
    let controlRequests = 0;
    await page.route('**/admin/overview', (route) => {
      overviewRequests += 1;
      return route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({ status: 401, message: 'admin auth required' }),
      });
    });
    await page.route('**/admin/control/tenants', (route) => {
      controlRequests += 1;
      return route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({ status: 401, message: 'admin auth required' }),
      });
    });

    await page.goto('/admin');
    await page.getByLabel(/admin token/i).fill('t1-admin-secret');
    await page.getByRole('button', { name: /connect|连接/i }).click();

    await expect(page.getByText(/token rejected|token 被拒绝/i)).toBeVisible();
    await expect(page.getByLabel(/admin token/i)).toBeVisible();
    await expect(page.getByRole('tab')).toHaveCount(0);
    await expect(page.getByRole('heading', { name: /tenants|租户/i })).toHaveCount(0);
    await page.waitForTimeout(PROBE_SETTLE_MS);
    expect(overviewRequests).toBe(1);
    expect(controlRequests).toBe(1);
  });
}

test('admin host failure is not mislabeled as a rejected token', async ({ page }) => {
  let controlRequests = 0;
  await page.route('**/admin/overview', (route) =>
    route.fulfill({
      status: 400,
      contentType: 'application/json',
      body: JSON.stringify({ status: 400, message: 'bad host' }),
    }),
  );
  await page.route('**/admin/control/tenants', (route) => {
    controlRequests += 1;
    return route.fulfill({
      status: 404,
      contentType: 'application/json',
      body: JSON.stringify({ status: 404, message: 'not found' }),
    });
  });

  await page.goto('/admin');
  await page.getByLabel(/admin token/i).fill(PLATFORM_TOKEN);
  await page.getByRole('button', { name: /connect|连接/i }).click();

  await expect(page.getByText(/admin api.*400|管理接口.*400/i)).toBeVisible();
  await expect(page.getByText(/token rejected|token 被拒绝/i)).toHaveCount(0);
  await page.waitForTimeout(PROBE_SETTLE_MS);
  expect(controlRequests).toBe(0);
});

test('tenant service failure takes precedence over control maintenance mode', async ({ page }) => {
  let controlRequests = 0;
  await page.route('**/admin/overview', (route) =>
    route.fulfill({
      status: 500,
      contentType: 'application/json',
      body: JSON.stringify({ status: 500, message: 'internal error' }),
    }),
  );
  await page.route('**/admin/control/tenants', (route) => {
    controlRequests += 1;
    return route.fulfill({
      status: 503,
      contentType: 'application/json',
      body: JSON.stringify({ status: 503, message: 'not configured' }),
    });
  });

  await page.goto('/admin');
  await page.getByLabel(/admin token/i).fill(PLATFORM_TOKEN);
  await page.getByRole('button', { name: /connect|连接/i }).click();

  await expect(page.getByText(/admin api.*500|管理接口.*500/i)).toBeVisible();
  await expect(page.getByRole('heading', { name: /tenants|租户/i })).toHaveCount(0);
  await page.waitForTimeout(PROBE_SETTLE_MS);
  expect(controlRequests).toBe(0);
});

test('stored-token network failure is reported after returning to the token gate', async ({ page }) => {
  await page.addInitScript((token) => {
    sessionStorage.setItem('agent-auth-admin-token', token);
  }, PLATFORM_TOKEN);
  await page.route('**/admin/overview', (route) => route.abort('failed'));

  await page.goto('/admin');

  await expect(page.getByText(/could not be reached|无法连接/i)).toBeVisible();
  await expect(page.getByLabel(/admin token/i)).toBeVisible();
  await expect(page.getByText(/token rejected|token 被拒绝/i)).toHaveCount(0);
});

test('tenant directory shows every field without horizontal compression on mobile', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.addInitScript((token) => {
    sessionStorage.setItem('agent-auth-admin-token', token);
  }, PLATFORM_TOKEN);
  await mockControl(page);
  await page.goto('/admin');

  const list = page.getByTestId('control-tenant-list');
  await expect(list).toBeVisible();
  await expect(list.getByText('https://t1.saas.example.com/admin', { exact: true })).toBeVisible();
  await expect(page.getByText(T1_ARN, { exact: true })).toBeVisible();
  await expect(page.getByRole('tab')).toHaveCount(0);
  await expect(page.getByRole('button', { name: /edit|delete|create|编辑|删除|创建/i })).toHaveCount(0);
  await expect(list.getByRole('button', { name: /copy|复制/i })).toHaveCount(2);
  const arn = page.getByText(T1_ARN, { exact: true });
  const fits = await arn.evaluate((element) => {
    const own = element.getBoundingClientRect();
    const parent = element.parentElement?.getBoundingClientRect();
    return (
      !!parent &&
      own.left >= parent.left &&
      own.right <= parent.right + 1 &&
      own.left >= 0 &&
      own.right <= window.innerWidth + 1 &&
      document.documentElement.scrollWidth <= window.innerWidth + 1
    );
  });
  expect(fits).toBe(true);
});
