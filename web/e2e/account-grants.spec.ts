import { expect, test, type Page } from '@playwright/test';
import type { components } from '../src/api/schema';

type Grant = components['schemas']['GrantView'];

const grant: Grant = {
  grant_id: 'grant-one',
  client_id: 'user-facing-client',
  actor_allowlist: ['agent-one', 'spiffe://example.com/agents/*'],
  max_act_chain: 2,
  resources: [{ resource: 'https://mcp.example.com', scopes: ['read', 'write'] }],
  status: 'active',
  expires_at: 1_900_000_000,
};

async function mockAccount(page: Page, grants: unknown[] = [grant]) {
  let current = grants;
  const calls = { deletes: 0 };
  await page.route('**/grants', (route) =>
    route.fulfill({ json: current }),
  );
  await page.route('**/grants/grant-one', async (route) => {
    expect(route.request().method()).toBe('DELETE');
    calls.deletes += 1;
    current = [{ ...grant, status: 'revoked' }];
    await route.fulfill({ status: 204 });
  });
  await page.route('**/account/sessions', (route) =>
    route.fulfill({ json: [] }),
  );
  await page.route('**/account/credentials', (route) =>
    route.fulfill({
      json: {
        passkeys: [], password_status: 'not_configured', password_supported: false,
        recovery_configured: false, recovery_codes_remaining: 0,
        reauthenticated: false, reauthenticate_after: 0,
      },
    }),
  );
  await page.route('**/recovery/status', (route) =>
    route.fulfill({ json: { configured: false, remaining: 0 } }),
  );
  return calls;
}

test('grant shows explicit actor patterns and the configured depth without inventing lineage', async ({ page }) => {
  await mockAccount(page);
  await page.goto('/account');
  const row = page.locator('.ant-list-item').filter({ hasText: grant.client_id });
  await expect(row.getByText('agent-one', { exact: true })).toBeVisible();
  await expect(row.getByText('spiffe://example.com/agents/*', { exact: true })).toBeVisible();
  await expect(row.getByText(/maximum delegation depth: 2|最大委托深度: 2/i)).toBeVisible();
  await expect(row.getByText(/configured limit.*not.*history|配置上限.*不是.*历史/i)).toBeVisible();
  await expect(row.getByText(grant.resources[0].resource, { exact: true })).toBeVisible();
  await expect(row.getByText('read', { exact: true })).toBeVisible();
});

test('ordinary, single actor, revoked, expired and malformed grants never imply unrestricted delegation', async ({ page }) => {
  await mockAccount(page, [
    { ...grant, grant_id: 'ordinary', client_id: 'ordinary', actor_allowlist: [] },
    { ...grant, grant_id: 'single', client_id: 'single', actor_allowlist: ['agent-only'], max_act_chain: 1 },
    { ...grant, grant_id: 'revoked', client_id: 'revoked-client', status: 'revoked' },
    { ...grant, grant_id: 'expired', client_id: 'expired-client', status: 'expired' },
    { ...grant, grant_id: 'elapsed', client_id: 'elapsed-client', expires_at: 1_000_000_000 },
    { ...grant, grant_id: 'invalid', client_id: 'invalid', actor_allowlist: null, max_act_chain: -1 },
    { ...grant, grant_id: 'partial', client_id: 'partial', actor_allowlist: ['agent-one', 123], max_act_chain: '8' },
    { grant_id: 'legacy', client_id: 'legacy', resources: [], status: 'active', expires_at: 1_900_000_000 },
  ]);
  await page.goto('/account');
  const rows = page.locator('.ant-list-item');
  await expect(rows.filter({ hasText: 'ordinary' }).getByText(/no agents.*authorized|未授权任何 Agent/i)).toBeVisible();
  await expect(rows.filter({ hasText: 'single' }).getByText('agent-only', { exact: true })).toBeVisible();
  await expect(rows.filter({ hasText: 'single' }).getByText(/maximum delegation depth: 1|最大委托深度: 1/i)).toBeVisible();
  for (const client of ['revoked-client', 'expired-client', 'elapsed-client']) {
    await expect(rows.filter({ hasText: client }).getByRole('button', { name: /^revoke$|^吊销$/i })).toHaveCount(0);
  }
  for (const client of ['invalid', 'partial', 'legacy']) {
    const row = rows.filter({ hasText: client });
    await expect(row.getByText(/actor authority.*unavailable|无法确认 actor 授权/i)).toBeVisible();
    await expect(row.getByText(/maximum delegation depth: unavailable|最大委托深度: 无法确认/i)).toBeVisible();
    await expect(row.getByText('agent-one', { exact: true })).toHaveCount(0);
  }
});

test('revocation reloads the actual grant and explains online, offline and running-operation boundaries', async ({ page }) => {
  const calls = await mockAccount(page);
  await page.goto('/account');
  await expect(page.getByText(/offline.*until.*expir|离线.*到期/i)).toBeVisible();
  await expect(page.getByText(/already running|正在执行/i)).toBeVisible();
  const row = page.locator('.ant-list-item').filter({ hasText: grant.client_id });
  await row.getByRole('button', { name: /^revoke$|^吊销$/i }).click();
  const confirm = page.locator('.ant-popconfirm:visible');
  await expect(confirm).toContainText(/online|在线/i);
  await confirm.getByRole('button', { name: /^revoke$|^吊销$/i }).click();
  await expect.poll(() => calls.deletes).toBe(1);
  await expect(row.getByText(/^revoked$|^已吊销$/i)).toBeVisible();
  await expect(row.getByRole('button', { name: /^revoke$|^吊销$/i })).toHaveCount(0);
});

for (const status of [401, 403]) {
  test(`refresh ${status} clears previous grant information`, async ({ page }) => {
    await mockAccount(page);
    await page.goto('/account');
    await expect(page.getByText('agent-one', { exact: true })).toBeVisible();
    await page.route('**/grants', (route) => route.fulfill({ status }));
    await page.getByRole('button', { name: /^refresh$|^刷新$/i }).click();
    await expect(page.getByText('agent-one', { exact: true })).toHaveCount(0);
    await expect(page.getByText(grant.client_id, { exact: true })).toHaveCount(0);
    await expect(page.getByText(status === 401
      ? /please sign in to manage|请先登录以管理/i
      : /request could not be completed|请求无法完成/i)).toBeVisible();
  });
}

test('late grant responses cannot restore information after permission is denied', async ({ page }) => {
  await mockAccount(page);
  let finishOld: (() => void) | undefined;
  let requests = 0;
  await page.route('**/grants', async (route) => {
    requests += 1;
    if (requests === 1) {
      await new Promise<void>((resolve) => { finishOld = resolve; });
      await route.fulfill({ json: [grant] });
    } else {
      await route.fulfill({ status: 403 });
    }
  });
  await page.goto('/account', { waitUntil: 'domcontentloaded' });
  await expect.poll(() => finishOld !== undefined).toBe(true);
  // Language changes reload the account through the public page flow.
  await page.getByRole('banner').getByRole('button', { name: /中\s*文|EN/ }).click();
  await expect(page.getByText(/request could not be completed|请求无法完成/i)).toBeVisible();
  const oldResponse = page.waitForResponse((response) =>
    new URL(response.url()).pathname === '/grants' && response.status() === 200,
  );
  finishOld!();
  await oldResponse;
  // Allow the response's React update to reach the rendered public interface.
  await page.evaluate(() => new Promise<void>((resolve) =>
    requestAnimationFrame(() => requestAnimationFrame(() => resolve())),
  ));
  expect(requests).toBeGreaterThanOrEqual(2);
  await expect(page.getByText(/request could not be completed|请求无法完成/i)).toBeVisible();
  await expect(page.getByText(grant.client_id, { exact: true })).toHaveCount(0);
});

for (const language of ['en', 'zh']) {
  test(`mobile ${language} safely renders long identifiers as text`, async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.addInitScript((lang) => localStorage.setItem('agent-auth-lang', lang), language);
    const identifier = `<img src=x onerror=alert(1)>${'very-long-actor-'.repeat(14)}`;
    await mockAccount(page, [{ ...grant, actor_allowlist: [identifier], client_id: 'long-client-'.repeat(20) }]);
    await page.goto('/account');
    const actor = page.getByText(identifier, { exact: true });
    await expect(actor).toBeVisible();
    await expect(actor.locator('img')).toHaveCount(0);
    await expect(page.getByText(language === 'en'
      ? /maximum delegation depth: 2/i
      : /最大委托深度: 2/)).toBeVisible();
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(overflow).toBeLessThanOrEqual(1);
  });
}
