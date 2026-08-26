import { expect, test, type Page } from '@playwright/test';

type LoginSession = {
  id: string;
  current: boolean;
  device: string;
  created_at: number;
  last_used_at: number;
  expires_at: number;
};

const initialSessions: LoginSession[] = [
  {
    id: 'current-session-handle',
    current: true,
    device: 'Chrome on Linux',
    created_at: 1_750_000_000,
    last_used_at: 1_750_000_300,
    expires_at: 1_800_000_000,
  },
  {
    id: 'iphone-session-handle',
    current: false,
    device: 'Safari on iPhone',
    created_at: 1_749_000_000,
    last_used_at: 1_749_500_000,
    expires_at: 1_799_000_000,
  },
  {
    id: 'firefox-session-handle',
    current: false,
    device: 'Firefox on Windows',
    created_at: 1_748_000_000,
    last_used_at: 1_748_500_000,
    expires_at: 1_798_000_000,
  },
];

async function mockAccount(page: Page) {
  let sessions = initialSessions.map((session) => ({ ...session }));
  const calls = { revokeOne: 0, revokeCurrent: 0, revokeOthers: 0 };

  await page.route('**/grants', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: '[]' }),
  );
  await page.route('**/recovery/status', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ configured: true, remaining: 8 }),
    }),
  );
  await page.route('**/passkey/status', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ configured: true, count: 1 }),
    }),
  );
  await page.route('**/account/sessions**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (request.method() === 'GET') {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(sessions),
      });
      return;
    }
    if (request.method() === 'DELETE' && path === '/account/sessions') {
      calls.revokeOthers += 1;
      sessions = sessions.filter((session) => session.current);
      await route.fulfill({ status: 204 });
      return;
    }
    if (request.method() === 'DELETE' && path.endsWith('/iphone-session-handle')) {
      calls.revokeOne += 1;
      sessions = sessions.filter((session) => session.id !== 'iphone-session-handle');
      await route.fulfill({ status: 204 });
      return;
    }
    if (request.method() === 'DELETE' && path.endsWith('/current-session-handle')) {
      calls.revokeCurrent += 1;
      sessions = [];
      await route.fulfill({ status: 204 });
      return;
    }
    await route.fulfill({ status: 404 });
  });

  return calls;
}

test('c12_5_account_lists_revokes_and_keeps_current_login_session', async ({ page }) => {
  const calls = await mockAccount(page);
  await page.goto('/account');

  await expect(page.getByRole('heading', { name: /login sessions|登录会话/i })).toBeVisible();
  await expect(page.getByText('Chrome on Linux')).toBeVisible();
  await expect(page.getByText('Safari on iPhone')).toBeVisible();
  await expect(page.getByText('Firefox on Windows')).toBeVisible();
  await expect(page.getByText(/^current$|^当前会话$/i)).toBeVisible();

  const iphone = page.locator('.ant-list-item').filter({ hasText: 'Safari on iPhone' });
  await iphone.getByRole('button', { name: /^revoke$|^吊销$/i }).click();
  await page
    .locator('.ant-popconfirm:visible')
    .getByRole('button', { name: /^revoke$|^吊销$/i })
    .click();
  await expect.poll(() => calls.revokeOne).toBe(1);
  await expect(page.getByText('Safari on iPhone')).toHaveCount(0);
  await expect(page.getByText(/login session revoked|登录会话已吊销/i)).toBeVisible();

  await page.getByRole('button', { name: /sign out other sessions|退出其他会话/i }).click();
  await page
    .locator('.ant-popconfirm:visible')
    .getByRole('button', { name: /sign out other sessions|退出其他会话/i })
    .click();
  await expect.poll(() => calls.revokeOthers).toBe(1);
  await expect(page.getByText('Firefox on Windows')).toHaveCount(0);
  await expect(page.getByText('Chrome on Linux')).toBeVisible();
  await expect(
    page
      .locator('button.ant-btn-default')
      .filter({ hasText: /sign out other sessions|退出其他会话/i }),
  ).toBeDisabled();
});

test('c12_5_current_login_session_revocation_returns_to_login_gate', async ({ page }) => {
  const calls = await mockAccount(page);
  await page.goto('/account');

  const current = page.locator('.ant-list-item').filter({ hasText: 'Chrome on Linux' });
  await current.getByRole('button', { name: /sign out|退出登录/i }).click();
  await page
    .locator('.ant-popconfirm:visible')
    .getByRole('button', { name: /^sign out$|^退出登录$/i })
    .click();

  await expect.poll(() => calls.revokeCurrent).toBe(1);
  await expect(
    page.getByText(/please sign in to manage your account|请先登录以管理你的账户/i),
  ).toBeVisible();
  await expect(page.getByText(/signed out|已退出登录/i)).toBeVisible();
});

test('session controls remain usable without horizontal overflow on mobile', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const calls = await mockAccount(page);
  await page.goto('/account');

  const current = page.locator('.ant-list-item').filter({ hasText: 'Chrome on Linux' });
  const iphone = page.locator('.ant-list-item').filter({ hasText: 'Safari on iPhone' });
  await expect(current.getByRole('button', { name: /sign out|退出登录/i })).toBeVisible();
  await expect(iphone.getByRole('button', { name: /^revoke$|^吊销$/i })).toBeVisible();
  await expect(
    page.getByRole('button', { name: /sign out other sessions|退出其他会话/i }),
  ).toBeVisible();

  await iphone.getByRole('button', { name: /^revoke$|^吊销$/i }).click();
  await page
    .locator('.ant-popconfirm:visible')
    .getByRole('button', { name: /^revoke$|^吊销$/i })
    .click();
  await expect.poll(() => calls.revokeOne).toBe(1);

  await page.getByRole('button', { name: /sign out other sessions|退出其他会话/i }).click();
  await page
    .locator('.ant-popconfirm:visible')
    .getByRole('button', { name: /sign out other sessions|退出其他会话/i })
    .click();
  await expect.poll(() => calls.revokeOthers).toBe(1);

  await current.getByRole('button', { name: /sign out|退出登录/i }).click();
  await page
    .locator('.ant-popconfirm:visible')
    .getByRole('button', { name: /^sign out$|^退出登录$/i })
    .click();
  await expect.poll(() => calls.revokeCurrent).toBe(1);
  await expect(
    page.getByText(/please sign in to manage your account|请先登录以管理你的账户/i),
  ).toBeVisible();

  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - window.innerWidth,
  );
  expect(overflow).toBeLessThanOrEqual(1);
});
