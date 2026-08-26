import { expect, test } from '@playwright/test';

test('c9_11_invitation_bearer_leaves_history_and_redirects_only_to_account', async ({
  page,
}) => {
  let postedToken: string | undefined;
  await page.route('**/login/invitation', async (route) => {
    postedToken = (route.request().postDataJSON() as { token: string }).token;
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      headers: {
        'set-cookie':
          '__Host-agent_auth_session=session; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600',
      },
      body: JSON.stringify({ authenticated: true, redirect_to: '/account' }),
    });
  });
  await page.route('**/account/sessions', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: '[]' }),
  );
  await page.route('**/grants', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: '[]' }),
  );

  await page.goto('/login');
  await page.goto('/invite#token=opaque.secret');
  expect(new URL(page.url()).search).toBe('');
  await expect.poll(() => new URL(page.url()).hash).toBe('');
  await page.getByRole('button', { name: /accept invitation|接受邀请/i }).click();
  await expect(page).toHaveURL(/\/account$/);
  expect(postedToken).toBe('opaque.secret');
  await page.goBack();
  await expect(page).toHaveURL(/\/login$/);
  expect(new URL(page.url()).hash).toBe('');
});

test('c9_11_failed_invitation_stays_memory_only_for_retry', async ({
  page,
}) => {
  let attempts = 0;
  await page.route('**/login/invitation', (route) => {
    attempts += 1;
    return route.fulfill({
      status: 400,
      contentType: 'application/json',
      body: JSON.stringify({ message: 'invalid invitation' }),
    });
  });
  await page.goto('/login');
  await page.goto('/invite#token=opaque.secret');
  await expect.poll(() => new URL(page.url()).hash).toBe('');
  const cleanedHistoryLength = await page.evaluate(() => window.history.length);
  const assertBearerAbsentFromBrowserState = async () => {
    const state = await page.evaluate(() => ({
      href: window.location.href,
      history: window.history.state,
      localStorage: { ...window.localStorage },
      sessionStorage: { ...window.sessionStorage },
    }));
    expect(JSON.stringify(state)).not.toContain('opaque.secret');
  };
  await assertBearerAbsentFromBrowserState();
  await page.getByRole('button', { name: /accept invitation|接受邀请/i }).click();

  await expect(page.getByText(/invalid, expired|邀请无效/i)).toBeVisible();
  const retry = page.getByRole('button', { name: /try again|重试/i });
  await expect(retry).toBeVisible();
  await retry.click();
  await expect.poll(() => attempts).toBe(2);
  expect(new URL(page.url()).hash).toBe('');
  expect(await page.evaluate(() => window.history.length)).toBe(cleanedHistoryLength);
  await assertBearerAbsentFromBrowserState();
  await page.goBack();
  await expect(page).toHaveURL(/\/login$/);
  expect(page.url()).not.toContain('opaque.secret');
});

test('mobile invitation view has no horizontal overflow', async ({ page }) => {
  await page.setViewportSize({ width: 360, height: 780 });
  await page.goto('/invite#token=opaque.secret');
  await expect(page.getByRole('button', { name: /accept invitation|接受邀请/i })).toBeVisible();
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth > document.documentElement.clientWidth,
  );
  expect(overflow).toBe(false);
});
