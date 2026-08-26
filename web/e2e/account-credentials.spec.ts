import { expect, test, type Page } from '@playwright/test';

type CredentialSummary = {
  passkeys: { id: string; name: string; created_at: number | null }[];
  password_status: 'not_configured' | 'change_required' | 'active';
  password_supported: boolean;
  recovery_configured: boolean;
  recovery_codes_remaining: number;
  reauthenticated: boolean;
  reauthenticate_after: number;
};

const baseSummary: CredentialSummary = {
  passkeys: [
    { id: 'opaque-phone-handle', name: 'Phone', created_at: 1_750_000_000 },
    { id: 'opaque-laptop-handle', name: 'Laptop', created_at: 1_740_000_000 },
  ],
  password_status: 'not_configured',
  password_supported: true,
  recovery_configured: true,
  recovery_codes_remaining: 8,
  reauthenticated: true,
  reauthenticate_after: 1_800_000_000,
};

async function mockAccount(page: Page, summary: CredentialSummary = baseSummary) {
  let current = structuredClone(summary);
  await page.route('**/grants', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: '[]' }),
  );
  await page.route('**/account/sessions', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify([
        {
          id: 'current-session',
          current: true,
          device: 'Chrome on Linux',
          created_at: 1_750_000_000,
          last_used_at: 1_750_000_100,
          expires_at: 1_800_000_000,
        },
      ]),
    }),
  );
  await page.route('**/recovery/status', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        configured: current.recovery_configured,
        remaining: current.recovery_codes_remaining,
      }),
    }),
  );
  await page.route('**/account/credentials', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(current),
    }),
  );
  return {
    update(next: CredentialSummary) {
      current = structuredClone(next);
    },
  };
}

test('c12_5_passkey_rename_and_password_enrollment', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mockAccount(page);
  let renameBody: unknown;
  let passwordBody: unknown;
  await page.route('**/account/passkeys/opaque-phone-handle', async (route) => {
    renameBody = route.request().postDataJSON();
    await route.fulfill({ status: 204 });
  });
  await page.route('**/account/password', async (route) => {
    passwordBody = route.request().postDataJSON();
    await route.fulfill({ status: 204 });
  });

  await page.goto('/account');
  const phone = page.locator('.ant-list-item').filter({ hasText: 'Phone' });
  await phone.getByRole('button', { name: /rename|重命名/i }).click();
  await page.getByLabel(/passkey name|passkey 名称/i).fill('Work phone');
  await page.getByRole('button', { name: /^save$|^保存$/i }).click();
  await expect.poll(() => renameBody).toEqual({ name: 'Work phone' });

  await page.getByLabel(/^new password$|^新密码$/i).fill('New account password 123!');
  await page
    .getByLabel(/confirm new password|确认新密码/i)
    .fill('New account password 123!');
  await page.getByRole('button', { name: /set password|设置密码/i }).click();

  await expect.poll(() => passwordBody).toEqual({ new_password: 'New account password 123!' });
  await expect(
    page.getByText(/please sign in to manage your account|请先登录以管理你的账户/i),
  ).toBeVisible();
  await expect(page.getByText(/password updated|密码已更新/i)).toBeVisible();
});

test('c12_5_active_password_rotation', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mockAccount(page, {
    ...baseSummary,
    password_status: 'active',
  });
  let passwordBody: unknown;
  await page.route('**/account/password', async (route) => {
    passwordBody = route.request().postDataJSON();
    await route.fulfill({ status: 204 });
  });

  await page.goto('/account');
  await page.getByLabel(/^new password$|^新密码$/i).fill('Rotated account password 456!');
  await page
    .getByLabel(/confirm new password|确认新密码/i)
    .fill('Rotated account password 456!');
  await page.getByRole('button', { name: /change password|修改密码/i }).click();

  await expect.poll(() => passwordBody).toEqual({
    new_password: 'Rotated account password 456!',
  });
  await expect(
    page.getByText(/please sign in to manage your account|请先登录以管理你的账户/i),
  ).toBeVisible();
  await expect(page.getByText(/password updated|密码已更新/i)).toBeVisible();
});

test('server-side password rejection keeps the account session active', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mockAccount(page);
  await page.route('**/account/password', (route) =>
    route.fulfill({
      status: 400,
      contentType: 'application/json',
      body: JSON.stringify({ error: 'password_policy_violation' }),
    }),
  );

  await page.goto('/account');
  await page.getByLabel(/^new password$|^新密码$/i).fill('Rejected account password 123!');
  await page
    .getByLabel(/confirm new password|确认新密码/i)
    .fill('Rejected account password 123!');
  await page.getByRole('button', { name: /set password|设置密码/i }).click();

  await expect(
    page.getByText(/use a different password between 12 and 128 bytes|请使用不同的 12 至 128 字节密码/i),
  ).toBeVisible();
  await expect(page.getByRole('button', { name: /set password|设置密码/i })).toBeVisible();
  await expect(
    page.getByText(/please sign in to manage your account|请先登录以管理你的账户/i),
  ).toHaveCount(0);
});

test('password enrollment is hidden for an unsupported identity', async ({ page }) => {
  await mockAccount(page, {
    ...baseSummary,
    password_supported: false,
  });

  await page.goto('/account');
  await expect(
    page.getByText(
      /password sign-in is not available for this identity|此身份不支持密码登录/i,
    ),
  ).toBeVisible();
  await expect(page.getByLabel(/^new password$|^新密码$/i)).toHaveCount(0);
  await expect(page.getByRole('button', { name: /set password|设置密码/i })).toHaveCount(0);
});

test('c12_5_last_passkey_removal_requires_replacement_factor', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mockAccount(page, {
    ...baseSummary,
    passkeys: [{ id: 'only-passkey', name: 'Only passkey', created_at: null }],
    password_status: 'not_configured',
    recovery_configured: false,
    recovery_codes_remaining: 0,
  });

  await page.goto('/account');
  const passkey = page.locator('.ant-list-item').filter({ hasText: 'Only passkey' });
  await expect(passkey.getByRole('button', { name: /remove|移除/i })).toBeDisabled();
  await expect(
    page.getByText(/add a password, recovery codes|请先添加密码、恢复码/i),
  ).toBeVisible();
});

test('c12_5_credential_mutation_reauthentication_path', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mockAccount(page);
  await page.route('**/account/passkeys/opaque-phone-handle', (route) =>
    route.fulfill({
      status: 403,
      contentType: 'application/json',
      body: JSON.stringify({ error: 'reauthentication_required' }),
    }),
  );

  await page.goto('/account');
  const phone = page.locator('.ant-list-item').filter({ hasText: 'Phone' });
  await phone.getByRole('button', { name: /rename|重命名/i }).click();
  await page.getByLabel(/passkey name|passkey 名称/i).fill('Work phone');
  await page.getByRole('button', { name: /^save$|^保存$/i }).click();

  const alert = page
    .getByRole('alert')
    .filter({ hasText: /confirm your identity|请确认身份/i });
  await expect(alert).toBeVisible();
  await expect(alert.getByRole('link', { name: /sign in again|重新登录/i })).toHaveAttribute(
    'href',
    '/login?next=%2Faccount',
  );
});

test('c9_3_account_preserves_show_once_codes_until_explicit_discard', async ({
  page,
}) => {
  await mockAccount(page, {
    ...baseSummary,
    recovery_configured: false,
    recovery_codes_remaining: 0,
  });
  const codes = Array.from({ length: 10 }, (_, index) => `v1.lookup.code-${index}`);
  await page.route('**/recovery/generate', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ recovery_codes: codes }),
    }),
  );

  await page.goto('/account');
  await page.getByRole('button', { name: /generate recovery codes|生成恢复码/i }).click();
  await page
    .locator('.ant-popconfirm:visible')
    .getByRole('button', { name: /generate recovery codes|生成恢复码/i })
    .click();

  await expect(page.getByTestId('recovery-codes')).toContainText(codes[0]);
  await expect(
    page.getByText(/please sign in to manage your account|请先登录以管理你的账户/i),
  ).toBeVisible();
  page.once('dialog', async (dialog) => {
    expect(dialog.message()).toMatch(/cannot be shown again|无法再次显示/i);
    await dialog.dismiss();
  });
  await page.getByRole('button', { name: /sign in|登录/i }).click();
  await expect(page).toHaveURL(/\/account$/);
  await expect(page.getByTestId('recovery-codes')).toContainText(codes[0]);
  await page
    .getByRole('button', { name: /i have saved these recovery codes|我已保存这些恢复码/i })
    .click();
  await expect(page.getByTestId('recovery-codes')).toHaveCount(0);
});

test('a stale recovery status 401 cannot hide newly returned show-once codes', async ({ page }) => {
  await mockAccount(page, {
    ...baseSummary,
    recovery_configured: false,
    recovery_codes_remaining: 0,
  });
  await page.unroute('**/recovery/status');
  let statusRequested!: () => void;
  const statusStarted = new Promise<void>((resolve) => {
    statusRequested = resolve;
  });
  let releaseStatus!: () => void;
  const statusRelease = new Promise<void>((resolve) => {
    releaseStatus = resolve;
  });
  await page.route('**/recovery/status', async (route) => {
    statusRequested();
    await statusRelease;
    await route.fulfill({ status: 401 });
  });
  const codes = Array.from({ length: 10 }, (_, index) => `v1.lookup.race-${index}`);
  await page.route('**/recovery/generate', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ recovery_codes: codes }),
    }),
  );

  await page.goto('/account');
  await statusStarted;
  await page.getByRole('button', { name: /generate recovery codes|生成恢复码/i }).click();
  await page
    .locator('.ant-popconfirm:visible')
    .getByRole('button', { name: /generate recovery codes|生成恢复码/i })
    .click();
  await expect(page.getByTestId('recovery-codes')).toContainText(codes[0]);

  releaseStatus();
  await expect(page.getByTestId('recovery-codes')).toContainText(codes[0]);
});

test('c12_5_recovery_rotation_lockout_prevention', async ({ page }) => {
  await mockAccount(page);
  await page.route('**/recovery/generate', (route) =>
    route.fulfill({
      status: 409,
      contentType: 'application/json',
      body: JSON.stringify({ error: 'last_viable_factor' }),
    }),
  );

  await page.goto('/account');
  await page.getByRole('button', { name: /generate new codes|重新生成/i }).click();
  await page
    .locator('.ant-popconfirm:visible')
    .getByRole('button', { name: /generate new codes|重新生成/i })
    .click();

  await expect(
    page.getByText(
      /add an active password or a passkey for this site|请先添加有效密码或当前站点的 passkey/i,
    ),
  ).toBeVisible();
  await expect(page.getByTestId('recovery-codes')).toHaveCount(0);
  await expect(
    page.getByText(/please sign in to manage your account|请先登录以管理你的账户/i),
  ).toHaveCount(0);
});

test('passkey deletion distinguishes a mutation conflict from lockout prevention', async ({
  page,
}) => {
  await mockAccount(page);
  await page.route('**/account/passkeys/opaque-phone-handle', (route) =>
    route.fulfill({
      status: 409,
      contentType: 'application/json',
      body: JSON.stringify({ error: 'credential_change_conflict' }),
    }),
  );

  await page.goto('/account');
  const phone = page.locator('.ant-list-item').filter({ hasText: 'Phone' });
  await phone.getByRole('button', { name: /remove|移除/i }).click();
  await page
    .locator('.ant-popconfirm:visible')
    .getByRole('button', { name: /remove|移除/i })
    .click();

  await expect(
    page.getByText(/credentials changed in another request|凭据已被另一个请求修改/i),
  ).toBeVisible();
  await expect(
    page.getByText(/add a password, recovery codes|请先添加密码、恢复码/i),
  ).toHaveCount(0);
});

test('credential controls fit a mobile viewport without horizontal overflow', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mockAccount(page);
  await page.goto('/account');

  await expect(page.getByRole('heading', { name: /sign-in methods|登录方式/i })).toBeVisible();
  await expect(page.getByRole('button', { name: /set password|设置密码/i })).toBeVisible();
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - window.innerWidth,
  );
  expect(overflow).toBeLessThanOrEqual(1);
});
