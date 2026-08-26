import { test, expect } from '@playwright/test';

test('login exposes account recovery and opens the recovery form', async ({ page }) => {
  await page.goto('/login');

  const recoveryLink = page.getByRole('link', {
    name: /use a recovery code|使用恢复码/i,
  });
  await expect(recoveryLink).toBeVisible();
  await expect(recoveryLink).toHaveAttribute('href', '/recover');

  await recoveryLink.click();
  await expect(page).toHaveURL(/\/recover$/);
  await expect(page.getByLabel(/recovery code|恢复码/i)).toBeVisible();
  await expect(page.getByRole('button', { name: /^recover$|^恢复$/i })).toBeVisible();
});

test('c9_3_recovery_reuses_ambiguous_operation_and_replaces_rejected_one', async ({
  page,
}) => {
  const operationIds: string[] = [];
  await page.route('**/recovery/verify', async (route) => {
    const body = route.request().postDataJSON() as {
      code: string;
      operation_id: string;
    };
    operationIds.push(body.operation_id);
    const attempt = operationIds.length;
    if (attempt === 1) {
      await route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'temporarily_unavailable' }),
      });
    } else if (attempt === 2) {
      await route.fulfill({ status: 400, body: 'invalid code' });
    } else {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ recovered: true, next: 'bind_new_factor' }),
      });
    }
  });

  await page.goto('/recover');
  await page.getByLabel(/recovery code|恢复码/i).fill('v1.lookup.secret');
  const submit = page.getByRole('button', { name: /recover|恢复/i });
  await submit.click();
  await expect.poll(() => operationIds.length).toBe(1);
  await expect(submit).toBeEnabled();
  await submit.click();
  await expect.poll(() => operationIds.length).toBe(2);
  await expect(submit).toBeEnabled();
  await submit.click();
  await expect.poll(() => operationIds.length).toBe(3);

  expect(operationIds[0]).toMatch(/^[A-Za-z0-9_-]{43}$/);
  expect(operationIds[1]).toBe(operationIds[0]);
  expect(operationIds[2]).not.toBe(operationIds[1]);
  await expect(page.getByText(/recovered|恢复成功/i)).toBeVisible();
});
