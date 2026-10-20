import { expect, test, type Page } from '@playwright/test';
import type { components } from '../src/api/schema';

type StoredEvent = components['schemas']['StoredSecurityEvent'];
const event: StoredEvent = {
  event: {
    schema_version: 'security-event-v1', tenant_id: 'tenant-one',
    event_id: 'event-one', occurred_at: 1_792_496_000, category: 'grant',
    action: 'grant.revoke', outcome: 'success',
    actor: { kind: 'admin', id: 'trusted-admin' },
    subject: { kind: 'grant', id: 'grant-one' },
    correlation: { request_id: 'request-one', grant_id: 'grant-one' },
  },
  delivery: {
    status: 'failed', attempts: 3, last_attempt_at: 1_792_496_010,
    history: [{ status: 'failed', occurred_at: 1_792_496_010 }],
  },
};

async function connectedAdmin(page: Page) {
  await page.addInitScript(() => sessionStorage.setItem('agent-auth-admin-token', 'test-admin'));
  await page.route('**/admin/session', (route) => route.fulfill({ status: 401 }));
  await page.route('**/admin/overview', (route) => route.fulfill({
    json: { phase: 'P3', issuer: 'https://issuer.example', endpoints: [], client_count: 0, active_sessions: 0 },
  }));
}

function response(url: URL, events: StoredEvent[], cursor?: string) {
  return {
    schema_version: 'security-event-v1', tenant_id: 'tenant-one',
    from: Number(url.searchParams.get('from')), through: Number(url.searchParams.get('through')),
    hot_retention_days: 30, events, total: events.length, next_cursor: cursor,
  };
}

test('security events use the tenant API and separate successful facts from failed delivery', async ({ page }) => {
  await connectedAdmin(page);
  const requests: URL[] = [];
  await page.route('**/admin/security-events?**', (route) => {
    const url = new URL(route.request().url());
    requests.push(url);
    return route.fulfill({ json: response(url, [event]) });
  });
  await page.goto('/admin?tab=security-events');
  await expect(page.getByRole('tab', { name: 'Security events', exact: true })).toBeVisible();
  const row = page.getByRole('row').filter({ hasText: 'grant.revoke' });
  await expect(row.getByText('Success', { exact: true })).toBeVisible();
  await expect(row.getByText('Delivery failed', { exact: true })).toBeVisible();
  await row.getByRole('button', { name: 'Details', exact: true }).focus();
  await page.keyboard.press('Enter');
  const details = page.getByRole('dialog');
  await expect(details.getByText('request-one', { exact: true })).toBeVisible();
  await expect(details.getByText('grant-one', { exact: true }).first()).toBeVisible();
  await expect(details.getByText('trusted-admin', { exact: true })).toBeVisible();
  await details.getByRole('button', { name: 'Close', exact: true }).focus();
  await page.keyboard.press('Escape');
  await expect(details).toHaveCount(0);
  expect(requests[0].searchParams.has('tenant_id')).toBe(false);
});

test('opaque cursor paging, previous, refresh and changed windows fetch the correct pages', async ({ page }) => {
  await connectedAdmin(page);
  const requests: URL[] = [];
  await page.route('**/admin/security-events?**', (route) => {
    const url = new URL(route.request().url());
    requests.push(url);
    const cursor = url.searchParams.get('cursor');
    return route.fulfill({ json: response(url, cursor
      ? [{ ...event, event: { ...event.event, event_id: 'event-two', action: 'client.delete' } }]
      : [event], cursor ? undefined : 'opaque+/=cursor') });
  });
  await page.goto('/admin?tab=security-events');
  await page.getByRole('button', { name: 'Next page', exact: true }).click();
  await expect(page.getByText('client.delete', { exact: true })).toBeVisible();
  expect(requests.at(-1)!.searchParams.get('cursor')).toBe('opaque+/=cursor');
  await page.getByRole('button', { name: 'Previous page', exact: true }).click();
  await expect(page.getByText('grant.revoke', { exact: true })).toBeVisible();
  expect(requests.at(-1)!.searchParams.has('cursor')).toBe(false);
  await page.getByRole('button', { name: 'Next page', exact: true }).click();
  await expect(page.getByText('client.delete', { exact: true })).toBeVisible();
  await page.getByLabel('From', { exact: true }).fill('2026-10-01T00:00');
  await page.getByLabel('Through', { exact: true }).fill('2026-10-20T00:00');
  await page.getByLabel('Page size', { exact: true }).fill('25');
  await page.getByRole('button', { name: 'Apply window', exact: true }).click();
  await expect(page.getByText('grant.revoke', { exact: true })).toBeVisible();
  expect(requests.at(-1)!.searchParams.get('limit')).toBe('25');
  expect(requests.at(-1)!.searchParams.has('cursor')).toBe(false);
  await expect(page).toHaveURL(/event_from=/);
  await page.getByRole('button', { name: 'Next page', exact: true }).click();
  await expect(page.getByText('client.delete', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect(page.getByText('grant.revoke', { exact: true })).toBeVisible();
  expect(requests.at(-1)!.searchParams.has('cursor')).toBe(false);
});

for (const status of [401, 403, 503]) {
  test(`refresh ${status} does not retain old security events`, async ({ page }) => {
    await connectedAdmin(page);
    await page.route('**/admin/security-events?**', (route) =>
      route.fulfill({ json: response(new URL(route.request().url()), [event]) }));
    await page.goto('/admin?tab=security-events');
    await expect(page.getByText('grant.revoke', { exact: true })).toBeVisible();
    await page.route('**/admin/security-events?**', (route) => route.fulfill({ status }));
    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await expect(page.getByText('grant.revoke', { exact: true })).toHaveCount(0);
    if (status !== 401) {
      await expect(page.getByRole('alert')).toContainText(status === 403
        ? 'Admin read permission required' : 'Could not load security events');
    } else {
      await expect(page.getByLabel(/admin token/i)).toBeVisible();
    }
  });
}

test('empty results, invalid windows and loading states have no misleading old data', async ({ page }) => {
  await connectedAdmin(page);
  let release: (() => void) | undefined;
  await page.route('**/admin/security-events?**', async (route) => {
    await new Promise<void>((resolve) => { release = resolve; });
    await route.fulfill({ json: response(new URL(route.request().url()), []) });
  });
  await page.goto('/admin?tab=security-events', { waitUntil: 'domcontentloaded' });
  await expect(page.getByText('Loading security events…', { exact: true })).toBeVisible();
  await expect.poll(() => release !== undefined).toBe(true);
  release!();
  await expect(page.getByText('No events in this window.', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Next page', exact: true })).toBeDisabled();
  await page.getByLabel('From', { exact: true }).fill('2026-10-20T00:00');
  await page.getByLabel('Through', { exact: true }).fill('2026-10-01T00:00');
  await page.getByRole('button', { name: 'Apply window', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('Enter a valid time window');
});

test('malformed tenant rows fail closed and arbitrary extra secret fields are never displayed', async ({ page }) => {
  await connectedAdmin(page);
  await page.route('**/admin/security-events?**', (route) => route.fulfill({
    json: response(new URL(route.request().url()), [{
      ...event, event: { ...event.event, tenant_id: 'other-tenant' },
    }]),
  }));
  await page.goto('/admin?tab=security-events');
  await expect(page.getByRole('alert')).toContainText('Could not load security events');
  await expect(page.getByText('grant.revoke', { exact: true })).toHaveCount(0);
  await page.route('**/admin/security-events?**', (route) => route.fulfill({
    json: response(new URL(route.request().url()), [{
      ...event, event: {
        ...event.event, correlation: { ...event.event.correlation, raw_token: 'must-never-display' },
        cookie: 'secret-cookie-marker',
      },
    }] as StoredEvent[]),
  }));
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await page.getByRole('row').filter({ hasText: 'grant.revoke' })
    .getByRole('button', { name: 'Details', exact: true }).click();
  await expect(page.getByText(/must-never-display|secret-cookie-marker/)).toHaveCount(0);
});

test('late responses from an old window cannot replace the current window', async ({ page }) => {
  await connectedAdmin(page);
  const release: (() => void)[] = [];
  await page.route('**/admin/security-events?**', async (route) => {
    const url = new URL(route.request().url());
    if (url.searchParams.get('from') === '1000') {
      await new Promise<void>((resolve) => release.push(resolve));
      await route.fulfill({ json: response(url, [event]) });
    } else {
      await route.fulfill({ json: response(url, [{
        ...event, event: { ...event.event, event_id: 'new-window', action: 'client.delete' },
      }]) });
    }
  });
  await page.goto('/admin?tab=security-events&event_from=1000&event_through=2000',
    { waitUntil: 'domcontentloaded' });
  await expect.poll(() => release.length).toBeGreaterThan(0);
  await page.getByLabel('From', { exact: true }).fill('2026-10-01T00:00');
  await page.getByLabel('Through', { exact: true }).fill('2026-10-20T00:00');
  await page.getByRole('button', { name: 'Apply window', exact: true }).click();
  await expect(page.getByText('client.delete', { exact: true })).toBeVisible();
  const oldResponse = page.waitForResponse((r) => new URL(r.url()).searchParams.get('from') === '1000');
  release.forEach((resolve) => resolve());
  await oldResponse;
  await page.evaluate(() => new Promise<void>((resolve) =>
    requestAnimationFrame(() => requestAnimationFrame(() => resolve())),
  ));
  await expect(page.getByText('client.delete', { exact: true })).toBeVisible();
  await expect(page.getByText('grant.revoke', { exact: true })).toHaveCount(0);
});

test('Chinese mobile view supports details and contains table overflow', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await connectedAdmin(page);
  await page.route('**/admin/security-events?**', (route) =>
    route.fulfill({ json: response(new URL(route.request().url()), [event]) }));
  await page.goto('/admin?tab=security-events&ui_locales=zh');
  const row = page.getByRole('row').filter({ hasText: 'grant.revoke' });
  await expect(row.getByText('操作成功', { exact: true })).toBeVisible();
  await expect(row.getByText('投递失败', { exact: true })).toBeVisible();
  await row.getByRole('button', { name: /详\s*情/ }).click();
  await expect(page.getByRole('dialog').getByText('request-one', { exact: true })).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - innerWidth);
  expect(overflow).toBeLessThanOrEqual(1);
});
