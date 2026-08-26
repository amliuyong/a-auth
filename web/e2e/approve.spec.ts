import { expect, test } from '@playwright/test';

test('c7b_6_approval_page_shows_requester_and_optional_binding_without_deciding', async ({
  page,
}) => {
  const bindingMessage = '  Invoice\t#4242  | Ω  ';
  let decisionRequests = 0;

  await page.route('**/bc-approve/*', (route) => {
    if (route.request().method() !== 'GET') {
      decisionRequests += 1;
      return route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({}),
      });
    }

    const authReqId = new URL(route.request().url()).pathname.split('/').pop();
    const withBinding = authReqId === 'with-binding';
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        client_id: withBinding ? 'invoice-agent' : 'reporting-agent',
        scope: ['openid'],
        resources: [],
        binding_message: withBinding ? bindingMessage : null,
        status: 'pending',
      }),
    });
  });

  await page.goto('/approve?auth_req_id=with-binding');
  await expect(page.getByText('invoice-agent', { exact: true })).toBeVisible();
  const bindingNode = page.locator('code').filter({ hasText: 'Invoice' });
  await expect(bindingNode).toHaveCount(1);
  expect(await bindingNode.textContent()).toBe(bindingMessage);
  expect(decisionRequests).toBe(0);

  await page.goto('/approve?auth_req_id=without-binding');
  await expect(page.getByText('reporting-agent', { exact: true })).toBeVisible();
  await expect(page.getByText(/verification message|核对信息/i)).toHaveCount(0);
  await expect(page.locator('code').filter({ hasText: 'Invoice' })).toHaveCount(0);
  expect(decisionRequests).toBe(0);
});
