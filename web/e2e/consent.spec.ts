import { expect, test } from '@playwright/test';

test('workload consent displays only the server validated actor and single hop limit', async ({ page }) => {
  let acknowledgedActor: unknown;
  await page.route('**/consent/context?*', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        client_id: 'coveai',
        client_name: 'CoveAI',
        client_source: 'registered',
        scopes: ['db:read'],
        resources: ['https://covedb.example'],
        workload_actor: 'analysis-runtime',
        csrf_token: 'server-issued-csrf',
      }),
    }),
  );
  await page.route('**/consent/decision', (route) => {
    acknowledgedActor = JSON.parse(route.request().postData() ?? '{}').workload_actor;
    return route.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
  });
  await page.goto(
    '/consent?client_id=coveai&redirect_uri=https%3A%2F%2Fcoveai.example%2Fcallback' +
      '&resource=https%3A%2F%2Fcovedb.example&workload_actor=unvalidated-query-actor',
  );
  await expect(page.getByText('analysis-runtime', { exact: true })).toBeVisible();
  await expect(page.getByText('unvalidated-query-actor', { exact: true })).toHaveCount(0);
  await expect(page.getByText(/one delegation hop|单跳委托/)).toBeVisible();
  await page.getByRole('button', { name: /^approve$|^同意$/i }).click();
  await expect.poll(() => acknowledgedActor).toBe('analysis-runtime');
});

test('consent loads the server context and submits its CSRF token', async ({ page }) => {
  const authorizeQuery =
    'response_type=code&client_id=query-client' +
    '&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback' +
    '&scope=openid&resource=https%3A%2F%2Fquery-a.example' +
    '&resource=https%3A%2F%2Fquery-b.example&state=opaque%20state' +
    '&nonce=oidf%20nonce&acr_values=urn%3Aexample%3Aacr&max_age=0';
  let contextUrl: URL | null = null;
  let decisionBody: Record<string, unknown> | null = null;

  await page.route('**/consent/context?*', (route) => {
    contextUrl = new URL(route.request().url());
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        client_id: 'registered-client',
        client_name: 'Registered Client',
        client_source: 'registered',
        scopes: ['openid', 'profile'],
        resource: 'https://resource-a.example',
        resources: ['https://resource-a.example', 'https://resource-b.example'],
        authorization_details: [
          {
            type: 'agent_auth_rar_v1',
            locations: ['https://resource-a.example'],
            resource_subset: ['reports/2026'],
            max_records: 25,
          },
        ],
        csrf_token: 'server-issued-csrf',
      }),
    });
  });
  await page.route('**/consent/decision', async (route) => {
    decisionBody = JSON.parse(route.request().postData() ?? '{}');
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({}),
    });
  });

  await page.goto(`/consent?${authorizeQuery}`);

  await expect(page.getByText(/Registered Client/)).toBeVisible();
  await expect(page.getByText('profile', { exact: true })).toBeVisible();
  await expect(page.locator('code').filter({ hasText: 'https://resource-a.example' })).toBeVisible();
  await expect(page.locator('code').filter({ hasText: 'https://resource-b.example' })).toBeVisible();
  await expect(page.getByText('reports/2026', { exact: true })).toBeVisible();
  expect(contextUrl?.search.slice(1)).toBe(authorizeQuery);
  await expect.poll(() => contextUrl?.searchParams.get('client_id')).toBe('query-client');
  expect(contextUrl?.searchParams.get('redirect_uri')).toBe('https://client.example/callback');
  expect(contextUrl?.searchParams.get('scope')).toBe('openid');
  expect(contextUrl?.searchParams.getAll('resource')).toEqual([
    'https://query-a.example',
    'https://query-b.example',
  ]);
  expect(contextUrl?.searchParams.get('state')).toBe('opaque state');

  await expect(page.locator('#agent-auth-consent-ready')).toHaveCount(1);
  await expect(page.getByRole('button', { name: /^deny$|^拒绝$/i })).toHaveAttribute(
    'id',
    'agent-auth-consent-deny',
  );
  await expect(page.getByRole('button', { name: /^approve$|^同意$/i })).toHaveAttribute(
    'id',
    'agent-auth-consent-approve',
  );
  await page.getByRole('button', { name: /^approve$|^同意$/i }).click();

  await expect.poll(() => decisionBody).not.toBeNull();
  expect(decisionBody).toEqual({
    decision: 'approve',
    csrf: 'server-issued-csrf',
    authorize_query: authorizeQuery,
  });
});

const PAYMENT_INTENT_ID = 'pi_Vb0oYlS9cG2nR1xQ7tU4wE8aZ3kM6jH5fD0pL2sN9qA';
const PAYMENT_TERMS_DIGEST = 'CJtWiXqs76hMBRVmjSmjnN3Lbdqhsm39pVT-rLdrdt4';
const PAYMENT_AUTHORIZE_QUERY =
  'response_type=code&client_id=pay-client' +
  '&redirect_uri=https%3A%2F%2Fshop.example%2Fcallback' +
  '&scope=payments%3Aexecute&resource=https%3A%2F%2Fpayments.example' +
  '&workload_actor=pay-runtime' +
  `&authorization_details=${encodeURIComponent(
    JSON.stringify([{ type: 'agent_auth_payment_v1', intent_id: PAYMENT_INTENT_ID }]),
  )}` +
  '&state=pay-state';
const PAYMENT_VIEW = {
  intent_id: PAYMENT_INTENT_ID,
  terms_digest: PAYMENT_TERMS_DIGEST,
  order_id: 'order-1',
  amount_minor: '1999',
  currency: 'USD',
  currency_exponent: 2,
  funding_source: { id: 'fs-visa-4242', version: 3, label: 'Visa •••• 4242' },
  payee: { id: 'payee-example-books', version: 7, name: 'Example Books Ltd' },
  actor: 'pay-runtime',
  execute_before: 1798761600,
  resource: 'https://payments.example',
};

function paymentConsentContext(payment: Record<string, unknown> | undefined) {
  return {
    client_id: 'pay-client',
    client_name: 'Example Shop',
    client_source: 'registered',
    scopes: ['payments:execute'],
    resource: 'https://payments.example',
    resources: ['https://payments.example'],
    workload_actor: 'pay-runtime',
    authorization_details: [
      {
        type: 'agent_auth_payment_v1',
        locations: ['https://payments.example'],
        actions: ['execute'],
        intent_id: PAYMENT_INTENT_ID,
        terms_digest: PAYMENT_TERMS_DIGEST,
        terms: {
          tenant: 'default',
          payer: 'payer-subject',
          client_id: 'pay-client',
          actor: 'pay-runtime',
          resource: 'https://payments.example',
          order_id: 'order-1',
          funding_source: { id: 'fs-visa-4242', version: 3, label: 'Visa •••• 4242' },
          payee: { id: 'payee-example-books', version: 7, name: 'Example Books Ltd' },
          amount_minor: '1999',
          currency: 'USD',
          currency_exponent: 2,
          execute_before: 1798761600,
        },
      },
    ],
    ...(payment === undefined ? {} : { payment }),
    csrf_token: 'payment-bound-csrf',
  };
}

test('c14_3_consent_displays_exact_payment_terms_and_acknowledges_digest', async ({ page }) => {
  let decisionBody: Record<string, unknown> | null = null;
  await page.route('**/consent/context?*', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(paymentConsentContext(PAYMENT_VIEW)),
    }),
  );
  await page.route('**/consent/decision', async (route) => {
    decisionBody = JSON.parse(route.request().postData() ?? '{}');
    await route.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
  });

  await page.goto(`/consent?${PAYMENT_AUTHORIZE_QUERY}`);

  const card = page.locator('#agent-auth-consent-payment');
  await expect(card).toBeVisible();
  await expect(card.getByText('19.99 USD', { exact: true })).toBeVisible();
  await expect(card.getByText('Visa •••• 4242', { exact: true })).toBeVisible();
  await expect(card.getByText('Example Books Ltd', { exact: true })).toBeVisible();
  await expect(card.getByText('order-1', { exact: true })).toBeVisible();
  await expect(card.getByText('pay-runtime', { exact: true })).toBeVisible();
  await expect(card.locator('time[datetime="2027-01-01T00:00:00.000Z"]')).toBeVisible();
  await expect(card.getByText(PAYMENT_INTENT_ID, { exact: true })).toBeVisible();
  await expect(
    card.getByText(
      /^Approve only this single payment\. Any change of amount, payee or funding source requires a new approval\.$|^仅批准这一笔支付。/,
    ),
  ).toBeVisible();
  // Minor units are never shown raw, and the payment entry is not repeated by the generic RAR card.
  await expect(page.getByText('1999', { exact: true })).toHaveCount(0);
  await expect(page.getByText(/^Fine-grained restrictions$|^细粒度约束$/)).toHaveCount(0);
  await expect(page.locator('.ant-tag', { hasText: 'https://payments.example' })).toHaveCount(0);
  await expect(page.locator('#agent-auth-consent-payment-invalid')).toHaveCount(0);

  await expect(page.locator('#agent-auth-consent-ready')).toHaveCount(1);
  await page.getByRole('button', { name: /^approve$|^同意$/i }).click();

  await expect.poll(() => decisionBody).not.toBeNull();
  expect(decisionBody).toEqual({
    decision: 'approve',
    csrf: 'payment-bound-csrf',
    authorize_query: PAYMENT_AUTHORIZE_QUERY,
    workload_actor: 'pay-runtime',
    payment_terms_digest: PAYMENT_TERMS_DIGEST,
  });
});

test('payment consent with a malformed amount keeps approve disabled and still allows deny', async ({
  page,
}) => {
  const decisions: Record<string, unknown>[] = [];
  await page.route('**/consent/context?*', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(paymentConsentContext({ ...PAYMENT_VIEW, amount_minor: '19.99' })),
    }),
  );
  await page.route('**/consent/decision', async (route) => {
    decisions.push(JSON.parse(route.request().postData() ?? '{}'));
    await route.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
  });

  await page.goto(`/consent?${PAYMENT_AUTHORIZE_QUERY}`);

  await expect(page.locator('#agent-auth-consent-ready')).toHaveCount(1);
  await expect(page.locator('#agent-auth-consent-payment-invalid')).toBeVisible();
  await expect(page.locator('#agent-auth-consent-payment')).toHaveCount(0);
  await expect(page.getByText(/19\.99/)).toHaveCount(0);
  const approve = page.getByRole('button', { name: /^approve$|^同意$/i });
  await expect(approve).toBeDisabled();
  await approve.click({ force: true });

  // The CSRF token of a payment authorization is bound to the digest, so deny echoes it too.
  await page.getByRole('button', { name: /^deny$|^拒绝$/i }).click();
  await expect.poll(() => decisions.length).toBe(1);
  expect(decisions).toEqual([
    {
      decision: 'deny',
      csrf: 'payment-bound-csrf',
      authorize_query: PAYMENT_AUTHORIZE_QUERY,
      workload_actor: 'pay-runtime',
      payment_terms_digest: PAYMENT_TERMS_DIGEST,
    },
  ]);
});

test('payment consent cannot be approved when the payment view is inconsistent or missing', async ({
  page,
}) => {
  let current: Record<string, unknown> | undefined;
  let approvals = 0;
  await page.route('**/consent/context?*', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(paymentConsentContext(current)),
    }),
  );
  await page.route('**/consent/decision', async (route) => {
    if (JSON.parse(route.request().postData() ?? '{}').decision === 'approve') approvals += 1;
    await route.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
  });

  for (const payment of [
    { ...PAYMENT_VIEW, currency_exponent: 5 },
    { ...PAYMENT_VIEW, currency: 'usd' },
    { ...PAYMENT_VIEW, actor: 'other-runtime' },
    { ...PAYMENT_VIEW, terms_digest: 'a-different-digest' },
    { ...PAYMENT_VIEW, payee: { id: 'payee-example-books', version: 7, name: '' } },
    undefined,
  ]) {
    current = payment;
    await page.goto(`/consent?${PAYMENT_AUTHORIZE_QUERY}`);
    await expect(page.locator('#agent-auth-consent-ready')).toHaveCount(1);
    await expect(page.locator('#agent-auth-consent-payment-invalid')).toBeVisible();
    await expect(page.locator('#agent-auth-consent-payment')).toHaveCount(0);
    await expect(page.getByRole('button', { name: /^approve$|^同意$/i })).toBeDisabled();
    await expect(page.getByText(/^Fine-grained restrictions$|^细粒度约束$/)).toHaveCount(0);
  }
  expect(approvals).toBe(0);
});

test('c4_8_dynamic_client_is_unverified_and_external_logo_is_never_rendered', async ({
  page,
}) => {
  const logoUrl = 'https://attacker.invalid/trusted-bank.png';
  const externalLogoRequests: string[] = [];
  page.on('request', (request) => {
    if (request.url() === logoUrl) externalLogoRequests.push(request.url());
  });
  await page.route('**/consent/context?*', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        client_id: 'dynamic-client',
        client_name: 'Trusted Bank',
        client_source: 'registered',
        scopes: ['openid'],
        resources: [],
        csrf_token: 'server-issued-csrf',
        logo_uri: logoUrl,
      }),
    }),
  );

  await page.goto(
    '/consent?client_id=dynamic-client' +
      '&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&scope=openid',
  );

  await expect(page.locator('#agent-auth-consent-ready')).toHaveCount(1);
  await expect(page.getByText(/Trusted Bank/)).toBeVisible();
  await expect(
    page.getByText(
      /This application is not verified\. Only approve if you trust it\.|此应用未经验证。仅在你信任它时才授权。/,
    ),
  ).toBeVisible();
  await expect(page.locator(`img[src="${logoUrl}"]`)).toHaveCount(0);
  await page.waitForTimeout(100);
  expect(externalLogoRequests).toEqual([]);
});

test('CIMD consent identifies the client without exposing its URL path', async ({ page }) => {
  const clientId = 'https://clients.example.com/private/customer/client.json';
  await page.route('**/consent/context?*', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        client_id: clientId,
        client_name: 'Example MCP Client',
        client_source: 'cimd',
        client_id_host: 'clients.example.com',
        redirect_uri_host: 'client.example',
        scopes: ['openid'],
        resources: [],
        csrf_token: 'server-issued-csrf',
      }),
    }),
  );

  await page.goto(
    `/consent?client_id=${encodeURIComponent(clientId)}` +
      '&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback',
  );

  await expect(
    page.getByText(/Example MCP Client \(clients\.example\.com\)/),
  ).toBeVisible();
  await expect(page.getByText('Redirect destination: client.example')).toBeVisible();
  await expect(page.getByText(/private\/customer\/client\.json/)).toHaveCount(0);
});

test('CIMD consent warns before redirecting to a loopback host', async ({ page }) => {
  const clientId = 'https://clients.example.com/client.json';
  await page.route('**/consent/context?*', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        client_id: clientId,
        client_name: 'Local MCP Client',
        client_source: 'cimd',
        client_id_host: 'clients.example.com',
        redirect_uri_host: '127.0.0.1',
        scopes: ['openid'],
        resources: [],
        csrf_token: 'server-issued-csrf',
      }),
    }),
  );

  await page.goto(
    `/consent?client_id=${encodeURIComponent(clientId)}` +
      '&redirect_uri=http%3A%2F%2F127.0.0.1%3A49152%2Fcallback',
  );

  await expect(
    page.getByText(
      'Local redirect destination: 127.0.0.1. Only continue if this application is running on this device.',
    ),
  ).toBeVisible();
});

test('CIMD consent recognizes a bracketed IPv6 loopback host', async ({ page }) => {
  const clientId = 'https://clients.example.com/client.json';
  await page.route('**/consent/context?*', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        client_id: clientId,
        client_name: 'Local IPv6 MCP Client',
        client_source: 'cimd',
        client_id_host: 'clients.example.com',
        redirect_uri_host: '[::1]',
        scopes: ['openid'],
        resources: [],
        csrf_token: 'server-issued-csrf',
      }),
    }),
  );

  await page.goto(
    `/consent?client_id=${encodeURIComponent(clientId)}` +
      '&redirect_uri=http%3A%2F%2F%5B%3A%3A1%5D%3A49152%2Fcallback',
  );

  await expect(
    page.getByText(
      'Local redirect destination: [::1]. Only continue if this application is running on this device.',
    ),
  ).toBeVisible();
});

test('consent redirects an expired session to login with the original authorize query', async ({
  page,
}) => {
  const authorizeQuery =
    'client_id=query-client&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback' +
    '&scope=openid%20profile&state=opaque%20state';
  await page.route('**/consent/context?*', (route) =>
    route.fulfill({ status: 401, contentType: 'text/plain', body: 'login required' }),
  );

  await page.goto(`/consent?${authorizeQuery}`);

  await page.waitForURL((url) => url.pathname === '/login');
  expect(new URL(page.url()).search.slice(1)).toBe(authorizeQuery);
});

test('a stale context 401 cannot redirect a newer consent request', async ({ page }) => {
  let releaseOld!: () => void;
  let markOldStarted!: () => void;
  const oldStarted = new Promise<void>((resolve) => {
    markOldStarted = resolve;
  });
  const oldGate = new Promise<void>((resolve) => {
    releaseOld = resolve;
  });

  await page.route('**/consent/context?*', async (route) => {
    const clientId = new URL(route.request().url()).searchParams.get('client_id');
    if (clientId === 'old-client') {
      markOldStarted();
      await oldGate;
      await route
        .fulfill({ status: 401, contentType: 'text/plain', body: 'login required' })
        .catch(() => {});
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        client_id: 'new-client',
        scopes: ['openid'],
        resources: [],
        csrf_token: 'new-request-csrf',
      }),
    });
  });

  await page.goto(
    '/consent?client_id=old-client&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback',
  );
  await oldStarted;
  await page.evaluate(() => {
    history.pushState(
      null,
      '',
      '/consent?client_id=new-client&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback',
    );
    dispatchEvent(new PopStateEvent('popstate'));
  });
  await expect(page.getByText(/new-client/)).toBeVisible();

  releaseOld();
  await page.waitForTimeout(100);
  await expect(page).toHaveURL(/\/consent\?client_id=new-client/);
});
