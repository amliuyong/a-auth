import { expect, test } from '@playwright/test';

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
