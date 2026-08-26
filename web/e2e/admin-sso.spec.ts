import { expect, test, type Page } from '@playwright/test';

function sessionBody(role: 'owner' | 'admin' | 'auditor' | 'member' = 'auditor') {
  return {
    tenant_id: 'default',
    actor: 'admin-user:scim-admin-user',
    auth_type: 'oidc_session',
    role,
    expires_at: Math.floor(Date.now() / 1000) + 600,
  };
}

async function mockOverview(page: Page) {
  await page.route('**/admin/overview', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        phase: 'P2',
        issuer: 'https://auth.example.com',
        endpoints: [],
        client_count: 1,
        active_sessions: 0,
      }),
    }),
  );
}

test('c12_3_enterprise_sso_navigation', async ({ page }) => {
  let sessionActive = false;
  await page.route('**/admin/session', (route) =>
    route.fulfill({
      status: sessionActive ? 200 : 401,
      contentType: 'application/json',
      body: JSON.stringify(
        sessionActive
          ? sessionBody('owner')
          : { status: 401, message: 'admin auth required' },
      ),
    }),
  );
  await page.route('**/admin/sso/start', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'text/html',
      body: '<script>location.replace("https://idp.example.test/authorize")</script>',
    }),
  );
  await page.route('https://idp.example.test/authorize', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'text/html',
      body: '<a href="http://localhost:5173/admin/sso/callback?code=test-code&state=test-state">Continue</a>',
    }),
  );
  await page.route('**/admin/sso/callback?code=test-code&state=test-state', (route) => {
    sessionActive = true;
    return route.fulfill({
      status: 303,
      headers: { location: '/admin' },
    });
  });
  await mockOverview(page);
  await page.goto('/admin');

  const sso = page.getByRole('link', { name: /enterprise sso|企业 sso/i });
  await expect(sso).toBeVisible();
  await expect(sso).toHaveAttribute('href', '/admin/sso/start');
  await expect(page.getByLabel(/admin token/i)).toBeVisible();
  await sso.click();
  await page.getByRole('link', { name: 'Continue' }).click();
  await expect(page).toHaveURL(/\/admin$/);
  await expect(page.getByRole('tab', { name: /dashboard|仪表盘/i })).toBeVisible();
  await expect(page.getByLabel(/admin token/i)).toHaveCount(0);
});

test('OIDC Admin session loads without a bearer and logout destroys it', async ({ page }) => {
  let active = true;
  let logoutRequests = 0;
  await page.route('**/admin/session', (route) =>
    route.fulfill({
      status: active ? 200 : 401,
      contentType: 'application/json',
      body: JSON.stringify(
        active ? sessionBody('owner') : { status: 401, message: 'admin auth required' },
      ),
    }),
  );
  await page.route('**/admin/logout', (route) => {
    logoutRequests += 1;
    active = false;
    return route.fulfill({
      status: 204,
      headers: {
        'set-cookie':
          '__Host-agent_auth_admin_session=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0',
      },
      body: '',
    });
  });
  await mockOverview(page);

  await page.goto('/admin');
  await expect(page.getByRole('tab', { name: /dashboard|仪表盘/i })).toBeVisible();
  await expect(page.getByLabel(/admin token/i)).toHaveCount(0);

  await page.getByRole('button', { name: /disconnect|断开/i }).click();
  await expect(page.getByRole('link', { name: /enterprise sso|企业 sso/i })).toBeVisible();
  expect(logoutRequests).toBe(1);
});

test('c12_3_oidc_session_displaces_stale_break_glass', async ({ page }) => {
  await page.addInitScript(() => {
    sessionStorage.setItem('agent-auth-admin-token', 'stale-break-glass-token');
  });
  let sessionAuthorization: string | undefined;
  let overviewAuthorization: string | undefined;
  await page.route('**/admin/session', (route) => {
    sessionAuthorization = route.request().headers().authorization;
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(sessionBody('owner')),
    });
  });
  await page.route('**/admin/overview', (route) => {
    overviewAuthorization = route.request().headers().authorization;
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        phase: 'P2',
        issuer: 'https://auth.example.com',
        endpoints: [],
        client_count: 1,
        active_sessions: 0,
      }),
    });
  });

  await page.goto('/admin');
  await expect(page.getByRole('tab', { name: /dashboard|仪表盘/i })).toBeVisible();
  expect(sessionAuthorization).toBeUndefined();
  expect(overviewAuthorization).toBeUndefined();
  expect(await page.evaluate(() => sessionStorage.getItem('agent-auth-admin-token'))).toBeNull();
});

test('session expiry during use returns to the sign-in gate', async ({ page }) => {
  await page.route('**/admin/session', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(sessionBody('auditor')),
    }),
  );
  await mockOverview(page);
  await page.route('**/admin/clients', (route) =>
    route.fulfill({
      status: 401,
      contentType: 'application/json',
      body: JSON.stringify({ status: 401, message: 'admin session expired' }),
    }),
  );
  await page.route('**/admin/logout', (route) => route.fulfill({ status: 204, body: '' }));

  await page.goto('/admin');
  await expect(page.getByRole('tab', { name: /dashboard|仪表盘/i })).toBeVisible();
  await page.getByRole('tab', { name: /clients|客户端/i }).click();
  await expect(page.getByRole('link', { name: /enterprise sso|企业 sso/i })).toBeVisible();
  await expect(page.getByRole('tab')).toHaveCount(0);
});

test('RFC 9470 Admin challenge starts enterprise SSO step-up', async ({ page }) => {
  await page.route('**/admin/session', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(sessionBody('owner')),
    }),
  );
  await mockOverview(page);
  await page.route('**/admin/oidc', (route) => {
    if (route.request().method() === 'GET') {
      return route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          tenant_id: 'default',
          issuer: 'https://idp.example.test',
          client_id: 'admin-client',
          authorization_endpoint: 'https://idp.example.test/authorize',
          token_endpoint: 'https://idp.example.test/token',
          jwks_uri: 'https://idp.example.test/jwks',
          redirect_uri: 'http://localhost:5173/admin/sso/callback',
          scopes: ['openid', 'email'],
          strong_acr_values: ['urn:example:admin:mfa'],
          identity_claim: 'email',
          identity_field: 'user_name',
          client_secret_configured: true,
          revision: 1,
          updated_at: Math.floor(Date.now() / 1000),
        }),
      });
    }
    return route.fulfill({
      status: 401,
      headers: {
        'www-authenticate':
          'Bearer error="insufficient_user_authentication", ' +
          'acr_values="urn:agent-auth:assurance:strong", max_age="300"',
      },
      contentType: 'application/json',
      body: JSON.stringify({
        status: 401,
        error: 'insufficient_user_authentication',
      }),
    });
  });
  await page.route('**/admin/sso/start?*', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'text/html',
      body: `<p id="step-up">${new URL(route.request().url()).searchParams.toString()}</p>`,
    }),
  );

  await page.goto('/admin?tab=admin-sso');
  await expect(page.getByLabel(/issuer/i)).toHaveValue('https://idp.example.test');
  await page.getByLabel(/client secret reference|client secret 引用/i).fill(
    'agent-auth/admin-oidc/default',
  );
  await page.getByRole('button', { name: /save|保存/i }).click();
  await expect(page.locator('#step-up')).toHaveText(
    'acr_values=urn%3Aagent-auth%3Aassurance%3Astrong&max_age=300',
  );
});

test('c12_3_auditor_denied_write_ux', async ({ page }) => {
  await page.route('**/admin/session', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(sessionBody('auditor')),
    }),
  );
  await mockOverview(page);
  const client = {
    client_id: 'client-a',
    redirect_uris: ['https://app.example.com/callback'],
    token_endpoint_auth_method: 'none',
    jwks: null,
    jwks_uri: null,
    token_endpoint_auth_signing_alg: null,
    default_resource: null,
    post_logout_redirect_uris: [],
    introspect_enabled: false,
    resource_ids: [],
    last_used_at: null,
    client_secret_expires_at: null,
    client_secret_credentials: {
      current: null,
      next: null,
      overlap_expires_at: null,
      version: 0,
    },
    registration_token_credentials: {
      current: null,
      next: null,
      overlap_expires_at: null,
      version: 0,
    },
  };
  await page.route('**/admin/clients', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        clients: [client],
        total: 1,
        registered_client_auth_methods_supported: ['none'],
      }),
    }),
  );
  await page.route('**/admin/clients/client-a', (route) =>
    route.fulfill({
      status: 403,
      contentType: 'application/json',
      body: JSON.stringify({
        status: 403,
        message: 'admin role does not permit this action',
      }),
    }),
  );

  await page.goto('/admin');
  await page.getByRole('tab', { name: /clients|客户端/i }).click();
  await expect(page.getByText('client-a', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: /delete|删除/i }).click();
  const denied = page.waitForResponse(
    (response) =>
      new URL(response.url()).pathname === '/admin/clients/client-a' &&
      response.request().method() === 'DELETE',
  );
  await page.getByRole('button', { name: /ok|确定/i }).click();
  expect((await denied).status()).toBe(403);
  await expect(page.getByText(/cannot manage admin access|不能管理 admin 访问/i)).toBeVisible();
  await expect(page.getByText('client-a', { exact: true })).toBeVisible();
});
