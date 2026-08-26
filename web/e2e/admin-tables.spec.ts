import { expect, test, type Locator, type Page } from '@playwright/test';

const ADMIN_TOKEN = 'dev-admin-token-not-for-prod';
const LAST_USED_AT = 1_750_032_000;
const CLIENT_AUTH_METHODS = [
  'none',
  'client_secret_basic',
  'client_secret_post',
  'private_key_jwt',
];
const LAYOUT_REGRESSION_CLIENT = {
  client_id: 'layout-regression-client-with-a-long-id',
  redirect_uris: ['https://layout-regression.example/callback/with/a/long/path'],
  token_endpoint_auth_method: 'client_secret_basic',
  default_resource: 'https://layout-regression.example/resource/with/a/long/path',
  post_logout_redirect_uris: [],
  introspect_enabled: true,
  resource_ids: [],
  last_used_at: LAST_USED_AT,
};
const UNUSED_LAYOUT_REGRESSION_CLIENT = {
  ...LAYOUT_REGRESSION_CLIENT,
  client_id: 'unused-layout-regression-client-with-a-long-id',
  redirect_uris: ['https://unused-layout-regression.example/callback/with/a/long/path'],
  default_resource: 'https://unused-layout-regression.example/resource/with/a/long/path',
  last_used_at: null,
};

async function connectedAdmin(page: Page) {
  await page.addInitScript((token) => {
    sessionStorage.setItem('agent-auth-admin-token', token);
  }, ADMIN_TOKEN);
  await page.route('**/admin/overview', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        phase: 'P3',
        issuer: 'https://issuer.example',
        endpoints: [],
        client_count: 1,
        active_sessions: 0,
      }),
    }),
  );
}

async function routeLayoutRegressionClient(page: Page) {
  await page.route('**/admin/clients', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        clients: [LAYOUT_REGRESSION_CLIENT, UNUSED_LAYOUT_REGRESSION_CLIENT],
        registered_client_auth_methods_supported: CLIENT_AUTH_METHODS,
      }),
    }),
  );
}

async function expectClientColumnsUniformAndResizable(page: Page) {
  const tableScroller = page.locator('.ant-table-content');
  await expect(tableScroller).toBeVisible();

  const headers = page.getByRole('columnheader');
  await expect(headers).toHaveCount(7);
  await expect(page.locator('[data-client-column-resizer]')).toHaveCount(7);
  const headerBoxes = await headers.evaluateAll((elements) =>
    elements.map((element) => {
      const box = element.getBoundingClientRect();
      return {
        x: box.x,
        right: box.right,
        height: box.height,
        position: getComputedStyle(element).position,
      };
    }),
  );
  for (let index = 0; index < headerBoxes.length; index += 1) {
    expect(headerBoxes[index].position).not.toBe('sticky');
    expect(headerBoxes[index].height).toBeCloseTo(headerBoxes[0].height, 1);
    if (index > 0) {
      expect(headerBoxes[index - 1].right).toBeLessThanOrEqual(headerBoxes[index].x + 0.5);
    }
  }

  const clientIdHeader = page.getByRole('columnheader', { name: /client id|客户端 ID/i });
  const lastTokenHeader = page.getByRole('columnheader', {
    name: /last token issued|最后签发 Token/i,
  });
  const actionsHeader = page.getByRole('columnheader', { name: /actions|操作/i });
  const clientRows = [
    page.getByRole('row', { name: /^layout-regression-client-with-a-long-id\b/i }),
    page.getByRole('row', { name: /^unused-layout-regression-client-with-a-long-id\b/i }),
  ];
  const rowCellPairs = clientRows.map((row) => ({
    lastTokenCell: row.getByRole('cell').nth(5),
    actionsCell: row.getByRole('cell').nth(6),
  }));

  const firstClientCell = clientRows[0].getByRole('cell').nth(0);
  const beforeHeaderBox = await clientIdHeader.boundingBox();
  const beforeCellBox = await firstClientCell.boundingBox();
  const beforeScrollWidth = await tableScroller.evaluate((element) => element.scrollWidth);
  expect(beforeHeaderBox).not.toBeNull();
  expect(beforeCellBox).not.toBeNull();
  expect(beforeHeaderBox!.width).toBeCloseTo(beforeCellBox!.width, 0);

  const resizeHandle = clientIdHeader.locator('[data-client-column-resizer]');
  const handleBox = await resizeHandle.boundingBox();
  expect(handleBox).not.toBeNull();
  await page.mouse.move(handleBox!.x + handleBox!.width / 2, handleBox!.y + handleBox!.height / 2);
  await page.mouse.down();
  await page.mouse.move(handleBox!.x + handleBox!.width / 2 + 80, handleBox!.y + handleBox!.height / 2);
  await page.mouse.up();

  const afterHeaderBox = await clientIdHeader.boundingBox();
  const afterCellBox = await firstClientCell.boundingBox();
  const afterScrollWidth = await tableScroller.evaluate((element) => element.scrollWidth);
  expect(afterHeaderBox).not.toBeNull();
  expect(afterCellBox).not.toBeNull();
  expect(afterHeaderBox!.width).toBeGreaterThanOrEqual(beforeHeaderBox!.width + 75);
  expect(afterHeaderBox!.width).toBeCloseTo(afterCellBox!.width, 0);
  expect(afterScrollWidth).toBeGreaterThanOrEqual(beforeScrollWidth + 75);

  await tableScroller.evaluate((element) => {
    element.scrollLeft = element.scrollWidth;
  });
  await expect(lastTokenHeader).toBeInViewport();
  await expect(actionsHeader).toBeInViewport();
  for (const { lastTokenCell, actionsCell } of rowCellPairs) {
    await expect(lastTokenCell).toBeInViewport();
    await expect(actionsCell).toBeInViewport();
  }
  const actionsCell = rowCellPairs[0].actionsCell;
  for (const button of [
    actionsCell.getByRole('button', { name: /^credentials$|^凭\s*据$/i }),
    actionsCell.getByRole('button', { name: /^edit$|^编\s*辑$/i }),
    actionsCell.getByRole('button', { name: /^delete$|^删\s*除$/i }),
  ]) {
    await expect(button).toBeInViewport();
    await button.click({ trial: true });
  }
}

test('overview shows metadata URLs and the OpenAPI download', async ({ page }) => {
  await connectedAdmin(page);
  await page.goto('/admin');

  const oidcUrl = 'https://issuer.example/.well-known/openid-configuration';
  const oauthUrl = 'https://issuer.example/.well-known/oauth-authorization-server';
  await expect(page.getByRole('link', { name: oidcUrl })).toHaveAttribute('href', oidcUrl);
  await expect(page.getByRole('link', { name: oauthUrl })).toHaveAttribute('href', oauthUrl);
  const openApiDownload = page.getByRole('link', { name: /download openapi|下载 openapi/i });
  await expect(openApiDownload).toHaveAttribute('href', 'https://issuer.example/openapi.json');
  await expect(openApiDownload).toHaveAttribute('download', 'agent-auth-openapi.json');
});

test('c10_24_clients_show_utc_activity_and_never_used', async ({ page }) => {
  await connectedAdmin(page);
  await page.route('**/admin/clients', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        clients: [
          {
            client_id: 'bridge-downstream',
            redirect_uris: [
              'https://bedrock-agentcore.us-east-1.amazonaws.com/identities/oauth2/callback/8cb665b5-97d3-47c2-ad63-026dc1d0b4d5',
            ],
            token_endpoint_auth_method: 'none',
            post_logout_redirect_uris: [],
            introspect_enabled: false,
            resource_ids: [],
            last_used_at: LAST_USED_AT,
          },
          {
            client_id: 'unused-client',
            redirect_uris: ['https://unused.example/callback'],
            token_endpoint_auth_method: 'none',
            post_logout_redirect_uris: [],
            introspect_enabled: false,
            resource_ids: [],
            last_used_at: null,
          },
        ],
        registered_client_auth_methods_supported: CLIENT_AUTH_METHODS,
      }),
    }),
  );

  await page.goto('/admin');
  await page.getByRole('tab', { name: /clients|客户端/i }).click();

  const clientId = page.getByText('bridge-downstream', { exact: true });
  const formattedLastUsed = await page.evaluate(
    (seconds) => `${new Date(seconds * 1000).toLocaleDateString(undefined, { timeZone: 'UTC' })} UTC`,
    LAST_USED_AT,
  );
  await expect(clientId).toBeVisible();
  expect(await clientId.evaluate((element) => element.getClientRects().length)).toBe(1);
  await expect(page.getByRole('columnheader', { name: /last token issued|最后签发 Token/i })).toBeVisible();
  await expect(page.getByText(formattedLastUsed, { exact: true })).toBeVisible();
  await expect(page.getByText(/^Never used$|^从未使用$/)).toBeVisible();
  await page.locator('.ant-table-content').evaluate((element) => {
    element.scrollLeft = element.scrollWidth;
  });
  await expect(page.getByRole('columnheader', { name: /actions|操作/i })).toBeInViewport();
});

test('admin clients uses uniform resizable columns at desktop widths', async ({ page }) => {
  await connectedAdmin(page);
  await routeLayoutRegressionClient(page);

  for (const viewport of [
    { width: 1440, height: 900 },
    { width: 1280, height: 800 },
    { width: 1024, height: 768 },
  ]) {
    await test.step(`${viewport.width}x${viewport.height}`, async () => {
      await page.setViewportSize(viewport);
      await page.goto('/admin?tab=clients&ui_locales=en');
      await expectClientColumnsUniformAndResizable(page);
    });
  }
});

test('admin clients keeps uniform resizable Chinese columns at 768px', async ({ page }) => {
  await page.setViewportSize({ width: 768, height: 800 });
  await page.addInitScript(() => {
    localStorage.setItem('agent-auth-lang', 'zh');
  });
  await connectedAdmin(page);
  await routeLayoutRegressionClient(page);

  await page.goto('/admin?tab=clients&ui_locales=zh');
  await expect(page.getByRole('columnheader', { name: '最后签发 Token' })).toBeAttached();
  await expect(page.getByRole('columnheader', { name: '操作' })).toBeAttached();
  await expectClientColumnsUniformAndResizable(page);
});

test('c10_23_clients_deep_link_reload_and_complete_list_search', async ({ page }) => {
  await connectedAdmin(page);
  await page.route('**/admin/clients', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        clients: [
          {
            client_id: 'bridge-downstream',
            redirect_uris: ['https://bridge.example/callback'],
            token_endpoint_auth_method: 'none',
            default_resource: 'https://bridge.example',
            post_logout_redirect_uris: [],
            introspect_enabled: false,
            resource_ids: [],
            last_used_at: null,
          },
          {
            client_id: 'billing-agent',
            redirect_uris: ['https://billing.example/callback'],
            token_endpoint_auth_method: 'client_secret_basic',
            default_resource: 'https://api.example/billing',
            post_logout_redirect_uris: [],
            introspect_enabled: true,
            resource_ids: ['https://api.example/invoices'],
            last_used_at: LAST_USED_AT,
          },
        ],
        registered_client_auth_methods_supported: CLIENT_AUTH_METHODS,
      }),
    }),
  );

  await page.goto('/admin?tab=clients&client_q=billing-agent');
  await expect(page.getByRole('tab', { name: /clients|客户端/i })).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByPlaceholder(/search client|搜索客户端/i)).toHaveValue('billing-agent');
  await expect(page.getByText('billing-agent', { exact: true })).toBeVisible();
  await expect(page.getByText('bridge-downstream', { exact: true })).toHaveCount(0);

  const search = page.getByPlaceholder(/search client|搜索客户端/i);
  await search.fill('bridge.example/callback');
  await search.press('Enter');
  expect(new URL(page.url()).searchParams.get('client_q')).toBe('bridge.example/callback');
  await expect(page.getByText('bridge-downstream', { exact: true })).toBeVisible();
  await expect(page.getByText('billing-agent', { exact: true })).toHaveCount(0);

  await page.reload();
  expect(new URL(page.url()).searchParams.get('client_q')).toBe('bridge.example/callback');
  await expect(page.getByPlaceholder(/search client|搜索客户端/i)).toHaveValue('bridge.example/callback');
  await expect(page.getByText('bridge-downstream', { exact: true })).toBeVisible();
  await expect(page.getByText('billing-agent', { exact: true })).toHaveCount(0);

  await page.getByRole('tab', { name: /dashboard|仪表盘/i }).click();
  await expect(page).toHaveURL(/\/admin$/);
  await page.goBack();
  expect(new URL(page.url()).searchParams.get('client_q')).toBe('bridge.example/callback');
  await expect(page.getByText('bridge-downstream', { exact: true })).toBeVisible();
  await page.goForward();
  await expect(page).toHaveURL(/\/admin$/);
  await expect(page.getByRole('tab', { name: /dashboard|仪表盘/i })).toHaveAttribute('aria-selected', 'true');

  await page.getByRole('tab', { name: /clients|客户端/i }).click();
  const clientsSearch = page.getByPlaceholder(/search client|搜索客户端/i);
  await clientsSearch.fill('api.example/billing');
  await clientsSearch.press('Enter');
  expect(new URL(page.url()).searchParams.get('client_q')).toBe('api.example/billing');
  await expect(page.getByText('billing-agent', { exact: true })).toBeVisible();
  await expect(page.getByText('bridge-downstream', { exact: true })).toHaveCount(0);

  await clientsSearch.fill('invoices');
  await clientsSearch.press('Enter');
  expect(new URL(page.url()).searchParams.get('client_q')).toBe('invoices');
  await expect(page.getByText('billing-agent', { exact: true })).toBeVisible();
  await expect(page.getByText('bridge-downstream', { exact: true })).toHaveCount(0);
});

test('client registration offers only executable authentication methods', async ({ page }) => {
  await connectedAdmin(page);
  await page.route('**/admin/clients', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        clients: [],
        registered_client_auth_methods_supported: CLIENT_AUTH_METHODS,
      }),
    }),
  );

  await page.goto('/admin?tab=clients');
  await page.getByRole('button', { name: /register client|注册客户端/i }).click();
  const dialog = page.getByRole('dialog');
  await dialog.locator('.ant-select-selector').click();

  const dropdown = page.locator('.ant-select-dropdown:visible');
  await expect(dropdown).toContainText('none (public + PKCE)');
  await expect(dropdown).toContainText('client_secret_basic');
  await expect(dropdown).toContainText('client_secret_post');
  await expect(dropdown).toContainText('private_key_jwt');
});

test('private_key_jwt clients expose their registered key configuration', async ({ page }) => {
  await connectedAdmin(page);
  await page.route('**/admin/clients', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        clients: [
          {
            client_id: 'legacy-private-jwt',
            redirect_uris: ['https://legacy.example/callback'],
            token_endpoint_auth_method: 'private_key_jwt',
            jwks_uri: 'https://legacy.example/jwks.json',
            token_endpoint_auth_signing_alg: 'ES256',
            post_logout_redirect_uris: [],
            introspect_enabled: false,
            resource_ids: [],
            last_used_at: null,
          },
        ],
        registered_client_auth_methods_supported: CLIENT_AUTH_METHODS,
      }),
    }),
  );

  await page.goto('/admin?tab=clients');
  await page.getByRole('button', { name: /^edit$|^编辑$/i }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByText('private_key_jwt', { exact: true })).toBeVisible();
  await dialog.locator('.ant-select-selector').click();

  const dropdown = page.locator('.ant-select-dropdown:visible');
  await expect(dropdown).toContainText('none (public + PKCE)');
  await expect(dropdown).toContainText('private_key_jwt');
  await page.keyboard.press('Escape');
  await expect(dialog.locator('.ant-segmented-item-selected', { hasText: 'JWKS URI' })).toBeVisible();
  await expect(dialog.locator('.ant-segmented-item-selected', { hasText: 'ES256' })).toBeVisible();
  await expect(dialog.getByRole('textbox', { name: 'JWKS URI', exact: true })).toHaveValue(
    'https://legacy.example/jwks.json',
  );
});

test('client registration submits inline and remote private_key_jwt metadata exclusively', async ({ page }) => {
  await connectedAdmin(page);
  const requests: Array<Record<string, unknown>> = [];
  await page.route('**/admin/clients', async (route) => {
    if (route.request().method() === 'POST') {
      const body = route.request().postDataJSON() as Record<string, unknown>;
      requests.push(body);
      await route.fulfill({
        status: 201,
        contentType: 'application/json',
        body: JSON.stringify({
          client_id: `private-client-${requests.length}`,
          redirect_uris: body.redirect_uris,
          token_endpoint_auth_method: body.token_endpoint_auth_method,
          jwks: body.jwks,
          jwks_uri: body.jwks_uri,
          token_endpoint_auth_signing_alg: body.token_endpoint_auth_signing_alg,
          post_logout_redirect_uris: [],
          introspect_enabled: false,
          resource_ids: [],
          last_used_at: null,
        }),
      });
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        clients: [],
        registered_client_auth_methods_supported: CLIENT_AUTH_METHODS,
      }),
    });
  });

  const choosePrivateKeyJwt = async () => {
    const dialog = page.getByRole('dialog');
    await dialog.locator('.ant-select-selector').click();
    await page.locator('.ant-select-dropdown:visible').getByText('private_key_jwt', { exact: true }).click();
    return dialog;
  };

  await page.goto('/admin?tab=clients');
  await page.getByRole('button', { name: /register client|注册客户端/i }).click();
  let dialog = await choosePrivateKeyJwt();
  await dialog.locator('#redirect_uris').fill('https://inline.example/callback');
  await dialog.getByLabel(/public jwks|公钥 jwks/i).fill(JSON.stringify({
    keys: [{
      kid: 'inline-key',
      kty: 'RSA',
      alg: 'RS256',
      use: 'sig',
      n: 'public-modulus',
      e: 'AQAB',
    }],
  }));
  await dialog.getByRole('button', { name: /^save$|^保存$/i }).click();
  await expect.poll(() => requests.length).toBe(1);

  await page.getByRole('button', { name: /register client|注册客户端/i }).click();
  dialog = await choosePrivateKeyJwt();
  await dialog.locator('#redirect_uris').fill('https://remote.example/callback');
  await dialog.locator('.ant-segmented-item-label', { hasText: 'JWKS URI' }).click();
  await dialog.locator('.ant-segmented-item-label', { hasText: 'ES256' }).click();
  await dialog.getByRole('textbox', { name: 'JWKS URI', exact: true }).fill(
    'https://remote.example/jwks.json',
  );
  await dialog.getByRole('button', { name: /^save$|^保存$/i }).click();
  await expect.poll(() => requests.length).toBe(2);

  expect(requests[0]).toMatchObject({
    token_endpoint_auth_method: 'private_key_jwt',
    token_endpoint_auth_signing_alg: 'RS256',
    jwks_uri: null,
    jwks: { keys: [{ kid: 'inline-key', kty: 'RSA', alg: 'RS256' }] },
  });
  expect(requests[1]).toMatchObject({
    token_endpoint_auth_method: 'private_key_jwt',
    token_endpoint_auth_signing_alg: 'ES256',
    jwks: null,
    jwks_uri: 'https://remote.example/jwks.json',
  });
});

test('an older client-list response cannot overwrite a post-create reload', async ({ page }) => {
  await connectedAdmin(page);
  let requestCount = 0;
  let releaseInitial!: () => void;
  let markInitialStarted!: () => void;
  const initialBlocked = new Promise<void>((resolve) => { releaseInitial = resolve; });
  const initialStarted = new Promise<void>((resolve) => { markInitialStarted = resolve; });
  const created = {
    client_id: 'created-client',
    redirect_uris: ['https://created.example/callback'],
    token_endpoint_auth_method: 'none',
    default_resource: 'https://created.example',
    post_logout_redirect_uris: [],
    introspect_enabled: false,
    resource_ids: [],
    last_used_at: null,
  };
  await page.route('**/admin/clients', async (route) => {
    if (route.request().method() === 'POST') {
      await route.fulfill({
        status: 201,
        contentType: 'application/json',
        body: JSON.stringify(created),
      });
      return;
    }
    const currentRequest = ++requestCount;
    if (currentRequest === 1) {
      markInitialStarted();
      await initialBlocked;
    }
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        clients: currentRequest === 1 ? [] : [created],
        registered_client_auth_methods_supported: CLIENT_AUTH_METHODS,
      }),
    });
  });

  await page.goto('/admin?tab=clients');
  await initialStarted;
  await page.getByRole('button', { name: /register client|注册客户端/i }).click();
  const dialog = page.getByRole('dialog');
  await dialog.locator('#redirect_uris').fill('https://created.example/callback');
  await dialog.getByLabel(/default resource|默认资源/i).fill('https://created.example');
  await dialog.getByRole('button', { name: /^save$|^保存$/i }).click();
  await expect(page.getByText('created-client', { exact: true })).toBeVisible();

  releaseInitial();
  await expect(page.getByText('created-client', { exact: true })).toBeVisible();
});

test('client credentials rotate with one-time reveal and explicit cutover', async ({ page }) => {
  await connectedAdmin(page);
  const current = {
    credential_id: 'cred_current',
    owner: 'billing-agent',
    created_at: 1_750_000_000,
    expires_at: 2_000_000_000,
    status: 'active',
    audit_identity: 'admin:current',
  };
  const next = {
    ...current,
    credential_id: 'cred_next',
    created_at: 1_760_000_000,
    audit_identity: 'admin:rotator',
  };
  let cutoverCalled = false;
  await page.route('**/admin/clients', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        clients: [{
          client_id: 'billing-agent',
          redirect_uris: ['https://billing.example/callback'],
          token_endpoint_auth_method: 'client_secret_basic',
          post_logout_redirect_uris: [],
          introspect_enabled: true,
          resource_ids: [],
          last_used_at: LAST_USED_AT,
          client_secret_expires_at: current.expires_at,
          client_secret_credentials: {
            current,
            next: null,
            overlap_expires_at: null,
            version: 1,
          },
          registration_token_credentials: {
            current: null,
            next: null,
            overlap_expires_at: null,
            version: 0,
          },
        }],
        registered_client_auth_methods_supported: CLIENT_AUTH_METHODS,
      }),
    }),
  );
  await page.route('**/admin/clients/*/credentials/*/*', async (route) => {
    const body = route.request().postDataJSON() as Record<string, unknown>;
    if (route.request().url().endsWith('/rotate')) {
      expect(body.expected_version).toBe(1);
      expect(body.expires_in_seconds).toBe(365 * 86_400);
      expect(body.overlap_seconds).toBe(24 * 3_600);
      expect(body.rotation_request_id).toEqual(expect.any(String));
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          credential: 'cs_shown-once',
          replayed: false,
          credentials: {
            current,
            next,
            overlap_expires_at: 1_760_086_400,
            version: 2,
          },
        }),
      });
      return;
    }
    expect(route.request().url()).toMatch(/\/cutover$/);
    expect(body).toEqual({ credential_id: 'cred_next', expected_version: 2 });
    cutoverCalled = true;
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        replayed: false,
        credentials: {
          current: next,
          next: null,
          overlap_expires_at: null,
          version: 3,
        },
      }),
    });
  });

  await page.goto('/admin?tab=clients');
  await page.getByRole('button', { name: /^credentials$|^凭据$/i }).click();
  const credentialsDialog = page.getByRole('dialog', { name: /credentials|凭据/i }).first();
  await expect(credentialsDialog.getByText('cred_current', { exact: true })).toBeVisible();

  await credentialsDialog.getByRole('button', { name: /^rotate$|^轮换$/i }).first().click();
  const rotateDialog = page.getByRole('dialog', { name: /rotate client secret|轮换 client secret/i });
  await rotateDialog.getByRole('button', { name: /^rotate$|^轮换$/i }).click();

  const revealDialog = page.getByRole('dialog', { name: /new credential|新凭据/i });
  await expect(revealDialog.getByText('cs_shown-once', { exact: true })).toBeVisible();
  await revealDialog.getByRole('button', { name: /i saved it|我已保存/i }).click();

  await credentialsDialog.getByRole('button', { name: /cut over|切换/i }).click();
  await page.locator('.ant-popconfirm-buttons .ant-btn-primary').click();
  await expect.poll(() => cutoverCalled).toBe(true);
  await expect(credentialsDialog.getByText('cred_next', { exact: true })).toBeVisible();
  await expect(credentialsDialog.getByText('cred_current', { exact: true })).toHaveCount(0);
});

test('initial access tokens are issued once, listed, and revoked', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await connectedAdmin(page);
  const token = {
    token_id: 'iat_token1',
    owner: 'bootstrap-job',
    scopes: ['dcr:register'],
    created_at: 1_750_000_000,
    expires_at: 2_000_000_000,
    status: 'active',
    audit_identity: 'admin:issuer',
    rate_limit_per_minute: 12,
    one_time: true,
    used_at: null,
    version: 1,
  };
  let issued = false;
  let revoked = false;
  await page.route('**/admin/initial-access-tokens', async (route) => {
    if (route.request().method() === 'POST') {
      expect(route.request().postDataJSON()).toEqual({
        owner: 'bootstrap-job',
        scopes: ['dcr:register'],
        expires_in_seconds: 48 * 3_600,
        rate_limit_per_minute: 12,
        one_time: true,
      });
      issued = true;
      await route.fulfill({
        status: 201,
        contentType: 'application/json',
        body: JSON.stringify({ ...token, token: 'iat_token1.shown-once' }),
      });
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ tokens: issued ? [token] : [], total: issued ? 1 : 0 }),
    });
  });
  await page.route('**/admin/initial-access-tokens/*/revoke', async (route) => {
    expect(route.request().postDataJSON()).toEqual({
      credential_id: 'iat_token1',
      expected_version: 1,
    });
    revoked = true;
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ ...token, status: 'revoked', version: 2 }),
    });
  });

  await page.goto('/admin?tab=initial-access');
  await page.getByRole('button', { name: /issue token|签发票据/i }).click();
  const createDialog = page.getByRole('dialog', { name: /issue initial access token|签发初始访问票据/i });
  await createDialog.getByLabel(/^owner$|^归属主体$/i).fill('bootstrap-job');
  await createDialog.getByLabel(/lifetime|有效期/i).fill('48');
  await createDialog.getByLabel(/rate limit|限速/i).fill('12');
  await createDialog.getByRole('switch').click();
  await createDialog.getByRole('button', { name: /issue token|签发票据/i }).click();

  const revealDialog = page.getByRole('dialog', { name: /initial access token issued|初始访问票据已签发/i });
  await expect(revealDialog.getByText('iat_token1.shown-once', { exact: true })).toBeVisible();
  await revealDialog.getByRole('button', { name: /i saved it|我已保存/i }).click();
  await expect(page.getByText('iat_token1', { exact: true })).toBeVisible();

  await page.getByRole('button', { name: /^revoke$|^吊销$/i }).click();
  await page.locator('.ant-popconfirm-buttons .ant-btn-primary').click();
  await expect.poll(() => revoked).toBe(true);
});

test('messages table copies the complete body', async ({ page, context }) => {
  const body =
    'https://issuer.example/login/callback?link_id=jdS_IH9E8BSwQ_mvJISiGYF10uR-Q8Qh&tag=ncvsRaPHGV7YcTE3wo74Zs-AS6T05ITgMLzNWDjkq3k';
  await connectedAdmin(page);
  await page.route('**/admin/messages', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        messages: [
          {
            message_id: 'msg-1',
            kind: 'magic_link',
            recipient: 'admin@example.com',
            body,
            created_at: 1_753_000_856,
          },
        ],
      }),
    }),
  );
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);

  await page.goto('/admin');
  await page.getByRole('tab', { name: /messages|消息/i }).click();

  const row = page.getByRole('row').filter({ hasText: 'admin@example.com' });
  const copy = row.getByRole('button', { name: /copy|复制/i });
  await expect(copy).toBeVisible();
  await copy.click();
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe(body);
});
