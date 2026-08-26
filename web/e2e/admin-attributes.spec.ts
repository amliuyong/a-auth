import { expect, test, type Page, type Route } from '@playwright/test';

const ADMIN_TOKEN = 'dev-admin-token-not-for-prod';
const CANONICAL = 'https://resource.example.com/';
const ALIAS = 'https://resource.example.com/audience';

type NamespaceOperation = {
  conflict_count: number;
  conflict_user_ids: string[];
  cursor: string | null;
  desired_exact_audiences: string[];
  expected_registration_revision: number;
  inflight_user_id: string | null;
  kind: string;
  operation_id: string;
  phase: string;
  revision: number;
  scan_complete: boolean;
  started_mutation: boolean;
  users_completed: number;
  users_scanned: number;
};

type NamespaceRegistration = {
  canonical_namespace: string;
  exact_audiences: string[];
  operation: NamespaceOperation | null;
  revision: number;
  state: string;
};

type Mapping = {
  enabled: boolean;
  mapping_id: string;
  mode: string;
  revision: number;
  source_claim: string;
  source_value: string | null;
  target_key: string;
  target_namespace: string;
  target_value: string | null;
};

async function json(route: Route, body: unknown, status = 200) {
  await route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  });
}

async function connectedAdmin(page: Page) {
  await page.addInitScript((token) => {
    sessionStorage.setItem('agent-auth-admin-token', token as string);
  }, ADMIN_TOKEN);
  await page.route('**/admin/session', (route) => json(route, {
    status: 401,
    message: 'no session',
  }, 401));
  await page.route('**/admin/overview', (route) => json(route, {
    phase: 'P1',
    issuer: 'https://localhost',
    endpoints: [],
    client_count: 0,
    active_sessions: 0,
  }));
}

function pendingRegistration(operationId: string): NamespaceRegistration {
  return {
    canonical_namespace: CANONICAL,
    exact_audiences: [ALIAS],
    operation: {
      conflict_count: 0,
      conflict_user_ids: [],
      cursor: null,
      desired_exact_audiences: [ALIAS],
      expected_registration_revision: 0,
      inflight_user_id: null,
      kind: 'create',
      operation_id: operationId,
      phase: 'validating',
      revision: 1,
      scan_complete: false,
      started_mutation: false,
      users_completed: 0,
      users_scanned: 0,
    },
    revision: 0,
    state: 'pending',
  };
}

test('c8_12_namespace_registration_revisioned_lifecycle', async ({ page }) => {
  await connectedAdmin(page);
  let registration: NamespaceRegistration | null = null;
  const puts: unknown[] = [];
  const advances: unknown[] = [];
  const cancels: unknown[] = [];
  const retires: Array<{ query: Record<string, string>; }> = [];

  await page.route('**/admin/attribute-namespaces**', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (request.method() === 'GET' && url.pathname === '/admin/attribute-namespaces') {
      return json(route, { registrations: registration ? [registration] : [] });
    }
    if (request.method() === 'PUT' && url.pathname === '/admin/attribute-namespaces') {
      const body = request.postDataJSON() as {
        canonical_namespace: string;
        exact_audiences: string[];
        expected_revision: number;
        operation_id: string;
      };
      puts.push(body);
      registration = pendingRegistration(body.operation_id);
      return json(route, registration);
    }
    if (request.method() === 'POST' && url.pathname.endsWith('/cancel')) {
      cancels.push(request.postDataJSON());
      registration = null;
      return json(route, { status: 200, message: 'cancelled' });
    }
    if (request.method() === 'POST' && url.pathname.endsWith('/advance')) {
      advances.push(request.postDataJSON());
      registration = {
        canonical_namespace: CANONICAL,
        exact_audiences: [ALIAS],
        operation: null,
        revision: 1,
        state: 'active',
      };
      return json(route, registration);
    }
    if (request.method() === 'DELETE' && url.pathname === '/admin/attribute-namespaces') {
      retires.push({ query: Object.fromEntries(url.searchParams) });
      registration = {
        canonical_namespace: CANONICAL,
        exact_audiences: [],
        operation: null,
        revision: 2,
        state: 'retired',
      };
      return json(route, registration);
    }
    return json(route, { status: 404, message: 'unmatched' }, 404);
  });

  await page.goto('/admin?tab=namespaces');
  await page.getByRole('button', { name: /create namespace|new namespace/i }).click();
  let dialog = page.getByRole('dialog');
  await dialog.getByLabel(/canonical namespace/i).fill(CANONICAL);
  const audiences = dialog.getByLabel(/exact audiences/i);
  await audiences.fill(ALIAS);
  await audiences.press('Enter');
  await audiences.press('Escape');
  await dialog.getByRole('button', { name: /start change/i }).click();

  await expect(page.getByText(/^Pending$/)).toBeVisible();
  await expect(dialog).toBeHidden();
  expect(puts).toHaveLength(1);
  expect(puts[0]).toMatchObject({
    canonical_namespace: CANONICAL,
    exact_audiences: [ALIAS],
    expected_revision: 0,
  });
  expect((puts[0] as { operation_id: string }).operation_id).toMatch(/^[0-9a-f-]{36}$/);

  await page.getByRole('button', { name: /^Cancel$/ }).click();
  await page.getByRole('button', { name: /^OK$/ }).click();
  await expect(page.getByText(/^Pending$/)).toHaveCount(0);
  expect(cancels).toEqual([{
    canonical_namespace: CANONICAL,
    operation_id: (puts[0] as { operation_id: string }).operation_id,
    expected_operation_revision: 1,
  }]);

  await page.getByRole('button', { name: /create namespace/i }).click();
  dialog = page.getByRole('dialog');
  await dialog.getByLabel(/canonical namespace/i).fill(CANONICAL);
  await dialog.getByLabel(/exact audiences/i).fill(ALIAS);
  await dialog.getByLabel(/exact audiences/i).press('Enter');
  await dialog.getByLabel(/exact audiences/i).press('Escape');
  await dialog.getByRole('button', { name: /start change/i }).click();
  await page.getByRole('button', { name: /^Continue$/ }).click();
  await expect(page.getByText(/^Active$/)).toBeVisible();
  expect(advances).toEqual([{
    canonical_namespace: CANONICAL,
    operation_id: (puts[1] as { operation_id: string }).operation_id,
    expected_operation_revision: 1,
  }]);

  await page.getByRole('button', { name: /^Retire$/ }).click();
  await page.getByRole('button', { name: /^OK$/ }).click();
  await expect(page.getByText(/^Retired$/)).toBeVisible();
  expect(retires).toHaveLength(1);
  expect(retires[0].query).toMatchObject({
    canonical_namespace: CANONICAL,
    expected_revision: '1',
  });
  expect(retires[0].query.operation_id).toMatch(/^[0-9a-f-]{36}$/);
});

test('c8_12_user_attribute_rmw_conflict_and_managed_purge', async ({ page }) => {
  await connectedAdmin(page);
  const userId = 'user:alice@example.com';
  let revision = 7;
  let values: Record<string, string> = {
    managed_active: 'treasury',
    managed_stale: 'legacy',
    note: 'initial',
  };
  const writes: Array<{ ifMatch: string | null; body: unknown }> = [];
  const purges: Array<{
    ifMatch: string | null;
    namespace: string | null;
    key: string | null;
  }> = [];

  const userDetail = () => ({
    user_id: userId,
    email: 'alice@example.com',
    status: 'active',
    created_at: 1_700_000_000,
    last_login_at: null,
    active_grants: 0,
    passkeys: 0,
    sessions: 0,
    has_recovery: false,
    recovery_unavailable: false,
    password_status: 'active',
    attributes: {
      [CANONICAL]: {
        canonical_namespace: CANONICAL,
        exact_audiences: [ALIAS],
        federation_owners: {
          managed_active: {
            upstream_idp_id: 'workforce',
            mapping_id: 'mapping-active',
            mapping_revision: 4,
            state: 'active',
          },
          ...(values.managed_stale === undefined ? {} : {
            managed_stale: {
              upstream_idp_id: 'workforce',
              mapping_id: 'mapping-stale',
              mapping_revision: 2,
              state: 'stale',
            },
          }),
        },
        kv: values,
        registration_state: 'active',
        revision,
      },
    },
  });

  await page.route('**/admin/attribute-namespaces**', (route) => json(route, {
    registrations: [{
      canonical_namespace: CANONICAL,
      exact_audiences: [ALIAS],
      operation: null,
      revision: 3,
      state: 'active',
    }],
  }));
  await page.route('**/admin/users**', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const decodedPath = decodeURIComponent(url.pathname);
    if (request.method() === 'GET' && decodedPath === '/admin/users') {
      return json(route, {
        users: [{
          user_id: userId,
          email: 'alice@example.com',
          status: 'active',
          created_at: 1_700_000_000,
          last_login_at: null,
        }],
        next_cursor: null,
      });
    }
    if (request.method() === 'GET' && decodedPath === `/admin/users/${userId}`) {
      return json(route, userDetail());
    }
    if (
      request.method() === 'PUT'
      && decodedPath === `/admin/users/${userId}/attributes`
    ) {
      const body = request.postDataJSON();
      writes.push({ ifMatch: request.headers()['if-match'] ?? null, body });
      if (writes.length === 1) {
        revision = 8;
        values = { ...values, concurrent: 'server' };
        return json(route, { status: 409, message: 'revision conflict' }, 409);
      }
      values = body as Record<string, string>;
      revision = 9;
      return json(route, { revision });
    }
    if (
      request.method() === 'DELETE'
      && decodedPath === `/admin/users/${userId}/attributes/federation-owner`
    ) {
      purges.push({
        ifMatch: request.headers()['if-match'] ?? null,
        namespace: url.searchParams.get('namespace'),
        key: url.searchParams.get('key'),
      });
      const key = url.searchParams.get('key');
      if (key) {
        const next = { ...values };
        delete next[key];
        values = next;
      }
      revision = 10;
      return json(route, { revision });
    }
    return json(route, { status: 404, message: 'unmatched' }, 404);
  });

  await page.goto('/admin?tab=users');
  await page.getByRole('button', { name: /^Details$/ }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByRole('heading', { name: /RS namespace attributes/i })).toBeVisible();

  const activeRow = dialog.getByRole('row').filter({ hasText: 'managed_active' });
  await expect(activeRow.getByRole('button', { name: /^Delete$/ })).toBeDisabled();

  const namespace = dialog.getByRole('combobox');
  const key = dialog.getByPlaceholder(/^Key$/);
  const value = dialog.getByPlaceholder(/^Value$/);
  await namespace.fill(CANONICAL);
  await key.fill('managed_active');
  await expect(dialog.getByRole('button', { name: /add.*update/i })).toBeDisabled();
  await expect(dialog.getByText(/cannot be changed/i)).toBeVisible();

  await key.fill('note');
  await value.fill('operator');
  await dialog.getByRole('button', { name: /add.*update/i }).click();
  await expect(dialog.getByText(/rev 8/)).toBeVisible();
  expect(writes[0]).toEqual({
    ifMatch: '7',
    body: {
      managed_active: 'treasury',
      managed_stale: 'legacy',
      note: 'operator',
    },
  });

  await key.fill('note');
  await value.fill('operator');
  await dialog.getByRole('button', { name: /add.*update/i }).click();
  await expect(dialog.getByText(/rev 9/)).toBeVisible();
  expect(writes[1]).toEqual({
    ifMatch: '8',
    body: {
      managed_active: 'treasury',
      managed_stale: 'legacy',
      note: 'operator',
      concurrent: 'server',
    },
  });

  const staleRow = dialog.getByRole('row').filter({ hasText: 'managed_stale' });
  await staleRow.getByRole('button', { name: /purge stale value/i }).click();
  await page.getByRole('button', { name: /^OK$/ }).click();
  await expect(dialog.getByText('managed_stale', { exact: true })).toHaveCount(0);
  expect(purges).toEqual([{
    ifMatch: '9',
    namespace: CANONICAL,
    key: 'managed_stale',
  }]);
});

test('c8_12_federation_mapping_revisioned_crud_uses_active_canonical_targets', async ({ page }) => {
  test.setTimeout(60_000);
  await connectedAdmin(page);
  const idp = {
    tenant_id: 'default',
    upstream_idp_id: 'workforce',
    upstream_issuer: 'https://idp.example.com/',
    client_id: 'client',
    authorization_endpoint: 'https://idp.example.com/authorize',
    token_endpoint: 'https://idp.example.com/token',
    jwks_uri: 'https://idp.example.com/jwks',
    scopes: ['openid'],
    strong_acr_values: [],
  };
  let registryRevision = 0;
  let mapping: Mapping | null = null;
  const creates: unknown[] = [];
  const updates: unknown[] = [];
  const deletes: Array<Record<string, string>> = [];

  await page.route('**/admin/attribute-namespaces**', (route) => json(route, {
    registrations: [
      {
        canonical_namespace: CANONICAL,
        exact_audiences: [ALIAS],
        operation: null,
        revision: 3,
        state: 'active',
      },
      {
        canonical_namespace: 'https://pending.example.com/',
        exact_audiences: ['https://pending.example.com/aud'],
        operation: pendingRegistration('11111111-1111-4111-8111-111111111111').operation,
        revision: 0,
        state: 'pending',
      },
    ],
  }));
  await page.route('**/admin/federation**', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (request.method() === 'GET' && url.pathname === '/admin/federation/default') {
      return json(route, { idps: [idp], total: 1 });
    }
    if (url.pathname.endsWith('/attribute-mappings')) {
      if (request.method() === 'GET') {
        return json(route, {
          tenant_id: 'default',
          upstream_idp_id: 'workforce',
          upstream_issuer: idp.upstream_issuer,
          registry_revision: registryRevision,
          mappings: mapping ? [mapping] : [],
        });
      }
      if (request.method() === 'POST') {
        const body = request.postDataJSON() as Record<string, unknown>;
        creates.push(body);
        registryRevision = 1;
        mapping = {
          enabled: true,
          mapping_id: 'mapping-1',
          mode: String(body.mode),
          revision: 1,
          source_claim: String(body.source_claim),
          source_value: body.source_value as string | null,
          target_key: String(body.target_key),
          target_namespace: String(body.target_namespace),
          target_value: body.target_value as string | null,
        };
        return json(route, { registry_revision: registryRevision, mapping }, 201);
      }
    }
    if (url.pathname.endsWith('/attribute-mappings/mapping-1')) {
      if (request.method() === 'PUT') {
        const body = request.postDataJSON() as Record<string, unknown>;
        updates.push(body);
        registryRevision += 1;
        mapping = {
          ...(mapping as Mapping),
          enabled: Boolean(body.enabled),
          mode: String(body.mode),
          revision: (mapping as Mapping).revision + 1,
          source_claim: String(body.source_claim),
          source_value: body.source_value as string | null,
          target_key: String(body.target_key),
          target_namespace: String(body.target_namespace),
          target_value: body.target_value as string | null,
        };
        return json(route, {
          registry_revision: registryRevision,
          mapping,
        });
      }
      if (request.method() === 'DELETE') {
        deletes.push(Object.fromEntries(url.searchParams));
        registryRevision += 1;
        mapping = null;
        return json(route, { status: 200, message: 'deleted' });
      }
    }
    return json(route, { status: 404, message: 'unmatched' }, 404);
  });

  await page.goto('/admin?tab=federation');
  await page.getByRole('button', { name: /expand row/i }).click();
  await page.getByRole('button', { name: /add mapping/i }).click();
  let dialog = page.getByRole('dialog');
  await dialog.getByLabel(/source claim/i).fill('department');
  const targetNamespace = dialog.getByRole('combobox', { name: /canonical namespace/i });
  await targetNamespace.click();
  const openDropdown = page.locator('.ant-select-dropdown:not(.ant-select-dropdown-hidden)');
  await expect(openDropdown).toContainText(CANONICAL);
  await expect(openDropdown).not.toContainText('https://pending.example.com/');
  await targetNamespace.fill(CANONICAL);
  await targetNamespace.press('Enter');
  await dialog.getByLabel(/target key/i).fill('department');
  await dialog.getByRole('button', { name: /^Save$/ }).click();
  await expect(page.getByText('department', { exact: true }).first()).toBeVisible();
  expect(creates).toEqual([{
    expected_registry_revision: 0,
    mode: 'copy_string',
    source_claim: 'department',
    source_value: null,
    target_namespace: CANONICAL,
    target_key: 'department',
    target_value: null,
  }]);

  await page.getByRole('button', { name: /^Edit$/ }).click();
  dialog = page.getByRole('dialog');
  await dialog.getByTitle('Copy string').click();
  const modeDropdown = page.locator('.ant-select-dropdown:not(.ant-select-dropdown-hidden)');
  await expect(modeDropdown).toBeVisible();
  await modeDropdown.getByText('Exact membership', { exact: true }).click();
  const requiredSourceValue = dialog.getByLabel(/required source value/i);
  await expect(requiredSourceValue).toBeVisible();
  await requiredSourceValue.fill('engineering');
  await dialog.getByLabel(/target key/i).fill('role');
  await dialog.getByLabel(/target value/i).fill('developer');
  await dialog.getByRole('button', { name: /^Save$/ }).click();
  await expect(dialog).toBeHidden();
  expect(updates[0]).toMatchObject({
    expected_registry_revision: 1,
    expected_mapping_revision: 1,
    enabled: true,
    mode: 'exact_membership',
    source_claim: 'department',
    source_value: 'engineering',
    target_namespace: CANONICAL,
    target_key: 'role',
    target_value: 'developer',
  });

  await page
    .getByRole('row')
    .filter({ hasText: 'Exact membership' })
    .getByRole('switch', { name: /^Enabled$/ })
    .click();
  expect(updates[1]).toMatchObject({
    expected_registry_revision: 2,
    expected_mapping_revision: 2,
    enabled: false,
  });

  await page.getByRole('button', { name: /^Delete$/ }).last().click();
  await page.getByRole('button', { name: /^OK$/ }).click();
  await expect(page.getByText(/no attribute mappings/i)).toBeVisible();
  expect(deletes).toEqual([{
    expected_registry_revision: '3',
    expected_mapping_revision: '3',
  }]);
});
