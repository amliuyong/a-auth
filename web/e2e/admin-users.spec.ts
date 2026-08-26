import { test, expect, type Page } from '@playwright/test';

// spec 003 §1.4 admin 本地 email 用户管理面前端 e2e(类 Cognito User Pool)。
//
// 覆盖前端 Users tab 的**交互 + OpenAPI 契约收发**(后端端点用 page.route mock;后端逻辑/gate
// 已由 Rust 进程内 e2e admin_users_e2e.rs 覆盖,此处不重测后端):
//   ①连接(admin token 门)→ 切 Users tab → 列表渲染(status tag)
//   ②创建用户(Modal → POST /admin/users → 刷新列表)
//   ③禁用(Popconfirm → POST /disable → status→disabled,操作按钮切换为 enable)
//   ④详情(GET /admin/users/{id} → 聚合计数 + unavailable 标记不当 0)
//   ⑤删除(Popconfirm → DELETE → tombstone)
//   ⑥URL 深链 + 服务端搜索;⑦重置临时密码。

const ADMIN_TOKEN = 'dev-admin-token-not-for-prod';
const LAST_LOGIN_AT = 1_750_000_000;

// 内存态用户表(mock 后端),让 UI 动作后 GET 反映变更。
type U = {
  user_id: string;
  email: string;
  status: string;
  created_at: number;
  last_login_at: number | null;
};

type AttributeView = {
  canonical_namespace: string;
  exact_audiences: string[];
  federation_owners: Record<string, never>;
  kv: Record<string, string>;
  registration_state: string;
  revision: number;
};

async function mockAdmin(page: Page, initial: U[]) {
  const users = new Map<string, U>(initial.map((u) => [u.user_id, u]));
  const attributes = new Map<string, Record<string, AttributeView>>();

  // token 门:overview 恒 200(有 Authorization 头)。
  await page.route('**/admin/overview', (r) =>
    r.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        phase: 'P1', issuer: 'https://localhost', endpoints: [], client_count: 0, active_sessions: 0,
      }),
    }),
  );

  // 统一路由所有 /admin/users*(后注册优先,兜住全部子路径),按 method+path 分派。
  await page.route(/\/admin\/users(\/[^?]*)?(\?.*)?$/, async (r) => {
    const req = r.request();
    const method = req.method();
    const url = new URL(req.url());
    const rest = url.pathname.split('/admin/users')[1] ?? ''; // '' | '/{id}' | '/{id}/disable'

    // 集合端点 /admin/users(rest 空)。
    if (rest === '' || rest === '/') {
      if (method === 'GET') {
        const query = (url.searchParams.get('q') ?? '').trim().toLowerCase();
        const status = url.searchParams.get('status') ?? 'non_deleted';
        const matched = Array.from(users.values()).filter((user) => {
          const matchesQuery = !query
            || user.email.toLowerCase().includes(query)
            || user.user_id.toLowerCase().includes(query);
          const matchesStatus = status === 'all'
            || (status === 'non_deleted' && user.status !== 'tombstoned')
            || user.status === status;
          return matchesQuery && matchesStatus;
        });
        return r.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ users: matched }),
        });
      }
      if (method === 'POST') {
        const payload = JSON.parse(req.postData() ?? '{}') as {
          email: string;
          issue_invitation?: boolean;
          initial_password?: string;
        };
        if (Boolean(payload.initial_password) === Boolean(payload.issue_invitation)) {
          return r.fulfill({
            status: 400,
            contentType: 'application/json',
            body: JSON.stringify({
              status: 400,
              message: 'exactly one bootstrap method is required',
            }),
          });
        }
        const email = payload.email.trim().toLowerCase();
        const uid = `user:${email}`;
        const existing = users.get(uid);
        if (existing?.status === 'tombstoned') {
          return r.fulfill({ status: 409, contentType: 'application/json', body: JSON.stringify({ status: 409, message: 'tombstoned' }) });
        }
        if (!existing) {
          users.set(uid, {
            user_id: uid,
            email,
            status: 'active',
            created_at: 1_700_000_000,
            last_login_at: null,
          });
        }
        return r.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            ...users.get(uid),
            invitation: payload.issue_invitation
              ? {
                  invitation_url: 'https://localhost/invite#token=show-once-token',
                  expires_at: 1_800_000_000,
                }
              : null,
          }),
        });
      }
    }

    const invitation = rest.match(/^\/([^/]+)\/invitation$/);
    if (invitation && method === 'POST') {
      const uid = decodeURIComponent(invitation[1]);
      if (!users.has(uid)) {
        return r.fulfill({
          status: 404,
          contentType: 'application/json',
          body: JSON.stringify({ status: 404, message: 'not found' }),
        });
      }
      return r.fulfill({
        status: 201,
        contentType: 'application/json',
        body: JSON.stringify({
          invitation_url: 'https://localhost/invite#token=regenerated-token',
          expires_at: 1_800_000_000,
        }),
      });
    }

    const reset = rest.match(/^\/([^/]+)\/reset-password$/);
    if (reset && method === 'POST') {
      const uid = decodeURIComponent(reset[1]);
      if (!users.has(uid)) {
        return r.fulfill({
          status: 404,
          contentType: 'application/json',
          body: JSON.stringify({ status: 404, message: 'not found' }),
        });
      }
      return r.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ status: 200, message: 'password reset' }),
      });
    }

    const attrs = rest.match(/^\/([^/]+)\/attributes$/);
    if (attrs && method === 'PUT') {
      const uid = decodeURIComponent(attrs[1]);
      const namespace = url.searchParams.get('namespace') ?? '';
      const current = attributes.get(uid) ?? {};
      const revision = (current[namespace]?.revision ?? 0) + 1;
      attributes.set(uid, {
        ...current,
        [namespace]: {
          canonical_namespace: namespace,
          exact_audiences: [namespace],
          federation_owners: {},
          kv: JSON.parse(req.postData() ?? '{}'),
          registration_state: 'active',
          revision,
        },
      });
      return r.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ revision }),
      });
    }

    // disable / enable:/{id}/disable | /{id}/enable。
    const act = rest.match(/^\/([^/]+)\/(disable|enable)$/);
    if (act && method === 'POST') {
      const uid = decodeURIComponent(act[1]);
      const u = users.get(uid);
      if (u) u.status = act[2] === 'disable' ? 'disabled' : 'active';
      return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ status: 200, message: act[2] }) });
    }

    // 单资源 /{id}:GET 详情 / DELETE 墓碑。
    const one = rest.match(/^\/([^/]+)$/);
    if (one) {
      const uid = decodeURIComponent(one[1]);
      if (method === 'GET') {
        const u = users.get(uid);
        if (!u) return r.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ status: 404, message: 'not found' }) });
        return r.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ...u,
            active_grants: 2,
            passkeys: 1,
            sessions: { unavailable: true }, // 故意:验证 UI 显 "unavailable" 不当 0
            has_recovery: true,
            password_status: 'change_required',
            attributes: attributes.get(uid) ?? {},
          }),
        });
      }
      if (method === 'DELETE') {
        const u = users.get(uid);
        if (u) u.status = 'tombstoned';
        return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ status: 200, message: 'tombstoned' }) });
      }
    }

    return r.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ status: 404, message: 'unmatched' }) });
  });
}

// 预置 sessionStorage 里的 admin token,直接进已连接态。
async function connectedAdmin(page: Page) {
  await page.addInitScript((tok) => {
    sessionStorage.setItem('agent-auth-admin-token', tok as string);
  }, ADMIN_TOKEN);
}

test('c10_24_users_show_utc_login_and_never_logged_in', async ({ page }) => {
  await connectedAdmin(page);
  await mockAdmin(page, [
    {
      user_id: 'user:alice@example.com',
      email: 'alice@example.com',
      status: 'active',
      created_at: 1_700_000_000,
      last_login_at: LAST_LOGIN_AT,
    },
    {
      user_id: 'user:bob@example.com',
      email: 'bob@example.com',
      status: 'disabled',
      created_at: 1_700_000_100,
      last_login_at: null,
    },
  ]);
  await page.goto('/admin');
  await page.getByRole('tab', { name: /users|用户/i }).click();
  await expect(page).toHaveURL(/\/admin\?tab=users$/);
  const formattedLastLogin = await page.evaluate(
    (seconds) => `${new Date(seconds * 1000).toLocaleString(undefined, { timeZone: 'UTC' })} UTC`,
    LAST_LOGIN_AT,
  );
  // email 精确匹配(排除 user_id 列的 `user:alice@…`);两行状态 tag 各出现。
  await expect(page.getByRole('columnheader', { name: /last login|最后登录/i })).toBeVisible();
  await expect(page.getByText('alice@example.com', { exact: true })).toBeVisible();
  await expect(page.getByText('bob@example.com', { exact: true })).toBeVisible();
  await expect(page.getByText(/^Active$|^正常$/)).toBeVisible();
  await expect(page.getByText(/^Disabled$|^已禁用$/)).toBeVisible();
  await expect(page.getByText(formattedLastLogin, { exact: true })).toBeVisible();
  await expect(page.getByText(/^Never logged in$|^从未登录$/)).toBeVisible();
});

test('c10_25_users_hide_tombstones_and_persist_status_filters', async ({ page }) => {
  await connectedAdmin(page);
  await mockAdmin(page, [
    { user_id: 'user:active@example.com', email: 'active@example.com', status: 'active', created_at: 1_700_000_000, last_login_at: null },
    { user_id: 'user:disabled@example.com', email: 'disabled@example.com', status: 'disabled', created_at: 1_700_000_100, last_login_at: null },
    { user_id: 'user:deleted@example.com', email: 'deleted@example.com', status: 'tombstoned', created_at: 1_700_000_200, last_login_at: null },
  ]);

  await page.goto('/admin?tab=users');
  await expect(page.getByText('active@example.com', { exact: true })).toBeVisible();
  await expect(page.getByText('disabled@example.com', { exact: true })).toBeVisible();
  await expect(page.getByText('deleted@example.com', { exact: true })).toHaveCount(0);

  const statusFilter = page.getByRole('combobox', { name: /user status|用户状态/i });
  await expect(statusFilter).toBeVisible();
  await expect(page.getByText(/^not deleted$|^未删除$/i)).toBeVisible();

  const deletedRequest = page.waitForRequest((request) => {
    const url = new URL(request.url());
    return url.pathname === '/admin/users' && url.searchParams.get('status') === 'tombstoned';
  });
  await page.getByText(/^not deleted$|^未删除$/i).click();
  await page.getByText(/^deleted$|^已删除$/i).last().click();
  await deletedRequest;
  await expect(page).toHaveURL(/user_status=tombstoned/);
  await expect(page.getByText('deleted@example.com', { exact: true })).toBeVisible();
  await expect(page.getByText('active@example.com', { exact: true })).toHaveCount(0);

  await page.reload();
  await expect(page.getByText(/^deleted$|^已删除$/i)).toBeVisible();
  await expect(page.getByText('deleted@example.com', { exact: true })).toBeVisible();

  const allRequest = page.waitForRequest((request) => {
    const url = new URL(request.url());
    return url.pathname === '/admin/users' && url.searchParams.get('status') === 'all';
  });
  await page.getByTitle(/^deleted$|^已删除$/i).click();
  await page.getByText(/^all$|^全部$/i).last().click();
  await allRequest;
  await expect(page).toHaveURL(/user_status=all/);
  await expect(page.getByText('active@example.com', { exact: true })).toBeVisible();
  await expect(page.getByText('disabled@example.com', { exact: true })).toBeVisible();
  await expect(page.getByText('deleted@example.com', { exact: true })).toBeVisible();

  await page.getByRole('tab', { name: /dashboard|仪表盘/i }).click();
  await expect(page).toHaveURL(/\/admin$/);
  await page.goBack();
  await expect(page).toHaveURL(/tab=users.*user_status=all|user_status=all.*tab=users/);
  await expect(page.getByText('deleted@example.com', { exact: true })).toBeVisible();
});

test('c10_25_load_more_preserves_selected_status_filter', async ({ page }) => {
  await connectedAdmin(page);
  await mockAdmin(page, []);
  const requests: Array<{ cursor: string | null; status: string | null }> = [];
  await page.route('**/admin/users*', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (request.method() !== 'GET' || url.pathname !== '/admin/users') {
      return route.fallback();
    }
    const cursor = url.searchParams.get('cursor');
    const status = url.searchParams.get('status');
    requests.push({ cursor, status });
    const email = cursor ? 'disabled-2@example.com' : 'disabled-1@example.com';
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        users: [{
          user_id: `user:${email}`,
          email,
          status: 'disabled',
          created_at: 1_700_000_000,
          last_login_at: null,
        }],
        next_cursor: cursor ? undefined : 'next-disabled-page',
      }),
    });
  });

  await page.goto('/admin?tab=users&user_status=disabled');
  await expect(page.getByText('disabled-1@example.com', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: /^load more$|^加载更多$/i }).click();
  await expect(page.getByText('disabled-2@example.com', { exact: true })).toBeVisible();
  expect(requests.some((request) => request.cursor === null)).toBe(true);
  expect(requests.at(-1)).toEqual({
    cursor: 'next-disabled-page',
    status: 'disabled',
  });
  expect(requests.every((request) => request.status === 'disabled')).toBe(true);
});

test('c10_23_users_deep_link_reload_and_browser_history', async ({ page }) => {
  await connectedAdmin(page);
  await mockAdmin(page, [
    { user_id: 'user:alice@example.com', email: 'alice@example.com', status: 'active', created_at: 1_700_000_000, last_login_at: LAST_LOGIN_AT },
    { user_id: 'user:bob@example.com', email: 'bob@example.com', status: 'active', created_at: 1_700_000_100, last_login_at: null },
  ]);
  const searched = page.waitForRequest((request) => {
    const url = new URL(request.url());
    return url.pathname === '/admin/users' && url.searchParams.get('q') === 'alice';
  });
  await page.goto('/admin?tab=users&user_q=alice');
  await searched;

  await expect(page.getByRole('tab', { name: /users|用户/i })).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByText('alice@example.com', { exact: true })).toBeVisible();
  await expect(page.getByText('bob@example.com', { exact: true })).toHaveCount(0);
  await expect(page.getByPlaceholder(/search email|搜索邮箱/i)).toHaveValue('alice');

  const search = page.getByPlaceholder(/search email|搜索邮箱/i);
  const searchedForBob = page.waitForRequest((request) => {
    const url = new URL(request.url());
    return url.pathname === '/admin/users' && url.searchParams.get('q') === 'bob';
  });
  await search.fill('bob');
  await search.press('Enter');
  await searchedForBob;
  await expect(page).toHaveURL(/\/admin\?tab=users&user_q=bob$/);
  await expect(page.getByText('bob@example.com', { exact: true })).toBeVisible();
  await expect(page.getByText('alice@example.com', { exact: true })).toHaveCount(0);
  await expect(search).toHaveValue('bob');

  const refreshed = page.waitForRequest((request) => {
    const url = new URL(request.url());
    return url.pathname === '/admin/users' && url.searchParams.get('q') === 'bob';
  });
  await page.reload();
  await refreshed;
  await expect(page).toHaveURL(/\/admin\?tab=users&user_q=bob$/);
  await expect(page.getByText('bob@example.com', { exact: true })).toBeVisible();
  await expect(page.getByText('alice@example.com', { exact: true })).toHaveCount(0);

  await page.getByRole('tab', { name: /dashboard|仪表盘/i }).click();
  await expect(page).toHaveURL(/\/admin$/);
  await page.goBack();
  await expect(page).toHaveURL(/tab=users&user_q=bob/);
  await expect(page.getByText('bob@example.com', { exact: true })).toBeVisible();
  await page.goForward();
  await expect(page).toHaveURL(/\/admin$/);
  await expect(page.getByRole('tab', { name: /dashboard|仪表盘/i })).toHaveAttribute('aria-selected', 'true');
});

test('c10_23_invalid_admin_tab_falls_back_to_overview', async ({ page }) => {
  await connectedAdmin(page);
  await mockAdmin(page, []);
  await page.goto('/admin?tab=not-a-real-tab');
  await expect(page.getByRole('tab', { name: /dashboard|仪表盘/i })).toHaveAttribute('aria-selected', 'true');
});

test('users tab: a stale search response cannot overwrite the current query', async ({ page }) => {
  await connectedAdmin(page);
  await mockAdmin(page, []);
  let releaseAlice!: () => void;
  let markAliceStarted!: () => void;
  const aliceBlocked = new Promise<void>((resolve) => { releaseAlice = resolve; });
  const aliceStarted = new Promise<void>((resolve) => { markAliceStarted = resolve; });
  await page.route('**/admin/users*', async (route) => {
    const query = new URL(route.request().url()).searchParams.get('q');
    if (query === 'alice') {
      markAliceStarted();
      await aliceBlocked;
    }
    const email = query === 'alice' ? 'alice@example.com' : 'bob@example.com';
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        users: [{
          user_id: `user:${email}`,
          email,
          status: 'active',
          created_at: 1_700_000_000,
          last_login_at: null,
        }],
      }),
    });
  });

  await page.goto('/admin?tab=users&user_q=alice');
  await aliceStarted;
  const search = page.getByPlaceholder(/search email|搜索邮箱/i);
  await search.fill('bob');
  await search.press('Enter');
  await expect(page).toHaveURL(/user_q=bob/);
  await expect(page.getByText('bob@example.com', { exact: true })).toBeVisible();

  releaseAlice();
  await expect(page.getByText('bob@example.com', { exact: true })).toBeVisible();
  await expect(page.getByText('alice@example.com', { exact: true })).toHaveCount(0);
});

test('c10_25_stale_status_response_cannot_overwrite_current_filter', async ({ page }) => {
  await connectedAdmin(page);
  await mockAdmin(page, []);
  let releaseDeleted!: () => void;
  let markDeletedStarted!: () => void;
  const deletedBlocked = new Promise<void>((resolve) => { releaseDeleted = resolve; });
  const deletedStarted = new Promise<void>((resolve) => { markDeletedStarted = resolve; });
  await page.route('**/admin/users*', async (route) => {
    const status = new URL(route.request().url()).searchParams.get('status') ?? 'non_deleted';
    if (status === 'tombstoned') {
      markDeletedStarted();
      await deletedBlocked;
    }
    const deleted = status === 'tombstoned';
    const email = deleted ? 'deleted@example.com' : 'active@example.com';
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        users: [{
          user_id: `user:${email}`,
          email,
          status: deleted ? 'tombstoned' : 'active',
          created_at: 1_700_000_000,
          last_login_at: null,
        }],
      }),
    });
  });

  await page.goto('/admin?tab=users');
  await expect(page.getByText('active@example.com', { exact: true })).toBeVisible();

  await page.getByTitle(/^not deleted$|^未删除$/i).click();
  await page.getByText(/^deleted$|^已删除$/i).last().click();
  await deletedStarted;

  await page
    .getByRole('tabpanel', { name: /users|用户/i })
    .getByTitle(/^deleted$|^已删除$/i)
    .click();
  await page.getByText(/^active$|^正常$/i).last().click();
  await expect(page).toHaveURL(/user_status=active/);
  await expect(page.getByText('active@example.com', { exact: true })).toBeVisible();

  releaseDeleted();
  await expect(page.getByText('active@example.com', { exact: true })).toBeVisible();
  await expect(page.getByText('deleted@example.com', { exact: true })).toHaveCount(0);
});

test('c10_25_completed_mutation_reloads_latest_status_filter', async ({ page }) => {
  await connectedAdmin(page);
  await mockAdmin(page, [
    { user_id: 'user:pending@example.com', email: 'pending@example.com', status: 'active', created_at: 1_700_000_000, last_login_at: null },
  ]);
  let releaseDelete!: () => void;
  let markDeleteStarted!: () => void;
  const deleteBlocked = new Promise<void>((resolve) => { releaseDelete = resolve; });
  const deleteStarted = new Promise<void>((resolve) => { markDeleteStarted = resolve; });
  await page.route(/\/admin\/users\/[^/?]+$/, async (route) => {
    if (route.request().method() !== 'DELETE') return route.fallback();
    markDeleteStarted();
    await deleteBlocked;
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ status: 200, message: 'deleted' }),
    });
  });

  await page.goto('/admin?tab=users');
  await expect(page.getByText('pending@example.com', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: /^delete$|^删除$/i }).click();
  await page.getByRole('button', { name: /^(ok|yes|确定|确 定)$/i }).click();
  await deleteStarted;

  await page.getByTitle(/^not deleted$|^未删除$/i).click();
  await page.getByText(/^disabled$|^已禁用$/i).last().click();
  await expect(page).toHaveURL(/user_status=disabled/);
  await expect(page.getByText('pending@example.com', { exact: true })).toHaveCount(0);

  const reloadRequest = page.waitForRequest((request) =>
    request.method() === 'GET'
    && new URL(request.url()).pathname === '/admin/users');
  releaseDelete();
  const request = await reloadRequest;
  expect(new URL(request.url()).searchParams.get('status')).toBe('disabled');
  await expect(page.getByText('pending@example.com', { exact: true })).toHaveCount(0);
});

test('users tab: create user via modal', async ({ page }) => {
  await connectedAdmin(page);
  await mockAdmin(page, []);
  await page.goto('/admin');
  await page.getByRole('tab', { name: /users|用户/i }).click();

  await page.getByRole('button', { name: /create user|创建用户/i }).click();
  await page.getByLabel(/email|邮箱/i).fill('carol@example.com');
  await page.getByLabel(/initial password|初始密码/i).fill('Initial password 123!');
  const createRequest = page.waitForRequest((request) =>
    request.method() === 'POST' && new URL(request.url()).pathname === '/admin/users',
  );
  await page.getByRole('button', { name: /^save$|^保存$/i }).click();

  const body = (await createRequest).postDataJSON();
  expect(body).toEqual({
    email: 'carol@example.com',
    initial_password: 'Initial password 123!',
    issue_invitation: false,
  });
  await expect(page.getByText('carol@example.com', { exact: true })).toBeVisible();
});

test('c9_11_admin_show_once_invitation_survives_until_explicit_discard', async ({ page }) => {
  await page.setViewportSize({ width: 360, height: 780 });
  await connectedAdmin(page);
  await mockAdmin(page, []);
  let rejectListReload = false;
  let userListLoads = 0;
  await page.route(/\/admin\/users(?:\?.*)?$/, async (route) => {
    if (route.request().method() !== 'GET' || !rejectListReload) return route.fallback();
    userListLoads += 1;
    return route.fulfill({
      status: 401,
      contentType: 'application/json',
      body: JSON.stringify({ status: 401, message: 'expired admin session' }),
    });
  });
  await page.goto('/admin?tab=users');
  await page.waitForLoadState('networkidle');
  rejectListReload = true;

  await page.getByRole('button', { name: /create user|创建用户/i }).click();
  const createDialog = page.getByRole('dialog');
  await createDialog.getByLabel(/email|邮箱/i).fill('invitee@example.com');
  await createDialog.getByText(/one-time invitation|一次性邀请链接/i).click();
  const createRequest = page.waitForRequest((request) =>
    request.method() === 'POST' && new URL(request.url()).pathname === '/admin/users',
  );
  await createDialog.getByRole('button', { name: /^save$|^保存$/i }).click();
  expect((await createRequest).postDataJSON()).toEqual({
    email: 'invitee@example.com',
    issue_invitation: true,
  });

  const invitationDialog = page.getByRole('dialog');
  const invitationUrl = invitationDialog.getByLabel(/invitation URL|邀请链接/i);
  await expect(invitationUrl).toHaveValue('https://localhost/invite#token=show-once-token');
  expect(userListLoads).toBe(0);
  expect(await page.evaluate(
    () => document.documentElement.scrollWidth > document.documentElement.clientWidth,
  )).toBe(false);
  expect(await page.evaluate(() => {
    const event = new Event('beforeunload', { cancelable: true });
    return window.dispatchEvent(event);
  })).toBe(false);

  await page.evaluate(() => {
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: () => Promise.reject(new Error('denied')) },
    });
  });
  await invitationDialog.getByRole('button', { name: /copy invitation URL|复制邀请链接/i }).click();
  await expect(page.getByText(/copy failed|复制失败/i)).toBeVisible();
  await expect(invitationUrl).toHaveValue('https://localhost/invite#token=show-once-token');

  const routeWarning = page.waitForEvent('dialog');
  await page.locator('[data-node-key="overview"]').evaluate((element) => {
    (element as HTMLElement).click();
  });
  const routeDialog = await routeWarning;
  expect(routeDialog.message()).toMatch(/cannot be recovered|无法找回/i);
  await routeDialog.dismiss();
  await expect(invitationUrl).toBeVisible();

  await invitationDialog.getByRole('button', { name: /^dismiss$|^关闭$/i }).click();
  const confirm = page.getByRole('dialog').last();
  await confirm.getByRole('button', { name: /^cancel$|^取消$/i }).click();
  await expect(invitationUrl).toBeVisible();
  await invitationDialog.getByRole('button', { name: /^dismiss$|^关闭$/i }).click();
  await page.getByRole('button', { name: /discard URL|丢弃链接/i }).click();
  await expect(invitationUrl).toHaveCount(0);
  await expect.poll(() => userListLoads).toBe(1);
});

test('users tab: regenerating an invitation reveals the replacement once', async ({ page }) => {
  await connectedAdmin(page);
  await mockAdmin(page, [
    {
      user_id: 'user:invite-again@example.com',
      email: 'invite-again@example.com',
      status: 'active',
      created_at: 1_700_000_000,
      last_login_at: null,
    },
  ]);
  await page.goto('/admin?tab=users');

  await page.getByRole('button', { name: /generate invitation|生成邀请/i }).click();
  await expect(page.getByLabel(/invitation URL|邀请链接/i))
    .toHaveValue('https://localhost/invite#token=regenerated-token');
});

test('c9_11_admin_serializes_concurrent_invitation_regeneration', async ({ page }) => {
  await connectedAdmin(page);
  await mockAdmin(page, [
    {
      user_id: 'user:invite-once@example.com',
      email: 'invite-once@example.com',
      status: 'active',
      created_at: 1_700_000_000,
      last_login_at: null,
    },
  ]);
  let requestCount = 0;
  let markRequestStarted!: () => void;
  let releaseRequest!: () => void;
  const requestStarted = new Promise<void>((resolve) => { markRequestStarted = resolve; });
  const requestBlocked = new Promise<void>((resolve) => { releaseRequest = resolve; });
  await page.route(/\/admin\/users\/[^/]+\/invitation$/, async (route) => {
    requestCount += 1;
    markRequestStarted();
    await requestBlocked;
    await route.fulfill({
      status: 201,
      contentType: 'application/json',
      body: JSON.stringify({
        invitation_url: 'https://localhost/invite#token=serialized-token',
        expires_at: 1_800_000_000,
      }),
    });
  });
  await page.goto('/admin?tab=users');

  const regenerate = page.getByRole('button', { name: /generate invitation|生成邀请/i });
  await regenerate.evaluate((element) => {
    (element as HTMLButtonElement).click();
    (element as HTMLButtonElement).click();
  });
  await requestStarted;
  await expect(regenerate).toBeDisabled();
  expect(requestCount).toBe(1);

  releaseRequest();
  await expect(page.getByLabel(/invitation URL|邀请链接/i))
    .toHaveValue('https://localhost/invite#token=serialized-token');
  expect(requestCount).toBe(1);
});

test('users tab: disable flips status and toggles action', async ({ page }) => {
  await connectedAdmin(page);
  await mockAdmin(page, [
    { user_id: 'user:dave@example.com', email: 'dave@example.com', status: 'active', created_at: 1_700_000_000, last_login_at: null },
  ]);
  await page.goto('/admin');
  await page.getByRole('tab', { name: /users|用户/i }).click();

  // 点 Disable → Popconfirm 确认 → 列表刷新为 disabled + 出现 Enable 按钮。
  await page.getByRole('button', { name: /^disable$|^禁用$/i }).click();
  await page.getByRole('button', { name: /^(ok|yes|确定|确 定)$/i }).click();

  await expect(page.getByRole('button', { name: /^enable$|^启用$/i })).toBeVisible();
});

test('c10_25_delete_removes_user_from_default_view', async ({ page }) => {
  await connectedAdmin(page);
  await mockAdmin(page, [
    { user_id: 'user:delete@example.com', email: 'delete@example.com', status: 'active', created_at: 1_700_000_000, last_login_at: null },
  ]);
  await page.goto('/admin?tab=users');

  await page.getByRole('button', { name: /^delete$|^删除$/i }).click();
  await page.getByRole('button', { name: /^(ok|yes|确定|确 定)$/i }).click();
  await expect(page.getByText('delete@example.com', { exact: true })).toHaveCount(0);

  await page.getByTitle(/^not deleted$|^未删除$/i).click();
  await page.getByText(/^deleted$|^已删除$/i).last().click();
  await expect(page.getByText('delete@example.com', { exact: true })).toBeVisible();
});

test('users tab: reset password submits a temporary password', async ({ page }) => {
  await connectedAdmin(page);
  await mockAdmin(page, [
    { user_id: 'user:reset@example.com', email: 'reset@example.com', status: 'active', created_at: 1_700_000_000, last_login_at: null },
  ]);
  await page.goto('/admin?tab=users');

  await page.getByRole('button', { name: /reset password|重置密码/i }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel(/^temporary password$|^临时密码$/i).fill('Reset password 456!');
  await dialog.getByLabel(/confirm temporary password|确认临时密码/i).fill('Reset password 456!');
  const requestPromise = page.waitForRequest((request) =>
    request.method() === 'POST'
    && decodeURIComponent(new URL(request.url()).pathname)
      === '/admin/users/user:reset@example.com/reset-password',
  );
  await dialog.getByRole('button', { name: /reset password|重置密码/i }).click();

  const request = await requestPromise;
  expect(request.postDataJSON()).toEqual({ temporary_password: 'Reset password 456!' });
  await expect(page.getByText(/password reset|密码已重置/i)).toBeVisible();
});

test('users tab: detail shows counts and unavailable marker', async ({ page }) => {
  await connectedAdmin(page);
  await mockAdmin(page, [
    { user_id: 'user:erin@example.com', email: 'erin@example.com', status: 'active', created_at: 1_700_000_000, last_login_at: null },
  ]);
  await page.goto('/admin');
  await page.getByRole('tab', { name: /users|用户/i }).click();

  await page.getByRole('button', { name: /details|详情/i }).click();
  // 聚合计数可见 + sessions 标 unavailable(§1.4 codex #4:store 失败不当 0)。
  await expect(page.getByText(/unavailable|不可用/i)).toBeVisible();
  await expect(page.getByText(/change required|首次登录需修改/i)).toBeVisible();
});

test('users tab: edits RS namespace attributes from user detail', async ({ page }) => {
  await connectedAdmin(page);
  await mockAdmin(page, [
    { user_id: 'user:frank@example.com', email: 'frank@example.com', status: 'active', created_at: 1_700_000_000, last_login_at: null },
  ]);
  await page.goto('/admin');
  await page.getByRole('tab', { name: /users|用户/i }).click();
  await page.getByRole('button', { name: /details|详情/i }).click();

  await expect(page.getByRole('heading', { name: /RS namespace attributes|RS 命名空间属性/i })).toBeVisible();
  const namespace = page.locator('.ant-modal .ant-select input');
  await namespace.click();
  await namespace.pressSequentially('https://mcp.example.com/');
  await page.getByPlaceholder(/^Key$|^键$/i).fill('role');
  await page.getByPlaceholder(/^Value$|^值$/i).fill('admin');
  const saved = page.waitForRequest((request) =>
    request.method() === 'PUT' && request.url().includes('/admin/users/') && request.url().includes('/attributes?'),
  );
  await page.getByRole('button', { name: /add.*update|添加.*更新/i }).click();
  await saved;

  await expect(
    page.getByRole('code').filter({ hasText: 'https://mcp.example.com/' }),
  ).toBeVisible();
  await expect(page.getByText('role', { exact: true })).toBeVisible();
  await expect(page.getByText('admin', { exact: true })).toBeVisible();
});
