import { test, expect, type Page, type CDPSession } from '@playwright/test';

// spec 003 §3.9 passkey 前端仪式 e2e(CDP 虚拟 authenticator)。
//
// 覆盖前端**仪式 + marshaling** 层(navigator.credentials.create/get 组装 + base64url 收发 + 续跑):
// 后端 4 个仪式端点 + status 用 page.route mock(后端验签/存储链由 Rust 进程内 e2e 覆盖)。
// 虚拟 authenticator(CDP WebAuthn.addVirtualAuthenticator,ctap2/internal/UV)免真硬件。
//
// 覆盖:①注册仪式全链(begin→create→finish,断言 clientDataJSON.type=webauthn.create + base64url 对齐)
//       ②认证仪式(种凭证→begin[allowCredentials 含它]→get→finish 建会话+续跑)
//       ③浏览器不支持(移除 PublicKeyCredential)→ passkey 入口不显示。

const RP_ID = 'localhost'; // Vite dev host;虚拟 authenticator 的 RP ID 须与之匹配。

test.beforeEach(async ({ page }) => {
  await page.route('**/account/sessions', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify([
        {
          id: 'current-session-handle',
          current: true,
          device: 'Chrome on Linux',
          created_at: 1_700_000_000,
          last_used_at: 1_700_000_100,
          expires_at: 1_800_000_000,
        },
      ]),
    }),
  );
  await page.route('**/account/credentials', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        passkeys: [],
        password_status: 'not_configured',
        password_supported: true,
        recovery_configured: false,
        recovery_codes_remaining: 0,
        reauthenticated: true,
        reauthenticate_after: 1_800_000_000,
      }),
    }),
  );
  await page.route('**/recovery/status', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ configured: false, remaining: 0 }),
    }),
  );
});

function b64url(bytes: number[]): string {
  return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecodeUtf8(s: string): string {
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
}

// 启用 CDP 虚拟 authenticator(ctap2 + internal + UV),返回 (client, authenticatorId)。
async function addVirtualAuthenticator(page: Page): Promise<{ client: CDPSession; authenticatorId: string }> {
  const client = await page.context().newCDPSession(page);
  await client.send('WebAuthn.enable');
  const { authenticatorId } = await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true, // 自动 UV 通过(免真生物识别)
      automaticPresenceSimulation: true,
    },
  });
  return { client, authenticatorId };
}

// 让 Account 进入已登录态(/grants 返 []),并 mock register begin/finish。
async function mockRegister(page: Page, challenge: string, onFinish?: (body: Record<string, unknown>) => void) {
  let registered = false;
  await page.route('**/grants', (r) =>
    r.fulfill({ status: 200, contentType: 'application/json', body: '[]' }),
  );
  await page.route('**/account/credentials', (r) =>
    r.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        passkeys: registered
          ? [{ id: 'new-passkey-handle', name: 'Passkey', created_at: 1_750_000_000 }]
          : [],
        password_status: 'not_configured',
        password_supported: true,
        recovery_configured: false,
        recovery_codes_remaining: 0,
        reauthenticated: true,
        reauthenticate_after: 1_800_000_000,
      }),
    }),
  );
  await page.route('**/passkey/register/begin', (r) =>
    r.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        rp_id: RP_ID, user_id: 'user:alice@example.com', challenge,
        exclude_credentials: [], alg: -7, user_verification: 'required',
      }),
    }),
  );
  await page.route('**/passkey/register/finish', async (r) => {
    onFinish?.(JSON.parse(r.request().postData() ?? '{}'));
    registered = true;
    await r.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ registered: true }),
    });
  });
}

test('login uses email and password by default with passkey and magic-link alternatives', async ({ page }) => {
  await page.goto('/login');

  await expect(page.getByLabel(/email|邮箱/i)).toHaveCount(1);
  await expect(page.getByLabel(/^password$|^密码$/i)).toHaveCount(1);
  const password = page.getByRole('button', { name: /^sign in$|^登录$/i });
  const passkey = page.getByRole('button', { name: /sign in with a passkey|用 passkey 登录/i });
  const magicLink = page.getByRole('button', { name: /send sign-in link|发送登录链接/i });
  await expect(page.getByLabel(/email|邮箱/i)).toHaveAttribute('id', 'agent-auth-login-email');
  await expect(page.getByLabel(/^password$|^密码$/i)).toHaveAttribute(
    'id',
    'agent-auth-login-password',
  );
  await expect(password).toHaveAttribute('id', 'agent-auth-login-submit');
  await expect(password).toHaveAttribute('type', 'submit');
  await expect(password).toHaveClass(/ant-btn-primary/);
  await expect(passkey).toBeVisible();
  await expect(passkey).toHaveAttribute('type', 'button');
  await expect(passkey).not.toHaveClass(/ant-btn-primary/);
  await expect(magicLink).toBeVisible();
  await expect(magicLink).toHaveAttribute('type', 'button');
  await expect(magicLink).not.toHaveClass(/ant-btn-primary/);
});

test('password sign-in continues after an active credential', async ({ page }) => {
  let loginBody: Record<string, unknown> | null = null;
  await page.route('**/authorize?*', (r) =>
    r.fulfill({ status: 200, contentType: 'text/plain', body: 'continued' }),
  );
  await page.route('**/login/password', async (r) => {
    loginBody = JSON.parse(r.request().postData() ?? '{}');
    await r.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ authenticated: true, password_change_required: false }),
    });
  });

  await page.goto('/login?client_id=web-client');
  await page.getByLabel(/email|邮箱/i).fill('alice@example.com');
  await page.getByLabel(/^password$|^密码$/i).fill('Permanent password 456!');
  await page.getByRole('button', { name: /^sign in$|^登录$/i }).click();

  await expect.poll(() => loginBody).not.toBeNull();
  expect(loginBody).toEqual({
    email: 'alice@example.com',
    password: 'Permanent password 456!',
    authorize_query: 'client_id=web-client',
  });
  await page.waitForURL(/\/authorize\?client_id=web-client$/);
});

test('first password sign-in requires an in-place password change', async ({ page }) => {
  await page.route('**/authorize?*', (r) =>
    r.fulfill({ status: 200, contentType: 'text/plain', body: 'continued' }),
  );
  await page.route('**/login/password', (r) =>
    r.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ authenticated: false, password_change_required: true }),
    }),
  );
  let changeBody: Record<string, unknown> | null = null;
  await page.route('**/login/password/change', async (r) => {
    changeBody = JSON.parse(r.request().postData() ?? '{}');
    await r.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ authenticated: true, password_change_required: false }),
    });
  });

  await page.goto('/login?client_id=first-client');
  await page.getByLabel(/email|邮箱/i).fill('first-login@example.com');
  await page.getByLabel(/^password$|^密码$/i).fill('Initial password 123!');
  await page.getByRole('button', { name: /^sign in$|^登录$/i }).click();

  await expect(page.getByText(/set a new password|必须设置新密码/i)).toBeVisible();
  await page.getByLabel(/^new password$|^新密码$/i).fill('Permanent password 456!');
  await page.getByLabel(/confirm new password|确认新密码/i).fill('Permanent password 456!');
  await page.getByRole('button', { name: /set password and sign in|设置密码并登录/i }).click();

  await expect.poll(() => changeBody).not.toBeNull();
  expect(changeBody).toEqual({
    email: 'first-login@example.com',
    current_password: 'Initial password 123!',
    new_password: 'Permanent password 456!',
    authorize_query: 'client_id=first-client',
  });
  await page.waitForURL(/\/authorize\?client_id=first-client$/);
});

test('register ceremony: begin → create → finish (marshaling correct)', async ({ page }) => {
  await addVirtualAuthenticator(page);
  const challenge = b64url(Array.from({ length: 32 }, (_, i) => i + 1));
  let finishBody: Record<string, unknown> | null = null;
  await mockRegister(page, challenge, (b) => {
    finishBody = b;
  });

  await page.goto('/account');
  const prompt = page.getByRole('alert').filter({ hasText: /protect your account|保护你的账户/i });
  await expect(prompt).toBeVisible();
  await prompt.getByRole('button', { name: /add a passkey|添加 passkey/i }).click();

  await expect.poll(() => finishBody).not.toBeNull();
  await expect(page.getByText(/passkey added|passkey 已添加/i)).toBeVisible();
  await expect(prompt).toHaveCount(0);
  await expect(page.getByText(/passkey verification failed|passkey 验证失败/i)).toHaveCount(0);
  const b = finishBody as unknown as { challenge: string; client_data_json: string; attestation_object: string };
  expect(b.challenge).toBe(challenge); // 回传后端下发的 challenge
  expect(b.client_data_json).toMatch(/^[A-Za-z0-9_-]+$/); // base64url 无填充(与后端对齐)
  expect(b.attestation_object).toMatch(/^[A-Za-z0-9_-]+$/);
  // clientDataJSON 解码 = 含 type=webauthn.create 的 JSON(证明真走了 navigator.credentials.create)。
  expect(JSON.parse(b64urlDecodeUtf8(b.client_data_json)).type).toBe('webauthn.create');
});

test('authenticate ceremony: seed cred → begin → get → finish → session', async ({ page }) => {
  const { client, authenticatorId } = await addVirtualAuthenticator(page);

  // 1. 先经注册仪式种一枚 resident credential 到虚拟 authenticator。
  let regFinished = false;
  await mockRegister(page, b64url(Array.from({ length: 32 }, (_, i) => i + 3)), () => {
    regFinished = true;
  });
  await page.goto('/account');
  await page.getByRole('button', { name: /add a passkey|添加 passkey/i }).click();
  await expect.poll(() => regFinished).toBe(true); // register/finish 被调 = 凭证已种

  // 2. 从虚拟 authenticator 读回 credentialId(供 authenticate allowCredentials)。
  const { credentials } = await client.send('WebAuthn.getCredentials', { authenticatorId });
  expect(credentials.length).toBeGreaterThan(0);
  const credId = credentials[0].credentialId; // CDP 返回 base64(标准);前端 b64urlToBuf 容忍标准 b64
  const credIdB64url = credId.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  // 3. mock authenticate begin(allowCredentials 含该凭证)+ finish。
  const authChallenge = b64url(Array.from({ length: 32 }, (_, i) => i + 5));
  let authFinishBody: Record<string, unknown> | null = null;
  await page.route('**/passkey/authenticate/begin**', (r) =>
    r.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        rp_id: RP_ID, challenge: authChallenge,
        allow_credentials: [credIdB64url], user_verification: 'required',
      }),
    }),
  );
  await page.route('**/passkey/authenticate/finish', async (r) => {
    authFinishBody = JSON.parse(r.request().postData() ?? '{}');
    await r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ authenticated: true }) });
  });
  // 续跑目标 /account(无 authorize_query/next);mock 它避免真跳转失败。
  await page.route('**/account', (r) => r.continue());

  // 4. 登录页共用 email 表单,直接提交 passkey → get → finish。
  await page.goto('/login');
  await page.getByLabel(/email|邮箱/i).fill('alice@example.com');
  await page.getByRole('button', { name: /sign in with a passkey|用 passkey 登录/i }).click();

  await expect.poll(() => authFinishBody).not.toBeNull();
  const ab = authFinishBody as unknown as {
    challenge: string; credential_id: string; client_data_json: string;
    authenticator_data: string; signature: string;
  };
  expect(ab.challenge).toBe(authChallenge);
  expect(ab.credential_id).toBe(credIdB64url); // rawId → credential_id
  // clientDataJSON.type = webauthn.get(证明走了 navigator.credentials.get)。
  expect(JSON.parse(b64urlDecodeUtf8(ab.client_data_json)).type).toBe('webauthn.get');
  expect(ab.authenticator_data).toMatch(/^[A-Za-z0-9_-]+$/);
  expect(ab.signature).toMatch(/^[A-Za-z0-9_-]+$/);
});

test('no passkey credential emphasizes magic-link without sending email', async ({ page }) => {
  let magicLinkRequests = 0;
  await page.route('**/passkey/authenticate/begin**', (r) =>
    r.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        rp_id: RP_ID,
        challenge: b64url(Array.from({ length: 32 }, (_, i) => i + 7)),
        allow_credentials: [],
        user_verification: 'required',
      }),
    }),
  );
  await page.route('**/login/magic-link', async (r) => {
    magicLinkRequests += 1;
    await r.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
  });

  await page.goto('/login');
  await page.getByLabel(/email|邮箱/i).fill('no-passkey@example.com');
  await page.getByRole('button', { name: /sign in with a passkey|用 passkey 登录/i }).click();

  await expect(page.getByText(/try the email sign-in link|请改用.*邮箱登录链接/i)).toBeVisible();
  await expect(page.getByRole('button', { name: /send sign-in link|发送登录链接/i })).toBeVisible();
  await expect(page.getByRole('button', { name: /^sign in$|^登录$/i })).toBeVisible();
  expect(magicLinkRequests).toBe(0);
});

test('disabled passkey falls back to magic-link without sending email', async ({ page }) => {
  let magicLinkRequests = 0;
  await page.route('**/passkey/authenticate/begin**', (r) =>
    r.fulfill({ status: 404, contentType: 'text/plain', body: 'passkey not enabled' }),
  );
  await page.route('**/login/magic-link', async (r) => {
    magicLinkRequests += 1;
    await r.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
  });

  await page.goto('/login');
  await page.getByLabel(/email|邮箱/i).fill('alice@example.com');
  await page.getByRole('button', { name: /sign in with a passkey|用 passkey 登录/i }).click();

  await expect(page.getByRole('button', { name: /send sign-in link|发送登录链接/i })).toBeVisible();
  await expect(page.getByRole('button', { name: /^sign in$|^登录$/i })).toBeVisible();
  await expect(page.getByRole('button', { name: /sign in with a passkey|用 passkey 登录/i })).toHaveCount(0);
  expect(magicLinkRequests).toBe(0);
});

test('account strongly prompts passkey enrollment and allows dismissal', async ({ page }) => {
  await page.route('**/grants', (r) =>
    r.fulfill({ status: 200, contentType: 'application/json', body: '[]' }),
  );

  await page.goto('/account');
  const prompt = page.getByRole('alert').filter({ hasText: /protect your account|保护你的账户/i });
  await expect(prompt).toBeVisible();
  await expect(prompt.getByRole('button', { name: /add a passkey|添加 passkey/i })).toBeVisible();
  await prompt.getByRole('button', { name: /not now|稍后设置/i }).click();
  await expect(prompt).toHaveCount(0);
  await expect(page.getByRole('button', { name: /add a passkey|添加 passkey/i })).toBeVisible();
});

test('account with an existing passkey does not show enrollment warning', async ({ page }) => {
  await page.route('**/grants', (r) =>
    r.fulfill({ status: 200, contentType: 'application/json', body: '[]' }),
  );
  await page.route('**/account/credentials', (r) =>
    r.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        passkeys: [{ id: 'existing-handle', name: 'Passkey', created_at: 1_750_000_000 }],
        password_status: 'not_configured',
        password_supported: true,
        recovery_configured: false,
        recovery_codes_remaining: 0,
        reauthenticated: true,
        reauthenticate_after: 1_800_000_000,
      }),
    }),
  );

  await page.goto('/account');
  await expect(page.getByText(/1 passkey.*configured|已配置 1 个 passkey/i)).toBeVisible();
  await expect(page.getByRole('alert').filter({ hasText: /protect your account|保护你的账户/i })).toHaveCount(0);
  await expect(page.getByRole('button', { name: /add a passkey|添加 passkey/i })).toBeVisible();
});

test('passkey status failure is not reported as unconfigured', async ({ page }) => {
  await page.route('**/grants', (r) =>
    r.fulfill({ status: 200, contentType: 'application/json', body: '[]' }),
  );
  await page.route('**/account/credentials', (r) =>
    r.fulfill({ status: 503, contentType: 'text/plain', body: 'store unavailable' }),
  );

  await page.goto('/account');
  await expect(page.getByText(/sign-in methods could not be loaded|无法加载登录方式/i)).toBeVisible();
  await expect(page.getByRole('alert').filter({ hasText: /protect your account|保护你的账户/i })).toHaveCount(0);
});

test('unsupported browser: passkey entry hidden', async ({ page }) => {
  await page.addInitScript(() => {
    // @ts-expect-error 删全局模拟旧浏览器/非安全上下文
    delete window.PublicKeyCredential;
  });
  await page.goto('/login');
  const magicLink = page.getByRole('button', { name: /send sign-in link|发送登录链接/i });
  await expect(magicLink).toBeVisible();
  await expect(magicLink).not.toHaveClass(/ant-btn-primary/);
  await expect(page.getByRole('button', { name: /^sign in$|^登录$/i })).toHaveClass(/ant-btn-primary/);
  await expect(page.getByRole('button', { name: /sign in with a passkey|用 passkey 登录/i })).toHaveCount(0);
});
