import fs from 'node:fs';
import { chromium } from '@playwright/test';

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

const mode = process.argv[2];
const baseUrl = required('API_URL').replace(/\/+$/, '');
const outputFile = required('OUTPUT_FILE');

if (!['issue', 'accept'].includes(mode)) {
  throw new Error('mode must be issue or accept');
}

const browser = await chromium.launch();
try {
  if (mode === 'issue') {
    const adminToken = required('ADMIN_TOKEN');
    const email = required('EMAIL');
    const context = await browser.newContext({
      permissions: ['clipboard-read', 'clipboard-write'],
    });
    const page = await context.newPage();
    await page.addInitScript((token) => {
      sessionStorage.setItem('agent-auth-admin-token', token);
    }, adminToken);
    await page.goto(`${baseUrl}/admin?tab=users`);

    await page.getByRole('button', { name: /create user|创建用户/i }).click();
    const createDialog = page.getByRole('dialog');
    await createDialog.getByLabel(/email|邮箱/i).fill(email);
    await createDialog.getByText(/one-time invitation|一次性邀请链接/i).click();
    const issued = page.waitForResponse((response) => {
      const url = new URL(response.url());
      return response.request().method() === 'POST'
        && url.pathname === '/admin/users'
        && response.status() === 201;
    });
    await createDialog.getByRole('button', { name: /^save$|^保存$/i }).click();
    const body = await (await issued).json();

    const invitationDialog = page.getByRole('dialog');
    const invitationUrl = await invitationDialog
      .getByLabel(/invitation URL|邀请链接/i)
      .inputValue();
    if (body.invitation?.invitation_url !== invitationUrl) {
      throw new Error('show-once invitation URL does not match the API response');
    }
    const parsed = new URL(invitationUrl);
    if (parsed.origin !== new URL(baseUrl).origin || parsed.pathname !== '/invite') {
      throw new Error('invitation URL does not target the deployed /invite page');
    }
    if (parsed.search) throw new Error('invitation bearer appeared in the query string');
    const token = new URLSearchParams(parsed.hash.slice(1)).get('token');
    const match = token?.match(/^([A-Za-z0-9_-]{43})\.([A-Za-z0-9_-]{43})$/);
    if (!match) throw new Error('invitation bearer format is invalid');

    await invitationDialog
      .getByRole('button', { name: /copy invitation URL|复制邀请链接/i })
      .click();
    const copied = await page.evaluate(() => navigator.clipboard.readText());
    if (copied !== invitationUrl) throw new Error('clipboard does not contain the invitation URL');

    fs.writeFileSync(
      outputFile,
      JSON.stringify({
        email,
        invitation_url: invitationUrl,
        token,
        locator: match[1],
        secret: match[2],
        expires_at: body.invitation.expires_at,
      }),
      { mode: 0o600 },
    );

    await invitationDialog.getByRole('button', { name: /^dismiss$|^关闭$/i }).click();
    await page.getByRole('button', { name: /discard URL|丢弃链接/i }).click();
    await page
      .getByLabel(/invitation URL|邀请链接/i)
      .waitFor({ state: 'detached' });
    await context.close();
  } else {
    const state = JSON.parse(fs.readFileSync(outputFile, 'utf8'));
    const context = await browser.newContext();
    const page = await context.newPage();
    await page.goto(state.invitation_url);
    if (new URL(page.url()).search) {
      throw new Error('recipient navigation sent the bearer in the query string');
    }
    await page.getByRole('button', { name: /accept invitation|接受邀请/i }).click();
    await page.waitForURL(`${baseUrl}/account`);
    const session = (await context.cookies()).find(
      (cookie) => cookie.name === '__Host-agent_auth_session',
    );
    if (!session?.value) throw new Error('invitation acceptance did not set a host-only session');
    fs.writeFileSync(
      outputFile,
      JSON.stringify({ ...state, session_id: session.value }),
      { mode: 0o600 },
    );
    await context.close();
  }
} finally {
  await browser.close();
}
