import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { chromium } from 'playwright';
import { assertSafeAdminNavigation } from './admin-navigation.mjs';

const required = (name) => {
  const value = process.env[name];
  assert.ok(value, `${name} is required`);
  return value;
};

const readToken = async (name) => {
  const value = (await readFile(required(name), 'utf8')).trim();
  assert.ok(value, `${name} must not be empty`);
  return value;
};

const controlUrl = required('SAAS_CONTROL_URL').replace(/\/$/, '');
const tenantUrls = {
  t1: required('SAAS_T1_URL').replace(/\/$/, ''),
  t2: required('SAAS_T2_URL').replace(/\/$/, ''),
};
const tokens = {
  platform: await readToken('SAAS_PLATFORM_TOKEN_FILE'),
  t1: await readToken('SAAS_T1_TOKEN_FILE'),
  t2: await readToken('SAAS_T2_TOKEN_FILE'),
};

const browser = await chromium.launch({ headless: true });

async function connect(baseUrl, token, viewport = { width: 1440, height: 900 }) {
  const expected = new URL(`${baseUrl}/admin`);
  const context = await browser.newContext({ viewport });
  await context.route('**/*', async (route) => {
    const request = route.request();
    if (
      request.isNavigationRequest() &&
      new URL(request.url()).origin !== expected.origin
    ) {
      await route.abort('blockedbyclient');
      return;
    }
    await route.continue();
  });
  const page = await context.newPage();
  const response = await page.goto(expected.href, { waitUntil: 'domcontentloaded' });
  assert.ok(response, 'live Admin navigation did not return an HTTP response');
  const redirectChain = [];
  for (
    let request = response.request();
    request;
    request = request.redirectedFrom()
  ) {
    redirectChain.push(request.url());
  }
  assertSafeAdminNavigation(expected.href, page.url(), redirectChain.reverse());
  await page.getByLabel(/admin token/i).fill(token);
  await page.getByRole('button', { name: /connect|连接/i }).click();
  return { context, page };
}

try {
  {
    const { context, page } = await connect(controlUrl, tokens.platform);
    await page.getByRole('heading', { name: /tenants|租户/i }).waitFor();
    await page.getByText('t1', { exact: true }).waitFor();
    await page.getByText('t2', { exact: true }).waitFor();
    assert.equal(await page.getByRole('tab').count(), 0);
    assert.equal(
      await page.getByRole('button', { name: /edit|delete|create|编辑|删除|创建/i }).count(),
      0,
    );
    assert.equal(await page.getByRole('button', { name: /copy|复制/i }).count(), 2);
    await context.close();
    console.log('PASS: live desktop control mode is read-only');
  }

  for (const tenant of ['t1', 't2']) {
    const { context, page } = await connect(tenantUrls[tenant], tokens[tenant]);
    await page
      .getByRole('tab', { name: /dashboard|overview|仪表盘|概览/i })
      .waitFor();
    assert.equal(await page.getByRole('heading', { name: /tenants|租户/i }).count(), 0);
    await context.close();
  }
  console.log('PASS: live t1 and t2 tenant modes do not enter control mode');

  {
    const { context, page } = await connect(controlUrl, tokens.t1);
    await page.getByText(/token rejected|token 被拒绝/i).waitFor();
    assert.equal(await page.getByRole('tab').count(), 0);
    assert.equal(await page.getByRole('heading', { name: /tenants|租户/i }).count(), 0);
    await context.close();
    console.log('PASS: live tenant credential cannot fall back on the control host');
  }

  {
    const { context, page } = await connect(
      controlUrl,
      tokens.platform,
      { width: 390, height: 844 },
    );
    const list = page.getByTestId('control-tenant-list');
    await list.waitFor();
    await list.getByText('t1', { exact: true }).waitFor();
    await list.getByText('t2', { exact: true }).waitFor();
    const arns = list.getByText(/^arn:aws:secretsmanager:/);
    assert.equal(await arns.count(), 2);
    assert.equal(await list.getByRole('button', { name: /copy|复制/i }).count(), 2);
    for (const arn of await arns.all()) {
      const fits = await arn.evaluate((element) => {
        const own = element.getBoundingClientRect();
        const parent = element.parentElement?.getBoundingClientRect();
        return (
          !!parent &&
          own.left >= parent.left &&
          own.right <= parent.right + 1 &&
          own.left >= 0 &&
          own.right <= window.innerWidth + 1 &&
          document.documentElement.scrollWidth <= window.innerWidth + 1
        );
      });
      assert.equal(fits, true, 'mobile Secret ARN must fit its field');
    }
    await context.close();
    console.log('PASS: live mobile control mode renders both long Secret ARNs without overlap');
  }
} finally {
  await browser.close();
}
