import { defineConfig, devices } from '@playwright/test';

// Playwright e2e(spec 003 §3.9 passkey 前端仪式)。Chromium only(CDP WebAuthn 虚拟 authenticator)。
// webServer 自动起 Vite dev(前端);后端由测试用 page.route mock(测前端仪式 + marshaling,后端链
// 已由 3.8 Rust 进程内 e2e 覆盖)。真机全链验证走部署环境,非本地 CI。
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'line' : 'list',
  use: {
    baseURL: 'http://localhost:5173',
    trace: 'on-first-retry',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    {
      name: 'mobile-chrome',
      testMatch: /account-credentials\.spec\.ts/,
      use: { ...devices['Pixel 5'] },
    },
  ],
  webServer: process.env.PLAYWRIGHT_EXTERNAL_WEB_SERVER
    ? undefined
    : {
        command: 'npm run dev',
        url: 'http://127.0.0.1:5173',
        reuseExistingServer: !process.env.CI,
        timeout: 60_000,
      },
});
