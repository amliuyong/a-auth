import { readFile, readdir } from 'node:fs/promises';
import vm from 'node:vm';

const dist = new URL('../dist/', import.meta.url);
const html = await readFile(new URL('index.html', dist), 'utf8');
const assets = await readdir(new URL('assets/', dist));

function requireBundle(condition, message) {
  if (!condition) {
    throw new Error(`OIDF BrowserControl bundle check failed: ${message}`);
  }
}

requireBundle(html.includes('type="module"'), 'modern module entry is missing');
requireBundle(html.includes('id="vite-legacy-polyfill"'), 'legacy polyfill entry is missing');
requireBundle(html.includes('id="vite-legacy-entry"'), 'legacy application entry is missing');
requireBundle(html.includes('System.import'), 'legacy SystemJS bootstrap is missing');

const legacyEntries = assets.filter((name) => /^index-legacy-[A-Za-z0-9_-]+\.js$/.test(name));
const polyfillEntries = assets.filter((name) =>
  /^polyfills-legacy-[A-Za-z0-9_-]+\.js$/.test(name),
);
requireBundle(legacyEntries.length === 1, 'expected exactly one legacy application bundle');
requireBundle(polyfillEntries.length === 1, 'expected exactly one legacy polyfill bundle');

const polyfills = await readFile(
  new URL(`assets/${polyfillEntries[0]}`, dist),
  'utf8',
);
requireBundle(polyfills.includes('XMLHttpRequest'), 'Fetch transport polyfill is missing');
requireBundle(polyfills.includes('fetch'), 'Fetch API polyfill is missing');

const legacyEntry = await readFile(
  new URL(`assets/${legacyEntries[0]}`, dist),
  'utf8',
);
requireBundle(legacyEntry.includes('System.register'), 'legacy SystemJS module is missing');
for (const marker of [
  'agent-auth-login-email',
  'agent-auth-login-password',
  'agent-auth-login-submit',
  'agent-auth-consent-ready',
  'agent-auth-consent-approve',
]) {
  requireBundle(legacyEntry.includes(marker), `legacy application is missing ${marker}`);
}
requireBundle(
  html.includes(`data-src="/assets/${legacyEntries[0]}"`),
  'legacy entry is not wired into the HTML bootstrap',
);
try {
  new vm.Script(legacyEntry, { filename: legacyEntries[0] });
} catch (error) {
  throw new Error(`OIDF BrowserControl bundle check failed: legacy entry is invalid: ${error}`);
}
