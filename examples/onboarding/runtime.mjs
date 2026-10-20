// Internal example helpers, not a reusable or published OAuth client SDK.
import { readFile, open, rename } from 'node:fs/promises';
import { resolve } from 'node:path';
import * as oauth from 'oauth4webapi';

export async function configuration() {
  const config = JSON.parse(await readFile(process.env.A_AUTH_EXAMPLE_CONFIG ?? 'config.json', 'utf8'));
  return validateConfiguration(config);
}

export function validateConfiguration(config) {
  if (typeof config.issuer !== 'string' || typeof config.resource !== 'string' ||
      typeof config.scope !== 'string' || !config.scope.trim()) throw new Error('Public configuration is incomplete');
  if (config.resource_metadata_url !== undefined && typeof config.resource_metadata_url !== 'string') {
    throw new Error('Resource metadata URL must be a string');
  }
  const urls = [config.issuer, config.resource];
  if (config.resource_metadata_url !== undefined) urls.push(config.resource_metadata_url);
  for (const value of urls) {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.username || url.password || url.hash ||
        /\.lambda-url\.[a-z0-9-]+\.on\.aws\.?$/i.test(url.hostname)) {
      throw new Error('Public endpoints require HTTPS, no userinfo/fragment and no Lambda Function URL');
    }
  }
  return config;
}

export async function authorizationServer(config) {
  const issuer = new URL(config.issuer);
  return oauth.processDiscoveryResponse(issuer, await oauth.discoveryRequest(issuer));
}

export async function savePrivate(filename, value) {
  const temporary = resolve(filename) + '.' + process.pid;
  const file = await open(temporary, 'wx', 0o600);
  try { await file.writeFile(JSON.stringify(value)); }
  finally { await file.close(); }
  await rename(temporary, filename);
}

export async function privateSession(filename = '.session.json') {
  const file = await open(filename, 'r');
  try {
    if ((await file.stat()).mode & 0o077) throw new Error('Credential file must be private (mode 0600)');
    const stored = JSON.parse(await file.readFile('utf8'));
    if (!stored.tokens?.access_token) throw new Error('Credential file has no access token');
    return stored;
  } finally { await file.close(); }
}

export function summary(flow, started, extra = {}) {
  console.log(JSON.stringify({ flow, result: 'PASS', elapsed_seconds: (Date.now() - started) / 1000, ...extra }));
}

export function fail(flow, error) {
  // HTTP/OAuth errors can contain credential-bearing responses. Print no bodies
  // or exception message; a stopped command is not a completed integration.
  console.error(JSON.stringify({ flow, result: 'FAIL', failure_type: error.name }));
  process.exitCode = 1;
}
