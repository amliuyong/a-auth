import assert from 'node:assert/strict';
import https from 'node:https';
import { readFile } from 'node:fs/promises';
import { once } from 'node:events';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { createApp } from '../../server.mjs';

const keys = await generateKeyPair('RS256');
const jwk = { ...await exportJWK(keys.publicKey), kid: 'controlled-key', alg: 'RS256', use: 'sig' };
const counts = { discovery: 0, jwks: 0 };
let metadata;
const issuerServer = https.createServer({
  cert: await readFile(process.argv[2]), key: await readFile(process.argv[3]),
}, (request, response) => {
  let body;
  if (request.url === '/.well-known/openid-configuration') {
    counts.discovery++;
    body = metadata;
  } else if (request.url === '/jwks') {
    counts.jwks++;
    body = { keys: [jwk] };
  } else {
    response.writeHead(404).end();
    return;
  }
  response.setHeader('content-type', 'application/json');
  response.end(JSON.stringify(body));
}).listen(0, '127.0.0.1');
await once(issuerServer, 'listening');
const issuer = `https://127.0.0.1:${issuerServer.address().port}`;
const resource = 'https://rs.example.com/mcp';
metadata = {
  issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`,
  jwks_uri: `${issuer}/jwks`, registration_endpoint: `${issuer}/register`,
  response_types_supported: ['code'], grant_types_supported: ['authorization_code'],
  code_challenge_methods_supported: ['S256'], scopes_supported: ['kb:read', 'offline_access'],
};
const server = createApp({ issuer, resource }).listen(0, '127.0.0.1');
await once(server, 'listening');
const base = `http://127.0.0.1:${server.address().port}`;
const call = async (token, message = {
  jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'fixture_echo', arguments: {} },
}) => fetch(`${base}/mcp`, {
  method: 'POST',
  headers: {
    'content-type': 'application/json', accept: 'application/json, text/event-stream',
    'mcp-protocol-version': '2025-03-26', ...(token ? { authorization: `Bearer ${token}` } : {}),
  },
  body: JSON.stringify(message),
});
const now = Math.floor(Date.now() / 1000);
const sign = (overrides = {}, key = keys.privateKey) => new SignJWT({
  iss: issuer, sub: 'controlled-user', aud: resource, scope: 'kb:read',
  iat: now, exp: now + 300, ...overrides,
}).setProtectedHeader({ alg: 'RS256', kid: 'controlled-key' }).sign(key);
try {
  assert.equal((await call()).status, 401);
  assert.deepEqual(counts, { discovery: 0, jwks: 0 });
  const wrongIssuer = await call(await sign({ iss: 'https://untrusted.example.com' }));
  assert.equal(wrongIssuer.status, 401);
  assert.deepEqual(counts, { discovery: 0, jwks: 0 });

  const response = await fetch(`${base}/.well-known/oauth-protected-resource/mcp`);
  assert.equal(response.status, 200);
  const prm = await response.json();
  assert.equal(prm.resource, resource);
  assert.deepEqual(prm.authorization_servers, [issuer]);
  assert.deepEqual(prm.scopes_supported, ['kb:read', 'offline_access']);

  const otherKeys = await generateKeyPair('RS256');
  for (const token of [
    await sign({ aud: 'https://wrong.example.com/mcp' }),
    await sign({ exp: now - 60 }),
    await sign({ exp: undefined }),
    await sign({ sub: '' }),
    await sign({}, otherKeys.privateKey),
    ...await Promise.all([{ jkt: 'controlled' }, {}, null].map(cnf => sign({ cnf }))),
  ]) {
    const rejected = await call(token);
    assert.equal(rejected.status, 401);
    assert.match(rejected.headers.get('www-authenticate'), /invalid_token/);
  }
  assert.equal((await call(await sign({ scope: 'other:read' }))).status, 403);
  const accepted = await call(await sign());
  assert.equal(accepted.status, 200);
  const body = await accepted.text();
  assert.ok(body.includes('controlled-fixture-ok'));
  assert.ok(!body.includes('"isError":true'));
  assert.ok(counts.jwks > 0);

  const checker = fileURLToPath(new URL('../../check-provider.mjs', import.meta.url));
  const run = promisify(execFile);
  const result = await run(process.execPath, [checker], { env: { ...process.env, ISSUER: issuer } });
  assert.equal(JSON.parse(result.stdout).isValid, true);
  metadata = { ...metadata, code_challenge_methods_supported: ['plain'] };
  await assert.rejects(run(process.execPath, [checker], {
    env: { ...process.env, ISSUER: issuer },
  }), error => error.code === 1 && JSON.parse(error.stdout).isValid === false);
  console.log('PASS controlled TLS discovery, JWT boundaries and tool call');
} finally {
  await Promise.all([server, issuerServer].map(listener => new Promise(resolve => listener.close(resolve))));
}
