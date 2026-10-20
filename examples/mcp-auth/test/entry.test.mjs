import assert from 'node:assert/strict';
import { test } from 'node:test';
import { once } from 'node:events';
import express from 'express';
import { createApp, rejectSenderBoundToken } from '../server.mjs';

test('entry rejects Lambda Function URLs before any discovery or listener', () => {
  const forbidden = 'https://fixture.lambda-url.us-east-1.on.aws';
  assert.throws(() => createApp({ issuer: forbidden, resource: 'https://rs.example.com/mcp' }));
  assert.throws(() => createApp({ issuer: 'https://auth.example.com', resource: `${forbidden}/mcp` }));
});

test('actual third-party middleware exposes bound PRM and rejects anonymous MCP calls', async () => {
  const resource = 'https://rs.example.com/mcp';
  const server = createApp({ issuer: 'https://auth.example.com', resource }).listen(0, '127.0.0.1');
  await once(server, 'listening');
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const response = await fetch(`${base}/mcp`, { method: 'POST' });
    assert.equal(response.status, 401);
    assert.match(response.headers.get('www-authenticate'), /resource_metadata=/);
    const metadata = await fetch(`${base}/.well-known/oauth-protected-resource/mcp`);
    assert.equal(metadata.status, 200);
    const body = await metadata.json();
    assert.equal(body.resource, resource);
    assert.deepEqual(body.authorization_servers, ['https://auth.example.com']);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('post-verification policy blocks sender-bound tokens before business actions', async () => {
  const app = express();
  app.use(express.json());
  // Synthetic, already-verified claims isolate the downstream policy seam.
  // This test does not claim cryptographic or actual AS/DPoP interoperability.
  app.use((request, _response, next) => {
    request.auth = { claims: request.body };
    next();
  });
  let calls = 0;
  app.post('/', rejectSenderBoundToken, (_request, response) => {
    calls++;
    response.sendStatus(200);
  });
  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const url = `http://127.0.0.1:${server.address().port}/`;
  try {
    for (const claims of [{ cnf: { jkt: 'synthetic-key' } }, { cnf: {} }, { cnf: null }]) {
      const response = await fetch(url, {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(claims),
      });
      assert.equal(response.status, 401);
      assert.equal(calls, 0);
    }
    const control = await fetch(url, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
    });
    assert.equal(control.status, 200);
    assert.equal(calls, 1);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
