// Run from an independent project after installing the actual npm tarball.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import {
  RsSdk, NAMESPACE, RAR_TYPE_V1, enforceRar, computeAth, computeJkt, verifyDpopProof,
} from '@amliuyong/a-auth';
import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from 'jose';

const issuer = 'https://issuer.example';
const resource = 'https://resource.example/mcp';
const { privateKey, publicKey } = await generateKeyPair('ES256');
const jwk = await exportJWK(publicKey);
Object.assign(jwk, { kid: await calculateJwkThumbprint(jwk), alg: 'ES256', use: 'sig' });
const sdk = new RsSdk({ issuer, resourceId: resource });
sdk.seedJwks({ keys: [jwk] });
const now = Math.floor(Date.now() / 1000);
async function token(overrides = {}) {
  return new SignJWT({
    iss: issuer, aud: [resource], sub: 'synthetic-subject', client_id: 'synthetic-client',
    scope: 'read', iat: now, exp: now + 300,
    [NAMESPACE]: { sub_type: 'user', auth_grant: 'synthetic-grant' }, ...overrides,
  }).setProtectedHeader({ typ: 'at+jwt', alg: 'ES256', kid: jwk.kid }).sign(privateKey);
}
const server = createServer(async (request, response) => {
  const result = await sdk.authenticate(request.headers.authorization, {
    requireSubType: 'user', requireScopes: ['read'],
  });
  response.writeHead(result.ok ? 200 : result.status, result.ok ? {} : result.headers);
  response.end(result.ok ? 'protected resource' : '');
});
server.listen(0, '127.0.0.1');
await once(server, 'listening');
try {
  const url = `http://127.0.0.1:${server.address().port}/protected`;
  const valid = await token();
  for (const [jwt, status] of [
    [valid, 200], [await token({ iss: 'https://wrong.example' }), 401],
    [await token({ aud: ['https://wrong.example'] }), 401],
    [await token({ scope: 'unrelated' }), 403],
    [await token({ authorization_details: [{ type: 'agent_auth_grant_summary_v1' }] }), 403],
  ]) {
    const response = await fetch(url, { headers: { Authorization: `Bearer ${jwt}` } });
    assert.equal(response.status, status);
    if (status !== 200) assert.match(response.headers.get('www-authenticate'), /resource_metadata=/);
  }
  assert.equal((await fetch(url)).status, 401);
  const rar = [{ type: RAR_TYPE_V1, resource_subset: [resource], max_records: 1 }];
  assert.equal(enforceRar(rar, { resource, declaredCount: 1 }).allowed, true);
  assert.equal(enforceRar(rar, { resource, declaredCount: 2 }).allowed, false);
  assert.equal(enforceRar([{ type: 'unknown-policy' }], { resource }).allowed, false);
  const proof = await new SignJWT({
    htm: 'GET', htu: resource, iat: now, jti: 'synthetic-proof', ath: await computeAth(valid),
  }).setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk }).sign(privateKey);
  const jkt = await computeJkt(jwk);
  assert.equal((await verifyDpopProof(proof, jkt, 'GET', resource, { accessToken: valid })).jti, 'synthetic-proof');
  await assert.rejects(verifyDpopProof(proof, jkt, 'POST', resource, { accessToken: valid }));
  await assert.rejects(verifyDpopProof(proof, 'wrong-thumbprint', 'GET', resource, { accessToken: valid }));
  await assert.rejects(verifyDpopProof(proof, jkt, 'GET', resource, { accessToken: 'different-token' }));
  console.log(JSON.stringify({ result: 'PASS', runtime: process.version, protected_http_cases: 6, rar_cases: 3, dpop_cases: 4 }));
} finally {
  await new Promise((resolve) => server.close(resolve));
}
