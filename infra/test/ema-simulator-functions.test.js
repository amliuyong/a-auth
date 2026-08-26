const assert = require('node:assert/strict');
const {
  generateKeyPairSync,
  sign,
  verify,
} = require('node:crypto');
const path = require('node:path');
const test = require('node:test');
const { pathToFileURL } = require('node:url');

const issuerModule = import(
  pathToFileURL(
    path.resolve(
      __dirname,
      '../functions/ema-simulator/issuer.mjs',
    ),
  ).href
);
const rsModule = import(
  pathToFileURL(
    path.resolve(__dirname, '../functions/ema-simulator/rs.mjs'),
  ).href
);

function compactJwt(header, claims, privateKey, algorithm, dsaEncoding) {
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encodedClaims = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const input = `${encodedHeader}.${encodedClaims}`;
  const signature = sign(algorithm, Buffer.from(input), {
    key: privateKey,
    ...(dsaEncoding ? { dsaEncoding } : {}),
  });
  return `${input}.${signature.toString('base64url')}`;
}

function event(method, rawPath, body, authorization) {
  return {
    rawPath,
    headers: {
      ...(body
        ? { 'content-type': 'application/x-www-form-urlencoded' }
        : {}),
      ...(authorization ? { authorization } : {}),
    },
    body,
    requestContext: { http: { method, path: rawPath } },
  };
}

test('issuer converts a DER P-256 signature to JWT P1363', async () => {
  const { derToP1363 } = await issuerModule;
  const { privateKey, publicKey } = generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  });
  const message = Buffer.from('ema-simulator');
  const der = sign('sha256', message, privateKey);
  const raw = derToP1363(der);
  assert.equal(raw.length, 64);
  assert.equal(
    verify(
      'sha256',
      message,
      { key: publicKey, dsaEncoding: 'ieee-p1363' },
      raw,
    ),
    true,
  );
});

test('issuer authenticates a Cognito user and emits a strict ID-JAG', async () => {
  const { createHandler } = await issuerModule;
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const cognitoJwk = rsa.publicKey.export({ format: 'jwk' });
  const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const publicJwk = ec.publicKey.export({ format: 'jwk' });
  const now = 2_000_000_000;
  const cognitoToken = compactJwt(
    { alg: 'RS256', kid: 'cognito-key' },
    {
      iss: 'https://cognito.example/pool',
      aud: 'source-client',
      token_use: 'id',
      sub: 'cognito-user',
      iat: now - 10,
      exp: now + 600,
    },
    rsa.privateKey,
    'RSA-SHA256',
  );
  const handler = createHandler({
    config: {
      issuer: 'https://issuer.example',
      resource: 'https://rs.example',
      assertionClientId: 'enterprise-client',
      cognitoIssuer: 'https://cognito.example/pool',
      cognitoClientId: 'source-client',
      kmsKeyId: 'kms-key',
      allowedAudiences: new Set(['https://auth.example']),
      allowedScopes: new Set(['mcp:read']),
    },
    dependencies: {
      now: () => now,
      loadBroker: async () => ({
        client_id: 'broker',
        client_secret: 'secret',
      }),
      loadCognitoJwks: async () => ({
        keys: [
          {
            ...cognitoJwk,
            alg: 'RS256',
            use: 'sig',
            kid: 'cognito-key',
          },
        ],
      }),
      loadPublicJwk: async () => ({
        ...publicJwk,
        alg: 'ES256',
        use: 'sig',
        kid: 'kms-key',
      }),
      sign: async (message) =>
        sign('sha256', Buffer.from(message), {
          key: ec.privateKey,
          dsaEncoding: 'ieee-p1363',
        }),
    },
  });
  const authorization = `Basic ${Buffer.from('broker:secret').toString(
    'base64',
  )}`;
  const form = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
    requested_token_type: 'urn:ietf:params:oauth:token-type:id-jag',
    subject_token: cognitoToken,
    audience: 'https://auth.example',
    resource: 'https://rs.example',
    scope: 'mcp:read',
  }).toString();

  const result = await handler(event('POST', '/token', form, authorization));
  assert.equal(result.statusCode, 200);
  assert.equal(result.headers['cache-control'], 'no-store');
  const payload = JSON.parse(result.body);
  const [encodedHeader, encodedClaims, encodedSignature] =
    payload.access_token.split('.');
  assert.deepEqual(
    JSON.parse(Buffer.from(encodedHeader, 'base64url')),
    {
      alg: 'ES256',
      typ: 'oauth-id-jag+jwt',
      kid: 'kms-key',
    },
  );
  const claims = JSON.parse(Buffer.from(encodedClaims, 'base64url'));
  assert.equal(claims.iss, 'https://issuer.example');
  assert.equal(claims.sub, 'cognito-user');
  assert.equal(claims.aud, 'https://auth.example');
  assert.equal(claims.client_id, 'enterprise-client');
  assert.equal(claims.resource, 'https://rs.example');
  assert.equal(claims.scope, 'mcp:read');
  assert.equal(claims.exp - claims.iat, 300);
  assert.equal(
    verify(
      'sha256',
      Buffer.from(`${encodedHeader}.${encodedClaims}`),
      { key: ec.publicKey, dsaEncoding: 'ieee-p1363' },
      Buffer.from(encodedSignature, 'base64url'),
    ),
    true,
  );

  const badClient = await handler(
    event(
      'POST',
      '/token',
      form,
      `Basic ${Buffer.from('broker:wrong').toString('base64')}`,
    ),
  );
  assert.equal(badClient.statusCode, 401);
  assert.equal(JSON.parse(badClient.body).error, 'invalid_client');

  const wrongAudience = new URLSearchParams(form);
  wrongAudience.set('audience', 'https://other.example');
  const rejected = await handler(
    event('POST', '/token', wrongAudience.toString(), authorization),
  );
  assert.equal(rejected.statusCode, 400);
  assert.equal(JSON.parse(rejected.body).error, 'invalid_target');
});

test('resource server proves 401, scoped 2xx, and insufficient-scope 403', async () => {
  const { createHandler } = await rsModule;
  const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const publicJwk = ec.publicKey.export({ format: 'jwk' });
  const now = 2_000_000_000;
  const accessToken = compactJwt(
    { alg: 'ES256', typ: 'at+jwt', kid: 'agent-auth-key' },
    {
      iss: 'https://auth.example',
      sub: 'enterprise-user',
      aud: 'https://rs.example',
      client_id: 'agent-auth-client',
      jti: 'token-1',
      scope: 'mcp:read',
      iat: now - 10,
      exp: now + 300,
    },
    ec.privateKey,
    'sha256',
    'ieee-p1363',
  );
  const handler = createHandler({
    config: {
      resource: 'https://rs.example',
      allowedIssuers: new Set(['https://auth.example']),
    },
    dependencies: {
      now: () => now,
      loadJwks: async () => ({
        keys: [
          {
            ...publicJwk,
            alg: 'ES256',
            use: 'sig',
            kid: 'agent-auth-key',
          },
        ],
      }),
    },
  });

  const unauthenticated = await handler(event('GET', '/allow'));
  assert.equal(unauthenticated.statusCode, 401);
  assert.match(
    unauthenticated.headers['www-authenticate'],
    /invalid_token/,
  );

  const authorization = `Bearer ${accessToken}`;
  const allowed = await handler(
    event('GET', '/allow', undefined, authorization),
  );
  assert.equal(allowed.statusCode, 200);
  assert.deepEqual(JSON.parse(allowed.body), { ok: true });

  const denied = await handler(
    event('GET', '/deny', undefined, authorization),
  );
  assert.equal(denied.statusCode, 403);
  assert.match(denied.headers['www-authenticate'], /scope="mcp:write"/);

  const tamperedParts = accessToken.split('.');
  const tamperedSignature = Buffer.from(tamperedParts[2], 'base64url');
  tamperedSignature[0] ^= 0x01;
  tamperedParts[2] = tamperedSignature.toString('base64url');
  const tampered = tamperedParts.join('.');
  const invalid = await handler(
    event('GET', '/allow', undefined, `Bearer ${tampered}`),
  );
  assert.equal(invalid.statusCode, 401);
});
