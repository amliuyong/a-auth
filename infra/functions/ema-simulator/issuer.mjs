import {
  createHash,
  createPublicKey,
  randomUUID,
  timingSafeEqual,
  verify,
} from 'node:crypto';

const TOKEN_EXCHANGE_GRANT =
  'urn:ietf:params:oauth:grant-type:token-exchange';
const ID_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:id_token';
const ID_JAG_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:id-jag';
const JWT_TYPE = 'urn:ietf:params:oauth:token-type:jwt';
const MAX_BODY_BYTES = 128 * 1024;
const MAX_JWT_BYTES = 128 * 1024;
const MAX_JWKS_BYTES = 128 * 1024;
const ID_JAG_LIFETIME_SECS = 300;

const base64Url = (value) =>
  Buffer.from(value).toString('base64url');

function response(statusCode, body, extraHeaders = {}) {
  return {
    statusCode,
    headers: {
      'cache-control': 'no-store',
      pragma: 'no-cache',
      'content-type': 'application/json',
      ...extraHeaders,
    },
    body: JSON.stringify(body),
  };
}

class OAuthError extends Error {
  constructor(error, statusCode = 400) {
    super(error);
    this.error = error;
    this.statusCode = statusCode;
  }
}

function requiredConfig(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

function parseJsonObject(raw) {
  const parsed = JSON.parse(raw);
  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
    throw new Error('expected a JSON object');
  }
  return parsed;
}

function secureEqual(left, right) {
  const leftHash = createHash('sha256').update(left).digest();
  const rightHash = createHash('sha256').update(right).digest();
  return timingSafeEqual(leftHash, rightHash);
}

function parseBasicAuthorization(headers) {
  const raw = headers?.authorization ?? headers?.Authorization;
  if (typeof raw !== 'string' || !raw.startsWith('Basic ')) {
    throw new OAuthError('invalid_client', 401);
  }
  const encoded = raw.slice(6);
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) {
    throw new OAuthError('invalid_client', 401);
  }
  let decoded;
  try {
    decoded = Buffer.from(encoded, 'base64').toString('utf8');
  } catch {
    throw new OAuthError('invalid_client', 401);
  }
  const separator = decoded.indexOf(':');
  if (separator <= 0) {
    throw new OAuthError('invalid_client', 401);
  }
  return [decoded.slice(0, separator), decoded.slice(separator + 1)];
}

function parseForm(event) {
  const contentType =
    event.headers?.['content-type'] ?? event.headers?.['Content-Type'] ?? '';
  if (!contentType.toLowerCase().startsWith('application/x-www-form-urlencoded')) {
    throw new OAuthError('invalid_request');
  }
  const encodedBody = event.body ?? '';
  const body = event.isBase64Encoded
    ? Buffer.from(encodedBody, 'base64').toString('utf8')
    : encodedBody;
  if (Buffer.byteLength(body) > MAX_BODY_BYTES) {
    throw new OAuthError('invalid_request');
  }
  return new URLSearchParams(body);
}

function singleParameter(form, name) {
  const values = form.getAll(name);
  if (values.length !== 1 || !values[0]) {
    throw new OAuthError('invalid_request');
  }
  return values[0];
}

function splitJwt(token) {
  if (
    typeof token !== 'string' ||
    !token ||
    Buffer.byteLength(token) > MAX_JWT_BYTES ||
    /\s/.test(token)
  ) {
    throw new OAuthError('invalid_grant');
  }
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((part) => !part)) {
    throw new OAuthError('invalid_grant');
  }
  try {
    const header = parseJsonObject(
      Buffer.from(parts[0], 'base64url').toString('utf8'),
    );
    const claims = parseJsonObject(
      Buffer.from(parts[1], 'base64url').toString('utf8'),
    );
    const signature = Buffer.from(parts[2], 'base64url');
    if (!signature.length) {
      throw new Error('empty signature');
    }
    return {
      header,
      claims,
      signingInput: `${parts[0]}.${parts[1]}`,
      signature,
    };
  } catch {
    throw new OAuthError('invalid_grant');
  }
}

function validateCognitoIdToken(token, jwks, config, now) {
  const parsed = splitJwt(token);
  if (
    parsed.header.alg !== 'RS256' ||
    typeof parsed.header.kid !== 'string' ||
    !parsed.header.kid ||
    Object.hasOwn(parsed.header, 'crit')
  ) {
    throw new OAuthError('invalid_grant');
  }
  const matches = (jwks.keys ?? []).filter(
    (key) =>
      key &&
      key.kty === 'RSA' &&
      key.kid === parsed.header.kid &&
      (key.alg === undefined || key.alg === 'RS256') &&
      key.use === 'sig',
  );
  if (matches.length !== 1) {
    throw new OAuthError('invalid_grant');
  }
  let key;
  try {
    key = createPublicKey({ key: matches[0], format: 'jwk' });
  } catch {
    throw new OAuthError('invalid_grant');
  }
  if (
    !verify(
      'RSA-SHA256',
      Buffer.from(parsed.signingInput),
      key,
      parsed.signature,
    )
  ) {
    throw new OAuthError('invalid_grant');
  }

  const claims = parsed.claims;
  if (
    claims.iss !== config.cognitoIssuer ||
    claims.aud !== config.cognitoClientId ||
    claims.token_use !== 'id' ||
    typeof claims.sub !== 'string' ||
    !claims.sub ||
    !Number.isInteger(claims.exp) ||
    claims.exp <= now ||
    !Number.isInteger(claims.iat) ||
    claims.iat > now + 60
  ) {
    throw new OAuthError('invalid_grant');
  }
  return claims;
}

function parseScope(raw, allowedScopes) {
  const requested = raw.split(' ').filter(Boolean);
  if (
    requested.length === 0 ||
    new Set(requested).size !== requested.length ||
    requested.some((scope) => !allowedScopes.has(scope))
  ) {
    throw new OAuthError('invalid_scope');
  }
  return requested;
}

function readDerLength(buffer, offset) {
  const first = buffer[offset];
  if (first < 0x80) {
    return { length: first, next: offset + 1 };
  }
  const count = first & 0x7f;
  if (count === 0 || count > 2 || offset + 1 + count > buffer.length) {
    throw new Error('invalid DER length');
  }
  let length = 0;
  for (let index = 0; index < count; index += 1) {
    length = (length << 8) | buffer[offset + 1 + index];
  }
  return { length, next: offset + 1 + count };
}

function readDerInteger(buffer, offset) {
  if (buffer[offset] !== 0x02) {
    throw new Error('invalid DER integer');
  }
  const { length, next } = readDerLength(buffer, offset + 1);
  const end = next + length;
  if (length === 0 || end > buffer.length) {
    throw new Error('invalid DER integer length');
  }
  let value = buffer.subarray(next, end);
  if ((value[0] & 0x80) !== 0) {
    throw new Error('negative DER integer');
  }
  while (value.length > 32 && value[0] === 0) {
    value = value.subarray(1);
  }
  if (value.length > 32) {
    throw new Error('invalid P-256 integer');
  }
  return { value, next: end };
}

export function derToP1363(signature) {
  const buffer = Buffer.from(signature);
  if (buffer[0] !== 0x30) {
    throw new Error('invalid DER sequence');
  }
  const sequence = readDerLength(buffer, 1);
  const end = sequence.next + sequence.length;
  if (end !== buffer.length) {
    throw new Error('invalid DER sequence length');
  }
  const r = readDerInteger(buffer, sequence.next);
  const s = readDerInteger(buffer, r.next);
  if (s.next !== end) {
    throw new Error('trailing DER data');
  }
  const raw = Buffer.alloc(64);
  r.value.copy(raw, 32 - r.value.length);
  s.value.copy(raw, 64 - s.value.length);
  return raw;
}

function publicJwkFromSpki(publicKey, kid) {
  const exported = createPublicKey({
    key: Buffer.from(publicKey),
    format: 'der',
    type: 'spki',
  }).export({ format: 'jwk' });
  if (
    exported.kty !== 'EC' ||
    exported.crv !== 'P-256' ||
    typeof exported.x !== 'string' ||
    typeof exported.y !== 'string'
  ) {
    throw new Error('unexpected KMS public key');
  }
  return {
    kty: 'EC',
    crv: 'P-256',
    x: exported.x,
    y: exported.y,
    use: 'sig',
    alg: 'ES256',
    kid,
  };
}

function configFromEnvironment() {
  const allowedAudiences = new Set(
    requiredConfig('ALLOWED_AGENT_AUTH_ISSUERS')
      .split(',')
      .map((value) => value.trim().replace(/\/$/, ''))
      .filter(Boolean),
  );
  const allowedScopes = new Set(
    requiredConfig('ALLOWED_SCOPES').split(' ').filter(Boolean),
  );
  if (allowedAudiences.size === 0 || allowedScopes.size === 0) {
    throw new Error('simulator allowlists must not be empty');
  }
  return {
    issuer: requiredConfig('ISSUER').replace(/\/$/, ''),
    resource: requiredConfig('RESOURCE').replace(/\/$/, ''),
    assertionClientId: requiredConfig('ASSERTION_CLIENT_ID'),
    cognitoIssuer: requiredConfig('COGNITO_ISSUER').replace(/\/$/, ''),
    cognitoJwksUri: requiredConfig('COGNITO_JWKS_URI'),
    cognitoClientId: requiredConfig('COGNITO_CLIENT_ID'),
    brokerSecretArn: requiredConfig('BROKER_SECRET_ARN'),
    kmsKeyId: requiredConfig('KMS_KEY_ID'),
    allowedAudiences,
    allowedScopes,
  };
}

async function fetchJson(url) {
  const result = await fetch(url, {
    redirect: 'error',
    signal: AbortSignal.timeout(5_000),
    headers: { accept: 'application/json' },
  });
  if (!result.ok) {
    throw new Error('upstream request failed');
  }
  const text = await result.text();
  if (Buffer.byteLength(text) > MAX_JWKS_BYTES) {
    throw new Error('upstream response too large');
  }
  return parseJsonObject(text);
}

let awsDependenciesPromise;
function defaultDependencies(config) {
  awsDependenciesPromise ??= (async () => {
    const [{ KMSClient, GetPublicKeyCommand, SignCommand }, secrets] =
      await Promise.all([
        import('@aws-sdk/client-kms'),
        import('@aws-sdk/client-secrets-manager'),
      ]);
    const kms = new KMSClient({});
    const secretClient = new secrets.SecretsManagerClient({});
    let broker;
    let cognitoJwks;
    let publicJwk;
    return {
      now: () => Math.floor(Date.now() / 1000),
      loadBroker: async () => {
        broker ??= (async () => {
          const output = await secretClient.send(
            new secrets.GetSecretValueCommand({
              SecretId: config.brokerSecretArn,
            }),
          );
          return parseJsonObject(output.SecretString ?? '');
        })();
        return broker;
      },
      loadCognitoJwks: async () => {
        cognitoJwks ??= fetchJson(config.cognitoJwksUri);
        return cognitoJwks;
      },
      loadPublicJwk: async () => {
        publicJwk ??= (async () => {
          const output = await kms.send(
            new GetPublicKeyCommand({ KeyId: config.kmsKeyId }),
          );
          if (!output.PublicKey) {
            throw new Error('KMS public key missing');
          }
          return publicJwkFromSpki(output.PublicKey, config.kmsKeyId);
        })();
        return publicJwk;
      },
      sign: async (message) => {
        const output = await kms.send(
          new SignCommand({
            KeyId: config.kmsKeyId,
            Message: Buffer.from(message),
            MessageType: 'RAW',
            SigningAlgorithm: 'ECDSA_SHA_256',
          }),
        );
        if (!output.Signature) {
          throw new Error('KMS signature missing');
        }
        return derToP1363(output.Signature);
      },
    };
  })();
  return awsDependenciesPromise;
}

export function createHandler(overrides = {}) {
  return async (event) => {
    let config;
    try {
      config = overrides.config ?? configFromEnvironment();
      const defaults = overrides.dependencies
        ? {}
        : await defaultDependencies(config);
      const dependencies = { ...defaults, ...overrides.dependencies };
      const path = event.rawPath ?? event.requestContext?.http?.path;
      const method =
        event.requestContext?.http?.method ?? event.httpMethod ?? 'GET';

      if (method === 'GET' && path === '/jwks.json') {
        const key = await dependencies.loadPublicJwk();
        return response(200, { keys: [key] });
      }
      if (method !== 'POST' || path !== '/token') {
        return response(404, { error: 'not_found' });
      }

      const [clientId, clientSecret] = parseBasicAuthorization(event.headers);
      const broker = await dependencies.loadBroker();
      if (
        typeof broker.client_id !== 'string' ||
        typeof broker.client_secret !== 'string' ||
        !secureEqual(clientId, broker.client_id) ||
        !secureEqual(clientSecret, broker.client_secret)
      ) {
        throw new OAuthError('invalid_client', 401);
      }

      const form = parseForm(event);
      if (singleParameter(form, 'grant_type') !== TOKEN_EXCHANGE_GRANT) {
        throw new OAuthError('unsupported_grant_type');
      }
      if (singleParameter(form, 'subject_token_type') !== ID_TOKEN_TYPE) {
        throw new OAuthError('invalid_request');
      }
      const requestedTokenType = singleParameter(
        form,
        'requested_token_type',
      );
      if (
        requestedTokenType !== ID_JAG_TOKEN_TYPE &&
        requestedTokenType !== JWT_TYPE
      ) {
        throw new OAuthError('invalid_request');
      }

      const audience = singleParameter(form, 'audience').replace(/\/$/, '');
      const resource = singleParameter(form, 'resource').replace(/\/$/, '');
      if (!config.allowedAudiences.has(audience)) {
        throw new OAuthError('invalid_target');
      }
      if (resource !== config.resource) {
        throw new OAuthError('invalid_target');
      }
      const scopes = parseScope(
        singleParameter(form, 'scope'),
        config.allowedScopes,
      );
      const now = dependencies.now();
      const cognitoClaims = validateCognitoIdToken(
        singleParameter(form, 'subject_token'),
        await dependencies.loadCognitoJwks(),
        config,
        now,
      );

      const header = {
        alg: 'ES256',
        typ: 'oauth-id-jag+jwt',
        kid: config.kmsKeyId,
      };
      const claims = {
        iss: config.issuer,
        sub: cognitoClaims.sub,
        aud: audience,
        client_id: config.assertionClientId,
        jti: randomUUID(),
        scope: scopes.join(' '),
        resource,
        iat: now,
        nbf: now - 5,
        exp: now + ID_JAG_LIFETIME_SECS,
      };
      const signingInput = `${base64Url(
        JSON.stringify(header),
      )}.${base64Url(JSON.stringify(claims))}`;
      const signature = await dependencies.sign(signingInput);
      const assertion = `${signingInput}.${base64Url(signature)}`;
      return response(200, {
        access_token: assertion,
        issued_token_type: ID_JAG_TOKEN_TYPE,
        token_type: 'Bearer',
        expires_in: ID_JAG_LIFETIME_SECS,
        scope: scopes.join(' '),
      });
    } catch (error) {
      if (error instanceof OAuthError) {
        return response(
          error.statusCode,
          { error: error.error },
          error.statusCode === 401
            ? { 'www-authenticate': 'Basic realm="ema-simulator"' }
            : {},
        );
      }
      return response(500, { error: 'server_error' });
    }
  };
}

export const handler = createHandler();
