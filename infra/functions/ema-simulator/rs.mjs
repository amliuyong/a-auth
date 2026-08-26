import { createPublicKey, verify } from 'node:crypto';

const MAX_JWT_BYTES = 128 * 1024;
const MAX_JWKS_BYTES = 128 * 1024;
const JWKS_CACHE_MILLIS = 5 * 60 * 1000;

function response(statusCode, body, extraHeaders = {}) {
  return {
    statusCode,
    headers: {
      'cache-control': 'no-store',
      'content-type': 'application/json',
      ...extraHeaders,
    },
    body: JSON.stringify(body),
  };
}

function bearerChallenge(error, scope) {
  const values = ['Bearer'];
  if (error) {
    values.push(`error="${error}"`);
  }
  if (scope) {
    values.push(`scope="${scope}"`);
  }
  return values.join(' ');
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
    throw new Error('expected JSON object');
  }
  return parsed;
}

function splitJwt(token) {
  if (
    typeof token !== 'string' ||
    !token ||
    Buffer.byteLength(token) > MAX_JWT_BYTES ||
    /\s/.test(token)
  ) {
    throw new Error('invalid token');
  }
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((part) => !part)) {
    throw new Error('invalid token');
  }
  const header = parseJsonObject(
    Buffer.from(parts[0], 'base64url').toString('utf8'),
  );
  const claims = parseJsonObject(
    Buffer.from(parts[1], 'base64url').toString('utf8'),
  );
  const signature = Buffer.from(parts[2], 'base64url');
  if (!signature.length) {
    throw new Error('invalid token');
  }
  return {
    header,
    claims,
    signingInput: `${parts[0]}.${parts[1]}`,
    signature,
  };
}

function extractBearer(headers) {
  const raw = headers?.authorization ?? headers?.Authorization;
  if (typeof raw !== 'string' || !raw.startsWith('Bearer ')) {
    throw new Error('missing bearer');
  }
  return raw.slice(7);
}

function exactAudience(value, expected) {
  return value === expected ||
    (Array.isArray(value) && value.length === 1 && value[0] === expected);
}

function configFromEnvironment() {
  const allowedIssuers = new Set(
    requiredConfig('ALLOWED_AGENT_AUTH_ISSUERS')
      .split(',')
      .map((value) => value.trim().replace(/\/$/, ''))
      .filter(Boolean),
  );
  if (allowedIssuers.size === 0) {
    throw new Error('ALLOWED_AGENT_AUTH_ISSUERS must not be empty');
  }
  return {
    resource: requiredConfig('RESOURCE').replace(/\/$/, ''),
    allowedIssuers,
  };
}

async function fetchJson(url) {
  const result = await fetch(url, {
    redirect: 'error',
    signal: AbortSignal.timeout(5_000),
    headers: { accept: 'application/json' },
  });
  if (!result.ok) {
    throw new Error('JWKS request failed');
  }
  const text = await result.text();
  if (Buffer.byteLength(text) > MAX_JWKS_BYTES) {
    throw new Error('JWKS response too large');
  }
  return parseJsonObject(text);
}

const jwksCache = new Map();
async function defaultLoadJwks(issuer) {
  const cached = jwksCache.get(issuer);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.value;
  }
  const value = await fetchJson(`${issuer}/jwks.json`);
  jwksCache.set(issuer, {
    value,
    expiresAt: Date.now() + JWKS_CACHE_MILLIS,
  });
  return value;
}

async function verifyAccessToken(token, config, dependencies) {
  const parsed = splitJwt(token);
  if (
    parsed.header.alg !== 'ES256' ||
    parsed.header.typ !== 'at+jwt' ||
    typeof parsed.header.kid !== 'string' ||
    !parsed.header.kid ||
    Object.hasOwn(parsed.header, 'crit')
  ) {
    throw new Error('invalid token header');
  }
  const claims = parsed.claims;
  const issuer =
    typeof claims.iss === 'string' ? claims.iss.replace(/\/$/, '') : '';
  const now = dependencies.now();
  if (
    !config.allowedIssuers.has(issuer) ||
    !exactAudience(claims.aud, config.resource) ||
    typeof claims.sub !== 'string' ||
    !claims.sub ||
    typeof claims.client_id !== 'string' ||
    !claims.client_id ||
    typeof claims.jti !== 'string' ||
    !claims.jti ||
    typeof claims.scope !== 'string' ||
    !Number.isInteger(claims.exp) ||
    claims.exp <= now ||
    !Number.isInteger(claims.iat) ||
    claims.iat > now + 60
  ) {
    throw new Error('invalid token claims');
  }

  const jwks = await dependencies.loadJwks(issuer);
  const matches = (jwks.keys ?? []).filter(
    (key) =>
      key &&
      key.kty === 'EC' &&
      key.crv === 'P-256' &&
      key.kid === parsed.header.kid &&
      (key.alg === undefined || key.alg === 'ES256') &&
      (key.use === undefined || key.use === 'sig'),
  );
  if (matches.length !== 1) {
    throw new Error('signing key not found');
  }
  const key = createPublicKey({ key: matches[0], format: 'jwk' });
  if (
    !verify(
      'sha256',
      Buffer.from(parsed.signingInput),
      { key, dsaEncoding: 'ieee-p1363' },
      parsed.signature,
    )
  ) {
    throw new Error('invalid signature');
  }
  return claims;
}

export function createHandler(overrides = {}) {
  return async (event) => {
    const path = event.rawPath ?? event.requestContext?.http?.path;
    const method =
      event.requestContext?.http?.method ?? event.httpMethod ?? 'GET';
    if (method !== 'GET' || (path !== '/allow' && path !== '/deny')) {
      return response(404, { error: 'not_found' });
    }

    const config = overrides.config ?? configFromEnvironment();
    const dependencies = {
      now: () => Math.floor(Date.now() / 1000),
      loadJwks: defaultLoadJwks,
      ...overrides.dependencies,
    };
    let claims;
    try {
      claims = await verifyAccessToken(
        extractBearer(event.headers),
        config,
        dependencies,
      );
    } catch {
      return response(
        401,
        { error: 'invalid_token' },
        { 'www-authenticate': bearerChallenge('invalid_token') },
      );
    }

    const scopes = new Set(claims.scope.split(' ').filter(Boolean));
    const requiredScope = path === '/allow' ? 'mcp:read' : 'mcp:write';
    if (!scopes.has(requiredScope)) {
      return response(
        403,
        { error: 'insufficient_scope' },
        {
          'www-authenticate': bearerChallenge(
            'insufficient_scope',
            requiredScope,
          ),
        },
      );
    }
    return response(200, { ok: true });
  };
}

export const handler = createHandler();
