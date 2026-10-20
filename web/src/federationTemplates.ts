const capabilities = {
  protocol: 'oidc',
  responseType: 'code',
  pkce: 'S256',
  tokenEndpointAuthMethod: 'client_secret_basic',
  idTokenSigningAlgorithm: 'RS256',
  strongAcrMapping: 'explicit',
} as const;

export const federationTemplates = [
  {
    id: 'okta',
    version: 1,
    name: 'Okta',
    guide: 'https://developer.okta.com/docs/guides/implement-grant-type/authcode/main/',
    issuerExample: 'https://your-org.okta.com/oauth2/default',
    capabilities,
  },
  {
    id: 'entra',
    version: 1,
    name: 'Microsoft Entra ID',
    guide: 'https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc',
    issuerExample: 'https://login.microsoftonline.com/TENANT-ID/v2.0',
    capabilities,
  },
  {
    id: 'oidc',
    version: 1,
    name: 'OpenID Connect',
    guide: 'https://openid.net/specs/openid-connect-discovery-1_0.html',
    issuerExample: 'https://identity.example.com',
    capabilities,
  },
] as const;

export type FederationForm = {
  upstream_idp_id: string;
  upstream_issuer: string;
  client_id: string;
  client_secret_ref: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  scopes: string;
  strong_acr_values: string;
};

function required(field: string, value: string) {
  if (typeof value !== 'string' || !value.trim() || value !== value.trim()) {
    throw new Error(`${field}: a non-empty value without surrounding whitespace is required`);
  }
  return value;
}

function endpoint(field: string, value: string, issuer = false) {
  required(field, value);
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${field}: an absolute HTTPS URL is required`);
  }
  const host = parsed.hostname.toLowerCase().replace(/\.+$/, '');
  const authority = value.slice('https://'.length).split(/[/?#]/, 1)[0];
  if (
    !value.startsWith('https://') || value.length > 2048 ||
    /[@%\\]/.test(authority) || /[\u0000-\u0020\u007f]/.test(value) ||
    parsed.protocol !== 'https:' || parsed.username || parsed.password ||
    value.includes('#') || (issuer && parsed.search) || (parsed.port && parsed.port !== '443') ||
    !host.includes('.') ||
    host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') ||
    host.endsWith('.internal') || host.endsWith('.test') ||
    /^[\d.]+$/.test(host) || host.startsWith('[') ||
    /\.lambda-url\.[a-z0-9-]+\.on\.aws$/.test(host)
  ) {
    throw new Error(`${field}: use a public HTTPS endpoint without credentials or a fragment`);
  }
  // This is format validation only; the server controls DNS and network access.
  return value;
}

export function buildFederationDraft(tenantId: string, form: FederationForm) {
  const scopes = (form.scopes ?? '').split(/[\s,]+/).filter(Boolean);
  if (!scopes.includes('openid')) {
    throw new Error('scopes: openid is required');
  }
  return {
    tenant_id: tenantId,
    upstream_idp_id: required('upstream_idp_id', form.upstream_idp_id),
    upstream_issuer: endpoint('upstream_issuer', form.upstream_issuer, true),
    client_id: required('client_id', form.client_id),
    client_secret_ref: required('client_secret_ref', form.client_secret_ref),
    authorization_endpoint: endpoint('authorization_endpoint', form.authorization_endpoint),
    token_endpoint: endpoint('token_endpoint', form.token_endpoint),
    jwks_uri: endpoint('jwks_uri', form.jwks_uri),
    scopes,
    strong_acr_values: (form.strong_acr_values ?? '').split(/[\s,]+/).filter(Boolean),
  };
}

export function inspectFederationMetadata(
  draft: ReturnType<typeof buildFederationDraft>,
  metadata: unknown,
): { status: 'PASS' | 'FAIL'; field?: string } {
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) {
    return { status: 'FAIL', field: 'metadata' };
  }
  const document = metadata as Record<string, unknown>;
  for (const [claim, expected] of [
    ['issuer', draft.upstream_issuer],
    ['authorization_endpoint', draft.authorization_endpoint],
    ['token_endpoint', draft.token_endpoint],
    ['jwks_uri', draft.jwks_uri],
  ]) {
    if (document[claim] !== expected) return { status: 'FAIL', field: claim };
  }
  return { status: 'PASS' };
}
