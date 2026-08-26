import type { operations } from './api/schema';

type ConsentContextQuery = operations['consent_context']['parameters']['query'];

export function consentContextQuery(authorizeQuery: string): ConsentContextQuery | null {
  const query = new URLSearchParams(authorizeQuery);
  const singletons = new Set<string>();
  for (const [key] of query) {
    if (key === 'resource') continue;
    if (singletons.has(key)) return null;
    singletons.add(key);
  }
  const client_id = query.get('client_id');
  const redirect_uri = query.get('redirect_uri');
  if (!client_id || !redirect_uri) return null;
  const resources = query.getAll('resource').filter(Boolean);

  return {
    client_id,
    redirect_uri,
    scope: query.get('scope') ?? undefined,
    resource: resources.length > 0 ? resources : undefined,
    state: query.get('state') ?? undefined,
    code_challenge: query.get('code_challenge') ?? undefined,
    code_challenge_method: query.get('code_challenge_method') ?? undefined,
    authorization_details: query.get('authorization_details') ?? undefined,
    authz_session_id: query.get('authz_session_id') ?? undefined,
    cimd_digest: query.get('cimd_digest') ?? undefined,
    cimd_binding: query.get('cimd_binding') ?? undefined,
  };
}
