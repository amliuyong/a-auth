import createClient from 'openapi-fetch';
import type { paths } from './schema';
import { adminStepUpPath } from '../adminStepUp';

// Admin API client: same-origin requests automatically carry the short-lived
// HttpOnly Admin SSO cookie. A sessionStorage bearer is injected only for the
// explicit bootstrap/break-glass path.
const baseUrl = import.meta.env.VITE_API_BASE ?? '';

const TOKEN_KEY = 'agent-auth-admin-token';

export function getAdminToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY);
}
export function setAdminToken(tok: string): void {
  sessionStorage.setItem(TOKEN_KEY, tok);
}
export function clearAdminToken(): void {
  sessionStorage.removeItem(TOKEN_KEY);
}

// Cookie-only client used to discover a daily OIDC session before considering a
// stale break-glass token left in sessionStorage.
export const adminSessionApi = createClient<paths>({ baseUrl });

// Explicit break-glass client: every request carries the operator-provided token.
export const adminApi = createClient<paths>({ baseUrl });

adminApi.use({
  onRequest({ request }) {
    const tok = getAdminToken();
    if (tok) request.headers.set('authorization', `Bearer ${tok}`);
    return request;
  },
  onResponse({ response }) {
    if (response.status === 401) {
      const path = adminStepUpPath(response.headers.get('www-authenticate'));
      if (path) window.location.assign(path);
    }
    return response;
  },
});
