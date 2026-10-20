import { open, unlink } from 'node:fs/promises';
import * as oauth from 'oauth4webapi';
import { authorizationServer, configuration, fail, privateSession, savePrivate, summary } from './runtime.mjs';

const started = Date.now();
let step = 'refresh-lock';
let lock;
let safeToUnlock = true;
try {
  lock = await open('.session.json.lock', 'wx', 0o600);
  const config = await configuration();
  const session = await privateSession();
  if (!session.tokens.refresh_token || session.issuer !== config.issuer ||
      session.resource !== config.resource || session.client_id !== config.client_id) {
    throw new Error('Only the original client can refresh its current family');
  }
  const as = await authorizationServer(config);
  if (!as.grant_types_supported?.includes('refresh_token')) throw new Error('Refresh not advertised');
  step = 'refresh-request';
  safeToUnlock = false;
  const client = { client_id: config.client_id };
  const response = await oauth.refreshTokenGrantRequest(as, client, oauth.None(),
    session.tokens.refresh_token, { additionalParameters: { resource: config.resource } });
  const tokens = await oauth.processRefreshTokenResponse(as, client, response);
  if (!tokens.refresh_token) throw new Error('Rotating refresh credential missing');
  step = 'refresh-private-commit';
  await savePrivate('.session.json', { ...session, created_at: Date.now(), tokens });
  safeToUnlock = true;
  summary('refresh', started, { stages: 3 });
} catch (error) {
  if (error instanceof oauth.ResponseBodyError && error.status < 500 &&
      ['invalid_grant', 'invalid_client', 'unauthorized_client', 'invalid_scope',
        'unsupported_grant_type', 'invalid_request'].includes(error.error) ||
      error instanceof oauth.WWWAuthenticateChallengeError && error.status < 500) {
    safeToUnlock = true;
  }
  fail(step, error);
  if (!safeToUnlock) console.error(JSON.stringify({ refresh_outcome: 'UNKNOWN', automatic_retry: false }));
} finally {
  await lock?.close();
  if (lock && safeToUnlock) await unlink('.session.json.lock');
}
