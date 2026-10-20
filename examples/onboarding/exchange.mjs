import { readFile, stat } from 'node:fs/promises';
import * as oauth from 'oauth4webapi';
import { authorizationServer, configuration, fail, privateSession, savePrivate, summary } from './runtime.mjs';

const started = Date.now();
let step = 'workload-configuration';
try {
  const config = await configuration();
  const session = await privateSession();
  if (!config.workload_actor || session.issuer !== config.issuer ||
      session.resource !== config.resource || session.client_id !== config.client_id) {
    throw new Error('Fresh original user authorization must match the selected public configuration');
  }
  if (!process.env.PLATFORM_TOKEN_FILE ||
      (await stat(process.env.PLATFORM_TOKEN_FILE)).mode & 0o077) {
    throw new Error('Fresh platform JWT must be supplied in a private file');
  }
  const platform = (await readFile(process.env.PLATFORM_TOKEN_FILE, 'utf8')).trim();
  const as = await authorizationServer(config);
  if (!as.grant_types_supported?.includes('urn:ietf:params:oauth:grant-type:token-exchange') ||
      !as.token_endpoint_auth_methods_supported?.includes('workload_oidc_jwt')) {
    throw new Error('Workload exchange capability not advertised');
  }
  step = 'workload-exchange';
  const client = { client_id: config.workload_actor };
  const response = await oauth.genericTokenEndpointRequest(as, client, oauth.None(),
    'urn:ietf:params:oauth:grant-type:token-exchange', {
      subject_token: session.tokens.access_token,
      subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      actor_token: platform,
      actor_token_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      resource: config.resource, scope: config.scope,
    });
  const tokens = await oauth.processGenericTokenEndpointResponse(as, client, response);
  // Existing a-auth deployments return their shared bearer TokenResponse.
  // Validate an issued_token_type when present without inventing a field the
  // deployed endpoint does not emit. The protected RS verifies the JWT itself.
  if (tokens.refresh_token || tokens.token_type.toLowerCase() !== 'bearer' ||
      tokens.issued_token_type !== undefined &&
        tokens.issued_token_type !== 'urn:ietf:params:oauth:token-type:access_token') {
    throw new Error('Unexpected delegated credential profile');
  }
  await savePrivate('.delegated.json', { issuer: config.issuer, resource: config.resource,
    actor: config.workload_actor, created_at: Date.now(), tokens });
  summary('workload-exchange', started, { stages: 3, online_resource_call: 'NOT_RUN' });
} catch (error) { fail(step, error); }
