import { createServer } from 'node:http';
import * as oauth from 'oauth4webapi';
import { authorizationServer, configuration, fail, savePrivate, summary } from './runtime.mjs';

const started = Date.now();
let step = 'pkce-configuration';
let server;
try {
  const config = await configuration();
  const as = await authorizationServer(config);
  if (!as.grant_types_supported?.includes('authorization_code') ||
      !as.code_challenge_methods_supported?.includes('S256') ||
      !as.token_endpoint_auth_methods_supported?.includes('none')) {
    throw new Error('Public S256 authorization-code capability not advertised');
  }
  const callback = new URL(config.redirect_uri);
  if (callback.protocol !== 'http:' || !['127.0.0.1', '[::1]', 'localhost'].includes(callback.hostname)) {
    throw new Error('The example needs a registered HTTP loopback callback');
  }
  const client = { client_id: config.client_id };
  const verifier = oauth.generateRandomCodeVerifier();
  const state = oauth.generateRandomState();
  const authorize = new URL(as.authorization_endpoint);
  authorize.search = new URLSearchParams({
    response_type: 'code', client_id: config.client_id, redirect_uri: config.redirect_uri,
    resource: config.resource, scope: config.scope, state,
    code_challenge: await oauth.calculatePKCECodeChallenge(verifier),
    code_challenge_method: 'S256',
    ...(config.workload_actor ? { workload_actor: config.workload_actor } : {}),
  }).toString();
  step = 'pkce-user-consent';
  const returned = new Promise((resolve, reject) => {
    server = createServer((request, response) => {
      const url = new URL(request.url, callback.origin);
      if (request.method !== 'GET' || url.pathname !== callback.pathname) {
        response.writeHead(404).end(); return;
      }
      try {
        const parameters = oauth.validateAuthResponse(as, client, url, state);
        response.writeHead(200, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' });
        response.end('Authorization received. Return to the CLI; do not share this callback URL.');
        resolve(parameters);
      } catch (error) {
        if (error instanceof oauth.AuthorizationResponseError &&
            url.searchParams.getAll('state').length === 1 && url.searchParams.get('state') === state) {
          response.writeHead(400).end('Authorization declined or failed. Return to the CLI.');
          reject(error); return;
        }
        // A wrong-state request does not consume the waiting real callback.
        response.writeHead(400).end();
      }
    });
    server.once('error', reject);
    server.listen(Number(callback.port || 80), callback.hostname.replace(/^\[|\]$/g, ''), () => {
      console.log('Open this URL and review the resource, scopes and actor before approving:');
      console.log(authorize.href);
    });
  });
  const timer = setTimeout(() => { server.close(); }, 10 * 60 * 1000);
  let parameters;
  try {
    parameters = await Promise.race([
      returned,
      new Promise((_, reject) => server.once('close', () => reject(new Error('Consent timed out')))),
    ]);
  } finally { clearTimeout(timer); }
  step = 'pkce-code-redemption';
  const response = await oauth.authorizationCodeGrantRequest(
    as, client, oauth.None(), parameters, config.redirect_uri, verifier,
    { additionalParameters: { resource: config.resource } },
  );
  const tokens = await oauth.processAuthorizationCodeResponse(as, client, response);
  step = 'pkce-private-storage';
  await savePrivate('.session.json', { issuer: config.issuer, resource: config.resource,
    client_id: config.client_id, created_at: Date.now(), tokens });
  summary('pkce', started, { stages: 5, workload_consent_requested: !!config.workload_actor });
} catch (error) { fail(step, error); }
finally { server?.close(); }
