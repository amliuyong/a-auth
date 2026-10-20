import * as oauth from 'oauth4webapi';
import { setTimeout as pause } from 'node:timers/promises';
import { authorizationServer, configuration, fail, savePrivate, summary } from './runtime.mjs';

const started = Date.now();
let step = 'device-capability';
try {
  const config = await configuration();
  if (config.workload_actor) throw new Error('Device flow cannot grant workload actor consent');
  const as = await authorizationServer(config);
  if (!as.device_authorization_endpoint ||
      !as.grant_types_supported?.includes('urn:ietf:params:oauth:grant-type:device_code')) {
    throw new Error('Device capability not advertised');
  }
  const client = { client_id: config.client_id };
  const device = await oauth.processDeviceAuthorizationResponse(as, client,
    await oauth.deviceAuthorizationRequest(as, client, oauth.None(), {
      scope: config.scope, resource: config.resource,
    }));
  // user_code is the human device authorization instruction, not a credential.
  console.log(JSON.stringify({ verification_uri: device.verification_uri, user_code: device.user_code }));
  step = 'device-poll';
  let interval = device.interval ?? 5;
  const expires = Date.now() + device.expires_in * 1000;
  let tokens;
  while (Date.now() < expires) {
    await pause(interval * 1000);
    try {
      tokens = await oauth.processDeviceCodeResponse(as, client,
        await oauth.deviceCodeGrantRequest(as, client, oauth.None(), device.device_code));
      break;
    } catch (error) {
      if (error instanceof oauth.ResponseBodyError && error.error === 'authorization_pending') continue;
      if (error instanceof oauth.ResponseBodyError && error.error === 'slow_down') { interval += 5; continue; }
      throw error;
    }
  }
  if (!tokens) throw new Error('Device authorization expired');
  await savePrivate('.session.json', { issuer: config.issuer, resource: config.resource,
    client_id: config.client_id, created_at: Date.now(), tokens });
  summary('device', started, { stages: 4 });
} catch (error) { fail(step, error); }
