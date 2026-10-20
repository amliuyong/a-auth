import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { configuration, fail, privateSession, summary } from './runtime.mjs';

const started = Date.now();
let step = 'protected-call-configuration';
let client;
try {
  const config = await configuration();
  const filename = process.env.A_AUTH_TOKEN_FILE ?? '.session.json';
  const session = await privateSession(filename);
  if (session.issuer !== config.issuer || session.resource !== config.resource ||
      session.actor && session.actor !== config.workload_actor) {
    throw new Error('Credential file is for a different issuer/resource');
  }
  const transport = new StreamableHTTPClientTransport(new URL(config.resource), {
    requestInit: { headers: { Authorization: `Bearer ${session.tokens.access_token}` } },
  });
  client = new Client({ name: 'a-auth-onboarding-cli', version: '1.0.0' });
  step = 'mcp-initialize';
  await client.connect(transport);
  step = 'mcp-tool-call';
  const result = await client.callTool({ name: 'identity', arguments: {} });
  if (result.isError || !Array.isArray(result.content) || result.content[0]?.type !== 'text') {
    throw new Error('Protected tool did not succeed');
  }
  const identity = JSON.parse(result.content[0].text);
  if (typeof identity.sub !== 'string' || !identity.sub ||
      session.actor && identity.act?.sub !== session.actor) {
    throw new Error('Protected response did not confirm the selected identity/actor');
  }
  summary('protected-mcp-call', started, { stages: 3, actor_confirmed: !!session.actor });
} catch (error) { fail(step, error); }
finally { await client?.close(); }
