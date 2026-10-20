import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { RsSdk, IntrospectionClient, deriveResourceMetadataUrl } from 'agent_auth_rs';
import { configuration, fail, validateConfiguration } from './runtime.mjs';

// The sample binds a local HTTP listener behind your HTTPS reverse proxy.
// RESOURCE is the actual public HTTPS endpoint, never the internal listener.
export async function startServer(config, port = Number(process.env.PORT ?? 8790)) {
  validateConfiguration(config);
  const sdk = new RsSdk({
    issuer: config.issuer, resourceId: config.resource,
    resourceMetadataUrl: config.resource_metadata_url,
  });
  const metadataUrl = new URL(config.resource_metadata_url ?? deriveResourceMetadataUrl(config.resource));
  const resourcePath = new URL(config.resource).pathname;
  const policy = { requireSubType: 'user', requireScopes: config.scope.split(' ') };
  const secret = process.env.RS_INTROSPECTION_SECRET;
  if (config.online && (!secret || !config.introspection_client_id)) {
    throw new Error('Online checks require the registered RS credentials in runtime configuration');
  }
  const online = config.online ? new IntrospectionClient({
    introspectionEndpoint: config.issuer.replace(/\/+$/, '') + '/introspect',
    clientId: config.introspection_client_id, clientSecret: secret,
    resourceId: config.resource, cacheTtlSecs: 0,
  }) : null;
  const server = createServer(async (request, response) => {
    try {
      const path = new URL(request.url, 'http://internal.invalid').pathname;
      if (request.method === 'GET' && path === metadataUrl.pathname) {
        response.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
        response.end(JSON.stringify({
          resource: config.resource, authorization_servers: [config.issuer],
          scopes_supported: policy.requireScopes, bearer_methods_supported: ['header'],
        }));
        return;
      }
      if (path !== resourcePath) { response.writeHead(404).end(); return; }
      const result = await sdk.authenticate(request.headers.authorization, policy);
      if (!result.ok) { response.writeHead(result.status, result.headers).end(); return; }
      if (result.token.claims.cnf !== undefined) {
        // These recipes support bearer credentials only. Never accept a bound
        // token as bearer by omitting the required proof/replay enforcement.
        const challenge = await sdk.authenticate(undefined, policy);
        response.writeHead(401, {
          'WWW-Authenticate': challenge.headers['WWW-Authenticate'].replace('Bearer ', 'Bearer error="invalid_token", '),
        }).end();
        return;
      }
      if (online) {
        try {
          await online.authorize(request.headers.authorization.replace(/^Bearer\s+/i, ''), policy);
        } catch (error) {
          const missing = await sdk.authenticate(undefined, policy);
          const status = error.kind === 'unavailable' ? 503 : error.kind === 'insufficient_scope' ? 403 : 401;
          const headers = status === 503 ? {} : {
            'WWW-Authenticate': missing.headers['WWW-Authenticate'].replace('Bearer ', `Bearer error="${status === 403 ? 'insufficient_scope' : 'invalid_token'}", `),
          };
          response.writeHead(status, headers).end(); return;
        }
      }
      if (request.method !== 'POST') {
        response.writeHead(405, { Allow: 'POST' }).end(); return;
      }
      const chunks = [];
      let size = 0;
      for await (const chunk of request) {
        size += chunk.length;
        if (size > 65536) { response.writeHead(413).end(); return; }
        chunks.push(chunk);
      }
      let body;
      try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
      catch { response.writeHead(400).end(); return; }
      const mcp = new McpServer({ name: 'a-auth-onboarding', version: '1.0.0' });
      mcp.registerTool('identity', {
        description: 'Return the already verified pairwise subject and optional actor',
        inputSchema: {},
      }, async () => ({ content: [{ type: 'text', text: JSON.stringify({
        sub: result.token.sub, act: result.token.claims.act ?? null,
      }) }] }));
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined, enableJsonResponse: true,
      });
      response.on('close', () => { void transport.close(); void mcp.close(); });
      await mcp.connect(transport);
      await transport.handleRequest(request, response, body);
    } catch {
      if (!response.headersSent) response.writeHead(503).end();
      else response.end();
    }
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const config = await configuration();
    await startServer(config);
    console.log(JSON.stringify({ flow: 'mcp-server', result: 'READY', resource: config.resource }));
  } catch (error) { fail('mcp-server', error); }
}
