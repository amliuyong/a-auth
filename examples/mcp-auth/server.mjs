import express from 'express';
import { MCPAuth } from 'mcp-auth';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import https from 'node:https';
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';

export function httpsIdentifier(value) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash ||
      url.hostname.toLowerCase().includes('.lambda-url.')) {
    throw Error('Use an HTTPS identifier without credentials, query, fragment or Lambda Function URL');
  }
  return value;
}

export function rejectSenderBoundToken(request, response, next) {
  if (!request.auth?.claims || Object.hasOwn(request.auth.claims, 'cnf')) {
    response.set('WWW-Authenticate', 'Bearer error="invalid_token"')
      .status(401).json({ error: 'invalid_token' });
    return;
  }
  next();
}

export function createApp({ issuer, resource, scope = 'kb:read' }) {
  httpsIdentifier(issuer);
  httpsIdentifier(resource);
  if (new URL(resource).pathname !== '/mcp' || !scope || /\s/.test(scope)) {
    throw Error('The resource path must be /mcp and scope must be one nonempty value');
  }
  const auth = new MCPAuth({
    protectedResources: [{
      metadata: {
        resource,
        authorizationServers: [{ issuer, type: 'oidc' }],
        scopesSupported: [scope, 'offline_access'],
      },
    }],
  });
  const app = express();
  app.use(auth.protectedResourceMetadataRouter());
  app.all('/mcp', auth.bearerAuth('jwt', {
    resource, audience: resource, requiredScopes: [scope],
  }), rejectSenderBoundToken, express.json({ limit: '1mb' }), async (request, response, next) => {
    if (request.method !== 'POST') return response.status(405).end();
    const server = new McpServer({ name: 'a-auth-interop-example', version: '1.0.0' });
    server.registerTool('fixture_echo', {
      description: 'Returns a fixed synthetic message without external actions',
      inputSchema: {},
    }, async () => ({ content: [{ type: 'text', text: 'controlled-fixture-ok' }] }));
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    response.on('close', () => { void transport.close(); void server.close(); });
    try {
      await server.connect(transport);
      await transport.handleRequest(request, response, request.body);
    } catch (error) {
      next(error);
    }
  });
  app.use((_error, _request, response, _next) => {
    if (!response.headersSent) response.status(500).json({ error: 'server_error' });
  });
  return app;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const app = createApp({
    issuer: process.env.ISSUER, resource: process.env.RESOURCE, scope: process.env.SCOPE,
  });
  const port = Number(process.env.PORT ?? '5544');
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw Error('Invalid unprivileged port');
  const cert = process.env.TLS_CERT_FILE;
  const key = process.env.TLS_KEY_FILE;
  if (Boolean(cert) !== Boolean(key)) throw Error('Configure both TLS files');
  const ready = () => console.log(`MCP listener ready on loopback port ${port}`);
  if (cert && key) {
    https.createServer({
      cert: fs.readFileSync(cert), key: fs.readFileSync(key), minVersion: 'TLSv1.2',
    }, app).listen(port, '127.0.0.1', ready);
  } else {
    app.listen(port, '127.0.0.1', ready);
  }
}
