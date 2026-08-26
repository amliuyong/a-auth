import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { dirname, extname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const host = process.env.OIDF_HTMLUNIT_HOST ?? '127.0.0.1';
const port = Number.parseInt(process.env.OIDF_HTMLUNIT_PORT ?? '4178', 10);
const dist = resolve(dirname(fileURLToPath(import.meta.url)), '../dist');
const csrf = 'htmlunit-csrf';
let consentAuthorizeQuery = null;

function send(response, status, contentType, body, headers = {}) {
  response.writeHead(status, { 'Content-Type': contentType, ...headers });
  response.end(body);
}

async function requestBody(request) {
  let body = '';
  for await (const chunk of request) {
    body += chunk;
    if (body.length > 64 * 1024) {
      throw new Error('request body too large');
    }
  }
  return JSON.parse(body);
}

function contentType(path) {
  return {
    '.css': 'text/css; charset=utf-8',
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.json': 'application/json',
    '.map': 'application/json',
  }[extname(path)] ?? 'application/octet-stream';
}

async function serveStatic(pathname, response) {
  const relative = pathname.startsWith('/assets/') ? pathname.slice(1) : 'index.html';
  const path = resolve(dist, relative);
  if (path !== dist && !path.startsWith(`${dist}${sep}`)) {
    send(response, 403, 'text/plain', 'forbidden');
    return;
  }
  try {
    send(response, 200, contentType(path), await readFile(path));
  } catch {
    send(response, 404, 'text/plain', 'not found');
  }
}

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url ?? '/', `http://${request.headers.host}`);
    if (request.method === 'GET' && url.pathname === '/health') {
      send(response, 200, 'text/plain', 'ok');
      return;
    }
    if (request.method === 'POST' && url.pathname === '/login/password') {
      const body = await requestBody(request);
      if (
        body.email !== 'oidf-user@example.com'
        || body.password !== 'Replaceable password 123!'
        || !body.authorize_query
      ) {
        send(response, 400, 'application/json', '{"error":"invalid fixture input"}');
        return;
      }
      send(
        response,
        200,
        'application/json',
        '{"authenticated":true,"password_change_required":false}',
      );
      return;
    }
    if (request.method === 'GET' && url.pathname === '/authorize') {
      response.writeHead(302, { Location: `/consent?${url.searchParams}` });
      response.end();
      return;
    }
    if (request.method === 'GET' && url.pathname === '/consent/context') {
      consentAuthorizeQuery = url.search.slice(1);
      send(
        response,
        200,
        'application/json',
        JSON.stringify({
          client_id: url.searchParams.get('client_id'),
          client_name: 'OIDF HtmlUnit Client',
          client_source: 'registered',
          scopes: ['openid'],
          resources: [],
          csrf_token: csrf,
        }),
      );
      return;
    }
    if (request.method === 'POST' && url.pathname === '/consent/decision') {
      const body = await requestBody(request);
      if (
        body.decision !== 'approve'
        || body.csrf !== csrf
        || body.authorize_query !== consentAuthorizeQuery
      ) {
        send(response, 400, 'application/json', '{"error":"invalid decision"}');
        return;
      }
      send(
        response,
        200,
        'application/json',
        JSON.stringify({
          redirect: `http://${request.headers.host}/callback?code=htmlunit-code`,
        }),
      );
      return;
    }
    if (request.method === 'GET' && url.pathname === '/callback') {
      send(
        response,
        200,
        'text/html; charset=utf-8',
        '<!doctype html><div id="submission_complete">complete</div>',
      );
      return;
    }
    if (request.method === 'GET') {
      await serveStatic(url.pathname, response);
      return;
    }
    send(response, 404, 'text/plain', 'not found');
  } catch (error) {
    send(response, 500, 'text/plain', String(error));
  }
});

server.listen(port, host, () => {
  process.stdout.write(`OIDF HtmlUnit fixture listening on http://${host}:${port}\n`);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
