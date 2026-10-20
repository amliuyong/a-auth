import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { test } from 'node:test';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

test('a cross-origin redirect cannot receive MCP headers or tool arguments', async () => {
  let sourceRequests = 0;
  let sinkRequests = 0;
  const sink = createServer(async (request, response) => {
    sinkRequests += 1;
    for await (const _chunk of request) {
      // Consume only synthetic test data; no credentials are used.
    }
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { content: [] } }));
  });
  await new Promise((resolve) => sink.listen(0, '127.0.0.1', resolve));
  const source = createServer((_request, response) => {
    sourceRequests += 1;
    response.writeHead(307, { Location: `http://127.0.0.1:${sink.address().port}/mcp` });
    response.end();
  });
  await new Promise((resolve) => source.listen(0, '127.0.0.1', resolve));
  const transport = new StreamableHTTPClientTransport(
    new URL(`http://127.0.0.1:${source.address().port}/mcp`),
    { requestInit: { headers: { 'x-private-example-marker': 'synthetic-marker' } } },
  );
  try {
    await transport.start();
    await assert.rejects(transport.send({
      jsonrpc: '2.0', id: 1, method: 'tools/call',
      params: { name: 'identity', arguments: { marker: 'synthetic-marker' } },
    }));
    assert.equal(sourceRequests, 1);
    assert.equal(sinkRequests, 0);
  } finally {
    await transport.close();
    await Promise.all([source, sink].map(
      (server) => new Promise((resolve) => server.close(resolve)),
    ));
  }
});
