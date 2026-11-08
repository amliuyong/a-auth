import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const run = promisify(execFile);

test('MCP 2 migration verifies signed JWTs and discovery over trusted loopback TLS', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'a-auth-mcp-migration-'));
  try {
    const cert = join(dir, 'cert.pem');
    const key = join(dir, 'key.pem');
    await run('openssl', [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
      '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
      '-keyout', key, '-out', cert,
    ]);
    assert.match(await readFile(cert, 'utf8'), /BEGIN CERTIFICATE/);
    // Node reads the extra trust file at process startup. No system trust or
    // certificate/hostname verification setting is changed.
    const result = await run(process.execPath, [
      fileURLToPath(new URL('fixtures/signed-flow.mjs', import.meta.url)), cert, key,
    ], { env: { ...process.env, NODE_EXTRA_CA_CERTS: cert }, timeout: 30_000 });
    assert.equal(result.stdout.trim(), 'PASS controlled TLS discovery, JWT boundaries and tool call');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
