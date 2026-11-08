import { MCPAuth } from 'mcp-auth';
import { httpsIdentifier } from './server.mjs';

const issuer = httpsIdentifier(process.env.ISSUER);
const checker = 'mcp-auth@1.0.0-beta.1 discovery-and-MCP-metadata';
try {
  const auth = new MCPAuth({
    protectedResourceMetadata: {
      resource: 'https://rs.example.com/mcp',
      authorizationServer: { issuer, type: 'oidc' },
    },
  });
  await auth.getAuthMetadataOptions();
  console.log(JSON.stringify({ checker, isValid: true }));
} catch {
  // Library errors can contain the issuer or discovery response. Keep those
  // private; the caller only needs the check's outcome.
  console.log(JSON.stringify({ checker, isValid: false }));
  process.exitCode = 1;
}
