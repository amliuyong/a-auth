import { fetchServerConfig, validateServerConfig } from 'mcp-auth';
import { httpsIdentifier } from './server.mjs';

const issuer = httpsIdentifier(process.env.ISSUER);
const config = await fetchServerConfig(issuer, { type: 'oidc' });
const result = validateServerConfig(config, true);
console.log(JSON.stringify({
  checker: 'mcp-auth@0.2.0 validateServerConfig', isValid: result.isValid,
  successes: (result.successes ?? []).map(({ code }) => code),
  warnings: (result.warnings ?? []).map(({ code }) => code),
  errors: (result.errors ?? []).map(({ code }) => code),
}, null, 2));
process.exitCode = result.isValid ? 0 : 1;
