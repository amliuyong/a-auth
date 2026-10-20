# MCP Auth library example

This private Node 22 example uses published `mcp-auth@0.2.0`, Express 5.2.1
and the official MCP SDK 1.32.0. Its single tool returns a fixed synthetic
message and performs no external action.

Copy this directory into a separate project and install the locked dependencies:

```bash
npm ci --ignore-scripts
ISSUER=https://auth.example.com RESOURCE=https://rs.example.com/mcp npm start
ISSUER=https://auth.example.com npm run check-provider
```

The listener binds only to `127.0.0.1:5544`. Publish it through a TLS proxy
mapping `/mcp` and `/.well-known/oauth-protected-resource/mcp` to this listener.
Both identifiers must be actual HTTPS addresses. The configured audience must
equal the protected resource exactly; the default required scope is `kb:read`.
Metadata discovery, signature, issuer, audience and scope enforcement use the
third-party library without adapters that relax validation.
This example supports Bearer tokens only. After signature verification it
rejects every token carrying `cnf`, including malformed/null values, before
calling the tool. It does not implement DPoP or mTLS proof verification.
JWT verification is offline: revocation may remain invisible until expiry.
Routes requiring current Grant/user authority need authenticated introspection.

For local TLS, set `TLS_CERT_FILE` and `TLS_KEY_FILE` to private test files.
Set `NODE_EXTRA_CA_CERTS` only for each local test process when its AS uses a
test CA. Certificate and hostname verification remain enabled; do not add the
test CA to system trust. This example requires no registry or AWS credentials.

Lambda Function URLs are prohibited in every authentication mode. AWS HTTP
entry points must use authenticated API Gateway/ALB or SDK Invoke. A gateway
must preserve the documented metadata path and enforce business-route auth.

Use a real client such as `mcp-remote` or MCP Inspector against the public
`/mcp` endpoint, with its own private credential store. The AS must provide a
registered loopback callback and code + S256 PKCE. A refresh test requires the
client to request `offline_access`, the deployment to enable refresh and the
response to include a refresh token. Wait for real expiry; do not rewrite token
lifetimes or response bodies. Clear the test client store and stop owned
listeners/daemons after testing. Never publish tokens, cookies, codes or claims.

`check-provider` runs the published library's metadata compatibility checker.
The separately hosted checker needs a publicly reachable issuer; a loopback
result cannot qualify it or a production deployment. The dated client,
negative-validation and cleanup results are in
[MCP interop records](../../docs/MCP_INTEROP.md).
