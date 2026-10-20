# Agent Auth resource-server SDK

ES modules and TypeScript declarations for validating access tokens at a
resource server. Requires Node.js 22.14 or later. Apache-2.0.

Registry publication is pending. Until a release receipt exists, install the
qualified local tarball in an independent project:

```bash
npm install /absolute/path/to/agent-auth-rs-sdk-1.0.0.tgz
```

After publication has been verified, the fixed registry command is
`npm install --save-exact @agent-auth/rs-sdk@1.0.0`.

```js
import { RsSdk } from '@agent-auth/rs-sdk';

const sdk = new RsSdk({
  issuer: 'https://auth.example.com',
  resourceId: 'https://mcp.example.com',
});
const result = await sdk.authenticate(request.headers.authorization, {
  requireSubType: 'user',
  requireScopes: ['read'],
});
if (!result.ok) {
  response.writeHead(result.status, result.headers).end();
} else {
  response.writeHead(200, { 'Content-Type': 'application/json' });
  response.end(JSON.stringify({ subject: result.token.sub }));
}
```

Configure the exact issuer and resource identifier of your deployment. The
SDK obtains public JWKS and rejects wrong issuer, audience, signature, expiry,
subject type and required scopes. It consumes the issued pairwise subject.

`verifyDpopProof` is a separate helper: the resource server must call it for a
verified `cnf.jkt` token, pass the actual method/URL/access token, and maintain
a replay cache using the returned `jti`. `authenticate` does not automatically
enforce DPoP. RAR helpers and route policy evaluators only narrow access.
Grant-backed RAR requires authenticated introspection; offline JWT verification
cannot promise immediate revocation or cancel an operation already running.

Version 1.x preserves the existing public verification API. Pin versions, run
the installed-artifact qualification on upgrades, and review release notes.
This package does not obtain, store, refresh or exchange OAuth credentials.

Release and compatibility evidence:
[RS SDK release guide](https://github.com/amliuyong/a-auth/blob/main/docs/RS_SDK_RELEASE.md).
