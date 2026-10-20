# Agent Auth resource-server SDK

Python 3.10+ access-token verification for resource servers. Apache-2.0.

Registry publication is pending. Install the qualified wheel or source
distribution into an independent virtual environment:

```bash
python -m venv .venv
.venv/bin/python -m pip install /absolute/path/to/agent_auth_rs_sdk-1.0.0-py3-none-any.whl
```

After publication has been verified, the fixed registry command is
`python -m pip install agent-auth-rs-sdk==1.0.0`.

```python
from agent_auth_rs import RsSdk, RsSdkConfig, RoutePolicy

sdk = RsSdk(RsSdkConfig(
    issuer="https://auth.example.com",
    resource_id="https://mcp.example.com",
))

def protected_resource(authorization_header):
    result = sdk.authenticate(
        authorization_header,
        RoutePolicy(require_sub_type="user", require_scopes=["read"]),
    )
    if not result.ok:
        return result.status, result.headers, None
    return 200, {}, {"subject": result.token.sub}
```

Configure the exact issuer and resource identifier of your deployment. The
SDK obtains public JWKS and rejects wrong issuer, audience, signature, expiry,
subject type and required scopes. It consumes the issued pairwise subject.

`verify_dpop_proof` is a separate helper: call it for a verified `cnf.jkt`
token with the actual method/URL/access token and maintain a replay cache using
the returned `jti`. `authenticate` does not automatically enforce DPoP.
RAR helpers and route policy evaluators only narrow access. Grant-backed RAR
requires authenticated introspection; offline JWT verification cannot promise
immediate revocation or cancel an operation already running.

Version 1.x preserves the existing public verification API. Pin versions, run
the installed-artifact qualification on upgrades, and review release notes.
This package does not obtain, store, refresh or exchange OAuth credentials.

Release and compatibility evidence:
[RS SDK release guide](https://github.com/amliuyong/a-auth/blob/main/docs/RS_SDK_RELEASE.md).
