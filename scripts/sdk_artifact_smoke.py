"""Run only with the installed wheel/sdist public entry; no source path imports."""
import json
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from agent_auth_rs import (
    AccessRequest, NAMESPACE, RAR_TYPE_V1, RoutePolicy, RsSdk, RsSdkConfig,
    VerifyError, compute_ath, compute_jkt, enforce_rar, verify_dpop_proof,
)

issuer, resource = "https://issuer.example", "https://resource.example/mcp"
key = ec.generate_private_key(ec.SECP256R1())
jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
jwk.update(kid=compute_jkt(jwk), alg="ES256", use="sig")
sdk = RsSdk(RsSdkConfig(issuer=issuer, resource_id=resource))
sdk.seed_jwks({"keys": [jwk]})
now = int(time.time())


def token(**overrides):
    claims = {
        "iss": issuer, "aud": [resource], "sub": "synthetic-subject",
        "client_id": "synthetic-client", "scope": "read", "iat": now, "exp": now + 300,
        NAMESPACE: {"sub_type": "user", "auth_grant": "synthetic-grant"},
    }
    claims.update(overrides)
    return jwt.encode(claims, key, algorithm="ES256", headers={"typ": "at+jwt", "kid": jwk["kid"]})


class Protected(BaseHTTPRequestHandler):
    def do_GET(self):
        result = sdk.authenticate(self.headers.get("Authorization"),
                                  RoutePolicy(require_sub_type="user", require_scopes=["read"]))
        self.send_response(200 if result.ok else result.status)
        for name, value in result.headers.items():
            self.send_header(name, value)
        self.end_headers()
        if result.ok:
            self.wfile.write(b"protected resource")

    def log_message(self, *_):
        pass


server = ThreadingHTTPServer(("127.0.0.1", 0), Protected)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    valid = token()
    for signed, expected in [
        (valid, 200), (token(iss="https://wrong.example"), 401),
        (token(aud=["https://wrong.example"]), 401), (token(scope="unrelated"), 403),
        (token(authorization_details=[{"type": "agent_auth_grant_summary_v1"}]), 403),
        (None, 401),
    ]:
        request = urllib.request.Request(f"http://127.0.0.1:{server.server_port}/protected",
                                         headers={"Authorization": f"Bearer {signed}"} if signed else {})
        try:
            response = urllib.request.urlopen(request)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            assert response.status == expected
            if expected != 200:
                assert "resource_metadata=" in response.headers["WWW-Authenticate"]
    rar = [{"type": RAR_TYPE_V1, "resource_subset": [resource], "max_records": 1}]
    assert enforce_rar(rar, AccessRequest(resource=resource, declared_count=1)).allowed
    assert not enforce_rar(rar, AccessRequest(resource=resource, declared_count=2)).allowed
    assert not enforce_rar([{"type": "unknown-policy"}], AccessRequest(resource=resource)).allowed
    proof = jwt.encode({
        "htm": "GET", "htu": resource, "iat": now, "jti": "synthetic-proof", "ath": compute_ath(valid),
    }, key, algorithm="ES256", headers={"typ": "dpop+jwt", "jwk": jwk})
    jkt = compute_jkt(jwk)
    assert verify_dpop_proof(proof, jkt, "GET", resource, access_token=valid).jti == "synthetic-proof"
    for binding, method, access in [(jkt, "POST", valid), ("wrong-thumbprint", "GET", valid),
                                    (jkt, "GET", "different-token")]:
        try:
            verify_dpop_proof(proof, binding, method, resource, access_token=access)
        except VerifyError:
            pass
        else:
            raise AssertionError("Invalid DPoP proof accepted")
    print(json.dumps({"result": "PASS", "protected_http_cases": 6, "rar_cases": 3, "dpop_cases": 4}))
finally:
    server.shutdown()
    server.server_close()
    thread.join()
