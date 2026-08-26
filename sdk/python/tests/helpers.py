"""测试 helper:生成 EC P-256 密钥 + JWKS(kid=JWK thumbprint)+ 签 fixture token。"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import Any, Optional

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

NAMESPACE = "https://a-auth.com/c"
_UNSET = object()


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class KeyMaterial:
    def __init__(self, alg: str = "ES256") -> None:
        if alg == "ES256":
            self.private_key = ec.generate_private_key(ec.SECP256R1())
            algorithm = ECAlgorithm(ECAlgorithm.SHA256)
        elif alg == "RS256":
            self.private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048
            )
            algorithm = RSAAlgorithm(RSAAlgorithm.SHA256)
        else:
            raise ValueError(f"unsupported test algorithm: {alg}")
        pub = self.private_key.public_key()
        jwk = json.loads(algorithm.to_jwk(pub))
        jwk["alg"] = alg
        jwk["use"] = "sig"
        jwk["kid"] = _jwk_thumbprint(jwk)
        self.public_jwk = jwk
        self.alg = alg


def _jwk_thumbprint(jwk: dict) -> str:
    if jwk["kty"] == "EC":
        members = {
            "crv": jwk["crv"],
            "kty": jwk["kty"],
            "x": jwk["x"],
            "y": jwk["y"],
        }
    elif jwk["kty"] == "RSA":
        members = {"e": jwk["e"], "kty": jwk["kty"], "n": jwk["n"]}
    else:
        raise ValueError(f"unsupported test key type: {jwk['kty']}")
    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True)
    return _b64u(hashlib.sha256(canonical.encode()).digest())


def jwks_of(*keys: KeyMaterial) -> dict:
    return {"keys": [k.public_jwk for k in keys]}


def sign_token(
    key: KeyMaterial,
    iss: str,
    aud: Any = None,
    sub: str = "user-1",
    client_id: Optional[str] = "app-1",
    scope: str = "openid",
    sub_type: Optional[str] = "user",  # None = 省略命名空间
    auth_grant: str = "grant-1",
    actor_types: Any = _UNSET,
    authorization_details: Any = _UNSET,
    typ: str = "at+jwt",
    exp_offset: int = 3600,
    nbf_offset: Optional[int] = None,
    now: Optional[int] = None,
    include_client_id: bool = True,
    include_iat: bool = True,
    include_exp: bool = True,
    kid_override: Optional[str] = None,
    alg_override: Optional[str] = None,
) -> str:
    n = now if now is not None else int(time.time())
    if aud is None:
        aud = [iss.rstrip("/") + "/rs"]
    payload: dict[str, Any] = {
        "iss": iss,
        "sub": sub,
        "aud": aud,
        "scope": scope,
    }
    if include_iat:
        payload["iat"] = n
    if include_exp:
        payload["exp"] = n + exp_offset
    if nbf_offset is not None:
        payload["nbf"] = n + nbf_offset
    if include_client_id and client_id is not None:
        payload["client_id"] = client_id
    if sub_type is not None:
        namespace = {"sub_type": sub_type, "auth_grant": auth_grant}
        if actor_types is not _UNSET:
            namespace["actor_types"] = actor_types
        payload[NAMESPACE] = namespace
    if authorization_details is not _UNSET:
        payload["authorization_details"] = authorization_details
    signing_alg = alg_override or key.alg
    headers = {
        "alg": signing_alg,
        "typ": typ,
        "kid": kid_override or key.public_jwk["kid"],
    }
    return jwt.encode(payload, key.private_key, algorithm=signing_alg, headers=headers)
