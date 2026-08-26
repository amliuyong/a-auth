"""access token 校验核心(spec 010 C8.2/C8.3 + RFC 9068 基线)。

顺序:解析 header(拒 alg:none)→ 按 kid 取公钥 → 强制 alg 与公钥类型一致 → 验签
     → RFC 9068 基线(typ=at+jwt / iss / exp,nbf,iat±skew / client_id)→ aud 严格单元素数组。
"""

from __future__ import annotations

from typing import Optional

import jwt
from jwt import PyJWK

from .jwks_cache import JwksCache
from .types import NAMESPACE, RsSdkConfig, VerifiedToken, VerifyError


def _expected_alg(jwk: dict) -> Optional[str]:
    """kid 对应公钥类型 → 唯一允许的 alg(C8.3)。"""
    kty = jwk.get("kty")
    if kty == "EC" and jwk.get("crv") == "P-256":
        return "ES256"
    if kty == "RSA":
        return "RS256"
    return None


class TokenVerifier:
    def __init__(self, cfg: RsSdkConfig, cache: JwksCache) -> None:
        self._cfg = cfg
        self._cache = cache
        self._skew = cfg.clock_skew_secs

    def verify(self, token: str) -> VerifiedToken:
        # 1. header:拒 alg:none;取 kid。
        try:
            header = jwt.get_unverified_header(token)
        except Exception as e:  # noqa: BLE001
            raise VerifyError("invalid_token", f"malformed header: {e}")
        alg = header.get("alg")
        if not alg or alg == "none":
            raise VerifyError("invalid_token", "alg:none 一律拒")
        kid = header.get("kid")
        if not kid:
            raise VerifyError("invalid_token", "缺 kid")

        # 2. 按 kid 取公钥;强制 alg 与公钥类型一致。
        jwk = self._cache.get_key(kid)
        if jwk is None:
            raise VerifyError("invalid_token", f"未知 kid: {kid}")
        want = _expected_alg(jwk)
        if want is None:
            raise VerifyError("invalid_token", f"不支持的公钥类型: {jwk.get('kty')}")
        if alg != want:
            raise VerifyError(
                "invalid_token", f"alg {alg} 与 kid 公钥类型(应 {want})不符"
            )

        # 3. 验签(只允许该单一 alg;不校 aud/iss,由下方按契约自己校)。
        try:
            key = PyJWK.from_dict(jwk).key
            claims = jwt.decode(
                token,
                key=key,
                algorithms=[want],
                options={
                    # RFC 9068 要求 exp + iat(nbf 可选;本 AS token 无 nbf,不强制)。
                    # PyJWT 对存在的 iat 会校未来性;require 确保 iat/exp 必在(评审 codex MEDIUM)。
                    "require": ["exp", "iat"],
                    "verify_aud": False,  # aud 我们严格自校(单元素数组)
                    "verify_iss": False,
                },
                leeway=self._skew,
            )
        except Exception as e:  # noqa: BLE001
            raise VerifyError("invalid_token", f"签名/时效校验失败: {e}")

        # 4. RFC 9068 基线。
        if header.get("typ") != "at+jwt":
            raise VerifyError("invalid_token", "typ 必须 at+jwt(拒非 access token)")
        if claims.get("iss") != self._cfg.issuer:
            raise VerifyError("invalid_token", "iss 不匹配")
        client_id = claims.get("client_id")
        if not isinstance(client_id, str) or not client_id:
            raise VerifyError("invalid_token", "缺顶层 client_id(C2.1)")

        # 5. aud 严格单元素数组 == 本 RS(拒裸字符串,C2.5a)。
        aud = claims.get("aud")
        if not (
            isinstance(aud, list) and len(aud) == 1 and aud[0] == self._cfg.resource_id
        ):
            raise VerifyError("invalid_token", "aud 非单元素数组或不匹配本 RS")

        # 命名空间字段(消费,不派生 sub)。
        sub_type = None
        auth_grant = None
        actor_types = None
        ns = claims.get(NAMESPACE)
        if isinstance(ns, dict):
            if isinstance(ns.get("sub_type"), str):
                sub_type = ns["sub_type"]
            if isinstance(ns.get("auth_grant"), str):
                auth_grant = ns["auth_grant"]
            if "actor_types" in ns:
                raw_actor_types = ns["actor_types"]
                if not (
                    isinstance(raw_actor_types, dict)
                    and all(
                        isinstance(actor_id, str) and isinstance(actor_type, str)
                        for actor_id, actor_type in raw_actor_types.items()
                    )
                ):
                    raise VerifyError(
                        "invalid_token", "命名空间 actor_types 必须是字符串映射"
                    )
                actor_types = dict(raw_actor_types)

        scope_raw = claims.get("scope")
        if isinstance(scope_raw, str):
            scope = [s for s in scope_raw.split(" ") if s]
        elif isinstance(scope_raw, list):
            scope = scope_raw
        else:
            scope = []

        return VerifiedToken(
            claims=claims,
            sub=claims.get("sub", "") if isinstance(claims.get("sub"), str) else "",
            aud=aud[0],
            client_id=client_id,
            scope=scope,
            sub_type=sub_type,
            auth_grant=auth_grant,
            actor_types=actor_types,
        )
