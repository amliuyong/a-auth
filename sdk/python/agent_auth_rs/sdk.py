"""Agent Auth RS 校验 SDK 主类(spec 010 P1b)。

用法(框架无关核心):
    sdk = RsSdk(RsSdkConfig(resource_id="https://mcp.kb.example.com", issuer="https://auth.example.com"))
    result = sdk.authenticate(request.headers.get("Authorization"), RoutePolicy(require_sub_type="user"))
    if not result.ok:
        return Response(status=result.status, headers=result.headers)
    # result.token: VerifiedToken
"""

from __future__ import annotations

import json
import re
import time
import urllib.request
from dataclasses import replace
from typing import Optional

from .authorization import (
    create_scope_resolver,
    derive_resource_metadata_url,
    normalize_required_scopes,
    normalize_resource_id,
    validate_resource_metadata_url,
)
from .jwks_cache import JwksCache
from .rar import _enforce_rar_with_evaluator
from .types import (
    AuthResult,
    Jwks,
    RoutePolicy,
    RsSdkConfig,
    VerifiedToken,
    VerifyError,
)
from .verifier import TokenVerifier

_BEARER_RE = re.compile(r"^Bearer\s+(.+)$", re.IGNORECASE)
_GRANT_BACKED_RAR_SUMMARY_TYPE = "agent_auth_grant_summary_v1"


class RsSdk:
    def __init__(self, cfg: RsSdkConfig) -> None:
        if cfg.scope_resolver is not None and cfg.scope_implications is not None:
            raise ValueError(
                "scope_resolver and scope_implications are mutually exclusive"
            )
        cfg = replace(
            cfg,
            resource_id=normalize_resource_id(cfg.resource_id),
            issuer=cfg.issuer.rstrip("/"),
        )
        self._cfg = cfg
        self._now = cfg.now or time.time
        jwks_uri = cfg.jwks_uri or f"{cfg.issuer}/jwks.json"

        def default_fetcher() -> Jwks:
            with urllib.request.urlopen(jwks_uri, timeout=5) as resp:  # noqa: S310
                if resp.status != 200:
                    raise RuntimeError(f"JWKS fetch {resp.status}")
                return json.loads(resp.read().decode("utf-8"))

        fetcher = cfg.jwks_fetcher or default_fetcher
        self._cache = JwksCache(
            fetcher,
            cfg.min_refetch_interval_secs,
            cfg.negative_cache_ttl_secs,
            self._now,
        )
        self._verifier = TokenVerifier(cfg, self._cache)
        self._prm_url = (
            validate_resource_metadata_url(cfg.resource_metadata_url)
            if cfg.resource_metadata_url is not None
            else derive_resource_metadata_url(cfg.resource_id)
        )
        self._scope_resolver = (
            cfg.scope_resolver
            if cfg.scope_resolver is not None
            else create_scope_resolver(cfg.scope_implications)
        )

    def seed_jwks(self, jwks: Jwks) -> None:
        """预热/离线注入 JWKS(测试;跳过网络)。"""
        self._cache.seed(jwks)

    def _www_authenticate(
        self, kind: str, required_scopes: Optional[list[str]] = None
    ) -> str:
        params: list[str] = []
        if kind == "invalid":
            params.append('error="invalid_token"')
        if kind == "insufficient":
            params.append('error="insufficient_scope"')
        if kind != "invalid" and required_scopes:
            params.append(f'scope="{" ".join(required_scopes)}"')
        params.append(f'resource_metadata="{self._prm_url}"')
        return f"Bearer {', '.join(params)}"

    def authenticate(
        self, authorization: Optional[str], policy: Optional[RoutePolicy] = None
    ) -> AuthResult:
        policy = policy or RoutePolicy()
        required_scopes = normalize_required_scopes(policy.require_scopes)
        token = _extract_bearer(authorization)
        if not token:
            return AuthResult(
                ok=False,
                status=401,
                headers={
                    "WWW-Authenticate": self._www_authenticate(
                        "missing", required_scopes
                    )
                },
                error=VerifyError("missing_token", "缺 Bearer token"),
            )

        try:
            verified: VerifiedToken = self._verifier.verify(token)
        except VerifyError as err:
            if err.kind == "unavailable":
                return AuthResult(ok=False, status=503, error=err)
            return AuthResult(
                ok=False,
                status=401,
                headers={"WWW-Authenticate": self._www_authenticate("invalid")},
                error=err,
            )

        # 路由策略(C8.2):sub_type / scope。403 带 RFC 6750 §3 的 WWW-Authenticate
        # error="insufficient_scope"(评审 Kiro MEDIUM-3)。
        if policy.require_sub_type and verified.sub_type != policy.require_sub_type:
            return AuthResult(
                ok=False,
                status=403,
                headers={
                    "WWW-Authenticate": self._www_authenticate(
                        "insufficient", required_scopes
                    )
                },
                error=VerifyError(
                    "insufficient_scope",
                    f"路由要求 sub_type={policy.require_sub_type},token 为 {verified.sub_type}",
                ),
            )
        if required_scopes:
            missing = [
                required
                for required in required_scopes
                if not any(
                    self._scope_resolver(granted, required) is True
                    for granted in verified.scope
                )
            ]
            if missing:
                return AuthResult(
                    ok=False,
                    status=403,
                    headers={
                        "WWW-Authenticate": self._www_authenticate(
                            "insufficient", required_scopes
                        )
                    },
                    error=VerifyError(
                        "insufficient_scope", f"缺 scope: {' '.join(missing)}"
                    ),
                )

        if _contains_grant_backed_rar_summary(
            verified.claims.get("authorization_details")
        ):
            return AuthResult(
                ok=False,
                status=403,
                headers={
                    "WWW-Authenticate": self._www_authenticate(
                        "insufficient", required_scopes
                    )
                },
                error=VerifyError(
                    "insufficient_scope",
                    "Grant-backed RAR summary requires authenticated introspection",
                ),
            )

        if policy.rar is not None:
            rar_result = _enforce_rar_with_evaluator(
                verified.claims.get("authorization_details"),
                policy.rar.request,
                evaluator=policy.rar.evaluator,
                claims={
                    "sub": verified.sub,
                    "scope": " ".join(verified.scope),
                },
            )
            if not rar_result.allowed:
                return AuthResult(
                    ok=False,
                    status=403,
                    headers={
                        "WWW-Authenticate": self._www_authenticate(
                            "insufficient", required_scopes
                        )
                    },
                    error=VerifyError(
                        "insufficient_scope",
                        rar_result.reason or "复杂 RAR 策略拒绝",
                    ),
                )

        return AuthResult(ok=True, token=verified)


def _extract_bearer(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    m = _BEARER_RE.match(authorization.strip())
    return m.group(1).strip() if m else None


def _contains_grant_backed_rar_summary(value: object) -> bool:
    if isinstance(value, dict):
        return value.get("type") == _GRANT_BACKED_RAR_SUMMARY_TYPE
    if not isinstance(value, list):
        return False
    return any(
        isinstance(detail, dict)
        and detail.get("type") == _GRANT_BACKED_RAR_SUMMARY_TYPE
        for detail in value
    )
