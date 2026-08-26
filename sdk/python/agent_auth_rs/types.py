"""Agent Auth RS SDK 类型(spec 010 P1b)。"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Literal, Optional

if TYPE_CHECKING:
    from .rar import AccessRequest, PolicyEvaluator

# 命名空间(docs/DESIGN §2,云无关永久常量)。
NAMESPACE = "https://a-auth.com/c"

SubType = Literal["user", "agent", "service"]

# 校验失败分类。
VerifyErrorKind = Literal[
    "missing_token", "invalid_token", "insufficient_scope", "unavailable"
]


class VerifyError(Exception):
    def __init__(self, kind: VerifyErrorKind, detail: str) -> None:
        super().__init__(detail)
        self.kind: VerifyErrorKind = kind
        self.detail = detail


Jwk = dict[str, Any]  # 一把 JWK(EC P-256 或 RSA);与 AS /jwks.json 形状一致
Jwks = dict[str, Any]  # {"keys": [Jwk, ...]}
ScopeResolver = Callable[[str, str], bool]
ScopeImplications = Mapping[str, Sequence[str]]


@dataclass
class VerifiedToken:
    claims: dict[str, Any]
    sub: str
    aud: str  # 单元素 aud(= 本 RS,已强校验)
    client_id: str
    scope: list[str]
    sub_type: Optional[SubType] = None
    auth_grant: Optional[str] = None
    actor_types: Optional[dict[str, str]] = None


@dataclass
class RsSdkConfig:
    resource_id: str  # 本 RS 资源标识(= 期望的单元素 aud)
    issuer: str  # AS issuer(token.iss 必须等于它)
    jwks_uri: Optional[str] = None  # 缺省 f"{issuer}/jwks.json"
    jwks_fetcher: Optional[Callable[[], Jwks]] = None  # 注入拉取器(测试/自定义)
    # 缺省按 RFC 9728 endpoint-path 规则派生。
    resource_metadata_url: Optional[str] = None
    scope_implications: Optional[ScopeImplications] = None
    scope_resolver: Optional[ScopeResolver] = None
    clock_skew_secs: int = 60
    min_refetch_interval_secs: int = 60
    negative_cache_ttl_secs: int = 300
    now: Optional[Callable[[], float]] = None  # 缺省 time.time()


@dataclass
class RarPolicy:
    """复杂 RAR 路由策略；只能由 SDK 完成 token 基线校验后执行。"""

    request: AccessRequest
    evaluator: PolicyEvaluator


@dataclass
class RoutePolicy:
    require_sub_type: Optional[SubType] = None
    require_scopes: list[str] = field(default_factory=list)
    rar: Optional[RarPolicy] = None


@dataclass
class AuthResult:
    ok: bool
    token: Optional[VerifiedToken] = None
    status: int = 200
    headers: dict[str, str] = field(default_factory=dict)
    error: Optional[VerifyError] = None
