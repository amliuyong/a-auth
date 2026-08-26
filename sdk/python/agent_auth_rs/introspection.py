"""Agent Auth RS SDK — introspection 消费路径 + 缓存 TTL 指引(spec 010 §3.5,非规范性)。

**何时用 introspection、何时用离线 JWT 校验(RsSdk.authenticate)?**

- **离线 JWT 校验**(默认、低延迟):RS 用 JWKS 公钥本地验签,不打 AS。适合绝大多数路由。
  代价:token 在 TTL 内被吊销(refresh 复用检测 / `/revoke` / Grant 吊销)后,离线校验**察觉不到**——
  存在"吊销到过期"的**残留有效窗口**(≤ access token TTL)。
- **在线 introspection**(高敏路由):RS 调 AS `/introspect`(RFC 7662)拿**权威 active 状态**,
  能立即反映吊销。代价:每次(或每 TTL)一次网络往返 + AS 依赖。

**缓存 TTL 指引(§3.5 核心)**:
- **高敏路由**(转账、删除、跨租户读等)**MUST** 用 `cache_ttl_secs=0`(**不缓存**)或 ≤ 秒级——
  否则缓存 `active:true` 就等于把 introspection 退化成"带残留窗口的离线校验",失去实时吊销的意义。
- 普通路由可给小正值(如 5s)平衡 AS 负载与吊销敏捷度。
- **`active:false` 永不缓存**(本实现强制):失效/吊销必须立即生效,缓存否定结果会制造"已吊销仍放行"漏洞。

本模块只做**消费路径**(RS→AS introspect + 短 TTL 正结果缓存);AS 侧 introspect 端点(调用方认证、
aud 隔离、回带命名空间/act 扩展字段)见 spec 010 C8.6/C8.7a、由 crates/http/src/introspect.rs 承载。
"""

from __future__ import annotations

import base64
import json
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .authorization import (
    create_scope_resolver,
    normalize_required_scopes,
    normalize_resource_id,
)
from .rar import _enforce_rar_with_evaluator
from .types import NAMESPACE, RoutePolicy, ScopeImplications, ScopeResolver, VerifyError


@dataclass
class IntrospectionConfig:
    """introspection 客户端配置。"""

    introspection_endpoint: str  # AS 的 /introspect 绝对 URL
    client_id: str  # 本 RS 的 introspection 凭证(控制面注册时领,spec 010 P1a)
    client_secret: str
    # 正结果(active:true)缓存 TTL 秒。**0 = 不缓存**(高敏路由默认建议 0 或 ≤ 秒级)。
    # active:false 永不缓存(见模块 docstring)。
    cache_ttl_secs: float = 0.0
    now: Optional[Callable[[], float]] = None  # 缺省 time.time()
    # 注入 HTTP 调用器(测试/自定义);签名 (endpoint, form_body, auth_header) -> (status, json_dict)。
    http_caller: Optional[Callable[[str, str, str], tuple[int, dict[str, Any]]]] = None
    # `authorize()` 的本 RS audience；原始 `introspect()` 消费不要求配置。
    resource_id: Optional[str] = None
    scope_implications: Optional[ScopeImplications] = None
    scope_resolver: Optional[ScopeResolver] = None


@dataclass
class IntrospectionResult:
    """introspection 响应的规范化结果。"""

    active: bool
    claims: dict[str, Any] = field(default_factory=dict)
    sub: Optional[str] = None
    aud: Optional[str] = None
    client_id: Optional[str] = None
    scope: list[str] = field(default_factory=list)
    sub_type: Optional[str] = None
    auth_grant: Optional[str] = None
    actor_types: Optional[dict[str, str]] = None


def _basic_auth_header(client_id: str, client_secret: str) -> str:
    """RFC 7617 Basic:base64(client_id:client_secret)。client_id/secret 按 RFC 6749 §2.3.1
    application/x-www-form-urlencoded 编码后再拼(与 AS 侧 client_auth 一致)。"""
    cid = urllib.parse.quote(client_id, safe="")
    csec = urllib.parse.quote(client_secret, safe="")
    raw = f"{cid}:{csec}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


class IntrospectionClient:
    """RS 侧 introspection 消费客户端(短 TTL 正结果缓存 + active:false 永不缓存)。"""

    def __init__(self, cfg: IntrospectionConfig) -> None:
        if cfg.scope_resolver is not None and cfg.scope_implications is not None:
            raise ValueError(
                "scope_resolver and scope_implications are mutually exclusive"
            )
        self._cfg = cfg
        self._resource_id = (
            normalize_resource_id(cfg.resource_id)
            if cfg.resource_id is not None
            else None
        )
        self._scope_resolver = (
            cfg.scope_resolver
            if cfg.scope_resolver is not None
            else create_scope_resolver(cfg.scope_implications)
        )
        self._now = cfg.now or time.time
        self._auth = _basic_auth_header(cfg.client_id, cfg.client_secret)
        self._caller = cfg.http_caller or self._default_caller
        # token -> (expires_at, IntrospectionResult);只缓存 active:true。
        self._cache: dict[str, tuple[float, IntrospectionResult]] = {}

    def _default_caller(
        self, endpoint: str, form_body: str, auth_header: str
    ) -> tuple[int, dict[str, Any]]:
        req = urllib.request.Request(  # noqa: S310
            endpoint,
            data=form_body.encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": auth_header,
            },
        )
        with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310
            body = resp.read().decode("utf-8")
            return resp.status, json.loads(body) if body else {}

    def introspect(self, token: str) -> IntrospectionResult:
        """查询 token 的权威 active 状态。

        - 命中未过期的正结果缓存 → 直接返回(仅当 cfg.cache_ttl_secs > 0)。
        - 否则调 AS /introspect;active:true 且 TTL>0 时入缓存;active:false 永不缓存。
        - AS 不可用(非 2xx / 网络错)→ raise VerifyError("unavailable"),由 RS 决定 fail-closed(推荐)。
        """
        now = self._now()
        if self._cfg.cache_ttl_secs > 0:
            hit = self._cache.get(token)
            if hit is not None:
                expires_at, cached = hit
                if now < expires_at:
                    return cached
                # 过期:清理。
                del self._cache[token]

        form = "token=" + urllib.parse.quote(token, safe="")
        try:
            status, body = self._caller(
                self._cfg.introspection_endpoint, form, self._auth
            )
        except Exception as exc:  # noqa: BLE001 网络/解析错都归 unavailable(RS 侧 fail-closed)
            raise VerifyError("unavailable", f"introspection 调用失败: {exc}") from exc

        if status != 200:
            raise VerifyError("unavailable", f"introspection 非 200: {status}")

        result = _parse_introspection(body)
        # 只缓存正结果(active:true);active:false 永不缓存(吊销立即生效)。
        if result.active and self._cfg.cache_ttl_secs > 0:
            self._cache[token] = (now + self._cfg.cache_ttl_secs, result)
        return result

    def invalidate(self, token: str) -> None:
        """从缓存移除某 token(如收到带外吊销通知时主动清)。"""
        self._cache.pop(token, None)

    def authorize(
        self, token: str, policy: Optional[RoutePolicy] = None
    ) -> IntrospectionResult:
        """在线组合授权：active + aud + route policy 全部通过后才执行复杂 RAR evaluator。"""
        if self._resource_id is None:
            raise ValueError(
                "IntrospectionConfig.resource_id is required for authorize()"
            )
        policy = policy or RoutePolicy()
        required_scopes = normalize_required_scopes(policy.require_scopes)
        result = self.introspect(token)
        if not result.active:
            raise VerifyError("invalid_token", "introspection token inactive")
        raw_audience = result.claims.get("aud")
        if not (
            isinstance(raw_audience, list)
            and len(raw_audience) == 1
            and raw_audience[0] == self._resource_id
        ):
            raise VerifyError("invalid_token", "introspection audience mismatch")
        if policy.require_sub_type and result.sub_type != policy.require_sub_type:
            raise VerifyError(
                "insufficient_scope",
                f"路由要求 sub_type={policy.require_sub_type},token 为 {result.sub_type}",
            )
        missing = [
            required
            for required in required_scopes
            if not any(
                self._scope_resolver(granted, required) is True
                for granted in result.scope
            )
        ]
        if missing:
            raise VerifyError("insufficient_scope", f"缺 scope: {' '.join(missing)}")
        if policy.rar is not None:
            rar_result = _enforce_rar_with_evaluator(
                result.claims.get("authorization_details"),
                policy.rar.request,
                evaluator=policy.rar.evaluator,
                claims={
                    "sub": result.sub,
                    "scope": " ".join(result.scope),
                },
            )
            if not rar_result.allowed:
                raise VerifyError(
                    "insufficient_scope",
                    rar_result.reason or "复杂 RAR 策略拒绝",
                )
        return result


def _parse_introspection(body: dict[str, Any]) -> IntrospectionResult:
    active = body.get("active") is True
    if not active:
        # RFC 7662:active:false 时其它字段无意义,不透出(防误用陈旧字段)。
        return IntrospectionResult(active=False)
    ns = body.get(NAMESPACE) or {}
    scope_raw = body.get("scope") or ""
    scope = scope_raw.split() if isinstance(scope_raw, str) else list(scope_raw)
    aud_raw = body.get("aud")
    # aud 恒单元素(C2.5a):数组取首,字符串直用。
    if isinstance(aud_raw, list):
        aud = aud_raw[0] if aud_raw else None
    else:
        aud = aud_raw
    actor_types = None
    if isinstance(ns, dict):
        raw_actor_types = ns.get("actor_types")
        if isinstance(raw_actor_types, dict) and all(
            isinstance(actor_id, str) and isinstance(actor_type, str)
            for actor_id, actor_type in raw_actor_types.items()
        ):
            actor_types = dict(raw_actor_types)
    return IntrospectionResult(
        active=True,
        claims=body,
        sub=body.get("sub"),
        aud=aud,
        client_id=body.get("client_id"),
        scope=scope,
        sub_type=ns.get("sub_type") if isinstance(ns, dict) else None,
        auth_grant=ns.get("auth_grant") if isinstance(ns, dict) else None,
        actor_types=actor_types,
    )
