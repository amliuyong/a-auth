"""JWKS 缓存 + 未知 kid 重取限流 + 负缓存(spec 010 C8.4)。

威胁:随机 kid 伪造 token 诱导 RS 高频重取 JWKS 放大打 AS。
防御:限流(最小重取间隔)+ 未知 kid 负缓存 + 拉取失败沿用旧缓存并拒当前 token。
(同步实现;Python 侧多为 WSGI/同步中间件,不引 asyncio 复杂度。)
"""

from __future__ import annotations

import threading
from typing import Callable, Optional

from .types import Jwk, Jwks, VerifyError


class JwksCache:
    def __init__(
        self,
        fetcher: Callable[[], Jwks],
        min_refetch_interval_secs: int,
        negative_cache_ttl_secs: int,
        now: Callable[[], float],
    ) -> None:
        self._fetcher = fetcher
        self._min_interval = min_refetch_interval_secs
        self._neg_ttl = negative_cache_ttl_secs
        self._now = now
        self._keys: dict[str, Jwk] = {}
        self._last_fetch = 0.0
        self._negative: dict[str, float] = {}  # 未知 kid → negative-until
        self._last_fetch_ok = True  # 上次重取是否成功(区分"已知查无"vs"拉取失败")
        # single-flight:多线程 WSGI 下并发未知 kid 共享一次重取(评审 codex MEDIUM)。
        self._lock = threading.Lock()

    def get_key(self, kid: str) -> Optional[Jwk]:
        cached = self._keys.get(kid)
        if cached is not None:
            return cached

        t = self._now()
        # 负缓存:窗口内已知查无的 kid 直接 None,不重取(已知 miss)。
        neg_until = self._negative.get(kid)
        if neg_until is not None and t < neg_until:
            return None

        # 限流:距上次重取不足间隔 → 不重取(用现缓存查)。
        if t - self._last_fetch < self._min_interval:
            return self._miss_or_unavailable(kid)

        # single-flight:持锁做 check→refetch→update;并发者进锁后先复查缓存/间隔,
        # 命中则不再重取(共享上一个线程的拉取结果),避免随机 kid 洪水下每线程各拉一次。
        with self._lock:
            again = self._keys.get(kid)
            if again is not None:
                return again
            t2 = self._now()
            neg2 = self._negative.get(kid)
            if neg2 is not None and t2 < neg2:
                return None
            if t2 - self._last_fetch < self._min_interval:
                return self._miss_or_unavailable(kid)
            self._refetch()
            after = self._keys.get(kid)
            if after is not None:
                return after
            if not self._last_fetch_ok:
                # 重取失败且仍未解析 → 瞬时不可用(上层 503,不误报 invalid_token)。
                raise VerifyError("unavailable", "JWKS 暂不可用(重取失败)")
            self._negative[kid] = self._now() + self._neg_ttl
            return None

    def _miss_or_unavailable(self, kid: str) -> Optional[Jwk]:
        """限流窗口内的未命中:上次拉取失败则视为瞬时不可用,否则已知 miss。"""
        k = self._keys.get(kid)
        if k is not None:
            return k
        if not self._last_fetch_ok:
            raise VerifyError("unavailable", "JWKS 暂不可用(上次重取失败)")
        return None

    def _refetch(self) -> None:
        # 无论成败都占用间隔(防失败风暴)。
        self._last_fetch = self._now()
        try:
            jwks = self._fetcher()
            nxt: dict[str, Jwk] = {}
            for k in jwks.get("keys", []):
                kid = k.get("kid")
                if kid:
                    nxt[kid] = k
            self._keys = nxt
            self._negative.clear()  # 新集可能含此前查无的 kid
            self._last_fetch_ok = True
        except Exception:
            # 拉取失败:沿用旧缓存(不清空、不放行未知 kid)。
            self._last_fetch_ok = False

    def seed(self, jwks: Jwks) -> None:
        nxt: dict[str, Jwk] = {}
        for k in jwks.get("keys", []):
            kid = k.get("kid")
            if kid:
                nxt[kid] = k
        self._keys = nxt
        self._last_fetch = self._now()
        self._last_fetch_ok = True
