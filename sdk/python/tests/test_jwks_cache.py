"""C8.4:未知 kid 重取限流 + 负缓存 + 拉取失败沿用旧缓存(随机 kid 洪水防放大)。"""

from __future__ import annotations

import base64
import json
import time

from agent_auth_rs import RsSdk, RsSdkConfig

from .helpers import KeyMaterial, jwks_of, sign_token

ISS = "https://auth.example.com"
RS = "https://mcp.kb.example.com"


def _b64u(o) -> str:
    return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()


def _forged(kid: str) -> str:
    n = int(time.time())
    return f'{_b64u({"alg": "ES256", "typ": "at+jwt", "kid": kid})}.{_b64u({"iss": ISS, "aud": [RS], "exp": n + 100, "client_id": "c"})}.sig'


def test_random_kid_flood_refetch_rate_limited():
    key = KeyMaterial()
    counter = {"n": 0}

    def fetcher():
        counter["n"] += 1
        return jwks_of(key)

    sdk = RsSdk(
        RsSdkConfig(
            resource_id=RS,
            issuer=ISS,
            min_refetch_interval_secs=60,
            negative_cache_ttl_secs=300,
            jwks_fetcher=fetcher,
        )
    )
    for i in range(100):
        r = sdk.authenticate(f"Bearer {_forged('random-' + str(i))}")
        assert not r.ok
    # 重取被限流:不是每 token 一次(100 次),窗口内应 ≤ 1。
    assert counter["n"] <= 1


def test_unknown_kid_negative_cached():
    key = KeyMaterial()
    counter = {"n": 0}

    def fetcher():
        counter["n"] += 1
        return jwks_of(key)

    sdk = RsSdk(
        RsSdkConfig(
            resource_id=RS,
            issuer=ISS,
            min_refetch_interval_secs=0,  # 关间隔限流,单独验负缓存
            negative_cache_ttl_secs=300,
            jwks_fetcher=fetcher,
        )
    )
    sdk.authenticate(f"Bearer {_forged('ghost')}")
    first = counter["n"]
    sdk.authenticate(f"Bearer {_forged('ghost')}")
    sdk.authenticate(f"Bearer {_forged('ghost')}")
    assert counter["n"] == first  # 负缓存命中,未再重取


def test_fetch_failure_keeps_old_cache_and_denies():
    key = KeyMaterial()
    state = {"fail": False}

    def fetcher():
        if state["fail"]:
            raise RuntimeError("JWKS down")
        return jwks_of(key)

    sdk = RsSdk(
        RsSdkConfig(
            resource_id=RS, issuer=ISS, min_refetch_interval_secs=0, jwks_fetcher=fetcher
        )
    )
    sdk.seed_jwks(jwks_of(key))
    good = sign_token(key, iss=ISS, aud=[RS])
    assert sdk.authenticate(f"Bearer {good}").ok

    state["fail"] = True
    assert not sdk.authenticate(f"Bearer {_forged('new-kid')}").ok  # 未知 kid 重取失败 → 拒
    # 旧 key 的有效 token 仍 ok(缓存未清空)。
    good2 = sign_token(key, iss=ISS, aud=[RS])
    assert sdk.authenticate(f"Bearer {good2}").ok


def test_never_fetched_plus_failure_is_503():
    # JWKS 从未拉到 + 拉取失败 + 未知 kid → 503 unavailable(非 401 invalid)。
    def fetcher():
        raise RuntimeError("JWKS down")

    sdk = RsSdk(
        RsSdkConfig(resource_id=RS, issuer=ISS, min_refetch_interval_secs=0, jwks_fetcher=fetcher)
    )
    r = sdk.authenticate(f"Bearer {_forged('k')}")
    assert not r.ok and r.status == 503  # 瞬时不可用 → 可重试


def test_single_flight_under_concurrency():
    # 多线程并发同一未知 kid → 只应触发 1 次重取(single-flight)。
    import threading

    key = KeyMaterial()
    counter = {"n": 0}
    lock = threading.Lock()

    def fetcher():
        with lock:
            counter["n"] += 1
        return jwks_of(key)

    sdk = RsSdk(
        RsSdkConfig(
            resource_id=RS, issuer=ISS, min_refetch_interval_secs=60, jwks_fetcher=fetcher
        )
    )
    forged = _forged("ghost")
    threads = [threading.Thread(target=lambda: sdk.authenticate(f"Bearer {forged}")) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert counter["n"] == 1  # single-flight:20 并发共享一次重取


def test_rotation_new_kid_refetched():
    key1 = KeyMaterial()
    key2 = KeyMaterial()
    state = {"jwks": jwks_of(key1)}
    sdk = RsSdk(
        RsSdkConfig(
            resource_id=RS,
            issuer=ISS,
            min_refetch_interval_secs=0,
            jwks_fetcher=lambda: state["jwks"],
        )
    )
    sdk.seed_jwks(jwks_of(key1))
    state["jwks"] = jwks_of(key1, key2)  # AS 轮换,JWKS 含两把
    t2 = sign_token(key2, iss=ISS, aud=[RS])
    # key2 kid 未知 → 重取 → 拉到新集 → 放行。
    assert sdk.authenticate(f"Bearer {t2}").ok


def test_c8_4_unknown_kid_refetch_rate_limit_and_negative_cache():
    key1 = KeyMaterial()
    key2 = KeyMaterial()
    key3 = KeyMaterial()
    now = [time.time()]
    current = {"jwks": jwks_of(key1)}
    fetches = {"n": 0}

    def rotating_fetcher():
        fetches["n"] += 1
        return current["jwks"]

    sdk = RsSdk(
        RsSdkConfig(
            resource_id=RS,
            issuer=ISS,
            now=lambda: now[0],
            min_refetch_interval_secs=60,
            negative_cache_ttl_secs=300,
            jwks_fetcher=rotating_fetcher,
        )
    )
    sdk.seed_jwks(jwks_of(key1))
    current["jwks"] = jwks_of(key1, key2)
    now[0] += 61
    assert sdk.authenticate(f"Bearer {sign_token(key2, iss=ISS, aud=[RS])}").ok
    assert fetches["n"] == 1, "unknown rotated kid must trigger one JWKS refetch"

    for i in range(20):
        assert not sdk.authenticate(f"Bearer {_forged(f'random-{i}')}").ok
    assert fetches["n"] == 1, "random kid flood must be rate limited"

    current["jwks"] = jwks_of(key1, key2, key3)
    now[0] += 59
    assert not sdk.authenticate(f"Bearer {sign_token(key3, iss=ISS, aud=[RS])}").ok
    assert fetches["n"] == 1, "refetch must remain suppressed inside 60 seconds"
    now[0] += 2
    assert sdk.authenticate(f"Bearer {sign_token(key3, iss=ISS, aud=[RS])}").ok
    assert fetches["n"] == 2, "refetch must resume after the rate-limit window"

    ghost_key = KeyMaterial()
    ghost_jwk = dict(ghost_key.public_jwk)
    ghost_jwk["kid"] = "ghost"
    ghost_token = sign_token(
        ghost_key, iss=ISS, aud=[RS], kid_override="ghost"
    )
    negative_now = [time.time()]
    negative_current = {"jwks": jwks_of(key1)}
    negative_fetches = {"n": 0}

    def negative_fetcher():
        negative_fetches["n"] += 1
        return negative_current["jwks"]

    negative_sdk = RsSdk(
        RsSdkConfig(
            resource_id=RS,
            issuer=ISS,
            now=lambda: negative_now[0],
            min_refetch_interval_secs=0,
            negative_cache_ttl_secs=300,
            jwks_fetcher=negative_fetcher,
        )
    )
    for _ in range(3):
        assert not negative_sdk.authenticate(f"Bearer {ghost_token}").ok
    assert negative_fetches["n"] == 1, "same unknown kid must hit negative cache"

    assert not negative_sdk.authenticate(f"Bearer {_forged('ghost-2')}").ok
    assert negative_fetches["n"] == 2, "negative cache must be keyed by kid"

    assert not negative_sdk.authenticate(f"Bearer {ghost_token}").ok
    assert negative_fetches["n"] == 3
    negative_current["jwks"] = {"keys": [key1.public_jwk, ghost_jwk]}
    negative_now[0] += 299
    assert not negative_sdk.authenticate(f"Bearer {ghost_token}").ok
    assert negative_fetches["n"] == 3, "negative cache must last 300 seconds"
    negative_now[0] += 2
    assert negative_sdk.authenticate(f"Bearer {ghost_token}").ok
    assert negative_fetches["n"] == 4, "expired negative entry must allow refetch"

    import threading

    concurrent_fetches = {"n": 0}
    counter_lock = threading.Lock()
    start = threading.Barrier(12)
    concurrent_results = []

    def concurrent_fetcher():
        with counter_lock:
            concurrent_fetches["n"] += 1
        time.sleep(0.05)
        return jwks_of(key1)

    concurrent_sdk = RsSdk(
        RsSdkConfig(
            resource_id=RS,
            issuer=ISS,
            min_refetch_interval_secs=0,
            negative_cache_ttl_secs=300,
            jwks_fetcher=concurrent_fetcher,
        )
    )

    def authenticate_concurrently():
        start.wait()
        concurrent_results.append(
            concurrent_sdk.authenticate(f"Bearer {_forged('concurrent-ghost')}")
        )

    threads = [
        threading.Thread(target=authenticate_concurrently) for _ in range(12)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(concurrent_results) == 12
    assert all(not result.ok for result in concurrent_results)
    assert concurrent_fetches["n"] == 1, "concurrent misses must share one refetch"

    fail = {"enabled": False}

    def failing_fetcher():
        if fail["enabled"]:
            raise RuntimeError("JWKS down")
        return jwks_of(key1)

    failure_sdk = RsSdk(
        RsSdkConfig(
            resource_id=RS,
            issuer=ISS,
            min_refetch_interval_secs=0,
            jwks_fetcher=failing_fetcher,
        )
    )
    failure_sdk.seed_jwks(jwks_of(key1))
    good = sign_token(key1, iss=ISS, aud=[RS])
    assert failure_sdk.authenticate(f"Bearer {good}").ok
    fail["enabled"] = True
    assert not failure_sdk.authenticate(f"Bearer {_forged('unavailable-kid')}").ok
    fresh_good = sign_token(key1, iss=ISS, aud=[RS], scope="kb:read")
    assert fresh_good != good
    assert failure_sdk.authenticate(f"Bearer {fresh_good}").ok
