"""spec 010 §3.5:introspection 消费路径 + 缓存 TTL 指引(非规范性)。

验:
- active:true 解析(命名空间 sub_type/auth_grant、aud 单元素、scope 分词);
- active:false 不透出其它字段(RFC 7662)+ **永不缓存**(吊销立即生效);
- cache_ttl_secs=0(高敏路由)→ 每次都真调 AS(无缓存残留窗口);
- cache_ttl_secs>0 → 正结果 TTL 内命中缓存、过期后重取;
- AS 不可用(非 200 / 抛错)→ VerifyError("unavailable")(RS 侧 fail-closed)。
"""

from __future__ import annotations

import pytest

from agent_auth_rs import (
    AccessRequest,
    IntrospectionClient,
    IntrospectionConfig,
    PolicyDecision,
    RarPolicy,
    RoutePolicy,
    VerifyError,
)
from agent_auth_rs.types import NAMESPACE

EP = "https://auth.example.com/introspect"
RS = "https://mcp.kb.example.com"


def _active_body():
    return {
        "active": True,
        "sub": "pairwise-sub-abc",
        "aud": [RS],
        "client_id": "agt_123",
        "scope": "read write",
        NAMESPACE: {
            "sub_type": "user",
            "auth_grant": "fam_xyz",
            "actor_types": {
                "agent-current": "agent",
                "service-earlier": "service",
            },
        },
    }


class _Caller:
    """可控 http_caller:记录调用次数,按预设返回。"""

    def __init__(self, responses):
        self.responses = responses  # list[(status, body)] 或单个 callable
        self.calls = 0

    def __call__(self, endpoint, form_body, auth_header):
        self.calls += 1
        assert endpoint == EP
        assert form_body.startswith("token=")
        assert auth_header.startswith("Basic ")
        r = self.responses
        if callable(r):
            return r(self.calls)
        # 列表:按次序取,超出用最后一个
        idx = min(self.calls - 1, len(r) - 1)
        return r[idx]


def test_active_true_parsed():
    caller = _Caller([(200, _active_body())])
    c = IntrospectionClient(
        IntrospectionConfig(EP, "agt_123", "sec", cache_ttl_secs=0, http_caller=caller)
    )
    r = c.introspect("tok-1")
    assert r.active
    assert r.sub == "pairwise-sub-abc"
    assert r.aud == RS  # 数组取首(单元素)
    assert r.client_id == "agt_123"
    assert r.scope == ["read", "write"]
    assert r.sub_type == "user"
    assert r.auth_grant == "fam_xyz"


def test_c2_2b_introspection_sdk_preserves_actor_types():
    caller = _Caller([(200, _active_body())])
    client = IntrospectionClient(
        IntrospectionConfig(
            EP,
            "agt_123",
            "sec",
            cache_ttl_secs=0,
            http_caller=caller,
        )
    )
    result = client.introspect("tok-c2-2b")
    assert result.sub_type == "user"
    assert result.auth_grant == "fam_xyz"
    assert result.actor_types == {
        "agent-current": "agent",
        "service-earlier": "service",
    }


def test_active_false_hides_other_fields():
    # active:false 时即便 body 带其它字段也不透出(RFC 7662)。
    caller = _Caller([(200, {"active": False, "sub": "leak", "scope": "x"})])
    c = IntrospectionClient(
        IntrospectionConfig(EP, "agt_123", "sec", http_caller=caller)
    )
    r = c.introspect("tok-2")
    assert not r.active
    assert r.sub is None
    assert r.scope == []


def test_high_sensitivity_no_cache_always_calls():
    # cache_ttl_secs=0(高敏路由):每次 introspect 都真调 AS,无缓存残留窗口。
    caller = _Caller([(200, _active_body())])
    c = IntrospectionClient(
        IntrospectionConfig(EP, "agt_123", "sec", cache_ttl_secs=0, http_caller=caller)
    )
    c.introspect("tok-3")
    c.introspect("tok-3")
    c.introspect("tok-3")
    assert caller.calls == 3, "cache_ttl_secs=0 应每次真调 AS(不缓存)"


def test_positive_cache_hits_within_ttl_then_refetches():
    clock = {"t": 1000.0}
    caller = _Caller([(200, _active_body())])
    c = IntrospectionClient(
        IntrospectionConfig(
            EP,
            "agt_123",
            "sec",
            cache_ttl_secs=5,
            now=lambda: clock["t"],
            http_caller=caller,
        )
    )
    c.introspect("tok-4")  # 真调(1)
    clock["t"] = 1003.0
    c.introspect("tok-4")  # 命中缓存(仍 1 次)
    assert caller.calls == 1, "TTL 内应命中缓存"
    clock["t"] = 1006.0  # 超过 5s TTL
    c.introspect("tok-4")  # 过期重取(2)
    assert caller.calls == 2, "TTL 过期应重取"


def test_active_false_never_cached():
    # active:false 永不缓存:即便配了 TTL,每次都真调(吊销立即生效)。
    caller = _Caller([(200, {"active": False})])
    c = IntrospectionClient(
        IntrospectionConfig(EP, "agt_123", "sec", cache_ttl_secs=60, http_caller=caller)
    )
    c.introspect("tok-5")
    c.introspect("tok-5")
    assert caller.calls == 2, "active:false 永不缓存(每次真调,吊销立即反映)"


def test_revocation_reflected_after_ttl():
    # 正结果缓存后,token 被吊销 → AS 返 active:false;TTL 过期后重取拿到 false。
    clock = {"t": 0.0}

    def responses(call_n):
        return (200, _active_body()) if call_n == 1 else (200, {"active": False})

    caller = _Caller(responses)
    c = IntrospectionClient(
        IntrospectionConfig(
            EP,
            "agt_123",
            "sec",
            cache_ttl_secs=5,
            now=lambda: clock["t"],
            http_caller=caller,
        )
    )
    assert c.introspect("tok-6").active  # 首次 active
    clock["t"] = 10.0  # TTL 过期
    assert not c.introspect("tok-6").active  # 重取拿到吊销后的 false


def test_as_unavailable_raises():
    caller = _Caller([(503, {})])
    c = IntrospectionClient(
        IntrospectionConfig(EP, "agt_123", "sec", http_caller=caller)
    )
    try:
        c.introspect("tok-7")
        assert False, "非 200 应 raise"
    except VerifyError as e:
        assert e.kind == "unavailable"


def test_caller_exception_maps_to_unavailable():
    def boom(endpoint, form_body, auth_header):
        raise ConnectionError("network down")

    c = IntrospectionClient(IntrospectionConfig(EP, "agt_123", "sec", http_caller=boom))
    try:
        c.introspect("tok-8")
        assert False, "网络错应 raise"
    except VerifyError as e:
        assert e.kind == "unavailable"


def test_invalidate_clears_cache():
    caller = _Caller([(200, _active_body())])
    c = IntrospectionClient(
        IntrospectionConfig(EP, "agt_123", "sec", cache_ttl_secs=60, http_caller=caller)
    )
    c.introspect("tok-9")  # 缓存(1)
    c.invalidate("tok-9")  # 主动清
    c.introspect("tok-9")  # 重取(2)
    assert caller.calls == 2, "invalidate 后应重取"


def test_c8_5b_introspection_evaluator_runs_only_after_active_audience_and_scope():
    complex_detail = {
        "type": "cedar_policy",
        "policy_ref": "doc-read",
        "locations": [RS],
    }
    calls = []

    def evaluator(detail, request, claims):
        calls.append((detail, request, claims))
        return PolicyDecision.ALLOW

    policy = RoutePolicy(
        require_sub_type="user",
        require_scopes=["read"],
        rar=RarPolicy(
            request=AccessRequest(resource=RS),
            evaluator=evaluator,
        ),
    )

    def client_for(body):
        return IntrospectionClient(
            IntrospectionConfig(
                EP,
                "agt_123",
                "sec",
                resource_id=RS,
                http_caller=_Caller([(200, body)]),
            )
        )

    inactive = {"active": False, "authorization_details": [complex_detail]}
    non_boolean_active = {
        **_active_body(),
        "active": "false",
        "authorization_details": [complex_detail],
    }
    wrong_audience = {
        **_active_body(),
        "aud": ["https://mcp.other.example.com"],
        "authorization_details": [complex_detail],
    }
    missing_scope = {
        **_active_body(),
        "scope": "write",
        "authorization_details": [complex_detail],
    }
    wrong_sub_type = {
        **_active_body(),
        NAMESPACE: {
            **_active_body()[NAMESPACE],
            "sub_type": "agent",
        },
        "authorization_details": [complex_detail],
    }
    multiple_audiences = {
        **_active_body(),
        "aud": [RS, "https://mcp.other.example.com"],
        "authorization_details": [complex_detail],
    }
    malformed_rar = {
        **_active_body(),
        "authorization_details": {"type": "cedar_policy"},
    }
    empty_rar = {
        **_active_body(),
        "authorization_details": {},
    }
    malformed_detail = {
        **_active_body(),
        "authorization_details": [42, complex_detail],
    }
    missing_type = {
        **_active_body(),
        "authorization_details": [{"policy_ref": "missing-type"}, complex_detail],
    }
    for body in (
        inactive,
        non_boolean_active,
        wrong_audience,
        missing_scope,
        wrong_sub_type,
        multiple_audiences,
        malformed_rar,
        empty_rar,
        malformed_detail,
        missing_type,
    ):
        with pytest.raises(VerifyError):
            client_for(body).authorize("tok-c8-5b", policy)
        assert calls == []

    valid = {
        **_active_body(),
        "authorization_details": [complex_detail],
    }
    allowed = client_for(valid).authorize("tok-c8-5b", policy)
    assert allowed.active
    assert len(calls) == 1
    detail, request, claims = calls[0]
    assert detail["policy_ref"] == "doc-read"
    assert request.resource == RS
    assert dict(claims) == {"sub": "pairwise-sub-abc", "scope": "read write"}

    denied_client = client_for(valid)
    with pytest.raises(VerifyError) as denied:
        denied_client.authorize(
            "tok-c8-5b",
            RoutePolicy(
                require_sub_type="user",
                require_scopes=["read"],
                rar=RarPolicy(
                    request=AccessRequest(resource=RS),
                    evaluator=lambda _detail, _request, _claims: PolicyDecision.DENY,
                ),
            ),
        )
    assert denied.value.kind == "insufficient_scope"
