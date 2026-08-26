"""C8.5b 复杂/策略型 RAR 可插拔评估器测试(spec 010 §5.1;设计双评审收敛)。

覆盖:type-keyed 分派(B1)/ deny-only 返回 + 冻结投影(B2)/ 未注册向后兼容 / 异常 fail-closed(H1)/
全 deny == 无 evaluator(H3)/ v1+额外字段 / 离线 JWT 与 introspection 同形状路径。
"""

from dataclasses import FrozenInstanceError
from types import MappingProxyType

import pytest

from agent_auth_rs.rar import (
    AccessRequest,
    PolicyDecision,
    RAR_TYPE_V1,
    _enforce_rar_with_evaluator,
    enforce_rar as enforce_simple_rar,
)

REQ = AccessRequest(resource="https://mcp.a.example.com")

# 一条词汇表外(策略型)detail:type != v1。
CX = {
    "type": "cedar_policy",
    "policy_ref": "doc-read",
    "locations": [REQ.resource],
    "context": {"classification": "internal"},
}


def enforce_rar(authorization_details, req, *, evaluator=None, claims=None):
    """测试内部 evaluator 语义；公开 package API 不暴露本入口。"""
    if evaluator is None and claims is None:
        return enforce_simple_rar(authorization_details, req)
    return _enforce_rar_with_evaluator(
        authorization_details,
        req,
        evaluator=evaluator,
        claims=claims,
    )


def allow_all(detail, req, claims):
    return PolicyDecision.ALLOW


def deny_all(detail, req, claims):
    return PolicyDecision.DENY


# ── 向后兼容:未注册 evaluator 时词汇表外条目整条拒(C8.5a 逐字节)──


def test_no_evaluator_out_of_vocab_type_rejected():
    r = enforce_rar([CX], REQ)  # 不传 evaluator
    assert not r.allowed
    assert r.matched


def test_no_evaluator_v1_with_extra_field_rejected():
    # type==v1 但含词汇表外字段 → 仍整条拒(评审 B1:并集判据)。
    d = {"type": RAR_TYPE_V1, "resource_subset": [REQ.resource], "weird_field": 1}
    r = enforce_rar([d], REQ)
    assert not r.allowed


# ── C8.5b:注册 evaluator 后词汇表外条目委托它判 ──


def test_evaluator_allow_passes():
    r = enforce_rar([CX], REQ, evaluator=allow_all)
    assert r.allowed
    assert r.matched


def test_evaluator_deny_rejects():
    r = enforce_rar([CX], REQ, evaluator=deny_all)
    assert not r.allowed
    assert r.matched


# ── B1:type==v1 的 vocab-pure 条 SDK 独占,即便注册了 evaluator 也不委托 ──


def test_v1_vocab_pure_never_delegates_even_with_evaluator():
    # evaluator 会拒一切;但 vocab-pure v1 条由 SDK 判(resource 在白名单 → 通过),不经 evaluator。
    def deny_everything(detail, req, claims):
        raise AssertionError("vocab-pure v1 条不该委托 evaluator")

    d = {"type": RAR_TYPE_V1, "resource_subset": [REQ.resource]}
    r = enforce_rar([d], REQ, evaluator=deny_everything)
    assert r.allowed  # SDK 词汇执行:resource 在白名单


# ── B1:type==v1 + 额外字段 → 既跑 SDK 词汇约束又跑 evaluator(AND)──


def test_v1_with_extra_field_needs_both_sdk_and_evaluator():
    d = {"type": RAR_TYPE_V1, "resource_subset": [REQ.resource], "extra": 1}
    # evaluator 通过但 SDK 词汇约束也须过:resource 在白名单 → 整体过。
    assert enforce_rar([d], REQ, evaluator=allow_all).allowed
    # evaluator 拒 → 整条拒(即便 SDK 词汇约束会过)。
    assert not enforce_rar([d], REQ, evaluator=deny_all).allowed
    # evaluator 过但 SDK 词汇约束拒(resource 不在白名单)→ 整条拒(AND)。
    d2 = {"type": RAR_TYPE_V1, "resource_subset": ["https://other/"], "extra": 1}
    assert not enforce_rar([d2], REQ, evaluator=allow_all).allowed


# ── B2:deny-only —— 非 ALLOW 的任何返回都按拒 ──


@pytest.mark.parametrize(
    "bad_return", [PolicyDecision.DENY, None, True, "allow", 1, object()]
)
def test_evaluator_non_allow_return_is_denied(bad_return):
    r = enforce_rar([CX], REQ, evaluator=lambda d, q, c: bad_return)
    assert not r.allowed, f"非 PolicyDecision.ALLOW 的返回 {bad_return!r} MUST 按拒"


# ── H1:evaluator 抛异常 → fail-closed 拒(引擎不可用不得变放行)──


def test_evaluator_exception_fail_closed():
    def boom(detail, req, claims):
        raise RuntimeError("policy engine down")

    r = enforce_rar([CX], REQ, evaluator=boom)
    assert not r.allowed


# ── B2:claims 投影运行时冻结 + 只含 {sub, scope}(去 aud)──


def test_claims_projection_frozen_and_minimal():
    captured = {}

    def capture(detail, req, claims):
        captured["view"] = claims
        # 尝试篡改应抛(MappingProxyType 不可变)。
        with pytest.raises(TypeError):
            claims["scope"] = "admin"  # type: ignore[index]
        return PolicyDecision.ALLOW

    claims = {
        "sub": "user:alice",
        "scope": "read",
        "aud": ["https://mcp.a.example.com"],
        "iss": "x",
    }
    enforce_rar([CX], REQ, evaluator=capture, claims=claims)
    view = captured["view"]
    assert isinstance(view, MappingProxyType)
    assert dict(view) == {
        "sub": "user:alice",
        "scope": "read",
    }  # 去 aud/iss,只投影 sub/scope


# ── H3:开 C8.5b 且 evaluator 全 deny 时结局 == 无 evaluator(不放宽 all-deny)──


def test_all_deny_equals_no_evaluator():
    details = [CX, {"type": "another_policy", "locations": [REQ.resource]}]
    without = enforce_rar(details, REQ)
    with_deny = enforce_rar(details, REQ, evaluator=deny_all)
    assert without.allowed == with_deny.allowed == False  # noqa: E712


# ── H3:数组内混合(v1 限制型 + 策略型)OR 语义 ──


def test_mixed_array_or_semantics():
    # v1 条 resource 不在白名单(拒) + 策略型条 evaluator 放行 → OR → 整体放行。
    v1_deny = {
        "type": RAR_TYPE_V1,
        "resource_subset": ["https://other/"],
        "locations": [REQ.resource],
    }
    r = enforce_rar([v1_deny, CX], REQ, evaluator=allow_all)
    assert r.allowed  # 策略型条通过 → OR 放行
    # 两条都拒 → 整体拒。
    assert not enforce_rar([v1_deny, CX], REQ, evaluator=deny_all).allowed


# ── H3:introspection-shaped 输入(同形状 authorization_details)也经 evaluator ──


def test_introspection_shaped_input_uses_evaluator():
    # introspection 响应的 authorization_details 与 JWT claims 同形状 → 同一 enforce_rar 入口。
    introspection_ad = [CX]
    assert enforce_rar(introspection_ad, REQ, evaluator=allow_all).allowed
    assert not enforce_rar(introspection_ad, REQ, evaluator=deny_all).allowed


# ── evaluator 拿到的 detail 是原始 JSON(含策略型字段),且是冻结视图 ──


def test_evaluator_receives_raw_detail_frozen():
    seen = {}

    def capture(detail, req, claims):
        seen["detail"] = dict(detail)
        with pytest.raises(TypeError):
            detail["injected"] = 1  # type: ignore[index]
        return PolicyDecision.ALLOW

    enforce_rar([CX], REQ, evaluator=capture)
    assert seen["detail"]["type"] == "cedar_policy"
    assert seen["detail"]["policy_ref"] == "doc-read"


def test_c8_5b_policy_evaluator_is_deny_only_and_fail_closed():
    assert not enforce_rar([CX], REQ).allowed
    with pytest.raises(TypeError):
        enforce_simple_rar([CX], REQ, evaluator=allow_all)
    assert enforce_rar([CX], REQ, evaluator=allow_all).allowed
    assert not enforce_rar([CX], REQ, evaluator=deny_all).allowed

    class AwaitableAllow:
        def __await__(self):
            if False:
                yield None
            return PolicyDecision.ALLOW

    rejected_values = [
        PolicyDecision.DENY,
        None,
        True,
        "allow",
        1,
        {},
        AwaitableAllow(),
    ]
    for value in rejected_values:
        assert not enforce_rar(
            [CX],
            REQ,
            evaluator=lambda _detail, _request, _claims, value=value: value,
        ).allowed

    def boom(_detail, _request, _claims):
        raise RuntimeError("policy engine unavailable")

    assert not enforce_rar([CX], REQ, evaluator=boom).allowed

    def must_not_delegate(_detail, _request, _claims):
        raise AssertionError("vocab-pure v1 must remain SDK-owned")

    vocab_pure = {"type": RAR_TYPE_V1, "resource_subset": [REQ.resource]}
    assert enforce_rar([vocab_pure], REQ, evaluator=must_not_delegate).allowed

    extended = {
        "type": RAR_TYPE_V1,
        "resource_subset": [REQ.resource],
        "policy_ref": "doc-read",
    }
    assert enforce_rar([extended], REQ, evaluator=allow_all).allowed
    assert not enforce_rar([extended], REQ, evaluator=deny_all).allowed
    extended_outside_resource = {
        **extended,
        "resource_subset": ["https://other.example.com"],
    }
    assert not enforce_rar(
        [extended_outside_resource],
        REQ,
        evaluator=allow_all,
    ).allowed

    evaluator_calls = []

    def must_not_run_before_v1_constraints(detail, request, claims):
        evaluator_calls.append((detail, request, claims))
        request.declared_count = 0
        return PolicyDecision.ALLOW

    hostile_request = AccessRequest(resource=REQ.resource, declared_count=10)
    guarded_extended = {
        "type": RAR_TYPE_V1,
        "max_records": 1,
        "policy_ref": "doc-read",
    }
    assert not enforce_rar(
        [guarded_extended],
        hostile_request,
        evaluator=must_not_run_before_v1_constraints,
    ).allowed
    assert evaluator_calls == []
    assert hostile_request.declared_count == 10

    malformed_calls = []
    malformed_extended = {
        "type": RAR_TYPE_V1,
        "max_records": "one",
        "policy_ref": "doc-read",
    }
    assert not enforce_rar(
        [malformed_extended],
        AccessRequest(resource=REQ.resource, declared_count=1),
        evaluator=lambda detail, request, claims: (
            malformed_calls.append((detail, request, claims)) or PolicyDecision.ALLOW
        ),
    ).allowed
    assert malformed_calls == []

    captured = {}
    source_request = AccessRequest(resource=REQ.resource)

    def capture(detail, request, claims):
        captured["detail"] = detail
        captured["request"] = request
        captured["claims"] = claims
        with pytest.raises(TypeError):
            detail["injected"] = True  # type: ignore[index]
        with pytest.raises(AttributeError):
            detail["locations"].append("https://evil.example.com")
        with pytest.raises(TypeError):
            detail["context"]["classification"] = "public"
        with pytest.raises(TypeError):
            claims["scope"] = "admin"  # type: ignore[index]
        with pytest.raises(AttributeError):
            claims["scope"].append("admin")
        with pytest.raises(FrozenInstanceError):
            request.resource = "https://evil.example.com"
        return PolicyDecision.ALLOW

    source_scope = ["read", "write"]
    source_claims = {
        "sub": "user:alice",
        "scope": source_scope,
        "aud": [REQ.resource],
        "iss": "https://auth.example.com",
    }
    assert enforce_rar(
        [CX],
        source_request,
        evaluator=capture,
        claims=source_claims,
    ).allowed
    assert captured["request"] is not source_request
    assert source_request.resource == REQ.resource
    assert isinstance(captured["detail"], MappingProxyType)
    assert captured["detail"]["type"] == CX["type"]
    assert captured["detail"]["policy_ref"] == CX["policy_ref"]
    assert captured["detail"]["locations"] == (REQ.resource,)
    assert isinstance(captured["detail"]["context"], MappingProxyType)
    assert dict(captured["detail"]["context"]) == {"classification": "internal"}
    assert isinstance(captured["claims"], MappingProxyType)
    assert dict(captured["claims"]) == {
        "sub": "user:alice",
        "scope": "read write",
    }
    assert source_scope == ["read", "write"]

    vocab_deny = {
        "type": RAR_TYPE_V1,
        "resource_subset": ["https://other.example.com"],
        "locations": [REQ.resource],
    }
    assert enforce_rar([vocab_deny, CX], REQ, evaluator=allow_all).allowed
    assert not enforce_rar([vocab_deny, CX], REQ, evaluator=deny_all).allowed
    assert enforce_rar([CX], REQ, evaluator=allow_all).allowed
