"""spec 010 C8.5a:声明式 RAR 约束词汇表 + 执行拦截越界读。

验:valid_from/to 时间范围、resource_subset 白名单、max_records 上界的执行;
fail-safe 红线(未知 type/未知约束字段整条拒);多条选中(locations);RAR 缺失回退。
"""

from __future__ import annotations

from agent_auth_rs import AccessRequest, enforce_rar, RAR_TYPE_V1

RS = "https://mcp.kb.example.com"


def v1(**fields):
    return {"type": RAR_TYPE_V1, **fields}


# --- RAR 缺失 → 放行(回退 scope) ---
def test_missing_rar_allows():
    r = enforce_rar(None, AccessRequest(resource=RS))
    assert r.allowed and not r.matched
    r = enforce_rar([], AccessRequest(resource=RS))
    assert r.allowed and not r.matched


# --- resource_subset:精确 + 前缀 + 空 deny-all ---
def test_resource_subset_exact():
    ad = [v1(resource_subset=[RS, "https://other/"])]
    assert enforce_rar(ad, AccessRequest(resource=RS)).allowed
    assert not enforce_rar(ad, AccessRequest(resource="https://evil")).allowed


def test_resource_subset_prefix():
    ad = [v1(resource_subset=["https://mcp.kb.example.com/docs/"])]
    assert enforce_rar(ad, AccessRequest(resource="https://mcp.kb.example.com/docs/2026/q1")).allowed
    # 前缀外 → 拒。
    assert not enforce_rar(ad, AccessRequest(resource="https://mcp.kb.example.com/secrets/x")).allowed


def test_resource_subset_empty_deny_all():
    ad = [v1(resource_subset=[])]
    r = enforce_rar(ad, AccessRequest(resource=RS))
    assert not r.allowed, "空 resource_subset = deny-all"


# --- valid_from/valid_to:数据时刻范围(闭区间) ---
def test_valid_time_range():
    # 2026-01-01 .. 2026-12-31(epoch)。
    ad = [v1(valid_from="2026-01-01T00:00:00Z", valid_to="2026-12-31T23:59:59Z")]
    import datetime

    inside = datetime.datetime(2026, 6, 1, tzinfo=datetime.timezone.utc).timestamp()
    before = datetime.datetime(2025, 6, 1, tzinfo=datetime.timezone.utc).timestamp()
    after = datetime.datetime(2027, 6, 1, tzinfo=datetime.timezone.utc).timestamp()
    assert enforce_rar(ad, AccessRequest(resource=RS, requested_time=inside)).allowed
    assert not enforce_rar(ad, AccessRequest(resource=RS, requested_time=before)).allowed
    assert not enforce_rar(ad, AccessRequest(resource=RS, requested_time=after)).allowed


def test_valid_time_missing_requested_time_fails_closed():
    ad = [v1(valid_from="2026-01-01T00:00:00Z")]
    # 约束含时间范围但请求没带 requested_time → fail-closed。
    assert not enforce_rar(ad, AccessRequest(resource=RS)).allowed


def test_valid_time_parse_failure_fails_closed():
    ad = [v1(valid_from="not-a-date")]
    assert not enforce_rar(ad, AccessRequest(resource=RS, requested_time=0)).allowed


def test_valid_time_epoch_form():
    ad = [v1(valid_from=1000, valid_to=2000)]
    assert enforce_rar(ad, AccessRequest(resource=RS, requested_time=1500)).allowed
    assert not enforce_rar(ad, AccessRequest(resource=RS, requested_time=2500)).allowed
    # 边界闭区间:端点放行。
    assert enforce_rar(ad, AccessRequest(resource=RS, requested_time=1000)).allowed
    assert enforce_rar(ad, AccessRequest(resource=RS, requested_time=2000)).allowed


# --- max_records:计数上界 ---
def test_max_records():
    ad = [v1(max_records=100)]
    assert enforce_rar(ad, AccessRequest(resource=RS, declared_count=50)).allowed
    assert enforce_rar(ad, AccessRequest(resource=RS, declared_count=100)).allowed
    assert not enforce_rar(ad, AccessRequest(resource=RS, declared_count=101)).allowed


def test_max_records_missing_count_fails_closed():
    ad = [v1(max_records=100)]
    assert not enforce_rar(ad, AccessRequest(resource=RS)).allowed


# --- fail-safe 红线:未知 type ---
def test_unknown_type_fails_closed():
    ad = [{"type": "some_future_rar_type", "resource_subset": [RS]}]
    r = enforce_rar(ad, AccessRequest(resource=RS))
    assert not r.allowed
    assert "未知 RAR type" in (r.reason or "")


# --- fail-safe 红线:词汇表外未知约束字段(整条拒,原子性) ---
def test_unknown_constraint_field_fails_closed():
    # 已知 type + 已知字段 resource_subset,但混入未知约束字段 max_bytes → 整条拒。
    ad = [v1(resource_subset=[RS], max_bytes=1024)]
    r = enforce_rar(ad, AccessRequest(resource=RS))
    assert not r.allowed, "未知约束字段应整条 fail-closed(不部分执行)"
    assert "未知约束字段" in (r.reason or "")


def test_rfc9396_meta_fields_not_treated_as_unknown():
    # locations/identifier 等 RFC 9396 元数据不触发未知字段拒。
    ad = [v1(resource_subset=[RS], locations=[RS], identifier="grant-1")]
    assert enforce_rar(ad, AccessRequest(resource=RS)).allowed


# --- 多条选中:locations 匹配 ---
def test_multiple_details_locations_selection():
    ad = [
        v1(locations=["https://other/"], resource_subset=["https://other/x"]),  # 不适用本 resource
        v1(locations=[RS], max_records=10),  # 适用本 resource
    ]
    # 选中第二条(locations 含 RS),max_records=10。
    assert enforce_rar(ad, AccessRequest(resource=RS, declared_count=5)).allowed
    assert not enforce_rar(ad, AccessRequest(resource=RS, declared_count=20)).allowed


def test_no_applicable_detail_fails_closed():
    # 有 RAR 但无一条 locations 匹配本次 resource → fail-closed。
    ad = [v1(locations=["https://other/"], resource_subset=["https://other/x"])]
    r = enforce_rar(ad, AccessRequest(resource=RS))
    assert not r.allowed
    assert not r.matched


def test_or_semantics_across_details():
    # 两条都适用(无 locations = 全局);第一条拒(count 超),第二条通过 → OR → 放行。
    ad = [
        v1(max_records=1),
        v1(resource_subset=[RS]),
    ]
    assert enforce_rar(ad, AccessRequest(resource=RS, declared_count=100)).allowed


# --- 组合约束(单条内 AND) ---
def test_combined_constraints_within_one_detail():
    ad = [v1(resource_subset=[RS], max_records=10)]
    # resource 通过 + count 通过 → 放行。
    assert enforce_rar(ad, AccessRequest(resource=RS, declared_count=5)).allowed
    # resource 通过但 count 超 → 拒(单条内 AND)。
    assert not enforce_rar(ad, AccessRequest(resource=RS, declared_count=50)).allowed


def test_c8_5a_builtin_vocabulary_enforces_all_constraints():
    assert RAR_TYPE_V1 == "agent_auth_rar_v1"
    for absent in (None, []):
        result = enforce_rar(absent, AccessRequest(resource=RS))
        assert result.allowed and not result.matched
    assert not enforce_rar("not-an-array", AccessRequest(resource=RS)).allowed

    combined = [
        v1(
            locations=[RS],
            valid_from=1000,
            valid_to=2000,
            resource_subset=[RS, "https://mcp.kb.example.com/docs/"],
            max_records=10,
        )
    ]
    for requested_time in (1000, 1500, 2000):
        assert enforce_rar(
            combined,
            AccessRequest(
                resource=RS,
                requested_time=requested_time,
                declared_count=10,
            ),
        ).allowed

    denied_requests = [
        AccessRequest(resource=RS, requested_time=999, declared_count=10),
        AccessRequest(resource=RS, requested_time=2001, declared_count=10),
        AccessRequest(
            resource="https://evil.example.com",
            requested_time=1500,
            declared_count=10,
        ),
        AccessRequest(resource=RS, requested_time=1500, declared_count=11),
        AccessRequest(resource=RS, declared_count=10),
        AccessRequest(resource=RS, requested_time=1500),
    ]
    for request in denied_requests:
        assert not enforce_rar(combined, request).allowed

    rfc3339 = [
        v1(
            valid_from="2026-01-01T00:00:00Z",
            valid_to="2026-12-31T23:59:59Z",
        )
    ]
    assert enforce_rar(
        rfc3339,
        AccessRequest(resource=RS, requested_time=1780272000),
    ).allowed
    assert not enforce_rar(
        rfc3339,
        AccessRequest(resource=RS, requested_time=1735689599),
    ).allowed
    invalid_instants = [
        "not-a-date",
        "2026-01-01",
        "2026-02-30T00:00:00Z",
        True,
        float("nan"),
        float("inf"),
    ]
    for invalid_instant in invalid_instants:
        assert not enforce_rar(
            [v1(valid_to=invalid_instant)],
            AccessRequest(resource=RS, requested_time=0),
        ).allowed

    exact_resource = [v1(resource_subset=[RS])]
    assert enforce_rar(
        exact_resource,
        AccessRequest(resource=RS),
    ).allowed
    assert not enforce_rar(
        exact_resource,
        AccessRequest(resource=f"{RS}/child"),
    ).allowed

    prefix = [v1(resource_subset=["https://mcp.kb.example.com/docs/"])]
    assert enforce_rar(
        prefix,
        AccessRequest(resource="https://mcp.kb.example.com/docs/2026/q1"),
    ).allowed
    assert not enforce_rar(
        prefix,
        AccessRequest(resource="https://mcp.kb.example.com/docsets/2026"),
    ).allowed
    assert not enforce_rar(
        [v1(resource_subset=[])],
        AccessRequest(resource=RS),
    ).allowed

    for invalid_count in (True, 10.5):
        assert not enforce_rar(
            [v1(max_records=invalid_count)],
            AccessRequest(resource=RS, declared_count=1),
        ).allowed

    assert not enforce_rar(
        [{"type": "future_rar", "resource_subset": [RS]}],
        AccessRequest(resource=RS),
    ).allowed
    assert not enforce_rar(
        [v1(resource_subset=[RS], max_bytes=1024)],
        AccessRequest(resource=RS),
    ).allowed
    assert not enforce_rar(
        [v1(locations=["https://other.example.com"], resource_subset=[RS])],
        AccessRequest(resource=RS),
    ).allowed

    multiple = [
        v1(locations=[RS], max_records=1),
        v1(locations=[RS], resource_subset=[RS]),
    ]
    assert enforce_rar(
        multiple,
        AccessRequest(resource=RS, declared_count=100),
    ).allowed
