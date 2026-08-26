"""Agent Auth RS SDK — 声明式 RAR 约束词汇表 + 执行(spec 010 C8.5a P2 / C8.5b P3)。

RFC 9396 `authorization_details` 是数组、每条带 `type` + 部署自定义字段。本 SDK 定义一组
**标准化、可通用识别执行的声明式约束词汇表**(词汇表内 = C8.5a 简单执行 P2;词汇表外/需策略引擎
= C8.5b P3),把 token(离线校验)或 introspection 响应里的约束**真正拦截越界读**——否则细粒度
授权是空承诺(docs §6)。

**词汇表(type = `agent_auth_rar_v1`)**:
- `valid_from`/`valid_to`:**可访问数据的时间范围**(非 token 有效期,那由 exp/nbf 管);RS 传本次
  访问的数据时刻 `requested_time`,判 ∈ [from, to](闭区间)。RFC 3339 UTC / epoch 秒;一端 null=不限该端。
- `resource_subset`:资源子集白名单(string[]);RS 传 `requested_resource`,判 ∈ 白名单
  (精确匹配;item 以 `/` 结尾 = 前缀匹配)。空数组 = deny-all(明确什么都不给,≠不限)。
- `max_records`:记录数上界;RS 传本次声明返回的 `requested_count`,判 ≤ max(SDK 不执行查询,
  校 RS 自证的计数;真正拦在 RS 返回前调本函数)。

**fail-safe 红线(codex+Kiro 双评审收敛,最关键裁决)**:
- **未知 `type`** → 整条 fail-closed 拒(**除非** RS 注册了策略评估器,见 C8.5b);未知 type 可能携带不可执行语义。
- **词汇表外的未知约束字段**(混在 `type==v1` 的一条里)→ **整条拒**(原子性:单条约束全部可执行 OR 全部拒,
  绝不"部分执行" —— 部分执行 = 放宽联合约束 = 越权漏洞)。RFC 9396 元数据字段(locations/type)不算约束。
- **多条选中**:按 `locations`(RFC 9396)匹配本次 resource(无 locations = 全局适用);任一匹配条
  全约束通过 → 放行;所有匹配条拒 OR 无匹配条 → 拒(fail-closed)。
- **RAR 缺失**(无 authorization_details)→ 本函数不拦(返回 allow),回退 scope/aud 级授权
  (RAR 是可选增强,RFC 9396 §2);RS 若要求"敏感路由必须有 RAR"由 RS 自策略据 has_rar 拒。

**C8.5b 复杂/策略型 RAR(可插拔评估器,P3,设计双评审收敛)**:词汇表外(`type != agent_auth_rar_v1`)的
detail 交 RS 注册的**策略评估器** `evaluator` 判定(内可接 Cedar/cedarpy 等),而非无条件拒。铁律:
- **严格 type-keyed 分派**(B1):vocab-pure `type==agent_auth_rar_v1` 由 SDK 独占;`type!=v1` 整条交
  evaluator;v1+额外字段由 SDK 词汇约束与 evaluator 共同判定(AND)。
- **未注册 evaluator → 词汇表外条目照旧整条拒**(C8.5a 逐字节向后兼容)。
- **只收窄绝不扩权,由类型钉死**(B2):evaluator 返回 `PolicyDecision`,只有 `PolicyDecision.ALLOW` 放行,
  其余(DENY / 抛异常 / 返回非 PolicyDecision / None)=拒;返回值**无法携带** scope/claims(不可表达 allow-with-extra)。
- **evaluator 输入运行时冻结**:detail 是递归冻结 JSON 副本;request 是冻结防御副本;token claims 是
  `MappingProxyType` 最小投影,防 evaluator 修改 detail/request/claims 后反噬。
- evaluator 本身**不引任何策略引擎**——SDK core 零 cedar 依赖;参考 Cedar 样例见 tests(cedarpy,非规范性)。
"""

from __future__ import annotations

import enum
import math
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Mapping, Optional

# 本 SDK 识别的 RAR type(词汇表版本;未来扩展新 type 需 SDK 显式支持)。
RAR_TYPE_V1 = "agent_auth_rar_v1"

# 词汇表内的约束字段(执行语义已定义)。
_VOCAB_CONSTRAINT_FIELDS = {"valid_from", "valid_to", "resource_subset", "max_records"}
# RFC 9396 固有的元数据字段(非约束,不触发未知字段 fail-closed)。
_RFC9396_META_FIELDS = {
    "type",
    "locations",
    "actions",
    "datatypes",
    "identifier",
    "privileges",
}
_RFC3339_INSTANT = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


class PolicyDecision(enum.Enum):
    """C8.5b 策略评估器的**封闭 deny-only 判定**(spec 010 §5.1,评审 B2)。

    只有 `ALLOW` 放行;其余一切(`DENY` / evaluator 返回非 `PolicyDecision` / `None` / 抛异常 / 未决)
    一律按拒处理。**故意不承载 scope/claims/attributes** —— evaluator 无法表达"allow-with-extra",
    结果只与整条 detail 结局逻辑 AND(RAR 只收窄、绝不作授权来源)。
    """

    ALLOW = "allow"
    DENY = "deny"


# C8.5b 策略评估器 hook(**同步**,评审 H1:异步会破坏 C8.5a 同步签名)。RS 在启动时预实例化策略引擎
# (Cedar 等,唯一 async 步),注册的闭包**同步**调已加载引擎。签名:(detail 原始 JSON, AccessRequest,
# 冻结 claims 投影) → PolicyDecision。返回非 PolicyDecision / 抛异常 → SDK 按拒处理(fail-closed)。
PolicyEvaluator = Callable[
    [Mapping[str, Any], "AccessRequest", Mapping[str, Any]], "PolicyDecision"
]


@dataclass(frozen=True)
class AccessRequest:
    """RS 本次访问的描述(供 RAR 执行比对)。"""

    resource: str  # 本次访问的资源标识(URI);用于 resource_subset + locations 选中
    requested_time: Optional[float] = (
        None  # 访问的数据时刻(Unix 秒);校 valid_from/valid_to 时必填
    )
    declared_count: Optional[int] = (
        None  # RS 声明本次返回的记录数;校 max_records 时必填
    )


@dataclass
class RarResult:
    allowed: bool
    reason: Optional[str] = None
    matched: bool = (
        False  # 是否有适用本次请求的 RAR 条目(便于 RS 区分"无约束放行" vs "约束通过")
    )


def _parse_instant(v: Any) -> Optional[float]:
    """RFC 3339 字符串 或 epoch 秒 → Unix 秒;解析失败返回 None(上层据此 fail-closed)。"""
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        parsed = float(v)
        return parsed if math.isfinite(parsed) else None
    if isinstance(v, str):
        import datetime

        if _RFC3339_INSTANT.fullmatch(v) is None:
            return None
        s = v
        # 兼容末尾 Z(UTC)。
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            parsed = datetime.datetime.fromisoformat(s)
            if parsed.tzinfo is None:
                return None
            return parsed.timestamp()
        except (OverflowError, ValueError):
            return None
    return None


def _resource_in_subset(resource: str, subset: list) -> bool:
    """resource ∈ 白名单:精确匹配;item 以 `/` 结尾则前缀匹配。"""
    for item in subset:
        if not isinstance(item, str):
            continue
        if item.endswith("/"):
            if resource.startswith(item):
                return True
        elif resource == item:
            return True
    return False


def _detail_applies(detail: dict, resource: str) -> bool:
    """该条 RAR 是否适用本次 resource:有 locations 则按 locations 匹配;无 locations = 全局适用。"""
    locs = detail.get("locations")
    if locs is None:
        return True
    if not isinstance(locs, list):
        return False
    return _resource_in_subset(resource, locs)


def _detail_shape_is_valid(detail: Any) -> bool:
    """Validate the RFC 9396 fields that control dispatch and resource selection."""
    if not isinstance(detail, dict):
        return False
    detail_type = detail.get("type")
    if not isinstance(detail_type, str) or not detail_type.strip():
        return False
    locations = detail.get("locations")
    return locations is None or (
        isinstance(locations, list)
        and all(isinstance(location, str) for location in locations)
    )


def _deep_freeze_json(value: Any) -> Any:
    """递归复制并冻结 JSON 值;数组转 tuple,对象转 MappingProxyType。"""
    if isinstance(value, dict):
        return MappingProxyType(
            {key: _deep_freeze_json(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_deep_freeze_json(item) for item in value)
    return value


def _run_evaluator(
    evaluator: PolicyEvaluator,
    detail: dict,
    req: AccessRequest,
    claims_view: Mapping[str, Any],
) -> bool:
    """跑 evaluator,**deny-only 折叠**(评审 B2):仅返回 PolicyDecision.ALLOW 才 True;其余
    (DENY / 非 PolicyDecision / None / 抛异常)一律 False(fail-closed)。detail 传递归冻结副本。"""
    try:
        request_view = AccessRequest(
            resource=req.resource,
            requested_time=req.requested_time,
            declared_count=req.declared_count,
        )
        decision = evaluator(_deep_freeze_json(detail), request_view, claims_view)
    except Exception:  # noqa: BLE001 — 策略引擎任何异常 = fail-closed 拒(H1:引擎不可用不得变放行)
        return False
    return decision is PolicyDecision.ALLOW


def _enforce_one(
    detail: dict,
    req: AccessRequest,
    evaluator: Optional[PolicyEvaluator],
    claims_view: Mapping[str, Any],
) -> RarResult:
    """执行单条 RAR 约束。**严格 type-keyed 分派**(评审 B1):
    - vocab-pure(type==v1 且字段全在词汇表)→ SDK 独占执行(下方词汇约束),**绝不**委托 evaluator。
    - out-of-vocab(type!=v1,或 v1+词汇表外字段)→ 委托 evaluator(未注册则整条拒);其中 v1+额外字段
      **先跑 SDK 词汇约束,通过后再跑 evaluator(AND)**,type!=v1 则仅 evaluator。
    """
    is_v1 = detail.get("type") == RAR_TYPE_V1
    has_extra_field = any(
        k not in _RFC9396_META_FIELDS and k not in _VOCAB_CONSTRAINT_FIELDS
        for k in detail.keys()
    )
    if not is_v1:
        if evaluator is None:
            return RarResult(
                False,
                f"未知 RAR type: {detail.get('type')!r}(fail-closed)",
                matched=True,
            )
        if not _run_evaluator(evaluator, detail, req, claims_view):
            return RarResult(
                False, "策略评估器拒绝该复杂 RAR 条目(C8.5b)", matched=True
            )
        return RarResult(True, matched=True)

    if has_extra_field and evaluator is None:
        return RarResult(False, "词汇表外未知约束字段(整条 fail-closed)", matched=True)

    # v1 约束始终先由 SDK 执行；v1+额外字段只有在内建约束通过后才交 evaluator。
    # valid_from / valid_to:数据时刻范围。
    vf_raw, vt_raw = detail.get("valid_from"), detail.get("valid_to")
    if vf_raw is not None or vt_raw is not None:
        if req.requested_time is None:
            return RarResult(
                False, "约束含时间范围但请求未带 requested_time", matched=True
            )
        if vf_raw is not None:
            vf = _parse_instant(vf_raw)
            if vf is None:
                return RarResult(
                    False, f"valid_from 解析失败: {vf_raw!r}(fail-closed)", matched=True
                )
            if req.requested_time < vf:
                return RarResult(False, "请求数据时刻早于 valid_from", matched=True)
        if vt_raw is not None:
            vt = _parse_instant(vt_raw)
            if vt is None:
                return RarResult(
                    False, f"valid_to 解析失败: {vt_raw!r}(fail-closed)", matched=True
                )
            if req.requested_time > vt:
                return RarResult(False, "请求数据时刻晚于 valid_to", matched=True)

    # resource_subset:资源子集白名单。
    rs = detail.get("resource_subset")
    if rs is not None:
        if not isinstance(rs, list):
            return RarResult(False, "resource_subset 非数组(fail-closed)", matched=True)
        # 空数组 = deny-all(明确什么都不给)。
        if not _resource_in_subset(req.resource, rs):
            return RarResult(
                False, "请求 resource 不在 resource_subset 白名单", matched=True
            )

    # max_records:记录数上界(RS 自证计数)。
    mr = detail.get("max_records")
    if mr is not None:
        if not isinstance(mr, int) or isinstance(mr, bool):
            return RarResult(False, "max_records 非整数(fail-closed)", matched=True)
        if req.declared_count is None:
            return RarResult(
                False, "约束含 max_records 但请求未带 declared_count", matched=True
            )
        if req.declared_count > mr:
            return RarResult(
                False,
                f"请求记录数 {req.declared_count} 超 max_records {mr}",
                matched=True,
            )

    if has_extra_field and not _run_evaluator(evaluator, detail, req, claims_view):
        return RarResult(False, "策略评估器拒绝该复杂 RAR 条目(C8.5b)", matched=True)

    return RarResult(True, matched=True)


def _frozen_claims_view(claims: Optional[Mapping[str, Any]]) -> Mapping[str, Any]:
    """从已校验 token claims 派生**运行时冻结**的只读投影 `{sub, scope}`(评审 B2)。

    - 去掉 `aud`(恒 == resource_id,RS 已知,纯冗余 surface);`sub` 供 Cedar principal,`scope` 供
      "RAR 在既有 scope 上收窄"判定。
    - 冻结:copy 出原语后 `MappingProxyType` 包裹——hostile/buggy evaluator 无法改此对象反噬 RS 下游。
    """
    src = claims or {}
    raw_sub = src.get("sub")
    raw_scope = src.get("scope")
    sub = raw_sub if isinstance(raw_sub, str) else None
    if isinstance(raw_scope, str):
        scope = raw_scope
    elif isinstance(raw_scope, (list, tuple)) and all(
        isinstance(item, str) for item in raw_scope
    ):
        scope = " ".join(raw_scope)
    else:
        scope = None
    proj = {"sub": sub, "scope": scope}
    return MappingProxyType(proj)


def _enforce_rar_with_evaluator(
    authorization_details: Optional[list],
    req: AccessRequest,
    *,
    evaluator: Optional[PolicyEvaluator] = None,
    claims: Optional[Mapping[str, Any]] = None,
) -> RarResult:
    """SDK 内部复杂 RAR 入口；调用方必须先完成 token active/验签、aud 与 scope 校验。

    - 缺失/空 → allow(RAR 是可选增强,回退 scope/aud 级授权;RS 可据 matched=False 自策略拒)。
    - 选中适用本次 resource 的条目(按 locations);**任一匹配条全约束通过 → allow**;
      所有匹配条拒 OR 有匹配条但全拒 → deny(fail-closed)。
    `evaluator` 只由 `RsSdk.authenticate` / `IntrospectionClient.authorize` 传入，不从公开低层
    `enforce_rar` 暴露，避免调用方拿未验证 claims 绕过基线授权。evaluator MUST 同步。
    """
    if authorization_details is None:
        return RarResult(
            True, "无 authorization_details(无细粒度约束,回退 scope 级)", matched=False
        )
    if not isinstance(authorization_details, list):
        return RarResult(
            False, "authorization_details 非数组(fail-closed)", matched=True
        )
    if not authorization_details:
        return RarResult(
            True, "空 authorization_details(无细粒度约束,回退 scope 级)", matched=False
        )
    if not all(_detail_shape_is_valid(detail) for detail in authorization_details):
        return RarResult(
            False,
            "authorization_details 条目形状无效(fail-closed)",
            matched=True,
        )

    applicable = [d for d in authorization_details if _detail_applies(d, req.resource)]
    if not applicable:
        # 有 RAR 但无一条适用本次 resource → fail-closed(RAR 存在即表示该 token 受细粒度约束)。
        return RarResult(
            False, "无适用本次 resource 的 RAR 条目(fail-closed)", matched=False
        )

    claims_view = _frozen_claims_view(claims)
    last_reason = None
    for d in applicable:
        r = _enforce_one(d, req, evaluator, claims_view)
        if r.allowed:
            return r  # 任一匹配条通过 → 放行(OR 语义)。
        last_reason = r.reason
    return RarResult(False, last_reason or "所有适用 RAR 条目均拒", matched=True)


def enforce_rar(
    authorization_details: Optional[list],
    req: AccessRequest,
) -> RarResult:
    """执行 C8.5a 内建 RAR 词汇表。

    复杂 C8.5b evaluator 只能通过 `RsSdk.authenticate` 或
    `IntrospectionClient.authorize` 的 `RoutePolicy.rar` 注册，确保 evaluator
    运行前已完成签名/active、aud 与 scope 基线校验。
    """
    return _enforce_rar_with_evaluator(authorization_details, req)


def extract_authorization_details(claims: dict) -> Optional[list]:
    """从 token claims / introspection 响应取 authorization_details(RFC 9396)。"""
    ad = claims.get("authorization_details")
    return ad if isinstance(ad, list) else None
