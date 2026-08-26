// Agent Auth RS SDK — 声明式 RAR 约束词汇表 + 执行(spec 010 C8.5a,P2)。
//
// RFC 9396 authorization_details 是数组、每条带 type + 部署自定义字段。本 SDK 定义标准化、可通用
// 识别执行的声明式约束词汇表(词汇表内 = C8.5a P2;词汇表外 = C8.5b P3),真正拦截越界读。
//
// 词汇表(type = agent_auth_rar_v1):
// - valid_from/valid_to:可访问数据的时间范围(非 token 有效期);RS 传 requestedTime,判 ∈ [from,to] 闭区间。
// - resource_subset:资源子集白名单;RS 传 requestedResource,判 ∈ 白名单(精确;item 以 / 结尾=前缀)。空=deny-all。
// - max_records:记录数上界;RS 传 declaredCount,判 ≤ max(SDK 不执行查询,校 RS 自证计数)。
//
// fail-safe 红线(codex+Kiro 双评审收敛):
// - 未知 type → 整条 fail-closed 拒(除非注册了 C8.5b 策略评估器)。
// - 词汇表外未知约束字段(混在 type==v1 一条)→ 整条拒(原子性:全执行 OR 全拒,绝不部分执行=越权漏洞)。
// - 多条按 locations 选中本次 resource(无 locations=全局);任一匹配条全通过→放行;全拒/无匹配→拒。
// - RAR 缺失 → allow(可选增强,回退 scope;RS 可据 matched=false 自策略拒)。
//
// C8.5b 复杂/策略型 RAR(可插拔评估器,P3,设计双评审收敛):词汇表外(type != v1)的 detail 交 RS 注册的
// 策略评估器 evaluator 判(内可接 Cedar/@cedar-policy/cedar-wasm),而非无条件拒。铁律:
// - 严格 type-keyed 分派(B1):type==v1 且字段全在词汇表 = SDK 独占(绝不委托);否则(type!=v1 或 v1+额外
//   字段)= 委托 evaluator(未注册则整条拒,C8.5a 逐字节向后兼容)。
// - 只收窄绝不扩权(B2):evaluator 返回封闭 PolicyDecision,只 ALLOW 放行,其余(DENY/非枚举/抛异常)=拒;
//   detail 递归冻结,request 使用冻结防御副本,claims 投影冻结且只含 {sub, scope}(去 aud)。
// - evaluator **同步**(H1:异步会破坏本文件同步签名);RS 启动时预实例化引擎(唯一 async 步),闭包同步调。

export const RAR_TYPE_V1 = "agent_auth_rar_v1";

/**
 * C8.5b 策略评估器的封闭 deny-only 判定(评审 B2)。只有 ALLOW 放行;其余一切(DENY / evaluator 返回
 * 非本枚举 / 抛异常 / 未决)一律按拒。故意不承载 scope/claims —— evaluator 无法表达 "allow-with-extra"。
 *
 * **用冻结单例对象(非字符串/数值枚举)+ 引用相等**:TS 字符串枚举 `===` 会与其字面量相等
 * (`"allow" === ALLOW` 为 true)、数值枚举与裸数字相等——都让 evaluator 误/恶意返回裸值绕过 deny-only。
 * 冻结单例只有**引用相等**(`ret === PolicyDecision.ALLOW`)才 true,JSON 反序列化/裸值无法伪造出同一引用,
 * 与 Python 侧 `is PolicyDecision.ALLOW`(枚举单例身份)语义对齐,从类型层堵死型别混淆放行。
 */
export const PolicyDecision = Object.freeze({
  DENY: Object.freeze({ decision: "deny" as const }),
  ALLOW: Object.freeze({ decision: "allow" as const }),
});
export type PolicyDecision = (typeof PolicyDecision)[keyof typeof PolicyDecision];

/**
 * C8.5b 策略评估器 hook(同步,评审 H1)。RS 启动时预实例化策略引擎(Cedar 等,唯一 async 步),
 * 注册的闭包同步调已加载引擎。返回非 PolicyDecision / 抛异常 → SDK 按拒(fail-closed)。
 * claims 是冻结只读投影 {sub, scope}。
 */
export type PolicyEvaluator = (
  detail: Readonly<Record<string, unknown>>,
  req: AccessRequest,
  claims: Readonly<Record<string, unknown>>,
) => PolicyDecision;

const VOCAB_CONSTRAINT_FIELDS = new Set(["valid_from", "valid_to", "resource_subset", "max_records"]);
const RFC9396_META_FIELDS = new Set([
  "type",
  "locations",
  "actions",
  "datatypes",
  "identifier",
  "privileges",
]);

export interface AccessRequest {
  /** 本次访问的资源标识(URI);用于 resource_subset + locations 选中。 */
  resource: string;
  /** 访问的数据时刻(Unix 秒);校 valid_from/valid_to 时必填。 */
  requestedTime?: number;
  /** RS 声明本次返回的记录数;校 max_records 时必填。 */
  declaredCount?: number;
}

export interface RarResult {
  allowed: boolean;
  reason?: string;
  /** 是否有适用本次请求的 RAR 条目(区分"无约束放行" vs "约束通过")。 */
  matched: boolean;
}

const RFC3339_INSTANT =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|([+-])(\d{2}):(\d{2}))$/;

function isLeapYear(year: number): boolean {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

function validCalendarDate(year: number, month: number, day: number): boolean {
  const monthLengths = [
    31,
    isLeapYear(year) ? 29 : 28,
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31,
  ];
  return month >= 1 && month <= 12 && day >= 1 && day <= monthLengths[month - 1]!;
}

/** RFC 3339 字符串 或 epoch 秒 → Unix 秒;解析失败 → null(上层 fail-closed)。 */
function parseInstant(v: unknown): number | null {
  if (typeof v === "number") return Number.isFinite(v) ? v : null;
  if (typeof v === "string") {
    const match = RFC3339_INSTANT.exec(v);
    if (match === null) return null;
    const [, yearRaw, monthRaw, dayRaw, hourRaw, minuteRaw, secondRaw, , offsetHourRaw, offsetMinuteRaw] =
      match;
    const year = Number(yearRaw);
    const month = Number(monthRaw);
    const day = Number(dayRaw);
    const hour = Number(hourRaw);
    const minute = Number(minuteRaw);
    const second = Number(secondRaw);
    const offsetHour = offsetHourRaw === undefined ? 0 : Number(offsetHourRaw);
    const offsetMinute = offsetMinuteRaw === undefined ? 0 : Number(offsetMinuteRaw);
    if (
      !validCalendarDate(year, month, day) ||
      hour > 23 ||
      minute > 59 ||
      second > 59 ||
      offsetHour > 23 ||
      offsetMinute > 59
    ) {
      return null;
    }
    const ms = Date.parse(v);
    return Number.isNaN(ms) ? null : ms / 1000;
  }
  return null;
}

function resourceInSubset(resource: string, subset: unknown[]): boolean {
  for (const item of subset) {
    if (typeof item !== "string") continue;
    if (item.endsWith("/")) {
      if (resource.startsWith(item)) return true;
    } else if (resource === item) {
      return true;
    }
  }
  return false;
}

function detailApplies(detail: Record<string, unknown>, resource: string): boolean {
  const locs = detail.locations;
  if (locs === undefined) return true;
  if (!Array.isArray(locs)) return false;
  return resourceInSubset(resource, locs);
}

function detailShapeIsValid(detail: unknown): detail is Record<string, unknown> {
  if (detail === null || typeof detail !== "object" || Array.isArray(detail)) {
    return false;
  }
  const detailType = (detail as Record<string, unknown>).type;
  if (typeof detailType !== "string" || detailType.trim().length === 0) {
    return false;
  }
  const locations = (detail as Record<string, unknown>).locations;
  return (
    locations === undefined ||
    (Array.isArray(locations) &&
      locations.every((location) => typeof location === "string"))
  );
}

function deepFreezeJson<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const nested of Object.values(value as Record<string, unknown>)) {
      deepFreezeJson(nested);
    }
    Object.freeze(value);
  }
  return value;
}

/** deny-only 折叠(评审 B2):仅 evaluator 返回 PolicyDecision.ALLOW 才 true;其余(DENY/非枚举/抛异常)=false。 */
function runEvaluator(
  evaluator: PolicyEvaluator,
  detail: Record<string, unknown>,
  req: AccessRequest,
  claims: Readonly<Record<string, unknown>>,
): boolean {
  try {
    // detail 传递归冻结的深拷贝,防 evaluator 篡改嵌套 JSON 后反噬 RS 下游。
    const frozenDetail = deepFreezeJson(structuredClone(detail));
    const frozenRequest = Object.freeze({
      resource: req.resource,
      requestedTime: req.requestedTime,
      declaredCount: req.declaredCount,
    });
    return evaluator(frozenDetail, frozenRequest, claims) === PolicyDecision.ALLOW;
  } catch {
    return false; // 引擎异常 = fail-closed(H1)。
  }
}

function enforceOne(
  detail: Record<string, unknown>,
  req: AccessRequest,
  evaluator: PolicyEvaluator | undefined,
  claims: Readonly<Record<string, unknown>>,
): RarResult {
  // 严格 type-keyed 分派(评审 B1):vocab-pure(type==v1 且字段全在词汇表)由 SDK 独占;否则 out-of-vocab。
  const isV1 = detail.type === RAR_TYPE_V1;
  let hasExtraField = false;
  for (const k of Object.keys(detail)) {
    if (RFC9396_META_FIELDS.has(k) || VOCAB_CONSTRAINT_FIELDS.has(k)) continue;
    hasExtraField = true;
    break;
  }
  if (!isV1) {
    if (evaluator === undefined) {
      return {
        allowed: false,
        reason: `未知 RAR type: ${String(detail.type)}(fail-closed)`,
        matched: true,
      };
    }
    if (!runEvaluator(evaluator, detail, req, claims)) {
      return { allowed: false, reason: "策略评估器拒绝该复杂 RAR 条目(C8.5b)", matched: true };
    }
    return { allowed: true, matched: true };
  }

  const extensionEvaluator = hasExtraField ? evaluator : undefined;
  if (hasExtraField && extensionEvaluator === undefined) {
    return {
      allowed: false,
      reason: "词汇表外未知约束字段(整条 fail-closed)",
      matched: true,
    };
  }

  // v1 约束始终先由 SDK 执行；v1+额外字段只有在内建约束通过后才交 evaluator。
  // valid_from / valid_to:数据时刻范围。
  const vf = detail.valid_from;
  const vt = detail.valid_to;
  if (vf !== undefined || vt !== undefined) {
    if (req.requestedTime === undefined) {
      return { allowed: false, reason: "约束含时间范围但请求未带 requestedTime", matched: true };
    }
    if (vf !== undefined) {
      const from = parseInstant(vf);
      if (from === null) return { allowed: false, reason: `valid_from 解析失败(fail-closed)`, matched: true };
      if (req.requestedTime < from) return { allowed: false, reason: "请求数据时刻早于 valid_from", matched: true };
    }
    if (vt !== undefined) {
      const to = parseInstant(vt);
      if (to === null) return { allowed: false, reason: `valid_to 解析失败(fail-closed)`, matched: true };
      if (req.requestedTime > to) return { allowed: false, reason: "请求数据时刻晚于 valid_to", matched: true };
    }
  }

  // resource_subset:白名单。
  const rs = detail.resource_subset;
  if (rs !== undefined) {
    if (!Array.isArray(rs)) return { allowed: false, reason: "resource_subset 非数组(fail-closed)", matched: true };
    if (!resourceInSubset(req.resource, rs)) {
      return { allowed: false, reason: "请求 resource 不在 resource_subset 白名单", matched: true };
    }
  }

  // max_records:记录数上界。
  const mr = detail.max_records;
  if (mr !== undefined) {
    if (typeof mr !== "number" || !Number.isInteger(mr)) {
      return { allowed: false, reason: "max_records 非整数(fail-closed)", matched: true };
    }
    if (req.declaredCount === undefined) {
      return { allowed: false, reason: "约束含 max_records 但请求未带 declaredCount", matched: true };
    }
    if (req.declaredCount > mr) {
      return { allowed: false, reason: `请求记录数 ${req.declaredCount} 超 max_records ${mr}`, matched: true };
    }
  }

  if (
    extensionEvaluator !== undefined &&
    !runEvaluator(extensionEvaluator, detail, req, claims)
  ) {
    return { allowed: false, reason: "策略评估器拒绝该复杂 RAR 条目(C8.5b)", matched: true };
  }

  return { allowed: true, matched: true };
}

/** 从已校验 token claims 派生运行时冻结的只读投影 {sub, scope}(评审 B2;去 aud=恒 resource_id 冗余)。 */
function frozenClaimsView(claims: Record<string, unknown> | undefined): Readonly<Record<string, unknown>> {
  const rawSub = claims?.sub;
  const rawScope = claims?.scope;
  const sub = typeof rawSub === "string" ? rawSub : undefined;
  const scope =
    typeof rawScope === "string"
      ? rawScope
      : Array.isArray(rawScope) &&
          rawScope.every((item) => typeof item === "string")
        ? rawScope.join(" ")
        : undefined;
  return Object.freeze({ sub, scope });
}

/**
 * SDK 内部复杂 RAR 入口。调用方必须先完成 token active/验签、aud 与 scope 校验。
 * 本函数不从 package 公开入口导出，避免调用方用未验证 claims 绕过基线授权。
 */
export function enforceRarWithEvaluator(
  authorizationDetails: unknown,
  req: AccessRequest,
  evaluator: PolicyEvaluator | undefined,
  claims: Record<string, unknown> | undefined,
): RarResult {
  return enforceRarInternal(authorizationDetails, req, evaluator, claims);
}

/**
 * 执行 C8.5a 内建 RAR 词汇表。
 * 缺失/空 → allow(回退 scope);选中适用本次 resource 的条目(按 locations),任一全通过→allow,
 * 全拒/无匹配→deny(fail-closed)。
 * C8.5b evaluator 只能通过 RsSdk.authenticate / IntrospectionClient.authorize 的 RoutePolicy.rar 注册。
 */
export function enforceRar(
  authorizationDetails: unknown,
  req: AccessRequest,
): RarResult {
  return enforceRarInternal(authorizationDetails, req, undefined, undefined);
}

function enforceRarInternal(
  authorizationDetails: unknown,
  req: AccessRequest,
  evaluator: PolicyEvaluator | undefined,
  claims: Record<string, unknown> | undefined,
): RarResult {
  if (authorizationDetails === undefined || authorizationDetails === null) {
    return { allowed: true, reason: "无 authorization_details(回退 scope 级)", matched: false };
  }
  if (!Array.isArray(authorizationDetails)) {
    return { allowed: false, reason: "authorization_details 非数组(fail-closed)", matched: true };
  }
  if (authorizationDetails.length === 0) {
    return { allowed: true, reason: "空 authorization_details(回退 scope 级)", matched: false };
  }
  if (!authorizationDetails.every(detailShapeIsValid)) {
    return {
      allowed: false,
      reason: "authorization_details 条目形状无效(fail-closed)",
      matched: true,
    };
  }

  const applicable = authorizationDetails.filter(
    (detail) => detailApplies(detail, req.resource),
  );
  if (applicable.length === 0) {
    return { allowed: false, reason: "无适用本次 resource 的 RAR 条目(fail-closed)", matched: false };
  }

  const claimsView = frozenClaimsView(claims);
  let lastReason: string | undefined;
  for (const d of applicable) {
    const r = enforceOne(d, req, evaluator, claimsView);
    if (r.allowed) return r; // OR 语义。
    lastReason = r.reason;
  }
  return { allowed: false, reason: lastReason ?? "所有适用 RAR 条目均拒", matched: true };
}

/** 从 token claims / introspection 响应取 authorization_details(RFC 9396)。 */
export function extractAuthorizationDetails(claims: Record<string, unknown>): unknown[] | undefined {
  const ad = claims.authorization_details;
  return Array.isArray(ad) ? ad : undefined;
}
