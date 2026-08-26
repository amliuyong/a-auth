// Agent Auth RS SDK — introspection 消费路径 + 缓存 TTL 指引(spec 010 §3.5,非规范性)。
//
// 何时用 introspection vs 离线 JWT 校验(RsSdk.authenticate)?
// - 离线 JWT 校验(默认、低延迟):JWKS 本地验签,不打 AS。代价:token 被吊销后离线校验察觉不到,
//   存在"吊销到过期"的残留有效窗口(≤ access TTL)。
// - 在线 introspection(高敏路由):调 AS /introspect(RFC 7662)拿权威 active 状态,立即反映吊销。
//   代价:每次(或每 TTL)一次网络往返 + AS 依赖。
//
// 缓存 TTL 指引(§3.5 核心):
// - 高敏路由(转账/删除/跨租户读)MUST 用 cacheTtlSecs=0(不缓存)或 ≤ 秒级——否则缓存 active:true
//   就把 introspection 退化成带残留窗口的离线校验,失去实时吊销意义。
// - 普通路由可给小正值(如 5s)平衡 AS 负载与吊销敏捷度。
// - active:false 永不缓存(本实现强制):吊销必须立即生效,缓存否定结果=已吊销仍放行漏洞。

import {
  createScopeResolver,
  normalizeRequiredScopes,
  normalizeResourceId,
} from "./authorization.js";
import {
  enforceRarWithEvaluator,
} from "./rar.js";
import {
  NAMESPACE,
  VerifyError,
  type RoutePolicy,
  type ScopeImplications,
  type ScopeResolver,
} from "./types.js";

/** introspection HTTP 调用器(注入以便离线单测);(endpoint, formBody, authHeader) -> {status, body}。 */
export type IntrospectionCaller = (
  endpoint: string,
  formBody: string,
  authHeader: string,
) => Promise<{ status: number; body: Record<string, unknown> }>;

export interface IntrospectionConfig {
  /** AS 的 /introspect 绝对 URL。 */
  introspectionEndpoint: string;
  /** 本 RS 的 introspection 凭证(控制面注册时领,spec 010 P1a)。 */
  clientId: string;
  clientSecret: string;
  /** 正结果(active:true)缓存 TTL 秒。0 = 不缓存(高敏路由默认建议)。active:false 永不缓存。 */
  cacheTtlSecs?: number;
  /** 当前时刻注入(测试;缺省 Date.now()/1000)。 */
  now?: () => number;
  /** 注入 HTTP 调用器(测试/自定义传输);缺省用全局 fetch。 */
  caller?: IntrospectionCaller;
  /** `authorize()` 的本 RS audience；原始 `introspect()` 消费不要求配置。 */
  resourceId?: string;
  scopeImplications?: ScopeImplications;
  scopeResolver?: ScopeResolver;
}

export interface IntrospectionResult {
  active: boolean;
  claims: Record<string, unknown>;
  sub?: string;
  aud?: string;
  clientId?: string;
  scope: string[];
  subType?: string;
  authGrant?: string;
  actorTypes?: Readonly<Record<string, string>>;
}

/** RFC 7617 Basic:base64(urlencode(clientId):urlencode(clientSecret))(与 AS 侧 client_auth 一致)。 */
function basicAuthHeader(clientId: string, clientSecret: string): string {
  const cid = encodeURIComponent(clientId);
  const csec = encodeURIComponent(clientSecret);
  const raw = `${cid}:${csec}`;
  // btoa 不在所有运行时都有;用 Buffer(Node)兜底。
  const b64 =
    typeof btoa === "function"
      ? btoa(raw)
      : Buffer.from(raw, "utf-8").toString("base64");
  return "Basic " + b64;
}

export class IntrospectionClient {
  private readonly cfg: IntrospectionConfig;
  private readonly now: () => number;
  private readonly auth: string;
  private readonly caller: IntrospectionCaller;
  private readonly cacheTtl: number;
  private readonly resourceId: string | undefined;
  private readonly scopeResolver: ScopeResolver;
  // token -> {expiresAt, result};只缓存 active:true。
  private readonly cache = new Map<string, { expiresAt: number; result: IntrospectionResult }>();

  constructor(cfg: IntrospectionConfig) {
    if (cfg.scopeResolver && cfg.scopeImplications) {
      throw new TypeError("scopeResolver and scopeImplications are mutually exclusive");
    }
    this.cfg = cfg;
    this.now = cfg.now ?? (() => Date.now() / 1000);
    this.auth = basicAuthHeader(cfg.clientId, cfg.clientSecret);
    this.cacheTtl = cfg.cacheTtlSecs ?? 0;
    this.resourceId =
      cfg.resourceId === undefined ? undefined : normalizeResourceId(cfg.resourceId);
    this.scopeResolver =
      cfg.scopeResolver ?? createScopeResolver(cfg.scopeImplications);
    this.caller = cfg.caller ?? this.defaultCaller.bind(this);
  }

  private async defaultCaller(
    endpoint: string,
    formBody: string,
    authHeader: string,
  ): Promise<{ status: number; body: Record<string, unknown> }> {
    const resp = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: authHeader,
      },
      body: formBody,
    });
    const text = await resp.text();
    return { status: resp.status, body: text ? JSON.parse(text) : {} };
  }

  /**
   * 查询 token 的权威 active 状态。
   * - 命中未过期正结果缓存 → 直接返回(仅当 cacheTtlSecs>0)。
   * - 否则调 AS /introspect;active:true 且 TTL>0 时入缓存;active:false 永不缓存。
   * - AS 不可用(非 200 / fetch 抛错)→ throw VerifyError("unavailable"),RS 侧 fail-closed(推荐)。
   */
  async introspect(token: string): Promise<IntrospectionResult> {
    const now = this.now();
    if (this.cacheTtl > 0) {
      const hit = this.cache.get(token);
      if (hit) {
        if (now < hit.expiresAt) return hit.result;
        this.cache.delete(token);
      }
    }

    const form = "token=" + encodeURIComponent(token);
    let status: number;
    let body: Record<string, unknown>;
    try {
      ({ status, body } = await this.caller(this.cfg.introspectionEndpoint, form, this.auth));
    } catch (err) {
      throw new VerifyError("unavailable", `introspection 调用失败: ${String(err)}`);
    }
    if (status !== 200) {
      throw new VerifyError("unavailable", `introspection 非 200: ${status}`);
    }

    const result = parseIntrospection(body);
    if (result.active && this.cacheTtl > 0) {
      this.cache.set(token, { expiresAt: now + this.cacheTtl, result });
    }
    return result;
  }

  /** 从缓存移除某 token(如收到带外吊销通知时主动清)。 */
  invalidate(token: string): void {
    this.cache.delete(token);
  }

  /** 在线组合授权：active + aud + route policy 全部通过后才执行复杂 RAR evaluator。 */
  async authorize(
    token: string,
    policy: RoutePolicy = {},
  ): Promise<IntrospectionResult> {
    if (this.resourceId === undefined) {
      throw new TypeError("IntrospectionConfig.resourceId is required for authorize()");
    }
    const requiredScopes = normalizeRequiredScopes(policy.requireScopes ?? []);
    const result = await this.introspect(token);
    if (!result.active) {
      throw new VerifyError("invalid_token", "introspection token inactive");
    }
    const rawAudience = result.claims.aud;
    if (
      !Array.isArray(rawAudience) ||
      rawAudience.length !== 1 ||
      rawAudience[0] !== this.resourceId
    ) {
      throw new VerifyError("invalid_token", "introspection audience mismatch");
    }
    if (policy.requireSubType && result.subType !== policy.requireSubType) {
      throw new VerifyError(
        "insufficient_scope",
        `路由要求 sub_type=${policy.requireSubType},token 为 ${result.subType ?? "(缺)"}`,
      );
    }
    const missing = requiredScopes.filter(
      (required) =>
        !result.scope.some(
          (granted) => this.scopeResolver(granted, required) === true,
        ),
    );
    if (missing.length > 0) {
      throw new VerifyError("insufficient_scope", `缺 scope: ${missing.join(" ")}`);
    }
    if (policy.rar !== undefined) {
      const rarResult = enforceRarWithEvaluator(
        result.claims.authorization_details,
        policy.rar.request,
        policy.rar.evaluator,
        {
          sub: result.sub,
          scope: result.scope.join(" "),
        },
      );
      if (!rarResult.allowed) {
        throw new VerifyError(
          "insufficient_scope",
          rarResult.reason ?? "复杂 RAR 策略拒绝",
        );
      }
    }
    return result;
  }
}

function parseIntrospection(body: Record<string, unknown>): IntrospectionResult {
  const active = body.active === true;
  if (!active) {
    // RFC 7662:active:false 时其它字段无意义,不透出(防误用陈旧字段)。
    return { active: false, claims: {}, scope: [] };
  }
  const ns = (body[NAMESPACE] as Record<string, unknown> | undefined) ?? {};
  const scopeRaw = body.scope;
  const scope =
    typeof scopeRaw === "string"
      ? scopeRaw.split(/\s+/).filter(Boolean)
      : Array.isArray(scopeRaw)
        ? (scopeRaw as string[])
        : [];
  const audRaw = body.aud;
  // aud 恒单元素(C2.5a):数组取首,字符串直用。
  const aud = Array.isArray(audRaw)
    ? ((audRaw[0] as string | undefined) ?? undefined)
    : (audRaw as string | undefined);
  const actorTypesRaw = ns.actor_types;
  const actorTypes =
    actorTypesRaw &&
    typeof actorTypesRaw === "object" &&
    !Array.isArray(actorTypesRaw) &&
    Object.values(actorTypesRaw).every((value) => typeof value === "string")
      ? { ...(actorTypesRaw as Record<string, string>) }
      : undefined;
  return {
    active: true,
    claims: body,
    sub: body.sub as string | undefined,
    aud,
    clientId: body.client_id as string | undefined,
    scope,
    subType: ns.sub_type as string | undefined,
    authGrant: ns.auth_grant as string | undefined,
    actorTypes,
  };
}
