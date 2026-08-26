// Agent Auth RS SDK 类型(spec 010 P1b / CONFORMANCE C8.2/C8.3/C8.4/C8.8)。
// 决策真相源:docs/DESIGN §6 / §2。本 SDK 只做 RS 侧**消费/校验**,不派生 sub(pairwise 见 §2.8)。

import type { AccessRequest, PolicyEvaluator } from "./rar.js";

/** 命名空间(docs/DESIGN §2,云无关永久常量)。 */
export const NAMESPACE = "https://a-auth.com/c";

/** 主体类型(命名空间下 sub_type,C2.3)。 */
export type SubType = "user" | "agent" | "service";

/** 一把 JWK 公钥(与 AS `/jwks.json` 发布形状一致:EC P-256 或 RSA)。 */
export interface Jwk {
  kty: string;
  kid: string;
  alg?: string;
  use?: string;
  // EC
  crv?: string;
  x?: string;
  y?: string;
  // RSA
  n?: string;
  e?: string;
}

export interface Jwks {
  keys: Jwk[];
}

/** 校验通过后暴露给 RS 的 token 视图。 */
export interface VerifiedToken {
  /** 原始 claims(JSON)。 */
  claims: Record<string, unknown>;
  sub: string;
  /** 单元素 aud(= 本 RS 资源标识,已强校验)。 */
  aud: string;
  clientId: string;
  scope: string[];
  /** 命名空间下 sub_type(C2.3);缺失时为 undefined。 */
  subType?: SubType;
  /** 命名空间下 auth_grant。 */
  authGrant?: string;
  /** 命名空间下 actor id -> actor type 叠加视图。 */
  actorTypes?: Readonly<Record<string, string>>;
}

/** 校验失败分类(映射到 401/403 + WWW-Authenticate)。 */
export type VerifyErrorKind =
  | "missing_token" // 无 Bearer token → 401(无 error 码,纯发现头)
  | "invalid_token" // 验签/时效/形状/aud 不过 → 401 error="invalid_token"
  | "insufficient_scope" // sub_type/scope 策略不满足 → 403
  | "unavailable"; // JWKS 拉取失败等瞬时 → 503

export class VerifyError extends Error {
  constructor(
    public kind: VerifyErrorKind,
    public detail: string,
  ) {
    super(detail);
    this.name = "VerifyError";
  }
}

/** JWKS 拉取器(注入以便离线单测;默认用全局 fetch 拉 jwksUri)。 */
export type JwksFetcher = () => Promise<Jwks>;

/** Return true when one granted scope satisfies one required scope. */
export type ScopeResolver = (grantedScope: string, requiredScope: string) => boolean;

/** Explicit broader-scope -> directly implied narrower scopes declarations. */
export type ScopeImplications = Readonly<Record<string, readonly string[]>>;

export interface RsSdkConfig {
  /** 本 RS 资源标识(= 期望的单元素 aud)。 */
  resourceId: string;
  /** AS issuer(token.iss 必须等于它)。 */
  issuer: string;
  /** JWKS 拉取地址(缺省 `${issuer}/jwks.json`);注入 jwksFetcher 时忽略。 */
  jwksUri?: string;
  /** 注入的 JWKS 拉取器(测试/自定义传输);缺省用全局 fetch。 */
  jwksFetcher?: JwksFetcher;
  /** PRM URL(WWW-Authenticate 发现头;缺省按 RFC 9728 endpoint-path 规则派生)。 */
  resourceMetadataUrl?: string;
  /** 显式 broader -> narrower scope 关系;传递闭包由 SDK 计算,循环配置拒绝。 */
  scopeImplications?: ScopeImplications;
  /** 自定义 scope 判定器;与 scopeImplications 互斥。 */
  scopeResolver?: ScopeResolver;
  /** 允许的时钟偏移秒(C10.6,缺省 60)。 */
  clockSkewSecs?: number;
  /** 未知 kid 重取的最小间隔秒(C8.4,缺省 60)。 */
  minRefetchIntervalSecs?: number;
  /** 未知 kid 负缓存 TTL 秒(C8.4,缺省 300)。 */
  negativeCacheTtlSecs?: number;
  /** 当前时刻注入(测试用;缺省 Date.now()/1000)。 */
  now?: () => number;
}

/** 路由级策略(声明式,C8.2)。 */
export interface RarPolicy {
  /** 本次资源访问描述；只在 token 基线授权通过后交给 evaluator。 */
  request: AccessRequest;
  evaluator: PolicyEvaluator;
}

export interface RoutePolicy {
  /** 要求的 sub_type(如 "user":M2M token 被 403)。 */
  requireSubType?: SubType;
  /** 要求 token.scope 含全部这些 scope(否则 403)。 */
  requireScopes?: readonly string[];
  /** 复杂 RAR 收窄策略；SDK 保证签名/active、aud、scope 先通过。 */
  rar?: RarPolicy;
}
