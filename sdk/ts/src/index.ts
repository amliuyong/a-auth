// Agent Auth RS 校验 SDK(spec 010 P1b)—— 公开入口。
//
// 用法(框架无关核心):
//   const sdk = new RsSdk({ resourceId: "https://mcp.kb.example.com", issuer: "https://auth.example.com" });
//   const result = await sdk.authenticate(authorizationHeader, { requireSubType: "user" });
//   if (!result.ok) { res.status(result.status).set(result.headers).end(); return; }
//   // result.token: VerifiedToken
//
// 决策真相源:docs/DESIGN §6/§2 / CONFORMANCE C8.2/C8.3/C8.4/C8.8。RS 侧只消费/校验,不派生 sub。

import { JwksCache } from "./jwks-cache.js";
import {
  enforceRarWithEvaluator,
} from "./rar.js";
import { TokenVerifier } from "./verifier.js";
import {
  createScopeResolver,
  deriveResourceMetadataUrl,
  normalizeRequiredScopes,
  normalizeResourceId,
  validateResourceMetadataUrl,
} from "./authorization.js";
import {
  VerifyError,
  type Jwks,
  type RoutePolicy,
  type RsSdkConfig,
  type ScopeResolver,
  type VerifiedToken,
} from "./types.js";

const GRANT_BACKED_RAR_SUMMARY_TYPE = "agent_auth_grant_summary_v1";

export * from "./types.js";
export {
  createScopeResolver,
  deriveResourceMetadataUrl,
  normalizeResourceId,
  validateResourceMetadataUrl,
  validateScopeToken,
} from "./authorization.js";
export {
  IntrospectionClient,
  type IntrospectionConfig,
  type IntrospectionResult,
  type IntrospectionCaller,
} from "./introspection.js";
export {
  RAR_TYPE_V1,
  PolicyDecision,
  enforceRar,
  extractAuthorizationDetails,
  type AccessRequest,
  type RarResult,
  type PolicyEvaluator,
} from "./rar.js";
export {
  verifyDpopProof,
  computeJkt,
  computeAth,
  normalizeHtu,
  type DPoPResult,
  type DPoPVerifyOptions,
} from "./dpop.js";

/** authenticate 的结果:成功带 token,失败带 HTTP 状态 + 头(含 WWW-Authenticate)。 */
export type AuthResult =
  | { ok: true; token: VerifiedToken }
  | { ok: false; status: number; headers: Record<string, string>; error: VerifyError };

export class RsSdk {
  private verifier: TokenVerifier;
  private cache: JwksCache;
  private resourceMetadataUrl: string;
  private scopeResolver: ScopeResolver;
  private now: () => number;

  constructor(cfgIn: RsSdkConfig) {
    if (cfgIn.scopeResolver && cfgIn.scopeImplications) {
      throw new TypeError("scopeResolver and scopeImplications are mutually exclusive");
    }
    const cfg: RsSdkConfig = {
      ...cfgIn,
      resourceId: normalizeResourceId(cfgIn.resourceId),
      issuer: cfgIn.issuer.replace(/\/+$/, ""),
    };
    this.now = cfg.now ?? (() => Math.floor(Date.now() / 1000));
    const jwksUri = cfg.jwksUri ?? `${cfg.issuer}/jwks.json`;
    const fetcher =
      cfg.jwksFetcher ??
      (async (): Promise<Jwks> => {
        const resp = await fetch(jwksUri);
        if (!resp.ok) throw new Error(`JWKS fetch ${resp.status}`);
        return (await resp.json()) as Jwks;
      });
    this.cache = new JwksCache(
      fetcher,
      cfg.minRefetchIntervalSecs ?? 60,
      cfg.negativeCacheTtlSecs ?? 300,
      this.now,
    );
    this.verifier = new TokenVerifier(
      { ...cfg, resourceId: cfg.resourceId, issuer: cfg.issuer },
      this.cache,
    );
    this.resourceMetadataUrl = cfg.resourceMetadataUrl !== undefined
      ? validateResourceMetadataUrl(cfg.resourceMetadataUrl)
      : deriveResourceMetadataUrl(cfg.resourceId);
    this.scopeResolver = cfg.scopeResolver ?? createScopeResolver(cfg.scopeImplications);
  }

  /** 预热/离线注入 JWKS(测试;跳过网络)。 */
  seedJwks(jwks: Jwks): void {
    this.cache.seed(jwks);
  }

  private wwwAuthenticate(
    kind: "missing" | "invalid" | "insufficient",
    requiredScopes: readonly string[] = [],
  ): string {
    const params: string[] = [];
    if (kind === "invalid") params.push('error="invalid_token"');
    if (kind === "insufficient") params.push('error="insufficient_scope"');
    if (kind !== "invalid" && requiredScopes.length > 0) {
      params.push(`scope="${requiredScopes.join(" ")}"`);
    }
    params.push(`resource_metadata="${this.resourceMetadataUrl}"`);
    return `Bearer ${params.join(", ")}`;
  }

  /**
   * 校验 Authorization 头 + 应用路由策略。
   * @param authorization `Authorization` 头原值(可能 undefined)。
   * @param policy 可选路由策略(requireSubType/requireScopes)。
   */
  async authenticate(
    authorization: string | undefined | null,
    policy: RoutePolicy = {},
  ): Promise<AuthResult> {
    const requiredScopes = normalizeRequiredScopes(policy.requireScopes ?? []);
    const token = extractBearer(authorization);
    if (!token) {
      return {
        ok: false,
        status: 401,
        headers: {
          "WWW-Authenticate": this.wwwAuthenticate("missing", requiredScopes),
        },
        error: new VerifyError("missing_token", "缺 Bearer token"),
      };
    }

    let verified: VerifiedToken;
    try {
      verified = await this.verifier.verify(token);
    } catch (e) {
      const err = e instanceof VerifyError ? e : new VerifyError("invalid_token", String(e));
      if (err.kind === "unavailable") {
        return { ok: false, status: 503, headers: {}, error: err };
      }
      // 无效/过期 token:401 + error="invalid_token"(C8.8,便于客户端区分该刷新)。
      return {
        ok: false,
        status: 401,
        headers: { "WWW-Authenticate": this.wwwAuthenticate("invalid") },
        error: err,
      };
    }

    // 路由策略(基线校验通过后,C8.2):sub_type / scope 不满足 → 403 insufficient_scope。
    // 403 带 RFC 6750 §3 的 WWW-Authenticate: Bearer error="insufficient_scope"(评审 Kiro MEDIUM-3)。
    if (policy.requireSubType && verified.subType !== policy.requireSubType) {
      return {
        ok: false,
        status: 403,
        headers: {
          "WWW-Authenticate": this.wwwAuthenticate("insufficient", requiredScopes),
        },
        error: new VerifyError(
          "insufficient_scope",
          `路由要求 sub_type=${policy.requireSubType},token 为 ${verified.subType ?? "(缺)"}`,
        ),
      };
    }
    if (requiredScopes.length > 0) {
      const missing = requiredScopes.filter(
        (required) =>
          !verified.scope.some(
            (granted) => this.scopeResolver(granted, required) === true,
          ),
      );
      if (missing.length > 0) {
        return {
          ok: false,
          status: 403,
          headers: {
            "WWW-Authenticate": this.wwwAuthenticate("insufficient", requiredScopes),
          },
          error: new VerifyError("insufficient_scope", `缺 scope: ${missing.join(" ")}`),
        };
      }
    }

    if (containsGrantBackedRarSummary(verified.claims.authorization_details)) {
      return {
        ok: false,
        status: 403,
        headers: {
          "WWW-Authenticate": this.wwwAuthenticate("insufficient", requiredScopes),
        },
        error: new VerifyError(
          "insufficient_scope",
          "Grant-backed RAR summary requires authenticated introspection",
        ),
      };
    }

    if (policy.rar !== undefined) {
      const rarResult = enforceRarWithEvaluator(
        verified.claims.authorization_details,
        policy.rar.request,
        policy.rar.evaluator,
        {
          sub: verified.sub,
          scope: verified.scope.join(" "),
        },
      );
      if (!rarResult.allowed) {
        return {
          ok: false,
          status: 403,
          headers: {
            "WWW-Authenticate": this.wwwAuthenticate("insufficient", requiredScopes),
          },
          error: new VerifyError(
            "insufficient_scope",
            rarResult.reason ?? "复杂 RAR 策略拒绝",
          ),
        };
      }
    }

    return { ok: true, token: verified };
  }
}

function extractBearer(authorization: string | undefined | null): string | null {
  if (!authorization) return null;
  const m = /^Bearer\s+(.+)$/i.exec(authorization.trim());
  return m ? (m[1] as string).trim() : null;
}

function containsGrantBackedRarSummary(value: unknown): boolean {
  if (isRecord(value)) {
    return value.type === GRANT_BACKED_RAR_SUMMARY_TYPE;
  }
  return Array.isArray(value)
    && value.some((detail) =>
      isRecord(detail) && detail.type === GRANT_BACKED_RAR_SUMMARY_TYPE
    );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
