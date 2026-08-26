// C8.5b 参考策略评估器样例(非规范性,spec 010 §5.1 H2)。
//
// 演示 RS 如何通过 RsSdk.authenticate + RoutePolicy.rar 注册策略评估器,让复杂 RAR 只在
// 验签、aud、scope 全部通过后交策略判定。
//
// **TS 侧真实可用官方 @cedar-policy/cedar-wasm(in-process)**;因其模块初始化是 async,须在 RS **启动时**
// 预加载(唯一 async 步),注册的闭包**同步**调已加载引擎(评审 H1——保 enforceRar 同步签名不被传染):
//
//   // 启动时(async,一次):
//   import init, { isAuthorized } from "@cedar-policy/cedar-wasm";
//   await init();
//   const engine = compilePolicySet(policyText);   // 预实例化
//   // 注册同步闭包:
//   const evaluator: PolicyEvaluator = (detail, req, claims) =>
//     engine.isAuthorized(detail, req, claims) ? PolicyDecision.ALLOW : PolicyDecision.DENY;
//
// 本测试用手写引擎(与 Python 样例对称,避免测试期强依赖 cedar-wasm)——hook 签名与上面 cedar 写法一致。

import { describe, it, expect } from "vitest";
import {
  PolicyDecision,
  RsSdk,
  type AccessRequest,
  type Jwks,
  type PolicyEvaluator,
} from "../src/index.js";
import { jwksOf, makeKey, signToken } from "./helpers.js";

const ISS = "https://auth.example.com";
const RS = "https://mcp.docs.example.com";
const NOW = Math.floor(Date.now() / 1000);

// 参考"策略引擎"(启动时预实例化,H1);evaluate 同步。规则:type=doc_policy 要求 sub ∈ allowed_subjects
// 且 token scope ⊆ max_scope(RAR 只收窄)。
class SamplePolicyEngine {
  constructor(readonly version: string) {}
  evaluate(detail: Readonly<Record<string, unknown>>, _req: AccessRequest, claims: Readonly<Record<string, unknown>>): PolicyDecision {
    if (detail.type !== "doc_policy") return PolicyDecision.DENY;
    const allowed = (detail.allowed_subjects as string[]) ?? [];
    if (!allowed.includes(claims.sub as string)) return PolicyDecision.DENY;
    const maxScope = new Set((detail.max_scope as string[]) ?? []);
    const tokenScope = String(claims.scope ?? "").split(/\s+/).filter(Boolean);
    if (!tokenScope.every((s) => maxScope.has(s))) return PolicyDecision.DENY;
    return PolicyDecision.ALLOW;
  }
}

describe("C8.5b 参考策略评估器样例", () => {
  const req: AccessRequest = { resource: RS };
  const engine = new SamplePolicyEngine("v1"); // 预实例化(H1)
  const evaluator: PolicyEvaluator = (d, q, c) => engine.evaluate(d, q, c); // 同步闭包

  async function authenticate(
    detail: Record<string, unknown>,
    selectedEvaluator: PolicyEvaluator,
    scope = "doc:read",
  ) {
    const key = await makeKey();
    const sdk = new RsSdk({
      resourceId: RS,
      issuer: ISS,
      jwksFetcher: async () => jwksOf(key) as Jwks,
    });
    sdk.seedJwks(jwksOf(key) as Jwks);
    const token = await signToken({
      key,
      iss: ISS,
      aud: [RS],
      sub: "user:alice",
      scope,
      authorizationDetails: [detail],
      now: NOW,
    });
    return sdk.authenticate(`Bearer ${token}`, {
      requireScopes: ["doc:read"],
      rar: { request: req, evaluator: selectedEvaluator },
    });
  }

  it("策略内 → 放行", async () => {
    const detail = {
      type: "doc_policy",
      allowed_subjects: ["user:alice"],
      max_scope: ["doc:read", "doc:list"],
      locations: [req.resource],
    };
    expect((await authenticate(detail, evaluator)).ok).toBe(true);
  });

  it("principal 不在白名单 → 拒", async () => {
    const detail = {
      type: "doc_policy",
      allowed_subjects: ["user:bob"],
      max_scope: ["doc:read"],
      locations: [req.resource],
    };
    expect((await authenticate(detail, evaluator)).ok).toBe(false);
  });

  it("scope 超出 max_scope → 拒(RAR 只收窄,不放行超授权)", async () => {
    const detail = {
      type: "doc_policy",
      allowed_subjects: ["user:alice"],
      max_scope: ["doc:read"],
      locations: [req.resource],
    };
    expect((await authenticate(detail, evaluator, "doc:read doc:write")).ok).toBe(false);
  });
});
