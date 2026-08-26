// C8.5b 复杂/策略型 RAR 可插拔评估器测试(spec 010 §5.1;设计双评审收敛)。
// 覆盖:type-keyed 分派(B1)/ deny-only + 冻结投影(B2)/ 未注册向后兼容 / 异常 fail-closed(H1)/
// 全 deny == 无 evaluator(H3)/ v1+额外字段 / 离线 JWT 与 introspection 同形状路径。

import { describe, it, expect } from "vitest";
import {
  PolicyDecision,
  RAR_TYPE_V1,
  type AccessRequest,
  type PolicyEvaluator,
} from "../src/index.js";
import {
  enforceRar as enforceSimpleRar,
  enforceRarWithEvaluator,
} from "../src/rar.js";

const REQ: AccessRequest = { resource: "https://mcp.a.example.com" };
const CX = {
  type: "cedar_policy",
  policy_ref: "doc-read",
  locations: [REQ.resource],
  context: { classification: "internal" },
};

const allowAll: PolicyEvaluator = () => PolicyDecision.ALLOW;
const denyAll: PolicyEvaluator = () => PolicyDecision.DENY;

function enforceRar(
  authorizationDetails: unknown,
  req: AccessRequest,
  opts: {
    evaluator?: PolicyEvaluator;
    claims?: Record<string, unknown>;
  } = {},
) {
  if (opts.evaluator === undefined && opts.claims === undefined) {
    return enforceSimpleRar(authorizationDetails, req);
  }
  return enforceRarWithEvaluator(
    authorizationDetails,
    req,
    opts.evaluator,
    opts.claims,
  );
}

describe("C8.5b evaluator — 向后兼容(未注册)", () => {
  it("词汇表外 type 未注册 evaluator → 整条拒", () => {
    const r = enforceRar([CX], REQ);
    expect(r.allowed).toBe(false);
    expect(r.matched).toBe(true);
  });
  it("v1+额外字段未注册 → 整条拒(B1 并集判据)", () => {
    const d = { type: RAR_TYPE_V1, resource_subset: [REQ.resource], weird_field: 1 };
    expect(enforceRar([d], REQ).allowed).toBe(false);
  });
});

describe("C8.5b evaluator — 委托判定", () => {
  it("evaluator ALLOW → 放行", () => {
    expect(enforceRar([CX], REQ, { evaluator: allowAll }).allowed).toBe(true);
  });
  it("evaluator DENY → 拒", () => {
    expect(enforceRar([CX], REQ, { evaluator: denyAll }).allowed).toBe(false);
  });
});

describe("C8.5b — 严格 type-keyed 分派(B1)", () => {
  it("vocab-pure v1 条 SDK 独占,不委托 evaluator", () => {
    const throwing: PolicyEvaluator = () => {
      throw new Error("vocab-pure v1 条不该委托 evaluator");
    };
    const d = { type: RAR_TYPE_V1, resource_subset: [REQ.resource] };
    expect(enforceRar([d], REQ, { evaluator: throwing }).allowed).toBe(true); // SDK 判:在白名单
  });
  it("v1+额外字段:SDK 词汇约束 AND evaluator", () => {
    const d = { type: RAR_TYPE_V1, resource_subset: [REQ.resource], extra: 1 };
    expect(enforceRar([d], REQ, { evaluator: allowAll }).allowed).toBe(true);
    expect(enforceRar([d], REQ, { evaluator: denyAll }).allowed).toBe(false); // evaluator 拒→整条拒
    const d2 = { type: RAR_TYPE_V1, resource_subset: ["https://other/"], extra: 1 };
    expect(enforceRar([d2], REQ, { evaluator: allowAll }).allowed).toBe(false); // SDK 词汇拒→整条拒(AND)
  });
});

describe("C8.5b — deny-only 返回(B2)", () => {
  const badReturns: unknown[] = [PolicyDecision.DENY, undefined, null, true, "allow", 1, {}];
  for (const bad of badReturns) {
    it(`非 ALLOW 返回 ${JSON.stringify(bad)} → 拒`, () => {
      const r = enforceRar([CX], REQ, { evaluator: (() => bad) as unknown as PolicyEvaluator });
      expect(r.allowed).toBe(false);
    });
  }
  it("evaluator 抛异常 → fail-closed(H1)", () => {
    const boom: PolicyEvaluator = () => {
      throw new Error("engine down");
    };
    expect(enforceRar([CX], REQ, { evaluator: boom }).allowed).toBe(false);
  });
});

describe("C8.5b — claims 投影冻结 + 最小化(B2)", () => {
  it("evaluator 拿到冻结 {sub, scope}(去 aud),篡改无效", () => {
    let seen: Record<string, unknown> | undefined;
    const capture: PolicyEvaluator = (_detail, _req, claims) => {
      seen = claims as Record<string, unknown>;
      expect(Object.isFrozen(claims)).toBe(true);
      return PolicyDecision.ALLOW;
    };
    const claims = {
      sub: "user:alice",
      scope: "read",
      aud: ["https://mcp.a.example.com"],
      iss: "x",
    };
    enforceRar([CX], REQ, { evaluator: capture, claims });
    expect(seen).toEqual({ sub: "user:alice", scope: "read" }); // 去 aud/iss
  });
  it("evaluator 拿到冻结原始 detail,篡改无效", () => {
    let seen: Record<string, unknown> | undefined;
    const capture: PolicyEvaluator = (detail) => {
      seen = detail as Record<string, unknown>;
      expect(Object.isFrozen(detail)).toBe(true);
      return PolicyDecision.ALLOW;
    };
    enforceRar([CX], REQ, { evaluator: capture });
    expect(seen?.type).toBe("cedar_policy");
    expect(seen?.policy_ref).toBe("doc-read");
  });
});

describe("C8.5b — H3:全 deny == 无 evaluator + OR + introspection 路径", () => {
  it("全 deny 结局 == 无 evaluator(不放宽 all-deny)", () => {
    const details = [CX, { type: "another_policy", locations: [REQ.resource] }];
    expect(enforceRar(details, REQ).allowed).toBe(false);
    expect(enforceRar(details, REQ, { evaluator: denyAll }).allowed).toBe(false);
  });
  it("数组内混合 v1限制型+策略型 OR 语义", () => {
    const v1Deny = { type: RAR_TYPE_V1, resource_subset: ["https://other/"], locations: [REQ.resource] };
    expect(enforceRar([v1Deny, CX], REQ, { evaluator: allowAll }).allowed).toBe(true); // 策略型过→OR放行
    expect(enforceRar([v1Deny, CX], REQ, { evaluator: denyAll }).allowed).toBe(false); // 都拒
  });
  it("introspection-shaped 输入(同形状)也经 evaluator", () => {
    const introspectionAd = [CX];
    expect(enforceRar(introspectionAd, REQ, { evaluator: allowAll }).allowed).toBe(true);
    expect(enforceRar(introspectionAd, REQ, { evaluator: denyAll }).allowed).toBe(false);
  });
});

describe("C8.5b exact policy boundary", () => {
  it("c8_5b_policy_evaluator_is_deny_only_and_fail_closed", () => {
    expect(enforceRar([CX], REQ).allowed).toBe(false);
    const publicHelper = enforceSimpleRar as unknown as (
      details: unknown,
      request: AccessRequest,
      bypass: { evaluator: PolicyEvaluator },
    ) => { allowed: boolean };
    expect(publicHelper([CX], REQ, { evaluator: allowAll }).allowed).toBe(false);
    expect(enforceRar([CX], REQ, { evaluator: allowAll }).allowed).toBe(true);
    expect(enforceRar([CX], REQ, { evaluator: denyAll }).allowed).toBe(false);

    const rejectedValues: unknown[] = [
      PolicyDecision.DENY,
      undefined,
      null,
      true,
      "allow",
      1,
      {},
      Promise.resolve(PolicyDecision.ALLOW),
    ];
    for (const value of rejectedValues) {
      const evaluator = (() => value) as unknown as PolicyEvaluator;
      expect(enforceRar([CX], REQ, { evaluator }).allowed).toBe(false);
    }

    const throwing: PolicyEvaluator = () => {
      throw new Error("policy engine unavailable");
    };
    expect(enforceRar([CX], REQ, { evaluator: throwing }).allowed).toBe(false);

    const mustNotDelegate: PolicyEvaluator = () => {
      throw new Error("vocab-pure v1 must remain SDK-owned");
    };
    const vocabPure = {
      type: RAR_TYPE_V1,
      resource_subset: [REQ.resource],
    };
    expect(
      enforceRar([vocabPure], REQ, { evaluator: mustNotDelegate }).allowed,
    ).toBe(true);

    const extended = {
      type: RAR_TYPE_V1,
      resource_subset: [REQ.resource],
      policy_ref: "doc-read",
    };
    expect(enforceRar([extended], REQ, { evaluator: allowAll }).allowed).toBe(true);
    expect(enforceRar([extended], REQ, { evaluator: denyAll }).allowed).toBe(false);
    expect(
      enforceRar(
        [{ ...extended, resource_subset: ["https://other.example.com"] }],
        REQ,
        { evaluator: allowAll },
      ).allowed,
    ).toBe(false);

    const evaluatorCalls: unknown[] = [];
    const hostileRequest: AccessRequest = {
      resource: REQ.resource,
      declaredCount: 10,
    };
    const guardedExtended = {
      type: RAR_TYPE_V1,
      max_records: 1,
      policy_ref: "doc-read",
    };
    expect(
      enforceRar([guardedExtended], hostileRequest, {
        evaluator: (detail, request, claims) => {
          evaluatorCalls.push({ detail, request, claims });
          request.declaredCount = 0;
          return PolicyDecision.ALLOW;
        },
      }).allowed,
    ).toBe(false);
    expect(evaluatorCalls).toHaveLength(0);
    expect(hostileRequest.declaredCount).toBe(10);

    const malformedCalls: unknown[] = [];
    expect(
      enforceRar(
        [{
          type: RAR_TYPE_V1,
          max_records: "one",
          policy_ref: "doc-read",
        }],
        { resource: REQ.resource, declaredCount: 1 },
        {
          evaluator: (detail, request, claims) => {
            malformedCalls.push({ detail, request, claims });
            return PolicyDecision.ALLOW;
          },
        },
      ).allowed,
    ).toBe(false);
    expect(malformedCalls).toHaveLength(0);

    let capturedDetail: Readonly<Record<string, unknown>> | undefined;
    let capturedRequest: AccessRequest | undefined;
    let capturedClaims: Readonly<Record<string, unknown>> | undefined;
    const sourceScope = ["read", "write"];
    const sourceRequest: AccessRequest = { resource: REQ.resource };
    const capture: PolicyEvaluator = (detail, request, claims) => {
      capturedDetail = detail;
      capturedRequest = request;
      capturedClaims = claims;
      expect(Object.isFrozen(detail)).toBe(true);
      expect(Object.isFrozen(claims)).toBe(true);
      expect(Object.isFrozen(detail.locations)).toBe(true);
      expect(Object.isFrozen(detail.context)).toBe(true);
      expect(() => {
        (detail as Record<string, unknown>).injected = true;
      }).toThrow();
      expect(() => {
        (detail.locations as string[]).push("https://evil.example.com");
      }).toThrow();
      expect(() => {
        (detail.context as Record<string, unknown>).classification = "public";
      }).toThrow();
      expect(() => {
        (claims as Record<string, unknown>).scope = "admin";
      }).toThrow();
      expect(Object.isFrozen(claims.scope)).toBe(true);
      expect(() => {
        (claims.scope as string[]).push("admin");
      }).toThrow();
      expect(Object.isFrozen(request)).toBe(true);
      expect(() => {
        request.resource = "https://evil.example.com";
      }).toThrow();
      return PolicyDecision.ALLOW;
    };
    expect(
      enforceRar([CX], sourceRequest, {
        evaluator: capture,
        claims: {
          sub: "user:alice",
          scope: sourceScope,
          aud: [REQ.resource],
          iss: "https://auth.example.com",
        },
      }).allowed,
    ).toBe(true);
    expect(capturedRequest).not.toBe(sourceRequest);
    expect(sourceRequest.resource).toBe(REQ.resource);
    expect(capturedDetail).toEqual(CX);
    expect(capturedClaims).toEqual({ sub: "user:alice", scope: "read write" });
    expect(sourceScope).toEqual(["read", "write"]);

    const vocabDeny = {
      type: RAR_TYPE_V1,
      resource_subset: ["https://other.example.com"],
      locations: [REQ.resource],
    };
    expect(
      enforceRar([vocabDeny, CX], REQ, { evaluator: allowAll }).allowed,
    ).toBe(true);
    expect(
      enforceRar([vocabDeny, CX], REQ, { evaluator: denyAll }).allowed,
    ).toBe(false);
    expect(enforceRar([CX], REQ, { evaluator: allowAll }).allowed).toBe(true);
  });
});
