// spec 010 §3.5:introspection 消费路径 + 缓存 TTL 指引(非规范性)。注入 caller + now,不依赖 AS。

import { describe, it, expect } from "vitest";
import {
  PolicyDecision,
  IntrospectionClient,
  type AccessRequest,
  type IntrospectionCaller,
  type PolicyEvaluator,
  VerifyError,
} from "../src/index.js";

const EP = "https://auth.example.com/introspect";
const RS = "https://mcp.kb.example.com";
const FIXTURE_NAMESPACE = "https://a-auth.com/c";

function activeBody(): Record<string, unknown> {
  return {
    active: true,
    sub: "pairwise-sub-abc",
    aud: [RS],
    client_id: "agt_123",
    scope: "read write",
    [FIXTURE_NAMESPACE]: {
      sub_type: "user",
      auth_grant: "fam_xyz",
      actor_types: {
        "agent-current": "agent",
        "service-earlier": "service",
      },
    },
  };
}

// 可控 caller:计数 + 按预设返回(数组按次序,或 callable 按调用序)。
function makeCaller(
  responses: Array<{ status: number; body: Record<string, unknown> }> | ((n: number) => { status: number; body: Record<string, unknown> }),
): IntrospectionCaller & { calls: number } {
  const state = { calls: 0 };
  const fn = (async (endpoint: string, formBody: string, authHeader: string) => {
    state.calls++;
    expect(endpoint).toBe(EP);
    expect(formBody.startsWith("token=")).toBe(true);
    expect(authHeader.startsWith("Basic ")).toBe(true);
    if (typeof responses === "function") return responses(state.calls);
    const idx = Math.min(state.calls - 1, responses.length - 1);
    return responses[idx];
  }) as IntrospectionCaller & { calls: number };
  Object.defineProperty(fn, "calls", { get: () => state.calls });
  return fn;
}

describe("IntrospectionClient", () => {
  it("解析 active:true(命名空间/aud 单元素/scope 分词)", async () => {
    const caller = makeCaller([{ status: 200, body: activeBody() }]);
    const c = new IntrospectionClient({ introspectionEndpoint: EP, clientId: "agt_123", clientSecret: "sec", cacheTtlSecs: 0, caller });
    const r = await c.introspect("tok-1");
    expect(r.active).toBe(true);
    expect(r.sub).toBe("pairwise-sub-abc");
    expect(r.aud).toBe(RS);
    expect(r.clientId).toBe("agt_123");
    expect(r.scope).toEqual(["read", "write"]);
    expect(r.subType).toBe("user");
    expect(r.authGrant).toBe("fam_xyz");
  });

  it("c2_2b_introspection_sdk_preserves_actor_types", async () => {
    const caller = makeCaller([{ status: 200, body: activeBody() }]);
    const client = new IntrospectionClient({
      introspectionEndpoint: EP,
      clientId: "agt_123",
      clientSecret: "sec",
      cacheTtlSecs: 0,
      caller,
    });
    const result = await client.introspect("tok-c2-2b");
    expect(result.subType).toBe("user");
    expect(result.authGrant).toBe("fam_xyz");
    expect(result.actorTypes).toEqual({
      "agent-current": "agent",
      "service-earlier": "service",
    });
  });

  it("active:false 不透出其它字段", async () => {
    const caller = makeCaller([{ status: 200, body: { active: false, sub: "leak", scope: "x" } }]);
    const c = new IntrospectionClient({ introspectionEndpoint: EP, clientId: "agt_123", clientSecret: "sec", caller });
    const r = await c.introspect("tok-2");
    expect(r.active).toBe(false);
    expect(r.sub).toBeUndefined();
    expect(r.scope).toEqual([]);
  });

  it("高敏路由 cacheTtlSecs=0 每次真调(无残留窗口)", async () => {
    const caller = makeCaller([{ status: 200, body: activeBody() }]);
    const c = new IntrospectionClient({ introspectionEndpoint: EP, clientId: "agt_123", clientSecret: "sec", cacheTtlSecs: 0, caller });
    await c.introspect("tok-3");
    await c.introspect("tok-3");
    await c.introspect("tok-3");
    expect(caller.calls).toBe(3);
  });

  it("正结果 TTL 内命中缓存、过期重取", async () => {
    let t = 1000;
    const caller = makeCaller([{ status: 200, body: activeBody() }]);
    const c = new IntrospectionClient({ introspectionEndpoint: EP, clientId: "agt_123", clientSecret: "sec", cacheTtlSecs: 5, now: () => t, caller });
    await c.introspect("tok-4"); // 真调(1)
    t = 1003;
    await c.introspect("tok-4"); // 命中缓存
    expect(caller.calls).toBe(1);
    t = 1006; // 超 5s TTL
    await c.introspect("tok-4"); // 重取(2)
    expect(caller.calls).toBe(2);
  });

  it("active:false 永不缓存(每次真调,吊销立即反映)", async () => {
    const caller = makeCaller([{ status: 200, body: { active: false } }]);
    const c = new IntrospectionClient({ introspectionEndpoint: EP, clientId: "agt_123", clientSecret: "sec", cacheTtlSecs: 60, caller });
    await c.introspect("tok-5");
    await c.introspect("tok-5");
    expect(caller.calls).toBe(2);
  });

  it("缓存后吊销 → TTL 过期重取拿到 active:false", async () => {
    let t = 0;
    const caller = makeCaller((n) => (n === 1 ? { status: 200, body: activeBody() } : { status: 200, body: { active: false } }));
    const c = new IntrospectionClient({ introspectionEndpoint: EP, clientId: "agt_123", clientSecret: "sec", cacheTtlSecs: 5, now: () => t, caller });
    expect((await c.introspect("tok-6")).active).toBe(true);
    t = 10;
    expect((await c.introspect("tok-6")).active).toBe(false);
  });

  it("AS 非 200 → VerifyError(unavailable)", async () => {
    const caller = makeCaller([{ status: 503, body: {} }]);
    const c = new IntrospectionClient({ introspectionEndpoint: EP, clientId: "agt_123", clientSecret: "sec", caller });
    await expect(c.introspect("tok-7")).rejects.toMatchObject({ kind: "unavailable" });
  });

  it("caller 抛错 → VerifyError(unavailable)", async () => {
    const caller = (async () => {
      throw new Error("network down");
    }) as IntrospectionCaller;
    const c = new IntrospectionClient({ introspectionEndpoint: EP, clientId: "agt_123", clientSecret: "sec", caller });
    await expect(c.introspect("tok-8")).rejects.toBeInstanceOf(VerifyError);
  });

  it("invalidate 清缓存后重取", async () => {
    const caller = makeCaller([{ status: 200, body: activeBody() }]);
    const c = new IntrospectionClient({ introspectionEndpoint: EP, clientId: "agt_123", clientSecret: "sec", cacheTtlSecs: 60, caller });
    await c.introspect("tok-9");
    c.invalidate("tok-9");
    await c.introspect("tok-9");
    expect(caller.calls).toBe(2);
  });
});

describe("C8.5b introspection policy seam", () => {
  it("c8_5b_introspection_evaluator_runs_only_after_active_audience_and_scope", async () => {
    const request: AccessRequest = { resource: RS };
    const complexDetail = {
      type: "cedar_policy",
      policy_ref: "doc-read",
      locations: [RS],
    };
    const calls: Array<{
      detail: Readonly<Record<string, unknown>>;
      request: AccessRequest;
      claims: Readonly<Record<string, unknown>>;
    }> = [];
    const evaluator: PolicyEvaluator = (detail, evaluatedRequest, claims) => {
      calls.push({ detail, request: evaluatedRequest, claims });
      return PolicyDecision.ALLOW;
    };
    const policy = {
      requireSubType: "user" as const,
      requireScopes: ["read"],
      rar: { request, evaluator },
    };
    const clientFor = (body: Record<string, unknown>) =>
      new IntrospectionClient({
        introspectionEndpoint: EP,
        clientId: "agt_123",
        clientSecret: "sec",
        resourceId: RS,
        caller: makeCaller([{ status: 200, body }]),
      });

    const rejectedBodies = [
      { active: false, authorization_details: [complexDetail] },
      {
        ...activeBody(),
        active: "false",
        authorization_details: [complexDetail],
      },
      {
        ...activeBody(),
        aud: ["https://mcp.other.example.com"],
        authorization_details: [complexDetail],
      },
      {
        ...activeBody(),
        scope: "write",
        authorization_details: [complexDetail],
      },
      {
        ...activeBody(),
        [FIXTURE_NAMESPACE]: {
          ...(activeBody()[FIXTURE_NAMESPACE] as Record<string, unknown>),
          sub_type: "agent",
        },
        authorization_details: [complexDetail],
      },
      {
        ...activeBody(),
        aud: [RS, "https://mcp.other.example.com"],
        authorization_details: [complexDetail],
      },
      {
        ...activeBody(),
        authorization_details: { type: "cedar_policy" },
      },
      {
        ...activeBody(),
        authorization_details: {},
      },
      {
        ...activeBody(),
        authorization_details: [42, complexDetail],
      },
      {
        ...activeBody(),
        authorization_details: [{ policy_ref: "missing-type" }, complexDetail],
      },
    ];
    for (const body of rejectedBodies) {
      await expect(clientFor(body).authorize("tok-c8-5b", policy)).rejects.toBeInstanceOf(
        VerifyError,
      );
      expect(calls).toHaveLength(0);
    }

    const valid = {
      ...activeBody(),
      authorization_details: [complexDetail],
    };
    const allowed = await clientFor(valid).authorize("tok-c8-5b", policy);
    expect(allowed.active).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.detail.policy_ref).toBe("doc-read");
    expect(calls[0]?.request.resource).toBe(RS);
    expect(calls[0]?.claims).toEqual({
      sub: "pairwise-sub-abc",
      scope: "read write",
    });

    await expect(
      clientFor(valid).authorize("tok-c8-5b", {
        requireSubType: "user",
        requireScopes: ["read"],
        rar: {
          request,
          evaluator: () => PolicyDecision.DENY,
        },
      }),
    ).rejects.toMatchObject({ kind: "insufficient_scope" });
  });
});
