// spec 010 C8.5a:声明式 RAR 约束词汇表 + 执行拦截越界读。

import { describe, it, expect } from "vitest";
import { enforceRar, RAR_TYPE_V1, type AccessRequest } from "../src/index.js";

const RS = "https://mcp.kb.example.com";
const v1 = (fields: Record<string, unknown>) => ({ type: RAR_TYPE_V1, ...fields });
const req = (r: Partial<AccessRequest> & { resource: string }): AccessRequest => r;

describe("enforceRar", () => {
  it("RAR 缺失 → 放行(回退 scope)", () => {
    expect(enforceRar(undefined, req({ resource: RS })).allowed).toBe(true);
    expect(enforceRar([], req({ resource: RS })).matched).toBe(false);
  });

  it("resource_subset 精确匹配", () => {
    const ad = [v1({ resource_subset: [RS, "https://other/"] })];
    expect(enforceRar(ad, req({ resource: RS })).allowed).toBe(true);
    expect(enforceRar(ad, req({ resource: "https://evil" })).allowed).toBe(false);
  });

  it("resource_subset 前缀匹配(/ 结尾)", () => {
    const ad = [v1({ resource_subset: ["https://mcp.kb.example.com/docs/"] })];
    expect(enforceRar(ad, req({ resource: "https://mcp.kb.example.com/docs/2026/q1" })).allowed).toBe(true);
    expect(enforceRar(ad, req({ resource: "https://mcp.kb.example.com/secrets/x" })).allowed).toBe(false);
  });

  it("空 resource_subset = deny-all", () => {
    expect(enforceRar([v1({ resource_subset: [] })], req({ resource: RS })).allowed).toBe(false);
  });

  it("valid_from/valid_to 时间范围(RFC3339,闭区间)", () => {
    const ad = [v1({ valid_from: "2026-01-01T00:00:00Z", valid_to: "2026-12-31T23:59:59Z" })];
    const inside = Date.parse("2026-06-01T00:00:00Z") / 1000;
    const before = Date.parse("2025-06-01T00:00:00Z") / 1000;
    const after = Date.parse("2027-06-01T00:00:00Z") / 1000;
    expect(enforceRar(ad, req({ resource: RS, requestedTime: inside })).allowed).toBe(true);
    expect(enforceRar(ad, req({ resource: RS, requestedTime: before })).allowed).toBe(false);
    expect(enforceRar(ad, req({ resource: RS, requestedTime: after })).allowed).toBe(false);
  });

  it("时间范围但缺 requestedTime → fail-closed", () => {
    const ad = [v1({ valid_from: "2026-01-01T00:00:00Z" })];
    expect(enforceRar(ad, req({ resource: RS })).allowed).toBe(false);
  });

  it("valid_from 解析失败 → fail-closed", () => {
    const ad = [v1({ valid_from: "not-a-date" })];
    expect(enforceRar(ad, req({ resource: RS, requestedTime: 0 })).allowed).toBe(false);
  });

  it("valid_from/to epoch 形式 + 边界闭区间", () => {
    const ad = [v1({ valid_from: 1000, valid_to: 2000 })];
    expect(enforceRar(ad, req({ resource: RS, requestedTime: 1500 })).allowed).toBe(true);
    expect(enforceRar(ad, req({ resource: RS, requestedTime: 2500 })).allowed).toBe(false);
    expect(enforceRar(ad, req({ resource: RS, requestedTime: 1000 })).allowed).toBe(true);
    expect(enforceRar(ad, req({ resource: RS, requestedTime: 2000 })).allowed).toBe(true);
  });

  it("max_records 上界", () => {
    const ad = [v1({ max_records: 100 })];
    expect(enforceRar(ad, req({ resource: RS, declaredCount: 50 })).allowed).toBe(true);
    expect(enforceRar(ad, req({ resource: RS, declaredCount: 100 })).allowed).toBe(true);
    expect(enforceRar(ad, req({ resource: RS, declaredCount: 101 })).allowed).toBe(false);
  });

  it("max_records 缺 declaredCount → fail-closed", () => {
    expect(enforceRar([v1({ max_records: 100 })], req({ resource: RS })).allowed).toBe(false);
  });

  it("红线:未知 type → fail-closed", () => {
    const ad = [{ type: "future_rar", resource_subset: [RS] }];
    const r = enforceRar(ad, req({ resource: RS }));
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain("未知 RAR type");
  });

  it("红线:词汇表外未知约束字段 → 整条拒(原子性)", () => {
    const ad = [v1({ resource_subset: [RS], max_bytes: 1024 })];
    const r = enforceRar(ad, req({ resource: RS }));
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain("未知约束字段");
  });

  it("RFC 9396 元数据字段不触发未知字段拒", () => {
    const ad = [v1({ resource_subset: [RS], locations: [RS], identifier: "grant-1" })];
    expect(enforceRar(ad, req({ resource: RS })).allowed).toBe(true);
  });

  it("多条按 locations 选中", () => {
    const ad = [
      v1({ locations: ["https://other/"], resource_subset: ["https://other/x"] }),
      v1({ locations: [RS], max_records: 10 }),
    ];
    expect(enforceRar(ad, req({ resource: RS, declaredCount: 5 })).allowed).toBe(true);
    expect(enforceRar(ad, req({ resource: RS, declaredCount: 20 })).allowed).toBe(false);
  });

  it("无适用条目 → fail-closed", () => {
    const ad = [v1({ locations: ["https://other/"], resource_subset: ["https://other/x"] })];
    const r = enforceRar(ad, req({ resource: RS }));
    expect(r.allowed).toBe(false);
    expect(r.matched).toBe(false);
  });

  it("OR 语义:多条适用,任一通过即放行", () => {
    const ad = [v1({ max_records: 1 }), v1({ resource_subset: [RS] })];
    expect(enforceRar(ad, req({ resource: RS, declaredCount: 100 })).allowed).toBe(true);
  });

  it("单条内 AND:resource 通过但 count 超 → 拒", () => {
    const ad = [v1({ resource_subset: [RS], max_records: 10 })];
    expect(enforceRar(ad, req({ resource: RS, declaredCount: 5 })).allowed).toBe(true);
    expect(enforceRar(ad, req({ resource: RS, declaredCount: 50 })).allowed).toBe(false);
  });

  it("c8_5a_builtin_vocabulary_enforces_all_constraints", () => {
    expect(RAR_TYPE_V1).toBe("agent_auth_rar_v1");
    for (const absent of [undefined, null, []]) {
      const result = enforceRar(absent, req({ resource: RS }));
      expect(result.allowed).toBe(true);
      expect(result.matched).toBe(false);
    }
    expect(enforceRar("not-an-array", req({ resource: RS })).allowed).toBe(false);

    const combined = [
      v1({
        locations: [RS],
        valid_from: 1000,
        valid_to: 2000,
        resource_subset: [RS, "https://mcp.kb.example.com/docs/"],
        max_records: 10,
      }),
    ];
    for (const requestedTime of [1000, 1500, 2000]) {
      expect(
        enforceRar(
          combined,
          req({ resource: RS, requestedTime, declaredCount: 10 }),
        ).allowed,
      ).toBe(true);
    }

    const deniedRequests: AccessRequest[] = [
      { resource: RS, requestedTime: 999, declaredCount: 10 },
      { resource: RS, requestedTime: 2001, declaredCount: 10 },
      {
        resource: "https://evil.example.com",
        requestedTime: 1500,
        declaredCount: 10,
      },
      { resource: RS, requestedTime: 1500, declaredCount: 11 },
      { resource: RS, declaredCount: 10 },
      { resource: RS, requestedTime: 1500 },
    ];
    for (const request of deniedRequests) {
      expect(enforceRar(combined, request).allowed).toBe(false);
    }

    const rfc3339 = [
      v1({
        valid_from: "2026-01-01T00:00:00Z",
        valid_to: "2026-12-31T23:59:59Z",
      }),
    ];
    expect(
      enforceRar(
        rfc3339,
        req({ resource: RS, requestedTime: Date.parse("2026-06-01T00:00:00Z") / 1000 }),
      ).allowed,
    ).toBe(true);
    expect(
      enforceRar(
        rfc3339,
        req({ resource: RS, requestedTime: Date.parse("2025-12-31T23:59:59Z") / 1000 }),
      ).allowed,
    ).toBe(false);
    for (const invalidInstant of [
      "not-a-date",
      "2026-01-01",
      "2026-02-30T00:00:00Z",
      true,
      Number.NaN,
      Number.POSITIVE_INFINITY,
    ]) {
      expect(
        enforceRar(
          [v1({ valid_to: invalidInstant })],
          req({ resource: RS, requestedTime: 0 }),
        ).allowed,
      ).toBe(false);
    }

    const exactResource = [v1({ resource_subset: [RS] })];
    expect(
      enforceRar(exactResource, req({ resource: RS })).allowed,
    ).toBe(true);
    expect(
      enforceRar(exactResource, req({ resource: `${RS}/child` })).allowed,
    ).toBe(false);

    const prefix = [
      v1({ resource_subset: ["https://mcp.kb.example.com/docs/"] }),
    ];
    expect(
      enforceRar(
        prefix,
        req({ resource: "https://mcp.kb.example.com/docs/2026/q1" }),
      ).allowed,
    ).toBe(true);
    expect(
      enforceRar(
        prefix,
        req({ resource: "https://mcp.kb.example.com/docsets/2026" }),
      ).allowed,
    ).toBe(false);
    expect(
      enforceRar(
        [v1({ resource_subset: [] })],
        req({ resource: RS }),
      ).allowed,
    ).toBe(false);

    for (const invalidCount of [true, 10.5]) {
      expect(
        enforceRar(
          [v1({ max_records: invalidCount })],
          req({ resource: RS, declaredCount: 1 }),
        ).allowed,
      ).toBe(false);
    }

    expect(
      enforceRar(
        [{ type: "future_rar", resource_subset: [RS] }],
        req({ resource: RS }),
      ).allowed,
    ).toBe(false);
    expect(
      enforceRar(
        [v1({ resource_subset: [RS], max_bytes: 1024 })],
        req({ resource: RS }),
      ).allowed,
    ).toBe(false);
    expect(
      enforceRar(
        [v1({ locations: ["https://other.example.com"], resource_subset: [RS] })],
        req({ resource: RS }),
      ).allowed,
    ).toBe(false);

    const multiple = [
      v1({ locations: [RS], max_records: 1 }),
      v1({ locations: [RS], resource_subset: [RS] }),
    ];
    expect(
      enforceRar(
        multiple,
        req({ resource: RS, declaredCount: 100 }),
      ).allowed,
    ).toBe(true);
  });
});
