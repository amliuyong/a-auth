// RS SDK 校验测试(spec 010 C8.2/C8.3/C8.4/C8.8)。fixture token 离线,不依赖 AS。

import { describe, it, expect } from "vitest";
import {
  PolicyDecision,
  RsSdk,
  createScopeResolver,
  deriveResourceMetadataUrl,
  type AccessRequest,
  type Jwks,
  type PolicyEvaluator,
} from "../src/index.js";
import { makeKey, jwksOf, signToken, type KeyMaterial } from "./helpers.js";

const ISS = "https://auth.example.com";
const RS = "https://mcp.kb.example.com";
// 用真实时钟基准签 fixture(jose 的 jwtVerify 用挂钟时间校时效,不接受注入时钟)。
const NOW = Math.floor(Date.now() / 1000);

async function sdkWith(key: KeyMaterial) {
  // 不注入 now:让时效校验按真实挂钟(与 jose 一致);fixture exp 也基于真实 now。
  const sdk = new RsSdk({ resourceId: RS, issuer: ISS, jwksFetcher: async () => jwksOf(key) as Jwks });
  sdk.seedJwks(jwksOf(key) as Jwks);
  return sdk;
}

describe("C8.2 aud 强校验 + sub_type 策略", () => {
  it("aud 匹配本 RS 的有效 token → ok", async () => {
    const key = await makeKey();
    const sdk = await sdkWith(key);
    const t = await signToken({ key, iss: ISS, aud: [RS], now: NOW });
    const r = await sdk.authenticate(`Bearer ${t}`);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.token.aud).toBe(RS);
      expect(r.token.subType).toBe("user");
      expect(r.token.clientId).toBe("app-1");
    }
  });

  it("c2_2b_offline_sdk_preserves_actor_types", async () => {
    const key = await makeKey();
    const sdk = await sdkWith(key);
    const actorTypes = {
      "agent-current": "agent",
      "service-earlier": "service",
    };
    const token = await signToken({
      key,
      iss: ISS,
      aud: [RS],
      actorTypes,
      now: NOW,
    });
    const result = await sdk.authenticate(`Bearer ${token}`);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.token.subType).toBe("user");
      expect(result.token.authGrant).toBe("grant-1");
      expect(result.token.actorTypes).toEqual(actorTypes);
    }
  });

  it("actor_types=null → 拒", async () => {
    const key = await makeKey();
    const sdk = await sdkWith(key);
    const token = await signToken({
      key,
      iss: ISS,
      aud: [RS],
      actorTypes: null as unknown as Record<string, string>,
      now: NOW,
    });
    const result = await sdk.authenticate(`Bearer ${token}`);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.status).toBe(401);
  });

  it("aud 不匹配本 RS → 401 invalid_token", async () => {
    const key = await makeKey();
    const sdk = await sdkWith(key);
    const t = await signToken({ key, iss: ISS, aud: ["https://mcp.other.example.com"], now: NOW });
    const r = await sdk.authenticate(`Bearer ${t}`);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.status).toBe(401);
      expect(r.headers["WWW-Authenticate"]).toContain('error="invalid_token"');
    }
  });

  it("裸字符串 aud → 拒(C2.5a 恒单元素数组)", async () => {
    const key = await makeKey();
    const sdk = await sdkWith(key);
    const t = await signToken({ key, iss: ISS, aud: RS, now: NOW }); // 裸字符串
    const r = await sdk.authenticate(`Bearer ${t}`);
    expect(r.ok).toBe(false);
  });

  it("require sub_type=user;agent token → 403 + insufficient_scope 头", async () => {
    const key = await makeKey();
    const sdk = await sdkWith(key);
    const t = await signToken({ key, iss: ISS, aud: [RS], subType: "agent", now: NOW });
    const r = await sdk.authenticate(`Bearer ${t}`, { requireSubType: "user" });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.status).toBe(403);
      expect(r.headers["WWW-Authenticate"]).toContain('error="insufficient_scope"');
    }
  });

  it("require sub_type=user;user token → ok", async () => {
    const key = await makeKey();
    const sdk = await sdkWith(key);
    const t = await signToken({ key, iss: ISS, aud: [RS], subType: "user", now: NOW });
    const r = await sdk.authenticate(`Bearer ${t}`, { requireSubType: "user" });
    expect(r.ok).toBe(true);
  });

  it("requireScopes 缺失 → 403 + scope 头", async () => {
    const key = await makeKey();
    const sdk = await sdkWith(key);
    const t = await signToken({ key, iss: ISS, aud: [RS], scope: "openid", now: NOW });
    const r = await sdk.authenticate(`Bearer ${t}`, { requireScopes: ["kb:write"] });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.status).toBe(403);
      expect(r.headers["WWW-Authenticate"]).toContain('scope="kb:write"');
    }
  });

  it("c8_2_audience_subject_and_scope_policy", async () => {
    const key = await makeKey();
    const sdk = await sdkWith(key);
    const valid = await signToken({
      key,
      iss: ISS,
      aud: [RS],
      scope: "kb:read",
      subType: "user",
      now: NOW,
    });
    expect((await sdk.authenticate(`Bearer ${valid}`, {
      requireSubType: "user",
      requireScopes: ["kb:read"],
    })).ok).toBe(true);

    for (const subType of ["agent", "service", "unknown", null] as const) {
      const m2mOrMissing = await signToken({
        key,
        iss: ISS,
        aud: [RS],
        scope: "kb:read",
        subType,
        now: NOW,
      });
      const result = await sdk.authenticate(`Bearer ${m2mOrMissing}`, {
        requireSubType: "user",
      });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.status).toBe(403);
    }

    for (const scope of ["kb:admin", "kb:read:all", "kb"]) {
      const broaderNameOnly = await signToken({
        key,
        iss: ISS,
        aud: [RS],
        scope,
        subType: "user",
        now: NOW,
      });
      const result = await sdk.authenticate(`Bearer ${broaderNameOnly}`, {
        requireScopes: ["kb:read"],
      });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.status).toBe(403);
    }

    const broaderNameOnly = await signToken({
      key,
      iss: ISS,
      aud: [RS],
      scope: "kb:admin",
      subType: "user",
      now: NOW,
    });
    const declared = new RsSdk({
      resourceId: RS,
      issuer: ISS,
      jwksFetcher: async () => jwksOf(key) as Jwks,
      scopeImplications: {
        "kb:admin": ["kb:write"],
        "kb:write": ["kb:read"],
      },
    });
    declared.seedJwks(jwksOf(key) as Jwks);
    expect((await declared.authenticate(`Bearer ${broaderNameOnly}`, {
      requireScopes: ["kb:read", "kb:write"],
    })).ok).toBe(true);

    expect(() => new RsSdk({
      resourceId: RS,
      issuer: ISS,
      jwksFetcher: async () => jwksOf(key) as Jwks,
      scopeImplications: {
        "kb:admin": ["kb:write"],
        "kb:write": ["kb:admin"],
      },
    })).toThrow(/cycle/);

    let resolverCalls = 0;
    const permissivePolicy = new RsSdk({
      resourceId: RS,
      issuer: ISS,
      jwksFetcher: async () => jwksOf(key) as Jwks,
      scopeResolver: () => {
        resolverCalls++;
        return true;
      },
    });
    permissivePolicy.seedJwks(jwksOf(key) as Jwks);
    const signed = await signToken({
      key,
      iss: ISS,
      aud: [RS],
      scope: "kb:admin",
      now: NOW,
    });
    const [header, body, signature] = signed.split(".");
    const corruptedSignature = (signature[0] === "A" ? "B" : "A") + signature.slice(1);
    const baselineInvalid = [
      await signToken({
        key,
        iss: ISS,
        aud: ["https://mcp.other.example.com"],
        scope: "kb:read",
        now: NOW,
      }),
      await signToken({
        key,
        iss: ISS,
        aud: [RS, "https://mcp.other.example.com"],
        scope: "kb:read",
        now: NOW,
      }),
      await signToken({ key, iss: ISS, aud: RS, scope: "kb:read", now: NOW }),
      await signToken({
        key,
        iss: "https://evil.example.com",
        aud: [RS],
        scope: "kb:read",
        now: NOW,
      }),
      await signToken({
        key,
        iss: ISS,
        aud: [RS],
        scope: "kb:read",
        clientId: null,
        now: NOW,
      }),
      await signToken({
        key,
        iss: ISS,
        aud: [RS],
        scope: "kb:read",
        typ: "JWT",
        now: NOW,
      }),
      await signToken({
        key,
        iss: ISS,
        aud: [RS],
        scope: "kb:read",
        now: 1,
        expOffset: 1,
      }),
      await signToken({
        key,
        iss: ISS,
        aud: [RS],
        scope: "kb:read",
        now: NOW,
        nbfOffset: 5000,
        expOffset: 10000,
      }),
      await signToken({
        key,
        iss: ISS,
        aud: [RS],
        scope: "kb:read",
        now: NOW + 5000,
        expOffset: 10000,
      }),
      await signToken({
        key,
        iss: ISS,
        aud: [RS],
        scope: "kb:read",
        now: NOW,
        includeExp: false,
      }),
      await signToken({
        key,
        iss: ISS,
        aud: [RS],
        scope: "kb:read",
        now: NOW,
        includeIat: false,
      }),
      `${header}.${body}.${corruptedSignature}`,
    ];
    for (const token of baselineInvalid) {
      const result = await permissivePolicy.authenticate(`Bearer ${token}`, {
        requireScopes: ["kb:read"],
      });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.status).toBe(401);
    }
    expect(resolverCalls).toBe(0);
    expect((await permissivePolicy.authenticate(`Bearer ${signed}`, {
      requireScopes: ["kb:read"],
    })).ok).toBe(true);
    expect(resolverCalls).toBeGreaterThan(0);
  });

  it("resourceId 尾斜杠归一化:aud 无尾斜杠仍匹配", async () => {
    const key = await makeKey();
    const sdk = new RsSdk({ resourceId: RS + "/", issuer: ISS, jwksFetcher: async () => jwksOf(key) as Jwks });
    sdk.seedJwks(jwksOf(key) as Jwks);
    const t = await signToken({ key, iss: ISS, aud: [RS], now: NOW }); // aud 无尾斜杠
    const r = await sdk.authenticate(`Bearer ${t}`);
    expect(r.ok).toBe(true);
  });

  it("RS256 token(P3 能力):正确公钥/alg → ok", async () => {
    const key = await makeKey("RS256");
    const sdk = await sdkWith(key);
    const t = await signToken({ key, iss: ISS, aud: [RS], now: NOW });
    const r = await sdk.authenticate(`Bearer ${t}`);
    expect(r.ok).toBe(true);
  });
});

describe("C8.3 按 kid 强制 alg + 拒 alg:none", () => {
  it("EC 公钥但 header 声明 RS256(算法混淆)→ 拒", async () => {
    const key = await makeKey("ES256");
    const sdk = await sdkWith(key);
    // 真实 ES256 签一枚,再把 header.alg 改写成 RS256(kid 仍指向 EC 公钥)——模拟算法混淆。
    const t = await signToken({ key, iss: ISS, aud: [RS] });
    const [, body, sig] = t.split(".");
    const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const confused = `${enc({ alg: "RS256", typ: "at+jwt", kid: key.publicJwk.kid })}.${body}.${sig}`;
    const r = await sdk.authenticate(`Bearer ${confused}`);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.status).toBe(401);
  });

  it("alg:none → 拒", async () => {
    const key = await makeKey();
    const sdk = await sdkWith(key);
    // 手工造一个 alg:none 的无签名 token。
    const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const t = `${enc({ alg: "none", typ: "at+jwt", kid: key.publicJwk.kid })}.${enc({ iss: ISS, aud: [RS], exp: NOW + 100, client_id: "c" })}.`;
    const r = await sdk.authenticate(`Bearer ${t}`);
    expect(r.ok).toBe(false);
  });

  it("c8_3_alg_key_pinning_and_none_rejection", async () => {
    const ecKey = await makeKey("ES256");
    const rsaKey = await makeKey("RS256");
    const rsa384Key = await makeKey("RS384");
    rsa384Key.publicJwk.alg = "RS256";
    const keys = jwksOf(ecKey, rsaKey, rsa384Key) as Jwks;
    const sdk = new RsSdk({
      resourceId: RS,
      issuer: ISS,
      jwksFetcher: async () => keys,
    });
    sdk.seedJwks(keys);

    const esToken = await signToken({ key: ecKey, iss: ISS, aud: [RS], now: NOW });
    const rsToken = await signToken({ key: rsaKey, iss: ISS, aud: [RS], now: NOW });
    expect((await sdk.authenticate(`Bearer ${esToken}`)).ok).toBe(true);
    expect((await sdk.authenticate(`Bearer ${rsToken}`)).ok).toBe(true);

    const rsaSignedForEcKid = await signToken({
      key: rsaKey,
      iss: ISS,
      aud: [RS],
      now: NOW,
      kidOverride: ecKey.publicJwk.kid,
    });
    const ecSignedForRsaKid = await signToken({
      key: ecKey,
      iss: ISS,
      aud: [RS],
      now: NOW,
      kidOverride: rsaKey.publicJwk.kid,
    });
    expect((await sdk.authenticate(`Bearer ${rsaSignedForEcKid}`)).ok).toBe(false);
    expect((await sdk.authenticate(`Bearer ${ecSignedForRsaKid}`)).ok).toBe(false);

    const rsa384Token = await signToken({
      key: rsa384Key,
      iss: ISS,
      aud: [RS],
      now: NOW,
    });
    expect((await sdk.authenticate(`Bearer ${rsa384Token}`)).ok).toBe(false);

    const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const noneToken = `${enc({ alg: "none", typ: "at+jwt", kid: ecKey.publicJwk.kid })}.${enc({ iss: ISS, aud: [RS], exp: NOW + 100, client_id: "c" })}.`;
    expect((await sdk.authenticate(`Bearer ${noneToken}`)).ok).toBe(false);
  });
});

describe("RFC 9068 基线", () => {
  it("typ != at+jwt → 拒(非 access token)", async () => {
    const key = await makeKey();
    const sdk = await sdkWith(key);
    const t = await signToken({ key, iss: ISS, aud: [RS], typ: "JWT", now: NOW });
    const r = await sdk.authenticate(`Bearer ${t}`);
    expect(r.ok).toBe(false);
  });

  it("iss 不匹配 → 拒", async () => {
    const key = await makeKey();
    const sdk = await sdkWith(key);
    const t = await signToken({ key, iss: "https://evil.example.com", aud: [RS], now: NOW });
    const r = await sdk.authenticate(`Bearer ${t}`);
    expect(r.ok).toBe(false);
  });

  it("缺 client_id → 拒(C2.1)", async () => {
    const key = await makeKey();
    const sdk = await sdkWith(key);
    const t = await signToken({ key, iss: ISS, aud: [RS], clientId: null, now: NOW });
    const r = await sdk.authenticate(`Bearer ${t}`);
    expect(r.ok).toBe(false);
  });

  it("过期 token → 401 invalid_token", async () => {
    const key = await makeKey();
    const sdk = await sdkWith(key);
    const t = await signToken({ key, iss: ISS, aud: [RS], now: NOW - 10_000, expOffset: 100 });
    const r = await sdk.authenticate(`Bearer ${t}`);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.status).toBe(401);
  });

  it("iat 在未来(超时钟偏移)→ 拒(评审 codex)", async () => {
    const key = await makeKey();
    const sdk = await sdkWith(key);
    // iat 在 now+5000(远超默认 60s skew);exp 更远,确保只因 iat 未来被拒。
    const t = await signToken({ key, iss: ISS, aud: [RS], now: NOW + 5000, expOffset: 10000 });
    const r = await sdk.authenticate(`Bearer ${t}`);
    expect(r.ok).toBe(false);
  });
});

describe("C8.8 WWW-Authenticate 发现头", () => {
  it("无 token → 401 纯发现头(无 error)", async () => {
    const key = await makeKey();
    const sdk = await sdkWith(key);
    const r = await sdk.authenticate(undefined);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.status).toBe(401);
      const h = r.headers["WWW-Authenticate"];
      expect(h).toContain(`resource_metadata="${RS}/.well-known/oauth-protected-resource"`);
      expect(h).not.toContain("invalid_token");
    }
  });

  it("无效 token → 401 带 error=invalid_token", async () => {
    const key = await makeKey();
    const sdk = await sdkWith(key);
    const r = await sdk.authenticate("Bearer garbage.token.here");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.headers["WWW-Authenticate"]).toContain('error="invalid_token"');
  });

  it("c8_8_prm_challenge_is_safe_exact_and_redacted", async () => {
    const resource = "https://mcp.example.com/mcp/v1";
    const metadata =
      "https://mcp.example.com/.well-known/oauth-protected-resource/mcp/v1";
    const sdk = new RsSdk({ resourceId: resource, issuer: ISS });

    const missing = await sdk.authenticate(undefined);
    expect(missing.ok).toBe(false);
    if (!missing.ok) {
      expect(missing.status).toBe(401);
      expect(missing.headers["WWW-Authenticate"]).toBe(
        `Bearer resource_metadata="${metadata}"`,
      );
    }

    const invalid = await sdk.authenticate(
      "Bearer private-validation-detail",
      { requireScopes: ["mcp:read"] },
    );
    expect(invalid.ok).toBe(false);
    if (!invalid.ok) {
      expect(invalid.status).toBe(401);
      expect(invalid.headers["WWW-Authenticate"]).toBe(
        `Bearer error="invalid_token", resource_metadata="${metadata}"`,
      );
      expect(invalid.headers["WWW-Authenticate"]).not.toContain(
        "private-validation-detail",
      );
      expect(invalid.headers["WWW-Authenticate"]).not.toContain("mcp:read");
    }

    const key = await makeKey();
    const validatingSdk = await sdkWith(key);
    const expiredToken = await signToken({
      key,
      iss: ISS,
      aud: [RS],
      now: NOW - 10_000,
      expOffset: 100,
    });
    const expired = await validatingSdk.authenticate(`Bearer ${expiredToken}`);
    expect(expired.ok).toBe(false);
    if (!expired.ok) {
      expect(expired.status).toBe(401);
      expect(expired.headers["WWW-Authenticate"]).toBe(
        `Bearer error="invalid_token", resource_metadata="${RS}/.well-known/oauth-protected-resource"`,
      );
      expect(expired.headers["WWW-Authenticate"]).not.toContain(expiredToken);
    }

    const derivations: Record<string, string> = {
      "https://mcp.example.com":
        "https://mcp.example.com/.well-known/oauth-protected-resource",
      "https://mcp.example.com/mcp":
        "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
      "https://mcp.example.com:8443/mcp/v1/tools/":
        "https://mcp.example.com:8443/.well-known/oauth-protected-resource/mcp/v1/tools",
    };
    for (const [source, expected] of Object.entries(derivations)) {
      expect(deriveResourceMetadataUrl(source)).toBe(expected);
    }

    const explicit = "https://metadata.example.com/custom/prm?tenant=t1";
    const explicitSdk = new RsSdk({
      resourceId: resource,
      issuer: ISS,
      resourceMetadataUrl: explicit,
    });
    const explicitResult = await explicitSdk.authenticate(undefined);
    expect(explicitResult.ok).toBe(false);
    if (!explicitResult.ok) {
      expect(explicitResult.headers["WWW-Authenticate"]).toBe(
        `Bearer resource_metadata="${explicit}"`,
      );
    }

    const unsafeResources = [
      "http://mcp.example.com/mcp",
      "https://user@mcp.example.com/mcp",
      "https://mcp.example.com/mcp?tenant=t1",
      "https://mcp.example.com/mcp#fragment",
      "https://mcp.example.com\\evil",
      "https://%65xample.com/mcp",
      "https://mcp.example.com/a/../mcp",
      "https://mcp.example.com/%2e%2e/mcp",
      "https://mcp.example.com/%zz",
    ];
    for (const resourceId of unsafeResources) {
      expect(() => new RsSdk({ resourceId, issuer: ISS })).toThrow(TypeError);
    }

    const unsafeMetadataUrls = [
      "http://metadata.example.com/prm",
      "https://user@metadata.example.com/prm",
      "https://metadata.example.com/prm#fragment",
      'https://metadata.example.com/prm"x',
      "https://metadata.example.com/prm\\x",
      "https://metadata.example.com/prm\r\nX-Injected: yes",
      "https://metadata.example.com/%zz",
    ];
    for (const resourceMetadataUrl of unsafeMetadataUrls) {
      expect(
        () =>
          new RsSdk({
            resourceId: resource,
            issuer: ISS,
            resourceMetadataUrl,
          }),
      ).toThrow(TypeError);
    }
  });
});

describe("RFC 9728 PRM URL 派生与显式 override", () => {
  it.each([
    [
      "https://mcp.example.com",
      "https://mcp.example.com/.well-known/oauth-protected-resource",
    ],
    [
      "https://mcp.example.com/mcp",
      "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
    ],
    [
      "https://mcp.example.com:8443/mcp/v1/tools/",
      "https://mcp.example.com:8443/.well-known/oauth-protected-resource/mcp/v1/tools",
    ],
    [
      "https://mcp.example.com:443/mcp/v1",
      "https://mcp.example.com:443/.well-known/oauth-protected-resource/mcp/v1",
    ],
    [
      "https://[0:0:0:0:0:0:0:1]:8443/mcp",
      "https://[::1]:8443/.well-known/oauth-protected-resource/mcp",
    ],
    [
      "https://mcp.example.com/a%3Cb",
      "https://mcp.example.com/.well-known/oauth-protected-resource/a%3Cb",
    ],
  ])("%s → %s", (resource, expected) => {
    expect(deriveResourceMetadataUrl(resource)).toBe(expected);
  });

  it("显式 resourceMetadataUrl 校验后逐字用于 challenge", async () => {
    const explicit = "https://metadata.example.com/custom/prm?tenant=t1";
    const sdk = new RsSdk({
      resourceId: "https://mcp.example.com/mcp",
      issuer: ISS,
      resourceMetadataUrl: explicit,
    });
    const result = await sdk.authenticate(undefined);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.headers["WWW-Authenticate"]).toBe(
        `Bearer resource_metadata="${explicit}"`,
      );
    }
  });

  it.each([
    "http://mcp.example.com/mcp",
    "https://user@mcp.example.com/mcp",
    "https://mcp.example.com/mcp?tenant=t1",
    "https://mcp.example.com/mcp#fragment",
    "https://mcp.example.com\\evil",
    "https://%65xample.com/mcp",
    "https://127.1/mcp",
    "https://1.2.3.4./mcp",
    "https://mcp.example.com/a/../mcp",
    "https://mcp.example.com/%2e%2e/mcp",
    "https://mcp.example.com/a<b",
    "https://mcp.example.com/a[b",
    "https://mcp.example.com/%zz",
    "not-a-url",
  ])("拒绝不适合作 resourceId 的值: %s", (resourceId) => {
    expect(() => new RsSdk({ resourceId, issuer: ISS })).toThrow(TypeError);
  });

  it.each([
    "http://metadata.example.com/prm",
    "https://user@metadata.example.com/prm",
    "https://metadata.example.com/prm#fragment",
    'https://metadata.example.com/prm"x',
    "https://metadata.example.com/prm\\x",
    "https://metadata.example.com/prm\r\nX-Injected: yes",
    "https://exa<mple.example/prm",
    "https://metadata.example.com/a<b",
    "https://metadata.example.com/a[b",
    "https://metadata.example.com/%zz",
    "",
  ])("拒绝不安全的显式 PRM URL: %s", (resourceMetadataUrl) => {
    expect(
      () =>
        new RsSdk({
          resourceId: RS,
          issuer: ISS,
          resourceMetadataUrl,
        }),
    ).toThrow(TypeError);
  });
});

describe("MCP operation scope challenge", () => {
  it("missing token 的 401 带当前 operation 完整 scope", async () => {
    const sdk = new RsSdk({ resourceId: RS, issuer: ISS });
    const result = await sdk.authenticate(undefined, {
      requireScopes: ["kb:read", "kb:write"],
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.headers["WWW-Authenticate"]).toBe(
        `Bearer scope="kb:read kb:write", resource_metadata="${RS}/.well-known/oauth-protected-resource"`,
      );
    }
  });

  it("invalid token 的 401 只暴露标准错误和 discovery", async () => {
    const sdk = new RsSdk({ resourceId: RS, issuer: ISS });
    const result = await sdk.authenticate("Bearer private-validation-detail", {
      requireScopes: ["kb:read"],
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.headers["WWW-Authenticate"]).toBe(
        `Bearer error="invalid_token", resource_metadata="${RS}/.well-known/oauth-protected-resource"`,
      );
      expect(result.headers["WWW-Authenticate"]).not.toContain(
        "private-validation-detail",
      );
    }
  });

  it("403 在一个 Bearer challenge 中给出 error、完整 scope 和 discovery", async () => {
    const key = await makeKey();
    const sdk = await sdkWith(key);
    const token = await signToken({
      key,
      iss: ISS,
      aud: [RS],
      scope: "kb:read",
      now: NOW,
    });
    const result = await sdk.authenticate(`Bearer ${token}`, {
      requireScopes: ["kb:read", "kb:write"],
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.headers["WWW-Authenticate"]).toBe(
        `Bearer error="insufficient_scope", scope="kb:read kb:write", resource_metadata="${RS}/.well-known/oauth-protected-resource"`,
      );
    }
  });

  it.each([
    "kb read",
    'kb"read',
    "kb\\read",
    "kb\r\nX-Injected:",
    "",
    "读",
  ])("拒绝无法安全进入 scope auth-param 的 token: %s", async (scope) => {
    const sdk = new RsSdk({ resourceId: RS, issuer: ISS });
    await expect(
      sdk.authenticate(undefined, { requireScopes: [scope] }),
    ).rejects.toThrow(TypeError);
  });

  it("c8_8a_operation_scope_challenges_are_complete", async () => {
    const metadata = `${RS}/.well-known/oauth-protected-resource`;
    const requiredScopes = ["kb:read", "kb:write"];
    const sdk = new RsSdk({ resourceId: RS, issuer: ISS });

    const missing = await sdk.authenticate(undefined, {
      requireScopes: requiredScopes,
    });
    expect(missing.ok).toBe(false);
    if (!missing.ok) {
      const challenge = missing.headers["WWW-Authenticate"];
      expect(missing.status).toBe(401);
      expect(challenge).toBe(
        `Bearer scope="kb:read kb:write", resource_metadata="${metadata}"`,
      );
      expect(challenge.match(/Bearer/g)).toHaveLength(1);
    }

    const key = await makeKey();
    const validatingSdk = await sdkWith(key);
    const token = await signToken({
      key,
      iss: ISS,
      aud: [RS],
      scope: "kb:read",
      now: NOW,
    });
    const insufficient = await validatingSdk.authenticate(`Bearer ${token}`, {
      requireScopes: requiredScopes,
    });
    expect(insufficient.ok).toBe(false);
    if (!insufficient.ok) {
      const challenge = insufficient.headers["WWW-Authenticate"];
      expect(insufficient.status).toBe(403);
      expect(challenge).toBe(
        `Bearer error="insufficient_scope", scope="kb:read kb:write", resource_metadata="${metadata}"`,
      );
      expect(challenge.match(/Bearer/g)).toHaveLength(1);
    }

    for (const scope of [
      "kb read",
      'kb"read',
      "kb\\read",
      "kb\r\nX-Injected:",
      "",
      "读",
    ]) {
      await expect(
        sdk.authenticate(undefined, { requireScopes: [scope] }),
      ).rejects.toThrow(TypeError);
      await expect(
        validatingSdk.authenticate(`Bearer ${token}`, {
          requireScopes: [scope],
        }),
      ).rejects.toThrow(TypeError);
    }
  });
});

describe("显式 scope implication resolver", () => {
  it("默认仅精确相等,不按冒号或前缀推断", () => {
    const resolver = createScopeResolver();
    expect(resolver("kb:read", "kb:read")).toBe(true);
    expect(resolver("kb", "kb:read")).toBe(false);
    expect(resolver("kb:admin", "kb:read")).toBe(false);
  });

  it("声明的 broader scope 传递满足 narrower scope", async () => {
    const key = await makeKey();
    const sdk = new RsSdk({
      resourceId: RS,
      issuer: ISS,
      jwksFetcher: async () => jwksOf(key) as Jwks,
      scopeImplications: {
        "kb:admin": ["kb:write"],
        "kb:write": ["kb:read"],
      },
    });
    sdk.seedJwks(jwksOf(key) as Jwks);
    const token = await signToken({
      key,
      iss: ISS,
      aud: [RS],
      scope: "kb:admin",
      now: NOW,
    });
    expect(
      (
        await sdk.authenticate(`Bearer ${token}`, {
          requireScopes: ["kb:read", "kb:write"],
        })
      ).ok,
    ).toBe(true);
  });

  it("未声明的 implication 仍返回 403", async () => {
    const key = await makeKey();
    const sdk = await sdkWith(key);
    const token = await signToken({
      key,
      iss: ISS,
      aud: [RS],
      scope: "kb:admin",
      now: NOW,
    });
    const result = await sdk.authenticate(`Bearer ${token}`, {
      requireScopes: ["kb:read"],
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.status).toBe(403);
  });

  it("拒绝循环 hierarchy 和双重 resolver 配置", () => {
    expect(() =>
      createScopeResolver({
        "kb:admin": ["kb:write"],
        "kb:write": ["kb:admin"],
      }),
    ).toThrow(/cycle/);
    expect(
      () =>
        new RsSdk({
          resourceId: RS,
          issuer: ISS,
          scopeImplications: { "kb:admin": ["kb:read"] },
          scopeResolver: () => true,
        }),
    ).toThrow(/mutually exclusive/);
  });

  it("自定义 resolver 只有同步 boolean true 才能授权", async () => {
    const key = await makeKey();
    const sdk = new RsSdk({
      resourceId: RS,
      issuer: ISS,
      jwksFetcher: async () => jwksOf(key) as Jwks,
      scopeResolver: (() => Promise.resolve(false)) as never,
    });
    sdk.seedJwks(jwksOf(key) as Jwks);
    const token = await signToken({
      key,
      iss: ISS,
      aud: [RS],
      scope: "kb:admin",
      now: NOW,
    });
    const result = await sdk.authenticate(`Bearer ${token}`, {
      requireScopes: ["kb:read"],
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.status).toBe(403);
  });
});

describe("C8.10b Grant-backed RAR delivery", () => {
  it("c8_10b_offline_sdk_rejects_grant_backed_rar_summary", async () => {
    const key = await makeKey();
    const sdk = await sdkWith(key);
    const token = await signToken({
      key,
      iss: ISS,
      aud: [RS],
      scope: "kb:read",
      authorizationDetails: [{
        type: "agent_auth_grant_summary_v1",
        locations: [RS],
        authorization_details_count: 4,
        authorization_details_sha256: "A".repeat(43),
        introspection_required: true,
      }],
      now: NOW,
    });

    const result = await sdk.authenticate(`Bearer ${token}`, {
      requireScopes: ["kb:read"],
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.status).toBe(403);
      expect("token" in result).toBe(false);
      expect(result.error.kind).toBe("insufficient_scope");
      expect(result.error.message).toContain("authenticated introspection");
    }
  });
});

describe("C8.5b verified RAR policy seam", () => {
  it("c8_5b_offline_evaluator_runs_only_after_signature_audience_and_scope", async () => {
    const key = await makeKey();
    const sdk = await sdkWith(key);
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
      requireScopes: ["kb:read"],
      rar: { request, evaluator },
    };

    const valid = await signToken({
      key,
      iss: ISS,
      aud: [RS],
      scope: "kb:read",
      authorizationDetails: [complexDetail],
      now: NOW,
    });
    const [header, payload, signature] = valid.split(".");
    const tamperedSignature =
      `${signature?.startsWith("A") ? "B" : "A"}${signature?.slice(1) ?? ""}`;
    const tampered = `${header}.${payload}.${tamperedSignature}`;
    const wrongAudience = await signToken({
      key,
      iss: ISS,
      aud: ["https://mcp.other.example.com"],
      scope: "kb:read",
      authorizationDetails: [complexDetail],
      now: NOW,
    });
    const missingScope = await signToken({
      key,
      iss: ISS,
      aud: [RS],
      scope: "openid",
      authorizationDetails: [complexDetail],
      now: NOW,
    });
    const multipleAudiences = await signToken({
      key,
      iss: ISS,
      aud: [RS, "https://mcp.other.example.com"],
      scope: "kb:read",
      authorizationDetails: [complexDetail],
      now: NOW,
    });
    const wrongSubType = await signToken({
      key,
      iss: ISS,
      aud: [RS],
      scope: "kb:read",
      subType: "agent",
      authorizationDetails: [complexDetail],
      now: NOW,
    });
    const malformedRar = await signToken({
      key,
      iss: ISS,
      aud: [RS],
      scope: "kb:read",
      authorizationDetails: { type: "cedar_policy" },
      now: NOW,
    });
    const emptyRar = await signToken({
      key,
      iss: ISS,
      aud: [RS],
      scope: "kb:read",
      authorizationDetails: {},
      now: NOW,
    });
    const malformedDetail = await signToken({
      key,
      iss: ISS,
      aud: [RS],
      scope: "kb:read",
      authorizationDetails: [42, complexDetail],
      now: NOW,
    });
    const missingType = await signToken({
      key,
      iss: ISS,
      aud: [RS],
      scope: "kb:read",
      authorizationDetails: [{ policy_ref: "missing-type" }, complexDetail],
      now: NOW,
    });

    for (const rejected of [
      tampered,
      wrongAudience,
      multipleAudiences,
      wrongSubType,
      missingScope,
      malformedRar,
      emptyRar,
      malformedDetail,
      missingType,
    ]) {
      const result = await sdk.authenticate(`Bearer ${rejected}`, policy);
      expect(result.ok).toBe(false);
      expect(calls).toHaveLength(0);
    }

    const allowed = await sdk.authenticate(`Bearer ${valid}`, policy);
    expect(allowed.ok).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.detail.policy_ref).toBe("doc-read");
    expect(calls[0]?.request.resource).toBe(RS);
    expect(calls[0]?.claims).toEqual({ sub: "user-1", scope: "kb:read" });

    const denied = await sdk.authenticate(`Bearer ${valid}`, {
      requireSubType: "user",
      requireScopes: ["kb:read"],
      rar: {
        request,
        evaluator: () => PolicyDecision.DENY,
      },
    });
    expect(denied.ok).toBe(false);
    if (!denied.ok) {
      expect(denied.status).toBe(403);
      expect("token" in denied).toBe(false);
    }
  });
});
