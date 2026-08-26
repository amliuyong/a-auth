// C8.4:未知 kid 重取的限流 + 负缓存 + single-flight + 拉取失败沿用旧缓存(随机 kid 洪水防放大)。

import { describe, it, expect } from "vitest";
import { RsSdk, type Jwks } from "../src/index.js";
import { makeKey, jwksOf, signToken } from "./helpers.js";

const ISS = "https://auth.example.com";
const RS = "https://mcp.kb.example.com";

describe("C8.4 未知 kid 重取限流 + 负缓存", () => {
  it("随机 kid 洪水:窗口内重取被限流,且伪造 token 全拒", async () => {
    const key = await makeKey();
    let now = 1_000_000;
    let fetchCount = 0;
    const sdk = new RsSdk({
      resourceId: RS,
      issuer: ISS,
      now: () => now,
      minRefetchIntervalSecs: 60,
      negativeCacheTtlSecs: 300,
      jwksFetcher: async () => {
        fetchCount++;
        return jwksOf(key) as Jwks;
      },
    });
    // 首个未知 kid 触发一次重取(拉到真集,但都不含随机 kid)。
    const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const forged = (kid: string) =>
      `${enc({ alg: "ES256", typ: "at+jwt", kid })}.${enc({ iss: ISS, aud: [RS], exp: now + 100, client_id: "c" })}.sig`;

    // 100 个不同随机 kid 的伪造 token,同一 60s 窗口内。
    for (let i = 0; i < 100; i++) {
      const r = await sdk.authenticate(`Bearer ${forged("random-kid-" + i)}`);
      expect(r.ok).toBe(false); // 全部拒(验签失败/未知 kid)
    }
    // 关键:重取被限流——不是每个 token 触发一次(100 次)。窗口内应 ≤ 1 次。
    expect(fetchCount).toBeLessThanOrEqual(1);
  });

  it("同一未知 kid 进负缓存:窗口内不重复重取", async () => {
    const key = await makeKey();
    let now = 1_000_000;
    let fetchCount = 0;
    const sdk = new RsSdk({
      resourceId: RS,
      issuer: ISS,
      now: () => now,
      minRefetchIntervalSecs: 0, // 关掉间隔限流,单独验负缓存
      negativeCacheTtlSecs: 300,
      jwksFetcher: async () => {
        fetchCount++;
        return jwksOf(key) as Jwks;
      },
    });
    const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const forged = `${enc({ alg: "ES256", typ: "at+jwt", kid: "ghost" })}.${enc({ iss: ISS, aud: [RS], exp: now + 100, client_id: "c" })}.sig`;
    await sdk.authenticate(`Bearer ${forged}`); // 第一次:重取 + 查无 → 负缓存
    const first = fetchCount;
    await sdk.authenticate(`Bearer ${forged}`); // 第二次:负缓存命中,不重取
    await sdk.authenticate(`Bearer ${forged}`);
    expect(fetchCount).toBe(first); // 负缓存生效,未再重取
  });

  it("JWKS 拉取失败:沿用旧缓存并拒当前 token(不放行)", async () => {
    const key = await makeKey();
    // SDK 缓存计时用注入 now;签 fixture 用真实挂钟(jose 校时效不接受注入时钟)。
    let now = Math.floor(Date.now() / 1000);
    let fail = false;
    const sdk = new RsSdk({
      resourceId: RS,
      issuer: ISS,
      now: () => now,
      minRefetchIntervalSecs: 0,
      jwksFetcher: async () => {
        if (fail) throw new Error("JWKS down");
        return jwksOf(key) as Jwks;
      },
    });
    sdk.seedJwks(jwksOf(key) as Jwks);
    // 已缓存 key → 有效 token 仍 ok。
    const good = await signToken({ key, iss: ISS, aud: [RS] });
    expect((await sdk.authenticate(`Bearer ${good}`)).ok).toBe(true);

    // 现在拉取会失败;一个未知 kid 的 token → 触发重取(失败)→ 拒,但旧缓存仍在。
    fail = true;
    now += 1000;
    const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const forged = `${enc({ alg: "ES256", typ: "at+jwt", kid: "new-kid" })}.${enc({ iss: ISS, aud: [RS], exp: now + 100, client_id: "c" })}.sig`;
    expect((await sdk.authenticate(`Bearer ${forged}`)).ok).toBe(false);
    // 旧 key 的有效 token 仍 ok(缓存未被清空)。
    const good2 = await signToken({ key, iss: ISS, aud: [RS] });
    expect((await sdk.authenticate(`Bearer ${good2}`)).ok).toBe(true);
  });

  it("JWKS 从未拉到 + 拉取失败 + 未知 kid → 503 unavailable(非 401 invalid)", async () => {
    const sdk = new RsSdk({
      resourceId: RS,
      issuer: ISS,
      minRefetchIntervalSecs: 0,
      jwksFetcher: async () => {
        throw new Error("JWKS down");
      },
    });
    const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const now = Math.floor(Date.now() / 1000);
    const forged = `${enc({ alg: "ES256", typ: "at+jwt", kid: "k" })}.${enc({ iss: ISS, aud: [RS], exp: now + 100, client_id: "c" })}.sig`;
    const r = await sdk.authenticate(`Bearer ${forged}`);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.status).toBe(503); // 瞬时不可用 → 可重试,不误报 re-login
  });

  it("轮换:新 kid 首次未知 → 重取后放行(降低旧缓存拒新 key 的窗口)", async () => {
    const key1 = await makeKey();
    const key2 = await makeKey();
    let current = jwksOf(key1) as Jwks;
    const sdk = new RsSdk({
      resourceId: RS,
      issuer: ISS,
      minRefetchIntervalSecs: 0,
      jwksFetcher: async () => current,
    });
    sdk.seedJwks(jwksOf(key1) as Jwks);
    // AS 轮换到 key2(JWKS 现含两把)。
    current = jwksOf(key1, key2) as Jwks;
    const t2 = await signToken({ key: key2, iss: ISS, aud: [RS] });
    // key2 kid 未知 → 触发重取 → 拉到新集 → 放行。
    const r = await sdk.authenticate(`Bearer ${t2}`);
    expect(r.ok).toBe(true);
  });

  it("c8_4_unknown_kid_refetch_rate_limit_and_negative_cache", async () => {
    const key1 = await makeKey();
    const key2 = await makeKey();
    const key3 = await makeKey();
    let now = Math.floor(Date.now() / 1000);
    let current = jwksOf(key1) as Jwks;
    let fetchCount = 0;
    const sdk = new RsSdk({
      resourceId: RS,
      issuer: ISS,
      now: () => now,
      minRefetchIntervalSecs: 60,
      negativeCacheTtlSecs: 300,
      jwksFetcher: async () => {
        fetchCount++;
        return current;
      },
    });
    sdk.seedJwks(jwksOf(key1) as Jwks);
    current = jwksOf(key1, key2) as Jwks;
    now += 61;
    const rotated = await signToken({ key: key2, iss: ISS, aud: [RS] });
    expect((await sdk.authenticate(`Bearer ${rotated}`)).ok).toBe(true);
    expect(fetchCount).toBe(1);

    const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const forged = (kid: string) =>
      `${enc({ alg: "ES256", typ: "at+jwt", kid })}.${enc({ iss: ISS, aud: [RS], exp: now + 100, client_id: "c" })}.sig`;
    for (let i = 0; i < 20; i++) {
      expect((await sdk.authenticate(`Bearer ${forged(`random-${i}`)}`)).ok).toBe(false);
    }
    expect(fetchCount).toBe(1);

    current = jwksOf(key1, key2, key3) as Jwks;
    now += 59;
    const stillLimited = await signToken({ key: key3, iss: ISS, aud: [RS] });
    expect((await sdk.authenticate(`Bearer ${stillLimited}`)).ok).toBe(false);
    expect(fetchCount).toBe(1);
    now += 2;
    const nextRotation = await signToken({ key: key3, iss: ISS, aud: [RS] });
    expect((await sdk.authenticate(`Bearer ${nextRotation}`)).ok).toBe(true);
    expect(fetchCount).toBe(2);

    const ghostKey = await makeKey();
    const ghostJwk = { ...ghostKey.publicJwk, kid: "ghost" };
    const ghostToken = await signToken({
      key: ghostKey,
      iss: ISS,
      aud: [RS],
      kidOverride: "ghost",
    });
    let negativeNow = Math.floor(Date.now() / 1000);
    let negativeCurrent = jwksOf(key1) as Jwks;
    let negativeFetchCount = 0;
    const negativeSdk = new RsSdk({
      resourceId: RS,
      issuer: ISS,
      now: () => negativeNow,
      minRefetchIntervalSecs: 0,
      negativeCacheTtlSecs: 300,
      jwksFetcher: async () => {
        negativeFetchCount++;
        return negativeCurrent;
      },
    });
    for (let i = 0; i < 3; i++) {
      expect((await negativeSdk.authenticate(`Bearer ${ghostToken}`)).ok).toBe(false);
    }
    expect(negativeFetchCount).toBe(1);

    expect((await negativeSdk.authenticate(`Bearer ${forged("ghost-2")}`)).ok).toBe(false);
    expect(negativeFetchCount).toBe(2);

    expect((await negativeSdk.authenticate(`Bearer ${ghostToken}`)).ok).toBe(false);
    expect(negativeFetchCount).toBe(3);
    negativeCurrent = { keys: [key1.publicJwk, ghostJwk] } as Jwks;
    negativeNow += 299;
    expect((await negativeSdk.authenticate(`Bearer ${ghostToken}`)).ok).toBe(false);
    expect(negativeFetchCount).toBe(3);
    negativeNow += 2;
    expect((await negativeSdk.authenticate(`Bearer ${ghostToken}`)).ok).toBe(true);
    expect(negativeFetchCount).toBe(4);

    let concurrentFetchCount = 0;
    const concurrentSdk = new RsSdk({
      resourceId: RS,
      issuer: ISS,
      minRefetchIntervalSecs: 0,
      negativeCacheTtlSecs: 300,
      jwksFetcher: async () => {
        concurrentFetchCount++;
        await new Promise((resolve) => setTimeout(resolve, 20));
        return jwksOf(key1) as Jwks;
      },
    });
    const concurrentResults = await Promise.all(
      Array.from({ length: 12 }, () =>
        concurrentSdk.authenticate(`Bearer ${forged("concurrent-ghost")}`),
      ),
    );
    expect(concurrentResults.every((result) => !result.ok)).toBe(true);
    expect(concurrentFetchCount).toBe(1);

    let fail = false;
    const failureSdk = new RsSdk({
      resourceId: RS,
      issuer: ISS,
      minRefetchIntervalSecs: 0,
      jwksFetcher: async () => {
        if (fail) throw new Error("JWKS down");
        return jwksOf(key1) as Jwks;
      },
    });
    failureSdk.seedJwks(jwksOf(key1) as Jwks);
    const good = await signToken({ key: key1, iss: ISS, aud: [RS] });
    expect((await failureSdk.authenticate(`Bearer ${good}`)).ok).toBe(true);
    fail = true;
    expect((await failureSdk.authenticate(`Bearer ${forged("unavailable-kid")}`)).ok).toBe(false);
    const freshGood = await signToken({ key: key1, iss: ISS, aud: [RS], scope: "kb:read" });
    expect(freshGood).not.toBe(good);
    expect((await failureSdk.authenticate(`Bearer ${freshGood}`)).ok).toBe(true);
  });
});
