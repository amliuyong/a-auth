// JWKS 缓存 + 未知 kid 重取限流 + 负缓存(spec 010 C8.4)。
//
// 威胁:攻击者用大量随机 kid 的伪造 token 诱导 RS 高频重取 JWKS、放大打 AS。
// 防御:① single-flight(并发只发一次重取);② 最小重取间隔(默认 60s);
//       ③ 未知 kid 负缓存(默认 300s,窗口内同一未知 kid 不再触发重取);
//       ④ 拉取失败沿用旧缓存并拒当前 token(不清缓存、不放行)。

import { VerifyError, type Jwk, type Jwks, type JwksFetcher } from "./types.js";

export class JwksCache {
  private keys = new Map<string, Jwk>(); // kid → jwk
  private lastFetch = 0; // 上次成功/尝试重取时刻(秒)
  private inflight: Promise<boolean> | null = null; // single-flight;resolve=本次是否成功
  private negativeCache = new Map<string, number>(); // 未知 kid → negative-until(秒)

  constructor(
    private fetcher: JwksFetcher,
    private minRefetchIntervalSecs: number,
    private negativeCacheTtlSecs: number,
    private now: () => number,
  ) {}

  /**
   * 按 kid 取公钥;未知则(受限流/负缓存约束地)重取一次再查。
   * - 返回 Jwk:命中。
   * - 返回 null:**已知查无**(伪造/未注册 kid;缓存新鲜或负缓存/限流命中)。
   * - 抛 VerifyError("unavailable"):**重取失败且 kid 仍未解析**(JWKS 瞬时不可用 → 上层 503,
   *   不误报 invalid_token 让客户端去重登录;评审 Kiro MEDIUM-1)。
   */
  async getKey(kid: string): Promise<Jwk | null> {
    const cached = this.keys.get(kid);
    if (cached) return cached;

    const t = this.now();
    // 负缓存:已知查无的 kid,窗口内直接返回 null,不触发重取(防随机 kid 洪水放大)。
    const negUntil = this.negativeCache.get(kid);
    if (negUntil !== undefined && t < negUntil) return null;

    // 限流:距上次重取不足 min 间隔 → 不重取(用现有缓存查,查无即已知 miss)。
    if (t - this.lastFetch < this.minRefetchIntervalSecs) {
      return this.keys.get(kid) ?? null;
    }

    const ok = await this.refetch();
    const after = this.keys.get(kid);
    if (after) return after;
    if (!ok) {
      // 重取失败(fetcher 抛)且仍未解析 → 瞬时不可用,不进负缓存、不误判 invalid。
      throw new VerifyError("unavailable", "JWKS 暂不可用(重取失败)");
    }
    // 重取成功但仍查无 → 进负缓存(短期不再为这个 kid 重取)。
    this.negativeCache.set(kid, this.now() + this.negativeCacheTtlSecs);
    return null;
  }

  /** single-flight 重取:并发调用共享同一次拉取;返回是否成功。失败沿用旧缓存(不清空)。 */
  private async refetch(): Promise<boolean> {
    if (this.inflight) return this.inflight;
    this.lastFetch = this.now(); // 无论成败都占用间隔(防失败风暴)
    this.inflight = (async () => {
      try {
        const jwks: Jwks = await this.fetcher();
        const next = new Map<string, Jwk>();
        for (const k of jwks.keys) {
          if (k.kid) next.set(k.kid, k);
        }
        this.keys = next;
        // 成功刷新 → 清负缓存(新集可能含此前查无的 kid)。
        this.negativeCache.clear();
        return true;
      } catch {
        // 拉取失败:沿用旧缓存(不清空、不放行未知 kid)。
        return false;
      } finally {
        this.inflight = null;
      }
    })();
    return this.inflight;
  }

  /** 测试/预热:直接注入一组 key(跳过网络)。 */
  seed(jwks: Jwks): void {
    const next = new Map<string, Jwk>();
    for (const k of jwks.keys) if (k.kid) next.set(k.kid, k);
    this.keys = next;
    this.lastFetch = this.now();
  }
}
