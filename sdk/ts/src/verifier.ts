// access token 校验核心(spec 010 C8.2/C8.3 + RFC 9068 基线,评审 SDK-VALID-1)。
//
// 顺序(策略判定前先跑基线):
//  1. 解析 header;拒 alg:none;按 kid 取公钥;**强制 alg 与该 kid 公钥类型一致**(挡算法混淆)。
//  2. 验签(jose,按解析出的公钥类型)。
//  3. RFC 9068 基线:typ=at+jwt、iss==配置 issuer、exp/nbf/iat(±skew)、顶层 client_id。
//  4. aud 强校验:单元素数组且 == 本 RS resourceId(拒裸字符串,C2.5a)。
//  返回 VerifiedToken;任何不过抛 VerifyError(kind=invalid_token)。sub_type/scope 策略在 middleware。

import { importJWK, jwtVerify, decodeProtectedHeader, type JWK } from "jose";
import { JwksCache } from "./jwks-cache.js";
import {
  NAMESPACE,
  VerifyError,
  type RsSdkConfig,
  type SubType,
  type VerifiedToken,
} from "./types.js";

/** kid 对应公钥类型 → 唯一允许的 alg(C8.3:不隐含依赖库默认)。 */
function expectedAlg(kty: string, crv?: string): string | null {
  if (kty === "EC" && crv === "P-256") return "ES256";
  if (kty === "RSA") return "RS256";
  return null; // 其它类型本 AS 不签 access token
}

export class TokenVerifier {
  private clockSkew: number;
  private nowFn: () => number;

  constructor(
    private cfg: Required<Pick<RsSdkConfig, "resourceId" | "issuer">> & RsSdkConfig,
    private cache: JwksCache,
  ) {
    this.clockSkew = cfg.clockSkewSecs ?? 60;
    this.nowFn = cfg.now ?? (() => Math.floor(Date.now() / 1000));
  }

  private now(): number {
    return this.nowFn();
  }

  async verify(token: string): Promise<VerifiedToken> {
    // 1. header:拒 alg:none;取 kid。
    let header: { alg?: string; kid?: string; typ?: string };
    try {
      header = decodeProtectedHeader(token) as typeof header;
    } catch {
      throw new VerifyError("invalid_token", "malformed JWT header");
    }
    const alg = header.alg;
    if (!alg || alg === "none") {
      throw new VerifyError("invalid_token", "alg:none 一律拒");
    }
    if (!header.kid) {
      throw new VerifyError("invalid_token", "缺 kid");
    }

    // 2. 按 kid 取公钥(未知 kid 触发受限重取);强制 alg 与公钥类型一致。
    const jwk = await this.cache.getKey(header.kid);
    if (!jwk) {
      throw new VerifyError("invalid_token", `未知 kid: ${header.kid}`);
    }
    const wantAlg = expectedAlg(jwk.kty, jwk.crv);
    if (!wantAlg) {
      throw new VerifyError("invalid_token", `不支持的公钥类型: ${jwk.kty}`);
    }
    if (alg !== wantAlg) {
      // 算法混淆:header 声明的 alg 与该 kid 公钥自身类型不符 → 拒。
      throw new VerifyError("invalid_token", `alg ${alg} 与 kid 公钥类型(应 ${wantAlg})不符`);
    }

    // 3. 验签(只允许该公钥类型对应的单一 alg;jose 会再核对 header.alg==wantAlg)。
    let payload: Record<string, unknown>;
    try {
      const key = await importJWK(jwk as JWK, wantAlg);
      const res = await jwtVerify(token, key, {
        algorithms: [wantAlg],
        // iss/aud/时效我们自己按契约校(jose 的 aud 匹配不区分裸字符串 vs 数组)。
        clockTolerance: this.clockSkew,
      });
      payload = res.payload as Record<string, unknown>;
    } catch {
      throw new VerifyError("invalid_token", "签名/时效校验失败");
    }

    // 4. RFC 9068 基线。
    if (header.typ !== "at+jwt") {
      throw new VerifyError("invalid_token", "typ 必须 at+jwt(拒非 access token)");
    }
    if (payload.iss !== this.cfg.issuer) {
      throw new VerifyError("invalid_token", "iss 不匹配");
    }
    const clientId = payload.client_id;
    if (typeof clientId !== "string" || clientId.length === 0) {
      throw new VerifyError("invalid_token", "缺顶层 client_id(C2.1)");
    }
    // RFC 9068 要求 exp + iat(nbf 可选;本 AS token 无 nbf,故不强制 nbf)。
    // jwtVerify 不强制这些存在,须自校(评审 codex MEDIUM)。
    if (typeof payload.exp !== "number") {
      throw new VerifyError("invalid_token", "缺 exp");
    }
    if (typeof payload.iat !== "number") {
      throw new VerifyError("invalid_token", "缺 iat(RFC 9068)");
    }
    // 拒未来签发(iat 超出 now+skew;jose 不校 iat 的未来性)。
    const nowSecs = this.now();
    if (payload.iat > nowSecs + this.clockSkew) {
      throw new VerifyError("invalid_token", "iat 在未来(超时钟偏移)");
    }

    // 5. aud 强校验:严格单元素数组 == 本 RS(拒裸字符串,C2.5a)。
    const aud = payload.aud;
    if (!Array.isArray(aud) || aud.length !== 1 || aud[0] !== this.cfg.resourceId) {
      throw new VerifyError("invalid_token", "aud 非单元素数组或不匹配本 RS");
    }

    // 命名空间字段(消费,不派生 sub)。
    const ns = payload[NAMESPACE];
    let subType: SubType | undefined;
    let authGrant: string | undefined;
    let actorTypes: Record<string, string> | undefined;
    if (ns && typeof ns === "object") {
      const o = ns as Record<string, unknown>;
      if (typeof o.sub_type === "string") subType = o.sub_type as SubType;
      if (typeof o.auth_grant === "string") authGrant = o.auth_grant;
      if (o.actor_types !== undefined) {
        if (
          !o.actor_types ||
          typeof o.actor_types !== "object" ||
          Array.isArray(o.actor_types) ||
          !Object.values(o.actor_types).every((value) => typeof value === "string")
        ) {
          throw new VerifyError(
            "invalid_token",
            "命名空间 actor_types 必须是字符串映射",
          );
        }
        actorTypes = { ...(o.actor_types as Record<string, string>) };
      }
    }

    const scope =
      typeof payload.scope === "string"
        ? payload.scope.split(" ").filter(Boolean)
        : Array.isArray(payload.scope)
          ? (payload.scope as string[])
          : [];

    return {
      claims: payload,
      sub: typeof payload.sub === "string" ? payload.sub : "",
      aud: aud[0] as string,
      clientId,
      scope,
      subType,
      authGrant,
      actorTypes,
    };
  }
}
