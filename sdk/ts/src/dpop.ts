// Agent Auth RS SDK — DPoP(RFC 9449)proof 校验(spec 010 §5.2 / C8.9,P3 能力,独立库提前备)。
//
// DPoP sender-constraint 强制点在 RS:AS 签 cnf.jkt-bound token,RS 每次请求校客户端的 DPoP proof
// (证明持有私钥)。本模块纯逻辑校验器(零 IO)。**默认不启用**:token 无 cnf.jkt 时跳过(P0–P2 bearer 假设);
// 有 cnf.jkt 时 MUST 校 proof。与 grant-ref(AS 内闭环)不同——RS SDK 独立分发,可消费任意 RFC 9449 AS 的
// cnf token,生态价值独立(codex+Kiro 双评审确认)。整体 DPoP 标 P3;本校验器作独立库能力提前就位。
//
// 校验步骤(RFC 9449 §4.3):typ=dpop+jwt + alg 与内嵌 jwk 一致(防混淆)+ 内嵌 jwk 自验签 +
// jkt(RFC 7638)== token.cnf.jkt + htm/htu(htu 去 query/fragment)+ iat 窗口 + ath(若给 access_token)+
// nonce(若服务端下发)。jti 重放缓存是 RS 责任(SDK 返回 jti 供去重)。

import { calculateJwkThumbprint, importJWK, jwtVerify, decodeProtectedHeader, type JWK } from "jose";
import { VerifyError } from "./types.js";

export interface DPoPResult {
  jkt: string; // proof 公钥 thumbprint(= token.cnf.jkt)
  jti: string; // 供 RS 侧重放缓存去重
  iat: number;
}

export interface DPoPVerifyOptions {
  accessToken?: string; // 若给,校 ath == SHA256(accessToken)
  expectedNonce?: string; // 若服务端下发 nonce,MUST 匹配
  iatWindowSecs?: number; // iat 接受窗口,默认 300
  now?: () => number; // 当前秒,默认 Date.now()/1000
}

function b64uNoPad(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256(input: string): Promise<Uint8Array> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(digest);
}

/** htu 规范化(RFC 9449 §4.3):去 fragment 与 query。 */
export function normalizeHtu(url: string): string {
  const noFrag = url.split("#")[0] ?? url;
  return noFrag.split("?")[0] ?? noFrag;
}

/** access token hash:base64url(SHA-256(access_token))。 */
export async function computeAth(accessToken: string): Promise<string> {
  return b64uNoPad(await sha256(accessToken));
}

/** RFC 7638 JWK thumbprint(jose calculateJwkThumbprint,SHA-256)。 */
export async function computeJkt(jwk: JWK): Promise<string> {
  return calculateJwkThumbprint(jwk, "sha256");
}

function expectedAlg(jwk: JWK): string | null {
  if (jwk.kty === "EC" && jwk.crv === "P-256") return "ES256";
  if (jwk.kty === "RSA") return "RS256";
  if (jwk.kty === "OKP" && jwk.crv === "Ed25519") return "EdDSA";
  return null;
}

/**
 * 校验一个 DPoP proof(RFC 9449 §4.3)。成功 resolve DPoPResult;失败 throw VerifyError。
 * @param tokenCnfJkt access token 的 cnf.jkt(RS 从已验签 token 取);proof 公钥 thumbprint MUST 等它。
 * @param htm 请求方法;@param htu 请求 URL(内部规范化去 query/fragment)。
 */
export async function verifyDpopProof(
  proofJwt: string,
  tokenCnfJkt: string,
  htm: string,
  htu: string,
  opts: DPoPVerifyOptions = {},
): Promise<DPoPResult> {
  const nowFn = opts.now ?? (() => Date.now() / 1000);
  const iatWindow = opts.iatWindowSecs ?? 300;

  // 1. header:typ + alg + 内嵌 jwk。
  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(proofJwt);
  } catch (e) {
    throw new VerifyError("invalid_token", `DPoP proof header 非法: ${String(e)}`);
  }
  if (header.typ !== "dpop+jwt") {
    throw new VerifyError("invalid_token", "DPoP proof typ 必须 dpop+jwt");
  }
  const alg = header.alg;
  if (!alg || alg === "none") {
    throw new VerifyError("invalid_token", "DPoP proof alg:none 一律拒");
  }
  const jwk = header.jwk as JWK | undefined;
  if (!jwk || typeof jwk !== "object") {
    throw new VerifyError("invalid_token", "DPoP proof 缺内嵌 jwk");
  }
  // 私钥字段绝不该出现在 proof jwk。
  for (const priv of ["d", "p", "q", "dp", "dq", "qi"]) {
    if (priv in jwk) throw new VerifyError("invalid_token", "DPoP jwk 含私钥字段(必须只含公钥)");
  }
  const want = expectedAlg(jwk);
  if (want === null) {
    throw new VerifyError("invalid_token", `DPoP jwk 不支持的类型: ${jwk.kty}`);
  }
  if (alg !== want) {
    throw new VerifyError("invalid_token", `DPoP alg ${alg} 与 jwk 类型(应 ${want})不符(防 alg 混淆)`);
  }

  // 2. 签名:用内嵌 jwk 自验。
  let payload: Record<string, unknown>;
  try {
    const key = await importJWK(jwk, want);
    const res = await jwtVerify(proofJwt, key, { algorithms: [want] });
    payload = res.payload as Record<string, unknown>;
  } catch (e) {
    throw new VerifyError("invalid_token", `DPoP proof 签名校验失败: ${String(e)}`);
  }

  // 3. jkt 匹配 token.cnf.jkt。
  const jkt = await computeJkt(jwk);
  if (jkt !== tokenCnfJkt) {
    throw new VerifyError("invalid_token", "DPoP proof jkt 不匹配 token cnf.jkt(sender-constraint)");
  }

  // 4. htm/htu。
  if (payload.htm !== htm) {
    throw new VerifyError("invalid_token", "DPoP htm 不匹配请求方法");
  }
  if (typeof payload.htu !== "string" || normalizeHtu(payload.htu) !== normalizeHtu(htu)) {
    throw new VerifyError("invalid_token", "DPoP htu 不匹配请求 URL");
  }

  // 5. iat 新鲜度。
  const iat = payload.iat;
  if (typeof iat !== "number") {
    throw new VerifyError("invalid_token", "DPoP proof iat 非法");
  }
  if (Math.abs(nowFn() - iat) > iatWindow) {
    throw new VerifyError("invalid_token", "DPoP proof iat 超出接受窗口(陈旧/时钟偏差)");
  }

  // 6. ath(若提供 access_token)。
  if (opts.accessToken !== undefined) {
    const expectedAth = await computeAth(opts.accessToken);
    if (payload.ath !== expectedAth) {
      throw new VerifyError("invalid_token", "DPoP ath 不匹配 access token(防 proof 换绑)");
    }
  }

  // 7. nonce(若服务端下发)。
  if (opts.expectedNonce !== undefined && payload.nonce !== opts.expectedNonce) {
    throw new VerifyError("invalid_token", "DPoP nonce 不匹配");
  }

  const jti = payload.jti;
  if (typeof jti !== "string" || !jti) {
    throw new VerifyError("invalid_token", "DPoP proof 缺 jti");
  }
  return { jkt, jti, iat: Math.floor(iat) };
}
