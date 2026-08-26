// 测试 helper:用 jose 生成 ES256/RS256 密钥对 + 签 fixture token + 导出 JWKS。
// 与 AS 签发形状对齐:header {alg,typ:at+jwt,kid},claims {iss,sub,aud:[rs],iat,exp,client_id,scope,NAMESPACE}。

import { SignJWT, exportJWK, generateKeyPair, calculateJwkThumbprint, type JWK } from "jose";

const FIXTURE_NAMESPACE = "https://a-auth.com/c";

export interface KeyMaterial {
  privateKey: CryptoKey;
  publicJwk: JWK; // 含 kid（AS 用 JWK thumbprint 作 kid）
  alg: string;
}

export async function makeKey(alg: "ES256" | "RS256" | "RS384" = "ES256"): Promise<KeyMaterial> {
  const { privateKey, publicKey } = await generateKeyPair(alg, { extractable: true });
  const publicJwk = await exportJWK(publicKey);
  publicJwk.alg = alg;
  publicJwk.use = "sig";
  publicJwk.kid = await calculateJwkThumbprint(publicJwk);
  return { privateKey, publicJwk, alg };
}

export function jwksOf(...keys: KeyMaterial[]): { keys: JWK[] } {
  return { keys: keys.map((k) => k.publicJwk) };
}

export interface TokenOpts {
  key: KeyMaterial;
  iss: string;
  aud?: unknown; // 默认单元素数组;可传裸字符串测试拒绝
  sub?: string;
  clientId?: string | null; // null = 省略
  scope?: string;
  subType?: string | null; // null = 省略命名空间
  authGrant?: string;
  actorTypes?: Readonly<Record<string, string>>;
  authorizationDetails?: unknown;
  typ?: string; // 默认 at+jwt
  expOffset?: number; // 相对 now 的过期偏移(秒),默认 +3600
  nbfOffset?: number;
  now?: number; // iat 基准
  includeIat?: boolean;
  includeExp?: boolean;
  algHeaderOverride?: string; // 篡改 header.alg 测算法混淆
  kidOverride?: string; // 篡改 kid
}

export async function signToken(o: TokenOpts): Promise<string> {
  const now = o.now ?? Math.floor(Date.now() / 1000);
  const aud = o.aud !== undefined ? o.aud : [o.iss.replace(/\/$/, "") + "/rs"];
  const payload: Record<string, unknown> = {
    iss: o.iss,
    sub: o.sub ?? "user-1",
    aud,
    scope: o.scope ?? "openid",
  };
  if (o.clientId !== null) payload.client_id = o.clientId ?? "app-1";
  if (o.subType !== null) {
    payload[FIXTURE_NAMESPACE] = {
      sub_type: o.subType ?? "user",
      auth_grant: o.authGrant ?? "grant-1",
      ...(o.actorTypes === undefined ? {} : { actor_types: o.actorTypes }),
    };
  }
  if (o.authorizationDetails !== undefined) {
    payload.authorization_details = o.authorizationDetails;
  }
  const header: Record<string, unknown> = {
    alg: o.algHeaderOverride ?? o.key.alg,
    typ: o.typ ?? "at+jwt",
    kid: o.kidOverride ?? o.key.publicJwk.kid,
  };
  let token = new SignJWT(payload).setProtectedHeader(header as any);
  if (o.includeIat !== false) token = token.setIssuedAt(now);
  if (o.includeExp !== false) {
    token = token.setExpirationTime(now + (o.expOffset ?? 3600));
  }
  if (o.nbfOffset !== undefined) {
    token = token.setNotBefore(now + o.nbfOffset);
  }
  return await token.sign(o.key.privateKey);
}
