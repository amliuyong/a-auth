// spec 010 §5.2 / C8.9:RS SDK DPoP(RFC 9449)proof 校验。EC P-256 proof(jose 构造)。

import { describe, it, expect } from "vitest";
import { generateKeyPair, exportJWK, SignJWT, calculateJwkThumbprint, type JWK } from "jose";
import { verifyDpopProof, computeJkt, computeAth, normalizeHtu, VerifyError } from "../src/index.js";

const HTU = "https://rs.example.com/api/data";
const HTM = "POST";

async function keypair() {
  const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
  const pubJwk = await exportJWK(publicKey);
  pubJwk.crv = pubJwk.crv ?? "P-256";
  return { privateKey, pubJwk: pubJwk as JWK };
}

async function makeProof(
  privateKey: CryptoKey,
  pubJwk: JWK,
  opts: {
    htm?: string;
    htu?: string;
    iat?: number;
    jti?: string;
    ath?: string;
    nonce?: string;
    typ?: string;
    omit?: Array<"htm" | "htu" | "iat">;
  } = {},
): Promise<string> {
  const iat = opts.iat ?? Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = {
    htm: opts.htm ?? HTM,
    htu: opts.htu ?? HTU,
    jti: opts.jti ?? "jti-1",
  };
  for (const claim of opts.omit ?? []) {
    if (claim !== "iat") delete payload[claim];
  }
  if (opts.ath !== undefined) payload.ath = opts.ath;
  if (opts.nonce !== undefined) payload.nonce = opts.nonce;
  let jwt = new SignJWT(payload).setProtectedHeader({
    typ: opts.typ ?? "dpop+jwt",
    alg: "ES256",
    jwk: pubJwk,
  });
  if (!opts.omit?.includes("iat")) jwt = jwt.setIssuedAt(iat);
  return jwt.sign(privateKey);
}

describe("verifyDpopProof", () => {
  it("合法 proof 通过", async () => {
    const { privateKey, pubJwk } = await keypair();
    const jkt = await computeJkt(pubJwk);
    const proof = await makeProof(privateKey, pubJwk);
    const r = await verifyDpopProof(proof, jkt, HTM, HTU);
    expect(r.jkt).toBe(jkt);
    expect(r.jti).toBe("jti-1");
  });

  it("jkt 不匹配 → 拒", async () => {
    const { privateKey, pubJwk } = await keypair();
    const proof = await makeProof(privateKey, pubJwk);
    const other = await keypair();
    const otherJkt = await computeJkt(other.pubJwk);
    await expect(verifyDpopProof(proof, otherJkt, HTM, HTU)).rejects.toMatchObject({ kind: "invalid_token" });
  });

  it("htu 不匹配 → 拒", async () => {
    const { privateKey, pubJwk } = await keypair();
    const jkt = await computeJkt(pubJwk);
    const proof = await makeProof(privateKey, pubJwk, { htu: "https://rs.example.com/other" });
    await expect(verifyDpopProof(proof, jkt, HTM, HTU)).rejects.toThrow(/htu/);
  });

  it("htm 不匹配 → 拒", async () => {
    const { privateKey, pubJwk } = await keypair();
    const jkt = await computeJkt(pubJwk);
    const proof = await makeProof(privateKey, pubJwk, { htm: "GET" });
    await expect(verifyDpopProof(proof, jkt, "POST", HTU)).rejects.toThrow(/htm/);
  });

  it("htu 规范化去 query/fragment", async () => {
    const { privateKey, pubJwk } = await keypair();
    const jkt = await computeJkt(pubJwk);
    const proof = await makeProof(privateKey, pubJwk, { htu: HTU + "?a=1#f" });
    const r = await verifyDpopProof(proof, jkt, HTM, HTU);
    expect(r.jkt).toBe(jkt);
    expect(normalizeHtu("https://x/a?q=1#f")).toBe("https://x/a");
  });

  it("typ != dpop+jwt → 拒", async () => {
    const { privateKey, pubJwk } = await keypair();
    const jkt = await computeJkt(pubJwk);
    const proof = await makeProof(privateKey, pubJwk, { typ: "JWT" });
    await expect(verifyDpopProof(proof, jkt, HTM, HTU)).rejects.toThrow(/dpop\+jwt/);
  });

  it("陈旧 iat → 拒", async () => {
    const { privateKey, pubJwk } = await keypair();
    const jkt = await computeJkt(pubJwk);
    const proof = await makeProof(privateKey, pubJwk, { iat: Math.floor(Date.now() / 1000) - 10_000 });
    await expect(verifyDpopProof(proof, jkt, HTM, HTU)).rejects.toThrow(/iat/);
  });

  it("ath 绑定:正确通过 / 错误拒", async () => {
    const { privateKey, pubJwk } = await keypair();
    const jkt = await computeJkt(pubJwk);
    const access = "the-access-token";
    const proofOk = await makeProof(privateKey, pubJwk, { ath: await computeAth(access) });
    const r = await verifyDpopProof(proofOk, jkt, HTM, HTU, { accessToken: access });
    expect(r.jkt).toBe(jkt);
    const proofBad = await makeProof(privateKey, pubJwk, { ath: await computeAth("other") });
    await expect(verifyDpopProof(proofBad, jkt, HTM, HTU, { accessToken: access })).rejects.toThrow(/ath/);
  });

  it("nonce:期望但缺 → 拒 / 匹配 → 通过", async () => {
    const { privateKey, pubJwk } = await keypair();
    const jkt = await computeJkt(pubJwk);
    const proofNoNonce = await makeProof(privateKey, pubJwk);
    await expect(
      verifyDpopProof(proofNoNonce, jkt, HTM, HTU, { expectedNonce: "srv-nonce" }),
    ).rejects.toThrow(/nonce/);
    const proofOk = await makeProof(privateKey, pubJwk, { nonce: "srv-nonce" });
    const r = await verifyDpopProof(proofOk, jkt, HTM, HTU, { expectedNonce: "srv-nonce" });
    expect(r.jkt).toBe(jkt);
  });

  it("jkt 计算与 jose thumbprint 一致(RFC 7638)", async () => {
    const { pubJwk } = await keypair();
    const jkt = await computeJkt(pubJwk);
    const direct = await calculateJwkThumbprint(pubJwk, "sha256");
    expect(jkt).toBe(direct);
  });

  it("c8_9_dpop_proof_binds_request_token_and_nonce", async () => {
    const { privateKey, pubJwk } = await keypair();
    const jkt = await computeJkt(pubJwk);
    const accessToken = "signed-access-token";
    const proof = await makeProof(privateKey, pubJwk, {
      htu: HTU + "?proof=1#fragment",
      ath: await computeAth(accessToken),
      nonce: "server-nonce",
      jti: "exact-proof",
    });
    const result = await verifyDpopProof(proof, jkt, HTM, HTU + "?request=2", {
      accessToken,
      expectedNonce: "server-nonce",
    });
    expect(result.jkt).toBe(jkt);
    expect(result.jti).toBe("exact-proof");

    const other = await keypair();
    await expect(verifyDpopProof(proof, await computeJkt(other.pubJwk), HTM, HTU)).rejects.toBeInstanceOf(
      VerifyError,
    );

    const wrongHtu = await makeProof(privateKey, pubJwk, { htu: "https://rs.example.com/other" });
    await expect(verifyDpopProof(wrongHtu, jkt, HTM, HTU)).rejects.toThrow(/htu/);

    const wrongHtm = await makeProof(privateKey, pubJwk, { htm: "GET" });
    await expect(verifyDpopProof(wrongHtm, jkt, HTM, HTU)).rejects.toThrow(/htm/);

    const stale = await makeProof(privateKey, pubJwk, {
      iat: Math.floor(Date.now() / 1000) - 301,
    });
    await expect(
      verifyDpopProof(stale, jkt, HTM, HTU, { iatWindowSecs: 300 }),
    ).rejects.toThrow(/iat/);

    const future = await makeProof(privateKey, pubJwk, {
      iat: Math.floor(Date.now() / 1000) + 301,
    });
    await expect(
      verifyDpopProof(future, jkt, HTM, HTU, { iatWindowSecs: 300 }),
    ).rejects.toThrow(/iat/);

    for (const missingClaim of ["htu", "htm", "iat"] as const) {
      const missing = await makeProof(privateKey, pubJwk, { omit: [missingClaim] });
      await expect(verifyDpopProof(missing, jkt, HTM, HTU)).rejects.toBeInstanceOf(VerifyError);
    }

    const missingAth = await makeProof(privateKey, pubJwk);
    await expect(
      verifyDpopProof(missingAth, jkt, HTM, HTU, { accessToken }),
    ).rejects.toThrow(/ath/);

    const wrongAth = await makeProof(privateKey, pubJwk, {
      ath: await computeAth("other-token"),
    });
    await expect(
      verifyDpopProof(wrongAth, jkt, HTM, HTU, { accessToken }),
    ).rejects.toThrow(/ath/);

    const missingNonce = await makeProof(privateKey, pubJwk);
    await expect(
      verifyDpopProof(missingNonce, jkt, HTM, HTU, { expectedNonce: "server-nonce" }),
    ).rejects.toThrow(/nonce/);

    const wrongNonce = await makeProof(privateKey, pubJwk, { nonce: "other-nonce" });
    await expect(
      verifyDpopProof(wrongNonce, jkt, HTM, HTU, { expectedNonce: "server-nonce" }),
    ).rejects.toThrow(/nonce/);

    for (const privateField of ["d", "p", "q", "dp", "dq", "qi"]) {
      const privateJwk = { ...pubJwk, [privateField]: "private-material-must-not-appear" } as JWK;
      const privateJwkProof = await makeProof(privateKey, privateJwk);
      await expect(verifyDpopProof(privateJwkProof, jkt, HTM, HTU)).rejects.toThrow(/私钥/);
    }

    const [protectedHeader, payload, signature] = proof.split(".");
    const tamperedSignature = (signature?.startsWith("A") ? "B" : "A") + signature?.slice(1);
    const tampered = `${protectedHeader}.${payload}.${tamperedSignature}`;
    await expect(verifyDpopProof(tampered, jkt, HTM, HTU)).rejects.toThrow(/签名/);
  });
});
