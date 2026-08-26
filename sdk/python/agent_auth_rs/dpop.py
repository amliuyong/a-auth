"""Agent Auth RS SDK — DPoP(RFC 9449)proof 校验(spec 010 §5.2 / C8.9,P3 能力,独立库提前备)。

DPoP 的 sender-constraint **强制点在 RS**——AS 只签发 `cnf.jkt`-bound token,真正拦"token 被盗用"
要 RS 校验客户端每次请求带的 **DPoP proof**(证明持有对应私钥)。本模块提供**纯逻辑校验器**(零 IO):
给定 proof JWT + token 的 `cnf.jkt` + 请求上下文(htu/htm)+ access token → 校验通过/拒。

**⚠️ 阶段与启用**:整体 DPoP 标 **P3**(硬化;P0–P2 用 bearer,AS 不签 cnf)。本校验器作为**独立分发库
能力提前就位**(与 grant-ref[AS 内闭环]不同——RS SDK 可消费任意符合 RFC 9449 的 AS 的 cnf token,
生态价值独立于本 AS 是否签 cnf,codex+Kiro 双评审确认)。**默认不启用**:token 无 `cnf.jkt` 时跳过 DPoP
(P0–P2 bearer 假设不破坏);token 有 `cnf.jkt` 时 MUST 校验 proof(无 proof / 校验失败 → 拒)。

**校验步骤(RFC 9449 §4.3,双评审红线全覆盖)**:
1. header:`typ == "dpop+jwt"`;`alg` 非 none/非对称、与嵌入 `jwk` 类型一致(防 alg 混淆);
2. 签名:用 proof **内嵌 jwk** 自验签(DPoP proof 自包含公钥);
3. `jkt`:RFC 7638 JWK thumbprint(规范化 JSON→SHA-256→base64url)MUST == token 的 `cnf.jkt`;
4. `htm`/`htu`:htm==请求方法;htu==请求 URL **去 query/fragment**后匹配(防 query 变化绕过);
5. `iat`:在接受窗口内(防陈旧 proof);`jti`:**SDK 提供 jti 供 RS 去重,重放缓存是 RS 责任**;
6. `ath`(若 access_token 提供):`ath == base64url(SHA256(access_token))`(防 proof 换绑到别的 token);
7. `nonce`(若服务端下发):MUST 精确匹配。

RS 侧 jti 重放缓存不在本模块(RS 责任;窗口 = iat 接受范围)。决策真相源:docs §2(cnf.jkt)/§6;C8.9。
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

import jwt
from jwt import PyJWK

from .types import VerifyError


@dataclass
class DPoPResult:
    """DPoP 校验通过的结果。"""

    jkt: str  # proof 公钥的 thumbprint(= token.cnf.jkt)
    jti: str  # proof 的 jti(供 RS 侧重放缓存去重)
    iat: int


def _b64u_no_pad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def compute_jkt(jwk: dict) -> str:
    """RFC 7638 JWK thumbprint(base64url(SHA-256(规范化 JSON)))。
    规范化 = 只取该 kty 的 required 成员、按字典序、无空白、UTF-8。"""
    kty = jwk.get("kty")
    if kty == "EC":
        members = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    elif kty == "RSA":
        members = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    elif kty == "OKP":
        members = {"crv": jwk["crv"], "kty": "OKP", "x": jwk["x"]}
    else:
        raise VerifyError("invalid_token", f"DPoP jwk 不支持的 kty: {kty}")
    canon = json.dumps(members, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    return _b64u_no_pad(hashlib.sha256(canon.encode("utf-8")).digest())


def compute_ath(access_token: str) -> str:
    """access token hash(base64url(SHA-256(access_token 的 ASCII 字节)))。"""
    return _b64u_no_pad(hashlib.sha256(access_token.encode("ascii")).digest())


def normalize_htu(url: str) -> str:
    """htu 规范化(RFC 9449 §4.3):去 query 与 fragment,只保留 scheme://host[:port]/path。"""
    # 先去 fragment 再去 query(顺序:# 可能在 ? 后)。
    url = url.split("#", 1)[0]
    url = url.split("?", 1)[0]
    return url


def _expected_alg(jwk: dict) -> Optional[str]:
    kty = jwk.get("kty")
    if kty == "EC" and jwk.get("crv") == "P-256":
        return "ES256"
    if kty == "RSA":
        return "RS256"
    return None


def verify_dpop_proof(
    proof_jwt: str,
    token_cnf_jkt: str,
    htm: str,
    htu: str,
    *,
    access_token: Optional[str] = None,
    expected_nonce: Optional[str] = None,
    iat_window_secs: int = 300,
    now: Optional[Callable[[], float]] = None,
) -> DPoPResult:
    """校验一个 DPoP proof(RFC 9449 §4.3)。成功返回 DPoPResult;失败 raise VerifyError。

    - `token_cnf_jkt`:access token 的 `cnf.jkt`(RS 从已验签 token 取);proof 公钥 thumbprint MUST 等它。
    - `htm`/`htu`:本次请求方法/URL(htu 内部规范化去 query/fragment)。
    - `access_token`:若提供,校 proof.ath == SHA256(access_token)(防 proof 换绑)。
    - `expected_nonce`:若服务端下发 nonce,MUST 匹配。
    - `iat_window_secs`:iat 接受窗口(默认 5min)。
    """
    now_fn = now or time.time
    # 1. header:typ + alg + 内嵌 jwk。
    try:
        header = jwt.get_unverified_header(proof_jwt)
    except Exception as e:  # noqa: BLE001
        raise VerifyError("invalid_token", f"DPoP proof header 非法: {e}")
    if header.get("typ") != "dpop+jwt":
        raise VerifyError("invalid_token", "DPoP proof typ 必须 dpop+jwt")
    alg = header.get("alg")
    if not alg or alg == "none":
        raise VerifyError("invalid_token", "DPoP proof alg:none 一律拒")
    jwk = header.get("jwk")
    if not isinstance(jwk, dict):
        raise VerifyError("invalid_token", "DPoP proof 缺内嵌 jwk")
    # 私钥字段绝不该出现在 proof 的 jwk(只该是公钥);出现即拒(防误信私钥材料)。
    if any(k in jwk for k in ("d", "p", "q", "dp", "dq", "qi")):
        raise VerifyError("invalid_token", "DPoP jwk 含私钥字段(必须只含公钥)")
    want = _expected_alg(jwk)
    if want is None:
        raise VerifyError("invalid_token", f"DPoP jwk 不支持的类型: {jwk.get('kty')}")
    if alg != want:
        raise VerifyError("invalid_token", f"DPoP alg {alg} 与 jwk 类型(应 {want})不符(防 alg 混淆)")

    # 2. 签名:用内嵌 jwk 自验。
    try:
        key = PyJWK.from_dict(jwk).key
        claims = jwt.decode(
            proof_jwt,
            key=key,
            algorithms=[want],
            options={"require": ["iat", "jti", "htm", "htu"], "verify_aud": False},
        )
    except Exception as e:  # noqa: BLE001
        raise VerifyError("invalid_token", f"DPoP proof 签名/必需 claim 校验失败: {e}")

    # 3. jkt 匹配 token.cnf.jkt(sender-constraint 核心)。
    jkt = compute_jkt(jwk)
    if jkt != token_cnf_jkt:
        raise VerifyError("invalid_token", "DPoP proof jkt 不匹配 token cnf.jkt(sender-constraint)")

    # 4. htm/htu。
    if claims.get("htm") != htm:
        raise VerifyError("invalid_token", "DPoP htm 不匹配请求方法")
    if normalize_htu(str(claims.get("htu", ""))) != normalize_htu(htu):
        raise VerifyError("invalid_token", "DPoP htu 不匹配请求 URL")

    # 5. iat 新鲜度(窗口内)。
    iat = claims.get("iat")
    if not isinstance(iat, (int, float)):
        raise VerifyError("invalid_token", "DPoP proof iat 非法")
    if abs(now_fn() - iat) > iat_window_secs:
        raise VerifyError("invalid_token", "DPoP proof iat 超出接受窗口(陈旧/时钟偏差)")

    # 6. ath(若提供 access_token)。
    if access_token is not None:
        expected_ath = compute_ath(access_token)
        if claims.get("ath") != expected_ath:
            raise VerifyError("invalid_token", "DPoP ath 不匹配 access token(防 proof 换绑)")

    # 7. nonce(若服务端下发)。
    if expected_nonce is not None and claims.get("nonce") != expected_nonce:
        raise VerifyError("invalid_token", "DPoP nonce 不匹配")

    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti:
        raise VerifyError("invalid_token", "DPoP proof 缺 jti")
    return DPoPResult(jkt=jkt, jti=jti, iat=int(iat))
