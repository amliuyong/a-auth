"""spec 010 §5.2 / C8.9:RS SDK DPoP(RFC 9449)proof 校验。EC P-256 proof,离线构造。"""

from __future__ import annotations

import base64
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

from agent_auth_rs import compute_ath, compute_jkt, normalize_htu, verify_dpop_proof
from agent_auth_rs.types import VerifyError

HTU = "https://rs.example.com/api/data"
HTM = "POST"


def _keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    jwk = json.loads(ECAlgorithm(ECAlgorithm.SHA256).to_jwk(priv.public_key()))
    # 只保留公钥字段(to_jwk 只导出公钥,确保无 d)。
    jwk = {"kty": jwk["kty"], "crv": jwk["crv"], "x": jwk["x"], "y": jwk["y"]}
    return priv, jwk


def _make_proof(
    priv,
    jwk,
    *,
    htm=HTM,
    htu=HTU,
    iat=None,
    jti="jti-1",
    ath=None,
    nonce=None,
    typ="dpop+jwt",
    alg="ES256",
    omit=(),
):
    payload = {"htm": htm, "htu": htu, "iat": int(iat if iat is not None else time.time()), "jti": jti}
    if ath is not None:
        payload["ath"] = ath
    if nonce is not None:
        payload["nonce"] = nonce
    for claim in omit:
        payload.pop(claim, None)
    headers = {"typ": typ, "alg": alg, "jwk": jwk}
    return jwt.encode(payload, priv, algorithm="ES256", headers=headers)


def test_valid_proof():
    priv, jwk = _keypair()
    jkt = compute_jkt(jwk)
    proof = _make_proof(priv, jwk)
    r = verify_dpop_proof(proof, jkt, HTM, HTU)
    assert r.jkt == jkt
    assert r.jti == "jti-1"


def test_jkt_mismatch_rejected():
    priv, jwk = _keypair()
    proof = _make_proof(priv, jwk)
    # token 的 cnf.jkt 是别的 key 的 thumbprint。
    _, other_jwk = _keypair()
    other_jkt = compute_jkt(other_jwk)
    try:
        verify_dpop_proof(proof, other_jkt, HTM, HTU)
        assert False, "jkt 不匹配应拒"
    except VerifyError as e:
        assert "cnf.jkt" in e.detail or "sender-constraint" in e.detail


def test_htu_mismatch_rejected():
    priv, jwk = _keypair()
    jkt = compute_jkt(jwk)
    proof = _make_proof(priv, jwk, htu="https://rs.example.com/other")
    try:
        verify_dpop_proof(proof, jkt, HTM, HTU)
        assert False, "htu 不匹配应拒"
    except VerifyError as e:
        assert "htu" in e.detail


def test_htm_mismatch_rejected():
    priv, jwk = _keypair()
    jkt = compute_jkt(jwk)
    proof = _make_proof(priv, jwk, htm="GET")
    try:
        verify_dpop_proof(proof, jkt, "POST", HTU)
        assert False, "htm 不匹配应拒"
    except VerifyError as e:
        assert "htm" in e.detail


def test_htu_normalization_ignores_query_fragment():
    # proof htu 带 query/fragment,请求 htu 不带 → 规范化后相等,放行。
    priv, jwk = _keypair()
    jkt = compute_jkt(jwk)
    proof = _make_proof(priv, jwk, htu=HTU + "?a=1#frag")
    r = verify_dpop_proof(proof, jkt, HTM, HTU)
    assert r.jkt == jkt
    # normalize_htu 单元验证。
    assert normalize_htu("https://x/a?q=1#f") == "https://x/a"


def test_typ_must_be_dpop_jwt():
    priv, jwk = _keypair()
    jkt = compute_jkt(jwk)
    proof = _make_proof(priv, jwk, typ="JWT")
    try:
        verify_dpop_proof(proof, jkt, HTM, HTU)
        assert False, "typ!=dpop+jwt 应拒"
    except VerifyError as e:
        assert "dpop+jwt" in e.detail


def test_stale_iat_rejected():
    priv, jwk = _keypair()
    jkt = compute_jkt(jwk)
    proof = _make_proof(priv, jwk, iat=time.time() - 10_000)  # 远超 5min 窗口
    try:
        verify_dpop_proof(proof, jkt, HTM, HTU)
        assert False, "陈旧 iat 应拒"
    except VerifyError as e:
        assert "iat" in e.detail


def test_ath_binding():
    priv, jwk = _keypair()
    jkt = compute_jkt(jwk)
    access = "the-access-token-value"
    # 正确 ath → 通过。
    proof_ok = _make_proof(priv, jwk, ath=compute_ath(access))
    r = verify_dpop_proof(proof_ok, jkt, HTM, HTU, access_token=access)
    assert r.jkt == jkt
    # 错 ath → 拒(proof 换绑到别的 token)。
    proof_bad = _make_proof(priv, jwk, ath=compute_ath("different-token"))
    try:
        verify_dpop_proof(proof_bad, jkt, HTM, HTU, access_token=access)
        assert False, "ath 不匹配应拒"
    except VerifyError as e:
        assert "ath" in e.detail


def test_nonce_required_when_expected():
    priv, jwk = _keypair()
    jkt = compute_jkt(jwk)
    # 期望 nonce 但 proof 没带 → 拒。
    proof = _make_proof(priv, jwk)
    try:
        verify_dpop_proof(proof, jkt, HTM, HTU, expected_nonce="server-nonce")
        assert False, "缺 nonce 应拒"
    except VerifyError as e:
        assert "nonce" in e.detail
    # 带正确 nonce → 通过。
    proof_ok = _make_proof(priv, jwk, nonce="server-nonce")
    r = verify_dpop_proof(proof_ok, jkt, HTM, HTU, expected_nonce="server-nonce")
    assert r.jkt == jkt


def test_jwk_with_private_key_field_rejected():
    # proof 的 jwk 含私钥字段 d → 拒(必须只含公钥)。
    priv, jwk = _keypair()
    jwk_with_d = dict(jwk)
    jwk_with_d["d"] = "should-not-be-here"
    proof = _make_proof(priv, jwk_with_d)
    jkt = compute_jkt(jwk)
    try:
        verify_dpop_proof(proof, jkt, HTM, HTU)
        assert False, "jwk 含私钥字段应拒"
    except VerifyError as e:
        assert "私钥" in e.detail


def test_compute_jkt_rfc7638_ec_deterministic():
    # 同一 jwk 计算 jkt 决定性(字段顺序无关)。
    _, jwk = _keypair()
    jkt1 = compute_jkt({"kty": jwk["kty"], "crv": jwk["crv"], "x": jwk["x"], "y": jwk["y"]})
    jkt2 = compute_jkt({"y": jwk["y"], "x": jwk["x"], "crv": jwk["crv"], "kty": jwk["kty"]})
    assert jkt1 == jkt2, "jkt 计算须字段顺序无关(RFC 7638 规范化)"


def test_c8_9_dpop_proof_binds_request_token_and_nonce():
    priv, jwk = _keypair()
    jkt = compute_jkt(jwk)
    access_token = "signed-access-token"
    proof = _make_proof(
        priv,
        jwk,
        htu=HTU + "?proof=1#fragment",
        ath=compute_ath(access_token),
        nonce="server-nonce",
        jti="exact-proof",
    )
    result = verify_dpop_proof(
        proof,
        jkt,
        HTM,
        HTU + "?request=2",
        access_token=access_token,
        expected_nonce="server-nonce",
    )
    assert result.jkt == jkt
    assert result.jti == "exact-proof"

    _, other_jwk = _keypair()
    with pytest.raises(VerifyError):
        verify_dpop_proof(proof, compute_jkt(other_jwk), HTM, HTU)

    wrong_htu = _make_proof(priv, jwk, htu="https://rs.example.com/other")
    with pytest.raises(VerifyError, match="htu"):
        verify_dpop_proof(wrong_htu, jkt, HTM, HTU)

    wrong_htm = _make_proof(priv, jwk, htm="GET")
    with pytest.raises(VerifyError, match="htm"):
        verify_dpop_proof(wrong_htm, jkt, HTM, HTU)

    stale = _make_proof(priv, jwk, iat=time.time() - 301)
    with pytest.raises(VerifyError, match="iat"):
        verify_dpop_proof(stale, jkt, HTM, HTU, iat_window_secs=300)

    future = _make_proof(priv, jwk, iat=time.time() + 301)
    with pytest.raises(VerifyError, match="iat"):
        verify_dpop_proof(future, jkt, HTM, HTU, iat_window_secs=300)

    for missing_claim in ("htu", "htm", "iat"):
        missing = _make_proof(priv, jwk, omit=(missing_claim,))
        with pytest.raises(VerifyError):
            verify_dpop_proof(missing, jkt, HTM, HTU)

    missing_ath = _make_proof(priv, jwk)
    with pytest.raises(VerifyError, match="ath"):
        verify_dpop_proof(missing_ath, jkt, HTM, HTU, access_token=access_token)

    wrong_ath = _make_proof(priv, jwk, ath=compute_ath("other-token"))
    with pytest.raises(VerifyError, match="ath"):
        verify_dpop_proof(wrong_ath, jkt, HTM, HTU, access_token=access_token)

    missing_nonce = _make_proof(priv, jwk)
    with pytest.raises(VerifyError, match="nonce"):
        verify_dpop_proof(missing_nonce, jkt, HTM, HTU, expected_nonce="server-nonce")

    wrong_nonce = _make_proof(priv, jwk, nonce="other-nonce")
    with pytest.raises(VerifyError, match="nonce"):
        verify_dpop_proof(wrong_nonce, jkt, HTM, HTU, expected_nonce="server-nonce")

    for private_field in ("d", "p", "q", "dp", "dq", "qi"):
        private_jwk = {**jwk, private_field: "private-material-must-not-appear"}
        private_jwk_proof = _make_proof(priv, private_jwk)
        with pytest.raises(VerifyError, match="私钥"):
            verify_dpop_proof(private_jwk_proof, jkt, HTM, HTU)

    parts = proof.split(".")
    signature = bytearray(base64.urlsafe_b64decode(parts[2] + "=="))
    signature[0] ^= 0x80
    parts[2] = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    with pytest.raises(VerifyError, match="签名"):
        verify_dpop_proof(".".join(parts), jkt, HTM, HTU)
