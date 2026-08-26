#!/usr/bin/env python3
"""P-1 spike 独立验签器:用 PyJWT + cryptography(与签发方无共享代码)验证
KMS ES256 Sign → infra-core der_to_jose 转换 → 组装的 JWT 能被标准 JOSE 验签器接受。

这是 P0 gate 的密码学判定:独立第三方验签通过 = DER→JOSE 转换对真实 KMS 输出成立、
第三方 RS(硬编码 ES256/标准库)不会拒签我们的 token。
"""
import sys
import jwt  # PyJWT
from cryptography.hazmat.primitives.serialization import load_der_public_key

JWT_PATH = "/tmp/spike_jwt.txt"
PUBKEY_DER_PATH = "/tmp/spike_pubkey.der"


def main() -> int:
    with open(JWT_PATH) as f:
        token = f.read().strip()
    with open(PUBKEY_DER_PATH, "rb") as f:
        spki_der = f.read()

    # KMS GetPublicKey 返回 SPKI(SubjectPublicKeyInfo)DER;cryptography 直接载入。
    pub = load_der_public_key(spki_der)

    try:
        claims = jwt.decode(
            token,
            key=pub,
            algorithms=["ES256"],
            audience="https://mcp.rs.example.com",
            options={"verify_exp": False},  # spike 用固定时间戳,不验 exp
        )
    except Exception as e:  # noqa: BLE001
        print(f"❌ 独立验签失败: {type(e).__name__}: {e}")
        print("   → DER→JOSE 转换或签名链有问题,P0 gate 未通过")
        return 1

    print("✅ 独立验签通过(PyJWT/ES256)——DER→JOSE 转换对真实 KMS 输出成立")
    print(f"   验出 claims: iss={claims.get('iss')} sub={claims.get('sub')} aud={claims.get('aud')}")

    # 负例:篡改签名最后一字符应被拒(证明验签真在校验、非恒真)。
    parts = token.split(".")
    tampered_sig = parts[2][:-1] + ("A" if parts[2][-1] != "A" else "B")
    tampered = f"{parts[0]}.{parts[1]}.{tampered_sig}"
    try:
        jwt.decode(tampered, key=pub, algorithms=["ES256"],
                   audience="https://mcp.rs.example.com", options={"verify_exp": False})
        print("❌ 篡改签名竟通过验签——验签器失效,gate 不可信")
        return 1
    except Exception:  # noqa: BLE001
        print("✅ 篡改签名被拒(验签器确在校验)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
