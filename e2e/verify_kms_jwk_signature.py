#!/usr/bin/env python3
import argparse
import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


def decode_base64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--algorithm", required=True)
    parser.add_argument("--jwk", required=True)
    signature = parser.add_mutually_exclusive_group(required=True)
    signature.add_argument("--signature")
    signature.add_argument("--signature-base64url")
    parser.add_argument(
        "--signature-format",
        choices=("der", "jose"),
        default="der",
        help="EC signature encoding; RSA signatures are always raw",
    )
    parser.add_argument("--message", required=True)
    parser.add_argument("--expected-issuer")
    parser.add_argument("--expected-subject")
    parser.add_argument("--expected-jws-alg")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    jwk = json.loads(Path(args.jwk).read_text())
    signature = (
        Path(args.signature).read_bytes()
        if args.signature
        else decode_base64url(args.signature_base64url)
    )
    message = Path(args.message).read_bytes()

    expected_jws = (
        args.expected_issuer,
        args.expected_subject,
        args.expected_jws_alg,
    )
    if any(value is not None for value in expected_jws):
        if not all(value is not None for value in expected_jws):
            raise ValueError("all expected JWS fields must be provided together")
        parts = message.decode("ascii").split(".")
        if len(parts) != 2:
            raise ValueError("expected a JWS signing input")
        header = json.loads(decode_base64url(parts[0]))
        claims = json.loads(decode_base64url(parts[1]))
        if (
            header.get("alg") != args.expected_jws_alg
            or header.get("kid") != jwk.get("kid")
            or claims.get("iss") != args.expected_issuer
            or claims.get("sub") != args.expected_subject
            or claims.get("aud") != f"{args.expected_issuer}/dr-probe"
        ):
            raise ValueError("JWS header or claims are not bound to the expected issuer")

    if args.algorithm == "ECDSA_SHA_256":
        if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
            raise ValueError("expected a P-256 EC JWK")
        if args.signature_format == "jose":
            if len(signature) != 64:
                raise ValueError("expected a 64-byte ES256 JOSE signature")
            signature = encode_dss_signature(
                int.from_bytes(signature[:32], "big"),
                int.from_bytes(signature[32:], "big"),
            )
        public_key = ec.EllipticCurvePublicNumbers(
            int.from_bytes(decode_base64url(jwk["x"]), "big"),
            int.from_bytes(decode_base64url(jwk["y"]), "big"),
            ec.SECP256R1(),
        ).public_key()
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    elif args.algorithm == "RSASSA_PKCS1_V1_5_SHA_256":
        if jwk.get("kty") != "RSA":
            raise ValueError("expected an RSA JWK")
        public_key = rsa.RSAPublicNumbers(
            int.from_bytes(decode_base64url(jwk["e"]), "big"),
            int.from_bytes(decode_base64url(jwk["n"]), "big"),
        ).public_key()
        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    else:
        raise ValueError(f"unsupported signing algorithm: {args.algorithm}")


if __name__ == "__main__":
    main()
