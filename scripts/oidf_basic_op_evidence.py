#!/usr/bin/env python3
"""Convert an official OIDF Basic OP plan export into release-gate evidence."""

import argparse
import base64
import json
import urllib.parse
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

EXPECTED_PLAN = "oidcc-basic-certification-test-plan"
EXPECTED_VARIANTS = {
    "server_metadata": "discovery",
    "client_registration": "dynamic_client",
}
CLEANUP_CONDITION = "UnregisterDynamicallyRegisteredClient"
REGISTRATION_CALL_CONDITION = "CallDynamicRegistrationEndpoint"
CLEANUP_NOT_REQUIRED_MESSAGE = (
    "Skipped evaluation due to missing required object: client"
)


def load_object(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise TypeError(f"{path} must contain a JSON object")
    return value


def variant_map(value: Any) -> dict[str, str]:
    if isinstance(value, dict) and isinstance(value.get("variant"), dict):
        value = value["variant"]
    if not isinstance(value, dict):
        raise TypeError("OIDF variant must be an object")
    if not all(
        isinstance(key, str) and isinstance(item, str) for key, item in value.items()
    ):
        raise ValueError("OIDF variant keys and values must be strings")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def stable_test_id(name: str, variant: dict[str, str]) -> str:
    suffix = "".join(f"[{key}={variant[key]}]" for key in sorted(variant))
    return f"{name}{suffix}"


def suite_base_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    require(parsed.scheme == "https", "OIDF exportedFrom must be HTTPS")
    require(
        parsed.hostname is not None
        and parsed.username is None
        and parsed.password is None,
        "OIDF exportedFrom must contain a valid host without userinfo",
    )
    try:
        _ = parsed.port
    except ValueError as error:
        raise ValueError("OIDF exportedFrom contains an invalid port") from error
    require(
        parsed.path in {"", "/"} and not parsed.query and not parsed.fragment,
        "OIDF exportedFrom must be an HTTPS origin",
    )
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))


def decode_base64url(value: str, label: str) -> bytes:
    try:
        encoded = value.encode("ascii")
        encoded += b"=" * (-len(encoded) % 4)
        return base64.b64decode(encoded, altchars=b"-_", validate=True)
    except (UnicodeEncodeError, ValueError) as error:
        raise ValueError(f"{label} is not valid base64url") from error


def load_signing_keys(path: Path) -> list[tuple[str, rsa.RSAPublicKey]]:
    jwks = load_object(path)
    keys = jwks.get("keys")
    require(isinstance(keys, list), "OIDF export JWKS keys must be an array")
    signing_keys: list[tuple[str, rsa.RSAPublicKey]] = []
    for index, key in enumerate(keys):
        require(
            isinstance(key, dict), f"OIDF export JWKS key {index} must be an object"
        )
        if (
            key.get("kty") != "RSA"
            or key.get("alg") not in {None, "RS256"}
            or key.get("use") not in {None, "sig"}
        ):
            continue
        kid = key.get("kid")
        modulus = key.get("n")
        exponent = key.get("e")
        require(
            isinstance(kid, str) and bool(kid),
            f"OIDF export JWKS RSA key {index} has no kid",
        )
        require(
            isinstance(modulus, str) and isinstance(exponent, str),
            f"OIDF export JWKS RSA key {kid} omits n or e",
        )
        public_numbers = rsa.RSAPublicNumbers(
            int.from_bytes(decode_base64url(exponent, f"OIDF JWK {kid} e"), "big"),
            int.from_bytes(decode_base64url(modulus, f"OIDF JWK {kid} n"), "big"),
        )
        try:
            signing_keys.append((kid, public_numbers.public_key()))
        except ValueError as error:
            raise ValueError(f"OIDF export JWKS RSA key {kid} is invalid") from error
    require(bool(signing_keys), "OIDF export JWKS contains no RS256 signing key")
    require(
        len({kid for kid, _key in signing_keys}) == len(signing_keys),
        "OIDF export JWKS contains duplicate signing key ids",
    )
    return signing_keys


def verify_signature(
    payload: bytes,
    encoded_signature: bytes,
    signing_keys: list[tuple[str, rsa.RSAPublicKey]],
    member: str,
) -> str:
    try:
        signature_text = encoded_signature.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise ValueError(f"{member} signature is not ASCII") from error
    signature = decode_base64url(signature_text, f"{member} signature")
    for kid, key in signing_keys:
        try:
            key.verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
            return kid
        except InvalidSignature:
            continue
    raise ValueError(f"{member} signature does not verify with the OIDF JWKS")


def safe_member(name: str) -> bool:
    path = PurePosixPath(name)
    return not path.is_absolute() and ".." not in path.parts and "\\" not in name


def read_exports(
    path: Path,
    signing_keys: list[tuple[str, rsa.RSAPublicKey]],
) -> list[tuple[dict[str, Any], str]]:
    exports: list[tuple[dict[str, Any], str]] = []
    with zipfile.ZipFile(path) as archive:
        names = [name for name in archive.namelist() if not name.endswith("/")]
        require(len(names) == len(set(names)), "OIDF export contains duplicate members")
        require(
            all(safe_member(name) for name in names),
            "OIDF export contains an unsafe member path",
        )
        json_names = {name for name in names if name.endswith(".json")}
        signature_names = {name for name in names if name.endswith(".sig")}
        require(
            set(names) == json_names | signature_names,
            "OIDF export contains an unexpected member type",
        )
        used_signatures: set[str] = set()
        for name in sorted(json_names):
            payload = archive.read(name)
            signature_name = f"{name.removesuffix('.json')}.sig"
            require(
                signature_name in signature_names,
                f"{name} has no matching OIDF signature member",
            )
            signature_kid = verify_signature(
                payload,
                archive.read(signature_name),
                signing_keys,
                name,
            )
            used_signatures.add(signature_name)
            value = json.loads(payload)
            if not isinstance(value, dict):
                raise TypeError(f"{name} must contain a JSON object")
            if "testInfo" in value:
                exports.append((value, signature_kid))
        require(
            used_signatures == signature_names,
            "OIDF export contains an orphan signature member",
        )
    require(bool(exports), "OIDF export contains no test JSON records")
    return exports


def cleanup_result_shape(entry: dict[str, Any]) -> str:
    if "result" not in entry:
        return "missing"
    value = entry["result"]
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "nonempty-string" if value else "empty-string"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unknown"


def cleanup_not_required(
    results: list[dict[str, Any]],
    cleanup_entries: list[dict[str, Any]],
) -> bool:
    if len(cleanup_entries) != 1:
        return False
    cleanup = cleanup_entries[0]
    return (
        cleanup.get("result") == "INFO"
        and cleanup.get("msg") == CLEANUP_NOT_REQUIRED_MESSAGE
        and cleanup.get("expected") == "client"
        and "mapped" in cleanup
        and cleanup["mapped"] is None
        and not any(
            entry.get("src") == REGISTRATION_CALL_CONDITION for entry in results
        )
    )


def dynamic_client_cleanup(export: dict[str, Any], instance_id: str) -> tuple[str, int]:
    results = export.get("results")
    require(
        isinstance(results, list),
        f"OIDF export {instance_id} results must be an array",
    )
    require(
        all(isinstance(entry, dict) for entry in results),
        f"OIDF export {instance_id} results must contain objects",
    )
    cleanup_entries = [
        entry for entry in results if entry.get("src") == CLEANUP_CONDITION
    ]
    require(
        bool(cleanup_entries),
        f"OIDF export {instance_id} has no dynamic-client cleanup result",
    )
    result_shapes = [cleanup_result_shape(entry) for entry in cleanup_entries]
    require(
        all(shape in {"missing", "nonempty-string"} for shape in result_shapes),
        (
            f"OIDF export {instance_id} has a malformed dynamic-client cleanup result "
            f"(cleanup entries={len(cleanup_entries)}; "
            f"result shapes=[{', '.join(result_shapes)}])"
        ),
    )
    if cleanup_not_required(results, cleanup_entries):
        return "not_required", 0
    cleanup_results = [
        entry["result"]
        for entry, shape in zip(cleanup_entries, result_shapes, strict=True)
        if shape == "nonempty-string"
    ]
    if not cleanup_results:
        return "failed", 0
    if all(result == "SUCCESS" for result in cleanup_results):
        return "passed", len(cleanup_results)
    return "failed", len(cleanup_results)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--export", required=True, type=Path)
    parser.add_argument("--plan-info", required=True, type=Path)
    parser.add_argument("--jwks", required=True, type=Path)
    parser.add_argument("--expected-origin", required=True)
    parser.add_argument("--runner-ref", required=True)
    parser.add_argument("--runner-commit", required=True)
    parser.add_argument("--runner-exit-code", required=True, type=int)
    parser.add_argument("--source-url", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    try:
        plan = load_object(args.plan_info)
        require(plan.get("planName") == EXPECTED_PLAN, "unexpected OIDF plan name")
        plan_id = plan.get("_id") or plan.get("id")
        require(isinstance(plan_id, str) and bool(plan_id), "OIDF plan id is missing")
        plan_variants = variant_map(plan.get("variant"))
        require(
            plan_variants == EXPECTED_VARIANTS,
            "OIDF plan variants are not discovery + dynamic_client",
        )
        expected_origin = suite_base_url(args.expected_origin)
        signing_keys = load_signing_keys(args.jwks)

        modules = plan.get("modules")
        require(
            isinstance(modules, list) and bool(modules), "OIDF plan modules are missing"
        )
        expected_instances: dict[str, tuple[str, dict[str, str]]] = {}
        for module in modules:
            require(isinstance(module, dict), "OIDF plan module must be an object")
            name = module.get("testModule")
            instances = module.get("instances")
            require(isinstance(name, str) and bool(name), "OIDF module name is missing")
            require(
                isinstance(instances, list) and bool(instances),
                f"OIDF module {name} has no executed instance",
            )
            instance_id = instances[-1]
            require(
                isinstance(instance_id, str) and bool(instance_id),
                f"OIDF module {name} latest instance is invalid",
            )
            require(
                instance_id not in expected_instances,
                f"duplicate OIDF instance id {instance_id}",
            )
            module_variant = variant_map(module.get("variant") or {})
            expected_instances[instance_id] = (name, module_variant)

        exports = read_exports(args.export, signing_keys)
        by_instance: dict[str, tuple[dict[str, Any], str]] = {}
        versions: set[str] = set()
        exported_from: set[str] = set()
        for export, signature_kid in exports:
            info = export.get("testInfo")
            require(isinstance(info, dict), "OIDF testInfo must be an object")
            instance_id = info.get("testId") or info.get("_id")
            require(
                isinstance(instance_id, str) and bool(instance_id),
                "OIDF exported test id is missing",
            )
            require(
                instance_id not in by_instance, f"duplicate export for {instance_id}"
            )
            by_instance[instance_id] = (export, signature_kid)
            version = export.get("exportedVersion")
            origin = export.get("exportedFrom")
            require(
                isinstance(version, str) and bool(version),
                f"OIDF export {instance_id} has no exportedVersion",
            )
            require(
                isinstance(origin, str) and bool(origin),
                f"OIDF export {instance_id} has no exportedFrom",
            )
            versions.add(version)
            exported_from.add(suite_base_url(origin))

        require(len(versions) == 1, "OIDF exports contain mixed suite versions")
        require(len(exported_from) == 1, "OIDF exports contain mixed suite origins")
        require(
            next(iter(exported_from)) == expected_origin,
            "OIDF exportedFrom does not match the trusted suite origin",
        )
        missing = sorted(set(expected_instances) - set(by_instance))
        extra = sorted(set(by_instance) - set(expected_instances))
        require(not missing, f"OIDF export omits plan instances: {missing}")
        require(not extra, f"OIDF export includes instances outside the plan: {extra}")

        origin = next(iter(exported_from))
        tests = []
        for instance_id, (module_name, module_variant) in expected_instances.items():
            export, signature_kid = by_instance[instance_id]
            info = export["testInfo"]
            require(
                info.get("planId") == plan_id, f"{instance_id} has the wrong planId"
            )
            require(
                info.get("testName") == module_name,
                f"{instance_id} testName does not match the plan module",
            )
            test_variants = variant_map(info.get("variant"))
            expected_test_variants = {**plan_variants, **module_variant}
            require(
                all(
                    test_variants.get(key) == value
                    for key, value in expected_test_variants.items()
                ),
                f"{instance_id} did not run with the expected module variants",
            )
            upstream_status = info.get("status")
            upstream_result = info.get("result") or "UNKNOWN"
            if upstream_status == "FINISHED" and upstream_result == "PASSED":
                status = "passed"
            elif upstream_status == "FINISHED" and upstream_result in {
                "FAILED",
                "REVIEW",
                "WARNING",
                "SKIPPED",
            }:
                status = "failed"
            else:
                status = "error"
            cleanup_status, cleanup_attempts = dynamic_client_cleanup(
                export,
                instance_id,
            )
            require(
                not (
                    cleanup_status == "not_required"
                    and upstream_status == "FINISHED"
                    and upstream_result == "PASSED"
                ),
                f"OIDF export {instance_id} passed without dynamic-client cleanup",
            )
            if cleanup_status != "passed" and status == "passed":
                status = "failed"
            test = {
                "id": stable_test_id(module_name, module_variant),
                "instance_id": instance_id,
                "status": status,
                "required": True,
                "upstream_status": upstream_status,
                "upstream_result": upstream_result,
                "dynamic_client_cleanup": cleanup_status,
                "dynamic_client_cleanup_attempts": cleanup_attempts,
                "signature_key_id": signature_kid,
                "log_url": f"{origin}log-detail.html?log={instance_id}",
            }
            if cleanup_status == "failed":
                test["waivable"] = False
            tests.append(test)

        suite = {
            "id": "oidf-basic-op-code",
            "kind": "oidf-plan",
            "version": next(iter(versions)),
            "source_url": args.source_url,
            "result_url": f"{origin}plan-detail.html?plan={plan_id}",
            "metadata_and_runtime": True,
            "plan": {
                "id": plan_id,
                "name": EXPECTED_PLAN,
                "variants": EXPECTED_VARIANTS,
                "module_count": len(modules),
                "runner_ref": args.runner_ref,
                "runner_commit": args.runner_commit,
                "runner_exit_code": args.runner_exit_code,
                "export_origin": origin,
                "signatures_verified": True,
            },
            "tests": tests,
        }
        args.output.write_text(json.dumps(suite, indent=2) + "\n", encoding="utf-8")
        return 0
    except (
        json.JSONDecodeError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
        zipfile.BadZipFile,
    ) as error:
        args.output.write_text(
            json.dumps(
                {
                    "id": "oidf-basic-op-code",
                    "kind": "oidf-plan",
                    "conversion_error": str(error),
                    "tests": [],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
