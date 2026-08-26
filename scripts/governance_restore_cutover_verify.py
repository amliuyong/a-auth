#!/usr/bin/env python3
"""Fail-closed verifier for governance-aware restore cutover candidates."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import pathlib
import struct
import sys
from collections.abc import Iterable
from typing import Any

SCHEMA_VERSION = 1
NORMALIZATION_VERSION = 1
REQUIRED_ROLES = {
    "admin_auth",
    "clients",
    "domain_map",
    "federation_config",
    "grants",
    "passkeys",
    "password_credentials",
    "scim_groups",
    "security_events",
    "tenant_keys",
    "users",
    "workload_trust",
}
RETAINED_ROLES = {"security_events"}
JSON_ATTRIBUTES = {"grant_json", "record", "record_json"}
TENANT_ATTRIBUTES = {"tenant", "tenant_id"}
TENANT_PREFIX_ATTRIBUTES = {
    "binding_id",
    "client_id",
    "credential_id",
    "email",
    "grant_id",
    "pk",
    "tenant_kind",
    "user_id",
}


class VerificationError(ValueError):
    """A cutover candidate cannot be proven safe."""


def _load_json(path: pathlib.Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise VerificationError(f"invalid JSON input: {path.name}") from error


def _resolve(manifest_path: pathlib.Path, value: object) -> pathlib.Path:
    if not isinstance(value, str) or not value:
        raise VerificationError("manifest contains an invalid scan path")
    path = pathlib.Path(value)
    return path if path.is_absolute() else manifest_path.parent / path


def _scan_items(path: pathlib.Path) -> list[dict[str, Any]]:
    scan = _load_json(path)
    if not isinstance(scan, dict) or not isinstance(scan.get("Items"), list):
        raise VerificationError(f"invalid DynamoDB scan: {path.name}")
    if scan.get("LastEvaluatedKey"):
        raise VerificationError(f"incomplete DynamoDB scan: {path.name}")
    items = scan["Items"]
    if not all(isinstance(item, dict) for item in items):
        raise VerificationError(f"invalid DynamoDB items: {path.name}")
    return items


def _attribute_string(item: dict[str, Any], name: str) -> str | None:
    value = item.get(name)
    if value is None:
        return None
    if (
        not isinstance(value, dict)
        or set(value) != {"S"}
        or not isinstance(value["S"], str)
    ):
        raise VerificationError(f"attribute {name} is not a DynamoDB string")
    return value["S"]


def _attribute_number(item: dict[str, Any], name: str) -> int | None:
    value = item.get(name)
    if value is None:
        return None
    if (
        not isinstance(value, dict)
        or set(value) != {"N"}
        or not isinstance(value["N"], str)
    ):
        raise VerificationError(f"attribute {name} is not a DynamoDB number")
    try:
        return int(value["N"])
    except ValueError as error:
        raise VerificationError(f"attribute {name} is not an integer") from error


def _attribute_strings(item: dict[str, Any], name: str) -> list[str]:
    value = item.get(name)
    if value is None:
        return []
    if not isinstance(value, dict) or len(value) != 1:
        raise VerificationError(f"attribute {name} has an invalid DynamoDB value")
    if "S" in value and isinstance(value["S"], str):
        return [value["S"]]
    if (
        "SS" in value
        and isinstance(value["SS"], list)
        and all(isinstance(entry, str) for entry in value["SS"])
    ):
        return list(value["SS"])
    if "L" in value and isinstance(value["L"], list):
        result = []
        for entry in value["L"]:
            if not isinstance(entry, dict) or set(entry) != {"S"}:
                raise VerificationError(
                    f"attribute {name} contains a non-string member"
                )
            result.append(entry["S"])
        return result
    raise VerificationError(f"attribute {name} is not a DynamoDB string collection")


def _plain_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for entry in value:
            yield from _plain_strings(entry)
    elif isinstance(value, dict):
        for entry in value.values():
            yield from _plain_strings(entry)


def _dynamo_strings(value: Any) -> Iterable[str]:
    if not isinstance(value, dict) or len(value) != 1:
        return
    kind, payload = next(iter(value.items()))
    if kind == "S" and isinstance(payload, str):
        yield payload
    elif kind == "SS" and isinstance(payload, list):
        for entry in payload:
            if isinstance(entry, str):
                yield entry
    elif kind == "L" and isinstance(payload, list):
        for entry in payload:
            yield from _dynamo_strings(entry)
    elif kind == "M" and isinstance(payload, dict):
        for entry in payload.values():
            yield from _dynamo_strings(entry)


def _item_strings(item: dict[str, Any]) -> Iterable[str]:
    for name, value in item.items():
        yield from _dynamo_strings(value)
        if name in JSON_ATTRIBUTES:
            encoded = _attribute_string(item, name)
            if encoded:
                try:
                    decoded = json.loads(encoded)
                except json.JSONDecodeError as error:
                    raise VerificationError(
                        f"attribute {name} contains invalid JSON"
                    ) from error
                yield from _plain_strings(decoded)


def _suppression_digest(
    key: bytes,
    tenant_id: str,
    target_class: str,
    alias_kind: str,
    normalization_version: int,
    normalized_value: str,
) -> str:
    message = bytearray(b"governance-suppression:v1\0")
    for value in (tenant_id, target_class, alias_kind, normalized_value):
        encoded = value.encode()
        message.extend(struct.pack(">Q", len(encoded)))
        message.extend(encoded)
    message.extend(struct.pack(">I", normalization_version))
    return (
        base64.urlsafe_b64encode(hmac.digest(key, message, "sha256"))
        .rstrip(b"=")
        .decode()
    )


def _physical_identity(value: str, tenants: set[str]) -> tuple[str, str]:
    matches = [
        (tenant, value[len(tenant) + 1 :])
        for tenant in tenants
        if value.startswith(f"{tenant}\x1f")
    ]
    if len(matches) != 1 or not matches[0][1]:
        raise VerificationError("restored authority contains an unscoped identity")
    return matches[0]


def _json_tenant_claims(value: Any, tenants: set[str]) -> set[str]:
    found = set()
    if isinstance(value, dict):
        for name, entry in value.items():
            if name in TENANT_ATTRIBUTES and isinstance(entry, str):
                if entry not in tenants:
                    raise VerificationError(
                        "restored authority contains an unknown tenant"
                    )
                found.add(entry)
            found.update(_json_tenant_claims(entry, tenants))
    elif isinstance(value, list):
        for entry in value:
            found.update(_json_tenant_claims(entry, tenants))
    elif isinstance(value, str) and "\x1f" in value:
        prefix, logical = value.split("\x1f", 1)
        if not logical or prefix not in tenants:
            raise VerificationError(
                "restored authority contains an unknown tenant prefix"
            )
        found.add(prefix)
    return found


def _item_tenants(item: dict[str, Any], tenants: set[str]) -> set[str]:
    found = set()
    for name in TENANT_ATTRIBUTES:
        value = _attribute_string(item, name)
        if value:
            if value not in tenants:
                raise VerificationError("restored authority contains an unknown tenant")
            found.add(value)
    for name in TENANT_PREFIX_ATTRIBUTES:
        for value in _attribute_strings(item, name):
            if "\x1f" not in value:
                continue
            prefix, logical = value.split("\x1f", 1)
            if not logical or prefix not in tenants:
                raise VerificationError(
                    "restored authority contains an unknown tenant prefix"
                )
            found.add(prefix)
    for name in JSON_ATTRIBUTES:
        encoded = _attribute_string(item, name)
        if not encoded:
            continue
        try:
            decoded = json.loads(encoded)
        except json.JSONDecodeError as error:
            raise VerificationError(
                f"attribute {name} contains invalid JSON"
            ) from error
        found.update(_json_tenant_claims(decoded, tenants))
    return found


def _parse_suppressions(
    items: list[dict[str, Any]],
    keys: dict[int, bytes],
    configured_tenants: set[str],
) -> tuple[set[tuple[str, str, str]], set[str], set[tuple[int, int]]]:
    heads = set()
    records: set[tuple[str, str, str]] = set()
    tenants = set()
    versions = set()
    for item in items:
        pk = _attribute_string(item, "pk")
        epoch = _attribute_number(item, "epoch")
        if not pk or epoch is None or epoch < 0:
            raise VerificationError("suppression authority contains a malformed key")
        if epoch == 0:
            if _attribute_string(item, "record_type") != "suppression_head":
                raise VerificationError(
                    "suppression authority contains a malformed head"
                )
            heads.add(pk)
            continue
        encoded = _attribute_string(item, "record")
        if not encoded:
            raise VerificationError("suppression authority contains an empty epoch")
        try:
            record = json.loads(encoded)
        except json.JSONDecodeError as error:
            raise VerificationError(
                "suppression authority contains invalid JSON"
            ) from error
        required = {
            "tenant_id",
            "target_class",
            "key_version",
            "normalization_version",
            "digest",
            "target_epoch",
            "created_at",
        }
        if not isinstance(record, dict) or set(record) != required:
            raise VerificationError("suppression authority contains an unknown schema")
        tenant = record["tenant_id"]
        target_class = record["target_class"]
        key_version = record["key_version"]
        normalization_version = record["normalization_version"]
        digest = record["digest"]
        if (
            not isinstance(tenant, str)
            or not tenant
            or tenant not in configured_tenants
            or target_class not in {"tenant", "user"}
            or not isinstance(key_version, int)
            or key_version not in keys
            or normalization_version != NORMALIZATION_VERSION
            or not isinstance(digest, str)
            or not digest
            or record["target_epoch"] != epoch
            or pk != f"{tenant}\x1f{target_class}\x1f{digest}"
        ):
            raise VerificationError("suppression authority cannot be verified")
        if target_class == "tenant":
            expected = _suppression_digest(
                keys[key_version],
                tenant,
                "tenant",
                "tenant_id",
                normalization_version,
                tenant,
            )
            if not hmac.compare_digest(expected, digest):
                raise VerificationError("tenant suppression digest is invalid")
        records.add((tenant, target_class, digest))
        tenants.add(tenant)
        versions.add((key_version, normalization_version))
    missing_heads = {
        f"{tenant}\x1f{target_class}\x1f{digest}"
        for tenant, target_class, digest in records
    } - heads
    if missing_heads:
        raise VerificationError("suppression authority is missing a partition head")
    return records, tenants, versions


def _parse_lifecycles(
    items: list[dict[str, Any]],
    configured_tenants: set[str],
) -> tuple[dict[str, str], set[str]]:
    lifecycles = {}
    tenants = set()
    for item in items:
        if _attribute_string(item, "record_type") != "tenant_lifecycle":
            continue
        encoded = _attribute_string(item, "record")
        if not encoded:
            raise VerificationError("tenant lifecycle is missing its record")
        try:
            record = json.loads(encoded)
        except json.JSONDecodeError as error:
            raise VerificationError("tenant lifecycle contains invalid JSON") from error
        tenant = record.get("tenant_id") if isinstance(record, dict) else None
        state = record.get("state") if isinstance(record, dict) else None
        if (
            not isinstance(tenant, str)
            or not tenant
            or tenant not in configured_tenants
            or state not in {"active", "offboarding"}
            or _attribute_string(item, "pk") != tenant
            or _attribute_string(item, "sk") != "LIFECYCLE"
            or tenant in lifecycles
        ):
            raise VerificationError("tenant lifecycle authority is malformed")
        lifecycles[tenant] = state
        tenants.add(tenant)
    return lifecycles, tenants


def _tenant_keys_are_control_only(item: dict[str, Any], expected_tenant: str) -> bool:
    encoded = _attribute_string(item, "record_json")
    if not encoded:
        return False
    try:
        record = json.loads(encoded)
    except json.JSONDecodeError as error:
        raise VerificationError("tenant key registry contains invalid JSON") from error
    return (
        isinstance(record, dict)
        and record.get("tenant_id") == expected_tenant
        and record.get("lifecycle") == "offboarded"
        and record.get("served_snapshot") is None
        and record.get("operation") is None
        and record.get("last_failure") is None
        and isinstance(record.get("pending_deletion_arns", []), list)
        and not record.get("pending_deletion_arns", [])
        and isinstance(record.get("offboarding_operation_id"), str)
        and bool(record["offboarding_operation_id"])
    )


def _validate_retained_item(role: str, item: dict[str, Any]) -> None:
    if role == "security_events":
        event_id = _attribute_string(item, "event_id")
        tenant_id = _attribute_string(item, "tenant_id")
        if (
            not event_id
            or len(event_id) > 64
            or not all(
                character.isascii() and (character.isalnum() or character in "-_.")
                for character in event_id
            )
            or not tenant_id
            or len(tenant_id) > 63
            or not all(
                character.isascii() and (character.isalnum() or character == "-")
                for character in tenant_id
            )
        ):
            raise VerificationError(
                "restored SecurityEvents contains a malformed retained audit event"
            )
        return
    raise VerificationError("restored authority contains an unknown retained role")


def _collect_restored_inventory(
    scans: dict[str, list[dict[str, Any]]],
    tenants: set[str],
) -> tuple[
    dict[tuple[str, str], set[tuple[str, str]]],
    set[tuple[str, str]],
    dict[str, dict[str, int]],
]:
    aliases: dict[tuple[str, str], set[tuple[str, str]]] = {}
    references: set[tuple[str, str]] = set()
    live_counts = {tenant: {} for tenant in tenants}

    for role, items in scans.items():
        for item in items:
            if role in RETAINED_ROLES:
                _validate_retained_item(role, item)
                continue
            item_tenants = _item_tenants(item, tenants)
            if len(item_tenants) != 1:
                raise VerificationError(
                    "restored authority contains mixed or unscoped tenant identity"
                )
            for tenant in item_tenants:
                if role == "tenant_keys" and _tenant_keys_are_control_only(
                    item, tenant
                ):
                    continue
                live_counts[tenant][role] = live_counts[tenant].get(role, 0) + 1

    for item in scans["admin_auth"]:
        tenant = _attribute_string(item, "tenant_id")
        if (
            not tenant
            or _attribute_string(item, "record_type") != "config"
            or _attribute_string(item, "key") != f"config#{tenant}"
        ):
            raise VerificationError(
                "restored AdminAuth contains transient or unknown authority"
            )

    for item in scans["users"]:
        record_type = _attribute_string(item, "record_type")
        if record_type is None:
            physical_id = _attribute_string(item, "user_id")
            if not physical_id:
                raise VerificationError(
                    "restored Users contains a malformed canonical row"
                )
            tenant, user_id = _physical_identity(physical_id, tenants)
            identity = (tenant, user_id)
            if identity in aliases:
                raise VerificationError(
                    "restored Users contains a duplicate canonical row"
                )
            user_aliases = {("canonical_id", user_id)}
            email = _attribute_string(item, "email")
            if email:
                email_tenant, logical_email = _physical_identity(email, tenants)
                if email_tenant != tenant:
                    raise VerificationError(
                        "restored Users contains a cross-tenant email"
                    )
                user_aliases.add(("email", logical_email))
            for field, kind in (
                ("scim_external_id", "scim_external_id"),
                ("scim_user_name", "scim_user_name"),
            ):
                value = _attribute_string(item, field)
                if value:
                    user_aliases.add((kind, value))
            aliases[identity] = user_aliases
        else:
            canonical = _attribute_string(item, "canonical_user_id")
            if canonical:
                references.add(_physical_identity(canonical, tenants))

    for role in ("passkeys", "password_credentials"):
        for item in scans[role]:
            user_id = _attribute_string(item, "user_id")
            if not user_id:
                raise VerificationError(
                    f"restored {role} contains a row without user_id"
                )
            references.add(_physical_identity(user_id, tenants))

    for item in scans["grants"]:
        encoded = _attribute_string(item, "grant_json")
        if not encoded:
            raise VerificationError("restored Grants contains a row without grant_json")
        try:
            grant = json.loads(encoded)
        except json.JSONDecodeError as error:
            raise VerificationError("restored Grants contains invalid JSON") from error
        physical_user_id = _attribute_string(item, "user_id")
        if (
            not isinstance(grant, dict)
            or not isinstance(grant.get("user_id"), str)
            or not physical_user_id
        ):
            raise VerificationError(
                "restored Grants contains a malformed user reference"
            )
        tenant, indexed_user_id = _physical_identity(physical_user_id, tenants)
        if indexed_user_id != grant["user_id"]:
            raise VerificationError(
                "restored Grants user index disagrees with grant_json"
            )
        references.add((tenant, indexed_user_id))

    for item in scans["scim_groups"]:
        members = _attribute_strings(item, "members")
        if not members:
            continue
        item_tenants = _item_tenants(item, tenants)
        if len(item_tenants) != 1:
            raise VerificationError("restored SCIM Group has an unscoped membership")
        tenant = next(iter(item_tenants))
        references.update((tenant, member) for member in members if member)

    return aliases, references, live_counts


def _verify(
    manifest_path: pathlib.Path,
    keys: dict[int, bytes],
) -> dict[str, Any]:
    manifest = _load_json(manifest_path)
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != SCHEMA_VERSION
    ):
        raise VerificationError("unsupported verifier manifest")
    configured_tenants = manifest.get("tenants")
    restored = manifest.get("restored_scans")
    if (
        not isinstance(configured_tenants, list)
        or not configured_tenants
        or not all(isinstance(tenant, str) and tenant for tenant in configured_tenants)
        or len(set(configured_tenants)) != len(configured_tenants)
        or not isinstance(restored, dict)
        or set(restored) != REQUIRED_ROLES
        or not keys
    ):
        raise VerificationError("verifier manifest is incomplete")

    governance_items = _scan_items(
        _resolve(manifest_path, manifest.get("governance_scan"))
    )
    suppression_items = _scan_items(
        _resolve(manifest_path, manifest.get("suppression_scan"))
    )
    tenants = set(configured_tenants)
    suppressions, suppression_tenants, versions = _parse_suppressions(
        suppression_items, keys, tenants
    )
    lifecycles, lifecycle_tenants = _parse_lifecycles(governance_items, tenants)
    if not suppression_tenants.issubset(tenants) or not lifecycle_tenants.issubset(
        tenants
    ):
        raise VerificationError("control authority contains an unknown tenant")
    scans = {
        role: _scan_items(_resolve(manifest_path, path))
        for role, path in restored.items()
    }
    aliases, references, live_counts = _collect_restored_inventory(scans, tenants)

    tenant_suppressions = set()
    for tenant in tenants:
        for key_version, normalization_version in versions:
            digest = _suppression_digest(
                keys[key_version],
                tenant,
                "tenant",
                "tenant_id",
                normalization_version,
                tenant,
            )
            if (tenant, "tenant", digest) in suppressions:
                tenant_suppressions.add(tenant)

    blocked_tenants = tenant_suppressions | {
        tenant for tenant, state in lifecycles.items() if state == "offboarding"
    }
    if any(sum(live_counts[tenant].values()) for tenant in blocked_tenants):
        raise VerificationError("offboarded tenant remains in restored live authority")

    if references - set(aliases):
        raise VerificationError("restored authority contains dangling user references")

    suppressed_users = 0
    for (tenant, _user_id), candidate_aliases in aliases.items():
        suppressed = False
        for alias_kind, normalized_value in candidate_aliases:
            for key_version, normalization_version in versions:
                digest = _suppression_digest(
                    keys[key_version],
                    tenant,
                    "user",
                    alias_kind,
                    normalization_version,
                    normalized_value,
                )
                suppressed |= (tenant, "user", digest) in suppressions
        suppressed_users += int(suppressed)
    if suppressed_users:
        raise VerificationError("erased user remains in restored authority")

    digest = hashlib.sha256()
    for path in sorted(
        {
            _resolve(manifest_path, manifest["governance_scan"]),
            _resolve(manifest_path, manifest["suppression_scan"]),
            *(_resolve(manifest_path, path) for path in restored.values()),
        },
        key=str,
    ):
        digest.update(path.read_bytes())

    return {
        "schema_version": SCHEMA_VERSION,
        "result": "passed",
        "tenants_checked": len(tenants),
        "blocked_tenants_checked": len(blocked_tenants),
        "users_checked": len(aliases),
        "user_references_checked": len(references),
        "suppression_epochs_checked": len(suppressions),
        "restored_items_checked": {
            role: len(items) for role, items in sorted(scans.items())
        },
        "input_sha256": digest.hexdigest(),
    }


def _parse_key(value: str) -> tuple[int, bytes]:
    version, separator, path_value = value.partition("=")
    if not separator:
        raise VerificationError("--hmac-key must be VERSION=PATH")
    try:
        key_version = int(version)
    except ValueError as error:
        raise VerificationError("HMAC key version must be an integer") from error
    try:
        key = pathlib.Path(path_value).read_bytes().rstrip(b"\n")
    except OSError as error:
        raise VerificationError("unable to read an HMAC key file") from error
    if key_version <= 0 or len(key) < 32:
        raise VerificationError("HMAC key material is invalid")
    return key_version, key


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=pathlib.Path)
    parser.add_argument("--hmac-key", required=True, action="append")
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    try:
        keys = dict(_parse_key(value) for value in args.hmac_key)
        if len(keys) != len(args.hmac_key):
            raise VerificationError("duplicate HMAC key version")
        evidence = _verify(args.manifest, keys)
        encoded = json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n"
        if args.output:
            temporary = args.output.with_name(f"{args.output.name}.current")
            temporary.write_text(encoded, encoding="utf-8")
            temporary.chmod(0o600)
            temporary.replace(args.output)
        else:
            sys.stdout.write(encoded)
        return 0
    except VerificationError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
