#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import re
from pathlib import Path


CREATE_KEY = re.compile(r"scim-create:[A-Za-z0-9_-]{43}")


def attribute_string(item: dict, name: str) -> str | None:
    value = item.get(name)
    if not isinstance(value, dict):
        return None
    string = value.get("S")
    return string if isinstance(string, str) else None


def tenant_prefix(user_id: str, tenants: list[str]) -> str | None:
    prefixes = [
        f"{tenant}\x1f"
        for tenant in tenants
        if user_id.startswith(f"{tenant}\x1f")
    ]
    return prefixes[0] if len(prefixes) == 1 else None


def canonical_sha256_token(value: str) -> bool:
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except ValueError:
        return False
    encoded = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode()
    return len(decoded) == 32 and encoded == value


def validate(items: list[dict], tenants: list[str]) -> None:
    for item in items:
        record_type = attribute_string(item, "record_type")
        if record_type is None:
            continue
        user_id = attribute_string(item, "user_id")
        if user_id is None:
            raise ValueError("SCIM authority row lacks a string physical key")
        prefix = tenant_prefix(user_id, tenants)
        if prefix is None:
            raise ValueError("SCIM authority row has an invalid tenant prefix")
        logical_key = user_id[len(prefix) :]
        if record_type == "scim_alias":
            kind = attribute_string(item, "alias_kind")
            value = attribute_string(item, "alias_value")
            if kind not in {"external", "username"} or value is None:
                raise ValueError("SCIM alias row lacks its canonical source fields")
            digest = (
                base64.urlsafe_b64encode(hashlib.sha256(value.encode()).digest())
                .rstrip(b"=")
                .decode()
            )
            if logical_key != f"scim-alias:{kind}:{digest}":
                raise ValueError(
                    "SCIM alias physical key does not match its source fields"
                )
        elif record_type == "scim_create":
            digest = logical_key.removeprefix("scim-create:")
            if (
                CREATE_KEY.fullmatch(logical_key) is None
                or not canonical_sha256_token(digest)
            ):
                raise ValueError("SCIM create-claim physical key is not canonical")
        else:
            raise ValueError("unknown SCIM authority row type")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--users", required=True)
    parser.add_argument("--tenants-json", required=True)
    args = parser.parse_args()
    items = json.loads(Path(args.users).read_text())
    tenants = json.loads(args.tenants_json)
    if not isinstance(items, list) or not (
        isinstance(tenants, list)
        and tenants
        and all(isinstance(tenant, str) and tenant for tenant in tenants)
    ):
        raise ValueError("invalid Users authority or tenant input")
    validate(items, tenants)


if __name__ == "__main__":
    main()
