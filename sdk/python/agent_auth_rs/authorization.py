"""RFC 9728 challenge URL and explicit scope implication helpers."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping, Sequence
from urllib.parse import urlsplit

from .types import ScopeImplications, ScopeResolver

_SCOPE_TOKEN = re.compile(r"^[\x21\x23-\x5b\x5d-\x7e]+$")
_DOT_SEGMENT = re.compile(r"^(?:\.|%2e){1,2}$", re.IGNORECASE)
_URI_PATH = re.compile(
    r"^(?:[a-z0-9\-._~!$&'()*+,;=:@/]|%[0-9a-f]{2})*$", re.IGNORECASE
)
_URI_QUERY = re.compile(
    r"^(?:[a-z0-9\-._~!$&'()*+,;=:@/?]|%[0-9a-f]{2})*$", re.IGNORECASE
)
_CANONICAL_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_NUMBERISH_HOST = re.compile(
    r"^(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+))*$", re.IGNORECASE
)
_PROTECTED_RESOURCE_WELL_KNOWN = "/.well-known/oauth-protected-resource"


def _validate_hostname(hostname: str, label: str) -> None:
    if ":" in hostname:
        try:
            ipaddress.IPv6Address(hostname)
        except ValueError as exc:
            raise ValueError(f"{label} must use a valid IPv6 host") from exc
        return
    without_final_dot = hostname[:-1] if hostname.endswith(".") else hostname
    labels = without_final_dot.split(".")
    if any(
        not part
        or len(part) > 63
        or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", part, re.IGNORECASE) is None
        for part in labels
    ):
        raise ValueError(f"{label} must use a valid DNS host")


def _explicit_port(netloc: str) -> int | None:
    if netloc.startswith("["):
        suffix = netloc[netloc.index("]") + 1 :]
        return int(suffix[1:]) if suffix.startswith(":") and len(suffix) > 1 else None
    _, separator, port = netloc.rpartition(":")
    return int(port) if separator and port else None


def _parse_https_url(value: str, label: str, allow_query: bool):
    if (
        not isinstance(value, str)
        or not value
        or any(ord(char) < 0x21 or ord(char) > 0x7E for char in value)
        or '"' in value
        or "\\" in value
    ):
        raise ValueError(f"{label} must contain only safe printable URI characters")
    if re.match(r"^https://", value, re.IGNORECASE) is None:
        raise ValueError(f"{label} must be an absolute HTTPS URL")

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{label} must be an absolute HTTPS URL") from exc
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError(f"{label} must be an absolute HTTPS URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"{label} must not contain userinfo")
    if "%" in parsed.netloc:
        raise ValueError(f"{label} must not contain an encoded authority")
    if (
        _URI_PATH.fullmatch(parsed.path) is None
        or _URI_QUERY.fullmatch(parsed.query) is None
    ):
        raise ValueError(f"{label} path and query must use valid RFC 3986 characters")
    if "#" in value:
        raise ValueError(f"{label} must not contain a fragment")
    if not allow_query and "?" in value:
        raise ValueError(f"{label} must not contain a query")
    if not allow_query and any(
        _DOT_SEGMENT.fullmatch(segment) for segment in parsed.path.split("/")
    ):
        raise ValueError(f"{label} must not contain dot path segments")
    numeric_hostname = (
        parsed.hostname[:-1] if parsed.hostname.endswith(".") else parsed.hostname
    )
    if _NUMBERISH_HOST.fullmatch(numeric_hostname):
        parts = numeric_hostname.split(".")
        if (
            parsed.hostname.endswith(".")
            or _CANONICAL_IPV4.fullmatch(numeric_hostname) is None
            or any(int(part) > 255 for part in parts)
            or any(len(part) > 1 and part.startswith("0") for part in parts)
        ):
            raise ValueError(f"{label} must use a canonical host")
    _validate_hostname(parsed.hostname, label)
    return parsed, port


def normalize_resource_id(resource_id: str) -> str:
    """Validate and normalize the resource identifier used for exact audience checks."""
    _parse_https_url(resource_id, "resource_id", allow_query=False)
    return resource_id.rstrip("/")


def derive_resource_metadata_url(resource_id: str) -> str:
    """Derive the RFC 9728 endpoint-path protected-resource metadata URL."""
    normalized = normalize_resource_id(resource_id)
    parsed, port = _parse_https_url(normalized, "resource_id", allow_query=False)
    hostname = parsed.hostname.encode("idna").decode("ascii").lower()
    if ":" in hostname:
        hostname = f"[{ipaddress.IPv6Address(hostname).compressed}]"
    configured_port = _explicit_port(parsed.netloc)
    authority = hostname if configured_port is None else f"{hostname}:{configured_port}"
    resource_path = parsed.path.rstrip("/")
    if resource_path == "/":
        resource_path = ""
    return f"https://{authority}{_PROTECTED_RESOURCE_WELL_KNOWN}{resource_path}"


def validate_resource_metadata_url(resource_metadata_url: str) -> str:
    """Validate an explicit challenge URL while preserving its configured spelling."""
    _parse_https_url(resource_metadata_url, "resource_metadata_url", allow_query=True)
    return resource_metadata_url


def validate_scope_token(scope: str) -> str:
    """Validate one RFC 6749 scope-token before using it in a response header."""
    if not isinstance(scope, str) or _SCOPE_TOKEN.fullmatch(scope) is None:
        raise ValueError(
            "scope values must be non-empty ASCII scope-token values without "
            "whitespace, quotes, or backslashes"
        )
    return scope


def normalize_required_scopes(scopes: Sequence[str]) -> list[str]:
    return [validate_scope_token(scope) for scope in scopes]


def create_scope_resolver(
    implications: ScopeImplications | None = None,
) -> ScopeResolver:
    """Build a transitive resolver from explicit broader -> narrower declarations."""
    source: Mapping[str, Sequence[str]] = implications or {}
    graph: dict[str, set[str]] = {}
    for broader, narrower_scopes in source.items():
        validate_scope_token(broader)
        graph[broader] = {validate_scope_token(scope) for scope in narrower_scopes}

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(scope: str) -> None:
        if scope in visiting:
            raise ValueError(f"scope implication cycle includes {scope}")
        if scope in visited:
            return
        visiting.add(scope)
        for implied in graph.get(scope, set()):
            visit(implied)
        visiting.remove(scope)
        visited.add(scope)

    for scope in graph:
        visit(scope)

    def resolves(granted_scope: str, required_scope: str) -> bool:
        if granted_scope == required_scope:
            return True
        pending = list(graph.get(granted_scope, set()))
        seen: set[str] = set()
        while pending:
            candidate = pending.pop()
            if candidate in seen:
                continue
            if candidate == required_scope:
                return True
            seen.add(candidate)
            pending.extend(graph.get(candidate, set()))
        return False

    return resolves
