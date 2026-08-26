#!/usr/bin/env python3
"""Verify protected OIDF initial access tokens without exposing credentials."""

import argparse
import http.client
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

MAX_RESPONSE_BYTES = 1024 * 1024
CLEANUP_RETRY_DELAYS = (0, 1, 2)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


class PreflightError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PreflightError(message)


def well_known(issuer: str) -> str:
    parsed = urllib.parse.urlsplit(issuer)
    path = parsed.path.rstrip("/")
    return urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            f"/.well-known/openid-configuration{path}",
            "",
            "",
        )
    )


def url_origin(value: str) -> tuple[str, str, int] | None:
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        return None
    default_port = 443 if parsed.scheme == "https" else 80
    return parsed.scheme, parsed.hostname.lower(), port or default_port


def validate_issuer(value: str, *, allow_insecure_loopback: bool) -> str:
    issuer = value.rstrip("/")
    origin = url_origin(issuer)
    require(origin is not None, "--issuer must be an absolute HTTP(S) URL")
    assert origin is not None
    require(
        not urllib.parse.urlsplit(issuer).query,
        "--issuer must not contain a query",
    )
    if origin[0] != "https":
        require(
            allow_insecure_loopback and origin[1] in {"127.0.0.1", "::1", "localhost"},
            "--issuer must be HTTPS",
        )
    return issuer


def trusted_endpoint(
    value: Any,
    *,
    issuer_origin: tuple[str, str, int],
    allow_insecure_loopback: bool,
) -> str:
    require(
        isinstance(value, str) and bool(value),
        "endpoint must be a non-empty string",
    )
    origin = url_origin(value)
    require(
        origin == issuer_origin,
        "endpoint must preserve the selected issuer's same origin",
    )
    assert origin is not None
    require(
        origin[0] == "https" or allow_insecure_loopback,
        "endpoint must use HTTPS",
    )
    return value


def parse_object(body: bytes) -> dict[str, Any]:
    try:
        value = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def request(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    json_body: dict[str, Any] | None = None,
    method: str | None = None,
) -> tuple[int, bytes]:
    body = None
    request_headers = {
        "accept": "application/json",
        "user-agent": "agent-auth-oidf-iat-preflight/1",
    }
    if json_body is not None:
        body = json.dumps(json_body).encode()
        request_headers["content-type"] = "application/json"
    if headers:
        request_headers.update(headers)
    req = urllib.request.Request(
        url,
        data=body,
        headers=request_headers,
        method=method,
    )

    def read_limited(response) -> bytes:
        response_body = response.read(MAX_RESPONSE_BYTES + 1)
        require(
            len(response_body) <= MAX_RESPONSE_BYTES,
            "OIDF preflight response exceeds the size limit",
        )
        return response_body

    try:
        with OPENER.open(req, timeout=20) as response:
            return response.status, read_limited(response)
    except urllib.error.HTTPError as error:
        return error.code, read_limited(error)
    except (
        TimeoutError,
        urllib.error.URLError,
        ConnectionError,
        http.client.HTTPException,
    ) as error:
        reason = getattr(error, "reason", str(error))
        raise PreflightError(f"request failed: {reason}") from error


def load_config(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    require(isinstance(value, dict), "OIDF configuration must be a JSON object")
    return value


def token_groups(config: dict[str, Any]) -> list[tuple[str, list[str]]]:
    groups: dict[str, list[str]] = {}
    for slot in ("client", "client2"):
        client = config.get(slot)
        require(isinstance(client, dict), f"config.{slot} must be an object")
        token = client.get("initial_access_token")
        require(
            isinstance(token, str) and bool(token),
            f"config.{slot}.initial_access_token must be configured",
        )
        groups.setdefault(token, []).append(slot)
    return list(groups.items())


def registration_error(status: int, body: bytes, slots: list[str]) -> str:
    error = parse_object(body).get("error")
    error_code = error if isinstance(error, str) and error else "unknown_error"
    slot_names = "/".join(slots)
    if status == 401 and error_code == "invalid_token":
        return (
            f"OIDF initial access token for {slot_names} returned "
            "HTTP 401 invalid_token; rotate OIDF_BASIC_OP_CONFIG_JSON"
        )
    return (
        f"OIDF initial access token for {slot_names} registration returned "
        f"HTTP {status} {error_code}"
    )


def run_preflight(
    *,
    config: dict[str, Any],
    issuer: str,
    redirect_uri: str,
    allow_insecure_loopback: bool,
    summary: dict[str, Any],
) -> dict[str, Any]:
    issuer_origin = url_origin(issuer)
    assert issuer_origin is not None
    server = config.get("server")
    require(isinstance(server, dict), "config.server must be an object")
    discovery_url = server.get("discoveryUrl")
    require(
        discovery_url == well_known(issuer),
        "config.server.discoveryUrl does not match the selected issuer",
    )

    discovery_status, discovery_body = request(discovery_url)
    require(
        discovery_status == 200,
        f"OIDF discovery returned HTTP {discovery_status}",
    )
    metadata = parse_object(discovery_body)
    require(
        metadata.get("issuer") == issuer,
        "OIDF discovery issuer does not match the selected issuer",
    )
    registration_endpoint = trusted_endpoint(
        metadata.get("registration_endpoint"),
        issuer_origin=issuer_origin,
        allow_insecure_loopback=allow_insecure_loopback,
    )

    probes = summary["probes"]
    # The official dynamic-registration plan also reuses these credentials.
    # A single-use IAT is therefore incompatible with this workflow.
    for token, slots in token_groups(config):
        probe: dict[str, Any] = {
            "slots": slots,
            "registration_status": None,
            "cleanup_status": None,
            "cleanup_attempts": 0,
        }
        probes.append(probe)
        registration_status, registration_body = request(
            registration_endpoint,
            headers={"authorization": f"Bearer {token}"},
            json_body={
                "client_name": "agent-auth OIDF IAT preflight",
                "redirect_uris": [redirect_uri],
                "token_endpoint_auth_method": "none",
            },
            method="POST",
        )
        probe["registration_status"] = registration_status
        if registration_status != 201:
            raise PreflightError(
                registration_error(registration_status, registration_body, slots)
            )

        registration = parse_object(registration_body)
        management_uri = trusted_endpoint(
            registration.get("registration_client_uri"),
            issuer_origin=issuer_origin,
            allow_insecure_loopback=allow_insecure_loopback,
        )
        management_token = registration.get("registration_access_token")
        require(
            isinstance(management_token, str) and bool(management_token),
            "registration response omitted cleanup credentials",
        )
        for attempt, delay in enumerate(CLEANUP_RETRY_DELAYS, start=1):
            if delay:
                time.sleep(delay)
            probe["cleanup_attempts"] = attempt
            try:
                cleanup_status, _cleanup_body = request(
                    management_uri,
                    headers={"authorization": f"Bearer {management_token}"},
                    method="DELETE",
                )
            except PreflightError as error:
                if attempt == len(CLEANUP_RETRY_DELAYS):
                    raise PreflightError(
                        "OIDF IAT preflight cleanup failed after "
                        f"{attempt} attempts: {error}"
                    ) from error
                continue
            probe["cleanup_status"] = cleanup_status
            if cleanup_status == 204:
                break
            if 500 <= cleanup_status < 600 and attempt < len(CLEANUP_RETRY_DELAYS):
                continue
            suffix = f" after {attempt} attempts" if attempt > 1 else ""
            raise PreflightError(
                f"OIDF IAT preflight cleanup returned HTTP {cleanup_status}{suffix}"
            )

    summary["status"] = "passed"
    summary["probe_count"] = len(probes)
    return summary


def write_summary(path: Path, summary: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--allowed-issuer", required=True)
    parser.add_argument("--redirect-uri", required=True)
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--allow-insecure-loopback", action="store_true")
    args = parser.parse_args()

    summary: dict[str, Any] = {
        "schema_version": 1,
        "status": "failed",
        "issuer": args.issuer.rstrip("/"),
        "discovery_url": None,
        "probe_count": 0,
        "probes": [],
    }
    try:
        issuer = validate_issuer(
            args.issuer,
            allow_insecure_loopback=args.allow_insecure_loopback,
        )
        allowed_issuer = validate_issuer(
            args.allowed_issuer,
            allow_insecure_loopback=args.allow_insecure_loopback,
        )
        require(
            issuer == allowed_issuer,
            "--issuer must match the configured environment issuer",
        )
        config = load_config(args.config)
        summary["issuer"] = issuer
        summary["discovery_url"] = well_known(issuer)
        summary = run_preflight(
            config=config,
            issuer=issuer,
            redirect_uri=args.redirect_uri,
            allow_insecure_loopback=args.allow_insecure_loopback,
            summary=summary,
        )
        write_summary(args.summary, summary)
        print(
            "OIDF initial access token preflight passed "
            f"for {summary['probe_count']} unique token(s)"
        )
        return 0
    except (
        json.JSONDecodeError,
        OSError,
        PreflightError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as error:
        summary["status"] = "failed"
        summary["probe_count"] = len(summary["probes"])
        summary["error"] = str(error)
        write_summary(args.summary, summary)
        print(f"OIDF initial access token preflight failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
