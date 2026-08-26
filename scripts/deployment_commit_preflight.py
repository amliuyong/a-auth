#!/usr/bin/env python3
"""Bind release evidence to the commit reported by the live issuer."""

import argparse
import http.client
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

DEPLOYMENT_HEADER = "x-agent-auth-deployment-commit"
MAX_RESPONSE_BYTES = 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


class PreflightError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PreflightError(message)


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


def response_headers(message) -> dict[str, list[str]]:
    return {key.lower(): message.get_all(key, []) for key in message}


def request(url: str) -> tuple[int, dict[str, list[str]], bytes]:
    req = urllib.request.Request(
        url,
        headers={
            "accept": "application/json",
            "cache-control": "no-cache",
            "pragma": "no-cache",
            "user-agent": "agent-auth-deployment-commit-preflight/1",
        },
    )

    def read_limited(response) -> bytes:
        body = response.read(MAX_RESPONSE_BYTES + 1)
        require(
            len(body) <= MAX_RESPONSE_BYTES,
            "deployment preflight response exceeds the size limit",
        )
        return body

    try:
        with OPENER.open(req, timeout=20) as response:
            return (
                response.status,
                response_headers(response.headers),
                read_limited(response),
            )
    except urllib.error.HTTPError as error:
        return (
            error.code,
            response_headers(error.headers),
            read_limited(error),
        )
    except (
        TimeoutError,
        urllib.error.URLError,
        ConnectionError,
        http.client.HTTPException,
    ) as error:
        reason = getattr(error, "reason", str(error))
        raise PreflightError(f"request failed: {reason}") from error


def parse_object(body: bytes) -> dict[str, Any]:
    try:
        value = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise PreflightError("discovery response is not valid JSON") from error
    require(isinstance(value, dict), "discovery response must be a JSON object")
    return value


def run_preflight(
    *,
    issuer: str,
    expected_deployment_version: str,
    summary: dict[str, Any],
) -> dict[str, Any]:
    discovery_url = well_known(issuer)
    summary["discovery_url"] = discovery_url
    status, headers, body = request(discovery_url)
    summary["discovery_status"] = status
    require(status == 200, f"live discovery returned HTTP {status}")
    metadata = parse_object(body)
    require(
        metadata.get("issuer") == issuer,
        "live discovery issuer does not match the selected issuer",
    )
    observed_values = headers.get(DEPLOYMENT_HEADER, [])
    require(
        len(observed_values) == 1,
        "live discovery must return exactly one deployment commit header",
    )
    observed = observed_values[0]
    require(
        isinstance(observed, str)
        and re.fullmatch(r"[0-9a-f]{40}", observed) is not None,
        "live discovery omitted a valid deployment commit header",
    )
    summary["deployment_version"] = observed
    require(
        observed == expected_deployment_version,
        "live deployment commit does not match the expected deployment version",
    )
    summary["status"] = "passed"
    return summary


def write_summary(path: Path, summary: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--allowed-issuer", required=True)
    parser.add_argument("--expected-deployment-version", required=True)
    parser.add_argument("--phase", required=True, choices=("start", "end"))
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--allow-insecure-loopback", action="store_true")
    args = parser.parse_args()

    summary: dict[str, Any] = {
        "schema_version": 1,
        "phase": args.phase,
        "status": "failed",
        "issuer": args.issuer.rstrip("/"),
        "discovery_url": None,
        "discovery_status": None,
        "expected_deployment_version": args.expected_deployment_version,
        "deployment_version": None,
    }
    try:
        require(
            re.fullmatch(r"[0-9a-f]{40}", args.expected_deployment_version) is not None,
            "--expected-deployment-version must be a full lowercase Git commit",
        )
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
        summary["issuer"] = issuer
        summary = run_preflight(
            issuer=issuer,
            expected_deployment_version=args.expected_deployment_version,
            summary=summary,
        )
        write_summary(args.summary, summary)
        print(
            "live deployment commit preflight passed "
            f"for {summary['deployment_version']}"
        )
        return 0
    except (OSError, PreflightError, TypeError, UnicodeError, ValueError) as error:
        summary["status"] = "failed"
        summary["error"] = str(error)
        write_summary(args.summary, summary)
        print(f"live deployment commit preflight failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
