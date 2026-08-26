#!/usr/bin/env python3
"""Verify the live SPA can be automated by the OIDF HtmlUnit browser."""

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

REQUIRED_MARKERS = (
    "agent-auth-login-email",
    "agent-auth-login-password",
    "agent-auth-login-submit",
    "agent-auth-consent-ready",
    "agent-auth-consent-approve",
)
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


class PreflightError(ValueError):
    pass


class ScriptParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.scripts: list[dict[str, str]] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if tag.lower() == "script":
            self.scripts.append(
                {key.lower(): value for key, value in attrs if value is not None}
            )


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
    parsed = urllib.parse.urlsplit(issuer)
    require(not parsed.query, "--issuer must not contain a query")
    if origin[0] != "https":
        require(
            allow_insecure_loopback and origin[1] in {"127.0.0.1", "::1", "localhost"},
            "--issuer must be HTTPS",
        )
    return issuer


def trusted_asset(
    value: str,
    *,
    label: str,
    base_url: str,
    issuer_origin: tuple[str, str, int],
) -> str:
    require(bool(value), f"{label} has no asset URL")
    url = urllib.parse.urljoin(base_url, value)
    parsed = urllib.parse.urlsplit(url)
    require(
        url_origin(url) == issuer_origin,
        f"{label} must preserve the selected issuer's same origin",
    )
    require(
        not parsed.query and not parsed.fragment,
        f"{label} must not contain a query or fragment",
    )
    return url


def request(url: str) -> tuple[int, str, bytes]:
    req = urllib.request.Request(
        url,
        headers={
            "accept": "text/html,application/javascript",
            "user-agent": "agent-auth-oidf-browser-preflight/1",
        },
    )
    try:
        with OPENER.open(req, timeout=20) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
            require(
                len(body) <= MAX_RESPONSE_BYTES,
                "live browser asset exceeds the preflight size limit",
            )
            return (
                response.status,
                response.headers.get("content-type", ""),
                body,
            )
    except urllib.error.HTTPError as error:
        return error.code, error.headers.get("content-type", ""), error.read(4096)
    except (TimeoutError, urllib.error.URLError) as error:
        reason = getattr(error, "reason", str(error))
        raise PreflightError(f"request failed: {reason}") from error


def decode(body: bytes, label: str) -> str:
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PreflightError(f"{label} is not valid UTF-8") from error


def run_preflight(
    *,
    issuer: str,
    summary: dict[str, Any],
) -> dict[str, Any]:
    issuer_origin = url_origin(issuer)
    assert issuer_origin is not None
    login_url = f"{issuer}/login"
    summary["login_url"] = login_url
    login_status, login_type, login_body = request(login_url)
    summary["login_status"] = login_status
    require(login_status == 200, f"live /login returned HTTP {login_status}")
    require(
        login_type.lower().startswith("text/html"),
        "live /login did not return HTML",
    )
    html = decode(login_body, "live /login")

    parser = ScriptParser()
    parser.feed(html)
    modern_entries = [
        script
        for script in parser.scripts
        if script.get("type") == "module" and bool(script.get("src"))
    ]
    require(bool(modern_entries), "modern module entry is missing")
    polyfill_entries = [
        script
        for script in parser.scripts
        if script.get("id") == "vite-legacy-polyfill"
    ]
    require(
        len(polyfill_entries) == 1,
        "expected exactly one legacy polyfill entry",
    )
    legacy_entries = [
        script for script in parser.scripts if script.get("id") == "vite-legacy-entry"
    ]
    require(
        len(legacy_entries) == 1,
        "expected exactly one legacy application entry",
    )
    require("System.import" in html, "legacy SystemJS bootstrap is missing")
    polyfill_url = trusted_asset(
        polyfill_entries[0].get("src", ""),
        label="legacy polyfill entry",
        base_url=login_url,
        issuer_origin=issuer_origin,
    )
    legacy_url = trusted_asset(
        legacy_entries[0].get("data-src", ""),
        label="legacy application entry",
        base_url=login_url,
        issuer_origin=issuer_origin,
    )

    summary["polyfill_bundle_url"] = polyfill_url
    polyfill_status, _polyfill_type, polyfill_body = request(polyfill_url)
    summary["polyfill_bundle_status"] = polyfill_status
    require(
        polyfill_status == 200,
        f"legacy polyfill bundle returned HTTP {polyfill_status}",
    )
    polyfills = decode(polyfill_body, "legacy polyfill bundle")
    require(
        "XMLHttpRequest" in polyfills,
        "XMLHttpRequest transport polyfill is missing",
    )
    require("fetch" in polyfills, "Fetch API polyfill is missing")

    summary["legacy_bundle_url"] = legacy_url
    bundle_status, _bundle_type, bundle_body = request(legacy_url)
    summary["legacy_bundle_status"] = bundle_status
    require(
        bundle_status == 200,
        f"legacy application bundle returned HTTP {bundle_status}",
    )
    legacy_bundle = decode(bundle_body, "legacy application bundle")
    require(
        "System.register" in legacy_bundle,
        "legacy application is not a SystemJS module",
    )
    present_markers = [marker for marker in REQUIRED_MARKERS if marker in legacy_bundle]
    summary["marker_count"] = len(present_markers)
    for marker in REQUIRED_MARKERS:
        require(
            marker in legacy_bundle,
            f"legacy application is missing {marker}",
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
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--allow-insecure-loopback", action="store_true")
    args = parser.parse_args()

    summary: dict[str, Any] = {
        "schema_version": 1,
        "status": "failed",
        "issuer": args.issuer.rstrip("/"),
        "login_url": None,
        "login_status": None,
        "polyfill_bundle_url": None,
        "polyfill_bundle_status": None,
        "legacy_bundle_url": None,
        "legacy_bundle_status": None,
        "marker_count": 0,
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
        summary["issuer"] = issuer
        summary = run_preflight(issuer=issuer, summary=summary)
        write_summary(args.summary, summary)
        print(
            "OIDF live browser preflight passed "
            f"with {summary['marker_count']} automation marker(s)"
        )
        return 0
    except (OSError, PreflightError, TypeError, UnicodeError, ValueError) as error:
        summary["status"] = "failed"
        summary["error"] = str(error)
        write_summary(args.summary, summary)
        print(f"OIDF live browser preflight failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
