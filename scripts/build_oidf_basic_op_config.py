#!/usr/bin/env python3
"""Build the secret OIDF Basic OP plan configuration from protected inputs."""

import argparse
import json
import os
import re
import stat
import tempfile
import urllib.parse
from pathlib import Path

HOSTED_SUITE = "https://www.certification.openid.net"
HOSTED_CALLBACK_MATCH = f"{HOSTED_SUITE}/test/*/callback*"
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+$")


def issuer_origin(value: str) -> str:
    parsed = urllib.parse.urlsplit(value.rstrip("/"))
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or "\\" in value
        or any(ord(char) < 0x21 or ord(char) == 0x7F for char in value)
    ):
        raise ValueError("--issuer must be an HTTPS origin without path or userinfo")
    try:
        _ = parsed.port
    except ValueError as error:
        raise ValueError("--issuer contains an invalid port") from error
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def protected_value(path: Path, option: str) -> str:
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise ValueError(f"{option} must not be accessible by group or other")
    value = path.read_text(encoding="utf-8")
    value = value.removesuffix("\n")
    if not value or "\n" in value or "\r" in value:
        raise ValueError(f"{option} must contain one non-empty line")
    return value


def validate_initial_access_token(value: str) -> str:
    token_id, separator, secret = value.partition(".")
    if (
        not separator
        or not token_id.startswith("iat_")
        or len(token_id) > 128
        or not secret
        or len(secret) > 256
    ):
        raise ValueError(
            "--initial-access-token-file must contain one iat_<id>.<secret> token"
        )
    return value


def build_config(
    issuer: str,
    email: str,
    password: str,
    initial_access_token: str,
) -> dict:
    if not EMAIL_PATTERN.fullmatch(email):
        raise ValueError("--email must be a single email address")
    callback_task = {
        "task": "Verify hosted callback completed",
        "match": HOSTED_CALLBACK_MATCH,
        "commands": [["wait", "id", "submission_complete", 30]],
    }

    def expected_error_browser(error: str) -> list[dict]:
        return [
            {
                "match": f"{issuer}/authorize*",
                "tasks": [
                    {
                        "task": "Capture expected authorization error",
                        "match": f"{issuer}/authorize*",
                        "commands": [
                            [
                                "wait",
                                "xpath",
                                "//*",
                                30,
                                error,
                                "update-image-placeholder",
                            ]
                        ],
                    }
                ],
            }
        ]

    return {
        "description": "agent-auth stable release conformance",
        "options": {"browsercontrol_css_enable": False},
        "server": {
            "discoveryUrl": f"{issuer}/.well-known/openid-configuration",
            "login_hint": email,
        },
        "client": {
            "client_name": "agent-auth-oidf-primary",
            "initial_access_token": initial_access_token,
        },
        "client2": {
            "client_name": "agent-auth-oidf-secondary",
            "initial_access_token": initial_access_token,
        },
        "browser": [
            {
                "match": f"{issuer}/authorize*prompt=none*",
                "tasks": [callback_task],
            },
            {
                "match": f"{issuer}/authorize*",
                "tasks": [
                    {
                        "task": "Authenticate dedicated test user",
                        "match": f"{issuer}/login*",
                        "optional": True,
                        "commands": [
                            ["wait", "id", "agent-auth-login-ready", 30],
                            ["wait", "id", "agent-auth-login-email", 30],
                            [
                                "wait",
                                "id",
                                "agent-auth-login-email",
                                30,
                                ".*",
                                "update-image-placeholder-optional",
                            ],
                            ["text", "id", "agent-auth-login-email", email],
                            ["text", "id", "agent-auth-login-password", password],
                            ["click", "id", "agent-auth-login-submit"],
                            ["wait", "contains", f"{issuer}/consent", 30],
                        ],
                    },
                    {
                        "task": "Approve requested access",
                        "match": f"{issuer}/consent*",
                        "optional": True,
                        "commands": [
                            ["wait", "id", "agent-auth-consent-ready", 30],
                            ["click", "id", "agent-auth-consent-approve"],
                            ["wait", "contains", HOSTED_SUITE, 30],
                        ],
                    },
                    callback_task,
                ],
            },
        ],
        "override": {
            "oidcc-ensure-registered-redirect-uri": {
                "browser": expected_error_browser("invalid_request"),
            },
            "oidcc-ensure-request-object-with-redirect-uri": {
                "browser": expected_error_browser("request_not_supported"),
            },
        },
    }


def atomic_write(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        text=True,
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            json.dump(value, handle, separators=(",", ":"))
            handle.write("\n")
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        Path(temporary).unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--password-file", required=True, type=Path)
    parser.add_argument("--initial-access-token-file", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    try:
        issuer = issuer_origin(args.issuer)
        password = protected_value(args.password_file, "--password-file")
        initial_access_token = validate_initial_access_token(
            protected_value(
                args.initial_access_token_file,
                "--initial-access-token-file",
            )
        )
        atomic_write(
            args.output,
            build_config(
                issuer,
                args.email,
                password,
                initial_access_token,
            ),
        )
        return 0
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
