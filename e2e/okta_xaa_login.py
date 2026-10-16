#!/usr/bin/env python3
"""One-time Okta sign-in for the EMA / C13.8 external acceptance (issue #2).

Runs an authorization-code + PKCE flow against the Okta org authorization
server, then stores the requesting app's client credentials and the resulting
refresh token in a mode-0600 JSON file outside the repository. Nothing secret is
printed. `e2e/okta_xaa_acquire.sh` later exchanges that refresh token for a
fresh ID-JAG.

Usage (run in your own terminal; the client secret is read with getpass):
  python3 -I e2e/okta_xaa_login.py \
    --org-url https://<your-org>.okta.com \
    --client-id <requesting-app-client-id> \
    [--out ~/.config/agent-auth/okta-xaa.json] [--port 8765] \
    [--client-secret-from-clipboard]
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import http.server
import json
import os
import secrets
import subprocess
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path


def fail(message: str) -> None:
    print(f"okta xaa login failed: {message}", file=sys.stderr)
    sys.exit(1)


def https_origin(value: str) -> str:
    parsed = urllib.parse.urlsplit(value.rstrip("/"))
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        fail("--org-url must be an HTTPS origin without path, query, or userinfo")
    return f"https://{parsed.netloc}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--org-url", required=True)
    parser.add_argument("--client-id", required=True)
    parser.add_argument(
        "--out",
        default=str(Path.home() / ".config" / "agent-auth" / "okta-xaa.json"),
    )
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--client-secret-from-clipboard",
        action="store_true",
        help="read the client secret from the macOS clipboard (no TTY needed)",
    )
    args = parser.parse_args()

    org = https_origin(args.org_url)
    out = Path(args.out).expanduser().resolve()
    repo = Path(__file__).resolve().parent.parent
    if out == repo or repo in out.parents:
        fail("--out must be outside the repository")
    if not args.client_id.isalnum():
        fail("--client-id contains unexpected characters")

    if args.client_secret_from_clipboard:
        client_secret = subprocess.run(
            ["pbpaste"], check=True, capture_output=True, text=True
        ).stdout.strip()
    else:
        client_secret = getpass.getpass("EMA Requesting Client secret: ").strip()
    if len(client_secret) < 16:
        fail("client secret looks too short")

    redirect_uri = f"http://localhost:{args.port}/callback"
    verifier = secrets.token_urlsafe(64)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    state = secrets.token_urlsafe(32)
    result: dict[str, str] = {}
    done = threading.Event()

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            pass

        def do_GET(self) -> None:  # noqa: N802
            parsed = urllib.parse.urlsplit(self.path)
            if parsed.path != "/callback":
                self.send_error(404)
                return
            query = urllib.parse.parse_qs(parsed.query)
            if query.get("state") != [state]:
                result["error"] = "state mismatch"
            elif "error" in query:
                result["error"] = query["error"][0]
            elif len(query.get("code", [])) != 1:
                result["error"] = "missing code"
            else:
                result["code"] = query["code"][0]
            self.send_response(200)
            self.send_header("content-type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                "Okta sign-in received. You can close this tab.\n".encode()
            )
            done.set()

    server = http.server.HTTPServer(("127.0.0.1", args.port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    authorize = f"{org}/oauth2/v1/authorize?" + urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": args.client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid offline_access",
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    print("Opening the browser for Okta sign-in. If it does not open, visit:")
    print(authorize)
    webbrowser.open(authorize)
    if not done.wait(timeout=300):
        server.shutdown()
        fail("timed out waiting for the Okta callback")
    server.shutdown()
    if "error" in result:
        fail(f"authorization failed: {result['error']}")

    form = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "code": result["code"],
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
            "client_id": args.client_id,
            "client_secret": client_secret,
        }
    ).encode()
    request = urllib.request.Request(
        f"{org}/oauth2/v1/token",
        data=form,
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            tokens = json.load(response)
    except urllib.error.HTTPError as error:
        try:
            detail = json.load(error).get("error", "unknown")
        except ValueError:
            detail = "unparseable error body"
        fail(f"token endpoint returned HTTP {error.code} ({detail})")
    refresh_token = tokens.get("refresh_token")
    if not isinstance(refresh_token, str) or not refresh_token:
        fail("Okta did not return a refresh token; check the Refresh Token grant")

    out.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(f"{out}.tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "org_url": org,
                "client_id": args.client_id,
                "client_secret": client_secret,
                "refresh_token": refresh_token,
            },
            handle,
        )
    os.replace(f"{out}.tmp", out)
    print(f"Stored Okta requesting-client state in {out} (mode 0600).")


if __name__ == "__main__":
    main()
