#!/usr/bin/env python3
"""Real Cognito Hosted UI round trips for e2e/admin_sso.sh."""

import html
import json
import os
import sys
import time
import urllib.parse as urlparse
from html.parser import HTMLParser
from pathlib import Path

import requests


TARGETS = json.loads(Path(os.environ["ADMIN_SSO_TARGETS_FILE"]).read_text())
USER = os.environ["TEST_USER"]
PASSWORD = Path(os.environ["TEST_PASSWORD_FILE"]).read_text().strip()
FLOW_COOKIE = "__Host-agent_auth_admin_oidc_flow"
SESSION_COOKIE = "__Host-agent_auth_admin_session"


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


class LoginFormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_login_form = False
        self.action = None
        self.fields = {}

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "form" and "/login" in values.get("action", ""):
            self.in_login_form = True
            self.action = html.unescape(values["action"])
        elif self.in_login_form and tag == "input":
            name = values.get("name")
            if name:
                self.fields[name] = values.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form" and self.in_login_form:
            self.in_login_form = False


def login(target):
    name = target["name"]
    base = target["base_url"].rstrip("/")
    session = requests.Session()

    start = session.get(
        f"{base}/admin/sso/start", allow_redirects=False, timeout=30
    )
    location = start.headers.get("location", "")
    if start.status_code != 303 or not location.startswith("https://"):
        fail(f"{name}: start expected 303 to HTTPS IdP, got {start.status_code}")
    if not session.cookies.get(FLOW_COOKIE):
        fail(f"{name}: start did not set the browser-binding flow cookie")

    page = None
    parser = None
    for attempt in range(6):
        page = session.get(location, timeout=30)
        parser = LoginFormParser()
        parser.feed(page.text)
        if page.status_code == 200 and parser.action:
            break
        time.sleep(attempt + 1)
    if page is None or parser is None or not parser.action:
        fail(f"{name}: Cognito login form was not available")

    fields = parser.fields
    fields.update({"username": USER, "password": PASSWORD})
    login_url = urlparse.urljoin(page.url, parser.action)
    submitted = session.post(
        login_url, data=fields, allow_redirects=False, timeout=30
    )
    callback = submitted.headers.get("location", "")
    expected_callback = f"{base}/admin/sso/callback"
    if (
        submitted.status_code not in (302, 303)
        or not callback.startswith(expected_callback)
        or "code=" not in callback
        or "state=" not in callback
    ):
        fail(
            f"{name}: Cognito login did not return code/state to the exact callback "
            f"(status {submitted.status_code})"
        )

    completed = session.get(callback, allow_redirects=False, timeout=30)
    if completed.status_code != 303:
        fail(
            f"{name}: Admin callback expected 303, got {completed.status_code}: "
            f"{completed.text[:160]}"
        )
    if completed.headers.get("location") != f"{base}/admin":
        fail(f"{name}: callback did not return to the same tenant Admin origin")
    raw_session = session.cookies.get(SESSION_COOKIE)
    if not raw_session:
        fail(f"{name}: callback did not create an Admin session cookie")
    if session.cookies.get(FLOW_COOKIE):
        fail(f"{name}: callback did not clear the one-time flow cookie")

    identity = session.get(f"{base}/admin/session", timeout=30)
    if identity.status_code != 200:
        fail(f"{name}: session status returned {identity.status_code}")
    body = identity.json()
    if (
        body.get("tenant_id") != ("default" if name == "dev" else name)
        or body.get("role") != target["role"]
        or body.get("auth_type") != "oidc_session"
        or not body.get("actor", "").startswith("admin-user:")
    ):
        fail(f"{name}: attributable session response is incorrect: {body}")
    expires_at = body.get("expires_at")
    now = int(time.time())
    if not isinstance(expires_at, int) or not (now < expires_at <= now + 900):
        fail(f"{name}: session expiry is not bounded to 15 minutes")

    readable = session.get(f"{base}/admin/clients", timeout=30)
    if readable.status_code != 200:
        fail(f"{name}: role {target['role']} could not read tenant clients")
    write = session.delete(
        f"{base}/admin/clients/admin-sso-live-missing", timeout=30
    )
    expected_write = 403 if target["role"] == "auditor" else 404
    if write.status_code != expected_write:
        fail(
            f"{name}: role {target['role']} write expected {expected_write}, "
            f"got {write.status_code}"
        )

    if target["role"] == "owner":
        config_before = session.get(f"{base}/admin/oidc", timeout=30)
        if config_before.status_code != 200:
            fail(f"{name}: owner could not read Admin OIDC config before step-up")
        before = config_before.json()
        denied = session.delete(
            f"{base}/admin/oidc",
            params={"expected_revision": before["revision"]},
            timeout=30,
        )
        challenge = denied.headers.get("www-authenticate", "")
        if (
            denied.status_code != 401
            or 'error="insufficient_user_authentication"' not in challenge
            or 'acr_values="urn:agent-auth:assurance:strong"' not in challenge
            or 'max_age="300"' not in challenge
        ):
            fail(
                f"{name}: baseline Cognito owner did not receive the RFC 9470 "
                f"challenge ({denied.status_code}, {challenge})"
            )
        config_after = session.get(f"{base}/admin/oidc", timeout=30)
        if config_after.status_code != 200 or config_after.json() != before:
            fail(f"{name}: rejected step-up mutation changed Admin OIDC config")

        step_up = session.get(
            f"{base}/admin/sso/start",
            params={
                "acr_values": "urn:agent-auth:assurance:strong",
                "max_age": "300",
            },
            allow_redirects=False,
            timeout=30,
        )
        upstream = urlparse.urlparse(step_up.headers.get("location", ""))
        upstream_query = urlparse.parse_qs(upstream.query)
        if (
            step_up.status_code != 303
            or upstream_query.get("acr_values")
            != ["urn:agent-auth:e2e:cognito-mfa"]
            or upstream_query.get("max_age") != ["300"]
        ):
            fail(f"{name}: Admin step-up requirements were not forwarded upstream")
        print(
            f"PASS: {name} baseline Cognito owner was challenged before mutation; "
            "canonical strong ACR mapped to the configured upstream ACR"
        )

    print(
        f"PASS: {name} real OIDC login created attributable "
        f"{target['role']} session and enforced write policy"
    )
    return {"target": target, "session": session, "raw_session": raw_session}


logins = [login(target) for target in TARGETS]
by_name = {item["target"]["name"]: item for item in logins}

cross = requests.get(
    f"{by_name['t2']['target']['base_url']}/admin/session",
    headers={"Cookie": f"{SESSION_COOKIE}={by_name['t1']['raw_session']}"},
    timeout=30,
)
if cross.status_code != 401:
    fail(f"t1 session cookie on t2 expected 401, got {cross.status_code}")
print("PASS: t1 Admin session cookie is rejected by t2")

for item in logins:
    name = item["target"]["name"]
    base = item["target"]["base_url"].rstrip("/")
    session = item["session"]
    logged_out = session.post(f"{base}/admin/logout", timeout=30)
    if logged_out.status_code != 204:
        fail(f"{name}: logout expected 204, got {logged_out.status_code}")
    stale = session.get(f"{base}/admin/session", timeout=30)
    if stale.status_code != 401:
        fail(f"{name}: destroyed session remained usable ({stale.status_code})")
    print(f"PASS: {name} logout persistently destroyed the Admin session")
