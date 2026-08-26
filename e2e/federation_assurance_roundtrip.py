#!/usr/bin/env python3
"""Drive the live C9.5 Cognito round trip without printing credentials."""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.parse as urlparse
from pathlib import Path

import requests


AS_URL = os.environ["AS_URL"].rstrip("/")
COGNITO_DOMAIN = os.environ["COGNITO_DOMAIN"].rstrip("/")
DOWN_CLIENT_ID = os.environ["DOWN_CLIENT_ID"]
DOWN_REDIRECT = os.environ["DOWN_REDIRECT"]
IDP = os.environ["UPSTREAM_IDP_ID"]
TEST_USER = os.environ["TEST_USER"]
TEST_PASSWORD_FILE = Path(os.environ["TEST_PASSWORD_FILE"])
RESULT_FILE = Path(os.environ["RESULT_FILE"])
RECOVERY_FILE = Path(os.environ["RECOVERY_FILE"])
EXPECTED_STRONG_ACR = os.environ["EXPECTED_STRONG_ACR"]
EXPECTED_STRONG_MAX_AGE = os.environ.get("EXPECTED_STRONG_MAX_AGE", "300")
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
SESSION_COOKIE = "__Host-agent_auth_session"


def persist_recovery(*, flow_state: str | None = None, session_id: str | None = None) -> None:
    recovery = {"flow_states": [], "session_id": ""}
    if RECOVERY_FILE.exists():
        recovery.update(json.loads(RECOVERY_FILE.read_text(encoding="utf-8")))
    if flow_state and flow_state not in recovery["flow_states"]:
        recovery["flow_states"].append(flow_state)
    if session_id:
        recovery["session_id"] = session_id
    RECOVERY_FILE.write_text(json.dumps(recovery, sort_keys=True), encoding="utf-8")


def fail(message: str) -> None:
    raise RuntimeError(message)


def assert_downstream_error(
    response: requests.Response, *, error: str, state: str
) -> None:
    location = response.headers.get("location", "")
    parsed = urlparse.urlparse(location)
    expected = urlparse.urlparse(DOWN_REDIRECT)
    if (
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
    ) != (
        expected.scheme,
        expected.netloc,
        expected.path,
        expected.params,
    ):
        fail(f"{error} was not returned to the registered downstream redirect")
    query = urlparse.parse_qs(parsed.query)
    if query.get("error") != [error] or query.get("state") != [state]:
        fail(f"{error} did not preserve the exact downstream state")


def authorize_url(*, state: str, extra: dict[str, str] | None = None) -> str:
    query = {
        "response_type": "code",
        "client_id": DOWN_CLIENT_ID,
        "redirect_uri": DOWN_REDIRECT,
        "code_challenge": CHALLENGE,
        "code_challenge_method": "S256",
        "scope": "openid",
        "state": state,
    }
    if extra:
        query.update(extra)
    return f"{AS_URL}/authorize?{urlparse.urlencode(query)}"


def cognito_login(session: requests.Session, location: str) -> str:
    response = session.get(location, timeout=30)

    csrf = re.search(r'name="_csrf" value="([^"]*)"', response.text)
    action = re.search(r'action="(/login[^"]*)"', response.text)
    if not csrf or not action:
        fail("Cognito login page did not expose the expected CSRF form")

    password = TEST_PASSWORD_FILE.read_text(encoding="utf-8")
    response = session.post(
        COGNITO_DOMAIN + action.group(1).replace("&amp;", "&"),
        data={
            "_csrf": csrf.group(1),
            "username": TEST_USER,
            "password": password,
        },
        allow_redirects=False,
        timeout=30,
    )
    callback = response.headers.get("location", "")
    if response.status_code not in (302, 303):
        fail(f"Cognito login returned HTTP {response.status_code}")
    if not callback.startswith(f"{AS_URL}/federation/callback") or "code=" not in callback:
        fail("Cognito login did not return an authorization code to Agent Auth")
    return callback


def begin_federation(session: requests.Session, *, state: str, strong: bool) -> tuple[str, str]:
    extra = {"idp_hint": IDP}
    if strong:
        extra["acr_values"] = "urn:agent-auth:assurance:strong"
    response = session.get(
        authorize_url(state=state, extra=extra),
        allow_redirects=False,
        timeout=30,
    )
    upstream = response.headers.get("location", "")
    if response.status_code != 303 or not upstream.startswith(COGNITO_DOMAIN):
        fail(f"Agent Auth did not redirect to Cognito (HTTP {response.status_code})")
    flow_state = urlparse.parse_qs(urlparse.urlparse(upstream).query).get("state", [""])[0]
    if not flow_state:
        fail("upstream authorization request omitted state")
    persist_recovery(flow_state=flow_state)
    upstream_query = urlparse.parse_qs(urlparse.urlparse(upstream).query)
    if strong:
        if upstream_query.get("acr_values") != [EXPECTED_STRONG_ACR]:
            fail("strong flow did not forward the configured upstream ACR")
        if upstream_query.get("prompt") != ["login"]:
            fail("strong flow did not force upstream reauthentication")
        if upstream_query.get("max_age") != [EXPECTED_STRONG_MAX_AGE]:
            fail("strong flow did not forward the effective max_age")
    return cognito_login(session, upstream), flow_state


def callback_baseline() -> tuple[requests.Session, str, str]:
    session = requests.Session()
    callback, flow_state = begin_federation(session, state="baseline", strong=False)
    response = session.get(callback, allow_redirects=False, timeout=30)
    if response.status_code != 303:
        fail(f"baseline callback returned HTTP {response.status_code}")
    if SESSION_COOKIE not in session.cookies:
        fail("baseline callback did not establish an Agent Auth session")
    persist_recovery(session_id=session.cookies.get(SESSION_COOKIE, ""))
    continuation = response.headers.get("location", "")
    if "/authorize" not in continuation:
        fail("baseline callback did not continue the downstream request")
    response = session.get(continuation, allow_redirects=False, timeout=30)
    location = response.headers.get("location", "")
    if response.status_code != 303 or "/consent" not in location:
        fail("baseline session was not recognized by downstream authorization")
    return session, flow_state, session.cookies.get(SESSION_COOKIE, "")


def callback_strong_negative() -> str:
    session = requests.Session()
    callback, flow_state = begin_federation(session, state="strong-negative", strong=True)
    response = session.get(callback, allow_redirects=False, timeout=30)
    if response.status_code != 303:
        fail(f"strong-negative callback returned HTTP {response.status_code}")
    assert_downstream_error(
        response,
        error="unmet_authentication_requirements",
        state="strong-negative",
    )
    if SESSION_COOKIE in session.cookies:
        fail("failed strong authentication unexpectedly established a local session")
    return flow_state


def assert_prompt_and_max_age(session: requests.Session) -> dict[str, bool]:
    no_session = requests.Session().get(
        authorize_url(state="prompt-none-no-session", extra={"prompt": "none"}),
        allow_redirects=False,
        timeout=30,
    )
    if no_session.status_code != 303:
        fail("prompt=none without a session did not return login_required")
    assert_downstream_error(
        no_session,
        error="login_required",
        state="prompt-none-no-session",
    )

    prompt_none = session.get(
        authorize_url(state="prompt-none-session", extra={"prompt": "none"}),
        allow_redirects=False,
        timeout=30,
    )
    if prompt_none.status_code != 303:
        fail("prompt=none with no reusable consent did not return consent_required")
    assert_downstream_error(
        prompt_none,
        error="consent_required",
        state="prompt-none-session",
    )

    prompt_login = session.get(
        authorize_url(state="prompt-login", extra={"prompt": "login"}),
        allow_redirects=False,
        timeout=30,
    )
    if prompt_login.status_code != 303 or "/login?" not in prompt_login.headers.get(
        "location", ""
    ):
        fail("prompt=login did not force reauthentication")

    max_age = session.get(
        authorize_url(state="max-age", extra={"max_age": "0"}),
        allow_redirects=False,
        timeout=30,
    )
    if max_age.status_code != 303 or "/login?" not in max_age.headers.get("location", ""):
        fail("max_age=0 did not force reauthentication")

    return {
        "prompt_none_no_session_login_required": True,
        "prompt_none_no_consent_consent_required": True,
        "prompt_login_reauthentication": True,
        "max_age_zero_reauthentication": True,
    }


def main() -> None:
    persist_recovery()
    baseline_session, baseline_flow_state, session_id = callback_baseline()
    if not session_id:
        fail("Agent Auth session cookie was empty")
    prompt_results = assert_prompt_and_max_age(baseline_session)
    strong_flow_state = callback_strong_negative()
    result = {
        "baseline_roundtrip": True,
        "strong_without_trusted_acr_rejected": True,
        "upstream_strong_parameters_forwarded": True,
        "session_id": session_id,
        "flow_states": [baseline_flow_state, strong_flow_state],
        **prompt_results,
    }
    RESULT_FILE.write_text(json.dumps(result, sort_keys=True), encoding="utf-8")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:  # noqa: BLE001 - fail with a sanitized message
        print(f"federation assurance round trip failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
