#!/usr/bin/env python3
"""Run agent-auth-owned black-box probes for selected RFC 9700 requirements."""

import argparse
import http.client
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def well_known(issuer: str, suffix: str) -> str:
    parsed = urllib.parse.urlsplit(issuer)
    path = parsed.path.rstrip("/")
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, f"/.well-known/{suffix}{path}", "", "")
    )


def request(
    url: str,
    *,
    form: dict[str, str] | None = None,
    json_body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    method: str | None = None,
) -> tuple[int, dict[str, str], bytes]:
    if form is not None and json_body is not None:
        raise ValueError("request accepts either form or json_body")
    body = None
    request_headers = {
        "accept": "application/json",
        "user-agent": "agent-auth-rfc9700-regression/1",
    }
    if form is not None:
        body = urllib.parse.urlencode(form).encode()
        request_headers["content-type"] = "application/x-www-form-urlencoded"
    elif json_body is not None:
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
    try:
        with OPENER.open(req, timeout=20) as response:
            return response.status, dict(response.headers.items()), response.read()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers.items()), error.read()
    except (TimeoutError, urllib.error.URLError) as error:
        return 0, {}, str(error).encode()


def parse_json(body: bytes) -> dict[str, Any]:
    try:
        value = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def load_json(url: str) -> tuple[int, dict[str, Any]]:
    status, _headers, body = request(url)
    return status, parse_json(body)


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


def trusted_endpoint(
    value: Any,
    *,
    issuer_origin: tuple[str, str, int],
    insecure_loopback: bool,
) -> bool:
    if not isinstance(value, str) or not value:
        return False
    origin = url_origin(value)
    if origin is None or origin != issuer_origin:
        return False
    return origin[0] == "https" or insecure_loopback


def result(
    test_id: str,
    section: str,
    passed: bool,
    detail: str,
    *,
    standard: str = "RFC 9700",
    request_summary: str,
    expected: str,
    applicability: str = "applicable to the selected agent-auth deployment",
    waivable: bool = True,
) -> dict[str, Any]:
    value = {
        "id": test_id,
        "status": "passed" if passed else "failed",
        "required": True,
        "standard": standard,
        "section": section,
        "request": request_summary,
        "expected": expected,
        "applicability": applicability,
        "observed": detail,
        "detail": detail,
    }
    if not waivable:
        value["waivable"] = False
    return value


def response_error(headers: dict[str, str], body: bytes) -> str | None:
    location = headers.get("Location") or headers.get("location")
    if location:
        parsed = urllib.parse.urlsplit(location)
        params = urllib.parse.parse_qs(f"{parsed.query}&{parsed.fragment}")
        values = params.get("error")
        return values[0] if values else None

    payload_error = parse_json(body).get("error")
    if isinstance(payload_error, str):
        return payload_error

    try:
        candidate = body.decode("utf-8").partition(":")[0].strip()
    except UnicodeDecodeError:
        return None
    return candidate if re.fullmatch(r"[a-z_]{1,64}", candidate) else None


def suite_document(
    *,
    source_version: str,
    source_url: str,
    result_url: str,
    tests: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "id": "agent-auth-rfc9700",
        "kind": "project-regression",
        "version": source_version,
        "source_url": source_url,
        "result_url": result_url,
        "metadata_and_runtime": True,
        "standard_url": "https://www.rfc-editor.org/rfc/rfc9700.html",
        "non_certification_statement": (
            "Project regression for selected RFC 9700 requirements; "
            "not an OIDF certification suite."
        ),
        "tests": tests,
    }


def write_suite(
    output: Path,
    *,
    source_version: str,
    source_url: str,
    result_url: str,
    tests: list[dict[str, Any]],
) -> int:
    output.write_text(
        json.dumps(
            suite_document(
                source_version=source_version,
                source_url=source_url,
                result_url=result_url,
                tests=tests,
            ),
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return 0 if all(test["status"] == "passed" for test in tests) else 1


def cleanup_dynamic_client(
    issuer: str,
    registration: dict[str, Any],
) -> dict[str, Any]:
    def delete_client(uri: str, access_token: str) -> int | None:
        try:
            status, _headers, _body = request(
                uri,
                headers={"authorization": f"Bearer {access_token}"},
                method="DELETE",
            )
            return status
        except (ValueError, UnicodeError, http.client.HTTPException):
            return None

    registration_client_uri = registration.get("registration_client_uri")
    registration_access_token = registration.get("registration_access_token")
    if not (
        isinstance(registration_client_uri, str)
        and isinstance(registration_access_token, str)
        and bool(registration_client_uri)
        and bool(registration_access_token)
    ):
        return result(
            "dynamic-client-cleanup",
            "3",
            False,
            "registration response omitted client management credentials",
            standard="RFC 7592",
            request_summary="DELETE the same-origin dynamic-client management URI",
            expected="client management credentials and HTTP 200 or 204",
            applicability="registration may have created a dynamic client",
            waivable=False,
        )

    try:
        parsed_cleanup_uri = urllib.parse.urlsplit(registration_client_uri)
    except ValueError:
        return result(
            "dynamic-client-cleanup",
            "3",
            False,
            "registration_client_uri was malformed",
            standard="RFC 7592",
            request_summary="DELETE the server-provided dynamic-client management URI",
            expected="valid fully qualified same-origin URI and HTTP 200 or 204",
            applicability="registration returned client management credentials",
            waivable=False,
        )

    issuer_origin = url_origin(issuer)
    cleanup_origin = url_origin(registration_client_uri)
    if cleanup_origin is None and not (
        parsed_cleanup_uri.scheme or parsed_cleanup_uri.netloc
    ):
        try:
            fallback_uri = urllib.parse.urljoin(f"{issuer}/", registration_client_uri)
        except ValueError:
            fallback_uri = ""
        fallback_origin = url_origin(fallback_uri)
        fallback_status = None
        if issuer_origin is not None and fallback_origin == issuer_origin:
            fallback_status = delete_client(fallback_uri, registration_access_token)
        return result(
            "dynamic-client-cleanup",
            "3",
            False,
            (
                "registration_client_uri was not fully qualified"
                if fallback_status is None
                else (
                    "registration_client_uri was not fully qualified; "
                    f"best-effort cleanup HTTP {fallback_status}"
                )
            ),
            standard="RFC 7592",
            request_summary="DELETE the server-provided dynamic-client management URI",
            expected="fully qualified same-origin URI and HTTP 200 or 204",
            applicability="registration returned client management credentials",
            waivable=False,
        )

    if issuer_origin is None or cleanup_origin != issuer_origin:
        return result(
            "dynamic-client-cleanup",
            "3",
            False,
            "registration_client_uri was invalid or did not preserve the issuer origin",
            standard="RFC 7592",
            request_summary="DELETE the same-origin dynamic-client management URI",
            expected="valid fully qualified client management URI preserves issuer origin",
            applicability="registration returned client management credentials",
            waivable=False,
        )

    cleanup_status = delete_client(registration_client_uri, registration_access_token)
    return result(
        "dynamic-client-cleanup",
        "3",
        cleanup_status in {200, 204},
        (
            f"HTTP {cleanup_status}"
            if cleanup_status is not None
            else "client management URI could not be requested safely"
        ),
        standard="RFC 7592",
        request_summary="DELETE the same-origin dynamic-client management URI",
        expected="HTTP 200 or 204",
        applicability="registration may have created a dynamic client",
        waivable=False,
    )


def run_public_client_probes(
    *,
    tests: list[dict[str, Any]],
    authorization_endpoint: str,
    token_endpoint: str,
    client_id: str,
    redirect_uri: str,
) -> None:
    common = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid",
        "state": "agent-auth-conformance",
    }

    def authorize_probe(
        test_id: str,
        section: str,
        expected_error: str,
        params: dict[str, str],
    ) -> None:
        url = f"{authorization_endpoint}?{urllib.parse.urlencode(params)}"
        status, headers, body = request(url)
        actual_error = response_error(headers, body)
        tests.append(
            result(
                test_id,
                section,
                status >= 300 and actual_error == expected_error,
                f"HTTP {status}; error={actual_error!r}",
                request_summary=(
                    f"GET authorization endpoint for negative probe {test_id}"
                ),
                expected=f"authorization is rejected with {expected_error}",
            )
        )

    authorize_probe(
        "runtime-reject-missing-pkce",
        "2.1.1",
        "invalid_request",
        {**common, "response_type": "code"},
    )
    authorize_probe(
        "runtime-reject-plain-pkce",
        "2.1.1",
        "invalid_request",
        {
            **common,
            "response_type": "code",
            "code_challenge": "a" * 43,
            "code_challenge_method": "plain",
        },
    )
    authorize_probe(
        "runtime-reject-implicit",
        "2.1.2",
        "unsupported_response_type",
        {**common, "response_type": "token"},
    )

    mismatched_redirect = f"{redirect_uri.rstrip('/')}/not-registered"
    mismatch_url = f"{authorization_endpoint}?{
        urllib.parse.urlencode(
            {
                **common,
                'redirect_uri': mismatched_redirect,
                'response_type': 'code',
                'code_challenge': 'a' * 43,
                'code_challenge_method': 'S256',
            }
        )
    }"
    mismatch_status, mismatch_headers, mismatch_body = request(mismatch_url)
    mismatch_location = (
        mismatch_headers.get("Location") or mismatch_headers.get("location") or ""
    )
    tests.append(
        result(
            "runtime-reject-redirect-mismatch",
            "4.1.3",
            mismatch_status >= 400
            and response_error(mismatch_headers, mismatch_body) == "invalid_request"
            and not mismatch_location.startswith(mismatched_redirect),
            f"HTTP {mismatch_status}; redirected={bool(mismatch_location)}",
            request_summary=(
                "GET authorization endpoint with an unregistered redirect URI"
            ),
            expected=(
                "HTTP error invalid_request without redirecting to the unregistered URI"
            ),
        )
    )

    password_status, password_headers, password_body = request(
        token_endpoint,
        form={
            "grant_type": "password",
            "client_id": client_id,
            "username": "not-a-user",
            "password": "not-a-password",
        },
    )
    tests.append(
        result(
            "runtime-reject-password-grant",
            "2.4",
            password_status >= 400
            and response_error(password_headers, password_body)
            == "unsupported_grant_type",
            f"HTTP {password_status}",
            request_summary="POST token endpoint with grant_type=password",
            expected="HTTP error unsupported_grant_type",
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--allowed-issuer", required=True)
    parser.add_argument("--redirect-uri", required=True)
    parser.add_argument("--source-version", required=True)
    parser.add_argument("--source-url", required=True)
    parser.add_argument("--result-url", required=True)
    parser.add_argument("--allow-insecure-loopback", action="store_true")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    issuer = args.issuer.rstrip("/")
    try:
        parsed_issuer = urllib.parse.urlsplit(issuer)
    except ValueError:
        parser.error("--issuer must be a valid HTTPS URL")
    insecure_loopback = (
        args.allow_insecure_loopback
        and parsed_issuer.scheme == "http"
        and parsed_issuer.hostname in {"127.0.0.1", "::1", "localhost"}
    )
    issuer_origin = url_origin(issuer)
    if (
        issuer_origin is None
        or (issuer_origin[0] != "https" and not insecure_loopback)
        or parsed_issuer.query
    ):
        parser.error("--issuer must be a valid HTTPS URL without query or fragment")
    allowed_issuer = args.allowed_issuer.rstrip("/")
    try:
        parsed_allowed_issuer = urllib.parse.urlsplit(allowed_issuer)
    except ValueError:
        parser.error("--allowed-issuer must be a valid HTTPS URL")
    allowed_insecure_loopback = (
        args.allow_insecure_loopback
        and parsed_allowed_issuer.scheme == "http"
        and parsed_allowed_issuer.hostname in {"127.0.0.1", "::1", "localhost"}
    )
    allowed_origin = url_origin(allowed_issuer)
    if (
        allowed_origin is None
        or (allowed_origin[0] != "https" and not allowed_insecure_loopback)
        or parsed_allowed_issuer.query
    ):
        parser.error(
            "--allowed-issuer must be a valid HTTPS URL without query or fragment"
        )
    if issuer != allowed_issuer:
        parser.error("--issuer must match the configured environment issuer")

    tests: list[dict[str, Any]] = []
    oidc_status, oidc = load_json(well_known(issuer, "openid-configuration"))
    oauth_status, oauth = load_json(well_known(issuer, "oauth-authorization-server"))
    tests.append(
        result(
            "oidc-discovery-issuer",
            "2.6",
            oidc_status == 200 and oidc.get("issuer") == issuer,
            f"HTTP {oidc_status}; issuer={oidc.get('issuer')!r}",
            request_summary="GET OIDC discovery metadata",
            expected="HTTP 200 with issuer exactly matching the selected issuer",
        )
    )
    tests.append(
        result(
            "oauth-metadata-issuer",
            "2.6",
            oauth_status == 200 and oauth.get("issuer") == issuer,
            f"HTTP {oauth_status}; issuer={oauth.get('issuer')!r}",
            request_summary="GET OAuth authorization-server metadata",
            expected="HTTP 200 with issuer exactly matching the selected issuer",
        )
    )

    endpoints = [
        oidc.get("authorization_endpoint"),
        oidc.get("token_endpoint"),
        oidc.get("jwks_uri"),
        oidc.get("registration_endpoint"),
    ]
    endpoints_secure = all(
        trusted_endpoint(
            endpoint,
            issuer_origin=issuer_origin,
            insecure_loopback=insecure_loopback,
        )
        for endpoint in endpoints
    )
    tests.append(
        result(
            "metadata-secure-endpoints",
            "2.6",
            endpoints_secure,
            (
                "authorization, token, JWKS, and registration endpoints are "
                "valid and preserve the issuer origin"
            ),
            request_summary="Inspect endpoints in OIDC discovery metadata",
            expected="valid same-origin HTTPS endpoint URLs",
        )
    )
    challenge_methods = oidc.get("code_challenge_methods_supported", [])
    tests.append(
        result(
            "metadata-pkce-s256-only",
            "2.1.1",
            "S256" in challenge_methods and "plain" not in challenge_methods,
            f"code_challenge_methods_supported={challenge_methods!r}",
            request_summary="Inspect code_challenge_methods_supported",
            expected="S256 is advertised and plain is not advertised",
        )
    )
    response_types = oidc.get("response_types_supported", [])
    tests.append(
        result(
            "metadata-no-implicit",
            "2.1.2",
            "code" in response_types
            and all("token" not in value for value in response_types),
            f"response_types_supported={response_types!r}",
            request_summary="Inspect response_types_supported",
            expected="code is advertised and implicit token response types are absent",
        )
    )
    grant_types = oidc.get("grant_types_supported", [])
    tests.append(
        result(
            "metadata-no-password-grant",
            "2.4",
            "password" not in grant_types,
            f"grant_types_supported={grant_types!r}",
            request_summary="Inspect grant_types_supported",
            expected="password is not advertised",
        )
    )

    authorization_endpoint = oidc.get("authorization_endpoint")
    token_endpoint = oidc.get("token_endpoint")
    registration_endpoint = oidc.get("registration_endpoint")
    runtime_endpoints_valid = endpoints_secure and all(
        isinstance(value, str)
        for value in (authorization_endpoint, token_endpoint, registration_endpoint)
    )
    if not runtime_endpoints_valid:
        tests.append(
            result(
                "dynamic-client-preflight",
                "2.1",
                False,
                (
                    "discovery returned a missing, malformed, cross-origin, "
                    "or insecure runtime endpoint"
                ),
                request_summary="Validate discovery runtime endpoints before probing",
                expected="authorization, token, and registration endpoints are trusted",
            )
        )
        return write_suite(
            args.output,
            source_version=args.source_version,
            source_url=args.source_url,
            result_url=args.result_url,
            tests=tests,
        )

    registration_status, _headers, registration_body = request(
        registration_endpoint,
        json_body={
            "client_name": "agent-auth RFC 9700 release regression",
            "redirect_uris": [args.redirect_uri],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        },
        method="POST",
    )
    registration = parse_json(registration_body)
    client_id = registration.get("client_id")
    registered = (
        registration_status == 201
        and isinstance(client_id, str)
        and bool(client_id)
        and registration.get("token_endpoint_auth_method") == "none"
        and not registration.get("client_secret")
    )
    has_management_credentials = all(
        isinstance(registration.get(field), str) and bool(registration[field])
        for field in ("registration_client_uri", "registration_access_token")
    )
    cleanup_required = 200 <= registration_status < 300 or has_management_credentials
    tests.append(
        result(
            "dynamic-client-preflight",
            "2.1",
            registered,
            f"HTTP {registration_status}; public client created={registered}",
            request_summary=(
                "POST registration endpoint for a public authorization-code client"
            ),
            expected=(
                "HTTP 201 with non-empty client_id, token endpoint auth method none, "
                "and no client secret"
            ),
        )
    )
    if cleanup_required:
        try:
            if registered:
                run_public_client_probes(
                    tests=tests,
                    authorization_endpoint=authorization_endpoint,
                    token_endpoint=token_endpoint,
                    client_id=client_id,
                    redirect_uri=args.redirect_uri,
                )
        finally:
            tests.append(cleanup_dynamic_client(issuer, registration))

    return write_suite(
        args.output,
        source_version=args.source_version,
        source_url=args.source_url,
        result_url=args.result_url,
        tests=tests,
    )


if __name__ == "__main__":
    raise SystemExit(main())
