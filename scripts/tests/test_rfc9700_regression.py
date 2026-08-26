import json
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar
from urllib.parse import parse_qs, urlsplit

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNNER = REPO_ROOT / "scripts" / "rfc9700_regression.py"


class CompliantIssuerHandler(BaseHTTPRequestHandler):
    registration_auth_methods: ClassVar[list[str | None]] = []
    requests: ClassVar[list[str]] = []

    def do_GET(self) -> None:
        type(self).requests.append(urlsplit(self.path).path)
        base_url = f"http://127.0.0.1:{self.server.server_port}"
        parsed = urlsplit(self.path)
        if parsed.path in {
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
        }:
            self.send_json(
                {
                    "issuer": base_url,
                    "authorization_endpoint": f"{base_url}/authorize",
                    "token_endpoint": f"{base_url}/token",
                    "jwks_uri": f"{base_url}/jwks.json",
                    "registration_endpoint": f"{base_url}/register",
                    "response_types_supported": ["code"],
                    "grant_types_supported": ["authorization_code", "refresh_token"],
                    "code_challenge_methods_supported": ["S256"],
                }
            )
            return
        if parsed.path == "/jwks.json":
            self.send_json({"keys": []})
            return
        if parsed.path == "/authorize":
            params = parse_qs(parsed.query)
            if params.get("redirect_uri") != ["https://suite.example/callback"]:
                self.send_text("invalid_request: redirect URI mismatch", status=400)
            elif params.get("response_type") == ["token"]:
                self.send_text("unsupported_response_type", status=400)
            elif params.get("code_challenge_method") == ["plain"] or (
                "code_challenge" not in params
                and getattr(self.server, "token_endpoint_auth_method", None) == "none"
            ):
                self.send_text("invalid_request: PKCE required", status=400)
            else:
                self.send_text("login page")
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:
        type(self).requests.append(urlsplit(self.path).path)
        path = urlsplit(self.path).path
        if path == "/register":
            base_url = f"http://127.0.0.1:{self.server.server_port}"
            request = json.loads(
                self.rfile.read(int(self.headers.get("content-length", "0")))
            )
            auth_method = request.get("token_endpoint_auth_method")
            type(self).registration_auth_methods.append(auth_method)
            self.server.token_endpoint_auth_method = auth_method
            response = {
                "client_id": "conformance-client",
                "token_endpoint_auth_method": auth_method,
                "registration_client_uri": (f"{base_url}/register/conformance-client"),
                "registration_access_token": "registration-token",
            }
            if auth_method != "none":
                response["client_secret"] = "replaceable-secret"
            self.send_json(response, status=201)
            return
        if path == "/token":
            form = parse_qs(
                self.rfile.read(int(self.headers.get("content-length", "0"))).decode()
            )
            if self.headers.get("authorization") is not None or form.get(
                "client_id"
            ) != ["conformance-client"]:
                self.send_json({"error": "invalid_client"}, status=400)
            else:
                self.send_json({"error": "unsupported_grant_type"}, status=400)
            return
        self.send_response(404)
        self.end_headers()

    def do_DELETE(self) -> None:
        type(self).requests.append(urlsplit(self.path).path)
        if urlsplit(self.path).path == "/register/conformance-client":
            self.send_response(204)
            self.end_headers()
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, _format: str, *_args) -> None:
        return

    def send_json(self, body: dict, *, status: int = 200) -> None:
        encoded = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def send_text(self, body: str, *, status: int = 200) -> None:
        encoded = body.encode()
        self.send_response(status)
        self.send_header("content-type", "text/plain; charset=utf-8")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


class ImplicitAcceptingIssuerHandler(CompliantIssuerHandler):
    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path == "/authorize":
            params = parse_qs(parsed.query)
            if params.get("response_type") == ["token"]:
                redirect_uri = params["redirect_uri"][0]
                body = b"unsupported_response_type"
                self.send_response(302)
                self.send_header(
                    "location",
                    f"{redirect_uri}#access_token=unsafe&token_type=Bearer",
                )
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
        super().do_GET()


class MissingCleanupCredentialsIssuerHandler(CompliantIssuerHandler):
    def do_POST(self) -> None:
        if urlsplit(self.path).path == "/register":
            self.send_json(
                {
                    "client_id": "conformance-client",
                    "client_secret": "replaceable-secret",
                },
                status=201,
            )
            return
        super().do_POST()


class CleanupFailingIssuerHandler(CompliantIssuerHandler):
    def do_DELETE(self) -> None:
        if urlsplit(self.path).path == "/register/conformance-client":
            self.send_json({"error": "temporarily_unavailable"}, status=503)
            return
        super().do_DELETE()


class RelativeRegistrationUriIssuerHandler(CompliantIssuerHandler):
    cleanup_requests = 0

    def do_POST(self) -> None:
        if urlsplit(self.path).path == "/register":
            self.send_json(
                {
                    "client_id": "conformance-client",
                    "client_secret": "replaceable-secret",
                    "registration_client_uri": "register/conformance-client",
                    "registration_access_token": "registration-token",
                },
                status=201,
            )
            return
        super().do_POST()

    def do_DELETE(self) -> None:
        type(self).cleanup_requests += 1
        super().do_DELETE()


class MalformedRegistrationUriIssuerHandler(CompliantIssuerHandler):
    cleanup_requests = 0

    def do_POST(self) -> None:
        if urlsplit(self.path).path == "/register":
            self.send_json(
                {
                    "client_id": "conformance-client",
                    "client_secret": "replaceable-secret",
                    "registration_client_uri": "https://[broken/register/client",
                    "registration_access_token": "registration-token",
                },
                status=201,
            )
            return
        super().do_POST()

    def do_DELETE(self) -> None:
        type(self).cleanup_requests += 1
        super().do_DELETE()


class UnsafeRequestRegistrationUriIssuerHandler(CompliantIssuerHandler):
    cleanup_requests = 0

    def do_POST(self) -> None:
        if urlsplit(self.path).path == "/register":
            base_url = f"http://127.0.0.1:{self.server.server_port}"
            self.send_json(
                {
                    "client_id": "conformance-client",
                    "client_secret": "replaceable-secret",
                    "registration_client_uri": (f"{base_url}/register/unsafe client"),
                    "registration_access_token": "registration-token",
                },
                status=201,
            )
            return
        super().do_POST()

    def do_DELETE(self) -> None:
        type(self).cleanup_requests += 1
        super().do_DELETE()


class CrossOriginRegistrationUriIssuerHandler(CompliantIssuerHandler):
    cleanup_requests = 0
    cleanup_authorizations: ClassVar[list[str | None]] = []

    def do_POST(self) -> None:
        if urlsplit(self.path).path == "/register":
            cross_origin_url = f"http://localhost:{self.server.server_port}"
            self.send_json(
                {
                    "client_id": "conformance-client",
                    "client_secret": "replaceable-secret",
                    "registration_client_uri": (
                        f"{cross_origin_url}/register/conformance-client"
                    ),
                    "registration_access_token": "registration-token",
                },
                status=201,
            )
            return
        super().do_POST()

    def do_DELETE(self) -> None:
        type(self).cleanup_requests += 1
        type(self).cleanup_authorizations.append(self.headers.get("authorization"))
        super().do_DELETE()


class CrossOriginEndpointIssuerHandler(CompliantIssuerHandler):
    registration_requests = 0

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path in {
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
        }:
            base_url = f"http://127.0.0.1:{self.server.server_port}"
            self.send_json(
                {
                    "issuer": base_url,
                    "authorization_endpoint": f"{base_url}/authorize",
                    "token_endpoint": f"{base_url}/token",
                    "jwks_uri": f"{base_url}/jwks.json",
                    "registration_endpoint": "http://127.0.0.1:9/register",
                    "response_types_supported": ["code"],
                    "grant_types_supported": ["authorization_code", "refresh_token"],
                    "code_challenge_methods_supported": ["S256"],
                }
            )
            return
        super().do_GET()

    def do_POST(self) -> None:
        type(self).registration_requests += 1
        super().do_POST()


class MissingClientIdIssuerHandler(CompliantIssuerHandler):
    cleanup_requests = 0

    def do_POST(self) -> None:
        if urlsplit(self.path).path == "/register":
            base_url = f"http://127.0.0.1:{self.server.server_port}"
            self.send_json(
                {
                    "client_secret": "replaceable-secret",
                    "registration_client_uri": (
                        f"{base_url}/register/conformance-client"
                    ),
                    "registration_access_token": "registration-token",
                },
                status=201,
            )
            return
        super().do_POST()

    def do_DELETE(self) -> None:
        type(self).cleanup_requests += 1
        super().do_DELETE()


class IncorrectRegistrationStatusIssuerHandler(CompliantIssuerHandler):
    cleanup_requests = 0

    def do_POST(self) -> None:
        if urlsplit(self.path).path == "/register":
            base_url = f"http://127.0.0.1:{self.server.server_port}"
            self.send_json(
                {
                    "client_id": "conformance-client",
                    "client_secret": "replaceable-secret",
                    "registration_client_uri": (
                        f"{base_url}/register/conformance-client"
                    ),
                    "registration_access_token": "registration-token",
                },
                status=200,
            )
            return
        super().do_POST()

    def do_DELETE(self) -> None:
        type(self).cleanup_requests += 1
        super().do_DELETE()


class Rfc9700RegressionCliTests(unittest.TestCase):
    def run_probe(
        self,
        handler: type[BaseHTTPRequestHandler],
        *,
        allowed_issuer_override: str | None = None,
    ):
        handler.registration_auth_methods = []
        handler.requests = []
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        issuer = f"http://127.0.0.1:{server.server_port}"
        try:
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "suite.json"
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(RUNNER),
                        "--issuer",
                        issuer,
                        "--allowed-issuer",
                        allowed_issuer_override or issuer,
                        "--redirect-uri",
                        "https://suite.example/callback",
                        "--source-version",
                        "abc123",
                        "--source-url",
                        "https://github.com/example/agent-auth/tree/abc123",
                        "--result-url",
                        "https://github.com/example/agent-auth/actions/runs/1",
                        "--allow-insecure-loopback",
                        "--output",
                        str(output),
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                suite = json.loads(output.read_text()) if output.exists() else None
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        return completed, suite

    def test_rejects_issuer_outside_configured_environment_before_network(
        self,
    ) -> None:
        completed, suite = self.run_probe(
            CompliantIssuerHandler,
            allowed_issuer_override="https://configured.example",
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIsNone(suite)
        self.assertIn("configured environment issuer", completed.stderr)
        self.assertEqual(CompliantIssuerHandler.requests, [])

    def test_selected_metadata_and_runtime_probes_pass(self) -> None:
        completed, suite = self.run_probe(CompliantIssuerHandler)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(CompliantIssuerHandler.registration_auth_methods, ["none"])
        self.assertEqual(suite["id"], "agent-auth-rfc9700")
        self.assertEqual(suite["kind"], "project-regression")
        self.assertIn(
            "not an OIDF certification suite", suite["non_certification_statement"]
        )
        self.assertGreaterEqual(len(suite["tests"]), 11)
        self.assertEqual({test["status"] for test in suite["tests"]}, {"passed"})
        standards = {test["id"]: test["standard"] for test in suite["tests"]}
        self.assertEqual(standards["dynamic-client-cleanup"], "RFC 7592")
        self.assertEqual(
            {
                standard
                for test_id, standard in standards.items()
                if test_id != "dynamic-client-cleanup"
            },
            {"RFC 9700"},
        )
        self.assertTrue(all(test["section"] for test in suite["tests"]))
        for field in ("request", "expected", "applicability", "observed"):
            self.assertTrue(all(test[field] for test in suite["tests"]))

    def test_runtime_implicit_acceptance_is_a_failure(self) -> None:
        completed, suite = self.run_probe(ImplicitAcceptingIssuerHandler)

        self.assertEqual(completed.returncode, 1)
        implicit = next(
            test for test in suite["tests"] if test["id"] == "runtime-reject-implicit"
        )
        self.assertEqual(implicit["status"], "failed")

    def test_missing_client_cleanup_credentials_fails_closed(self) -> None:
        completed, suite = self.run_probe(MissingCleanupCredentialsIssuerHandler)

        self.assertEqual(completed.returncode, 1)
        cleanup = next(
            test for test in suite["tests"] if test["id"] == "dynamic-client-cleanup"
        )
        self.assertEqual(cleanup["status"], "failed")
        self.assertIs(cleanup["waivable"], False)
        self.assertIn("omitted", cleanup["detail"])

    def test_client_cleanup_failure_is_non_waivable(self) -> None:
        completed, suite = self.run_probe(CleanupFailingIssuerHandler)

        self.assertEqual(completed.returncode, 1)
        cleanup = next(
            test for test in suite["tests"] if test["id"] == "dynamic-client-cleanup"
        )
        self.assertEqual(cleanup["status"], "failed")
        self.assertIs(cleanup["waivable"], False)
        self.assertEqual(cleanup["detail"], "HTTP 503")

    def test_relative_registration_client_uri_fails_but_is_cleaned_up(self) -> None:
        RelativeRegistrationUriIssuerHandler.cleanup_requests = 0
        completed, suite = self.run_probe(RelativeRegistrationUriIssuerHandler)

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(RelativeRegistrationUriIssuerHandler.cleanup_requests, 1)
        cleanup = next(
            test for test in suite["tests"] if test["id"] == "dynamic-client-cleanup"
        )
        self.assertEqual(cleanup["status"], "failed")
        self.assertIs(cleanup["waivable"], False)
        self.assertIn("not fully qualified", cleanup["detail"])
        self.assertIn("best-effort cleanup HTTP 204", cleanup["detail"])

    def test_malformed_registration_client_uri_fails_without_crashing(self) -> None:
        MalformedRegistrationUriIssuerHandler.cleanup_requests = 0
        completed, suite = self.run_probe(MalformedRegistrationUriIssuerHandler)

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(MalformedRegistrationUriIssuerHandler.cleanup_requests, 0)
        cleanup = next(
            test for test in suite["tests"] if test["id"] == "dynamic-client-cleanup"
        )
        self.assertEqual(cleanup["status"], "failed")
        self.assertIs(cleanup["waivable"], False)
        self.assertIn("malformed", cleanup["detail"])

    def test_unsafe_cleanup_request_fails_without_losing_evidence(self) -> None:
        UnsafeRequestRegistrationUriIssuerHandler.cleanup_requests = 0
        completed, suite = self.run_probe(UnsafeRequestRegistrationUriIssuerHandler)

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(UnsafeRequestRegistrationUriIssuerHandler.cleanup_requests, 0)
        cleanup = next(
            test for test in suite["tests"] if test["id"] == "dynamic-client-cleanup"
        )
        self.assertEqual(cleanup["status"], "failed")
        self.assertIs(cleanup["waivable"], False)
        self.assertIn("could not be requested safely", cleanup["detail"])

    def test_cross_origin_registration_client_uri_never_receives_bearer(self) -> None:
        CrossOriginRegistrationUriIssuerHandler.cleanup_requests = 0
        CrossOriginRegistrationUriIssuerHandler.cleanup_authorizations = []
        completed, suite = self.run_probe(CrossOriginRegistrationUriIssuerHandler)

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(CrossOriginRegistrationUriIssuerHandler.cleanup_requests, 0)
        self.assertEqual(
            CrossOriginRegistrationUriIssuerHandler.cleanup_authorizations, []
        )
        cleanup = next(
            test for test in suite["tests"] if test["id"] == "dynamic-client-cleanup"
        )
        self.assertEqual(cleanup["status"], "failed")
        self.assertIs(cleanup["waivable"], False)
        self.assertIn("did not preserve the issuer origin", cleanup["detail"])

    def test_cross_origin_discovery_endpoint_stops_before_registration(self) -> None:
        CrossOriginEndpointIssuerHandler.registration_requests = 0
        completed, suite = self.run_probe(CrossOriginEndpointIssuerHandler)

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(CrossOriginEndpointIssuerHandler.registration_requests, 0)
        preflight = next(
            test for test in suite["tests"] if test["id"] == "dynamic-client-preflight"
        )
        self.assertEqual(preflight["status"], "failed")
        self.assertIn("cross-origin", preflight["detail"])

    def test_created_client_without_client_id_is_still_cleaned_up(self) -> None:
        MissingClientIdIssuerHandler.cleanup_requests = 0
        completed, suite = self.run_probe(MissingClientIdIssuerHandler)

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(MissingClientIdIssuerHandler.cleanup_requests, 1)
        cleanup = next(
            test for test in suite["tests"] if test["id"] == "dynamic-client-cleanup"
        )
        self.assertEqual(cleanup["status"], "passed")

    def test_client_from_nonconforming_success_status_is_still_cleaned_up(self) -> None:
        IncorrectRegistrationStatusIssuerHandler.cleanup_requests = 0
        completed, suite = self.run_probe(IncorrectRegistrationStatusIssuerHandler)

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(IncorrectRegistrationStatusIssuerHandler.cleanup_requests, 1)
        cleanup = next(
            test for test in suite["tests"] if test["id"] == "dynamic-client-cleanup"
        )
        self.assertEqual(cleanup["status"], "passed")


if __name__ == "__main__":
    unittest.main()
