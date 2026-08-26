import json
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar
from urllib.parse import urlsplit

REPO_ROOT = Path(__file__).resolve().parents[2]
PREFLIGHT = REPO_ROOT / "scripts" / "oidf_iat_preflight.py"


class IatIssuerHandler(BaseHTTPRequestHandler):
    requests: ClassVar[list[str]] = []
    registration_authorizations: ClassVar[list[str | None]] = []
    cleanup_authorizations: ClassVar[list[str | None]] = []
    registration_status = 201
    cleanup_statuses: ClassVar[list[int]] = [204]
    cleanup_disconnects = 0
    cross_origin_cleanup = False
    registration_redirect_url: ClassVar[str | None] = None
    cleanup_redirect_url: ClassVar[str | None] = None

    def do_GET(self) -> None:
        type(self).requests.append(urlsplit(self.path).path)
        base_url = f"http://127.0.0.1:{self.server.server_port}"
        if urlsplit(self.path).path == "/.well-known/openid-configuration":
            self.send_json(
                {
                    "issuer": base_url,
                    "registration_endpoint": f"{base_url}/register",
                }
            )
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:
        type(self).requests.append(urlsplit(self.path).path)
        if urlsplit(self.path).path != "/register":
            self.send_response(404)
            self.end_headers()
            return
        type(self).registration_authorizations.append(self.headers.get("authorization"))
        if type(self).registration_redirect_url is not None:
            self.send_response(307)
            self.send_header("location", type(self).registration_redirect_url)
            self.end_headers()
            return
        if type(self).registration_status != 201:
            self.send_json(
                {"error": "invalid_token"},
                status=type(self).registration_status,
            )
            return
        base_url = f"http://127.0.0.1:{self.server.server_port}"
        cleanup_uri = (
            "http://127.0.0.1:1/register/unsafe"
            if type(self).cross_origin_cleanup
            else f"{base_url}/register/preflight-client"
        )
        self.send_json(
            {
                "client_id": "preflight-client",
                "registration_client_uri": cleanup_uri,
                "registration_access_token": "registration-token",
            },
            status=201,
        )

    def do_DELETE(self) -> None:
        type(self).requests.append(urlsplit(self.path).path)
        if urlsplit(self.path).path != "/register/preflight-client":
            self.send_response(404)
            self.end_headers()
            return
        type(self).cleanup_authorizations.append(self.headers.get("authorization"))
        if type(self).cleanup_disconnects > 0:
            type(self).cleanup_disconnects -= 1
            self.close_connection = True
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.connection.close()
            return
        if type(self).cleanup_redirect_url is not None:
            self.send_response(307)
            self.send_header("location", type(self).cleanup_redirect_url)
            self.end_headers()
            return
        statuses = type(self).cleanup_statuses
        status = statuses.pop(0) if len(statuses) > 1 else statuses[0]
        self.send_json(
            {"status": "deleted"},
            status=status,
        )

    def log_message(self, _format: str, *_args) -> None:
        return

    def send_json(self, body: dict, *, status: int = 200) -> None:
        encoded = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


class OidfIatPreflightCliTests(unittest.TestCase):
    def run_preflight(
        self,
        *,
        registration_status: int = 201,
        cleanup_statuses: tuple[int, ...] = (204,),
        cleanup_disconnects: int = 0,
        cross_origin_cleanup: bool = False,
        second_token: str = "iat_primary.secret-value",
        registration_redirect_url: str | None = None,
        cleanup_redirect_url: str | None = None,
        allowed_issuer_override: str | None = None,
    ):
        IatIssuerHandler.requests = []
        IatIssuerHandler.registration_authorizations = []
        IatIssuerHandler.cleanup_authorizations = []
        IatIssuerHandler.registration_status = registration_status
        IatIssuerHandler.cleanup_statuses = list(cleanup_statuses)
        IatIssuerHandler.cleanup_disconnects = cleanup_disconnects
        IatIssuerHandler.cross_origin_cleanup = cross_origin_cleanup
        IatIssuerHandler.registration_redirect_url = registration_redirect_url
        IatIssuerHandler.cleanup_redirect_url = cleanup_redirect_url
        server = ThreadingHTTPServer(("127.0.0.1", 0), IatIssuerHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        issuer = f"http://127.0.0.1:{server.server_port}"
        config = {
            "server": {"discoveryUrl": f"{issuer}/.well-known/openid-configuration"},
            "client": {
                "initial_access_token": "iat_primary.secret-value",
            },
            "client2": {
                "initial_access_token": second_token,
            },
        }
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                config_path = root / "config.json"
                summary_path = root / "summary.json"
                config_path.write_text(json.dumps(config), encoding="utf-8")
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(PREFLIGHT),
                        "--config",
                        str(config_path),
                        "--issuer",
                        issuer,
                        "--allowed-issuer",
                        allowed_issuer_override or issuer,
                        "--redirect-uri",
                        (
                            "https://www.certification.openid.net/test/a/"
                            "agent-auth-iat-preflight/callback"
                        ),
                        "--summary",
                        str(summary_path),
                        "--allow-insecure-loopback",
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                summary = (
                    json.loads(summary_path.read_text(encoding="utf-8"))
                    if summary_path.exists()
                    else None
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        return completed, summary

    def test_rejects_issuer_outside_configured_environment_before_network(
        self,
    ) -> None:
        completed, summary = self.run_preflight(
            allowed_issuer_override="https://configured.example",
        )

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(summary["status"], "failed")
        self.assertIn("configured environment issuer", summary["error"])
        self.assertEqual(IatIssuerHandler.requests, [])

    def test_reuses_shared_iat_and_cleans_up_disposable_client(self) -> None:
        completed, summary = self.run_preflight()

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            IatIssuerHandler.registration_authorizations,
            ["Bearer iat_primary.secret-value"],
        )
        self.assertEqual(
            IatIssuerHandler.cleanup_authorizations,
            ["Bearer registration-token"],
        )
        self.assertEqual(summary["status"], "passed")
        self.assertEqual(summary["probe_count"], 1)
        self.assertEqual(summary["probes"][0]["slots"], ["client", "client2"])
        self.assertEqual(summary["probes"][0]["registration_status"], 201)
        self.assertEqual(summary["probes"][0]["cleanup_status"], 204)
        self.assertEqual(summary["probes"][0]["cleanup_attempts"], 1)
        rendered = json.dumps(summary)
        self.assertNotIn("iat_primary", rendered)
        self.assertNotIn("secret-value", rendered)
        self.assertNotIn("registration-token", rendered)

    def test_invalid_iat_fails_before_oidf_with_actionable_status(self) -> None:
        completed, summary = self.run_preflight(registration_status=401)

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(IatIssuerHandler.cleanup_authorizations, [])
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(summary["probes"][0]["registration_status"], 401)
        self.assertIn("invalid_token", summary["error"])
        self.assertIn("rotate OIDF_BASIC_OP_CONFIG_JSON", completed.stderr)
        self.assertNotIn("secret-value", json.dumps(summary))
        self.assertNotIn("secret-value", completed.stderr)

    def test_cross_origin_cleanup_uri_never_receives_bearer(self) -> None:
        completed, summary = self.run_preflight(cross_origin_cleanup=True)

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(IatIssuerHandler.cleanup_authorizations, [])
        self.assertEqual(summary["status"], "failed")
        self.assertIn("same origin", summary["error"])

    def test_cleanup_failure_fails_closed(self) -> None:
        completed, summary = self.run_preflight(cleanup_statuses=(503,))

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(summary["probes"][0]["cleanup_status"], 503)
        self.assertEqual(summary["probes"][0]["cleanup_attempts"], 3)
        self.assertIn("cleanup returned HTTP 503 after 3 attempts", summary["error"])

    def test_cleanup_retries_transient_failure_until_deleted(self) -> None:
        completed, summary = self.run_preflight(cleanup_statuses=(503, 204))

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(summary["status"], "passed")
        self.assertEqual(summary["probes"][0]["cleanup_status"], 204)
        self.assertEqual(summary["probes"][0]["cleanup_attempts"], 2)
        self.assertEqual(
            IatIssuerHandler.cleanup_authorizations,
            ["Bearer registration-token", "Bearer registration-token"],
        )

    def test_cleanup_retries_connection_drop_until_deleted(self) -> None:
        completed, summary = self.run_preflight(cleanup_disconnects=1)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(summary["status"], "passed")
        self.assertEqual(summary["probes"][0]["cleanup_status"], 204)
        self.assertEqual(summary["probes"][0]["cleanup_attempts"], 2)
        self.assertEqual(
            IatIssuerHandler.cleanup_authorizations,
            ["Bearer registration-token", "Bearer registration-token"],
        )

    def test_cleanup_requires_rfc7592_no_content_status(self) -> None:
        completed, summary = self.run_preflight(cleanup_statuses=(200,))

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(summary["probes"][0]["cleanup_status"], 200)
        self.assertEqual(summary["probes"][0]["cleanup_attempts"], 1)
        self.assertIn("cleanup returned HTTP 200", summary["error"])

    def test_registration_redirect_does_not_forward_initial_access_token(
        self,
    ) -> None:
        completed, summary = self.run_preflight(
            registration_redirect_url="http://127.0.0.1:1/unsafe"
        )

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(IatIssuerHandler.cleanup_authorizations, [])
        self.assertIn("registration returned HTTP 307", summary["error"])

    def test_cleanup_redirect_does_not_forward_management_token(self) -> None:
        completed, summary = self.run_preflight(
            cleanup_redirect_url="http://127.0.0.1:1/unsafe"
        )

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(
            IatIssuerHandler.cleanup_authorizations,
            ["Bearer registration-token"],
        )
        self.assertIn("cleanup returned HTTP 307", summary["error"])

    def test_distinct_iats_are_each_probed_once(self) -> None:
        completed, summary = self.run_preflight(
            second_token="iat_secondary.other-secret"
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(len(IatIssuerHandler.registration_authorizations), 2)
        self.assertEqual(len(IatIssuerHandler.cleanup_authorizations), 2)
        self.assertEqual(summary["probe_count"], 2)


if __name__ == "__main__":
    unittest.main()
