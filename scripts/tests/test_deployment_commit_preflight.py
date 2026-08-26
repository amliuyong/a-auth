import json
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
PREFLIGHT = REPO_ROOT / "scripts" / "deployment_commit_preflight.py"
DEPLOYMENT_COMMIT = "a" * 40


class DiscoveryHandler(BaseHTTPRequestHandler):
    deployment_commits: ClassVar[list[str]] = [DEPLOYMENT_COMMIT]
    issuer: ClassVar[str] = ""
    redirect_url: ClassVar[str | None] = None
    requests: ClassVar[list[str]] = []
    request_headers: ClassVar[list[dict[str, str]]] = []

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        type(self).requests.append(path)
        type(self).request_headers.append(
            {key.lower(): value for key, value in self.headers.items()}
        )
        if path != "/.well-known/openid-configuration":
            self.send_response(404)
            self.end_headers()
            return
        if type(self).redirect_url is not None:
            self.send_response(302)
            self.send_header("location", type(self).redirect_url)
            self.end_headers()
            return
        body = json.dumps({"issuer": type(self).issuer}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        for deployment_commit in type(self).deployment_commits:
            self.send_header(
                "x-agent-auth-deployment-commit",
                deployment_commit,
            )
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args) -> None:
        return


class DeploymentCommitPreflightCliTests(unittest.TestCase):
    def run_preflight(
        self,
        *,
        deployment_commits: list[str] | None = None,
        expected_commit: str = DEPLOYMENT_COMMIT,
        issuer_override: str | None = None,
        allowed_issuer_override: str | None = None,
        redirect_url: str | None = None,
        phase: str = "start",
    ):
        DiscoveryHandler.deployment_commits = (
            [DEPLOYMENT_COMMIT] if deployment_commits is None else deployment_commits
        )
        DiscoveryHandler.redirect_url = redirect_url
        DiscoveryHandler.requests = []
        DiscoveryHandler.request_headers = []
        server = ThreadingHTTPServer(("127.0.0.1", 0), DiscoveryHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        issuer = f"http://127.0.0.1:{server.server_port}"
        DiscoveryHandler.issuer = issuer_override or issuer
        try:
            with tempfile.TemporaryDirectory() as directory:
                summary_path = Path(directory) / "summary.json"
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(PREFLIGHT),
                        "--issuer",
                        issuer,
                        "--allowed-issuer",
                        allowed_issuer_override or issuer,
                        "--expected-deployment-version",
                        expected_commit,
                        "--phase",
                        phase,
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

    def test_accepts_exact_live_deployment_commit(self) -> None:
        completed, summary = self.run_preflight()

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(summary["status"], "passed")
        self.assertEqual(summary["phase"], "start")
        self.assertEqual(summary["discovery_status"], 200)
        self.assertEqual(summary["deployment_version"], DEPLOYMENT_COMMIT)
        self.assertEqual(
            DiscoveryHandler.requests,
            ["/.well-known/openid-configuration"],
        )
        self.assertEqual(
            DiscoveryHandler.request_headers[0]["cache-control"],
            "no-cache",
        )
        self.assertEqual(
            DiscoveryHandler.request_headers[0]["pragma"],
            "no-cache",
        )

    def test_rejects_missing_or_mismatched_deployment_header(self) -> None:
        for observed in ([], ["b" * 40], ["A" * 40], ["a" * 39]):
            with self.subTest(observed=observed):
                completed, summary = self.run_preflight(
                    deployment_commits=observed,
                )

                self.assertEqual(completed.returncode, 1)
                self.assertEqual(summary["status"], "failed")
                self.assertIn("deployment commit", summary["error"])

    def test_rejects_duplicate_deployment_headers(self) -> None:
        completed, summary = self.run_preflight(
            deployment_commits=[DEPLOYMENT_COMMIT, DEPLOYMENT_COMMIT],
        )

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(summary["status"], "failed")
        self.assertIn("exactly one", summary["error"])

    def test_rejects_discovery_issuer_mismatch(self) -> None:
        completed, summary = self.run_preflight(
            issuer_override="https://wrong.example",
        )

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(summary["status"], "failed")
        self.assertIn("issuer does not match", summary["error"])

    def test_does_not_follow_discovery_redirect(self) -> None:
        completed, summary = self.run_preflight(
            redirect_url="http://127.0.0.1:1/unsafe",
        )

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(summary["discovery_status"], 302)
        self.assertIn("returned HTTP 302", summary["error"])
        self.assertEqual(
            DiscoveryHandler.requests,
            ["/.well-known/openid-configuration"],
        )

    def test_rejects_issuer_outside_the_configured_environment_before_network(
        self,
    ) -> None:
        completed, summary = self.run_preflight(
            allowed_issuer_override="https://configured.example",
        )

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(summary["status"], "failed")
        self.assertIsNone(summary["discovery_status"])
        self.assertIn("configured environment issuer", summary["error"])
        self.assertEqual(DiscoveryHandler.requests, [])

    def test_rejects_non_commit_expected_version_before_network(self) -> None:
        completed, summary = self.run_preflight(expected_commit="main")

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(summary["status"], "failed")
        self.assertIsNone(summary["discovery_status"])
        self.assertIn("full lowercase Git commit", summary["error"])
        self.assertEqual(DiscoveryHandler.requests, [])

    def test_records_end_phase(self) -> None:
        completed, summary = self.run_preflight(phase="end")

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(summary["phase"], "end")


if __name__ == "__main__":
    unittest.main()
