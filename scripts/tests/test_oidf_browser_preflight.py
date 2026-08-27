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
PREFLIGHT = REPO_ROOT / "scripts" / "oidf_browser_preflight.py"

REQUIRED_MARKERS = (
    "agent-auth-login-ready",
    "agent-auth-login-email",
    "agent-auth-login-password",
    "agent-auth-login-submit",
    "agent-auth-consent-ready",
    "agent-auth-consent-approve",
)


class BrowserAssetHandler(BaseHTTPRequestHandler):
    html: ClassVar[str] = ""
    polyfill_bundle: ClassVar[str] = ""
    legacy_bundle: ClassVar[str] = ""
    serve_polyfill = True
    legacy_redirect_url: ClassVar[str | None] = None
    requests: ClassVar[list[str]] = []

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        type(self).requests.append(path)
        if path == "/login":
            self.send_body(self.html, "text/html; charset=utf-8")
            return
        if path == "/assets/polyfills-legacy-test.js":
            if not type(self).serve_polyfill:
                self.send_response(404)
                self.end_headers()
                return
            self.send_body(self.polyfill_bundle, "application/javascript")
            return
        if path == "/assets/index-legacy-test.js":
            if type(self).legacy_redirect_url is not None:
                self.send_response(302)
                self.send_header("location", type(self).legacy_redirect_url)
                self.end_headers()
                return
            self.send_body(self.legacy_bundle, "application/javascript")
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, _format: str, *_args) -> None:
        return

    def send_body(self, body: str, content_type: str) -> None:
        encoded = body.encode()
        self.send_response(200)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


class OidfBrowserPreflightCliTests(unittest.TestCase):
    def run_preflight(
        self,
        *,
        html: str | None = None,
        polyfill_bundle: str = "XMLHttpRequest;fetch;",
        legacy_bundle: str | None = None,
        serve_polyfill: bool = True,
        legacy_redirect_url: str | None = None,
        allowed_issuer_override: str | None = None,
    ):
        BrowserAssetHandler.requests = []
        BrowserAssetHandler.serve_polyfill = serve_polyfill
        BrowserAssetHandler.legacy_redirect_url = legacy_redirect_url
        BrowserAssetHandler.html = html or (
            '<!doctype html><script type="module" src="/assets/index.js"></script>'
            '<script nomodule id="vite-legacy-polyfill" '
            'src="/assets/polyfills-legacy-test.js"></script>'
            '<script nomodule id="vite-legacy-entry" '
            'data-src="/assets/index-legacy-test.js">'
            "System.import(document.getElementById('vite-legacy-entry')"
            ".getAttribute('data-src'))</script>"
        )
        BrowserAssetHandler.polyfill_bundle = polyfill_bundle
        BrowserAssetHandler.legacy_bundle = legacy_bundle or (
            "System.register([]);"
            + ";".join(f'"{marker}"' for marker in REQUIRED_MARKERS)
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), BrowserAssetHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        issuer = f"http://127.0.0.1:{server.server_port}"
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
        self.assertEqual(BrowserAssetHandler.requests, [])

    def test_accepts_live_legacy_bundle_with_all_oidf_markers(self) -> None:
        completed, summary = self.run_preflight()

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(summary["status"], "passed")
        self.assertEqual(summary["login_status"], 200)
        self.assertEqual(summary["polyfill_bundle_status"], 200)
        self.assertEqual(summary["legacy_bundle_status"], 200)
        self.assertEqual(summary["marker_count"], len(REQUIRED_MARKERS))
        self.assertEqual(
            BrowserAssetHandler.requests,
            [
                "/login",
                "/assets/polyfills-legacy-test.js",
                "/assets/index-legacy-test.js",
            ],
        )

    def test_rejects_missing_legacy_polyfill_bundle(self) -> None:
        completed, summary = self.run_preflight(serve_polyfill=False)

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(summary["polyfill_bundle_status"], 404)
        self.assertIn("polyfill bundle returned HTTP 404", summary["error"])
        self.assertEqual(
            BrowserAssetHandler.requests,
            ["/login", "/assets/polyfills-legacy-test.js"],
        )

    def test_rejects_legacy_polyfill_without_fetch_transport(self) -> None:
        completed, summary = self.run_preflight(polyfill_bundle="XMLHttpRequest;")

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(summary["status"], "failed")
        self.assertIn("Fetch API polyfill is missing", summary["error"])

    def test_rejects_html_without_legacy_application_entry(self) -> None:
        completed, summary = self.run_preflight(
            html=(
                '<!doctype html><script type="module" '
                'src="/assets/index.js"></script>'
                '<script id="vite-legacy-polyfill" '
                'src="/assets/polyfills-legacy-test.js"></script>'
                "<script>System.import('missing')</script>"
            )
        )

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(summary["status"], "failed")
        self.assertIn("legacy application entry", summary["error"])
        self.assertEqual(BrowserAssetHandler.requests, ["/login"])

    def test_rejects_modern_only_spa_from_incompatible_deployment(self) -> None:
        completed, summary = self.run_preflight(
            html=(
                '<!doctype html><html><head><script type="module" crossorigin '
                'src="/assets/index-Ch-ZalZX.js"></script></head>'
                '<body><div id="root"></div></body></html>'
            )
        )

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(summary["status"], "failed")
        self.assertIn("legacy polyfill entry", summary["error"])
        self.assertEqual(BrowserAssetHandler.requests, ["/login"])

    def test_rejects_cross_origin_legacy_bundle_without_fetching_it(self) -> None:
        completed, summary = self.run_preflight(
            html=(
                '<!doctype html><script type="module" '
                'src="/assets/index.js"></script>'
                '<script id="vite-legacy-polyfill" '
                'src="/assets/polyfills-legacy-test.js"></script>'
                '<script id="vite-legacy-entry" '
                'data-src="http://127.0.0.1:1/assets/index-legacy-test.js">'
                "System.import('unsafe')</script>"
            )
        )

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(summary["status"], "failed")
        self.assertIn("same origin", summary["error"])
        self.assertEqual(BrowserAssetHandler.requests, ["/login"])

    def test_does_not_follow_cross_origin_legacy_bundle_redirect(self) -> None:
        completed, summary = self.run_preflight(
            legacy_redirect_url="http://127.0.0.1:1/unsafe.js"
        )

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(summary["legacy_bundle_status"], 302)
        self.assertIn("legacy application bundle returned HTTP 302", summary["error"])

    def test_rejects_legacy_bundle_missing_oidf_marker(self) -> None:
        completed, summary = self.run_preflight(
            legacy_bundle=(
                "System.register([]);"
                + ";".join(f'"{marker}"' for marker in REQUIRED_MARKERS[:-1])
            )
        )

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(summary["status"], "failed")
        self.assertIn(REQUIRED_MARKERS[-1], summary["error"])
        self.assertNotIn("System.register", json.dumps(summary))


if __name__ == "__main__":
    unittest.main()
