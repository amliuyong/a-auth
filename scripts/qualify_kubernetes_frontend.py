#!/usr/bin/env python3
"""Exercise the built frontend container against a real loopback HTTP fixture."""

import argparse
import concurrent.futures
import hashlib
import http.server
import json
import secrets
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    name = "a-auth-frontend-check-" + secrets.token_hex(6)
    received = []
    slow_started, slow_release = threading.Event(), threading.Event()
    checks = {}
    html = None

    class Backend(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            if self.path == "/slow":
                slow_started.set()
                slow_release.wait(15)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"drained")
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            received.append((self.path, body, dict(self.headers)))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"proxied":true}')

    backend = http.server.ThreadingHTTPServer(("127.0.0.1", 8080), Backend)
    thread = threading.Thread(target=backend.serve_forever, daemon=True)
    thread.start()

    def request(path, method="GET", body=None, headers=None):
        req = urllib.request.Request(
            "http://127.0.0.1:8083" + path,
            data=body,
            method=method,
            headers=headers or {},
        )
        try:
            response = urllib.request.urlopen(req, timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, dict(response.headers), response.read()

    def check(label):
        checks[label] = "PASS"
        print(label + " PASS", flush=True)

    status = "FAIL"
    try:
        subprocess.run(
            [
                "docker", "run", "--detach", "--name", name, "--network", "host",
                "--read-only", "--user", "65532:65532",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m",
                args.image,
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 20
        while True:
            try:
                assert request("/health/frontend")[0] == 204
                break
            except (OSError, AssertionError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.2)
        for path in ("/", "/login", "/invite", "/consent", "/recover",
                     "/account", "/approve", "/error"):
            code, headers, body = request(path + "?state=private-test-marker")
            assert code == 200 and b'id="root"' in body
            assert headers["Cache-Control"] == "no-store"
            html = body
        check("public_browser_pages")
        import re
        asset = re.search(rb'(?:src|href)="(/assets/[^"]+\.js)"', html)[1].decode()
        assert request(asset)[0] == 200
        assert request("/assets/absent.js")[0] == 404
        assert request("/unknown-page")[0] == 404
        check("static_assets_and_missing_paths")
        private_headers = {
            "Authorization": "Bearer private-test-marker",
            "Cookie": "session=private-test-marker",
        }
        for path in ("/admin", "/admin/clients", "/scim", "/scim/v2/Users",
                     "/%61dmin/clients", "//admin/clients",
                     "/assets/../admin", "/token"):
            assert request(path, headers=private_headers)[0] == 404, path
        assert request("/login?state=private-test-marker", "POST",
                       b"never-proxy-this")[0] == 403
        check("private_families_and_token_excluded")
        payload = b'{"decision":"approve","csrf":"fixture-only"}'
        proxy_headers = {
            **private_headers,
            "Host": "auth.example.test",
            "Origin": "https://auth.example.test",
            "Content-Type": "application/json",
        }
        assert request("/consent/decision", "POST", payload, proxy_headers)[0] == 200
        path, body, forwarded = received.pop()
        assert path == "/consent/decision" and body == payload
        for header, value in proxy_headers.items():
            assert forwarded[header] == value, header
        check("same_origin_protocol_post")
        container = json.loads(subprocess.check_output(
            ["docker", "inspect", name], text=True
        ))[0]
        assert container["Config"]["User"] == "65532:65532"
        assert container["HostConfig"]["ReadonlyRootfs"]
        assert container["HostConfig"]["CapDrop"] == ["ALL"]
        assert set(container["HostConfig"]["Tmpfs"]) == {"/tmp"}
        assert all(m["Destination"] == "/tmp" for m in container["Mounts"])
        check("nonroot_readonly_without_secret_mounts")
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            pending = pool.submit(request, "/slow")
            assert slow_started.wait(5)
            subprocess.run(["docker", "kill", "--signal", "QUIT", name],
                           check=True, stdout=subprocess.DEVNULL)
            time.sleep(0.2)
            slow_release.set()
            assert pending.result()[0::2] == (200, b"drained")
        subprocess.run(["docker", "wait", name], check=True,
                       stdout=subprocess.DEVNULL, timeout=10)
        check("graceful_frontend_drain")
        logs = subprocess.check_output(
            ["docker", "logs", name], stderr=subprocess.STDOUT, text=True
        )
        assert "private-test-marker" not in logs and "fixture-only" not in logs
        access = [json.loads(line) for line in logs.splitlines()
                  if line.startswith('{"event":"frontend_access"')]
        assert access and all(set(e) == {
            "event", "method", "status", "elapsed_seconds"
        } for e in access)
        check("credential_free_access_logs")
        status = "PASS"
    finally:
        slow_release.set()
        backend.shutdown()
        backend.server_close()
        image = json.loads(subprocess.check_output(
            ["docker", "image", "inspect", args.image], text=True
        ))[0]
        receipt = {
            "status": status, "checks": checks, "image_id": image["Id"],
            "source_commit": image["Config"].get("Labels", {}).get(
                "org.opencontainers.image.revision"
            ),
            "fixture": "Linux host-network loopback HTTP; installed browser/TLS NOT_RUN",
            "html_sha256": hashlib.sha256(html).hexdigest() if html else None,
        }
        args.receipt.write_text(json.dumps(receipt, indent=2) + "\n")
        subprocess.run(["docker", "rm", "--force", name],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
