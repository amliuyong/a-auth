import json
import os
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HARNESS = REPO_ROOT / "e2e" / "okta_scim_users.sh"
SOURCE_COMMIT = "a" * 40
ISSUER = "https://issuer.example.com"
OKTA_TOKEN = "okta-api-token-value"
SCIM_TOKEN = "scim-bearer-token-value"


class OktaScimUsersHarnessTests(unittest.TestCase):
    def install_mock(self, directory: Path, name: str, source: str) -> None:
        path = directory / name
        path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
        path.chmod(0o700)

    def run_harness(
        self,
        root: Path,
        *,
        cleanup_delete_status: int = 204,
        run_id: str = "mock-run",
        scim_secret: str | None = None,
        preexisting_user: bool = False,
        preexisting_evidence: bool = False,
        preexisting_lock: bool = False,
        create_collision_after_preflight: bool = False,
        interrupt_after_create: bool = False,
    ) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
        mock_bin = root / "bin"
        mock_bin.mkdir()
        state_file = root / "mock-state.json"
        curl_log = root / "curl-argv.jsonl"
        evidence = root / "evidence.json"
        okta_token_file = root / "okta-token"
        scim_token_file = root / "scim-token"
        okta_token_file.write_text(OKTA_TOKEN, encoding="utf-8")
        scim_token_file.write_text(SCIM_TOKEN, encoding="utf-8")
        okta_token_file.chmod(0o600)
        scim_token_file.chmod(0o600)
        if preexisting_user:
            state_file.write_text(
                json.dumps({"assigned": False, "created": True, "deleted": False}),
                encoding="utf-8",
            )
        if preexisting_evidence:
            evidence.write_text("stale evidence", encoding="utf-8")
        if preexisting_lock:
            Path(f"{evidence}.lock").mkdir()

        self.install_mock(
            mock_bin,
            "git",
            f"""
            #!/usr/bin/env python3
            import sys

            if "rev-parse" in sys.argv:
                print("{SOURCE_COMMIT}")
            elif "status" not in sys.argv:
                raise SystemExit("unexpected git invocation: " + repr(sys.argv))
            """,
        )
        self.install_mock(
            mock_bin,
            "aws",
            f"""
            #!/usr/bin/env python3
            import json
            import os
            import sys

            invocation = " ".join(sys.argv)
            if "secretsmanager get-secret-value" in invocation:
                print(json.dumps({{"current": {{"secret": os.environ["MOCK_SCIM_SECRET"]}}}}))
            elif "DeploymentCommit" in invocation:
                print("{SOURCE_COMMIT}")
            elif "FrontendSpaUrl" in invocation:
                print("{ISSUER}")
            else:
                raise SystemExit("unexpected aws invocation: " + repr(sys.argv))
            """,
        )
        self.install_mock(
            mock_bin,
            "sleep",
            """
            #!/usr/bin/env sh
            exit 0
            """,
        )
        self.install_mock(
            mock_bin,
            "curl",
            """
            #!/usr/bin/env python3
            import json
            import os
            import signal
            import sys
            import urllib.parse
            from pathlib import Path

            args = sys.argv[1:]

            def option(name, default=None):
                try:
                    return args[args.index(name) + 1]
                except ValueError:
                    return default

            method = option("--request", "GET")
            output = Path(option("--output"))
            url = next(value for value in reversed(args) if value.startswith("https://"))
            state_path = Path(os.environ["MOCK_STATE_FILE"])
            state = (
                json.loads(state_path.read_text(encoding="utf-8"))
                if state_path.exists()
                else {"assigned": False, "created": False, "deleted": False}
            )
            status = 500
            body = {}

            if url.endswith("/api/v1/apps/app123") and method == "GET":
                status, body = 200, {"status": "ACTIVE"}
            elif url.endswith("/api/v1/users?activate=true") and method == "POST":
                if os.environ["MOCK_CREATE_COLLISION"] == "1":
                    state["created"] = True
                    state["deleted"] = False
                    status, body = 400, {"errorCode": "E0000001"}
                elif state["created"] and not state["deleted"]:
                    status, body = 400, {"errorCode": "E0000001"}
                else:
                    state["created"] = True
                    state["deleted"] = False
                    status, body = 200, {"id": "okta-user-1", "status": "ACTIVE"}
            elif url.endswith("/api/v1/apps/app123/users") and method == "POST":
                state["assigned"] = True
                status, body = 200, {"id": "okta-user-1"}
            elif "/api/v1/apps/app123/users/okta-user-1" in url and method == "DELETE":
                state["assigned"] = False
                status, body = 204, {}
            elif "/scim/v2/Users?" in url and method == "GET":
                status = 200
                body = {
                    "totalResults": 1,
                    "Resources": [
                        {
                            "id": "canonical-user-1",
                            "externalId": "okta-user-1",
                            "active": state["assigned"],
                        }
                    ],
                }
            elif "/api/v1/users/okta-user-1/lifecycle/deactivate" in url:
                status, body = 200, {"status": "DEPROVISIONED"}
            elif url.endswith("/api/v1/users/okta-user-1") and method == "DELETE":
                status = int(os.environ["MOCK_CLEANUP_DELETE_STATUS"])
                if status == 204:
                    state["deleted"] = True
                body = {}
            elif url.endswith("/api/v1/users/okta-user-1") and method == "GET":
                status, body = (404, {}) if state["deleted"] else (200, {"id": "okta-user-1"})
            elif "/api/v1/users/" in url and method == "GET":
                email = urllib.parse.unquote(url.rsplit("/", 1)[-1])
                if state["created"] and not state["deleted"]:
                    status, body = 200, {"id": "okta-user-1", "profile": {"login": email}}
                else:
                    status, body = 404, {}

            state_path.write_text(json.dumps(state), encoding="utf-8")
            with Path(os.environ["MOCK_CURL_LOG"]).open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(args) + "\\n")
            output.write_text(json.dumps(body), encoding="utf-8")
            print(status, end="", flush=True)
            if (
                url.endswith("/api/v1/users?activate=true")
                and method == "POST"
                and status == 200
                and os.environ["MOCK_INTERRUPT_AFTER_CREATE"] == "1"
            ):
                os.kill(os.getppid(), signal.SIGTERM)
            """,
        )

        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{mock_bin}:{env['PATH']}",
                "MOCK_STATE_FILE": str(state_file),
                "MOCK_CURL_LOG": str(curl_log),
                "MOCK_CLEANUP_DELETE_STATUS": str(cleanup_delete_status),
                "MOCK_CREATE_COLLISION": (
                    "1" if create_collision_after_preflight else "0"
                ),
                "MOCK_INTERRUPT_AFTER_CREATE": ("1" if interrupt_after_create else "0"),
                "OKTA_ORG_URL": "https://example.okta.com",
                "OKTA_API_TOKEN_FILE": str(okta_token_file),
                "OKTA_APP_ID": "app123",
                "BASE_URL": ISSUER,
                "STACK_NAME": "AgentAuthDev",
                "SCIM_WAIT_SECONDS": "30",
                "OKTA_SCIM_RUN_ID": run_id,
                "EVIDENCE_FILE": str(evidence),
                "PROFILE": "ci-test",
                "REGION": "us-east-1",
            }
        )
        if scim_secret is None:
            env["SCIM_TOKEN_FILE"] = str(scim_token_file)
        else:
            env["SCIM_SECRET_ARN"] = (
                "arn:aws:secretsmanager:us-east-1:123456789012:secret:test"
            )
            env["MOCK_SCIM_SECRET"] = scim_secret
        result = subprocess.run(
            ["bash", str(HARNESS)],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        return result, evidence, curl_log

    def test_provision_deprovision_reprovision_and_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result, evidence_file, curl_log = self.run_harness(Path(directory))
            evidence = json.loads(evidence_file.read_text(encoding="utf-8"))
            evidence_mode = stat.S_IMODE(evidence_file.stat().st_mode)
            checksum_file = Path(f"{evidence_file}.sha256")
            checksum_mode = stat.S_IMODE(checksum_file.stat().st_mode)
            checksum = checksum_file.read_text(encoding="utf-8")
            checksum_check = subprocess.run(
                ["sha256sum", "-c", str(checksum_file)],
                capture_output=True,
                text=True,
                check=False,
            )
            temporary_files = list(evidence_file.parent.glob(".evidence.json.*"))
            lock_exists = Path(f"{evidence_file}.lock").exists()
            calls = curl_log.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(evidence_mode, 0o600)
        self.assertEqual(checksum_mode, 0o600)
        self.assertRegex(checksum, rf"^[0-9a-f]{{64}}  {evidence_file}\n$")
        self.assertEqual(checksum_check.returncode, 0, checksum_check.stderr)
        self.assertEqual(temporary_files, [])
        self.assertFalse(lock_exists)
        self.assertEqual(evidence["evidence_kind"], "third_party")
        self.assertEqual(evidence["source_commit"], SOURCE_COMMIT)
        self.assertEqual(evidence["deployed_commit"], SOURCE_COMMIT)
        self.assertEqual(
            [check["scim_active"] for check in evidence["checks"]],
            [True, False, True],
        )
        self.assertEqual(
            [check["stage"] for check in evidence["checks"]],
            ["provision", "deprovision", "re-provision"],
        )
        self.assertTrue(evidence["fixture_cleanup"]["requested"])
        self.assertTrue(evidence["fixture_cleanup"]["verified"])
        self.assertTrue(evidence["fixture_cleanup"]["agent_auth_inactive"])
        self.assertIsInstance(evidence["fixture_cleanup"]["observed_at"], str)
        self.assertNotIn(OKTA_TOKEN, calls)
        self.assertNotIn(SCIM_TOKEN, calls)

    def test_cleanup_failure_prevents_success_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result, evidence_file, _ = self.run_harness(
                Path(directory),
                cleanup_delete_status=500,
            )
            evidence_exists = evidence_file.exists()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cleanup delete returned Okta HTTP 500", result.stderr)
        self.assertFalse(evidence_exists)
        self.assertNotIn("Evidence:", result.stdout)

    def test_rejects_unsafe_run_id_before_provider_calls(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result, evidence_file, curl_log = self.run_harness(
                Path(directory),
                run_id="../unsafe",
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("safe identifier", result.stderr)
        self.assertFalse(evidence_file.exists())
        self.assertFalse(curl_log.exists())

    def test_rejects_header_injection_in_secrets_manager_token(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result, evidence_file, curl_log = self.run_harness(
                Path(directory),
                scim_secret="valid-token-value\r\nInjected: header",
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(evidence_file.exists())
        self.assertFalse(curl_log.exists())

    def test_refuses_to_delete_a_preexisting_directory_user(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result, evidence_file, curl_log = self.run_harness(
                root,
                preexisting_user=True,
            )
            calls = curl_log.read_text(encoding="utf-8")
            state = json.loads((root / "mock-state.json").read_text(encoding="utf-8"))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("login already exists", result.stderr)
        self.assertFalse(evidence_file.exists())
        self.assertNotIn('"POST"', calls)
        self.assertFalse(state["deleted"])

    def test_refuses_to_overwrite_existing_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result, evidence_file, curl_log = self.run_harness(
                Path(directory),
                preexisting_evidence=True,
            )
            retained = evidence_file.read_text(encoding="utf-8")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must not already exist", result.stderr)
        self.assertEqual(retained, "stale evidence")
        self.assertFalse(curl_log.exists())

    def test_create_collision_does_not_delete_an_unconfirmed_user(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result, evidence_file, curl_log = self.run_harness(
                root,
                create_collision_after_preflight=True,
            )
            calls = curl_log.read_text(encoding="utf-8")
            state = json.loads((root / "mock-state.json").read_text(encoding="utf-8"))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("create-user expected Okta HTTP 200, got 400", result.stderr)
        self.assertFalse(evidence_file.exists())
        self.assertIn('"POST"', calls)
        self.assertNotIn('"DELETE"', calls)
        self.assertTrue(state["created"])
        self.assertFalse(state["deleted"])

    def test_interrupt_after_create_deletes_confirmed_user_without_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result, evidence_file, curl_log = self.run_harness(
                root,
                interrupt_after_create=True,
            )
            calls = curl_log.read_text(encoding="utf-8")
            state = json.loads((root / "mock-state.json").read_text(encoding="utf-8"))

        self.assertEqual(result.returncode, 143)
        self.assertTrue(state["deleted"])
        self.assertFalse(state["assigned"])
        self.assertFalse(evidence_file.exists())
        self.assertFalse(Path(f"{evidence_file}.sha256").exists())
        self.assertNotIn("Evidence:", result.stdout)
        self.assertIn('"DELETE"', calls)

    def test_lock_contention_does_not_remove_the_existing_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result, evidence_file, curl_log = self.run_harness(
                Path(directory),
                preexisting_lock=True,
            )
            lock_exists = Path(f"{evidence_file}.lock").is_dir()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exclusively reserve", result.stderr)
        self.assertTrue(lock_exists)
        self.assertFalse(curl_log.exists())


if __name__ == "__main__":
    unittest.main()
