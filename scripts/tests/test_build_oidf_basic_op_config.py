import json
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BUILDER = REPO_ROOT / "scripts" / "build_oidf_basic_op_config.py"
VALIDATOR = REPO_ROOT / "scripts" / "validate_oidf_config.py"
ISSUER = "https://issuer.example.com"
EMAIL = "oidf-user@example.com"
PASSWORD = "Replaceable password 123!"
INITIAL_ACCESS_TOKEN = "iat_test.controlled-secret"


class BuildOidfBasicOpConfigCliTests(unittest.TestCase):
    def test_builds_valid_secret_config_without_printing_password(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            password_file = root / "password"
            initial_access_token_file = root / "initial-access-token"
            output = root / "oidf-config.json"
            summary = root / "summary.json"
            password_file.write_text(PASSWORD + "\n")
            password_file.chmod(0o600)
            initial_access_token_file.write_text(INITIAL_ACCESS_TOKEN + "\n")
            initial_access_token_file.chmod(0o600)

            built = subprocess.run(
                [
                    sys.executable,
                    str(BUILDER),
                    "--issuer",
                    ISSUER + "/",
                    "--email",
                    EMAIL,
                    "--password-file",
                    str(password_file),
                    "--initial-access-token-file",
                    str(initial_access_token_file),
                    "--output",
                    str(output),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            validated = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATOR),
                    "--config",
                    str(output),
                    "--issuer",
                    ISSUER,
                    "--summary",
                    str(summary),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            config = json.loads(output.read_text())
            output_mode = stat.S_IMODE(output.stat().st_mode)

        self.assertEqual(built.returncode, 0, built.stderr)
        self.assertEqual(validated.returncode, 0, validated.stderr)
        self.assertEqual(output_mode, 0o600)
        command_output = built.stdout + built.stderr
        self.assertNotIn(PASSWORD, command_output)
        self.assertNotIn(INITIAL_ACCESS_TOKEN, command_output)
        self.assertEqual(config["server"]["login_hint"], EMAIL)
        self.assertEqual(
            config["client"]["initial_access_token"],
            INITIAL_ACCESS_TOKEN,
        )
        self.assertEqual(
            config["client2"]["initial_access_token"],
            INITIAL_ACCESS_TOKEN,
        )
        self.assertEqual(
            config["browser"][0]["match"],
            f"{ISSUER}/authorize*prompt=none*",
        )
        self.assertEqual(
            config["browser"][0]["tasks"],
            [
                {
                    "task": "Verify hosted callback completed",
                    "match": "https://www.certification.openid.net/test/*/callback*",
                    "commands": [["wait", "id", "submission_complete", 30]],
                }
            ],
        )
        self.assertEqual(
            config["browser"][1]["tasks"][0]["commands"][3],
            ["text", "id", "agent-auth-login-password", PASSWORD],
        )
        self.assertEqual(
            config["browser"][1]["tasks"][0]["commands"][1][-1],
            "update-image-placeholder-optional",
        )
        self.assertEqual(
            config["browser"][1]["tasks"][1]["commands"][0],
            ["wait", "id", "agent-auth-consent-ready", 30],
        )
        self.assertEqual(
            config["browser"][1]["tasks"][-1]["match"],
            "https://www.certification.openid.net/test/*/callback*",
        )
        self.assertEqual(
            set(config["override"]),
            {
                "oidcc-ensure-registered-redirect-uri",
                "oidcc-ensure-request-object-with-redirect-uri",
            },
        )
        self.assertEqual(
            config["override"]["oidcc-ensure-registered-redirect-uri"]["browser"][0][
                "tasks"
            ][0]["commands"][0][4],
            "invalid_request",
        )
        self.assertEqual(
            config["override"]["oidcc-ensure-request-object-with-redirect-uri"][
                "browser"
            ][0]["tasks"][0]["commands"][0][4],
            "request_not_supported",
        )
        self.assertEqual(
            config["override"]["oidcc-ensure-registered-redirect-uri"]["browser"][0][
                "tasks"
            ][0]["commands"][0][-1],
            "update-image-placeholder",
        )

    def test_rejects_unprotected_inputs_and_non_origin_issuer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            password_file = root / "password"
            initial_access_token_file = root / "initial-access-token"
            password_file.write_text(PASSWORD)
            password_file.chmod(0o644)
            initial_access_token_file.write_text(INITIAL_ACCESS_TOKEN)
            initial_access_token_file.chmod(0o600)
            output = root / "oidf-config.json"
            base = [
                sys.executable,
                str(BUILDER),
                "--email",
                EMAIL,
                "--password-file",
                str(password_file),
                "--initial-access-token-file",
                str(initial_access_token_file),
                "--output",
                str(output),
            ]
            loose_password = subprocess.run(
                [*base, "--issuer", ISSUER],
                capture_output=True,
                text=True,
                check=False,
            )
            password_file.chmod(0o600)
            initial_access_token_file.chmod(0o644)
            loose_iat = subprocess.run(
                [*base, "--issuer", ISSUER],
                capture_output=True,
                text=True,
                check=False,
            )
            initial_access_token_file.chmod(0o600)
            path_issuer = subprocess.run(
                [*base, "--issuer", ISSUER + "/tenant"],
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertNotEqual(loose_password.returncode, 0)
        self.assertIn("group or other", loose_password.stderr)
        self.assertNotEqual(loose_iat.returncode, 0)
        self.assertIn("group or other", loose_iat.stderr)
        self.assertNotEqual(path_issuer.returncode, 0)
        self.assertIn("HTTPS origin", path_issuer.stderr)


if __name__ == "__main__":
    unittest.main()
