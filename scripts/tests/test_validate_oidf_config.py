import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = REPO_ROOT / "scripts" / "validate_oidf_config.py"
ISSUER = "https://issuer.example.com"


def valid_config() -> dict:
    callback_task = {
        "task": "Verify callback",
        "match": "https://www.certification.openid.net/test/*/callback*",
        "commands": [["wait", "id", "submission_complete", 30]],
    }
    expected_error = {
        "browser": [
            {
                "match": "https://issuer.example.com/authorize*",
                "tasks": [
                    {
                        "task": "Capture expected error",
                        "match": "https://issuer.example.com/authorize*",
                        "commands": [
                            [
                                "wait",
                                "xpath",
                                "//*",
                                30,
                                "invalid_request",
                                "update-image-placeholder",
                            ]
                        ],
                    }
                ],
            }
        ]
    }
    request_object_error = copy.deepcopy(expected_error)
    request_object_error["browser"][0]["tasks"][0]["commands"][0][4] = (
        "request_not_supported"
    )
    return {
        "description": "agent-auth release gate",
        "server": {
            "discoveryUrl": (
                "https://issuer.example.com/.well-known/openid-configuration"
            ),
            "login_hint": "user@example.com",
        },
        "client": {
            "client_name": "first",
            "initial_access_token": "iat_primary.secret",
        },
        "client2": {
            "client_name": "second",
            "initial_access_token": "iat_secondary.secret",
        },
        "browser": [
            {
                "match": "https://issuer.example.com/authorize*prompt=none*",
                "tasks": [copy.deepcopy(callback_task)],
            },
            {
                "match": "https://issuer.example.com/authorize*",
                "tasks": [
                    {
                        "task": "Authenticate",
                        "match": "https://issuer.example.com/login*",
                        "optional": True,
                        "commands": [
                            ["wait", "id", "agent-auth-login-email", 30],
                            [
                                "wait",
                                "id",
                                "agent-auth-login-email",
                                30,
                                ".*",
                                "update-image-placeholder-optional",
                            ],
                            [
                                "text",
                                "id",
                                "agent-auth-login-email",
                                "user@example.com",
                            ],
                            ["text", "id", "agent-auth-login-password", "password"],
                            ["click", "id", "agent-auth-login-submit"],
                            [
                                "wait",
                                "contains",
                                "https://issuer.example.com/consent",
                                30,
                            ],
                        ],
                    },
                    {
                        "task": "Consent",
                        "match": "https://issuer.example.com/consent*",
                        "optional": True,
                        "commands": [
                            ["wait", "id", "agent-auth-consent-ready", 30],
                            ["click", "id", "agent-auth-consent-approve"],
                            [
                                "wait",
                                "contains",
                                "https://www.certification.openid.net",
                                30,
                            ],
                        ],
                    },
                    copy.deepcopy(callback_task),
                ],
            },
        ],
        "override": {
            "oidcc-ensure-registered-redirect-uri": copy.deepcopy(expected_error),
            "oidcc-ensure-request-object-with-redirect-uri": request_object_error,
        },
    }


class ValidateOidfConfigCliTests(unittest.TestCase):
    def run_validator(self, config: dict, issuer: str = ISSUER):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = root / "config.json"
            summary_path = root / "summary.json"
            config_path.write_text(json.dumps(config))
            completed = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATOR),
                    "--config",
                    str(config_path),
                    "--issuer",
                    issuer,
                    "--summary",
                    str(summary_path),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            summary = json.loads(summary_path.read_text())
        return completed, summary

    def run_validator_with_normalized_config(
        self,
        config: dict,
        issuer: str = ISSUER,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = root / "config.json"
            normalized_path = config_path
            summary_path = root / "summary.json"
            config_path.write_text(json.dumps(config))
            completed = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATOR),
                    "--config",
                    str(config_path),
                    "--issuer",
                    issuer,
                    "--summary",
                    str(summary_path),
                    "--normalized-config",
                    str(normalized_path),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            summary = json.loads(summary_path.read_text())
            normalized = (
                json.loads(normalized_path.read_text())
                if normalized_path.exists()
                else None
            )
            normalized_mode = (
                normalized_path.stat().st_mode & 0o777
                if normalized_path.exists()
                else None
            )
        return completed, summary, normalized, normalized_mode

    def test_validates_without_reproducing_browser_commands(self) -> None:
        config = valid_config()
        config["browser"][1]["tasks"][0]["commands"][3][3] = "secret-value"

        completed, summary = self.run_validator(config)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(summary["issuer"], ISSUER)
        self.assertEqual(summary["browser_rule_count"], 2)
        self.assertEqual(summary["browser_command_count"], 11)
        self.assertEqual(summary["browser_override_count"], 2)
        self.assertEqual(summary["browser_override_command_count"], 2)
        self.assertEqual(
            summary["initial_access_token_slots"],
            ["client", "client2"],
        )
        self.assertNotIn("secret-value", json.dumps(summary))
        self.assertNotIn("iat_primary.secret", json.dumps(summary))
        self.assertNotIn("iat_secondary.secret", json.dumps(summary))

    def test_normalizes_legacy_response_type_override_before_runner_use(self) -> None:
        config = valid_config()
        del config["override"]["oidcc-ensure-request-object-with-redirect-uri"]
        config["override"]["oidcc-response-type-missing"] = copy.deepcopy(
            config["override"]["oidcc-ensure-registered-redirect-uri"]
        )

        completed, summary, normalized, normalized_mode = (
            self.run_validator_with_normalized_config(config)
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            set(normalized["override"]),
            {
                "oidcc-ensure-registered-redirect-uri",
                "oidcc-ensure-request-object-with-redirect-uri",
            },
        )
        self.assertEqual(summary["browser_override_count"], 2)
        self.assertEqual(summary["browser_override_command_count"], 2)
        self.assertEqual(normalized_mode, 0o600)

    def test_rejects_wrong_discovery_target_or_missing_browser(self) -> None:
        cases = []
        config = valid_config()
        config["server"]["discoveryUrl"] = (
            "https://other.example/.well-known/openid-configuration"
        )
        cases.append(config)
        config = valid_config()
        config["browser"] = []
        cases.append(config)
        config = valid_config()
        del config["client"]["initial_access_token"]
        cases.append(config)
        config = valid_config()
        config["client2"]["initial_access_token"] = ""
        cases.append(config)
        config = valid_config()
        config["browser"][1]["tasks"][0]["commands"] = []
        cases.append(config)
        config = valid_config()
        config["browser"][1]["tasks"][0]["commands"].append(
            ["click", "id", "unexpected-extra-command"]
        )
        cases.append(config)
        config = valid_config()
        config["override"] = {
            "oidcc-broken": {
                "browser": [
                    {
                        "match": "https://issuer.example.com/authorize*",
                        "tasks": [],
                    }
                ]
            }
        }
        cases.append(config)

        for config in cases:
            with self.subTest(config=config):
                completed, summary = self.run_validator(config)
                self.assertEqual(completed.returncode, 1)
                self.assertFalse(summary["valid"])

        completed, summary = self.run_validator(
            valid_config(),
            "https://issuer.example.com\\@attacker.invalid",
        )
        self.assertEqual(completed.returncode, 1)
        self.assertFalse(summary["valid"])

    def test_rejects_missing_basic_op_automation_contract(self) -> None:
        cases = []
        config = valid_config()
        config["browser"][1]["tasks"][1]["commands"] = [
            command
            for command in config["browser"][1]["tasks"][1]["commands"]
            if command[:3] != ["wait", "id", "agent-auth-consent-ready"]
        ]
        cases.append(config)
        config = valid_config()
        config["browser"] = config["browser"][1:]
        cases.append(config)
        config = valid_config()
        config["browser"].reverse()
        cases.append(config)
        config = valid_config()
        config["browser"][0]["tasks"][0]["commands"].append(
            ["text", "css", "input[type=password]", "password"]
        )
        cases.append(config)
        config = valid_config()
        config["browser"][0]["match-limit"] = 0
        cases.append(config)
        config = valid_config()
        config["browser"][0]["tasks"][0]["optional"] = True
        cases.append(config)
        config = valid_config()
        config["browser"][1]["tasks"][2]["optional"] = True
        cases.append(config)
        config = valid_config()
        config["browser"][0]["tasks"][0]["match"] = (
            "https://www.certification.openid.net/test/a/*"
        )
        cases.append(config)
        config = valid_config()
        config["browser"][0]["tasks"][0]["match"] = (
            "https://www.certification.openid.net/test/*/callback"
        )
        cases.append(config)
        config = valid_config()
        config["browser"][1]["tasks"][2]["match"] = (
            "https://www.certification.openid.net/test/*"
        )
        cases.append(config)
        config = valid_config()
        displaced_login_commands = config["browser"][1]["tasks"][0]["commands"]
        config["browser"][1]["tasks"][0]["commands"] = []
        config["browser"][1]["tasks"][2]["commands"].extend(displaced_login_commands)
        cases.append(config)
        config = valid_config()
        config["browser"].insert(
            0,
            {
                "match": f"{ISSUER}/*",
                "tasks": [
                    {
                        "task": "Overlapping catch-all",
                        "commands": [["click", "id", "continue"]],
                    }
                ],
            },
        )
        cases.append(config)
        config = valid_config()
        config["browser"].append(
            {
                "match": f"{ISSUER}/authorize*",
                "tasks": [
                    {
                        "task": "Duplicate authorize rule",
                        "commands": [["click", "id", "continue"]],
                    }
                ],
            },
        )
        cases.append(config)
        config = valid_config()
        del config["override"]["oidcc-ensure-registered-redirect-uri"]
        cases.append(config)
        config = valid_config()
        config["override"]["oidcc-prompt-none-logged-in"] = copy.deepcopy(
            config["override"]["oidcc-ensure-registered-redirect-uri"]
        )
        cases.append(config)
        config = valid_config()
        config["override"]["oidcc-ensure-registered-redirect-uri"]["browser"][0][
            "match"
        ] = "https://unrelated.example/authorize*"
        config["override"]["oidcc-ensure-registered-redirect-uri"]["browser"][0][
            "tasks"
        ][0]["match"] = "https://unrelated.example/authorize*"
        cases.append(config)
        config = valid_config()
        config["override"]["oidcc-ensure-registered-redirect-uri"]["browser"][0][
            "match-limit"
        ] = 0
        cases.append(config)
        config = valid_config()
        config["override"]["oidcc-ensure-registered-redirect-uri"]["browser"][0][
            "tasks"
        ][0]["optional"] = True
        cases.append(config)
        config = valid_config()
        config["override"]["oidcc-ensure-registered-redirect-uri"]["browser"][0][
            "tasks"
        ][0]["commands"][0][4] = "login_required"
        cases.append(config)
        config = valid_config()
        config["override"]["oidcc-ensure-request-object-with-redirect-uri"]["browser"][
            0
        ]["tasks"][0]["commands"][0][4] = "invalid_request"
        cases.append(config)
        config = valid_config()
        config["override"]["oidcc-response-type-missing"] = copy.deepcopy(
            config["override"]["oidcc-ensure-registered-redirect-uri"]
        )
        config["override"]["oidcc-response-type-missing"]["browser"][0]["tasks"][0][
            "commands"
        ][0][4] = "login_required"
        cases.append(config)

        for config in cases:
            with self.subTest(config=config):
                completed, summary = self.run_validator(config)
                self.assertEqual(completed.returncode, 1)
                self.assertFalse(summary["valid"])

    def test_rejects_browser_arguments_unsupported_by_oidf_runner(self) -> None:
        invalid_commands = [
            ["click", "role", "button"],
            ["click", "id", "button", "sometimes"],
            ["text", "id", "email", 123],
            ["wait", "id", "ready", "30"],
            ["wait", "contains", "/callback", 30, "unused-regex"],
            [
                "wait",
                "xpath",
                "//*",
                30,
                "invalid_request",
                "unknown-action",
            ],
            ["wait-element-visible", "id", "ready", 0],
        ]

        for command in invalid_commands:
            config = valid_config()
            config["browser"][1]["tasks"][0]["commands"].append(command)
            with self.subTest(command=command):
                completed, summary = self.run_validator(config)
                self.assertEqual(completed.returncode, 1)
                self.assertFalse(summary["valid"])


if __name__ == "__main__":
    unittest.main()
