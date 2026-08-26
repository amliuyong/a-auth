import base64
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

REPO_ROOT = Path(__file__).resolve().parents[2]
CONVERTER = REPO_ROOT / "scripts" / "oidf_basic_op_evidence.py"
RUNNER_COMMIT = "932b46f1e507871eb0b34621aaef65ff04442e6f"
SIGNING_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
SIGNING_KID = "test-export-signing-key"


def encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode()


def export_jwks() -> dict:
    numbers = SIGNING_KEY.public_key().public_numbers()
    modulus = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    exponent = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    return {
        "keys": [
            {
                "kty": "RSA",
                "kid": SIGNING_KID,
                "alg": "RS256",
                "use": "sig",
                "n": encode_base64url(modulus).rstrip("="),
                "e": encode_base64url(exponent).rstrip("="),
            }
        ]
    }


def plan_info() -> dict:
    return {
        "_id": "plan-1",
        "planName": "oidcc-basic-certification-test-plan",
        "variant": {
            "variant": {
                "server_metadata": "discovery",
                "client_registration": "dynamic_client",
            }
        },
        "modules": [
            {
                "testModule": "oidcc-server",
                "variant": {
                    "response_type": "code",
                    "client_auth_type": "client_secret_basic",
                },
                "instances": ["instance-1"],
            },
            {
                "testModule": "oidcc-server-secret-post",
                "variant": {
                    "response_type": "code",
                    "client_auth_type": "client_secret_post",
                },
                "instances": ["instance-2"],
            },
        ],
    }


def exported_test(
    instance_id: str,
    test_name: str,
    *,
    status: str = "FINISHED",
    result: str = "PASSED",
) -> dict:
    client_auth_type = (
        "client_secret_post"
        if test_name == "oidcc-server-secret-post"
        else "client_secret_basic"
    )
    return {
        "exportedVersion": "release-v5.2.1-932b46f",
        "exportedFrom": "https://www.certification.openid.net/",
        "testInfo": {
            "testId": instance_id,
            "testName": test_name,
            "planId": "plan-1",
            "status": status,
            "result": result,
            "variant": {
                "variant": {
                    "server_metadata": "discovery",
                    "client_registration": "dynamic_client",
                    "response_type": "code",
                    "client_auth_type": client_auth_type,
                }
            },
        },
        "results": [
            {
                "src": "UnregisterDynamicallyRegisteredClient",
                "result": "SUCCESS",
                "msg": "Client successfully unregistered",
            }
        ],
    }


class OidfBasicOpEvidenceCliTests(unittest.TestCase):
    def run_converter(
        self,
        plan: dict,
        exports: list[dict],
        *,
        omit_signature: int | None = None,
        tamper_signature: int | None = None,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan_path = root / "plan.json"
            export_path = root / "export.zip"
            jwks_path = root / "jwks.json"
            output_path = root / "suite.json"
            plan_path.write_text(json.dumps(plan))
            jwks_path.write_text(json.dumps(export_jwks()))
            with zipfile.ZipFile(export_path, "w") as archive:
                for index, exported in enumerate(exports):
                    payload = json.dumps(exported).encode()
                    archive.writestr(f"test-log-{index}.json", payload)
                    if index == omit_signature:
                        continue
                    signature = SIGNING_KEY.sign(
                        payload,
                        padding.PKCS1v15(),
                        hashes.SHA256(),
                    )
                    if index == tamper_signature:
                        signature = bytes([signature[0] ^ 1]) + signature[1:]
                    archive.writestr(
                        f"test-log-{index}.sig",
                        encode_base64url(signature),
                    )
            completed = subprocess.run(
                [
                    sys.executable,
                    str(CONVERTER),
                    "--export",
                    str(export_path),
                    "--plan-info",
                    str(plan_path),
                    "--jwks",
                    str(jwks_path),
                    "--expected-origin",
                    "https://www.certification.openid.net/",
                    "--runner-ref",
                    "release-v5.2.1",
                    "--runner-commit",
                    RUNNER_COMMIT,
                    "--runner-exit-code",
                    "1",
                    "--source-url",
                    (
                        "https://gitlab.com/openid/conformance-suite/"
                        "-/tree/release-v5.2.1"
                    ),
                    "--output",
                    str(output_path),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            suite = json.loads(output_path.read_text())
        return completed, suite

    def test_converts_complete_plan_and_preserves_upstream_results(self) -> None:
        completed, suite = self.run_converter(
            plan_info(),
            [
                exported_test("instance-1", "oidcc-server"),
                exported_test(
                    "instance-2",
                    "oidcc-server-secret-post",
                    result="WARNING",
                ),
            ],
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(suite["id"], "oidf-basic-op-code")
        self.assertEqual(suite["plan"]["module_count"], 2)
        self.assertEqual(suite["plan"]["runner_exit_code"], 1)
        self.assertTrue(suite["plan"]["signatures_verified"])
        self.assertEqual(
            {test["signature_key_id"] for test in suite["tests"]},
            {SIGNING_KID},
        )
        self.assertEqual(
            {test["status"] for test in suite["tests"]},
            {"passed", "failed"},
        )
        warning = next(
            test for test in suite["tests"] if test["instance_id"] == "instance-2"
        )
        self.assertEqual(warning["upstream_result"], "WARNING")
        self.assertEqual(warning["dynamic_client_cleanup"], "passed")

    def test_cleanup_warning_is_explicitly_non_waivable(self) -> None:
        cleanup_failure = exported_test(
            "instance-1",
            "oidcc-server",
            result="WARNING",
        )
        cleanup_failure["results"][0]["result"] = "WARNING"
        completed, suite = self.run_converter(
            plan_info(),
            [
                cleanup_failure,
                exported_test("instance-2", "oidcc-server-secret-post"),
            ],
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        failed = next(
            test for test in suite["tests"] if test["instance_id"] == "instance-1"
        )
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["dynamic_client_cleanup"], "failed")
        self.assertIs(failed["waivable"], False)

    def test_resultless_cleanup_logs_do_not_override_success_verdict(self) -> None:
        cleanup_with_progress_logs = exported_test("instance-1", "oidcc-server")
        success = cleanup_with_progress_logs["results"][0]
        cleanup_with_progress_logs["results"] = [
            {
                "src": "UnregisterDynamicallyRegisteredClient",
                "msg": "cleanup progress log one",
            },
            {
                "src": "UnregisterDynamicallyRegisteredClient",
                "msg": "cleanup progress log two",
            },
            success,
        ]
        completed, suite = self.run_converter(
            plan_info(),
            [
                cleanup_with_progress_logs,
                exported_test("instance-2", "oidcc-server-secret-post"),
            ],
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        cleaned = next(
            test for test in suite["tests"] if test["instance_id"] == "instance-1"
        )
        self.assertEqual(cleaned["dynamic_client_cleanup"], "passed")
        self.assertEqual(cleaned["dynamic_client_cleanup_attempts"], 1)

    def test_cleanup_is_not_required_when_suite_skips_before_registration(
        self,
    ) -> None:
        skipped_before_registration = exported_test(
            "instance-1",
            "oidcc-server",
            result="SKIPPED",
        )
        skipped_before_registration["results"] = [
            {
                "src": "UnregisterDynamicallyRegisteredClient",
                "result": "INFO",
                "msg": "Skipped evaluation due to missing required object: client",
                "expected": "client",
                "mapped": None,
            }
        ]
        completed, suite = self.run_converter(
            plan_info(),
            [
                skipped_before_registration,
                exported_test("instance-2", "oidcc-server-secret-post"),
            ],
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        skipped = next(
            test for test in suite["tests"] if test["instance_id"] == "instance-1"
        )
        self.assertEqual(skipped["status"], "failed")
        self.assertEqual(skipped["upstream_result"], "SKIPPED")
        self.assertEqual(skipped["dynamic_client_cleanup"], "not_required")
        self.assertEqual(skipped["dynamic_client_cleanup_attempts"], 0)
        self.assertNotIn("waivable", skipped)

    def test_cleanup_not_required_evidence_must_match_exactly(self) -> None:
        exact_cleanup = {
            "src": "UnregisterDynamicallyRegisteredClient",
            "result": "INFO",
            "msg": "Skipped evaluation due to missing required object: client",
            "expected": "client",
            "mapped": None,
        }
        cases = []

        changed = dict(exact_cleanup)
        changed["msg"] = "Skipped cleanup"
        cases.append(("different message", [changed]))

        changed = dict(exact_cleanup)
        changed["expected"] = "client2"
        cases.append(("different expected object", [changed]))

        changed = dict(exact_cleanup)
        changed["mapped"] = "client"
        cases.append(("mapped client object", [changed]))

        cases.append(
            (
                "registration endpoint was called",
                [
                    {
                        "src": "CallDynamicRegistrationEndpoint",
                        "result": "SUCCESS",
                        "msg": "Registration endpoint returned a response",
                    },
                    exact_cleanup,
                ],
            )
        )

        cases.append(("duplicate cleanup entries", [exact_cleanup, exact_cleanup]))

        for name, results in cases:
            with self.subTest(name=name):
                cleanup = exported_test(
                    "instance-1",
                    "oidcc-server",
                    result="SKIPPED",
                )
                cleanup["results"] = results
                completed, suite = self.run_converter(
                    plan_info(),
                    [
                        cleanup,
                        exported_test("instance-2", "oidcc-server-secret-post"),
                    ],
                )

                self.assertEqual(completed.returncode, 0, completed.stderr)
                failed = next(
                    test
                    for test in suite["tests"]
                    if test["instance_id"] == "instance-1"
                )
                self.assertEqual(failed["dynamic_client_cleanup"], "failed")
                self.assertIs(failed["waivable"], False)

    def test_passed_module_cannot_report_cleanup_not_required(self) -> None:
        passed_without_registration = exported_test("instance-1", "oidcc-server")
        passed_without_registration["results"] = [
            {
                "src": "UnregisterDynamicallyRegisteredClient",
                "result": "INFO",
                "msg": "Skipped evaluation due to missing required object: client",
                "expected": "client",
                "mapped": None,
            }
        ]
        completed, suite = self.run_converter(
            plan_info(),
            [
                passed_without_registration,
                exported_test("instance-2", "oidcc-server-secret-post"),
            ],
        )

        self.assertEqual(completed.returncode, 1)
        self.assertIn(
            "passed without dynamic-client cleanup",
            suite["conversion_error"],
        )

    def test_fails_closed_when_cleanup_result_is_missing(self) -> None:
        missing_cleanup = exported_test("instance-1", "oidcc-server")
        missing_cleanup["results"] = []
        completed, suite = self.run_converter(
            plan_info(),
            [
                missing_cleanup,
                exported_test("instance-2", "oidcc-server-secret-post"),
            ],
        )

        self.assertEqual(completed.returncode, 1)
        self.assertIn("no dynamic-client cleanup result", suite["conversion_error"])

    def test_missing_cleanup_verdict_is_a_non_waivable_failure(self) -> None:
        missing_verdict = exported_test("instance-1", "oidcc-server")
        missing_verdict["results"] = [
            {
                "src": "UnregisterDynamicallyRegisteredClient",
                "msg": "cleanup progress log",
            }
        ]
        completed, suite = self.run_converter(
            plan_info(),
            [
                missing_verdict,
                exported_test("instance-2", "oidcc-server-secret-post"),
            ],
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        failed = next(
            test for test in suite["tests"] if test["instance_id"] == "instance-1"
        )
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["upstream_result"], "PASSED")
        self.assertEqual(failed["dynamic_client_cleanup"], "failed")
        self.assertEqual(failed["dynamic_client_cleanup_attempts"], 0)
        self.assertIs(failed["waivable"], False)

    def test_fails_closed_when_one_cleanup_result_is_malformed(self) -> None:
        malformed_cleanup = exported_test("instance-1", "oidcc-server")
        malformed_cleanup["results"].append(
            {
                "src": "UnregisterDynamicallyRegisteredClient",
                "result": {"status": "must-not-appear-in-public-evidence"},
                "msg": "must-not-appear-in-public-evidence",
            }
        )
        completed, suite = self.run_converter(
            plan_info(),
            [
                malformed_cleanup,
                exported_test("instance-2", "oidcc-server-secret-post"),
            ],
        )

        self.assertEqual(completed.returncode, 1)
        self.assertIn(
            "malformed dynamic-client cleanup result", suite["conversion_error"]
        )
        self.assertIn(
            "cleanup entries=2; result shapes=[nonempty-string, object]",
            suite["conversion_error"],
        )
        self.assertNotIn("must-not-appear", suite["conversion_error"])

    def test_fails_closed_when_plan_module_export_is_missing(self) -> None:
        completed, suite = self.run_converter(
            plan_info(),
            [exported_test("instance-1", "oidcc-server")],
        )

        self.assertEqual(completed.returncode, 1)
        self.assertIn("omits plan instances", suite["conversion_error"])

    def test_interrupted_module_is_an_error_not_a_waivable_failure(self) -> None:
        completed, suite = self.run_converter(
            plan_info(),
            [
                exported_test(
                    "instance-1",
                    "oidcc-server",
                    status="INTERRUPTED",
                    result="UNKNOWN",
                ),
                exported_test("instance-2", "oidcc-server-secret-post"),
            ],
        )

        self.assertEqual(completed.returncode, 0)
        interrupted = next(
            test for test in suite["tests"] if test["instance_id"] == "instance-1"
        )
        self.assertEqual(interrupted["status"], "error")

    def test_fails_closed_on_wrong_executed_module_variant(self) -> None:
        wrong_variant = exported_test("instance-1", "oidcc-server")
        wrong_variant["testInfo"]["variant"]["variant"]["client_auth_type"] = (
            "client_secret_post"
        )
        completed, suite = self.run_converter(
            plan_info(),
            [
                wrong_variant,
                exported_test("instance-2", "oidcc-server-secret-post"),
            ],
        )

        self.assertEqual(completed.returncode, 1)
        self.assertIn("expected module variants", suite["conversion_error"])

    def test_fails_closed_on_untrusted_export_origin(self) -> None:
        first = exported_test("instance-1", "oidcc-server")
        second = exported_test("instance-2", "oidcc-server-secret-post")
        first["exportedFrom"] = "https://attacker.example/"
        second["exportedFrom"] = "https://attacker.example/"
        completed, suite = self.run_converter(
            plan_info(),
            [first, second],
        )

        self.assertEqual(completed.returncode, 1)
        self.assertIn("trusted suite origin", suite["conversion_error"])

    def test_fails_closed_when_signature_member_is_missing(self) -> None:
        completed, suite = self.run_converter(
            plan_info(),
            [
                exported_test("instance-1", "oidcc-server"),
                exported_test("instance-2", "oidcc-server-secret-post"),
            ],
            omit_signature=1,
        )

        self.assertEqual(completed.returncode, 1)
        self.assertIn("no matching OIDF signature", suite["conversion_error"])

    def test_fails_closed_when_export_signature_is_invalid(self) -> None:
        completed, suite = self.run_converter(
            plan_info(),
            [
                exported_test("instance-1", "oidcc-server"),
                exported_test("instance-2", "oidcc-server-secret-post"),
            ],
            tamper_signature=0,
        )

        self.assertEqual(completed.returncode, 1)
        self.assertIn("does not verify", suite["conversion_error"])


if __name__ == "__main__":
    unittest.main()
