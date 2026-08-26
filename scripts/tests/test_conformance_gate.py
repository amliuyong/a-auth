import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
GATE = REPO_ROOT / "scripts" / "conformance_gate.py"
POLICY = REPO_ROOT / ".github" / "conformance" / "policy.json"
ISSUER = "https://issuer.example.com"
VERSION = "a" * 40
NOW = "2026-08-01T13:00:00Z"
RUNNER_COMMIT = "932b46f1e507871eb0b34621aaef65ff04442e6f"


def rfc_test(status: str = "passed") -> dict:
    return {
        "id": "runtime-reject-implicit",
        "status": status,
        "required": True,
        "standard": "RFC 9700",
        "section": "2.1.2",
        "request": "GET authorization endpoint with response_type=token",
        "expected": "unsupported_response_type",
        "applicability": "implicit flow is disabled",
        "observed": "HTTP 400",
    }


def cleanup_test(status: str = "passed") -> dict:
    return {
        "id": "dynamic-client-cleanup",
        "status": status,
        "required": True,
        "waivable": False,
        "standard": "RFC 7592",
        "section": "3",
        "request": "DELETE dynamic-client management URI",
        "expected": "HTTP 204",
        "applicability": "dynamic registration created a client",
        "observed": "HTTP 204",
    }


def oidf_test(
    status: str = "passed",
    *,
    upstream_status: str = "FINISHED",
    upstream_result: str = "PASSED",
) -> dict:
    return {
        "id": (
            "oidcc-server[client_auth_type=client_secret_basic][response_type=code]"
        ),
        "instance_id": "instance-1",
        "status": status,
        "required": True,
        "upstream_status": upstream_status,
        "upstream_result": upstream_result,
        "dynamic_client_cleanup": "passed",
        "dynamic_client_cleanup_attempts": 1,
        "signature_key_id": "production-signing-key",
        "log_url": "https://www.certification.openid.net/log-detail.html?log=instance-1",
    }


def deployment_preflights() -> list[dict]:
    return [
        {
            "schema_version": 1,
            "phase": phase,
            "status": "passed",
            "issuer": ISSUER,
            "expected_deployment_version": VERSION,
            "deployment_version": VERSION,
        }
        for phase in ("start", "end")
    ]


def passing_evidence() -> dict:
    return {
        "schema_version": 1,
        "generated_at": "2026-08-01T12:00:00Z",
        "deployment": {"issuer": ISSUER, "version": VERSION},
        "deployment_preflights": deployment_preflights(),
        "requested_claims": ["oidc-basic-op-code"],
        "suites": [
            {
                "id": "agent-auth-rfc9700",
                "kind": "project-regression",
                "version": "agent-auth@abc123",
                "source_url": "https://github.com/example/agent-auth/tree/abc123",
                "result_url": "https://github.com/example/agent-auth/actions/runs/1",
                "metadata_and_runtime": True,
                "standard_url": "https://www.rfc-editor.org/rfc/rfc9700.html",
                "non_certification_statement": (
                    "Project regression for selected RFC 9700 requirements; "
                    "not an OIDF certification suite."
                ),
                "tests": [rfc_test(), cleanup_test()],
            },
            {
                "id": "oidf-basic-op-code",
                "kind": "oidf-plan",
                "version": "release-v5.2.1-932b46f",
                "source_url": (
                    "https://gitlab.com/openid/conformance-suite/-/tree/release-v5.2.1"
                ),
                "result_url": "https://www.certification.openid.net/plan-detail.html?plan=1",
                "metadata_and_runtime": True,
                "plan": {
                    "id": "1",
                    "name": "oidcc-basic-certification-test-plan",
                    "variants": {
                        "server_metadata": "discovery",
                        "client_registration": "dynamic_client",
                    },
                    "module_count": 1,
                    "runner_ref": "release-v5.2.1",
                    "runner_commit": RUNNER_COMMIT,
                    "runner_exit_code": 0,
                    "export_origin": "https://www.certification.openid.net/",
                    "signatures_verified": True,
                },
                "tests": [oidf_test()],
            },
        ],
        "exceptions": [],
    }


class ConformanceGateCliTests(unittest.TestCase):
    def run_gate(self, evidence: dict, policy: dict | None = None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence_path = root / "evidence.json"
            policy_path = root / "policy.json"
            summary_path = root / "summary.md"
            approved_claims_path = root / "approved-profile-claims.json"
            evidence_path.write_text(json.dumps(evidence))
            policy_path.write_text(json.dumps(policy or json.loads(POLICY.read_text())))
            completed = subprocess.run(
                [
                    sys.executable,
                    str(GATE),
                    "--evidence",
                    str(evidence_path),
                    "--policy",
                    str(policy_path),
                    "--expected-issuer",
                    ISSUER,
                    "--expected-deployment-version",
                    VERSION,
                    "--now",
                    NOW,
                    "--summary",
                    str(summary_path),
                    "--approved-claims",
                    str(approved_claims_path),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            summary = summary_path.read_text() if summary_path.exists() else ""
            approved_claims = (
                json.loads(approved_claims_path.read_text())
                if approved_claims_path.exists()
                else None
            )
        return completed, summary, approved_claims

    def test_required_suites_pass_for_the_deployed_issuer(self) -> None:
        completed, summary, approved_claims = self.run_gate(passing_evidence())

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("# External conformance gate: PASS", summary)
        self.assertIn("Required tests passed: 3", summary)
        self.assertIn("https://www.certification.openid.net/plan-detail", summary)
        self.assertEqual(approved_claims["schema_version"], 2)
        self.assertEqual(
            approved_claims["approved_profile_claims"],
            ["oidc-basic-op-code"],
        )
        self.assertIn("fapi", approved_claims["explicit_non_claims"])
        self.assertIn("openid-federation", approved_claims["explicit_non_claims"])
        self.assertEqual(approved_claims["deployment"]["version"], VERSION)
        self.assertEqual(approved_claims["valid_until"], "2026-08-02T12:00:00Z")
        self.assertRegex(approved_claims["evidence_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(approved_claims["policy_version"], "2026-08-08")
        self.assertRegex(approved_claims["policy_sha256"], r"^[0-9a-f]{64}$")

    def test_required_failure_blocks_and_is_reported(self) -> None:
        evidence = passing_evidence()
        evidence["suites"][0]["tests"][0]["status"] = "failed"

        completed, summary, approved_claims = self.run_gate(evidence)

        self.assertEqual(completed.returncode, 1)
        self.assertIsNone(approved_claims)
        self.assertIn("# External conformance gate: FAIL", summary)
        self.assertIn(
            "agent-auth-rfc9700/runtime-reject-implicit",
            summary,
        )

    def test_not_required_cleanup_with_zero_attempts_can_reach_policy(self) -> None:
        evidence = passing_evidence()
        oidf = evidence["suites"][1]["tests"][0]
        oidf["status"] = "failed"
        oidf["upstream_result"] = "SKIPPED"
        oidf["dynamic_client_cleanup"] = "not_required"
        oidf["dynamic_client_cleanup_attempts"] = 0
        evidence["suites"][1]["plan"]["runner_exit_code"] = 1
        evidence["exceptions"] = [
            {
                "suite_id": "oidf-basic-op-code",
                "test_id": oidf["id"],
                "approved_by": "@release-owner",
                "approved_at": "2026-08-01T12:30:00Z",
                "reason": "The optional module is not applicable",
                "issue_url": "https://github.com/amliuyong/a-auth/issues/99",
                "expires_at": "2026-08-03T00:00:00Z",
            }
        ]

        completed, summary, approved_claims = self.run_gate(evidence)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIsNotNone(approved_claims)
        self.assertIn("Required tests waived: 1", summary)

    def test_approved_unexpired_exception_waives_exact_failure(self) -> None:
        evidence = passing_evidence()
        evidence["suites"][0]["tests"][0]["status"] = "failed"
        evidence["exceptions"] = [
            {
                "suite_id": "agent-auth-rfc9700",
                "test_id": "runtime-reject-implicit",
                "approved_by": "@release-owner",
                "approved_at": "2026-08-01T12:30:00Z",
                "reason": "Tracked regression under investigation",
                "issue_url": "https://github.com/amliuyong/a-auth/issues/99",
                "expires_at": "2026-08-03T00:00:00Z",
            }
        ]

        completed, summary, approved_claims = self.run_gate(evidence)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIsNotNone(approved_claims)
        self.assertIn("Required tests waived: 1", summary)
        self.assertIn("agent-auth-rfc9700/runtime-reject-implicit", summary)

    def test_untrusted_or_incomplete_evidence_fails_closed(self) -> None:
        cases = []
        invalid = passing_evidence()
        invalid["schema_version"] = 2
        cases.append(("schema version", invalid, "schema_version"))
        invalid = passing_evidence()
        invalid.pop("deployment_preflights")
        cases.append(("missing deployment preflights", invalid, "preflights"))
        invalid = passing_evidence()
        invalid["deployment_preflights"][1]["deployment_version"] = "b" * 40
        cases.append(("changed deployment during suites", invalid, "end preflight"))
        invalid = passing_evidence()
        invalid["suites"].pop()
        cases.append(("missing suite", invalid, "required_suites"))
        invalid = passing_evidence()
        invalid["suites"][0]["metadata_and_runtime"] = False
        cases.append(("metadata only", invalid, "metadata_and_runtime"))
        invalid = passing_evidence()
        invalid["suites"][0]["tests"] = []
        cases.append(("empty test set", invalid, "required test"))
        invalid = passing_evidence()
        optional = rfc_test()
        optional["id"] = "optional-test"
        optional["required"] = False
        invalid["suites"][0]["tests"].append(optional)
        cases.append(("optional required-suite test", invalid, "every test"))
        invalid = passing_evidence()
        invalid["suites"][0]["version"] = ""
        cases.append(("missing version", invalid, "version"))
        invalid = passing_evidence()
        invalid["requested_claims"].append("fapi2-security-profile")
        cases.append(("extra claim", invalid, "claims"))
        invalid = passing_evidence()
        policy = json.loads(POLICY.read_text())
        policy["explicit_non_claims"].append("oidc-basic-op-code")
        completed, summary, approved_claims = self.run_gate(invalid, policy)
        self.assertEqual(completed.returncode, 1)
        self.assertIsNone(approved_claims)
        self.assertIn("overlap", summary)
        invalid = passing_evidence()
        invalid["generated_at"] = "2026-07-30T12:00:00Z"
        cases.append(("stale", invalid, "generated_at"))
        invalid = passing_evidence()
        invalid["suites"].append(copy.deepcopy(invalid["suites"][0]))
        cases.append(("duplicate suite", invalid, "duplicate"))
        invalid = passing_evidence()
        invalid["suites"][0]["tests"][0]["status"] = "unknown"
        cases.append(("unknown status", invalid, "status"))
        invalid = passing_evidence()
        invalid["suites"][1]["plan"]["variants"]["server_metadata"] = "static"
        cases.append(("wrong plan variant", invalid, "variants"))
        invalid = passing_evidence()
        invalid["suites"][1]["plan"]["runner_commit"] = "b" * 40
        cases.append(("wrong runner commit", invalid, "runner_commit"))
        invalid = passing_evidence()
        invalid["suites"][1]["tests"][0]["upstream_result"] = "WARNING"
        cases.append(("false passed OIDF warning", invalid, "FINISHED/PASSED"))
        invalid = passing_evidence()
        invalid["suites"][1]["tests"][0]["status"] = "failed"
        invalid["suites"][1]["tests"][0]["upstream_result"] = "WARNING"
        invalid["suites"][1]["tests"][0]["dynamic_client_cleanup"] = "failed"
        invalid["suites"][1]["tests"][0]["waivable"] = False
        cases.append(("OIDF cleanup failure", invalid, "cleanup evidence is invalid"))
        invalid = passing_evidence()
        invalid["suites"][1]["tests"][0]["dynamic_client_cleanup"] = "not_required"
        invalid["suites"][1]["tests"][0]["dynamic_client_cleanup_attempts"] = 1
        cases.append(
            (
                "not-required cleanup with attempts",
                invalid,
                "cleanup evidence is invalid",
            )
        )
        invalid = passing_evidence()
        invalid["suites"][1]["tests"][0]["dynamic_client_cleanup"] = "not_required"
        invalid["suites"][1]["tests"][0]["dynamic_client_cleanup_attempts"] = 0
        cases.append(
            (
                "passing module without cleanup",
                invalid,
                "passing module cannot omit dynamic-client cleanup",
            )
        )
        invalid = passing_evidence()
        invalid["suites"][1]["tests"][0]["status"] = "failed"
        invalid["suites"][1]["tests"][0]["dynamic_client_cleanup"] = "not_required"
        invalid["suites"][1]["tests"][0]["dynamic_client_cleanup_attempts"] = 0
        invalid["suites"][1]["plan"]["runner_exit_code"] = 1
        cases.append(
            (
                "rewritten failure passed upstream without cleanup",
                invalid,
                "passed upstream without dynamic-client cleanup",
            )
        )
        invalid = passing_evidence()
        invalid["suites"][1]["tests"][0]["dynamic_client_cleanup_attempts"] = 0
        cases.append(
            ("passed cleanup without attempts", invalid, "cleanup evidence is invalid")
        )
        invalid = passing_evidence()
        invalid["suites"][1]["tests"][0]["dynamic_client_cleanup_attempts"] = True
        cases.append(
            ("boolean cleanup attempts", invalid, "cleanup evidence is invalid")
        )
        invalid = passing_evidence()
        invalid["suites"][1]["plan"]["runner_exit_code"] = 1
        cases.append(
            ("runner failed with green export", invalid, "official runner failed")
        )

        for name, invalid_evidence, expected_reason in cases:
            with self.subTest(name=name):
                completed, summary, approved_claims = self.run_gate(invalid_evidence)
                self.assertEqual(completed.returncode, 1)
                self.assertIsNone(approved_claims)
                self.assertIn("# External conformance gate: FAIL", summary)
                self.assertIn(expected_reason, summary)

    def test_interrupted_oidf_run_cannot_be_waived(self) -> None:
        evidence = passing_evidence()
        evidence["suites"][1]["tests"] = [
            oidf_test(
                "error",
                upstream_status="INTERRUPTED",
                upstream_result="UNKNOWN",
            )
        ]
        evidence["exceptions"] = [
            {
                "suite_id": "oidf-basic-op-code",
                "test_id": evidence["suites"][1]["tests"][0]["id"],
                "approved_by": "@release-owner",
                "approved_at": "2026-08-01T12:30:00Z",
                "reason": "Runner was interrupted",
                "issue_url": "https://github.com/amliuyong/a-auth/issues/99",
                "expires_at": "2026-08-03T00:00:00Z",
            }
        ]

        completed, summary, approved_claims = self.run_gate(evidence)

        self.assertEqual(completed.returncode, 1)
        self.assertIsNone(approved_claims)
        self.assertIn("not an error", summary)

    def test_dynamic_client_cleanup_failure_cannot_be_waived(self) -> None:
        evidence = passing_evidence()
        evidence["suites"][0]["tests"][1]["status"] = "failed"
        evidence["exceptions"] = [
            {
                "suite_id": "agent-auth-rfc9700",
                "test_id": "dynamic-client-cleanup",
                "approved_by": "@release-owner",
                "approved_at": "2026-08-01T12:30:00Z",
                "reason": "Cleanup endpoint is temporarily unavailable",
                "issue_url": "https://github.com/amliuyong/a-auth/issues/99",
                "expires_at": "2026-08-03T00:00:00Z",
            }
        ]

        completed, summary, approved_claims = self.run_gate(evidence)

        self.assertEqual(completed.returncode, 1)
        self.assertIsNone(approved_claims)
        self.assertIn("non-waivable cleanup", summary)

    def test_invalid_exception_records_fail_closed(self) -> None:
        evidence = passing_evidence()
        evidence["suites"][0]["tests"][0]["status"] = "failed"
        exception = {
            "suite_id": "agent-auth-rfc9700",
            "test_id": "runtime-reject-implicit",
            "approved_by": "@release-owner",
            "approved_at": "2026-08-01T12:30:00Z",
            "reason": "Tracked suite regression",
            "issue_url": "https://github.com/amliuyong/a-auth/issues/99",
            "expires_at": "2026-08-03T00:00:00Z",
        }
        evidence["exceptions"] = [exception]
        cases = []

        invalid = copy.deepcopy(evidence)
        invalid["exceptions"][0]["expires_at"] = "2026-08-01T12:30:00Z"
        cases.append(("expired", invalid, "expires_at"))
        invalid = copy.deepcopy(evidence)
        invalid["exceptions"][0]["approved_at"] = "2026-08-02T00:00:00Z"
        cases.append(("future approval", invalid, "approved_at"))
        invalid = copy.deepcopy(evidence)
        invalid["exceptions"][0]["expires_at"] = "2026-10-01T00:00:00Z"
        cases.append(("too long", invalid, "max_exception_days"))
        invalid = copy.deepcopy(evidence)
        del invalid["exceptions"][0]["approved_by"]
        cases.append(("missing approver", invalid, "approved_by"))
        invalid = copy.deepcopy(evidence)
        invalid["exceptions"][0]["issue_url"] = "https://example.com/ticket/99"
        cases.append(("invalid issue", invalid, "issue_url"))
        invalid = copy.deepcopy(evidence)
        invalid["suites"][0]["tests"][0]["status"] = "passed"
        cases.append(("exception without failure", invalid, "failed required test"))
        invalid = copy.deepcopy(evidence)
        invalid["exceptions"].append(copy.deepcopy(invalid["exceptions"][0]))
        cases.append(("duplicate exception", invalid, "duplicate exception"))

        for name, invalid_evidence, expected_reason in cases:
            with self.subTest(name=name):
                completed, summary, approved_claims = self.run_gate(invalid_evidence)
                self.assertEqual(completed.returncode, 1)
                self.assertIsNone(approved_claims)
                self.assertIn("# External conformance gate: FAIL", summary)
                self.assertIn(expected_reason, summary)


if __name__ == "__main__":
    unittest.main()
