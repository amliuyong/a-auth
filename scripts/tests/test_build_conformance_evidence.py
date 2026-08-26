import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BUILDER = REPO_ROOT / "scripts" / "build_conformance_evidence.py"


class BuildConformanceEvidenceCliTests(unittest.TestCase):
    def test_combines_suite_results_with_deployment_identity(self) -> None:
        suites = [
            {
                "id": "agent-auth-rfc9700",
                "kind": "project-regression",
                "version": "agent-auth@abc123",
                "source_url": "https://github.com/example/agent-auth/tree/abc123",
                "result_url": "https://github.com/example/agent-auth/actions/runs/1",
                "metadata_and_runtime": True,
                "tests": [{"id": "pkce", "status": "passed", "required": True}],
            },
            {
                "id": "oidc-basic-op-code",
                "kind": "oidf-plan",
                "version": "oidf-conformance-suite@v5.1.37",
                "source_url": "https://gitlab.com/openid/conformance-suite",
                "result_url": "https://www.certification.openid.net/plan/1",
                "metadata_and_runtime": True,
                "tests": [{"id": "code-flow", "status": "passed", "required": True}],
            },
        ]

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            suite_paths = []
            for index, suite in enumerate(suites):
                path = root / f"suite-{index}.json"
                path.write_text(json.dumps(suite))
                suite_paths.append(path)
            exceptions_path = root / "exceptions.json"
            exceptions_path.write_text("[]")
            preflight_paths = []
            for phase in ("start", "end"):
                path = root / f"deployment-{phase}.json"
                path.write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "phase": phase,
                            "status": "passed",
                            "issuer": "https://issuer.example.com",
                            "expected_deployment_version": "a" * 40,
                            "deployment_version": "a" * 40,
                        }
                    )
                )
                preflight_paths.append(path)
            output = root / "evidence.json"

            completed = subprocess.run(
                [
                    sys.executable,
                    str(BUILDER),
                    "--issuer",
                    "https://issuer.example.com",
                    "--deployment-version",
                    "a" * 40,
                    "--generated-at",
                    "2026-08-01T12:00:00Z",
                    "--claim",
                    "oidc-basic-op-code",
                    "--suite",
                    str(suite_paths[0]),
                    "--suite",
                    str(suite_paths[1]),
                    "--deployment-preflight",
                    str(preflight_paths[0]),
                    "--deployment-preflight",
                    str(preflight_paths[1]),
                    "--exceptions",
                    str(exceptions_path),
                    "--output",
                    str(output),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            evidence = json.loads(output.read_text())

        self.assertEqual(evidence["schema_version"], 1)
        self.assertEqual(
            evidence["deployment"],
            {"issuer": "https://issuer.example.com", "version": "a" * 40},
        )
        self.assertEqual(evidence["requested_claims"], ["oidc-basic-op-code"])
        self.assertEqual(evidence["suites"], suites)
        self.assertEqual(
            [preflight["phase"] for preflight in evidence["deployment_preflights"]],
            ["start", "end"],
        )
        self.assertEqual(evidence["exceptions"], [])


if __name__ == "__main__":
    unittest.main()
