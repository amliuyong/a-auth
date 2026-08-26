import copy
import unittest
from pathlib import Path

from scripts.ci_required_gate import EXPECTED_JOBS, validate_results

REPO_ROOT = Path(__file__).resolve().parents[2]
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"


class RequiredCiGateTests(unittest.TestCase):
    def successful_results(self) -> dict[str, dict[str, str]]:
        return {job: {"result": "success"} for job in EXPECTED_JOBS}

    def test_pull_request_requires_every_job_to_succeed(self) -> None:
        validate_results("pull_request", self.successful_results())

        for job in EXPECTED_JOBS:
            with self.subTest(job=job):
                results = self.successful_results()
                results[job]["result"] = "skipped"
                with self.assertRaisesRegex(
                    ValueError,
                    f"{job} must conclude success",
                ):
                    validate_results("pull_request", results)

    def test_push_and_dispatch_require_every_job_to_succeed(self) -> None:
        for event_name in ("push", "workflow_dispatch"):
            with self.subTest(event_name=event_name):
                validate_results(event_name, self.successful_results())
                results = self.successful_results()
                results["conformance-exact"]["result"] = "skipped"
                with self.assertRaisesRegex(
                    ValueError,
                    "conformance-exact must conclude success",
                ):
                    validate_results(event_name, results)

    def test_failure_cancellation_missing_and_extra_jobs_fail_closed(self) -> None:
        for result in ("failure", "cancelled"):
            with self.subTest(result=result):
                results = self.successful_results()
                results["rust-tests"]["result"] = result
                with self.assertRaisesRegex(
                    ValueError,
                    "rust-tests must conclude success",
                ):
                    validate_results("push", results)

        missing = self.successful_results()
        missing.pop("web-checks")
        with self.assertRaisesRegex(ValueError, "CI dependency set drifted"):
            validate_results("push", missing)

        extra = copy.deepcopy(self.successful_results())
        extra["unreviewed-job"] = {"result": "success"}
        with self.assertRaisesRegex(ValueError, "CI dependency set drifted"):
            validate_results("push", extra)

    def test_workflow_wires_the_stable_required_check(self) -> None:
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        required_job = workflow.split("\n  required-ci:\n", maxsplit=1)[1]

        self.assertIn("    name: Required CI\n", required_job)
        self.assertIn("    if: ${{ always() }}\n", required_job)
        self.assertIn(
            "python3 -m unittest scripts.tests.test_ci_required_gate -v",
            required_job,
        )
        self.assertIn(
            "python3 scripts/ci_required_gate.py",
            required_job,
        )
        self.assertNotIn("github.event_name != 'pull_request'", workflow)
        for job in EXPECTED_JOBS:
            self.assertIn(f"      - {job}\n", required_job)


if __name__ == "__main__":
    unittest.main()
