import copy
import unittest
from pathlib import Path

from scripts.ci_required_gate import EXPECTED_JOBS, validate_results

REPO_ROOT = Path(__file__).resolve().parents[2]
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"


class RequiredCiGateTests(unittest.TestCase):
    def successful_results(self) -> dict[str, dict[str, str]]:
        return {job: {"result": "success"} for job in EXPECTED_JOBS}

    def test_pull_request_allows_only_full_conformance_to_be_skipped(self) -> None:
        validate_results("pull_request", self.successful_results())
        results = self.successful_results()
        results["conformance-exact"]["result"] = "skipped"
        validate_results("pull_request", results)

        for job in EXPECTED_JOBS:
            if job == "conformance-exact":
                continue
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
        for event_name in ("pull_request", "push", "workflow_dispatch"):
            for job in EXPECTED_JOBS:
                for result in ("failure", "cancelled"):
                    with self.subTest(event=event_name, job=job, result=result):
                        results = self.successful_results()
                        results[job]["result"] = result
                        with self.assertRaisesRegex(
                            ValueError,
                            f"{job} must conclude success",
                        ):
                            validate_results(event_name, results)

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
        for job in EXPECTED_JOBS:
            self.assertIn(f"      - {job}\n", required_job)

    def test_only_full_selectors_run_after_merge_or_manual_dispatch(self) -> None:
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        exact_job = workflow.split("\n  conformance-exact:\n", maxsplit=1)[1].split(
            "\n  sdk-checks:\n", maxsplit=1
        )[0]
        condition = "    if: ${{ github.event_name != 'pull_request' }}\n"
        self.assertIn(condition, exact_job)
        self.assertEqual(workflow.count(condition), 1)
        self.assertIn("run: ./scripts/run_conformance_exact_tests.sh", exact_job)


if __name__ == "__main__":
    unittest.main()
