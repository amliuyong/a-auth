import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"


class CiBrowserIsolationTests(unittest.TestCase):
    def job_block(self, job_id: str) -> str:
        lines = CI_WORKFLOW.read_text(encoding="utf-8").splitlines()
        marker = f"  {job_id}:"
        self.assertIn(marker, lines, f"missing CI job: {job_id}")
        start = lines.index(marker)
        end = next(
            (
                index
                for index in range(start + 1, len(lines))
                if lines[index].startswith("  ")
                and not lines[index].startswith("    ")
                and lines[index].rstrip().endswith(":")
            ),
            len(lines),
        )
        return "\n".join(lines[start:end])

    def test_htmlunit_smoke_has_an_isolated_timeout_budget(self) -> None:
        web_checks = self.job_block("web-checks")
        self.assertNotIn("Run OIDF HtmlUnit browser smoke", web_checks)
        self.assertNotIn("run-oidf-htmlunit-smoke.sh", web_checks)

        htmlunit = self.job_block("oidf-htmlunit-smoke")
        self.assertIn("timeout-minutes: 10", htmlunit)
        self.assertIn("Run OIDF HtmlUnit browser smoke", htmlunit)
        self.assertIn("./scripts/run-oidf-htmlunit-smoke.sh", htmlunit)
        self.assertNotIn("Run exact Web conformance selectors", htmlunit)
        self.assertNotIn("github.event_name != 'pull_request'", htmlunit)


if __name__ == "__main__":
    unittest.main()
