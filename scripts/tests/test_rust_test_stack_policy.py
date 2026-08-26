import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
EXACT_RUNNER = REPO_ROOT / "scripts" / "run_conformance_exact_tests.sh"
STACK_POLICY = REPO_ROOT / "scripts" / "rust_test_stack.sh"
STACK_POLICY_SOURCE = "source ./scripts/rust_test_stack.sh"


class RustTestStackPolicyTests(unittest.TestCase):
    def active_lines(self, text: str) -> list[str]:
        return [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]

    def workflow_step_script(self, name: str) -> str:
        lines = CI_WORKFLOW.read_text(encoding="utf-8").splitlines()
        marker = f"      - name: {name}"
        start = lines.index(marker)
        end = next(
            (
                index
                for index in range(start + 1, len(lines))
                if lines[index].startswith("      - name:")
            ),
            len(lines),
        )
        return "\n".join(lines[start:end])

    def test_refresh_ci_and_exact_runner_share_stack_policy(self) -> None:
        self.assertTrue(
            STACK_POLICY.is_file(), "shared Rust test stack policy is missing"
        )
        policy = STACK_POLICY.read_text(encoding="utf-8")
        self.assertIn(
            'export RUST_MIN_STACK="${RUST_MIN_STACK:-8388608}"',
            self.active_lines(policy),
        )

        refresh_step = self.workflow_step_script("Run AWS refresh stack regressions")
        refresh_lines = self.active_lines(refresh_step)
        source_index = refresh_lines.index(STACK_POLICY_SOURCE)
        self.assertEqual(
            refresh_lines[source_index : source_index + 4],
            [
                STACK_POLICY_SOURCE,
                "cargo test -p agent-auth-http --features aws \\",
                "--test code_flow_e2e --locked refresh \\",
                "-- --test-threads=1",
            ],
        )
        self.assertNotIn("unset RUST_MIN_STACK", refresh_step)

        exact_runner = EXACT_RUNNER.read_text(encoding="utf-8")
        exact_lines = self.active_lines(exact_runner)
        source_index = exact_lines.index(STACK_POLICY_SOURCE)
        cargo_index = next(
            index
            for index, line in enumerate(exact_lines)
            if line.startswith("cargo test ")
        )
        self.assertLess(source_index, cargo_index)
        self.assertNotIn("8388608", exact_runner)


if __name__ == "__main__":
    unittest.main()
