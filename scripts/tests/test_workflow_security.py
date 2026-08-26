import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_ROOT = REPO_ROOT / ".github" / "workflows"
PINNED_ACTION = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
PINNED_CONTAINER = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-f]{64}$")


class WorkflowSecurityTests(unittest.TestCase):
    def workflow_files(self) -> list[Path]:
        return sorted([*WORKFLOW_ROOT.glob("*.yml"), *WORKFLOW_ROOT.glob("*.yaml")])

    def test_external_actions_are_pinned_to_full_commit_shas(self) -> None:
        for path in self.workflow_files():
            for line_number, line in enumerate(path.read_text().splitlines(), 1):
                stripped = line.strip()
                if not stripped.startswith("uses:"):
                    continue
                reference, separator, comment = stripped.partition("#")
                action = reference.removeprefix("uses:").strip()
                if action.startswith("./"):
                    continue
                if action.startswith("docker://"):
                    self.assertRegex(
                        action,
                        PINNED_CONTAINER,
                        f"{path.relative_to(REPO_ROOT)}:{line_number}",
                    )
                    continue
                self.assertRegex(
                    action,
                    PINNED_ACTION,
                    f"{path.relative_to(REPO_ROOT)}:{line_number}",
                )
                self.assertTrue(
                    separator and comment.strip(),
                    f"{path.relative_to(REPO_ROOT)}:{line_number} "
                    "must retain a version comment",
                )

    def test_checkout_never_persists_credentials(self) -> None:
        for path in self.workflow_files():
            lines = path.read_text().splitlines()
            checkout_indexes = [
                index
                for index, line in enumerate(lines)
                if line.strip().startswith("uses: actions/checkout@")
            ]
            for index in checkout_indexes:
                uses_indent = len(lines[index]) - len(lines[index].lstrip())
                step_indent = uses_indent - 2
                step_end = next(
                    (
                        candidate
                        for candidate in range(index + 1, len(lines))
                        if lines[candidate].lstrip().startswith("- ")
                        and len(lines[candidate]) - len(lines[candidate].lstrip())
                        == step_indent
                    ),
                    len(lines),
                )
                with_index = next(
                    (
                        candidate
                        for candidate in range(index + 1, step_end)
                        if lines[candidate].split("#", 1)[0].strip() == "with:"
                        and len(lines[candidate]) - len(lines[candidate].lstrip())
                        == uses_indent
                    ),
                    None,
                )
                self.assertIsNotNone(
                    with_index,
                    f"{path.relative_to(REPO_ROOT)}:{index + 1}",
                )
                with_end = next(
                    (
                        candidate
                        for candidate in range(with_index + 1, step_end)
                        if lines[candidate].strip()
                        and len(lines[candidate]) - len(lines[candidate].lstrip())
                        <= uses_indent
                    ),
                    step_end,
                )
                with_values = {
                    line.split("#", 1)[0].strip()
                    for line in lines[with_index + 1 : with_end]
                    if len(line) - len(line.lstrip()) == uses_indent + 2
                }
                self.assertIn(
                    "persist-credentials: false",
                    with_values,
                    f"{path.relative_to(REPO_ROOT)}:{index + 1}",
                )
