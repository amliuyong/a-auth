import re
from dataclasses import dataclass
from pathlib import Path

RUNS_ON = re.compile(r"^(?P<indent>\s*)runs-on:\s*(?P<value>.*?)\s*$")
LIST_ITEM = re.compile(r"^\s*-\s+(?P<value>.+?)\s*$")
DEDICATED_RUNNER_LABELS = frozenset(
    ("self-hosted", "Linux", "ARM64", "agent-auth-conformance")
)


@dataclass(frozen=True)
class RunnerSpec:
    line_number: int
    labels: tuple[str, ...]


def _yaml_scalar(value: str) -> str:
    scalar = value.split("#", 1)[0].strip()
    if len(scalar) >= 2 and scalar[0] == scalar[-1] and scalar[0] in "\"'":
        return scalar[1:-1]
    return scalar


def _runner_specs(path: Path) -> list[RunnerSpec]:
    lines = path.read_text(encoding="utf-8").splitlines()
    specs: list[RunnerSpec] = []

    for index, line in enumerate(lines):
        match = RUNS_ON.match(line.split("#", 1)[0].rstrip())
        if match is None:
            continue

        value = _yaml_scalar(match.group("value"))
        if value:
            specs.append(RunnerSpec(index + 1, (value,)))
            continue

        runs_on_indent = len(match.group("indent"))
        labels: list[str] = []
        for continuation_index in range(index + 1, len(lines)):
            continuation = lines[continuation_index].split("#", 1)[0].rstrip()
            if not continuation.strip():
                continue
            continuation_indent = len(continuation) - len(continuation.lstrip())
            if continuation_indent <= runs_on_indent:
                break
            item = LIST_ITEM.match(continuation)
            if item is None:
                raise ValueError(
                    f"{path.name}:{continuation_index + 1} uses an unsupported "
                    "runs-on structure"
                )
            label = _yaml_scalar(item.group("value"))
            if not label:
                raise ValueError(
                    f"{path.name}:{continuation_index + 1} has an empty runner label"
                )
            labels.append(label)

        if not labels:
            raise ValueError(f"{path.name}:{index + 1} has an empty runs-on value")
        specs.append(RunnerSpec(index + 1, tuple(labels)))

    return specs


def validate_runner_scope(workflow_root: Path) -> None:
    workflow_files = sorted(
        [*workflow_root.glob("*.yml"), *workflow_root.glob("*.yaml")]
    )
    violations: list[str] = []
    release_workflow_found = False

    for path in workflow_files:
        specs = _runner_specs(path)
        if not specs:
            violations.append(f"{path.name} must declare at least one runs-on value")
            continue

        if path.name != "release-conformance.yml":
            for spec in specs:
                if spec.labels != ("ubuntu-latest",):
                    violations.append(
                        f"{path.name}:{spec.line_number} must use ubuntu-latest; "
                        f"found {', '.join(spec.labels)}"
                    )
            continue

        release_workflow_found = True
        dedicated_count = 0
        for spec in specs:
            if spec.labels == ("ubuntu-latest",):
                continue
            if (
                len(spec.labels) == len(DEDICATED_RUNNER_LABELS)
                and frozenset(spec.labels) == DEDICATED_RUNNER_LABELS
            ):
                dedicated_count += 1
                continue
            violations.append(
                f"{path.name}:{spec.line_number} has an unexpected runner scope: "
                f"{', '.join(spec.labels)}"
            )
        if dedicated_count != 1:
            violations.append(
                "release-conformance.yml must declare exactly one dedicated "
                f"self-hosted runner; found {dedicated_count}"
            )

    if not release_workflow_found:
        violations.append("release-conformance.yml is required")
    if violations:
        raise ValueError("\n".join(violations))
