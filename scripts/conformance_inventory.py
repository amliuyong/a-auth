#!/usr/bin/env python3
"""Validate the conformance checklist inventory and incomplete-row ownership."""

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

STATUS_NAMES = {"☑": "complete", "◑": "partial", "☐": "missing"}
CLASSIFICATIONS = {
    "required_blocker",
    "disabled_not_applicable",
    "externally_blocked",
}
APPLICABILITY = {
    "unconditional",
    "required_for_claimed_profile",
    "not_applicable",
}
ISSUE_URL = re.compile(r"https://github\.com/amliuyong/a-auth/issues/[1-9][0-9]*")
SUMMARY = re.compile(
    r"^> 当前机器校验摘要：total=(\d+)，☑=(\d+)，◑=(\d+)，☐=(\d+)。$",
    re.MULTILINE,
)


@dataclass(frozen=True)
class Requirement:
    status: str
    requirement_id: str
    level: str
    phase: str
    requirement: str
    test: str


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load_object(path: Path) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, f"duplicate JSON key: {key}")
            result[key] = value
        return result

    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicates,
    )
    require(isinstance(value, dict), f"{path} must contain a JSON object")
    return value


def split_markdown_row(line: str) -> list[str]:
    stripped = line.strip()
    if not stripped.startswith("|") or not stripped.endswith("|"):
        return []
    body = stripped[1:-1]
    cells: list[str] = []
    start = 0
    for index, character in enumerate(body):
        if character != "|":
            continue
        backslashes = 0
        cursor = index - 1
        while cursor >= 0 and body[cursor] == "\\":
            backslashes += 1
            cursor -= 1
        if backslashes % 2 == 0:
            cells.append(body[start:index].strip())
            start = index + 1
    cells.append(body[start:].strip())
    return cells


def parse_requirements(document: Path) -> tuple[list[Requirement], dict[str, int]]:
    text = document.read_text(encoding="utf-8")
    summary_match = SUMMARY.search(text)
    require(summary_match is not None, "human-readable conformance summary is missing")
    summary_counts = {
        "total": int(summary_match.group(1)),
        "complete": int(summary_match.group(2)),
        "partial": int(summary_match.group(3)),
        "missing": int(summary_match.group(4)),
    }
    requirements = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        cells = split_markdown_row(line)
        if not cells or cells[0] not in STATUS_NAMES:
            continue
        require(
            len(cells) == 6,
            f"{document}:{line_number} conformance row must contain six cells",
        )
        requirement = Requirement(
            status=STATUS_NAMES[cells[0]],
            requirement_id=cells[1],
            level=cells[2],
            phase=cells[3],
            requirement=cells[4],
            test=cells[5],
        )
        require(
            bool(requirement.requirement_id),
            f"{document}:{line_number} requirement id is empty",
        )
        require(
            bool(requirement.level)
            and bool(requirement.phase)
            and bool(requirement.requirement)
            and bool(requirement.test),
            f"{document}:{line_number} conformance row contains an empty field",
        )
        requirements.append(requirement)
    ids = [requirement.requirement_id for requirement in requirements]
    duplicates = sorted(
        requirement_id for requirement_id, count in Counter(ids).items() if count > 1
    )
    require(not duplicates, f"duplicate conformance requirement ids: {duplicates}")
    return requirements, summary_counts


def count_requirements(requirements: list[Requirement]) -> dict[str, int]:
    counts = Counter(requirement.status for requirement in requirements)
    return {
        "total": len(requirements),
        "complete": counts["complete"],
        "partial": counts["partial"],
        "missing": counts["missing"],
    }


def requirement_ids_sha256(requirements: list[Requirement]) -> str:
    normalized = "\n".join(
        requirement.requirement_id for requirement in requirements
    ).encode()
    return hashlib.sha256(normalized).hexdigest()


def validate_incomplete(
    requirements: list[Requirement],
    configured: Any,
) -> list[dict[str, Any]]:
    require(
        isinstance(configured, list),
        "incomplete_requirements must be an array",
    )
    by_id = {requirement.requirement_id: requirement for requirement in requirements}
    incomplete = {
        requirement.requirement_id: requirement
        for requirement in requirements
        if requirement.status != "complete"
    }
    configured_ids: list[str] = []
    for entry in configured:
        require(
            isinstance(entry, dict),
            "incomplete_requirements must contain objects",
        )
        requirement_id = entry.get("id")
        require(
            isinstance(requirement_id, str) and bool(requirement_id),
            "incomplete requirement id is required",
        )
        configured_ids.append(requirement_id)
        require(
            requirement_id in by_id,
            f"incomplete requirement {requirement_id} is absent from the document",
        )
        requirement = by_id[requirement_id]
        require(
            requirement.status != "complete",
            f"complete requirement {requirement_id} must not be classified as incomplete",
        )
        require(
            entry.get("status") == requirement.status,
            f"incomplete requirement {requirement_id} status drifted",
        )
        classification = entry.get("classification")
        applicability = entry.get("applicability")
        require(
            classification in CLASSIFICATIONS,
            f"incomplete requirement {requirement_id} has invalid classification",
        )
        require(
            applicability in APPLICABILITY,
            f"incomplete requirement {requirement_id} has invalid applicability",
        )
        if applicability == "not_applicable":
            require(
                classification == "disabled_not_applicable",
                f"not-applicable requirement {requirement_id} must be disabled",
            )
            require(
                "(if " in requirement.level,
                f"unconditional requirement {requirement_id} cannot be not applicable",
            )
        else:
            require(
                classification != "disabled_not_applicable",
                f"applicable requirement {requirement_id} cannot be disabled",
            )
        issues = entry.get("tracking_issues")
        require(
            isinstance(issues, list)
            and all(
                isinstance(issue, str) and ISSUE_URL.fullmatch(issue)
                for issue in issues
            ),
            f"incomplete requirement {requirement_id} has invalid tracking issues",
        )
        if classification != "disabled_not_applicable":
            require(
                bool(issues),
                f"incomplete requirement {requirement_id} needs a tracking issue",
            )
        require(
            isinstance(entry.get("reason"), str) and bool(entry["reason"].strip()),
            f"incomplete requirement {requirement_id} needs a reason",
        )
    duplicates = sorted(
        requirement_id
        for requirement_id, count in Counter(configured_ids).items()
        if count > 1
    )
    require(not duplicates, f"duplicate incomplete classifications: {duplicates}")
    require(
        set(configured_ids) == set(incomplete),
        "incomplete requirement classifications do not match the document: "
        f"missing={sorted(set(incomplete) - set(configured_ids))}, "
        f"extra={sorted(set(configured_ids) - set(incomplete))}",
    )
    return configured


def validate_inventory(
    document: Path,
    inventory_path: Path,
) -> tuple[dict[str, int], list[dict[str, Any]]]:
    inventory = load_object(inventory_path)
    require(
        inventory.get("schema_version") == 1,
        "inventory schema_version must be 1",
    )
    require(
        inventory.get("document") == "docs/CONFORMANCE.md",
        "inventory document must be docs/CONFORMANCE.md",
    )
    requirements, summary_counts = parse_requirements(document)
    actual_counts = count_requirements(requirements)
    expected_counts = inventory.get("expected_counts")
    require(
        expected_counts == actual_counts,
        f"inventory counts drifted: expected={expected_counts}, actual={actual_counts}",
    )
    actual_ids_sha256 = requirement_ids_sha256(requirements)
    require(
        inventory.get("requirement_ids_sha256") == actual_ids_sha256,
        "conformance requirement id digest drifted",
    )
    require(
        summary_counts == actual_counts,
        f"human summary counts drifted: summary={summary_counts}, actual={actual_counts}",
    )
    incomplete = validate_incomplete(
        requirements,
        inventory.get("incomplete_requirements"),
    )
    return actual_counts, incomplete


def render_summary(
    counts: dict[str, int],
    incomplete: list[dict[str, Any]],
) -> str:
    classification_counts = Counter(entry["classification"] for entry in incomplete)
    lines = [
        "# Conformance inventory: PASS",
        "",
        f"- Total requirements: {counts['total']}",
        f"- Complete: {counts['complete']}",
        f"- Partial: {counts['partial']}",
        f"- Missing: {counts['missing']}",
        f"- Required blockers: {classification_counts['required_blocker']}",
        f"- Externally blocked: {classification_counts['externally_blocked']}",
        (
            "- Disabled/not applicable: "
            f"{classification_counts['disabled_not_applicable']}"
        ),
        "",
        "## Incomplete requirements",
        "",
        "| ID | Status | Applicability | Classification |",
        "| --- | --- | --- | --- |",
    ]
    lines.extend(
        "| {id} | {status} | {applicability} | {classification} |".format(**entry)
        for entry in incomplete
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--document", required=True, type=Path)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args()
    try:
        counts, incomplete = validate_inventory(args.document, args.inventory)
        summary = render_summary(counts, incomplete)
        if args.summary:
            args.summary.write_text(summary, encoding="utf-8")
        print(summary, end="")
        return 0
    except (json.JSONDecodeError, OSError, TypeError, ValueError) as error:
        print(f"Conformance inventory validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
