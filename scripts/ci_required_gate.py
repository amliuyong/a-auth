"""Fail closed over the CI jobs required for a protected merge."""

import argparse
import json
import sys
from typing import Any

EXPECTED_JOBS = (
    "markdownlint",
    "rust-quality",
    "rust-tests",
    "conformance-exact",
    "sdk-checks",
    "infra-tests",
    "web-checks",
    "oidf-htmlunit-smoke",
    "conformance-tooling",
)
SUPPORTED_EVENTS = {
    "pull_request",
    "push",
    "workflow_dispatch",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_results(event_name: str, needs: dict[str, Any]) -> None:
    require(event_name in SUPPORTED_EVENTS, f"unsupported CI event: {event_name}")
    require(
        set(needs) == set(EXPECTED_JOBS),
        "CI dependency set drifted from the reviewed required jobs",
    )

    for job in EXPECTED_JOBS:
        detail = needs[job]
        require(isinstance(detail, dict), f"{job} result must be an object")
        result = detail.get("result")
        require(
            result == "success",
            f"{job} must conclude success",
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--needs-json", required=True)
    args = parser.parse_args()

    try:
        needs = json.loads(args.needs_json)
        require(isinstance(needs, dict), "--needs-json must contain an object")
        validate_results(args.event_name, needs)
        print("Required CI dependencies satisfied")
        return 0
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        print(f"Required CI failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
