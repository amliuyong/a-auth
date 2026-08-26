#!/usr/bin/env python3
"""Build one release-gate evidence document from suite result files."""

import argparse
import json
from pathlib import Path
from typing import Any


def load(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--deployment-version", required=True)
    parser.add_argument("--generated-at", required=True)
    parser.add_argument("--claim", action="append", required=True)
    parser.add_argument("--suite", action="append", required=True, type=Path)
    parser.add_argument(
        "--deployment-preflight",
        action="append",
        required=True,
        type=Path,
    )
    parser.add_argument("--exceptions", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    suites = [load(path) for path in args.suite]
    deployment_preflights = [load(path) for path in args.deployment_preflight]
    require(
        len(deployment_preflights) == 2,
        "exactly two deployment preflight summaries are required",
    )
    for index, phase in enumerate(("start", "end")):
        preflight = deployment_preflights[index]
        require(
            isinstance(preflight, dict)
            and preflight.get("schema_version") == 1
            and preflight.get("phase") == phase
            and preflight.get("status") == "passed"
            and preflight.get("issuer") == args.issuer.rstrip("/")
            and preflight.get("expected_deployment_version") == args.deployment_version
            and preflight.get("deployment_version") == args.deployment_version,
            f"deployment {phase} preflight does not bind the selected deployment",
        )
    exceptions = load(args.exceptions)
    evidence = {
        "schema_version": 1,
        "generated_at": args.generated_at,
        "deployment": {
            "issuer": args.issuer.rstrip("/"),
            "version": args.deployment_version,
        },
        "requested_claims": args.claim,
        "deployment_preflights": deployment_preflights,
        "suites": suites,
        "exceptions": exceptions,
    }
    args.output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
