#!/usr/bin/env python3
"""Evaluate external conformance evidence for a deployed issuer."""

import argparse
import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise TypeError(f"{path} must contain a JSON object")
    return value


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamps must include a timezone")
    return parsed


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def require_nonempty_string(value: Any, message: str) -> str:
    require(isinstance(value, str) and bool(value.strip()), message)
    return value


def require_https(value: Any, message: str) -> str:
    text = require_nonempty_string(value, message)
    require(text.startswith("https://"), message)
    return text


def validate_deployment_preflights(
    evidence: dict[str, Any],
    expected_issuer: str,
    expected_version: str,
) -> None:
    preflights = evidence.get("deployment_preflights")
    require(
        isinstance(preflights, list) and len(preflights) == 2,
        "evidence deployment preflights must contain start and end summaries",
    )
    for index, phase in enumerate(("start", "end")):
        preflight = preflights[index]
        require(
            isinstance(preflight, dict)
            and preflight.get("schema_version") == 1
            and preflight.get("phase") == phase
            and preflight.get("status") == "passed"
            and preflight.get("issuer") == expected_issuer
            and preflight.get("expected_deployment_version") == expected_version
            and preflight.get("deployment_version") == expected_version,
            f"deployment {phase} preflight does not bind the selected deployment",
        )


def write_failure(summary: Path, reason: str) -> None:
    summary.write_text(
        "\n".join(
            [
                "# External conformance gate: FAIL",
                "",
                "## Reason",
                "",
                f"- {reason}",
                "",
            ]
        ),
        encoding="utf-8",
    )


def validate_suite_contract(
    suite_id: str,
    suite: dict[str, Any],
    suite_policy: dict[str, Any],
) -> None:
    require(
        suite.get("kind") == suite_policy.get("kind"),
        f"{suite_id} kind does not match policy",
    )
    if suite_policy.get("all_tests_required") is True:
        require(
            all(test.get("required") is True for test in suite["tests"]),
            f"{suite_id} policy requires every test",
        )
    if suite_policy["kind"] == "oidf-plan":
        plan = suite.get("plan")
        require(isinstance(plan, dict), f"{suite_id} plan is required")
        require(
            plan.get("name") == suite_policy["plan_name"],
            f"{suite_id} used the wrong OIDF plan",
        )
        require(
            plan.get("variants") == suite_policy["variants"],
            f"{suite_id} used the wrong OIDF plan variants",
        )
        require(
            plan.get("runner_ref") == suite_policy["runner_ref"],
            f"{suite_id} runner_ref does not match policy",
        )
        require(
            plan.get("runner_commit") == suite_policy["runner_commit"],
            f"{suite_id} runner_commit does not match policy",
        )
        require(
            isinstance(plan.get("runner_exit_code"), int)
            and plan["runner_exit_code"] >= 0,
            f"{suite_id} runner_exit_code is required",
        )
        require(
            suite.get("source_url") == suite_policy["source_url"],
            f"{suite_id} source_url does not match the pinned runner",
        )
        require(
            plan.get("export_origin") == suite_policy["export_origin"],
            f"{suite_id} export_origin does not match policy",
        )
        require(
            plan.get("signatures_verified") is True,
            f"{suite_id} export signatures were not verified",
        )
        require(
            plan.get("module_count") == len(suite["tests"]),
            f"{suite_id} module_count does not match exported tests",
        )
        for test in suite["tests"]:
            require_nonempty_string(
                test.get("instance_id"),
                f"{suite_id}/{test['id']} instance_id is required",
            )
            require(
                test.get("upstream_status")
                in {
                    "FINISHED",
                    "INTERRUPTED",
                    "CONFIGURED",
                    "WAITING",
                    "RUNNING",
                    "UNKNOWN",
                    None,
                },
                f"{suite_id}/{test['id']} has an invalid upstream_status",
            )
            require_nonempty_string(
                test.get("upstream_result"),
                f"{suite_id}/{test['id']} upstream_result is required",
            )
            require_nonempty_string(
                test.get("signature_key_id"),
                f"{suite_id}/{test['id']} signature_key_id is required",
            )
            cleanup_status = test.get("dynamic_client_cleanup")
            cleanup_attempts = test.get("dynamic_client_cleanup_attempts")
            valid_cleanup = (
                cleanup_status == "passed"
                and type(cleanup_attempts) is int
                and cleanup_attempts >= 1
            ) or (
                cleanup_status == "not_required"
                and type(cleanup_attempts) is int
                and cleanup_attempts == 0
            )
            require(
                valid_cleanup,
                f"{suite_id}/{test['id']} dynamic-client cleanup evidence is invalid",
            )
            if cleanup_status == "not_required":
                require(
                    test.get("status") != "passed",
                    f"{suite_id}/{test['id']} passing module cannot omit dynamic-client cleanup",
                )
                require(
                    not (
                        test.get("upstream_status") == "FINISHED"
                        and test.get("upstream_result") == "PASSED"
                    ),
                    f"{suite_id}/{test['id']} passed upstream without dynamic-client cleanup",
                )
            require_https(
                test.get("log_url"),
                f"{suite_id}/{test['id']} log_url must be HTTPS",
            )
            if test["status"] == "passed":
                require(
                    test["upstream_status"] == "FINISHED"
                    and test["upstream_result"] == "PASSED",
                    f"{suite_id}/{test['id']} passed without OIDF FINISHED/PASSED",
                )
        if all(test["status"] == "passed" for test in suite["tests"]):
            require(
                plan["runner_exit_code"] == 0,
                f"{suite_id} official runner failed despite passing exports",
            )
    elif suite_policy["kind"] == "project-regression":
        require(
            suite.get("standard_url") == suite_policy["standard_url"],
            f"{suite_id} standard_url does not match policy",
        )
        require(
            suite.get("non_certification_statement")
            == suite_policy["non_certification_statement"],
            f"{suite_id} must retain the non-certification statement",
        )
        for test in suite["tests"]:
            expected_standard = (
                "RFC 7592" if test.get("id") == "dynamic-client-cleanup" else "RFC 9700"
            )
            require(
                test.get("standard") == expected_standard,
                f"{suite_id}/{test['id']} must identify {expected_standard}",
            )
            for field in (
                "section",
                "request",
                "expected",
                "applicability",
                "observed",
            ):
                require_nonempty_string(
                    test.get(field),
                    f"{suite_id}/{test['id']} {field} is required",
                )
        non_waivable_tests = suite_policy.get("non_waivable_tests", [])
        require(
            isinstance(non_waivable_tests, list)
            and all(
                isinstance(test_id, str) and test_id for test_id in non_waivable_tests
            ),
            f"{suite_id} non_waivable_tests must be an array of test ids",
        )
        tests_by_id = {test["id"]: test for test in suite["tests"]}
        require(
            set(non_waivable_tests) <= set(tests_by_id),
            f"{suite_id} omits a policy non-waivable test",
        )
        for test_id in non_waivable_tests:
            require(
                tests_by_id[test_id].get("waivable") is False,
                f"{suite_id}/{test_id} must be explicitly non-waivable",
            )
    else:
        raise ValueError(f"{suite_id} policy has an unsupported kind")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--expected-issuer", required=True)
    parser.add_argument("--expected-deployment-version", required=True)
    parser.add_argument("--now")
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--approved-claims", required=True, type=Path)
    args = parser.parse_args()
    approved_claims_tmp = args.approved_claims.with_name(
        f".{args.approved_claims.name}.tmp"
    )
    try:
        args.approved_claims.unlink(missing_ok=True)
        approved_claims_tmp.unlink(missing_ok=True)
        now = parse_time(args.now) if args.now else datetime.now(timezone.utc)
        evidence = load_json(args.evidence)
        policy = load_json(args.policy)

        require(policy.get("schema_version") == 1, "policy schema_version must be 1")
        policy_version = require_nonempty_string(
            policy.get("policy_version"),
            "policy policy_version is required",
        )
        require(
            evidence.get("schema_version") == 1,
            "evidence schema_version must be 1",
        )

        generated_at = parse_time(evidence["generated_at"])
        max_age = timedelta(hours=policy["max_evidence_age_hours"])
        require(generated_at <= now, "generated_at must not be in the future")
        require(
            now - generated_at <= max_age,
            f"generated_at exceeds the {policy['max_evidence_age_hours']} hour limit",
        )

        claims = evidence["requested_claims"]
        require(isinstance(claims, list), "requested_claims must be an array")
        require(
            all(isinstance(claim, str) and claim for claim in claims),
            "requested_claims must contain non-empty strings",
        )
        required_claims = set(policy["required_claims"])
        allowed_claims = set(policy["allowed_claims"])
        claim_set = set(claims)
        require(
            len(claims) == len(claim_set),
            "requested_claims contain duplicates",
        )
        require(
            required_claims <= claim_set,
            "requested_claims omit a required profile",
        )
        require(
            claim_set <= allowed_claims,
            "requested_claims include an unapproved profile",
        )
        explicit_non_claims = policy["explicit_non_claims"]
        require(
            isinstance(explicit_non_claims, list)
            and all(
                isinstance(non_claim, str) and non_claim
                for non_claim in explicit_non_claims
            ),
            "policy explicit_non_claims must contain non-empty strings",
        )
        require(
            len(explicit_non_claims) == len(set(explicit_non_claims)),
            "policy explicit_non_claims contain duplicates",
        )
        require(
            claim_set.isdisjoint(explicit_non_claims),
            "approved claims and explicit non-claims overlap",
        )

        suite_list = evidence["suites"]
        require(isinstance(suite_list, list), "suites must be an array")
        require(
            all(isinstance(suite, dict) for suite in suite_list),
            "suites must contain objects",
        )
        suite_ids = [suite.get("id") for suite in suite_list]
        require(
            all(isinstance(suite_id, str) and suite_id for suite_id in suite_ids),
            "every suite id is required",
        )
        require(
            len(suite_ids) == len(set(suite_ids)),
            "duplicate suite id in evidence",
        )
        suites = {suite["id"]: suite for suite in suite_list}
        required_suites = policy["required_suites"]
        require(
            isinstance(required_suites, dict) and bool(required_suites),
            "policy required_suites must be an object",
        )
        require(
            set(suites) == set(required_suites),
            "evidence suites do not exactly match policy required_suites",
        )
        for suite_id, suite_policy in required_suites.items():
            suite = suites[suite_id]
            require(
                isinstance(suite_policy, dict),
                f"policy for {suite_id} must be an object",
            )
            require_nonempty_string(
                suite.get("version"),
                f"{suite_id} version is required",
            )
            require_https(
                suite.get("source_url"),
                f"{suite_id} source_url must be HTTPS",
            )
            require_https(
                suite.get("result_url"),
                f"{suite_id} result_url must be HTTPS",
            )
            require(
                suite.get("metadata_and_runtime") is True,
                f"{suite_id} metadata_and_runtime must be true",
            )
            tests = suite.get("tests")
            require(isinstance(tests, list), f"{suite_id} tests must be an array")
            require(
                any(
                    isinstance(test, dict) and test.get("required") is True
                    for test in tests
                ),
                f"{suite_id} must contain at least one required test",
            )
            require(
                all(isinstance(test, dict) for test in tests),
                f"{suite_id} tests must contain objects",
            )
            test_ids = [test.get("id") for test in tests]
            require(
                all(isinstance(test_id, str) and test_id for test_id in test_ids),
                f"{suite_id} test ids are required",
            )
            require(
                len(test_ids) == len(set(test_ids)),
                f"{suite_id} contains a duplicate test id",
            )
            for test in tests:
                require(
                    test.get("status") in {"passed", "failed", "skipped", "error"},
                    f"{suite_id}/{test['id']} has an invalid status",
                )
                require(
                    isinstance(test.get("required"), bool),
                    f"{suite_id}/{test['id']} required must be boolean",
                )
                require(
                    isinstance(test.get("waivable", True), bool),
                    f"{suite_id}/{test['id']} waivable must be boolean",
                )
            validate_suite_contract(suite_id, suite, suite_policy)

        deployment = evidence["deployment"]
        require(isinstance(deployment, dict), "deployment must be an object")
        require(
            deployment.get("issuer") == args.expected_issuer.rstrip("/"),
            "deployment issuer does not match --expected-issuer",
        )
        require(
            deployment.get("version") == args.expected_deployment_version,
            "deployment version does not match --expected-deployment-version",
        )
        validate_deployment_preflights(
            evidence,
            args.expected_issuer.rstrip("/"),
            args.expected_deployment_version,
        )

        required_tests = [
            (suite_id, test)
            for suite_id in required_suites
            for test in suites[suite_id]["tests"]
            if test["required"]
        ]
        failed_tests = [
            (suite_id, test)
            for suite_id, test in required_tests
            if test["status"] != "passed"
        ]
        waivable_keys = {
            (suite_id, test["id"])
            for suite_id, test in failed_tests
            if test["status"] == "failed" and test.get("waivable", True) is True
        }
        exception_list = evidence["exceptions"]
        require(isinstance(exception_list, list), "exceptions must be an array")
        require(
            all(isinstance(exception, dict) for exception in exception_list),
            "exceptions must contain objects",
        )
        exception_keys = [
            (exception.get("suite_id"), exception.get("test_id"))
            for exception in exception_list
        ]
        require(
            len(exception_keys) == len(set(exception_keys)),
            "duplicate exception target in evidence",
        )
        max_exception_age = timedelta(days=policy["max_exception_days"])
        for exception, key in zip(exception_list, exception_keys, strict=True):
            require(
                key in waivable_keys,
                "exception must target a waivable failed required test, not an error, skip, or non-waivable cleanup",
            )
            for field in ("approved_by", "reason"):
                require_nonempty_string(
                    exception.get(field),
                    f"exception {field} is required",
                )
            issue_url = exception.get("issue_url")
            issue_repository = policy.get("exception_issue_repository")
            require_nonempty_string(
                issue_repository,
                "policy exception_issue_repository is required",
            )
            require(
                isinstance(issue_url, str)
                and re.fullmatch(
                    rf"https://github\.com/{re.escape(issue_repository)}/issues/[1-9][0-9]*",
                    issue_url,
                )
                is not None,
                "exception issue_url must link to an issue in the policy repository",
            )
            approved_at = parse_time(exception["approved_at"])
            expires_at = parse_time(exception["expires_at"])
            require(
                approved_at <= now, "exception approved_at must not be in the future"
            )
            require(expires_at > now, "exception expires_at must be in the future")
            require(
                expires_at - approved_at <= max_exception_age,
                "exception exceeds policy max_exception_days",
            )
        exceptions = {
            (exception["suite_id"], exception["test_id"]): exception
            for exception in exception_list
        }
        waived = []
        failures = []
        for suite_id, test in failed_tests:
            exception = exceptions.get((suite_id, test["id"]))
            if (
                test["status"] == "failed"
                and test.get("waivable", True) is True
                and exception
                and parse_time(exception["expires_at"]) > now
            ):
                waived.append((suite_id, test, exception))
            else:
                failures.append(f"{suite_id}/{test['id']} ({test['status']})")

        if failures:
            lines = [
                "# External conformance gate: FAIL",
                "",
                "## Required failures",
                "",
                *[f"- `{failure}`" for failure in failures],
            ]
            args.summary.write_text("\n".join(lines) + "\n", encoding="utf-8")
            return 1

        lines = [
            "# External conformance gate: PASS",
            "",
            f"- Issuer: `{deployment['issuer']}`",
            f"- Deployment version: `{deployment['version']}`",
            f"- Required tests passed: {len(required_tests) - len(failed_tests)}",
            f"- Required tests waived: {len(waived)}",
            "",
            "## Suites",
            "",
        ]
        for suite_id in required_suites:
            suite = suites[suite_id]
            lines.append(f"- `{suite_id}` `{suite['version']}`: {suite['result_url']}")
        if waived:
            lines.extend(["", "## Active exceptions", ""])
            for suite_id, test, exception in waived:
                lines.append(
                    f"- `{suite_id}/{test['id']}` until `{exception['expires_at']}` "
                    f"by `{exception['approved_by']}`: {exception['issue_url']} "
                    f"({exception['reason']})"
                )
        args.summary.write_text("\n".join(lines) + "\n", encoding="utf-8")
        approved_claims = {
            "schema_version": 2,
            "approved_at": now.isoformat().replace("+00:00", "Z"),
            "valid_until": (generated_at + max_age).isoformat().replace("+00:00", "Z"),
            "deployment": deployment,
            "approved_profile_claims": claims,
            "explicit_non_claims": explicit_non_claims,
            "evidence_sha256": hashlib.sha256(args.evidence.read_bytes()).hexdigest(),
            "policy_version": policy_version,
            "policy_sha256": hashlib.sha256(args.policy.read_bytes()).hexdigest(),
        }
        approved_claims_tmp.write_text(
            json.dumps(approved_claims, indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(approved_claims_tmp, args.approved_claims)
        return 0
    except (json.JSONDecodeError, KeyError, OSError, TypeError, ValueError) as error:
        args.approved_claims.unlink(missing_ok=True)
        approved_claims_tmp.unlink(missing_ok=True)
        write_failure(args.summary, f"Evidence validation failed: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
