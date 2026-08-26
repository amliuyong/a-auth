#!/usr/bin/env python3
"""Security-sensitive helpers for the external conformance workflow."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import tarfile
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

WORKFLOW_PATH = ".github/workflows/release-conformance.yml"
TRUSTED_CONFORMANCE_SERVER = "https://www.certification.openid.net/"
MONITOR_ISSUE_TITLE = "[conformance] continuous gate monitoring failure"
EXTERNAL_JOB_NAME = "OIDC Basic OP and selected RFC 9700"
SCHEDULE_MAX_INTERVAL_HOURS = 30
RUNNER_STALL_HOURS = 3


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_https_issuer(value: str) -> None:
    parsed = urllib.parse.urlsplit(value)
    require(parsed.scheme == "https", "issuer must use HTTPS")
    require(
        parsed.hostname is not None
        and parsed.username is None
        and parsed.password is None,
        "issuer must contain a valid host without userinfo",
    )
    require(
        not parsed.query and not parsed.fragment,
        "issuer must not contain a query or fragment",
    )
    try:
        _ = parsed.port
    except ValueError as error:
        raise ValueError("issuer contains an invalid port") from error


def validate_inputs(args: argparse.Namespace) -> None:
    validate_https_issuer(args.issuer)
    require(
        args.conformance_server == TRUSTED_CONFORMANCE_SERVER,
        "unexpected OIDF conformance server",
    )
    require(
        re.fullmatch(r"[0-9a-f]{40}", args.deployment_version) is not None,
        "deployment_version must be a full Git commit",
    )
    subprocess.run(
        ["git", "cat-file", "-e", f"{args.deployment_version}^{{commit}}"],
        check=True,
    )
    reachable = subprocess.run(
        [
            "git",
            "merge-base",
            "--is-ancestor",
            args.deployment_version,
            args.workflow_sha,
        ],
        check=False,
    )
    require(
        reachable.returncode == 0,
        "deployment_version must be reachable from the trusted workflow ref",
    )
    require(
        args.event_name in {"workflow_dispatch", "schedule"},
        "conformance workflow event must be workflow_dispatch or schedule",
    )
    require(
        args.github_ref == "refs/heads/main",
        "conformance runs must use main",
    )
    expected_workflow_ref = f"{args.repository}/{WORKFLOW_PATH}@refs/heads/main"
    require(
        args.workflow_ref == expected_workflow_ref,
        "direct conformance workflow source is not trusted main",
    )


def load_json_object(path: Path, name: str) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), f"{name} must contain a JSON object")
    return value


def parse_timestamp(value: Any, field: str) -> datetime:
    require(isinstance(value, str) and bool(value), f"{field} is required")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(parsed.tzinfo is not None, f"{field} must include a timezone")
    return parsed


def require_string_array(value: Any, field: str) -> list[str]:
    require(
        isinstance(value, list)
        and all(isinstance(item, str) and bool(item) for item in value),
        f"{field} must contain non-empty strings",
    )
    require(len(value) == len(set(value)), f"{field} contains duplicates")
    return value


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
            f"deployment {phase} preflight does not bind the promoted deployment",
        )


def validate_promotion(args: argparse.Namespace) -> None:
    if args.summary:
        args.summary.unlink(missing_ok=True)
    approved = load_json_object(args.approved_claims, "approved claims")
    evidence = load_json_object(args.evidence, "evidence")
    policy = load_json_object(args.policy, "policy")
    require(
        set(approved)
        == {
            "schema_version",
            "approved_at",
            "valid_until",
            "deployment",
            "approved_profile_claims",
            "explicit_non_claims",
            "evidence_sha256",
            "policy_version",
            "policy_sha256",
        },
        "approved claims document has an unexpected shape",
    )
    require(
        approved.get("schema_version") == 2,
        "approved claims schema_version must be 2",
    )
    require(policy.get("schema_version") == 1, "policy schema_version must be 1")
    require(evidence.get("schema_version") == 1, "evidence schema_version must be 1")
    require(
        approved.get("policy_version") == policy.get("policy_version"),
        "approved claims policy_version does not match policy",
    )
    require(
        approved.get("policy_sha256")
        == hashlib.sha256(args.policy.read_bytes()).hexdigest(),
        "approved claims policy_sha256 does not match policy",
    )
    validate_https_issuer(args.expected_issuer)
    expected_issuer = args.expected_issuer.rstrip("/")
    require(
        re.fullmatch(r"[0-9a-f]{40}", args.expected_deployment_version) is not None,
        "expected deployment version must be a full Git commit",
    )
    digest = hashlib.sha256(args.evidence.read_bytes()).hexdigest()
    require(
        approved.get("evidence_sha256") == digest,
        "approved claims evidence_sha256 does not match the evidence",
    )
    deployment = approved.get("deployment")
    evidence_deployment = evidence.get("deployment")
    require(
        isinstance(deployment, dict) and set(deployment) == {"issuer", "version"},
        "approved claims deployment must contain only issuer and version",
    )
    require(
        evidence_deployment == deployment,
        "approved claims deployment does not match the evidence",
    )
    require(
        deployment.get("issuer") == expected_issuer,
        "approved claims issuer does not match the promoted issuer",
    )
    require(
        deployment.get("version") == args.expected_deployment_version,
        "approved claims deployment does not match the promoted commit",
    )
    validate_deployment_preflights(
        evidence,
        expected_issuer,
        args.expected_deployment_version,
    )
    now = parse_timestamp(args.now, "--now") if args.now else datetime.now(timezone.utc)
    approved_at = parse_timestamp(approved.get("approved_at"), "approved_at")
    valid_until = parse_timestamp(approved.get("valid_until"), "valid_until")
    generated_at = parse_timestamp(evidence.get("generated_at"), "generated_at")
    require(generated_at <= approved_at, "approved_at precedes evidence generation")
    require(approved_at <= now, "approved_at must not be in the future")
    require(now < valid_until, "approved claims are expired")
    max_age = timedelta(hours=policy["max_evidence_age_hours"])
    require(
        valid_until == generated_at + max_age,
        "approved claims validity does not match policy evidence age",
    )
    approved_profiles = require_string_array(
        approved.get("approved_profile_claims"),
        "approved_profile_claims",
    )
    requested_claims = require_string_array(
        evidence.get("requested_claims"),
        "evidence requested_claims",
    )
    require(
        approved_profiles == requested_claims,
        "approved profile claims do not match the evidence",
    )
    allowed_claims = require_string_array(
        policy.get("allowed_claims"),
        "policy allowed_claims",
    )
    required_claims = require_string_array(
        policy.get("required_claims"),
        "policy required_claims",
    )
    require(
        set(required_claims) <= set(approved_profiles) <= set(allowed_claims),
        "approved profile claims violate policy",
    )
    required_for_promotion = set(args.required_claim)
    require(
        required_for_promotion <= set(approved_profiles),
        "promotion requires a profile that is not approved",
    )
    explicit_non_claims = require_string_array(
        approved.get("explicit_non_claims"),
        "explicit_non_claims",
    )
    policy_non_claims = require_string_array(
        policy.get("explicit_non_claims"),
        "policy explicit_non_claims",
    )
    require(
        explicit_non_claims == policy_non_claims,
        "explicit non-claims do not match policy",
    )
    require(
        set(approved_profiles).isdisjoint(explicit_non_claims),
        "approved profiles overlap explicit non-claims",
    )
    summary = "\n".join(
        [
            "# Promotion conformance authorization: PASS",
            "",
            f"- Issuer: `{deployment['issuer']}`",
            f"- Deployment version: `{deployment['version']}`",
            f"- Valid until: `{approved['valid_until']}`",
            "- Approved profiles: "
            + ", ".join(f"`{profile}`" for profile in approved_profiles),
            "- Explicit non-claims: "
            + ", ".join(f"`{profile}`" for profile in explicit_non_claims),
            "",
        ]
    )
    if args.summary:
        args.summary.write_text(summary, encoding="utf-8")
    print(summary, end="")


def issue_body(args: argparse.Namespace) -> str:
    summary = ""
    if args.summary.is_file():
        summary = args.summary.read_text(encoding="utf-8")
    deployment = args.deployment_version or "<not configured>"
    return (
        "The external conformance release gate failed.\n\n"
        f"- Job result: `{args.job_result}`\n"
        f"- Issuer: `{args.issuer}`\n"
        f"- Deployment: `{deployment}`\n"
        f"- Workflow run: {args.server_url}/{args.repository}/actions/runs/"
        f"{args.run_id}\n\n"
        f"{summary}"
    )


def track_failure(args: argparse.Namespace) -> None:
    if re.fullmatch(r"[0-9a-f]{40}", args.deployment_version):
        title = f"[conformance] gate failed for {args.deployment_version[:12]}"
    else:
        title = "[conformance] gate configuration invalid"
    args.body.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    args.body.write_text(issue_body(args), encoding="utf-8")
    listed = subprocess.run(
        [
            "gh",
            "issue",
            "list",
            "--state",
            "open",
            "--limit",
            "100",
            "--json",
            "number,title",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    issues = json.loads(listed.stdout)
    require(isinstance(issues, list), "gh issue list returned invalid JSON")
    matches = [
        issue
        for issue in issues
        if isinstance(issue, dict)
        and issue.get("title") == title
        and isinstance(issue.get("number"), int)
    ]
    if matches:
        command = [
            "gh",
            "issue",
            "comment",
            str(matches[0]["number"]),
            "--body-file",
            str(args.body),
        ]
    else:
        command = [
            "gh",
            "issue",
            "create",
            "--title",
            title,
            "--body-file",
            str(args.body),
        ]
    subprocess.run(command, check=True)


def workflow_time(item: dict[str, Any], field: str) -> datetime:
    value = item.get(field)
    return parse_timestamp(value, f"workflow run {field}")


def continuous_gate_findings(
    *,
    runs: list[dict[str, Any]],
    latest_schedule_jobs: list[dict[str, Any]],
    deployment_version: str,
    max_evidence_age_hours: int,
    now: datetime,
) -> list[str]:
    require(
        isinstance(max_evidence_age_hours, int) and max_evidence_age_hours > 0,
        "policy max_evidence_age_hours must be a positive integer",
    )
    findings = []
    if re.fullmatch(r"[0-9a-f]{40}", deployment_version) is None:
        findings.append(
            "The configured deployment version is missing or is not a full Git commit."
        )

    scheduled = [
        run for run in runs if isinstance(run, dict) and run.get("event") == "schedule"
    ]
    if not scheduled:
        findings.append("No scheduled run exists for the release conformance workflow.")
        findings.append("No successful evidence exists for the scheduled gate.")
        return findings

    latest = max(scheduled, key=lambda run: workflow_time(run, "created_at"))
    latest_created = workflow_time(latest, "created_at")
    require(latest_created <= now, "latest scheduled run is in the future")
    if now - latest_created >= timedelta(hours=SCHEDULE_MAX_INTERVAL_HOURS):
        findings.append(
            "No scheduled run started within the last "
            f"{SCHEDULE_MAX_INTERVAL_HOURS} hours."
        )

    expected_jobs = [
        job
        for job in latest_schedule_jobs
        if isinstance(job, dict) and job.get("name") == EXTERNAL_JOB_NAME
    ]
    expected_job = expected_jobs[0] if len(expected_jobs) == 1 else None
    latest_id = latest.get("id")
    exclude_latest_success = False
    if latest.get("status") == "completed":
        if expected_job is None:
            findings.append(
                f"The latest scheduled run does not contain the required {EXTERNAL_JOB_NAME} job."
            )
            exclude_latest_success = True
        elif expected_job.get("conclusion") == "skipped":
            findings.append(
                f"The required {EXTERNAL_JOB_NAME} job was skipped in the latest schedule."
            )
            exclude_latest_success = True
        elif expected_job.get("conclusion") != "success":
            exclude_latest_success = True

    active_statuses = {"queued", "in_progress", "waiting", "pending", "requested"}
    job_status = expected_job.get("status") if expected_job else None
    if (
        latest.get("status") in active_statuses or job_status in active_statuses
    ) and now - latest_created >= timedelta(hours=RUNNER_STALL_HOURS):
        findings.append(
            "The latest scheduled run has not completed after "
            f"{RUNNER_STALL_HOURS} hours; the dedicated runner may be unavailable."
        )
        exclude_latest_success = True

    successful = [
        run
        for run in scheduled
        if run.get("status") == "completed"
        and run.get("conclusion") == "success"
        and not (exclude_latest_success and run.get("id") == latest_id)
    ]
    if not successful:
        findings.append("No successful evidence exists for the scheduled gate.")
        return findings

    latest_success = max(
        successful,
        key=lambda run: workflow_time(run, "updated_at"),
    )
    latest_success_at = workflow_time(latest_success, "updated_at")
    require(latest_success_at <= now, "latest successful run is in the future")
    if now - latest_success_at >= timedelta(hours=max_evidence_age_hours):
        findings.append(
            "The latest successful evidence is stale: it is at least "
            f"{max_evidence_age_hours} hours old."
        )
    return findings


def monitor_issue_body(
    args: argparse.Namespace,
    findings: list[str],
    *,
    checked_at: str,
    latest_schedule_url: str | None,
) -> str:
    latest = latest_schedule_url or "`<none>`"
    rendered_findings = "\n".join(f"- {finding}" for finding in findings)
    return (
        "The continuous release-conformance watchdog detected a failure.\n\n"
        f"- Checked at: `{checked_at}`\n"
        f"- Latest scheduled run: {latest}\n"
        f"- Workflow: {args.server_url}/{args.repository}/actions/workflows/"
        "release-conformance.yml\n\n"
        "## Findings\n\n"
        f"{rendered_findings}\n"
    )


def open_monitor_issues() -> list[dict[str, Any]]:
    listed = subprocess.run(
        [
            "gh",
            "issue",
            "list",
            "--state",
            "open",
            "--limit",
            "100",
            "--json",
            "number,title",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    issues = json.loads(listed.stdout)
    require(isinstance(issues, list), "gh issue list returned invalid JSON")
    return [
        issue
        for issue in issues
        if isinstance(issue, dict)
        and issue.get("title") == MONITOR_ISSUE_TITLE
        and isinstance(issue.get("number"), int)
    ]


def sync_monitor_issue(
    args: argparse.Namespace,
    findings: list[str],
    *,
    checked_at: str,
    latest_schedule_url: str | None,
) -> None:
    matches = open_monitor_issues()
    if findings:
        args.body.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        args.body.write_text(
            monitor_issue_body(
                args,
                findings,
                checked_at=checked_at,
                latest_schedule_url=latest_schedule_url,
            ),
            encoding="utf-8",
        )
        if matches:
            command = [
                "gh",
                "issue",
                "edit",
                str(matches[0]["number"]),
                "--body-file",
                str(args.body),
            ]
        else:
            command = [
                "gh",
                "issue",
                "create",
                "--title",
                MONITOR_ISSUE_TITLE,
                "--body-file",
                str(args.body),
            ]
        subprocess.run(command, check=True)
    elif matches:
        subprocess.run(
            [
                "gh",
                "issue",
                "close",
                str(matches[0]["number"]),
                "--comment",
                f"Watchdog no longer reports an active failure at {checked_at}.",
            ],
            check=True,
        )


def github_api_object(path: str, name: str) -> dict[str, Any]:
    response = subprocess.run(
        ["gh", "api", "-X", "GET", path],
        check=True,
        capture_output=True,
        text=True,
    )
    value = json.loads(response.stdout)
    require(isinstance(value, dict), f"{name} API response must be an object")
    return value


def monitor_continuous_gate(args: argparse.Namespace) -> None:
    now = parse_timestamp(args.now, "--now") if args.now else datetime.now(timezone.utc)
    checked_at = now.isoformat().replace("+00:00", "Z")
    enabled = args.schedule_enabled == "true"
    findings: list[str] = []
    latest_schedule_url = None
    if enabled:
        require(
            re.fullmatch(r"[^/]+/[^/]+", args.repository) is not None,
            "repository must use owner/name format",
        )
        policy = load_json_object(args.policy, "policy")
        runs_response = github_api_object(
            "repos/"
            f"{args.repository}/actions/workflows/release-conformance.yml/"
            "runs?branch=main&event=schedule&per_page=100",
            "workflow runs",
        )
        runs = runs_response.get("workflow_runs")
        require(isinstance(runs, list), "workflow runs response must contain an array")
        scheduled = [
            run
            for run in runs
            if isinstance(run, dict) and run.get("event") == "schedule"
        ]
        latest_schedule_jobs: list[dict[str, Any]] = []
        if scheduled:
            latest = max(
                scheduled,
                key=lambda run: workflow_time(run, "created_at"),
            )
            latest_schedule_url = latest.get("html_url")
            require(
                latest_schedule_url is None or isinstance(latest_schedule_url, str),
                "workflow run html_url must be a string",
            )
            run_id = latest.get("id")
            require(isinstance(run_id, int), "workflow run id must be an integer")
            jobs_response = github_api_object(
                f"repos/{args.repository}/actions/runs/{run_id}/jobs?per_page=100",
                "workflow jobs",
            )
            jobs = jobs_response.get("jobs")
            require(
                isinstance(jobs, list), "workflow jobs response must contain an array"
            )
            latest_schedule_jobs = jobs
        findings = continuous_gate_findings(
            runs=runs,
            latest_schedule_jobs=latest_schedule_jobs,
            deployment_version=args.deployment_version,
            max_evidence_age_hours=policy.get("max_evidence_age_hours"),
            now=now,
        )

    sync_monitor_issue(
        args,
        findings,
        checked_at=checked_at,
        latest_schedule_url=latest_schedule_url,
    )
    if findings:
        raise ValueError("; ".join(findings))
    state = "enabled and healthy" if enabled else "disabled by repository configuration"
    print(f"Continuous release-conformance watchdog: {state}")


def exception_approval_binding(exception: dict) -> str:
    values = {}
    for field in ("suite_id", "test_id", "expires_at"):
        value = exception.get(field)
        require(
            isinstance(value, str) and bool(value),
            f"exception {field} is required for issue approval",
        )
        values[field] = value
    return (
        "<!-- agent-auth-conformance-waiver -->\n"
        f"- Suite: `{values['suite_id']}`\n"
        f"- Test: `{values['test_id']}`\n"
        f"- Expires: `{values['expires_at']}`"
    )


def load_issue_events(repository: str, issue_number: str) -> list[dict]:
    response = subprocess.run(
        [
            "gh",
            "api",
            "--paginate",
            "--slurp",
            f"repos/{repository}/issues/{issue_number}/events?per_page=100",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    pages = json.loads(response.stdout)
    require(isinstance(pages, list), "gh issue events returned invalid JSON")
    events = []
    for page in pages:
        require(isinstance(page, list), "gh issue events page must be an array")
        require(
            all(isinstance(event, dict) for event in page),
            "gh issue events must contain objects",
        )
        events.extend(page)
    return events


def verify_exception_approval(
    exception: dict,
    issue: dict,
    events: list[dict],
    *,
    approval_label: str,
    approvers: set[str],
    issue_url: str,
) -> None:
    approved_by = exception.get("approved_by")
    approved_at = exception.get("approved_at")
    require(
        isinstance(approved_by, str) and bool(approved_by),
        "exception approved_by is required for issue approval",
    )
    require(
        isinstance(approved_at, str) and bool(approved_at),
        "exception approved_at is required for issue approval",
    )
    approver = approved_by.removeprefix("@").lower()
    require(
        approver in approvers,
        f"{issue_url} exception approver is not an allowed release owner",
    )
    labels = issue.get("labels")
    require(isinstance(labels, list), f"{issue_url} labels must be an array")
    active_labels = {
        label.get("name")
        for label in labels
        if isinstance(label, dict) and isinstance(label.get("name"), str)
    }
    require(
        approval_label in active_labels,
        f"{issue_url} does not have the required approval label",
    )
    body = issue.get("body")
    require(isinstance(body, str), f"{issue_url} body must be a string")
    require(
        exception_approval_binding(exception) in body,
        f"{issue_url} does not bind the exact exception target and expiry",
    )
    approval_events = [
        event
        for event in events
        if event.get("event") in {"labeled", "unlabeled"}
        and isinstance(event.get("label"), dict)
        and event["label"].get("name") == approval_label
    ]
    require(
        bool(approval_events),
        f"{issue_url} has no approval label audit event",
    )
    latest = approval_events[-1]
    actor = latest.get("actor")
    require(
        latest.get("event") == "labeled"
        and isinstance(actor, dict)
        and isinstance(actor.get("login"), str)
        and actor["login"].lower() == approver
        and latest.get("created_at") == approved_at,
        f"{issue_url} approval label event does not match approved_by and approved_at",
    )


def verify_exception_issues(args: argparse.Namespace) -> None:
    evidence = json.loads(args.evidence.read_text(encoding="utf-8"))
    require(isinstance(evidence, dict), "evidence must be a JSON object")
    policy = json.loads(args.policy.read_text(encoding="utf-8"))
    require(isinstance(policy, dict), "policy must be a JSON object")
    issue_repository = policy.get("exception_issue_repository")
    require(
        isinstance(issue_repository, str) and bool(issue_repository),
        "policy exception_issue_repository is required",
    )
    require(
        args.repository == issue_repository,
        "workflow repository does not match policy exception_issue_repository",
    )
    approval_label = policy.get("exception_approval_label")
    configured_approvers = policy.get("exception_approvers")
    require(
        isinstance(approval_label, str) and bool(approval_label),
        "policy exception_approval_label is required",
    )
    require(
        isinstance(configured_approvers, list)
        and bool(configured_approvers)
        and all(
            isinstance(value, str) and bool(value) for value in configured_approvers
        ),
        "policy exception_approvers must be a non-empty string array",
    )
    approvers = {value.removeprefix("@").lower() for value in configured_approvers}
    exceptions = evidence.get("exceptions")
    require(isinstance(exceptions, list), "evidence exceptions must be an array")
    exceptions_by_issue: dict[str, list[dict]] = {}
    for exception in exceptions:
        require(isinstance(exception, dict), "exceptions must contain objects")
        issue_url = exception.get("issue_url")
        match = (
            re.fullmatch(
                rf"https://github\.com/{re.escape(issue_repository)}/issues/([1-9][0-9]*)",
                issue_url,
            )
            if isinstance(issue_url, str)
            else None
        )
        require(
            match is not None,
            "exception issue_url must link to an issue in the selected repository",
        )
        exceptions_by_issue.setdefault(issue_url, []).append(exception)
    for issue_url, issue_exceptions in sorted(exceptions_by_issue.items()):
        issue_number = issue_url.rsplit("/", 1)[-1]
        response = subprocess.run(
            [
                "gh",
                "api",
                f"repos/{issue_repository}/issues/{issue_number}",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        issue = json.loads(response.stdout)
        require(isinstance(issue, dict), f"{issue_url} returned invalid JSON")
        require("pull_request" not in issue, f"{issue_url} resolves to a pull request")
        require(
            issue.get("html_url") == issue_url, f"{issue_url} did not resolve exactly"
        )
        require(issue.get("state") == "open", f"{issue_url} is not open")
        events = load_issue_events(issue_repository, issue_number)
        for exception in issue_exceptions:
            verify_exception_approval(
                exception,
                issue,
                events,
                approval_label=approval_label,
                approvers=approvers,
                issue_url=issue_url,
            )


def secure_remove(path: Path) -> None:
    if path.is_symlink():
        path.unlink(missing_ok=True)
    elif path.is_file():
        subprocess.run(["shred", "--remove", "--", str(path)], check=True)


def clean_sensitive_files(paths: list[Path], raw_dir: Path) -> None:
    errors: list[OSError | subprocess.CalledProcessError] = []
    for path in paths:
        try:
            secure_remove(path)
        except (OSError, subprocess.CalledProcessError) as error:
            errors.append(error)
    if raw_dir.is_dir():
        for root, directories, files in os.walk(raw_dir, topdown=False):
            root_path = Path(root)
            for filename in files:
                try:
                    secure_remove(root_path / filename)
                except (OSError, subprocess.CalledProcessError) as error:
                    errors.append(error)
            for directory in directories:
                try:
                    (root_path / directory).rmdir()
                except OSError as error:
                    errors.append(error)
        try:
            raw_dir.rmdir()
        except OSError as error:
            errors.append(error)
    if errors:
        raise RuntimeError(f"failed to remove {len(errors)} sensitive path(s)")


def create_secret_file(path: Path, value: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(value)


def verify_archive(encrypted_archive: Path, passphrase_file: Path) -> None:
    process = subprocess.Popen(
        [
            "gpg",
            "--batch",
            "--quiet",
            "--pinentry-mode",
            "loopback",
            "--passphrase-file",
            str(passphrase_file),
            "--decrypt",
            str(encrypted_archive),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    try:
        with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
            for _member in archive:
                pass
    except (tarfile.TarError, OSError):
        process.kill()
        process.wait()
        raise
    finally:
        process.stdout.close()
    stderr = process.stderr.read() if process.stderr is not None else b""
    return_code = process.wait()
    if return_code != 0:
        raise subprocess.CalledProcessError(
            return_code,
            process.args,
            stderr=stderr,
        )


def encrypt_evidence(args: argparse.Namespace) -> None:
    passphrase_file = args.work_dir / "artifact-passphrase"
    plaintext_archive = args.work_dir / "oidf-raw.tar"
    cleanup_paths = [passphrase_file, plaintext_archive, args.secret_config]
    encrypted_complete = False
    try:
        require(
            len(args.passphrase) >= 32,
            "CONFORMANCE_ARTIFACT_PASSPHRASE must contain at least 32 characters",
        )
        args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        args.raw_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        args.encrypted_archive.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        create_secret_file(passphrase_file, args.passphrase)
        descriptor = os.open(
            plaintext_archive,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with (
            os.fdopen(descriptor, "wb") as plaintext,
            tarfile.open(fileobj=plaintext, mode="w") as archive,
        ):
            archive.add(args.raw_dir, arcname=".")
        subprocess.run(
            [
                "gpg",
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase-file",
                str(passphrase_file),
                "--symmetric",
                "--cipher-algo",
                "AES256",
                "--digest-algo",
                "SHA512",
                "--s2k-mode",
                "3",
                "--s2k-digest-algo",
                "SHA512",
                "--output",
                str(args.encrypted_archive),
                str(plaintext_archive),
            ],
            check=True,
        )
        verify_archive(args.encrypted_archive, passphrase_file)
        digest = hashlib.sha256(args.encrypted_archive.read_bytes()).hexdigest()
        args.checksum.write_text(
            f"{digest}  {args.encrypted_archive.name}\n",
            encoding="ascii",
        )
        encrypted_complete = True
    finally:
        try:
            clean_sensitive_files(cleanup_paths, args.raw_dir)
        finally:
            if not encrypted_complete:
                args.encrypted_archive.unlink(missing_ok=True)
                args.checksum.unlink(missing_ok=True)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("validate-inputs")
    validate.add_argument("--issuer", required=True)
    validate.add_argument("--conformance-server", required=True)
    validate.add_argument("--deployment-version", required=True)
    validate.add_argument("--workflow-sha", required=True)
    validate.add_argument("--event-name", required=True)
    validate.add_argument("--github-ref", required=True)
    validate.add_argument("--workflow-ref", required=True)
    validate.add_argument("--repository", required=True)
    validate.set_defaults(handler=validate_inputs)

    promotion = commands.add_parser("validate-promotion")
    promotion.add_argument("--approved-claims", required=True, type=Path)
    promotion.add_argument("--evidence", required=True, type=Path)
    promotion.add_argument("--policy", required=True, type=Path)
    promotion.add_argument("--expected-issuer", required=True)
    promotion.add_argument("--expected-deployment-version", required=True)
    promotion.add_argument("--required-claim", action="append", required=True)
    promotion.add_argument("--now")
    promotion.add_argument("--summary", type=Path)
    promotion.set_defaults(handler=validate_promotion)

    track = commands.add_parser("track-failure")
    track.add_argument("--issuer", required=True)
    track.add_argument("--deployment-version", required=True)
    track.add_argument("--server-url", required=True)
    track.add_argument("--repository", required=True)
    track.add_argument("--run-id", required=True)
    track.add_argument("--job-result", required=True)
    track.add_argument("--summary", required=True, type=Path)
    track.add_argument("--body", required=True, type=Path)
    track.set_defaults(handler=track_failure)

    monitor = commands.add_parser("monitor")
    monitor.add_argument("--repository", required=True)
    monitor.add_argument("--server-url", required=True)
    monitor.add_argument("--schedule-enabled", required=True)
    monitor.add_argument("--deployment-version", required=True)
    monitor.add_argument("--policy", required=True, type=Path)
    monitor.add_argument("--body", required=True, type=Path)
    monitor.add_argument("--now")
    monitor.set_defaults(handler=monitor_continuous_gate)

    encrypt = commands.add_parser("encrypt-evidence")
    encrypt.add_argument("--raw-dir", required=True, type=Path)
    encrypt.add_argument("--secret-config", required=True, type=Path)
    encrypt.add_argument("--work-dir", required=True, type=Path)
    encrypt.add_argument("--encrypted-archive", required=True, type=Path)
    encrypt.add_argument("--checksum", required=True, type=Path)
    encrypt.set_defaults(
        handler=encrypt_evidence,
        passphrase=os.environ.get("ARTIFACT_PASSPHRASE", ""),
    )

    verify = commands.add_parser("verify-exception-issues")
    verify.add_argument("--evidence", required=True, type=Path)
    verify.add_argument("--policy", required=True, type=Path)
    verify.add_argument("--repository", required=True)
    verify.add_argument("--failure-summary", required=True, type=Path)
    verify.set_defaults(handler=verify_exception_issues)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        args.handler(args)
        return 0
    except (
        json.JSONDecodeError,
        OSError,
        RuntimeError,
        subprocess.CalledProcessError,
        tarfile.TarError,
        ValueError,
    ) as error:
        if args.command == "validate-promotion" and args.summary:
            args.summary.write_text(
                "\n".join(
                    [
                        "# Promotion conformance authorization: FAIL",
                        "",
                        "## Reason",
                        "",
                        f"- {error}",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
        failure_summary = getattr(args, "failure_summary", None)
        if failure_summary is not None:
            write_failure = (
                "# External conformance gate: FAIL\n\n"
                "## Reason\n\n"
                f"- Exception tracking issue verification failed: {error}\n"
            )
            failure_summary.write_text(write_failure, encoding="utf-8")
        print(error, file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
