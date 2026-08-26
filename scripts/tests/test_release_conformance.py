import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from scripts import release_conformance

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "release_conformance.py"

ISSUER = "https://issuer.example.com"
SERVER = "https://www.certification.openid.net/"
PASSPHRASE = "correct horse battery staple release gate"
POLICY = REPO_ROOT / ".github" / "conformance" / "policy.json"


class ReleaseConformanceCliTests(unittest.TestCase):
    def conformance_run(
        self,
        *,
        run_id: int,
        status: str,
        conclusion: str | None,
        created_at: str,
        updated_at: str,
    ) -> dict:
        return {
            "id": run_id,
            "event": "schedule",
            "status": status,
            "conclusion": conclusion,
            "created_at": created_at,
            "updated_at": updated_at,
            "html_url": f"https://github.com/example/agent-auth/actions/runs/{run_id}",
        }

    def workflow_step_script(self, name: str) -> str:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "release-conformance.yml"
        ).read_text()
        lines = workflow.splitlines()
        step_index = lines.index(f"      - name: {name}")
        run_index = next(
            index
            for index in range(step_index + 1, len(lines))
            if lines[index].strip() == "run: |"
        )
        run_indent = len(lines[run_index]) - len(lines[run_index].lstrip())
        script_lines = []
        for line in lines[run_index + 1 :]:
            indent = len(line) - len(line.lstrip())
            if line.strip() and indent <= run_indent:
                break
            script_lines.append(line)
        return textwrap.dedent("\n".join(script_lines)) + "\n"

    def make_git_repository(self, root: Path) -> str:
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(
            ["git", "-C", str(root), "config", "user.email", "ci@example.com"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(root), "config", "user.name", "CI"],
            check=True,
        )
        (root / "tracked").write_text("first\n")
        subprocess.run(["git", "-C", str(root), "add", "tracked"], check=True)
        subprocess.run(
            ["git", "-C", str(root), "commit", "-qm", "first"],
            check=True,
        )
        return subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def validate_command(self, commit: str) -> list[str]:
        return [
            sys.executable,
            str(SCRIPT),
            "validate-inputs",
            "--issuer",
            ISSUER,
            "--conformance-server",
            SERVER,
            "--deployment-version",
            commit,
            "--workflow-sha",
            commit,
            "--event-name",
            "workflow_dispatch",
            "--github-ref",
            "refs/heads/main",
            "--workflow-ref",
            (
                "example/agent-auth/.github/workflows/"
                "release-conformance.yml@refs/heads/main"
            ),
            "--repository",
            "example/agent-auth",
        ]

    def promotion_fixture(self, root: Path) -> argparse.Namespace:
        evidence = {
            "schema_version": 1,
            "generated_at": "2026-08-08T11:00:00Z",
            "deployment": {
                "issuer": ISSUER,
                "version": "a" * 40,
            },
            "deployment_preflights": [
                {
                    "schema_version": 1,
                    "phase": phase,
                    "status": "passed",
                    "issuer": ISSUER,
                    "expected_deployment_version": "a" * 40,
                    "deployment_version": "a" * 40,
                }
                for phase in ("start", "end")
            ],
            "requested_claims": ["oidc-basic-op-code"],
        }
        evidence_path = root / "evidence.json"
        evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
        policy = json.loads(POLICY.read_text(encoding="utf-8"))
        policy_path = root / "policy.json"
        policy_path.write_text(json.dumps(policy), encoding="utf-8")
        approved = {
            "schema_version": 2,
            "approved_at": "2026-08-08T12:00:00Z",
            "valid_until": "2026-08-09T11:00:00Z",
            "deployment": evidence["deployment"],
            "approved_profile_claims": ["oidc-basic-op-code"],
            "explicit_non_claims": policy["explicit_non_claims"],
            "evidence_sha256": hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
            "policy_version": policy["policy_version"],
            "policy_sha256": hashlib.sha256(policy_path.read_bytes()).hexdigest(),
        }
        approved_path = root / "approved-profile-claims.json"
        approved_path.write_text(json.dumps(approved), encoding="utf-8")
        return argparse.Namespace(
            approved_claims=approved_path,
            evidence=evidence_path,
            policy=policy_path,
            expected_issuer=ISSUER,
            expected_deployment_version="a" * 40,
            required_claim=["oidc-basic-op-code"],
            now="2026-08-08T12:30:00Z",
            summary=root / "promotion-summary.md",
        )

    def test_accepts_reachable_commit_from_trusted_main_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commit = self.make_git_repository(root)
            completed = subprocess.run(
                self.validate_command(commit),
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_rejects_manual_dispatch_from_untrusted_ref(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commit = self.make_git_repository(root)
            command = self.validate_command(commit)
            command[command.index("refs/heads/main")] = "refs/heads/feature"
            completed = subprocess.run(
                command,
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(completed.returncode, 1)
        self.assertIn("conformance runs must use main", completed.stderr)

    def test_rejects_reusable_workflow_event(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commit = self.make_git_repository(root)
            command = self.validate_command(commit)
            command[command.index("workflow_dispatch")] = "workflow_call"
            completed = subprocess.run(
                command,
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(completed.returncode, 1)
        self.assertIn("must be workflow_dispatch or schedule", completed.stderr)

    def test_rejects_scheduled_run_with_untrusted_workflow_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commit = self.make_git_repository(root)
            command = self.validate_command(commit)
            command[command.index("workflow_dispatch")] = "schedule"
            trusted = (
                "example/agent-auth/.github/workflows/"
                "release-conformance.yml@refs/heads/main"
            )
            command[command.index(trusted)] = (
                "example/agent-auth/.github/workflows/"
                "release-conformance.yml@refs/heads/feature"
            )
            completed = subprocess.run(
                command,
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(completed.returncode, 1)
        self.assertIn("workflow source is not trusted main", completed.stderr)

    def test_tracks_existing_failure_issue_without_shell_interpolation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            summary = root / "summary.md"
            body = root / "failure.md"
            summary.write_text("# Gate failed\n")
            args = argparse.Namespace(
                issuer=ISSUER,
                deployment_version="a" * 40,
                job_result="failure",
                server_url="https://github.com",
                repository="example/agent-auth",
                run_id="123",
                summary=summary,
                body=body,
            )
            listed = subprocess.CompletedProcess(
                [],
                0,
                stdout=json.dumps(
                    [
                        {
                            "number": 27,
                            "title": "[conformance] gate failed for aaaaaaaaaaaa",
                        }
                    ]
                ),
            )
            with mock.patch(
                "scripts.release_conformance.subprocess.run",
                side_effect=[listed, subprocess.CompletedProcess([], 0)],
            ) as run:
                release_conformance.track_failure(args)
            rendered_body = body.read_text()

        self.assertEqual(
            run.call_args_list[1].args[0][:4],
            ["gh", "issue", "comment", "27"],
        )
        self.assertIn("# Gate failed", rendered_body)

    def test_tracks_invalid_configuration_without_an_empty_issue_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = argparse.Namespace(
                issuer=ISSUER,
                deployment_version="",
                job_result="skipped",
                server_url="https://github.com",
                repository="example/agent-auth",
                run_id="123",
                summary=root / "missing-summary.md",
                body=root / "failure.md",
            )
            listed = subprocess.CompletedProcess([], 0, stdout="[]")
            with mock.patch(
                "scripts.release_conformance.subprocess.run",
                side_effect=[listed, subprocess.CompletedProcess([], 0)],
            ) as run:
                release_conformance.track_failure(args)
            rendered_body = args.body.read_text()

        self.assertEqual(
            run.call_args_list[1].args[0][:4],
            ["gh", "issue", "create", "--title"],
        )
        self.assertEqual(
            run.call_args_list[1].args[0][4],
            "[conformance] gate configuration invalid",
        )
        self.assertIn("Deployment: `<not configured>`", rendered_body)
        self.assertIn("Job result: `skipped`", rendered_body)

    def test_scheduled_workflow_requires_explicit_enablement(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "release-conformance.yml"
        ).read_text()

        self.assertIn(
            "github.event_name != 'schedule' ||\n"
            "      vars.CONFORMANCE_SCHEDULE_ENABLED == 'true'",
            workflow,
        )
        self.assertIn(
            "needs.external-conformance.result != 'success'",
            workflow,
        )
        self.assertNotIn("needs.external-conformance.result != 'skipped'", workflow)
        tracker = workflow[workflow.index("  track-release-gate-failure:") :]
        self.assertIn("github.event_name != 'schedule'", tracker)
        self.assertIn("vars.CONFORMANCE_SCHEDULE_ENABLED == 'true'", tracker)
        self.assertIn(
            "JOB_RESULT: ${{ needs.external-conformance.result }}",
            tracker,
        )
        self.assertIn('--job-result "$JOB_RESULT"', tracker)
        self.assertNotIn(
            '--job-result "${{ needs.external-conformance.result }}"',
            tracker,
        )
        self.assertIn("      issues: write", tracker)
        self.assertNotIn("    environment: conformance", tracker)
        self.assertIn(
            "needs.external-conformance.outputs.issuer_b64",
            tracker,
        )
        self.assertNotIn(
            "issues: write",
            workflow[: workflow.index("  track-release-gate-failure:")],
        )
        self.assertIn("validate-promotion", workflow)
        self.assertIn(
            "rm -f conformance-results/approved-profile-claims.json",
            workflow,
        )
        self.assertIn("id: encrypt_evidence", workflow)
        self.assertIn(
            "steps.encrypt_evidence.outcome != 'success'",
            workflow,
        )
        self.assertLess(
            workflow.index(
                "- name: Invalidate approval after evidence packaging failure"
            ),
            workflow.index("- name: Upload conformance evidence"),
        )

    def test_promotion_accepts_exact_unexpired_gate_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = self.promotion_fixture(Path(directory))

            release_conformance.validate_promotion(args)
            summary = args.summary.read_text(encoding="utf-8")

        self.assertIn("# Promotion conformance authorization: PASS", summary)
        self.assertIn("`oidc-basic-op-code`", summary)
        self.assertIn("`fapi`", summary)

    def test_promotion_rejects_stale_mismatched_or_overclaimed_artifact(self) -> None:
        def mutate_policy(
            args: argparse.Namespace,
            _approved: dict,
            _evidence: dict,
        ) -> None:
            policy = json.loads(args.policy.read_text(encoding="utf-8"))
            policy["max_evidence_age_hours"] = 12
            args.policy.write_text(json.dumps(policy), encoding="utf-8")

        cases = [
            (
                "expired",
                lambda args, approved, evidence: setattr(
                    args,
                    "now",
                    "2026-08-09T11:00:00Z",
                ),
                "expired",
            ),
            (
                "deployment mismatch",
                lambda args, approved, evidence: setattr(
                    args,
                    "expected_deployment_version",
                    "b" * 40,
                ),
                "promoted commit",
            ),
            (
                "issuer mismatch",
                lambda args, approved, evidence: setattr(
                    args,
                    "expected_issuer",
                    "https://other.example.com",
                ),
                "promoted issuer",
            ),
            (
                "evidence digest mismatch",
                lambda args, approved, evidence: approved.__setitem__(
                    "evidence_sha256",
                    "0" * 64,
                ),
                "evidence_sha256",
            ),
            (
                "unapproved required profile",
                lambda args, approved, evidence: args.required_claim.append("fapi"),
                "not approved",
            ),
            (
                "non-claim drift",
                lambda args, approved, evidence: approved.__setitem__(
                    "explicit_non_claims",
                    [
                        item
                        for item in approved["explicit_non_claims"]
                        if item != "fapi"
                    ],
                ),
                "non-claims",
            ),
            (
                "policy digest mismatch",
                mutate_policy,
                "policy_sha256",
            ),
        ]
        for name, mutate, expected in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                args = self.promotion_fixture(Path(directory))
                approved = json.loads(args.approved_claims.read_text(encoding="utf-8"))
                evidence = json.loads(args.evidence.read_text(encoding="utf-8"))
                mutate(args, approved, evidence)
                args.approved_claims.write_text(
                    json.dumps(approved),
                    encoding="utf-8",
                )
                args.evidence.write_text(json.dumps(evidence), encoding="utf-8")

                with self.assertRaisesRegex(ValueError, expected):
                    release_conformance.validate_promotion(args)

    def test_promotion_cli_writes_failure_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = self.promotion_fixture(Path(directory))
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "validate-promotion",
                    "--approved-claims",
                    str(args.approved_claims),
                    "--evidence",
                    str(args.evidence),
                    "--policy",
                    str(args.policy),
                    "--expected-issuer",
                    args.expected_issuer,
                    "--expected-deployment-version",
                    args.expected_deployment_version,
                    "--required-claim",
                    "oidc-basic-op-code",
                    "--now",
                    "2026-08-09T11:00:00Z",
                    "--summary",
                    str(args.summary),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            summary = args.summary.read_text(encoding="utf-8")

        self.assertEqual(completed.returncode, 1)
        self.assertIn("# Promotion conformance authorization: FAIL", summary)
        self.assertIn("expired", summary)

    def test_promotion_rejects_rehashed_evidence_without_live_deployment_binding(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = self.promotion_fixture(Path(directory))
            evidence = json.loads(args.evidence.read_text(encoding="utf-8"))
            evidence.pop("deployment_preflights")
            args.evidence.write_text(json.dumps(evidence), encoding="utf-8")
            approved = json.loads(args.approved_claims.read_text(encoding="utf-8"))
            approved["evidence_sha256"] = hashlib.sha256(
                args.evidence.read_bytes()
            ).hexdigest()
            args.approved_claims.write_text(json.dumps(approved), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "preflights"):
                release_conformance.validate_promotion(args)

    def test_self_hosted_runner_is_dedicated_and_checks_isolation_first(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "release-conformance.yml"
        ).read_text()

        for label in (
            "self-hosted",
            "Linux",
            "ARM64",
            "agent-auth-conformance",
        ):
            self.assertIn(f"      - {label}", workflow)
        self.assertLess(
            workflow.index("- name: Verify dedicated runner isolation"),
            workflow.index("- name: Check out repository"),
        )
        self.assertIn("AWS_WEB_IDENTITY_TOKEN_FILE", workflow)
        self.assertIn("169.254.169.254/latest/api/token", workflow)

    def test_oidf_runner_exit_code_is_exported_under_actions_errexit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / "oidf-conformance-suite" / "scripts" / "run-test-plan.py"
            runner.parent.mkdir(parents=True)
            runner.write_text("raise SystemExit(17)\n")
            raw_root = root / "agent-auth-conformance" / "raw-oidf"
            (raw_root / "exports").mkdir(parents=True)
            (root / "agent-auth-conformance" / "oidf-config.json").write_text("{}")
            output = root / "github-output"
            output.write_text("")
            script = root / "step.sh"
            script.write_text(
                self.workflow_step_script("Run official OIDF Basic OP plan")
            )
            environment = {
                **os.environ,
                "CONFORMANCE_TOKEN": "test-token",
                "GITHUB_OUTPUT": str(output),
                "GITHUB_WORKSPACE": str(root),
                "RUNNER_TEMP": str(root),
            }

            completed = subprocess.run(
                [
                    "bash",
                    "--noprofile",
                    "--norc",
                    "-e",
                    "-o",
                    "pipefail",
                    str(script),
                ],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            output_text = output.read_text()

        self.assertEqual(completed.returncode, 17)
        self.assertEqual(output_text, "exit_code=17\n")
        self.assertIn("OIDF runner exited with status 17", completed.stdout)

    def test_live_preflights_run_before_official_oidf_plan(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "release-conformance.yml"
        ).read_text()

        deployment_preflight = "- name: Preflight live deployment commit before suites"
        deployment_postflight = "- name: Preflight live deployment commit after suites"
        secret_config = "- name: Validate secret OIDF plan configuration"
        iat_preflight = "- name: Preflight protected OIDF initial access tokens"
        browser_preflight = "- name: Preflight live OIDF browser assets"
        regression = "- name: Run agent-auth-owned selected RFC 9700 regression"
        fetch_runner = "- name: Fetch the pinned official OIDF runner"
        runner = "- name: Run official OIDF Basic OP plan"
        self.assertIn(deployment_preflight, workflow)
        self.assertIn(deployment_postflight, workflow)
        self.assertIn(iat_preflight, workflow)
        self.assertIn(browser_preflight, workflow)
        self.assertLess(
            workflow.index(deployment_preflight),
            workflow.index(secret_config),
        )
        self.assertLess(
            workflow.index(deployment_preflight),
            workflow.index(iat_preflight),
        )
        self.assertLess(
            workflow.index(iat_preflight),
            workflow.index(browser_preflight),
        )
        self.assertLess(workflow.index(browser_preflight), workflow.index(runner))
        self.assertLess(workflow.index(browser_preflight), workflow.index(regression))
        self.assertLess(workflow.index(browser_preflight), workflow.index(fetch_runner))
        self.assertLess(workflow.index(runner), workflow.index(deployment_postflight))
        self.assertLess(
            workflow.index(deployment_postflight),
            workflow.index("- name: Build release evidence"),
        )
        iat_block = workflow[
            workflow.index(iat_preflight) : workflow.index(browser_preflight)
        ]
        deployment_block = workflow[
            workflow.index(deployment_preflight) : workflow.index(secret_config)
        ]
        browser_block = workflow[
            workflow.index(browser_preflight) : workflow.index(regression)
        ]
        self.assertNotIn("continue-on-error:", deployment_block)
        self.assertNotIn("continue-on-error:", iat_block)
        self.assertNotIn("continue-on-error:", browser_block)
        deployment_script = self.workflow_step_script(
            "Preflight live deployment commit before suites"
        )
        self.assertIn("scripts/deployment_commit_preflight.py", deployment_script)
        self.assertIn('--issuer "$ISSUER"', deployment_script)
        self.assertIn('--allowed-issuer "$CONFIGURED_ISSUER"', deployment_script)
        self.assertIn(
            '--expected-deployment-version "$DEPLOYMENT_VERSION"',
            deployment_script,
        )
        self.assertIn("--phase start", deployment_script)
        self.assertIn(
            "--summary conformance-results/deployment-commit-preflight-start.json",
            deployment_script,
        )
        postflight_script = self.workflow_step_script(
            "Preflight live deployment commit after suites"
        )
        self.assertIn("scripts/deployment_commit_preflight.py", postflight_script)
        self.assertIn("--phase end", postflight_script)
        self.assertIn(
            "--summary conformance-results/deployment-commit-preflight-end.json",
            postflight_script,
        )
        preflight_script = self.workflow_step_script(
            "Preflight protected OIDF initial access tokens"
        )
        self.assertIn("scripts/oidf_iat_preflight.py", preflight_script)
        self.assertIn(
            '--config "$RUNNER_TEMP/agent-auth-conformance/oidf-config.json"',
            preflight_script,
        )
        self.assertIn('--issuer "$ISSUER"', preflight_script)
        self.assertIn('--allowed-issuer "$CONFIGURED_ISSUER"', preflight_script)
        self.assertIn(
            "--summary conformance-results/oidf-iat-preflight.json",
            preflight_script,
        )
        browser_script = self.workflow_step_script("Preflight live OIDF browser assets")
        self.assertIn("scripts/oidf_browser_preflight.py", browser_script)
        self.assertIn('--issuer "$ISSUER"', browser_script)
        self.assertIn('--allowed-issuer "$CONFIGURED_ISSUER"', browser_script)
        self.assertIn(
            "--summary conformance-results/oidf-browser-preflight.json",
            browser_script,
        )
        regression_script = self.workflow_step_script(
            "Run agent-auth-owned selected RFC 9700 regression"
        )
        self.assertIn("scripts/rfc9700_regression.py", regression_script)
        self.assertIn('--allowed-issuer "$CONFIGURED_ISSUER"', regression_script)
        self.assertEqual(
            workflow.count("steps.oidf_browser_preflight.outcome == 'success'"),
            5,
        )
        self.assertEqual(
            workflow.count("steps.oidf_iat_preflight.outcome == 'success'"),
            5,
        )
        self.assertEqual(
            workflow.count("steps.deployment_commit_preflight.outcome == 'success'"),
            6,
        )
        self.assertEqual(
            workflow.count("steps.deployment_commit_postflight.outcome == 'success'"),
            2,
        )
        evidence_script = self.workflow_step_script("Build release evidence")
        normalized_evidence_script = " ".join(evidence_script.replace("\\", "").split())
        self.assertIn(
            "--deployment-preflight "
            "conformance-results/deployment-commit-preflight-start.json",
            normalized_evidence_script,
        )
        self.assertIn(
            "--deployment-preflight "
            "conformance-results/deployment-commit-preflight-end.json",
            normalized_evidence_script,
        )

    def test_verifies_exception_is_an_open_issue_in_the_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence.json"
            policy = root / "policy.json"
            issue_url = "https://github.com/example/agent-auth/issues/27"
            exception = {
                "suite_id": "oidf-basic-op-code",
                "test_id": "oidcc-server[response_type=code]",
                "approved_by": "@release-owner",
                "approved_at": "2026-08-01T12:00:00Z",
                "expires_at": "2026-08-08T12:00:00Z",
                "issue_url": issue_url,
            }
            evidence.write_text(json.dumps({"exceptions": [exception]}))
            policy.write_text(
                json.dumps(
                    {
                        "exception_issue_repository": "example/agent-auth",
                        "exception_approval_label": "conformance-waiver-approved",
                        "exception_approvers": ["release-owner"],
                    }
                )
            )
            args = argparse.Namespace(
                evidence=evidence,
                policy=policy,
                repository="example/agent-auth",
            )
            issue_response = subprocess.CompletedProcess(
                [],
                0,
                stdout=json.dumps(
                    {
                        "html_url": issue_url,
                        "state": "open",
                        "number": 27,
                        "body": release_conformance.exception_approval_binding(
                            exception
                        ),
                        "labels": [{"name": "conformance-waiver-approved"}],
                    }
                ),
            )
            events_response = subprocess.CompletedProcess(
                [],
                0,
                stdout=json.dumps(
                    [
                        [
                            {
                                "event": "labeled",
                                "label": {"name": "conformance-waiver-approved"},
                                "actor": {"login": "release-owner"},
                                "created_at": "2026-08-01T12:00:00Z",
                            }
                        ]
                    ]
                ),
            )
            with mock.patch(
                "scripts.release_conformance.subprocess.run",
                side_effect=[issue_response, events_response],
            ) as run:
                release_conformance.verify_exception_issues(args)

        self.assertEqual(
            run.call_args_list[0].args[0],
            ["gh", "api", "repos/example/agent-auth/issues/27"],
        )
        self.assertEqual(
            run.call_args_list[1].args[0],
            [
                "gh",
                "api",
                "--paginate",
                "--slurp",
                "repos/example/agent-auth/issues/27/events?per_page=100",
            ],
        )

    def test_rejects_closed_exception_tracking_issue(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence.json"
            policy = root / "policy.json"
            issue_url = "https://github.com/example/agent-auth/issues/27"
            evidence.write_text(
                json.dumps(
                    {
                        "exceptions": [
                            {
                                "suite_id": "suite",
                                "test_id": "test",
                                "approved_by": "@release-owner",
                                "approved_at": "2026-08-01T12:00:00Z",
                                "expires_at": "2026-08-08T12:00:00Z",
                                "issue_url": issue_url,
                            }
                        ]
                    }
                )
            )
            policy.write_text(
                json.dumps(
                    {
                        "exception_issue_repository": "example/agent-auth",
                        "exception_approval_label": "conformance-waiver-approved",
                        "exception_approvers": ["release-owner"],
                    }
                )
            )
            args = argparse.Namespace(
                evidence=evidence,
                policy=policy,
                repository="example/agent-auth",
            )
            response = subprocess.CompletedProcess(
                [],
                0,
                stdout=json.dumps(
                    {
                        "html_url": issue_url,
                        "state": "closed",
                        "number": 27,
                    }
                ),
            )
            with (
                mock.patch(
                    "scripts.release_conformance.subprocess.run",
                    return_value=response,
                ),
                self.assertRaisesRegex(ValueError, "is not open"),
            ):
                release_conformance.verify_exception_issues(args)

    def test_rejects_workflow_repository_that_does_not_match_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence.json"
            policy = root / "policy.json"
            evidence.write_text(json.dumps({"exceptions": []}))
            policy.write_text(
                json.dumps(
                    {
                        "exception_issue_repository": "owner/trusted",
                        "exception_approval_label": "conformance-waiver-approved",
                        "exception_approvers": ["release-owner"],
                    }
                )
            )
            args = argparse.Namespace(
                evidence=evidence,
                policy=policy,
                repository="fork/untrusted",
            )

            with self.assertRaisesRegex(ValueError, "does not match policy"):
                release_conformance.verify_exception_issues(args)

    def test_rejects_self_asserted_approver_without_matching_label_event(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence.json"
            policy = root / "policy.json"
            issue_url = "https://github.com/example/agent-auth/issues/27"
            exception = {
                "suite_id": "suite",
                "test_id": "test",
                "approved_by": "@release-owner",
                "approved_at": "2026-08-01T12:00:00Z",
                "expires_at": "2026-08-08T12:00:00Z",
                "issue_url": issue_url,
            }
            evidence.write_text(json.dumps({"exceptions": [exception]}))
            policy.write_text(
                json.dumps(
                    {
                        "exception_issue_repository": "example/agent-auth",
                        "exception_approval_label": "conformance-waiver-approved",
                        "exception_approvers": ["release-owner"],
                    }
                )
            )
            args = argparse.Namespace(
                evidence=evidence,
                policy=policy,
                repository="example/agent-auth",
            )
            issue_response = subprocess.CompletedProcess(
                [],
                0,
                stdout=json.dumps(
                    {
                        "html_url": issue_url,
                        "state": "open",
                        "body": release_conformance.exception_approval_binding(
                            exception
                        ),
                        "labels": [{"name": "conformance-waiver-approved"}],
                    }
                ),
            )
            events_response = subprocess.CompletedProcess(
                [],
                0,
                stdout=json.dumps(
                    [
                        [
                            {
                                "event": "labeled",
                                "label": {"name": "conformance-waiver-approved"},
                                "actor": {"login": "someone-else"},
                                "created_at": "2026-08-01T12:00:00Z",
                            }
                        ]
                    ]
                ),
            )
            with (
                mock.patch(
                    "scripts.release_conformance.subprocess.run",
                    side_effect=[issue_response, events_response],
                ),
                self.assertRaisesRegex(ValueError, "does not match approved_by"),
            ):
                release_conformance.verify_exception_issues(args)

    @unittest.skipUnless(
        shutil.which("gpg") and shutil.which("shred"),
        "gpg and shred are required",
    )
    def test_encrypts_raw_evidence_and_removes_plaintext(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work = root / "work"
            raw = work / "raw"
            results = root / "results"
            raw.mkdir(parents=True)
            results.mkdir()
            (raw / "export.json").write_text('{"secret":"raw"}\n')
            secret_config = work / "oidf-config.json"
            secret_config.write_text('{"password":"secret"}\n')
            encrypted = results / "oidf-raw.tar.gpg"
            checksum = results / "oidf-raw.tar.gpg.sha256"
            env = {**os.environ, "ARTIFACT_PASSPHRASE": PASSPHRASE}

            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "encrypt-evidence",
                    "--raw-dir",
                    str(raw),
                    "--secret-config",
                    str(secret_config),
                    "--work-dir",
                    str(work),
                    "--encrypted-archive",
                    str(encrypted),
                    "--checksum",
                    str(checksum),
                ],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(encrypted.is_file())
            self.assertTrue(checksum.is_file())
            self.assertFalse(raw.exists())
            self.assertFalse(secret_config.exists())
            decrypted = subprocess.run(
                [
                    "gpg",
                    "--batch",
                    "--quiet",
                    "--pinentry-mode",
                    "loopback",
                    "--passphrase",
                    PASSPHRASE,
                    "--decrypt",
                    str(encrypted),
                ],
                check=True,
                capture_output=True,
            ).stdout
            with tarfile.open(fileobj=io.BytesIO(decrypted)) as archive:
                exported = archive.extractfile("./export.json")
                assert exported is not None
                self.assertEqual(exported.read(), b'{"secret":"raw"}\n')

    def test_encryption_failure_still_removes_sensitive_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work = root / "work"
            raw = work / "raw"
            raw.mkdir(parents=True)
            (raw / "export.json").write_text('{"secret":"raw"}\n')
            secret_config = work / "oidf-config.json"
            secret_config.write_text('{"password":"secret"}\n')
            encrypted = root / "oidf-raw.tar.gpg"
            checksum = root / "oidf-raw.tar.gpg.sha256"
            env = {**os.environ, "ARTIFACT_PASSPHRASE": "short"}
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "encrypt-evidence",
                    "--raw-dir",
                    str(raw),
                    "--secret-config",
                    str(secret_config),
                    "--work-dir",
                    str(work),
                    "--encrypted-archive",
                    str(encrypted),
                    "--checksum",
                    str(checksum),
                ],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(completed.returncode, 1)
        self.assertIn("at least 32 characters", completed.stderr)
        self.assertFalse(raw.exists())
        self.assertFalse(secret_config.exists())
        self.assertFalse(encrypted.exists())
        self.assertFalse(checksum.exists())

    def test_continuous_monitor_accepts_fresh_successful_schedule(self) -> None:
        runs = [
            self.conformance_run(
                run_id=123,
                status="completed",
                conclusion="success",
                created_at="2026-08-25T03:20:00Z",
                updated_at="2026-08-25T04:00:00Z",
            )
        ]
        jobs = [
            {
                "name": "OIDC Basic OP and selected RFC 9700",
                "status": "completed",
                "conclusion": "success",
            }
        ]

        findings = release_conformance.continuous_gate_findings(
            runs=runs,
            latest_schedule_jobs=jobs,
            deployment_version="a" * 40,
            max_evidence_age_hours=24,
            now=datetime(2026, 8, 25, 20, tzinfo=timezone.utc),
        )

        self.assertEqual(findings, [])

    def test_continuous_monitor_reports_missing_version_skipped_and_stale(
        self,
    ) -> None:
        runs = [
            self.conformance_run(
                run_id=124,
                status="completed",
                conclusion="success",
                created_at="2026-08-25T03:20:00Z",
                updated_at="2026-08-25T03:21:00Z",
            ),
            self.conformance_run(
                run_id=123,
                status="completed",
                conclusion="success",
                created_at="2026-08-23T03:20:00Z",
                updated_at="2026-08-23T04:00:00Z",
            ),
        ]
        jobs = [
            {
                "name": "OIDC Basic OP and selected RFC 9700",
                "status": "completed",
                "conclusion": "skipped",
            }
        ]

        findings = release_conformance.continuous_gate_findings(
            runs=runs,
            latest_schedule_jobs=jobs,
            deployment_version="",
            max_evidence_age_hours=24,
            now=datetime(2026, 8, 25, 20, tzinfo=timezone.utc),
        )

        self.assertTrue(any("deployment version" in item for item in findings))
        self.assertTrue(any("was skipped" in item for item in findings))
        self.assertTrue(
            any("successful evidence is stale" in item for item in findings)
        )

    def test_continuous_monitor_reports_unavailable_runner(self) -> None:
        runs = [
            self.conformance_run(
                run_id=125,
                status="queued",
                conclusion=None,
                created_at="2026-08-25T03:20:00Z",
                updated_at="2026-08-25T03:20:00Z",
            ),
            self.conformance_run(
                run_id=123,
                status="completed",
                conclusion="success",
                created_at="2026-08-24T03:20:00Z",
                updated_at="2026-08-24T04:00:00Z",
            ),
        ]
        jobs = [
            {
                "name": "OIDC Basic OP and selected RFC 9700",
                "status": "queued",
                "conclusion": None,
            }
        ]

        findings = release_conformance.continuous_gate_findings(
            runs=runs,
            latest_schedule_jobs=jobs,
            deployment_version="a" * 40,
            max_evidence_age_hours=24,
            now=datetime(2026, 8, 25, 7, tzinfo=timezone.utc),
        )

        self.assertTrue(any("runner may be unavailable" in item for item in findings))
        self.assertTrue(
            any("successful evidence is stale" in item for item in findings)
        )

    def test_continuous_monitor_reports_missing_schedule(self) -> None:
        findings = release_conformance.continuous_gate_findings(
            runs=[],
            latest_schedule_jobs=[],
            deployment_version="a" * 40,
            max_evidence_age_hours=24,
            now=datetime(2026, 8, 25, 20, tzinfo=timezone.utc),
        )

        self.assertTrue(any("No scheduled run" in item for item in findings))
        self.assertTrue(any("No successful evidence" in item for item in findings))

    def test_continuous_monitor_creates_and_recovers_tracker_issue(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            body = Path(directory) / "monitor.md"
            args = argparse.Namespace(
                body=body,
                server_url="https://github.com",
                repository="example/agent-auth",
            )
            listed_empty = subprocess.CompletedProcess([], 0, stdout="[]")
            listed_open = subprocess.CompletedProcess(
                [],
                0,
                stdout=json.dumps(
                    [
                        {
                            "number": 42,
                            "title": release_conformance.MONITOR_ISSUE_TITLE,
                        }
                    ]
                ),
            )
            completed = subprocess.CompletedProcess([], 0)
            with mock.patch(
                "scripts.release_conformance.subprocess.run",
                side_effect=[
                    listed_empty,
                    completed,
                    listed_open,
                    completed,
                    listed_open,
                    completed,
                ],
            ) as run:
                release_conformance.sync_monitor_issue(
                    args,
                    ["The deployment version is missing or invalid."],
                    checked_at="2026-08-25T20:00:00Z",
                    latest_schedule_url=None,
                )
                release_conformance.sync_monitor_issue(
                    args,
                    ["The latest successful evidence is stale."],
                    checked_at="2026-08-25T20:30:00Z",
                    latest_schedule_url="https://github.com/example/run/123",
                )
                release_conformance.sync_monitor_issue(
                    args,
                    [],
                    checked_at="2026-08-25T21:00:00Z",
                    latest_schedule_url="https://github.com/example/run/123",
                )

        self.assertEqual(
            run.call_args_list[1].args[0][:4],
            ["gh", "issue", "create", "--title"],
        )
        self.assertEqual(
            run.call_args_list[1].args[0][4],
            release_conformance.MONITOR_ISSUE_TITLE,
        )
        self.assertEqual(
            run.call_args_list[3].args[0][:4],
            ["gh", "issue", "edit", "42"],
        )
        self.assertEqual(
            run.call_args_list[5].args[0][:4],
            ["gh", "issue", "close", "42"],
        )

    def test_continuous_monitor_workflow_has_narrow_permissions(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "release-conformance-monitor.yml"
        ).read_text(encoding="utf-8")

        self.assertIn('cron: "47 */3 * * *"', workflow)
        self.assertIn("      actions: read", workflow)
        self.assertIn("      contents: read", workflow)
        self.assertIn("      issues: write", workflow)
        self.assertIn("if: ${{ github.ref == 'refs/heads/main' }}", workflow)
        self.assertIn("release_conformance.py monitor", workflow)
        self.assertIn("vars.CONFORMANCE_DEPLOYMENT_VERSION", workflow)
        self.assertIn("vars.CONFORMANCE_SCHEDULE_ENABLED", workflow)
        self.assertNotIn("    environment: conformance", workflow)


if __name__ == "__main__":
    unittest.main()
