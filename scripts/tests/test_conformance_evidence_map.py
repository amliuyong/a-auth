import copy
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.conformance_evidence_map import (
    expected_library_selector,
    rust_test_is_active,
    validate_evidence_map,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCUMENT = REPO_ROOT / "docs" / "CONFORMANCE.md"
INVENTORY = REPO_ROOT / ".github" / "conformance" / "requirements.json"
EVIDENCE_MAP = REPO_ROOT / ".github" / "conformance" / "evidence-map.json"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
NODE_EXACT_REPORT_VALIDATOR = REPO_ROOT / "scripts" / "validate_node_exact_report.cjs"


class ConformanceEvidenceMapTests(unittest.TestCase):
    def validate_node_exact_report(
        self, report: str, selector: str
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as handle:
            handle.write(report)
            handle.flush()
            return subprocess.run(
                ["node", str(NODE_EXACT_REPORT_VALIDATOR), handle.name, selector],
                check=False,
                capture_output=True,
                text=True,
            )

    def playwright_mapping(self) -> dict:
        mapping = json.loads(EVIDENCE_MAP.read_text(encoding="utf-8"))
        mapping["targets"] = {
            "ci.web.exact": {
                "kind": "workflow_step",
                "coverage_level": "suite",
                "job": "web-checks",
                "step": "Build production bundle",
                "run_commands": ["npm run build"],
            },
            "exact.test.playwright": {
                "kind": "repo_test",
                "coverage_level": "exact",
                "framework": "playwright",
                "path": "web/e2e/admin-users.spec.ts",
                "selector": "c8_12_ui_exact_selector",
                "runner": "scripts/run_sdk_conformance_exact_tests.sh",
                "ci_target": "ci.web.exact",
            },
            **mapping["targets"],
        }
        return mapping

    def unittest_mapping(self) -> dict:
        mapping = json.loads(EVIDENCE_MAP.read_text(encoding="utf-8"))
        mapping["targets"] = {
            "exact.test.unittest": {
                "kind": "repo_test",
                "coverage_level": "exact",
                "framework": "unittest",
                "path": "scripts/tests/test_release_conformance.py",
                "test_class": "ReleaseConformanceCliTests",
                "selector": "test_promotion_accepts_exact_unexpired_gate_artifact",
                "runner": "scripts/run_sdk_conformance_exact_tests.sh",
                "ci_target": "ci.sdk.exact",
            },
            **mapping["targets"],
        }
        return mapping

    @staticmethod
    def playwright_source() -> str:
        source = (REPO_ROOT / "web/e2e/admin-users.spec.ts").read_text(encoding="utf-8")
        return (
            source
            + "\n"
            + "test('c8_12_ui_exact_selector', async ({ page }) => {\n"
            + "  await page.goto('/admin');\n"
            + "});\n"
        )

    def validate_copy(
        self,
        *,
        evidence_map: dict | None = None,
        evidence_map_text: str | None = None,
        workflow_text: str | None = None,
        file_overrides: dict[str, str] | None = None,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "docs").mkdir()
            (root / ".github" / "conformance").mkdir(parents=True)
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / "scripts").mkdir()
            document = root / "docs" / "CONFORMANCE.md"
            inventory = root / ".github" / "conformance" / "requirements.json"
            mapping = root / ".github" / "conformance" / "evidence-map.json"
            workflow = root / ".github" / "workflows" / "ci.yml"
            document.write_text(DOCUMENT.read_text(encoding="utf-8"), encoding="utf-8")
            inventory.write_text(
                INVENTORY.read_text(encoding="utf-8"), encoding="utf-8"
            )
            selected = evidence_map or json.loads(
                EVIDENCE_MAP.read_text(encoding="utf-8")
            )
            mapping.write_text(
                evidence_map_text or json.dumps(selected),
                encoding="utf-8",
            )
            workflow.write_text(
                workflow_text or WORKFLOW.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            for target in selected["targets"].values():
                source_values = [
                    target.get("path") or target.get("script"),
                    target.get("manifest"),
                    target.get("module_owner"),
                ]
                for source_value in filter(None, source_values):
                    source = REPO_ROOT / str(source_value)
                    destination = root / str(source_value)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(source.read_bytes())
                    destination.chmod(source.stat().st_mode)
                runner_value = target.get("runner")
                if runner_value:
                    source = REPO_ROOT / runner_value
                    destination = root / runner_value
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(source.read_bytes())
                    destination.chmod(source.stat().st_mode)
            for relative_path, content in (file_overrides or {}).items():
                destination = root / relative_path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(content, encoding="utf-8")
            validate_evidence_map(root, document, inventory, mapping, workflow)

    def test_repository_evidence_map_is_valid(self) -> None:
        counts, exact_ids = validate_evidence_map(
            REPO_ROOT,
            DOCUMENT,
            INVENTORY,
            EVIDENCE_MAP,
            WORKFLOW,
        )
        self.assertEqual(counts["total"], 149)
        self.assertEqual(counts["complete"], 144)
        self.assertEqual(counts["unconditional_must"], 109)
        self.assertEqual(counts["exact_unconditional_must"], 109)
        self.assertEqual(counts["complete_without_exact"], 0)
        self.assertEqual(counts["applicability_unconditional"], 116)
        self.assertEqual(counts["applicability_profile"], 30)
        self.assertEqual(counts["applicability_not_applicable"], 3)
        self.assertEqual(
            exact_ids,
            [
                "1.1",
                "1.1b",
                "1.2",
                "1.2b",
                "1.3",
                "1.4",
                "1.5",
                "1.6a",
                "1.6",
                "1.7",
                "1.8",
                "2.1",
                "2.2a",
                "2.2b",
                "2.3",
                "2.3a",
                "2.4",
                "2.5a",
                "2.5b",
                "2.6",
                "2.7",
                "2.8",
                "2.9",
                "2.10",
                "2.11",
                "3.1",
                "3.2",
                "3.3",
                "3.4",
                "3.5",
                "3.6",
                "4.1",
                "4.2",
                "4.3",
                "4.4a",
                "4.4b",
                "4.5",
                "4.6",
                "4.7",
                "4.8",
                "4.9",
                "4.10",
                "5.1",
                "5.2",
                "5.3",
                "5.4",
                "5.5",
                "5.6",
                "5.7",
                "6.1",
                "6.2",
                "6.3",
                "6.4",
                "6.5",
                "7.1",
                "7.2",
                "7.3",
                "7.4",
                "7.5",
                "7.6a",
                "7.6b",
                "7.7",
                "7.8",
                "7.8a",
                "7.9",
                "7b.1",
                "7b.2",
                "7b.3",
                "7b.4",
                "7b.5",
                "7b.6",
                "8.1",
                "8.1b",
                "8.2",
                "8.3",
                "8.4",
                "8.5a",
                "8.5b",
                "8.6",
                "8.7a",
                "8.7a'",
                "8.7b",
                "8.8",
                "8.8a",
                "8.9",
                "8.10",
                "8.10b",
                "8.11",
                "8.12",
                "9.1",
                "9.2",
                "9.3",
                "9.4",
                "9.5",
                "9.6",
                "9.7",
                "9.8",
                "9.9",
                "9.10",
                "9.11",
                "10.1",
                "10.2",
                "10.3",
                "10.4",
                "10.5",
                "10.6",
                "10.7",
                "10.8",
                "10.9",
                "10.9b",
                "10.10",
                "10.11a",
                "10.11b",
                "10.12",
                "10.13",
                "10.14",
                "10.15a",
                "10.16",
                "10.17",
                "10.19",
                "10.20",
                "10.21",
                "10.22a",
                "10.23",
                "10.24",
                "10.25",
                "11.1",
                "11.2",
                "11.3",
                "11.4",
                "12.1",
                "12.2",
                "12.3",
                "12.4",
                "12.5",
                "12.6",
                "12.7",
                "12.8",
                "13.1",
                "13.2",
                "13.3",
                "13.4",
                "13.5",
                "13.6",
                "13.7",
                "13.8",
            ],
        )
        mapping = json.loads(EVIDENCE_MAP.read_text(encoding="utf-8"))
        self.assertEqual(
            mapping["requirements"]["1.1"]["automated_targets"],
            [
                "exact.c1.1.closed-field-contract",
                "exact.c1.1.cimd-gate",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["1.8"]["automated_targets"],
            ["exact.c1.1.cimd-gate"],
        )

        self.assertEqual(
            mapping["requirements"]["3.2"]["automated_targets"],
            [
                "exact.c3.2.same-request-cache",
                "exact.c3.2.request-fingerprint-mismatch",
                "exact.c3.2.single-decode",
                "exact.c3.2.origin-pkce-binding",
                "exact.c3.2.client-identity-mismatch",
                "exact.c3.2.dpop-identity-mismatch",
                "exact.c3.2.cleanup-failure-retry",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["3.4"]["automated_targets"],
            [
                "exact.c3.4.envelope-roundtrip",
                "exact.c3.4.delete-only-runtime",
                "exact.c3.4.token-route-scope",
                "exact.c3.4.non-token-route-scope",
                "exact.c3.4.primary-runtime-isolation",
                "exact.c3.4.standby-runtime-isolation",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["4.2"]["automated_targets"],
            [
                "exact.c4.2.registry-metadata",
                "exact.c4.2.phase-projection",
                "exact.c4.2.admission-registry",
                "exact.c4.2.invalid-record-fail-closed",
                "exact.c4.2.token-auth-matrix",
                "exact.c4.2.revocation-auth-matrix",
                "exact.c4.2.method-substitution",
                "exact.c4.2.general-inline-jwks",
                "exact.c4.2.private-inline-kid",
                "exact.c4.2.general-key-replacement",
                "exact.c4.2.private-claims-replay",
                "exact.c4.2.private-jwks-uri",
                "exact.c4.2.private-rs256",
                "exact.c4.2.private-key-rotation",
                "exact.c4.2.private-replay-dependency",
                "exact.c4.2.private-revocation",
                "exact.c4.2.private-introspection",
                "exact.c4.2.private-par",
                "exact.c4.2.private-refresh",
                "exact.c4.2.private-ciba",
                "exact.c4.2.private-prm",
                "exact.c4.2.private-sessions",
                "exact.c4.2.general-key-migration",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["4.3"]["automated_targets"],
            [
                "exact.c4.3.registration-uri",
                "exact.c4.3.untrusted-host",
                "exact.c4.3.management-ownership",
                "exact.c4.3.anonymous-ip-throttle",
                "exact.c4.3.iat-routing",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["4.8"]["automated_targets"],
            [
                "exact.c4.8.context-no-logo",
                "exact.c4.8.unverified-no-external-logo",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["4.9"]["coverage_level"],
            "exact",
        )
        self.assertEqual(
            mapping["requirements"]["4.9"]["automated_targets"],
            [
                "exact.c4.9.registered-priority",
                "exact.c4.9.url-policy",
                "exact.c4.9.literal-targets",
                "exact.c4.9.document-contract",
                "exact.c4.9.document-mismatch-http",
                "exact.c4.9.transport-pinning",
                "exact.c4.9.redirect-policy",
                "exact.c4.9.redirect-limit",
                "exact.c4.9.dns-address-validation",
                "exact.c4.9.dns-fail-closed",
                "exact.c4.9.fetch-budget",
                "exact.c4.9.total-timeout",
                "exact.c4.9.singleflight-timeout",
                "exact.c4.9.concurrency-bound",
                "exact.c4.9.cache-store",
                "exact.c4.9.cache-policy",
                "exact.c4.9.cache-isolation",
                "exact.c4.9.malformed-not-cached",
                "exact.c4.9.oversized-not-cached",
                "exact.c4.9.public-snapshot",
                "exact.c4.9.private-key-snapshot",
                "exact.c4.9.continuation-binding",
                "exact.c4.9.consent-continuation",
                "exact.c4.9.login-continuation",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["4.9"]["recorded_references"],
            [],
        )
        self.assertEqual(
            mapping["requirements"]["4.1"]["automated_targets"],
            [
                "exact.c4.1.pkce-method",
                "exact.c4.1.rfc7636-vector",
                "exact.c4.1.verifier-format",
                "exact.c4.1.authorize-public-required",
                "exact.c4.1.authorize-confidential-tuple",
                "exact.c4.1.authorize-runtime-capability",
                "exact.c4.1.confidential-basic",
                "exact.c4.1.confidential-basic-auth",
                "exact.c4.1.confidential-post",
                "exact.c4.1.confidential-private-key-jwt",
                "exact.c4.1.token-client-downgrade",
                "exact.c4.1.token-workload-reclassification",
                "exact.c4.1.token-unexpected-verifier",
                "exact.c4.1.token-challenge-binding",
                "exact.c4.1.cimd-required",
                "exact.c4.1.consent-public",
                "exact.c4.1.consent-confidential",
                "exact.c4.1.consent-tuple",
                "exact.c4.1.consent-workload",
                "exact.c4.1.par-public",
                "exact.c4.1.par-confidential",
                "exact.c4.1.par-tuple",
                "exact.c4.1.par-workload",
                "exact.c2.1.access-token-shape",
                "exact.c5.6.workload-rejected",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["4.10"]["automated_targets"],
            [
                "exact.c4.10.normalization",
                "exact.c4.10.web-redirect-matrix",
                "exact.c4.10.native-redirect-matrix",
                "exact.c4.10.native-loopback-match",
                "exact.c4.10.dcr",
                "exact.c4.10.authorize-legacy",
                "exact.c4.10.rfc7592",
                "exact.c4.10.admin-legacy",
                "exact.c4.10.admin-revalidation",
                "exact.c4.10.dynamo",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["5.4"]["automated_targets"],
            [
                "exact.c5.4.sts-timeout",
                "exact.c5.4.circuit-breaker",
                "exact.c5.4.half-open-boundary",
                "exact.c5.4.half-open-success",
                "exact.c5.4.half-open-failure",
                "exact.c5.4.half-open-single-probe",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["6.5"]["automated_targets"],
            [
                "exact.c6.5.authoritative-session-projection",
                "exact.c6.5.dynamo-authority",
                "exact.c6.5.eventbridge-shape",
                "exact.c6.5.replay-order",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["7.6a"]["automated_targets"],
            [
                "exact.c3.5.revoke-delete",
                "exact.c7.6a.online-offline-boundary",
                "exact.c7.6a.requires-auth",
                "exact.c7.6a.wrong-secret",
                "exact.c7.6a.owner-isolation",
                "exact.c7.6a.idempotent-no-leak",
                "exact.c7.6a.required-token",
                "exact.c7.6a.hint-nonsemantic",
                "exact.c1.1.closed-field-contract",
            ],
        )
        self.assertEqual(mapping["requirements"]["7.6b"]["coverage_level"], "exact")
        self.assertEqual(
            mapping["requirements"]["7.6b"]["automated_targets"],
            [
                "exact.c7.6b.grant-cascade",
                "exact.c7.6b.cleanup-retry",
                "exact.c7.6b.introspection-grant",
                "exact.c7.6b.introspection-family",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["10.6"]["automated_targets"],
            [
                "exact.c10.6.verify-time-boundaries",
                "exact.c7.6a.online-offline-boundary",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["10.8"]["automated_targets"],
            [
                "exact.c4.3.anonymous-ip-throttle",
                "exact.c10.8.global-quota",
                "exact.c10.8.global-quota-fail-closed",
                "exact.c4.3.iat-routing",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["5.7"]["automated_targets"],
            [
                "exact.c5.7.admin-jwt-binding",
                "exact.c5.7.admin-x509-binding",
                "exact.c5.7.jwt-es256",
                "exact.c5.7.jwt-jose",
                "exact.c5.7.jwt-wrong-key",
                "exact.c5.7.jwt-audience",
                "exact.c5.7.jwt-audience-array",
                "exact.c5.7.jwt-issuer-independent",
                "exact.c5.7.jwt-ambiguity",
                "exact.c5.7.jwt-trust-domain",
                "exact.c5.7.jwt-trust-domain-parser",
                "exact.c5.7.jwt-subject-shape",
                "exact.c5.7.jwt-pattern-negative",
                "exact.c5.7.jwt-pattern-deep",
                "exact.c5.7.jwt-pattern-boundaries",
                "exact.c5.7.jwt-tenant-isolation",
                "exact.c5.7.jwt-token-type",
                "exact.c5.7.jwt-token-type-case",
                "exact.c5.7.jwt-expiry",
                "exact.c5.7.jwt-required-claims",
                "exact.c5.7.jwt-missing-iat",
                "exact.c5.7.jwt-mixed-jwk",
                "exact.c5.7.jwt-nbf",
                "exact.c5.7.jwt-max-lifetime",
                "exact.c5.7.jwt-rs256",
                "exact.c5.7.x509-success",
                "exact.c5.7.x509-parser-happy",
                "exact.c5.7.x509-parser-dns",
                "exact.c5.7.x509-no-cert",
                "exact.c5.7.x509-exclusive-identity",
                "exact.c5.7.x509-binding-negative",
                "exact.c5.7.x509-binding-isolation",
                "exact.c5.7.x509-ambiguity",
                "exact.c5.7.x509-mechanism-isolation",
                "exact.c5.7.x509-san",
                "exact.c5.7.x509-no-san",
                "exact.c5.7.x509-no-uri",
                "exact.c5.7.x509-multi-uri",
                "exact.c5.7.x509-non-spiffe-uri",
                "exact.c5.7.x509-malformed-pem",
                "exact.c5.7.x509-validity",
                "exact.c5.7.x509-no-assertion-downgrade",
                "exact.c5.7.x509-feature-gate",
                "exact.c5.7.x509-saas-gate",
                "exact.c1.2.phase-matrix",
                "exact.c5.7.x509-discovery",
                "exact.c5.7.lambda-client-cert-source",
                "exact.c3.4.primary-runtime-isolation",
                "exact.c5.7.mtls-infra",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["6.3"]["automated_targets"],
            [
                "exact.c6.3.exchange-failure-terminal",
                "exact.c6.3.exchange-failure-conflict",
                "exact.c6.3.exchange-failure-injected",
                "exact.c6.3.exchange-failure-concurrent",
                "exact.c6.3.confidential-replay-auth",
                "exact.c6.3.bound-replay-revocation",
                "exact.c6.3.replay-finalize-race",
                "exact.c6.3.replay-rate-limit",
                "exact.c6.3.introspection-revocation",
                "exact.c6.3.dynamo-cancel-retry",
                "exact.c10.4.dynamo-exchange-failure-fence",
                "exact.c10.4.dynamo-exchange-failure-after-await",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["9.5"]["automated_targets"],
            [
                "exact.c9.5.prompt-none-login-required",
                "exact.c9.5.prompt-none-consent-required",
                "exact.c9.5.prompt-none-silent-code",
                "exact.c9.5.prompt-none-resource-consent",
                "exact.c9.5.prompt-login-reauth",
                "exact.c9.5.prompt-none-combination",
                "exact.c9.5.max-age-zero",
                "exact.c9.5.max-age-authorization-time",
                "exact.c9.5.max-age-reauthentication",
                "exact.c9.5.federation-max-age-forwarding",
                "exact.c9.5.federation-acr-amr",
                "exact.c9.5.federation-unmapped-acr",
                "exact.c9.5.federation-auth-time",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["9.11"]["automated_targets"],
            [
                "exact.c9.11.bootstrap-xor",
                "exact.c9.11.crypto-rng",
                "exact.c9.11.show-once",
                "exact.c9.11.regeneration",
                "exact.c10.24.invitation-login",
                "exact.c9.11.concurrent-consume",
                "exact.c9.11.lifecycle-fail-closed",
                "exact.c9.11.eligibility",
                "exact.c9.11.tenant-isolation",
                "exact.c9.11.dynamo-verifier-record",
                "exact.c9.11.dynamo-atomic-consume",
                "exact.c9.11.dynamo-issue-reconcile",
                "exact.c9.11.dynamo-issue-mismatch",
                "exact.c9.11.dynamo-accept-reconcile",
                "exact.c9.11.dynamo-accept-mismatch",
                "exact.c9.11.web-history",
                "exact.c9.11.web-retry",
                "exact.c9.11.web-show-once",
                "exact.c9.11.web-concurrent-regeneration",
                "exact.c9.11.infra",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["10.23"]["automated_targets"],
            [
                "exact.c10.23.user-navigation",
                "exact.c10.23.invalid-tab",
                "exact.c10.23.client-search",
                "exact.c10.23.user-search-pagination",
                "exact.c10.23.user-search-pagination-dynamo",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["10.24"]["automated_targets"],
            [
                "exact.c10.24.user-memory-monotonic",
                "exact.c10.24.user-dynamo-contract",
                "exact.c10.24.client-memory-daily",
                "exact.c10.24.client-dynamo-contract",
                "exact.c10.24.user-observation-failure",
                "exact.c10.24.client-observation-failure",
                "exact.c10.24.password-login",
                "exact.c9.7.admin-provisioned-login",
                "exact.c9.7.disabled-no-send",
                "exact.c10.24.invitation-login",
                "exact.c10.24.passkey-login",
                "exact.c10.24.passkey-authority-rollback",
                "exact.c10.24.federation-login",
                "exact.c10.24.federation-disabled-denial",
                "exact.c10.24.recovery-login",
                "exact.c10.24.recovery-authority-rollback",
                "exact.c10.24.recovery-replay",
                "exact.c10.24.token-issuance",
                "exact.c3.1.rotation-and-opaque-handle",
                "exact.c2.10.claim-omission",
                "exact.c7.4.delegated-token",
                "exact.c7b.4.one-shot",
                "exact.c7b.2.approved-one-shot",
                "exact.c10.24.ciba-push-success",
                "exact.c10.24.ciba-push-delivery-failure",
                "exact.c10.24.ciba-push-tombstone",
                "exact.c10.24.admin-user-null",
                "exact.c10.24.admin-client-time",
                "exact.c10.24.web-users",
                "exact.c10.24.web-clients",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["7b.2"]["automated_targets"],
            [
                "exact.c7b.2.poll-errors",
                "exact.c7b.poll-interval-boundary",
                "exact.c7b.poll-claim-memory",
                "exact.c7b.poll-claim-dynamo",
                "exact.c7b.2.concurrent-pending",
                "exact.c7b.2.denied",
                "exact.c7b.2.approved-one-shot",
                "exact.c7b.2.concurrent-one-shot",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["7b.3"]["automated_targets"],
            ["exact.c7b.3.sessionless-poll"],
        )
        self.assertEqual(
            mapping["requirements"]["7b.4"]["automated_targets"],
            [
                "exact.c7b.4.poll-errors",
                "exact.c7b.poll-interval-boundary",
                "exact.c7b.poll-claim-memory",
                "exact.c7b.poll-claim-dynamo",
                "exact.c7b.4.concurrent-pending",
                "exact.c7b.4.denied",
                "exact.c7b.4.one-shot",
                "exact.c7b.4.concurrent-one-shot",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["7b.5"]["automated_targets"],
            [
                "exact.c7b.5.registration",
                "exact.c7b.5.confidential-only",
                "exact.c7b.5.endpoint-ssrf",
                "exact.c7b.5.endpoint-required",
                "exact.c7b.5.capability-gate",
                "exact.c7b.5.poll-compatibility",
                "exact.c4.7.push-dpop-invariant",
                "exact.c7b.5.ping-dispatch",
                "exact.c7b.5.poll-auth",
                "exact.c7b.6.global-push-quota",
                "exact.c10.24.ciba-push-success",
                "exact.c10.24.ciba-push-delivery-failure",
                "exact.c7b.5.snapshot",
                "exact.c7b.5.downgrade-rejection",
                "exact.c10.24.ciba-push-tombstone",
                "exact.c7b.5.discovery",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["7b.6"]["automated_targets"],
            [
                "exact.c7b.6.user-cooldown",
                "exact.c7b.1.id-token-resolution",
                "exact.c7b.6.approval-display",
                "exact.c7b.6.approval-page",
                "exact.c7b.6.global-push-quota",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["10.4"]["automated_targets"],
            [
                "exact.c10.4.boundary",
                "exact.c10.4.authorization-code",
                "exact.c7b.4.poll-errors",
                "exact.c10.4.session-token",
                "exact.c10.4.session-read-after-await",
                "exact.c10.4.jti",
                "exact.c10.4.jti-read-after-await",
                "exact.c10.4.grace-read-after-await",
                "exact.c10.4.device-token-commit-time",
                "exact.c10.4.device-approval-commit-time",
                "exact.c8.11.strict-gates",
                "exact.c3.5.reuse-delete",
                "exact.c10.4.memory-code-write-fence",
                "exact.c10.4.memory-write-fence",
                "exact.c10.4.dynamo-code-write-fence",
                "exact.c10.4.dynamo-exchange-failure-fence",
                "exact.c10.4.dynamo-exchange-failure-after-await",
                "exact.c10.4.dynamo-session-transition-after-await",
                "exact.c6.5.dynamo-authority",
                "exact.c7b.poll-claim-dynamo",
                "exact.c10.4.dynamo-device-write-fence",
                "exact.c10.4.dynamo-release-classification",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["10.5"]["automated_targets"],
            [
                "exact.c10.5.persistent-identities",
                "exact.c10.5.unexpired-artifact",
                "exact.c10.5.active-grant",
                "exact.c10.5.idle-tombstone",
                "exact.c10.5.active-refresh",
                "exact.c10.5.grace-pending",
                "exact.c10.5.late-reference",
                "exact.c10.5.hard-delete",
                "exact.c10.5.code-reference-atomicity",
                "exact.c10.5.refresh-reference-atomicity",
                "exact.c10.5.tombstone-revision-fence",
                "exact.c10.5.hard-delete-transaction",
                "exact.c10.5.coverage-required",
                "exact.c10.5.coverage-version",
                "exact.c10.5.code-query",
                "exact.c10.5.refresh-query",
                "exact.c10.5.migration-checkpoints",
                "exact.c10.5.migration-generation",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["8.5b"]["automated_targets"],
            [
                "exact.c8.5b.python-policy-boundary",
                "exact.c8.5b.python-offline-binding",
                "exact.c8.5b.python-introspection-binding",
                "exact.c8.5b.typescript-policy-boundary",
                "exact.c8.5b.typescript-offline-binding",
                "exact.c8.5b.typescript-introspection-binding",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["8.7b"]["automated_targets"],
            [
                "exact.c8.7b.authorization-code",
                "exact.c8.7b.authorization-code-bearer",
                "exact.c8.7b.refresh",
                "exact.c8.7b.workload",
                "exact.c8.7b.device",
                "exact.c8.7b.ciba",
                "exact.c8.7b.ema",
                "exact.c8.7b.introspection-reflection",
            ],
        )
        self.assertEqual(mapping["requirements"]["8.1b"]["coverage_level"], "exact")
        self.assertEqual(
            mapping["requirements"]["8.1b"]["automated_targets"],
            [
                "exact.c8.1b.forwarded-host-overwrite",
                "exact.c8.1b.saas-host-tenant-binding",
                "exact.c8.1b.owner-derived-from-host",
                "exact.c8.1b.cross-tenant-unbind",
                "exact.c8.1b.control-host-rejected",
                "exact.c8.1b.unregistered-host",
                "exact.c8.1b.issuer-origin-registration-guard",
                "exact.c8.1b.resource-owner-binding",
                "exact.c8.1b.client-delete-cascade",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["7b.1"]["automated_targets"],
            [
                "exact.c7b.1.exactly-one-hint",
                "exact.c7b.1.id-token-resolution",
                "exact.c7b.1.id-token-tamper",
                "exact.c7b.1.id-token-audience",
                "exact.c7b.1.login-hint-token-fail-closed",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["8.10"]["automated_targets"],
            [
                "exact.c2.2a.access-signer-shape",
                "exact.c2.2a.delegation-signer-shape",
                "exact.c8.10.size-thresholds",
                "exact.c8.10.access-oversize",
                "exact.c8.10.delegation-oversize",
                "exact.c8.10.public-guidance",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["8.10b"]["automated_targets"],
            [
                "exact.c8.10b.rust-code-refresh",
                "exact.c8.10b.rust-token-exchange",
                "exact.c8.10b.python-offline-fail-closed",
                "exact.c8.10b.typescript-offline-fail-closed",
                "exact.c8.10b.delivery-gating",
                "exact.c8.10b.summary-parser",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["9.1"]["automated_targets"],
            [
                "exact.c9.1.per-email-cooldown",
                "exact.c9.1.global-email-quota",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["9.2"]["automated_targets"],
            [
                "exact.c9.2.browser-nonce-binding",
                "exact.c9.2.dynamo-bound-consume",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["9.7"]["automated_targets"],
            [
                "exact.c9.7.no-jit-suppression",
                "exact.c9.7.admin-provisioned-login",
                "exact.c9.7.disabled-no-send",
                "exact.c9.7.tombstoned-no-revival",
                "exact.c9.7.alias-binding",
                "exact.c9.7.password-no-jit",
                "exact.c9.7.passkey-no-jit",
                "exact.c9.7.passkey-postwrite-status",
                "exact.c9.7.passkey-postwrite-epoch",
                "exact.c9.7.recovery-no-jit",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["9.8"]["automated_targets"],
            [
                "exact.c9.8.infra-store",
                "exact.c9.8.password-policy",
                "exact.c9.8.salted-argon2",
                "exact.c9.8.phc-profile",
                "exact.c9.8.storage-profile",
                "exact.c9.10.secret-wrappers",
                "exact.c9.8.dynamo-store",
                "exact.c9.8.memory-store",
                "exact.c10.24.password-login",
                "exact.c9.9.concurrent-change",
                "exact.c9.10.alias-success",
                "exact.c9.10.alias-failure-fixed-read",
                "exact.c9.8.scim-version-fence",
                "exact.c9.8.admin-reset",
                "exact.c9.8.code-version-fence",
                "exact.c9.8.device-ciba-reset-fence",
                "exact.c9.8.legacy-refresh-fence",
                "exact.c9.8.legacy-device-fence",
                "exact.c9.8.legacy-ciba-fence",
                "exact.c9.8.reset-eligibility",
                "exact.c9.8.partial-write-recovery",
                "exact.c9.8.pending-alias-fence",
                "exact.c9.8.legacy-session-revocation",
                "exact.c9.8.tombstone-cleanup",
                "exact.c9.8.markerless-pending-reset",
                "exact.c9.8.aws-reset-reconciliation",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["9.9"]["automated_targets"],
            [
                "exact.c10.24.password-login",
                "exact.c9.9.authz-session-gate",
                "exact.c9.9.concurrent-change",
                "exact.c9.7.no-jit-suppression",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["9.10"]["automated_targets"],
            [
                "exact.c9.7.password-no-jit",
                "exact.c9.10.dummy-profile",
                "exact.c9.10.alias-success",
                "exact.c9.10.alias-failure-fixed-read",
                "exact.c9.10.account-hmac",
                "exact.c9.10.success-budget",
                "exact.c9.10.failure-budget",
                "exact.c9.10.parameter-failure-budget",
                "exact.c9.9.concurrent-change",
                "exact.c9.10.session-failure-budget",
                "exact.c9.10.trusted-source-ip",
                "exact.c9.10.lambda-source-ip",
                "exact.c9.10.tenant-isolation",
                "exact.c9.10.global-budget",
                "exact.c9.10.store-fail-closed",
                "exact.c9.10.rate-store-errors",
                "exact.c9.10.dynamo-retry-exhaustion",
                "exact.c9.10.worker-saturation",
                "exact.c9.10.spawn-blocking",
                "exact.c9.10.secret-wrappers",
                "exact.c9.10.body-limit",
                "exact.c9.10.change-shared-gates",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["10.1"]["automated_targets"],
            [
                "exact.c10.1.code-auth-failure",
                "exact.c10.1.code-kms-transient",
                "exact.c6.3.exchange-failure-terminal",
                "exact.c10.1.code-finalize-failure",
                "exact.c10.1.code-owner-fence-memory",
                "exact.c10.4.dynamo-code-write-fence",
                "exact.c10.1.refresh-kms-transient",
                "exact.c10.1.refresh-finalize-failure",
                "exact.c10.1.refresh-owner-fence-memory",
                "exact.c3.1.dynamo-conditional-cas",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["10.2"]["automated_targets"],
            [
                "exact.c10.1.code-kms-transient",
                "exact.c10.1.refresh-kms-transient",
                "exact.c10.2.client-credentials-kms",
                "exact.c10.2.token-exchange-kms",
                "exact.c10.2.device-kms",
                "exact.c10.2.ciba-kms",
                "exact.c10.2.ema-kms",
                "exact.c10.2.proactive-gate",
                "exact.c10.2.gate-placement",
                "exact.c10.2.test-run-isolation",
                "exact.c10.2.test-run-validation",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["10.2"]["recorded_references"],
            [],
        )
        self.assertEqual(
            mapping["requirements"]["10.3"]["automated_targets"],
            [
                "exact.c10.3.kms-adapter",
                "exact.c10.3.der-full-width",
                "exact.c10.3.der-sign-padding",
                "exact.c10.3.der-short-padding",
                "exact.c10.3.jose-roundtrip",
                "exact.c10.3.malformed-der",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["10.11a"]["automated_targets"],
            ["exact.c10.11a.rotation-overlap-jwks"],
        )
        self.assertEqual(
            mapping["requirements"]["10.11b"]["coverage_level"],
            "exact",
        )
        self.assertEqual(
            mapping["requirements"]["10.11b"]["automated_targets"],
            [
                "exact.c10.11a.rotation-overlap-jwks",
                "exact.c10.11b.rotation-windows",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["10.12"]["coverage_level"],
            "exact",
        )
        self.assertEqual(
            mapping["requirements"]["10.12"]["automated_targets"],
            [
                "exact.c10.12.public-jwks",
                "exact.c10.12.provisioner",
                "exact.c10.12.runbook",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["10.13"]["coverage_level"],
            "exact",
        )
        self.assertEqual(
            mapping["requirements"]["10.13"]["automated_targets"],
            [
                "exact.c10.13.control-plane",
                "exact.c10.13.complete-pairs",
                "exact.c10.13.es256-forgery",
                "exact.c10.13.rs256-forgery",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["10.13"]["recorded_references"],
            [],
        )
        self.assertEqual(
            mapping["requirements"]["10.15a"]["automated_targets"],
            [
                "exact.c2.1.access-token-shape",
                "exact.c2.6-c2.9.id-token-boundary",
                "exact.c2.7.es256-client",
                "exact.c3.1.rotation-and-opaque-handle",
                "exact.c8.7b.authorization-code",
                "exact.c8.7b.refresh",
                "exact.c8.7b.workload",
                "exact.c8.7b.device",
                "exact.c8.7b.ciba",
                "exact.c8.7b.ema",
                "exact.c8.7b.introspection-reflection",
                "exact.c5.6.token-exchange",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["2.3"]["automated_targets"],
            [
                "exact.c2.1.access-token-shape",
                "exact.c2.3a.2lo-sub",
                "exact.c2.3.service-2lo",
                "exact.c2.3.workload-jwt-routing",
                "exact.c2.3.service-policy-snapshot",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["2.3a"]["automated_targets"],
            [
                "exact.c2.3a.2lo-sub",
                "exact.c2.3.service-2lo",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["13.1"]["automated_targets"],
            [
                "exact.c13.1.feature-off",
                "exact.c13.1.feature-on-no-probe",
                "exact.c13.1.dependency-gate",
                "exact.c13.1.metadata-golden",
                "exact.c13.1.deployment-config",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["13.2"]["automated_targets"],
            ["exact.c13.2.ema-request-boundary"],
        )
        self.assertEqual(
            mapping["requirements"]["13.3"]["automated_targets"],
            [
                "exact.c13.3.policy-index",
                "exact.c13.3.policy-validation",
                "exact.c13.3.identity-time-decision",
                "exact.c13.3.http-claim-signature",
                "exact.c13.3.http-key-selection",
                "exact.c13.3.http-rs256",
                "exact.c13.3.fixed-trust-anchor",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["13.4"]["automated_targets"],
            [
                "exact.c13.4.resource-scope-decision",
                "exact.c13.4.rar-actor-dpop-decision",
                "exact.c13.4.http-scope",
                "exact.c13.4.http-target-rar",
                "exact.c13.4.http-strict-resource",
                "exact.c13.4.http-assertion-semantics",
                "exact.c8.7b.ema",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["13.8"]["automated_targets"],
            [
                "exact.c13.8.malformed-form",
                "exact.c13.2.ema-request-boundary",
                "exact.c13.4.http-target-rar",
                "exact.c13.5.http-serial-replay",
                "exact.c10.2.ema-kms",
                "exact.c13.8.permanent-failure",
                "exact.c13.7.http-access-contract",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["10.16"]["automated_targets"],
            [
                "exact.c2.1.access-token-shape",
                "exact.c10.16.cloudfront-ttl",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["10.17"]["automated_targets"],
            [
                "exact.c10.17.hot-path-zero-cedar",
                "exact.c10.17.cold-path-cedar",
                "exact.c10.17.refresh-stale-read-gate",
                "exact.c7.4.delegated-token",
                "exact.c10.17.publish-activate",
                "exact.c10.17.publish-idempotent",
                "exact.c10.17.publish-failure",
                "exact.c10.17.recompute-narrow",
                "exact.c10.17.recompute-reloosen",
                "exact.c10.17.recompute-revoke",
                "exact.c10.17.recompute-dry-run",
                "exact.c10.17.recompute-cas",
                "exact.c10.17.recompute-revoke-fence",
                "exact.c10.17.resource-less-preserve",
                "exact.c10.17.empty-scope-preserve",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["10.19"]["automated_targets"],
            [
                "exact.c10.19.codes",
                "exact.c10.19.clients",
                "exact.c10.19.users",
                "exact.c10.19.federated-user",
                "exact.c10.19.grants",
                "exact.c10.19.refresh",
                "exact.c10.19.sessions",
                "exact.c10.19.passkeys",
                "exact.c10.19.recovery",
                "exact.c10.19.authz-sessions",
                "exact.c10.19.reclaim",
                "exact.c10.19.magic-links",
                "exact.c10.19.devices",
                "exact.c10.19.ciba",
                "exact.c10.19.workload-trust",
                "exact.c10.19.messages",
                "exact.c10.19.flat-compat",
                "exact.c10.19.dynamo-client-read",
                "exact.c10.19.dynamo-code-keys",
                "exact.c10.19.dynamo-session-read",
                "exact.c11.2.dynamo-grant-read",
                "exact.c10.19.dynamo-refresh-read",
                "exact.c10.5.code-query",
                "exact.c10.5.refresh-query",
                "exact.c10.19.saas-http-flow",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["10.19"]["recorded_references"],
            [],
        )
        self.assertEqual(
            mapping["requirements"]["10.22a"]["automated_targets"],
            [
                "exact.c10.22a.guard",
                "exact.c10.22a.counterexample",
                "exact.c10.22a.runtime-denial",
                "exact.c10.22a.shared-signer-denial",
                "exact.c10.22a.issuance-wiring",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["10.22a"]["recorded_references"],
            [],
        )
        self.assertEqual(
            mapping["requirements"]["10.20"]["automated_targets"],
            ["exact.c1.1b.discovery"],
        )
        self.assertEqual(
            mapping["requirements"]["10.21"]["automated_targets"],
            ["exact.c10.21.cookie-session-isolation"],
        )
        self.assertEqual(
            mapping["requirements"]["11.1"]["automated_targets"],
            [
                "exact.c11.1.regional-id",
                "exact.c11.1.failback-revision",
                "exact.c11.1.code-refresh-owner",
                "exact.c11.1.jti-owner",
                "exact.c11.1.dynamo-admission",
                "exact.c11.1.split-brain",
                "exact.c11.1.persistent-fence",
                "exact.c11.1.primary-topology",
                "exact.c11.1.runtime-fence-iam",
                "exact.c11.1.standby-topology",
                "exact.c11.1.edge-affinity",
                "exact.c11.1.governance-drill-topology",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["11.1"]["recorded_references"],
            [],
        )
        self.assertEqual(mapping["requirements"]["11.3"]["coverage_level"], "exact")
        self.assertEqual(
            mapping["requirements"]["11.3"]["automated_targets"],
            [
                "exact.c11.3.quiescence-fence",
                "exact.c11.1.failback-revision",
                "exact.c11.1.code-refresh-owner",
                "exact.c11.1.jti-owner",
                "exact.c11.1.edge-affinity",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["11.3"]["recorded_references"],
            [],
        )
        self.assertEqual(mapping["requirements"]["11.4"]["coverage_level"], "exact")
        self.assertEqual(
            mapping["requirements"]["11.4"]["automated_targets"],
            [
                "exact.c11.4.mrk-create",
                "exact.c10.13.control-plane",
                "exact.c11.4.regional-probes",
                "exact.c11.4.probe-fail-closed",
                "exact.c11.4.snapshot-gate",
                "exact.c10.13.complete-pairs",
                "exact.c11.4.regional-runtime",
                "exact.c11.4.single-region-fail-closed",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["11.4"]["recorded_references"],
            [],
        )
        self.assertEqual(mapping["requirements"]["12.4"]["coverage_level"], "exact")
        self.assertEqual(
            mapping["requirements"]["12.1"]["automated_targets"],
            [
                "exact.c12.1.verifier-storage",
                "exact.c12.1.auth-method-versioning",
                "exact.c12.1.client-secret-rotation",
                "exact.c12.1.client-secret-auto-cutover",
                "exact.c12.1.client-secret-rollback",
                "exact.c12.1.registration-token-rotation",
                "exact.c12.1.registration-token-migration",
                "exact.c12.1.expiry",
                "exact.c12.1.client-secret-auth-migration",
                "exact.c12.1.client-secret-update-migration",
                "exact.c12.1.storage-migration",
                "exact.c12.1.iat-lifecycle",
                "exact.c12.1.admin-overlap",
                "exact.c12.1.admin-expiry",
                "exact.c12.1.admin-owner-isolation",
                "exact.c12.1.admin-host-isolation",
                "exact.c12.1.admin-revision-regression",
                "exact.c12.1.admin-time-immutability",
                "exact.c12.1.admin-rollback",
                "exact.c12.1.admin-rollback-validation",
                "exact.c12.1.admin-retired-resurrection",
                "exact.c12.1.admin-retired-owner-isolation",
                "exact.c12.1.admin-legacy-lifetime",
                "exact.c12.1.admin-copy-migration",
                "exact.c12.1.admin-raw-reset",
                "exact.c12.1.admin-validated-stage",
                "exact.c12.1.admin-break-glass",
                "exact.c12.1.admin-owner-bound-infra",
                "exact.c12.1.irreversible-migration-infra",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["12.2"]["automated_targets"],
            [
                "exact.c12.2.core-flow",
                "exact.c12.2.lifecycle-epoch",
                "exact.c12.2.tombstone-retry",
                "exact.c12.2.tenant-isolation",
                "exact.c12.2.okta-flow",
                "exact.c12.2.okta-cleanup-failure",
                "exact.c12.2.okta-run-id",
                "exact.c12.2.okta-secret-injection",
                "exact.c12.2.okta-preexisting-user",
                "exact.c12.2.okta-evidence-reservation",
                "exact.c12.2.okta-create-collision",
                "exact.c12.2.okta-interrupt-cleanup",
                "exact.c12.2.okta-lock-contention",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["12.3"]["automated_targets"],
            [
                "exact.c12.3.group-domain-separation",
                "exact.c12.3.group-tenant-isolation",
                "exact.c12.3.group-stable-generation",
                "exact.c12.3.group-idempotence",
                "exact.c12.3.oidc-browser-pkce-binding",
                "exact.c12.3.oidc-callback-security",
                "exact.c12.3.saas-tenant-oidc",
                "exact.c12.3.auditor-read-only",
                "exact.c12.3.role-action-matrix",
                "exact.c12.3.session-authority-revalidation",
                "exact.c12.3.session-expiry-isolation",
                "exact.c12.3.logout-persistence",
                "exact.c12.3.admin-auth-dynamo-routing",
                "exact.c12.3.web-enterprise-sso",
                "exact.c12.3.web-session-precedence",
                "exact.c12.3.web-auditor-denial",
                "exact.c12.3.scim-groups-infra",
                "exact.c12.3.admin-sso-infra",
                "exact.c12.1.admin-break-glass",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["12.4"]["automated_targets"],
            [
                "exact.c12.4.local-class-mapping",
                "exact.c12.4.policy-actions",
                "exact.c12.4.acr-values-step-up",
                "exact.c12.4.amr-no-elevation",
                "exact.c12.4.unknown-acr",
                "exact.c12.4.rar-authorize",
                "exact.c12.4.rar-consent",
                "exact.c12.4.rar-success",
                "exact.c12.4.admin-step-up",
                "exact.c10.24.passkey-login",
                "exact.c9.5.federation-acr-amr",
                "exact.c9.5.federation-unmapped-acr",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["12.5"]["automated_targets"],
            [
                "exact.c12.5.login-session-management",
                "exact.c12.5.current-session-revocation",
                "exact.c6.1.confidential-owner",
                "exact.c12.5.credential-summary",
                "exact.c12.5.reauthentication-gate",
                "exact.c12.5.password-lifecycle",
                "exact.c12.5.passkey-management",
                "exact.c12.5.factor-race",
                "exact.c12.5.passkey-registration-reauth",
                "exact.c12.5.credential-owner-fence",
                "exact.c12.5.credential-tombstone-fence",
                "exact.c12.5.session-dynamo-idempotency",
                "exact.c9.3.generate-show-once",
                "exact.c9.3.last-viable",
                "exact.c9.3.passkey-backup",
                "exact.c12.5.web-session-management",
                "exact.c12.5.web-current-session",
                "exact.c12.5.web-credential-lifecycle",
                "exact.c12.5.web-password-rotation",
                "exact.c12.5.web-last-factor",
                "exact.c12.5.web-reauthentication",
                "exact.c12.5.web-recovery-lockout",
                "exact.c9.3.web-show-once",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["12.5"]["recorded_references"],
            [],
        )
        self.assertEqual(
            mapping["requirements"]["12.6"]["automated_targets"],
            [
                "exact.c12.6.event-envelope",
                "exact.c10.24.password-login",
                "exact.c9.7.admin-provisioned-login",
                "exact.c12.3.role-action-matrix",
                "exact.c10.17.recompute-revoke",
                "exact.c12.6.key-secret-events",
                "exact.c12.1.admin-break-glass",
                "exact.c10.22a.runtime-denial",
                "exact.c12.6.event-dedup-export",
                "exact.c12.6.delivery-history",
                "exact.c12.6.admin-export",
                "exact.c12.6.dynamo-ledger",
                "exact.c12.6.dynamo-reconcile",
                "exact.c12.6.ingress-batch",
                "exact.c12.6.archive-retry",
                "exact.c12.6.archive-terminal",
                "exact.c12.6.event-hot-infra",
                "exact.c12.6.event-archive-infra",
                "exact.c12.6.event-alarm-infra",
                "exact.c12.6.ssf-account-projection",
                "exact.c12.6.ssf-allowlist",
                "exact.c12.6.ssf-session-projection",
                "exact.c12.6.ssf-credential-projection",
                "exact.c12.6.ssf-stream-lifecycle",
                "exact.c12.6.ssf-delivery-selection",
                "exact.c12.6.ssf-set-contract",
                "exact.c12.6.ssf-worker-retry",
                "exact.c12.6.ssf-retry-exhaustion",
                "exact.c12.6.ssf-revoke-fence",
                "exact.c12.6.ssf-tenant-keys",
                "exact.c12.6.ssf-admin-lifecycle",
                "exact.c12.6.ssf-admin-key-rotation",
                "exact.c12.6.ssf-admin-outbox",
                "exact.c12.6.ssf-saas-scope",
                "exact.c12.6.ssf-metadata-scope",
                "exact.c12.6.ssf-table-infra",
                "exact.c12.6.ssf-worker-infra",
                "exact.c10.11a.rotation-overlap-jwks",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["12.6"]["recorded_references"],
            [],
        )
        self.assertEqual(
            mapping["requirements"]["12.7"]["automated_targets"],
            [
                "exact.c12.7.user-export",
                "exact.c12.7.governance-rbac",
                "exact.c12.7.tenant-export-redaction",
                "exact.c12.7.legal-hold-resume",
                "exact.c12.7.post-primary-hold",
                "exact.c12.7.continuation",
                "exact.c12.7.user-erasure",
                "exact.c12.7.offboarding-legacy-tombstone",
                "exact.c12.7.offboarding-resume",
                "exact.c12.7.stale-worker-hold",
                "exact.c12.7.secondary-region",
                "exact.c12.7.residency-config",
                "exact.c12.7.suppression-domain",
                "exact.c12.7.retention-deadline",
                "exact.c12.7.retention-region",
                "exact.c12.7.retention-atomic",
                "exact.c12.7.governance-authorities-infra",
                "exact.c12.7.runtime-suppression-access-infra",
                "exact.c12.7.governance-worker-infra",
                "exact.c12.7.backup-excludes-control-infra",
                "exact.c12.7.background-writers-infra",
                "exact.c12.7.residency-deployment-infra",
                "exact.c12.7.recoverable-authority-infra",
                "exact.c12.7.daily-backup-infra",
                "exact.c12.7.backup-deadline-infra",
                "exact.c12.7.export-cursor-infra",
                "exact.c12.7.offboarding-live-counts-infra",
                "exact.c12.7.replica-zero-count-infra",
                "exact.c12.7.retention-exception-infra",
                "exact.c12.7.secret-ownership-infra",
                "exact.c12.7.verifier-control-authority-infra",
                "exact.c12.7.verifier-strong-read-infra",
                "exact.c12.7.verifier-business-roles-infra",
                "exact.c12.7.verifier-evidence-infra",
                "exact.c12.7.live-cutover-roles-infra",
                "exact.c12.7.live-cutover-provenance-infra",
                "exact.c12.7.live-cutover-cleanup-infra",
                "exact.c12.7.live-cutover-publication-infra",
                "exact.c12.7.live-cutover-resume-infra",
                "exact.c12.7.live-cutover-ambiguous-infra",
                "exact.c12.7.restore-clean",
                "exact.c12.7.restore-user-suppression",
                "exact.c12.7.restore-tenant-suppression",
                "exact.c12.7.restore-retained-controls",
                "exact.c12.7.restore-dangling-reference",
                "exact.c12.7.restore-key-version",
                "exact.c12.7.restore-unknown-tenant",
                "exact.c12.7.restore-transient-admin",
                "exact.c12.7.restore-incomplete-scan",
                "exact.c12.7.restore-malformed-audit",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["12.7"]["recorded_references"],
            [],
        )
        self.assertEqual(
            mapping["requirements"]["12.8"]["automated_targets"],
            [
                "exact.c12.8.evidence-assembly",
                "exact.c12.8.oidf-export",
                "exact.c12.8.oidf-origin",
                "exact.c12.8.oidf-signature",
                "exact.c12.8.gate-pass",
                "exact.c12.8.gate-failure",
                "exact.c12.8.exception-pass",
                "exact.c12.8.invalid-evidence",
                "exact.c12.8.invalid-exceptions",
                "exact.c12.8.workflow-chain",
                "exact.c12.8.workflow-promotion",
                "exact.c12.8.promotion-pass",
                "exact.c12.8.promotion-reject",
                "exact.c12.8.exception-issue-binding",
                "exact.c12.8.monitor-fresh",
                "exact.c12.8.monitor-config-skipped-stale",
                "exact.c12.8.monitor-runner",
                "exact.c12.8.monitor-schedule",
                "exact.c12.8.monitor-issue",
                "exact.c12.8.monitor-workflow",
                "exact.c12.8.complete-row-gate",
            ],
        )
        self.assertEqual(
            mapping["requirements"]["8.11"]["applicability"],
            "required_for_claimed_profile",
        )
        self.assertEqual(
            mapping["requirements"]["8.12"]["applicability"],
            "required_for_claimed_profile",
        )
        self.assertEqual(
            mapping["requirements"]["9.4"]["applicability"],
            "required_for_claimed_profile",
        )
        self.assertEqual(
            mapping["requirements"]["9.3"]["applicability"],
            "unconditional",
        )
        self.assertEqual(
            mapping["requirements"]["8.8a"]["applicability"],
            "unconditional",
        )

    def test_repository_aggregate_counts_are_pinned(self) -> None:
        mapping = json.loads(EVIDENCE_MAP.read_text(encoding="utf-8"))
        self.assertEqual(len(mapping["targets"]), 1036)
        rust_runner = (
            REPO_ROOT / "scripts" / "run_conformance_exact_tests.sh"
        ).read_text(encoding="utf-8")
        calls = re.findall(
            r"^run_(?:lib_)?exact[ \t]+(\S+)[ \t]+(\S+)[ \t]*$",
            rust_runner,
            flags=re.MULTILINE,
        )
        self.assertEqual(len(calls), 879)
        self.assertEqual(
            len(set(calls)),
            879,
        )
        web_runner = (
            REPO_ROOT / "scripts" / "run_web_conformance_exact_tests.sh"
        ).read_text(encoding="utf-8")
        web_calls = re.findall(
            r"^run_playwright_exact[ \t]+(\S+)[ \t]+(\S+)[ \t]*$",
            web_runner,
            flags=re.MULTILINE,
        )
        self.assertEqual(len(web_calls), 31)
        self.assertEqual(len(set(web_calls)), 31)
        infra_runner = (
            REPO_ROOT / "scripts" / "run_infra_conformance_exact_tests.sh"
        ).read_text(encoding="utf-8")
        infra_calls = re.findall(
            r"^run_node_exact[ \t]+(\S+)[ \t]+(\S+)[ \t]*$",
            infra_runner,
            flags=re.MULTILINE,
        )
        self.assertEqual(len(infra_calls), 51)
        self.assertEqual(len(set(infra_calls)), 51)
        python_runner = (
            REPO_ROOT / "scripts" / "run_python_conformance_exact_tests.sh"
        ).read_text(encoding="utf-8")
        python_calls = re.findall(
            r"^run_unittest_exact[ \t]+(\S+)[ \t]+(\S+)[ \t]+(\S+)[ \t]*$",
            python_runner,
            flags=re.MULTILINE,
        )
        self.assertEqual(len(python_calls), 40)
        self.assertEqual(len(set(python_calls)), 40)

    def test_node_exact_report_requires_the_named_subtest(self) -> None:
        selector = "c10_9b_interactive_page_behaviors_attach_clickjacking_policy"
        report = (
            "TAP version 13\n"
            f"# Subtest: {selector}\n"
            f"ok 1 - {selector}\n"
            "1..1\n"
            "# tests 1\n"
            "# pass 1\n"
            "# fail 0\n"
            "# skipped 0\n"
        )
        result = self.validate_node_exact_report(report, selector)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_node_exact_report_rejects_wrapper_only_pass(self) -> None:
        selector = "missing_exact_selector"
        report = (
            "TAP version 13\n"
            "# Subtest: test/frontend-api-behavior.test.js\n"
            "ok 1 - test/frontend-api-behavior.test.js\n"
            "1..1\n"
            "# tests 1\n"
            "# pass 1\n"
            "# fail 0\n"
            "# skipped 0\n"
        )
        result = self.validate_node_exact_report(report, selector)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactSubtest=false", result.stderr)

    def test_rejects_unmapped_requirement(self) -> None:
        mapping = json.loads(EVIDENCE_MAP.read_text(encoding="utf-8"))
        mapping["requirements"].pop("1.1")
        with self.assertRaisesRegex(ValueError, "mappings do not match"):
            self.validate_copy(evidence_map=mapping)

    def test_rejects_duplicate_requirement_key(self) -> None:
        mapping_text = EVIDENCE_MAP.read_text(encoding="utf-8")
        duplicate = json.dumps(
            json.loads(mapping_text)["requirements"]["1.1"],
            ensure_ascii=False,
        )
        mapping_text = mapping_text.replace(
            '    "1.1": {',
            f'    "1.1": {duplicate},\n    "1.1": {{',
            1,
        )
        with self.assertRaisesRegex(ValueError, "duplicate JSON key: 1.1"):
            self.validate_copy(evidence_map_text=mapping_text)

    def test_rejects_complete_requirement_without_exact_selector(self) -> None:
        mapping = json.loads(EVIDENCE_MAP.read_text(encoding="utf-8"))
        mapping["requirements"]["1.1b"]["automated_targets"] = []
        mapping["requirements"]["1.1b"]["coverage_level"] = "none"
        with self.assertRaisesRegex(
            ValueError,
            "complete requirement 1.1b must retain exact automated targets",
        ):
            self.validate_copy(evidence_map=mapping)

    def test_rejects_requirement_level_suite_mapping(self) -> None:
        mapping = json.loads(EVIDENCE_MAP.read_text(encoding="utf-8"))
        mapping["requirements"]["1.1"]["automated_targets"] = ["ci.conformance.exact"]
        mapping["requirements"]["1.1"]["coverage_level"] = "suite"
        with self.assertRaisesRegex(
            ValueError, "automation must be an exact repo test"
        ):
            self.validate_copy(evidence_map=mapping)

    def test_rejects_renamed_ci_step(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8").replace(
            "- name: Run exact conformance selectors",
            "- name: Run renamed tests",
            1,
        )
        with self.assertRaisesRegex(ValueError, "missing CI step"):
            self.validate_copy(workflow_text=workflow)

    def test_rejects_ci_step_that_no_longer_runs_suite(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8").replace(
            "run: ./scripts/run_conformance_exact_tests.sh",
            "run: echo skipped",
            1,
        )
        with self.assertRaisesRegex(ValueError, "no longer runs required command"):
            self.validate_copy(workflow_text=workflow)

    def test_rejects_ci_command_left_only_in_comment(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8").replace(
            "run: ./scripts/run_conformance_exact_tests.sh",
            "run: |\n          # ./scripts/run_conformance_exact_tests.sh\n          echo skipped",
            1,
        )
        with self.assertRaisesRegex(ValueError, "no longer runs required command"):
            self.validate_copy(workflow_text=workflow)

    def test_rejects_missing_or_ignored_exact_selector(self) -> None:
        mapping = json.loads(EVIDENCE_MAP.read_text(encoding="utf-8"))
        changed = copy.deepcopy(mapping)
        changed["targets"]["exact.c10.14.quota"]["selector"] = "renamed_selector"
        with self.assertRaisesRegex(ValueError, "selector is missing or ignored"):
            self.validate_copy(evidence_map=changed)

    def test_rejects_missing_pytest_exact_selector(self) -> None:
        mapping = json.loads(EVIDENCE_MAP.read_text(encoding="utf-8"))
        mapping["targets"]["exact.c2.2b.python-offline-sdk"]["selector"] = (
            "test_renamed_selector"
        )
        with self.assertRaisesRegex(ValueError, "selector is missing or ignored"):
            self.validate_copy(evidence_map=mapping)

    def test_unittest_exact_selector_is_supported(self) -> None:
        mapping = self.unittest_mapping()
        runner_path = "scripts/run_sdk_conformance_exact_tests.sh"
        runner = (REPO_ROOT / runner_path).read_text(encoding="utf-8")
        runner += (
            "\nrun_unittest_exact scripts/tests/test_release_conformance.py "
            "ReleaseConformanceCliTests "
            "test_promotion_accepts_exact_unexpired_gate_artifact\n"
        )

        self.validate_copy(
            evidence_map=mapping,
            file_overrides={runner_path: runner},
        )

    def test_rejects_missing_unittest_exact_selector(self) -> None:
        mapping = self.unittest_mapping()
        mapping["targets"]["exact.test.unittest"]["selector"] = "test_renamed_selector"
        runner_path = "scripts/run_sdk_conformance_exact_tests.sh"
        runner = (REPO_ROOT / runner_path).read_text(encoding="utf-8")
        runner += (
            "\nrun_unittest_exact scripts/tests/test_release_conformance.py "
            "ReleaseConformanceCliTests test_renamed_selector\n"
        )

        with self.assertRaisesRegex(ValueError, "selector is missing or ignored"):
            self.validate_copy(
                evidence_map=mapping,
                file_overrides={runner_path: runner},
            )

    def test_rejects_unittest_selector_missing_from_exact_runner(self) -> None:
        mapping = self.unittest_mapping()

        with self.assertRaisesRegex(ValueError, "not executed by its runner"):
            self.validate_copy(evidence_map=mapping)

    def test_rejects_missing_vitest_exact_selector(self) -> None:
        mapping = json.loads(EVIDENCE_MAP.read_text(encoding="utf-8"))
        mapping["targets"]["exact.c2.2b.typescript-offline-sdk"]["selector"] = (
            "renamed_selector"
        )
        with self.assertRaisesRegex(ValueError, "selector is missing or ignored"):
            self.validate_copy(evidence_map=mapping)

    def test_rejects_missing_playwright_exact_selector(self) -> None:
        mapping = self.playwright_mapping()
        mapping["targets"]["exact.test.playwright"]["selector"] = "renamed_selector"
        with self.assertRaisesRegex(ValueError, "selector is missing or ignored"):
            self.validate_copy(
                evidence_map=mapping,
                file_overrides={
                    "web/e2e/admin-users.spec.ts": self.playwright_source()
                },
            )

    def test_rejects_missing_node_exact_selector(self) -> None:
        mapping = json.loads(EVIDENCE_MAP.read_text(encoding="utf-8"))
        mapping["targets"]["exact.c8.12.durable-authority"]["selector"] = (
            "renamed_selector"
        )
        with self.assertRaisesRegex(ValueError, "selector is missing or ignored"):
            self.validate_copy(evidence_map=mapping)

    def test_rejects_commented_vitest_exact_selector(self) -> None:
        mapping = json.loads(EVIDENCE_MAP.read_text(encoding="utf-8"))
        target = mapping["targets"]["exact.c2.2b.typescript-offline-sdk"]
        source_path = str(target["path"])
        source = (REPO_ROOT / source_path).read_text(encoding="utf-8")
        source = source.replace(
            '  it("c2_2b_offline_sdk_preserves_actor_types",',
            '  // it("c2_2b_offline_sdk_preserves_actor_types",',
            1,
        )
        with self.assertRaisesRegex(ValueError, "selector is missing or ignored"):
            self.validate_copy(file_overrides={source_path: source})

    def test_rejects_sdk_selector_missing_from_exact_runner(self) -> None:
        runner_path = "scripts/run_sdk_conformance_exact_tests.sh"
        runner = (REPO_ROOT / runner_path).read_text(encoding="utf-8")
        runner = runner.replace(
            "run_pytest_exact sdk/python/tests/test_sdk.py "
            "test_c2_2b_offline_sdk_preserves_actor_types",
            "run_pytest_exact sdk/python/tests/test_sdk.py test_other_selector",
        )
        with self.assertRaisesRegex(ValueError, "not executed by its runner"):
            self.validate_copy(file_overrides={runner_path: runner})

    def test_rejects_playwright_selector_missing_from_exact_runner(self) -> None:
        mapping = self.playwright_mapping()
        with self.assertRaisesRegex(ValueError, "not executed by its runner"):
            self.validate_copy(
                evidence_map=mapping,
                file_overrides={
                    "web/e2e/admin-users.spec.ts": self.playwright_source()
                },
            )

    def test_rejects_node_selector_missing_from_exact_runner(self) -> None:
        runner_path = "scripts/run_infra_conformance_exact_tests.sh"
        runner = (REPO_ROOT / runner_path).read_text(encoding="utf-8")
        runner = runner.replace(
            "run_node_exact infra/test/conformance-attributes-config.test.js "
            "c8_12_attribute_authority_tables_are_durable_without_ttl",
            "run_node_exact infra/test/conformance-attributes-config.test.js "
            "other_selector",
        )
        with self.assertRaisesRegex(ValueError, "not executed by its runner"):
            self.validate_copy(file_overrides={runner_path: runner})

    def test_external_rust_test_module_selector_matches_cargo_path(self) -> None:
        manifest = REPO_ROOT / "crates/http/Cargo.toml"
        self.assertEqual(
            expected_library_selector(
                REPO_ROOT
                / "crates/http/src/adapters/aws/federation_attribute_mappings_tests.rs",
                manifest,
                "reconciliation_registry_condition_fences_the_exact_mapping_snapshot",
            ),
            "adapters::aws::federation_attribute_mappings_tests::"
            "reconciliation_registry_condition_fences_the_exact_mapping_snapshot",
        )
        self.assertEqual(
            expected_library_selector(
                REPO_ROOT / "crates/http/src/lib.rs",
                manifest,
                "root_selector",
            ),
            "tests::root_selector",
        )

    def test_rejects_exact_runner_not_invoked_by_ci_step(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8").replace(
            "run: ./scripts/run_conformance_exact_tests.sh",
            "run: cargo test --workspace --lib --locked",
            1,
        )
        with self.assertRaisesRegex(ValueError, "no longer runs required command"):
            self.validate_copy(workflow_text=workflow)

    def test_rejects_playwright_runner_not_invoked_by_ci_step(self) -> None:
        mapping = self.playwright_mapping()
        runner_path = "scripts/run_sdk_conformance_exact_tests.sh"
        runner = (REPO_ROOT / runner_path).read_text(encoding="utf-8")
        runner += (
            "\nrun_playwright_exact "
            "web/e2e/admin-users.spec.ts c8_12_ui_exact_selector\n"
        )
        with self.assertRaisesRegex(ValueError, "runner is not invoked by its CI step"):
            self.validate_copy(
                evidence_map=mapping,
                file_overrides={
                    "web/e2e/admin-users.spec.ts": self.playwright_source(),
                    runner_path: runner,
                },
            )

    def test_rejects_runner_using_wrong_integration_target(self) -> None:
        runner = (REPO_ROOT / "scripts" / "run_conformance_exact_tests.sh").read_text(
            encoding="utf-8"
        )
        runner = runner.replace(
            "run_exact admin_e2e "
            "saas_admin_client_create_uses_the_request_tenant_subject_profile",
            "run_exact code_flow_e2e "
            "saas_admin_client_create_uses_the_request_tenant_subject_profile",
        )
        with self.assertRaisesRegex(ValueError, "not executed by its runner"):
            self.validate_copy(
                file_overrides={"scripts/run_conformance_exact_tests.sh": runner}
            )

    def test_rejects_runner_using_wrong_library_package(self) -> None:
        runner = (REPO_ROOT / "scripts" / "run_conformance_exact_tests.sh").read_text(
            encoding="utf-8"
        )
        runner = runner.replace(
            "run_lib_exact agent-auth-token "
            "claims::tests::act_chain_nesting_rfc8693_example",
            "run_lib_exact agent-auth-http "
            "claims::tests::act_chain_nesting_rfc8693_example",
        )
        with self.assertRaisesRegex(ValueError, "not executed by its runner"):
            self.validate_copy(
                file_overrides={"scripts/run_conformance_exact_tests.sh": runner}
            )

    def test_rejects_library_target_owned_by_wrong_package(self) -> None:
        mapping = json.loads(EVIDENCE_MAP.read_text(encoding="utf-8"))
        changed = copy.deepcopy(mapping)
        changed["targets"]["exact.c2.4.nesting"]["package"] = "agent-auth-http"
        with self.assertRaisesRegex(ValueError, "package does not own source"):
            self.validate_copy(evidence_map=changed)

    def test_rejects_library_cargo_selector_that_does_not_match_source(self) -> None:
        mapping = json.loads(EVIDENCE_MAP.read_text(encoding="utf-8"))
        changed = copy.deepcopy(mapping)
        changed["targets"]["exact.c2.4.nesting"]["cargo_selector"] = (
            "claims::tests::renamed_selector"
        )
        with self.assertRaisesRegex(
            ValueError, "cargo_selector does not match source module"
        ):
            self.validate_copy(evidence_map=changed)

    def test_path_module_owner_must_mount_active_source_exactly_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            crate = Path(directory) / "crate"
            source = crate / "src"
            source.mkdir(parents=True)
            manifest = crate / "Cargo.toml"
            manifest.write_text(
                '[package]\nname = "fixture"\nversion = "0.0.0"\n',
                encoding="utf-8",
            )
            test_path = source / "nested_tests.rs"
            test_path.write_text(
                "#[test]\nfn exact_selector() {}\n",
                encoding="utf-8",
            )
            owner = source / "owner.rs"
            owner.write_text(
                '#[path = "nested_tests.rs"]\nmod nested_tests;\n',
                encoding="utf-8",
            )
            self.assertEqual(
                expected_library_selector(
                    test_path,
                    manifest,
                    "exact_selector",
                    owner,
                ),
                "owner::nested_tests::exact_selector",
            )
            owner.write_text(
                '// #[path = "nested_tests.rs"]\n// mod nested_tests;\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ValueError, "module_owner must mount the source path exactly once"
            ):
                expected_library_selector(
                    test_path,
                    manifest,
                    "exact_selector",
                    owner,
                )

    def test_rejects_library_selector_from_wrong_module_with_same_leaf(self) -> None:
        mapping = json.loads(EVIDENCE_MAP.read_text(encoding="utf-8"))
        changed = copy.deepcopy(mapping)
        selector = "other_module::tests::act_chain_nesting_rfc8693_example"
        changed["targets"]["exact.c2.4.nesting"]["cargo_selector"] = selector
        runner = (REPO_ROOT / "scripts" / "run_conformance_exact_tests.sh").read_text(
            encoding="utf-8"
        )
        runner = runner.replace(
            "claims::tests::act_chain_nesting_rfc8693_example",
            selector,
        )
        with self.assertRaisesRegex(
            ValueError, "cargo_selector does not match source module"
        ):
            self.validate_copy(
                evidence_map=changed,
                file_overrides={"scripts/run_conformance_exact_tests.sh": runner},
            )

    def test_rust_test_detection_rejects_comment_helper_and_ignore(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tests.rs"
            path.write_text(
                "// async fn exact_selector() {}\nfn exact_selector() {}\n",
                encoding="utf-8",
            )
            self.assertFalse(rust_test_is_active(path, "exact_selector"))
            path.write_text(
                "/*\n#[tokio::test]\nasync fn exact_selector() {}\n*/\n",
                encoding="utf-8",
            )
            self.assertFalse(rust_test_is_active(path, "exact_selector"))
            path.write_text(
                "#[tokio::test]\nasync fn exact_selector() {}\n",
                encoding="utf-8",
            )
            self.assertTrue(rust_test_is_active(path, "exact_selector"))
            path.write_text(
                "let quote = '\"';\n#[tokio::test]\nasync fn exact_selector() {}\n",
                encoding="utf-8",
            )
            self.assertTrue(rust_test_is_active(path, "exact_selector"))
            path.write_text(
                "#[ignore]\n#[tokio::test]\nasync fn exact_selector() {}\n",
                encoding="utf-8",
            )
            self.assertFalse(rust_test_is_active(path, "exact_selector"))
            path.write_text(
                "#[tokio::test]\nasync fn other_test() {}\n"
                "fn helper() {}\n"
                "async fn exact_selector() {}\n",
                encoding="utf-8",
            )
            self.assertFalse(rust_test_is_active(path, "exact_selector"))

    def test_rejects_unbound_recorded_live_reference(self) -> None:
        mapping = json.loads(EVIDENCE_MAP.read_text(encoding="utf-8"))
        changed = copy.deepcopy(mapping)
        changed["targets"]["live.c9.4.passkey"] = {
            "kind": "recorded_live_reference",
            "coverage_level": "recorded_reference",
            "script": "e2e/passkey_saas_isolation.sh",
            "deployment_commit": "0" * 40,
            "evidence_sha256": "0" * 64,
            "verification": "recorded_reference_only",
        }
        changed["requirements"]["9.4"]["recorded_references"] = ["live.c9.4.passkey"]
        with self.assertRaisesRegex(ValueError, "row does not name evidence script"):
            self.validate_copy(evidence_map=changed)

    def test_rejects_conditional_applicability_drift(self) -> None:
        mapping = json.loads(EVIDENCE_MAP.read_text(encoding="utf-8"))
        changed = copy.deepcopy(mapping)
        changed["requirements"]["10.15"]["applicability"] = "unconditional"
        with self.assertRaisesRegex(ValueError, "applicability drifted"):
            self.validate_copy(evidence_map=changed)

    def test_rejects_missing_applicability_basis(self) -> None:
        mapping = json.loads(EVIDENCE_MAP.read_text(encoding="utf-8"))
        changed = copy.deepcopy(mapping)
        changed["requirements"]["1.1"]["applicability_basis"] = ""
        with self.assertRaisesRegex(ValueError, "applicability_basis is required"):
            self.validate_copy(evidence_map=changed)


if __name__ == "__main__":
    unittest.main()
