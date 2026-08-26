import importlib.util
import json
import pathlib
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "governance_restore_cutover_verify.py"
SPEC = importlib.util.spec_from_file_location("restore_verifier", SCRIPT)
restore_verifier = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(restore_verifier)

KEY = b"k" * 48
TENANT = "t1"
USER_ID = "user-1"


def string(value):
    return {"S": value}


def number(value):
    return {"N": str(value)}


def scan(items):
    return {"Items": items, "Count": len(items), "ScannedCount": len(items)}


def lifecycle(state="active", tenant=TENANT):
    record = {
        "tenant_id": tenant,
        "state": state,
        "revision": 1,
        "updated_at": 10,
    }
    return {
        "pk": string(tenant),
        "sk": string("LIFECYCLE"),
        "record_type": string("tenant_lifecycle"),
        "record": string(json.dumps(record, separators=(",", ":"))),
    }


def suppression(target_class, alias_kind, value, epoch=1, key_version=1):
    digest = restore_verifier._suppression_digest(
        KEY, TENANT, target_class, alias_kind, 1, value
    )
    pk = f"{TENANT}\x1f{target_class}\x1f{digest}"
    record = {
        "tenant_id": TENANT,
        "target_class": target_class,
        "key_version": key_version,
        "normalization_version": 1,
        "digest": digest,
        "target_epoch": epoch,
        "created_at": 10,
    }
    return [
        {
            "pk": string(pk),
            "epoch": number(0),
            "record_type": string("suppression_head"),
        },
        {
            "pk": string(pk),
            "epoch": number(epoch),
            "record": string(json.dumps(record, separators=(",", ":"))),
        },
    ]


def canonical_user():
    return {
        "user_id": string(f"{TENANT}\x1f{USER_ID}"),
        "email": string(f"{TENANT}\x1fuser@example.com"),
        "scim_external_id": string("external-1"),
        "scim_user_name": string("user@example.com"),
    }


class RestoreVerifierTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def write_case(
        self,
        *,
        governance=None,
        suppressions=None,
        role_items=None,
        tenants=None,
    ):
        governance_path = self.root / "governance.json"
        suppression_path = self.root / "suppression.json"
        governance_path.write_text(
            json.dumps(scan(governance if governance is not None else [lifecycle()])),
            encoding="utf-8",
        )
        suppression_path.write_text(
            json.dumps(scan(suppressions or [])), encoding="utf-8"
        )
        role_items = role_items or {"users": [canonical_user()]}
        restored = {}
        for role in restore_verifier.REQUIRED_ROLES:
            path = self.root / f"{role}.json"
            path.write_text(
                json.dumps(scan(role_items.get(role, []))), encoding="utf-8"
            )
            restored[role] = path.name
        manifest = {
            "schema_version": 1,
            "tenants": [TENANT] if tenants is None else tenants,
            "governance_scan": governance_path.name,
            "suppression_scan": suppression_path.name,
            "restored_scans": restored,
        }
        manifest_path = self.root / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return manifest_path

    def verify(self, manifest):
        return restore_verifier._verify(manifest, {1: KEY})

    def test_clean_candidate_passes_with_referential_integrity(self):
        manifest = self.write_case(
            role_items={
                "users": [canonical_user()],
                "passkeys": [
                    {
                        "credential_id": string(f"{TENANT}\x1fcredential-1"),
                        "user_id": string(f"{TENANT}\x1f{USER_ID}"),
                    }
                ],
                "password_credentials": [{"user_id": string(f"{TENANT}\x1f{USER_ID}")}],
                "grants": [
                    {
                        "grant_id": string(f"{TENANT}\x1fgrant-1"),
                        "user_id": string(f"{TENANT}\x1f{USER_ID}"),
                        "grant_json": string(
                            json.dumps({"grant_id": "grant-1", "user_id": USER_ID})
                        ),
                    }
                ],
                "scim_groups": [
                    {
                        "pk": string(f"{TENANT}\x1fscim-group:group-1"),
                        "members": {"L": [string(USER_ID)]},
                    }
                ],
            }
        )

        evidence = self.verify(manifest)

        self.assertEqual(evidence["result"], "passed")
        self.assertEqual(evidence["users_checked"], 1)
        self.assertEqual(evidence["user_references_checked"], 1)

    def test_canonical_or_alias_suppression_rejects_restored_user(self):
        for alias_kind, value in (
            ("canonical_id", USER_ID),
            ("email", "user@example.com"),
            ("scim_external_id", "external-1"),
            ("scim_user_name", "user@example.com"),
        ):
            with self.subTest(alias_kind=alias_kind):
                manifest = self.write_case(
                    suppressions=suppression("user", alias_kind, value)
                )
                with self.assertRaisesRegex(
                    restore_verifier.VerificationError,
                    "erased user remains",
                ):
                    self.verify(manifest)

    def test_tenant_suppression_or_lifecycle_rejects_live_authority(self):
        cases = (
            ([lifecycle()], suppression("tenant", "tenant_id", TENANT)),
            ([lifecycle("offboarding")], []),
        )
        for governance, suppressions in cases:
            with self.subTest(governance=governance, suppressions=suppressions):
                manifest = self.write_case(
                    governance=governance,
                    suppressions=suppressions,
                )
                with self.assertRaisesRegex(
                    restore_verifier.VerificationError,
                    "offboarded tenant remains",
                ):
                    self.verify(manifest)

    def test_retained_audit_and_offboarded_key_control_record_are_allowed(self):
        key_record = {
            "tenant_id": TENANT,
            "lifecycle": "offboarded",
            "served_snapshot": None,
            "operation": None,
            "pending_deletion_arns": [],
            "scheduled_deletion_arns": ["arn:pending"],
            "offboarding_operation_id": "offboard-1",
        }
        manifest = self.write_case(
            suppressions=suppression("tenant", "tenant_id", TENANT),
            role_items={
                "security_events": [
                    {
                        "event_id": string("event-1"),
                        "tenant_id": string(TENANT),
                    }
                ],
                "tenant_keys": [
                    {
                        "tenant_id": string(TENANT),
                        "record_json": string(json.dumps(key_record)),
                    }
                ],
            },
        )

        evidence = self.verify(manifest)

        self.assertEqual(evidence["blocked_tenants_checked"], 1)

    def test_platform_security_event_is_retained_non_authority(self):
        manifest = self.write_case(
            role_items={
                "security_events": [
                    {
                        "event_id": string("platform-event-1"),
                        "tenant_id": string("platform"),
                    }
                ],
            },
        )

        evidence = self.verify(manifest)

        self.assertEqual(evidence["blocked_tenants_checked"], 0)
        self.assertEqual(evidence["restored_items_checked"]["security_events"], 1)

    def test_malformed_retained_security_event_fails_closed(self):
        malformed_events = (
            {"tenant_id": string(TENANT)},
            {"event_id": string("event-1")},
            {"event_id": string(""), "tenant_id": string(TENANT)},
            {"event_id": string("event-1"), "tenant_id": string("")},
            {"event_id": string("bad event"), "tenant_id": string(TENANT)},
            {"event_id": string("event-1"), "tenant_id": string("bad/tenant")},
            {"event_id": string("e" * 65), "tenant_id": string(TENANT)},
            {"event_id": string("event-1"), "tenant_id": string("t" * 64)},
            {"event_id": string("event-\N{SNOWMAN}"), "tenant_id": string(TENANT)},
        )
        for event in malformed_events:
            with self.subTest(event=event):
                manifest = self.write_case(role_items={"security_events": [event]})
                with self.assertRaisesRegex(
                    restore_verifier.VerificationError,
                    "malformed retained audit event",
                ):
                    self.verify(manifest)

    def test_incomplete_offboarded_key_control_record_is_live_authority(self):
        base = {
            "tenant_id": TENANT,
            "lifecycle": "offboarded",
            "served_snapshot": None,
            "operation": None,
            "pending_deletion_arns": [],
            "offboarding_operation_id": "offboard-1",
        }
        invalid_records = [
            {key: value for key, value in base.items() if key != "tenant_id"},
            {**base, "last_failure": {"error_class": "kms"}},
            {**base, "pending_deletion_arns": ["arn:pending"]},
            {**base, "offboarding_operation_id": ""},
            {
                key: value
                for key, value in base.items()
                if key != "offboarding_operation_id"
            },
        ]
        for key_record in invalid_records:
            with self.subTest(key_record=key_record):
                manifest = self.write_case(
                    suppressions=suppression("tenant", "tenant_id", TENANT),
                    role_items={
                        "tenant_keys": [
                            {
                                "tenant_id": string(TENANT),
                                "record_json": string(json.dumps(key_record)),
                            }
                        ]
                    },
                )
                with self.assertRaisesRegex(
                    restore_verifier.VerificationError,
                    "offboarded tenant remains",
                ):
                    self.verify(manifest)

    def test_dangling_user_reference_fails_closed(self):
        manifest = self.write_case(
            role_items={
                "passkeys": [
                    {
                        "credential_id": string(f"{TENANT}\x1fcredential-1"),
                        "user_id": string(f"{TENANT}\x1fmissing-user"),
                    }
                ]
            }
        )

        with self.assertRaisesRegex(
            restore_verifier.VerificationError,
            "dangling user references",
        ):
            self.verify(manifest)

    def test_offboarded_tenant_rejection_precedes_unrelated_dangling_reference(self):
        manifest = self.write_case(
            tenants=[TENANT, "t2"],
            governance=[lifecycle(), lifecycle("offboarding", "t2")],
            role_items={
                "users": [canonical_user()],
                "grants": [
                    {
                        "grant_id": string(f"{TENANT}\x1fgrant-1"),
                        "user_id": string(f"{TENANT}\x1fmissing-user"),
                        "grant_json": string(
                            json.dumps(
                                {"grant_id": "grant-1", "user_id": "missing-user"}
                            )
                        ),
                    }
                ],
                "clients": [{"client_id": string("t2\x1fclient-1")}],
            },
        )

        with self.assertRaisesRegex(
            restore_verifier.VerificationError,
            "offboarded tenant remains",
        ):
            self.verify(manifest)

    def test_unknown_suppression_key_version_fails_closed(self):
        manifest = self.write_case(
            suppressions=suppression("user", "canonical_id", USER_ID, key_version=2)
        )

        with self.assertRaisesRegex(
            restore_verifier.VerificationError,
            "cannot be verified",
        ):
            self.verify(manifest)

    def test_unknown_restored_tenant_fails_closed(self):
        manifest = self.write_case(
            role_items={
                "clients": [{"client_id": string("removed-tenant\x1fclient-1")}]
            }
        )

        with self.assertRaisesRegex(
            restore_verifier.VerificationError,
            "unknown tenant prefix",
        ):
            self.verify(manifest)

    def test_lifecycle_cannot_introduce_a_trusted_tenant(self):
        manifest = self.write_case(
            governance=[lifecycle(), lifecycle(tenant="rogue-tenant")]
        )

        with self.assertRaisesRegex(
            restore_verifier.VerificationError,
            "tenant lifecycle authority is malformed",
        ):
            self.verify(manifest)

    def test_lifecycle_requires_the_runtime_sort_key(self):
        malformed = lifecycle()
        malformed["sk"] = string("tenant-lifecycle")
        manifest = self.write_case(governance=[malformed])

        with self.assertRaisesRegex(
            restore_verifier.VerificationError,
            "tenant lifecycle authority is malformed",
        ):
            self.verify(manifest)

    def test_mixed_tenant_identifiers_fail_closed(self):
        manifest = self.write_case(
            role_items={
                "users": [canonical_user()],
                "domain_map": [
                    {
                        "tenant_id": string(TENANT),
                        "client_id": string("rogue-tenant\x1fclient-1"),
                    }
                ],
            }
        )

        with self.assertRaisesRegex(
            restore_verifier.VerificationError,
            "unknown tenant prefix",
        ):
            self.verify(manifest)

    def test_admin_transient_and_unknown_rows_fail_closed(self):
        rows = (
            {
                "key": string("flow#opaque"),
                "tenant_id": string(TENANT),
                "record_type": string("flow"),
            },
            {
                "key": string("session#opaque"),
                "tenant_id": string(TENANT),
                "record_type": string("session"),
            },
            {
                "key": string(f"config#{TENANT}"),
                "tenant_id": string(TENANT),
                "record_type": string("future_type"),
            },
        )
        for row in rows:
            with self.subTest(row=row):
                manifest = self.write_case(
                    role_items={
                        "users": [canonical_user()],
                        "admin_auth": [row],
                    }
                )
                with self.assertRaisesRegex(
                    restore_verifier.VerificationError,
                    "transient or unknown authority",
                ):
                    self.verify(manifest)

    def test_incomplete_scan_is_rejected(self):
        manifest = self.write_case()
        users = self.root / "users.json"
        value = json.loads(users.read_text(encoding="utf-8"))
        value["LastEvaluatedKey"] = {"user_id": string("next")}
        users.write_text(json.dumps(value), encoding="utf-8")

        with self.assertRaisesRegex(
            restore_verifier.VerificationError,
            "incomplete DynamoDB scan",
        ):
            self.verify(manifest)


if __name__ == "__main__":
    unittest.main()
