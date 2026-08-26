import copy
import json
import tempfile
import unittest
from pathlib import Path

from scripts.conformance_inventory import validate_inventory

REPO_ROOT = Path(__file__).resolve().parents[2]

DOCUMENT = REPO_ROOT / "docs" / "CONFORMANCE.md"
INVENTORY = REPO_ROOT / ".github" / "conformance" / "requirements.json"


class ConformanceInventoryTests(unittest.TestCase):
    def validate_copy(
        self,
        *,
        document_text: str | None = None,
        inventory: dict | None = None,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            document = root / "CONFORMANCE.md"
            inventory_path = root / "requirements.json"
            document.write_text(
                document_text
                if document_text is not None
                else DOCUMENT.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            inventory_path.write_text(
                json.dumps(
                    inventory
                    if inventory is not None
                    else json.loads(INVENTORY.read_text(encoding="utf-8"))
                ),
                encoding="utf-8",
            )
            validate_inventory(document, inventory_path)

    def test_repository_inventory_matches_document(self) -> None:
        counts, incomplete = validate_inventory(DOCUMENT, INVENTORY)

        self.assertEqual(
            counts,
            {"total": 149, "complete": 144, "partial": 2, "missing": 3},
        )
        self.assertEqual(len(incomplete), 5)

    def test_rejects_status_and_count_drift(self) -> None:
        document = DOCUMENT.read_text(encoding="utf-8").replace(
            "| ◑ | 10.22b |",
            "| ☑ | 10.22b |",
            1,
        )

        with self.assertRaisesRegex(ValueError, "inventory counts drifted"):
            self.validate_copy(document_text=document)

    def test_rejects_human_summary_drift(self) -> None:
        document = DOCUMENT.read_text(encoding="utf-8").replace(
            "total=149",
            "total=150",
            1,
        )

        with self.assertRaisesRegex(ValueError, "human summary counts drifted"):
            self.validate_copy(document_text=document)

    def test_rejects_unclassified_incomplete_requirement(self) -> None:
        inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
        inventory["incomplete_requirements"] = [
            entry
            for entry in inventory["incomplete_requirements"]
            if entry["id"] != "12.2"
        ]

        with self.assertRaisesRegex(
            ValueError,
            "classifications do not match",
        ):
            self.validate_copy(inventory=inventory)

    def test_rejects_duplicate_requirement_id(self) -> None:
        document = DOCUMENT.read_text(encoding="utf-8")
        duplicate = next(
            line for line in document.splitlines() if line.startswith("| ☑ | 1.1 |")
        )
        document = f"{document}\n{duplicate}\n"

        with self.assertRaisesRegex(ValueError, "duplicate conformance"):
            self.validate_copy(document_text=document)

    def test_rejects_duplicate_inventory_json_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            document = root / "CONFORMANCE.md"
            inventory_path = root / "requirements.json"
            document.write_text(
                DOCUMENT.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            inventory_text = INVENTORY.read_text(encoding="utf-8").replace(
                '  "schema_version": 1,',
                '  "schema_version": 1,\n  "schema_version": 1,',
                1,
            )
            inventory_path.write_text(inventory_text, encoding="utf-8")

            with self.assertRaisesRegex(
                ValueError,
                "duplicate JSON key: schema_version",
            ):
                validate_inventory(document, inventory_path)

    def test_rejects_complete_requirement_id_drift(self) -> None:
        document = DOCUMENT.read_text(encoding="utf-8").replace(
            "| ☑ | 1.1 |",
            "| ☑ | 1.1-renamed |",
            1,
        )

        with self.assertRaisesRegex(ValueError, "id digest drifted"):
            self.validate_copy(document_text=document)

    def test_unconditional_must_cannot_be_not_applicable(self) -> None:
        inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
        changed = copy.deepcopy(inventory)
        changed["expected_counts"] = {
            "total": 149,
            "complete": 143,
            "partial": 3,
            "missing": 3,
        }
        changed["incomplete_requirements"].append(
            {
                "id": "1.1",
                "status": "partial",
                "applicability": "not_applicable",
                "classification": "disabled_not_applicable",
                "tracking_issues": [],
                "reason": "Test fixture for unconditional applicability validation.",
            }
        )
        document = (
            DOCUMENT.read_text(encoding="utf-8")
            .replace(
                "total=149，☑=144，◑=2，☐=3",
                "total=149，☑=143，◑=3，☐=3",
                1,
            )
            .replace(
                "| ☑ | 1.1 |",
                "| ◑ | 1.1 |",
                1,
            )
        )

        with self.assertRaisesRegex(ValueError, "cannot be not applicable"):
            self.validate_copy(document_text=document, inventory=changed)

    def test_applicable_gap_requires_tracking_issue(self) -> None:
        inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
        changed = copy.deepcopy(inventory)
        requirement = next(
            entry
            for entry in changed["incomplete_requirements"]
            if entry["id"] == "12.2"
        )
        requirement["tracking_issues"] = []

        with self.assertRaisesRegex(ValueError, "needs a tracking issue"):
            self.validate_copy(inventory=changed)


if __name__ == "__main__":
    unittest.main()
