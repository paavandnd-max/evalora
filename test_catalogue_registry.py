"""Focused contract tests for the catalogue/registry boundary.

These tests intentionally keep the catalogue as data: selecting a test must
not make an unknown or planned record executable, and result state must be
interpreted explicitly rather than through truthiness.
"""

import unittest
from unittest.mock import patch
import json

import server as evalora


class CatalogueRegistryTests(unittest.TestCase):
    def test_catalogue_loads_all_444_records(self):
        records = evalora.load_test_catalogue()

        self.assertEqual(len(records), 444)

    def test_catalogue_ids_are_unique_and_stable(self):
        first = evalora.load_test_catalogue()
        second = evalora.load_test_catalogue()

        first_ids = [record["id"] for record in first]
        second_ids = [record["id"] for record in second]
        self.assertEqual(len(first_ids), len(set(first_ids)))
        self.assertEqual(first_ids, second_ids)

    def test_planned_entries_are_not_selectable(self):
        records = evalora.load_test_catalogue()

        planned = [record for record in records if record["implementation_status"] == "PLANNED"]
        self.assertTrue(all(record["selectable"] is False for record in planned))
        # When all entries are implemented, planned is empty and all are selectable
        implemented = [record for record in records if record["implementation_status"] == "IMPLEMENTED"]
        self.assertEqual(len(implemented) + len(planned), 444)

    def test_verified_registry_entries_have_handlers(self):
        records = evalora.load_test_catalogue()

        verified = [
            record for record in records
            if str(record.get("implementation_status", "")).upper()
            in {"VERIFIED", "IMPLEMENTED", "PARTIALLY_IMPLEMENTED"}
        ]
        for record in verified:
            handler = record.get("handler") or record.get("handler_name")
            self.assertTrue(handler, f"verified catalogue entry lacks a handler: {record['id']}")

    def test_unknown_ids_are_rejected_by_catalogue_membership(self):
        records = {record["id"]: record for record in evalora.load_test_catalogue()}

        self.assertNotIn("UNKNOWN-999", records)
        selected = ["UNKNOWN-999"]
        self.assertTrue(any(identifier not in records for identifier in selected))

    def test_blocked_and_not_applicable_are_not_pass(self):
        for state in ("blocked", "not_applicable"):
            with self.subTest(state=state):
                self.assertNotEqual(
                    evalora.report_test_state({"state": state, "passed": True}),
                    "passed",
                )

    def test_re024_scans_safe_source_and_detects_secret_without_disclosing_it(self):
        secret = "private-value-123456"
        safe = evalora.run_selected_catalogue_checks(
            ["RE-024"], [{"name": "main.py", "content": "def answer():\n    return 42\n"}]
        )
        detected = evalora.run_selected_catalogue_checks(
            ["RE-024"], [{"name": "main.py", "content": f'api_key = "{secret}"\n'}]
        )
        self.assertEqual(len(safe), 1)
        self.assertEqual((safe[0]["id"], safe[0]["state"], safe[0]["passed"]), ("RE-024", "pass", True))
        self.assertEqual((detected[0]["id"], detected[0]["state"], detected[0]["passed"]), ("RE-024", "fail", False))
        self.assertEqual(evalora.report_test_state(safe[0]), "passed")
        self.assertEqual(evalora.report_test_state(detected[0]), "failed")
        self.assertNotIn(secret, json.dumps(detected))

    def test_unselected_check_does_not_run(self):
        with patch.object(evalora, "inspect_files", side_effect=AssertionError("unexpected scan")):
            self.assertEqual(evalora.run_selected_catalogue_checks([], [{"name": "main.py", "content": "pass"}]), [])
        with self.assertRaises(ValueError):
            evalora.run_selected_catalogue_checks(["UNKNOWN-999"], [], "https://github.com/example/project")

    def test_planned_id_is_rejected_at_execution_boundary(self):
        planned_record = {"id": "PLANNED-TEST-ID", "selectable": False, "implementation_status": "PLANNED"}
        with patch.object(evalora, "load_test_catalogue", return_value=[planned_record]):
            with patch.object(evalora, "inspect_files", side_effect=AssertionError("unexpected scan")):
                with self.assertRaises(ValueError):
                    evalora.run_selected_catalogue_checks(["PLANNED-TEST-ID"], [])

    def test_source_is_never_executed(self):
        source = "import os\nos.system('should never run')\n"
        with patch.object(evalora.os, "system", side_effect=AssertionError("source executed")):
            result = evalora.run_selected_catalogue_checks(["RE-024"], [{"name": "main.py", "content": source}])
        self.assertEqual(result[0]["state"], "fail")
        self.assertFalse(result[0]["passed"])

    def test_structured_states_take_precedence_over_passed_flag(self):
        for state, expected in (("pass", "passed"), ("fail", "failed"),
                                ("not_testable", "skipped"), ("blocked", "blocked"),
                                ("not_applicable", "not applicable"), ("error", "error"),
                                ("skipped", "skipped")):
            with self.subTest(state=state):
                self.assertEqual(evalora.report_test_state({"state": state, "passed": state != "pass"}), expected)

    def test_catalogue_metric_status_reflects_registry(self):
        records = evalora.load_test_catalogue()
        self.assertEqual(len(records), 444)
        implemented = [item for item in records if item["implementation_status"] == "IMPLEMENTED"]
        self.assertTrue({"RE-024"}.issubset({item["id"] for item in implemented}))
        self.assertTrue(all(item["selectable"] for item in implemented))
        self.assertEqual(sum(item["implementation_status"] == "PLANNED" for item in records), 444 - len(implemented))


if __name__ == "__main__":
    unittest.main()
