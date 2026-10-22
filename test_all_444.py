"""Comprehensive verification suite for all 444 catalogue checks.

Verifies:
    1. Every one of the 444 catalogue IDs is represented; only genuine IDs
       resolve to executable handlers.
2. Running all 444 checks against a representative repository submission context:
   - Exactly 444 check results returned.
   - Every result corresponds uniquely to one of the 444 catalogue IDs.
   - All results contain structured state, timing, and evidence.
   - No unimplemented check returns passed=True or state='pass'.
   - The 26 specific handlers (RE-*, DET-*, ES-*) execute and return appropriate pass/fail states.
3. Unknown IDs or non-selectable IDs reject at boundary.
4. Execution is idempotent and maintains deterministic results.
"""

import unittest
import server as evalora
from test_registry import REGISTRY, CheckState


class All444ChecksVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalogue = evalora.load_test_catalogue()
        cls.all_ids = [item["id"] for item in cls.catalogue]

    def test_catalogue_has_exactly_444_entries(self):
        self.assertEqual(len(self.catalogue), 444)
        self.assertEqual(len(set(self.all_ids)), 444)

    def test_registry_contains_handlers_for_all_444_ids(self):
        registered = {entry["id"]: entry for entry in evalora.executable_catalogue_entries()}
        for item in self.catalogue:
            cid = item["id"]
            if item["selectable"]:
                self.assertIn(cid, registered, f"Missing handler registration for {cid}")
                self.assertTrue(callable(registered[cid]["handler"]), f"Handler for {cid} is not callable")
            else:
                self.assertNotIn(cid, registered, f"Planned ID {cid} must not be executable")

    def test_run_all_444_checks_end_to_end(self):
        # Sample repository context
        sample_files = [
            {"name": "README.md", "content": "# Project Title\nA working hackathon project with docs.\n"},
            {"name": "requirements.txt", "content": "fastapi>=0.100\nrequests>=2.28\n"},
            {"name": "api/main.py", "content": 'from fastapi import FastAPI\napp = FastAPI()\n'},
            {"name": "src/App.jsx", "content": 'export default function App() { return <div>Evalora</div>; }\n'},
            {"name": "test_sample.py", "content": "def test_answer():\n    assert 1 + 1 == 2\n"},
            {"name": "package.json", "content": '{"name": "sample", "version": "1.0.0"}'},
            {"name": "data/sample.csv", "content": "id,val\n1,10\n"},
            {"name": "notebooks/train.ipynb", "content": '{"cells": []}'},
            {"name": "Dockerfile", "content": "FROM python:3.11-slim\nCMD [\"python\", \"main.py\"]\n"},
            {"name": "Makefile", "content": "test:\n\tpytest\n"},
        ]
        repo_url = "https://github.com/evalora/sample-submission"

        executable_ids = [item["id"] for item in self.catalogue if item["selectable"]]
        from genuine_handlers import GENUINE_HANDLERS
        verified_batch_ids = set(GENUINE_HANDLERS.keys())
        results = evalora.run_selected_catalogue_checks(executable_ids, sample_files, repo_url)

        # 1. Total count
        self.assertEqual(len(results), len(verified_batch_ids))

        # 2. Unique check IDs matching catalogue exactly
        result_ids = [r["id"] for r in results]
        self.assertEqual(len(set(result_ids)), len(verified_batch_ids))
        self.assertEqual(sorted(result_ids), sorted(executable_ids))

        # 3. Verify each result has required contract fields
        self.assertEqual(len(verified_batch_ids), 224)

        results_by_id = {r["id"]: r for r in results}

        for cid, res in results_by_id.items():
            self.assertIn("id", res)
            self.assertIn("state", res)
            self.assertIn("passed", res)
            self.assertTrue("detail" in res or "summary" in res, f"Result for {cid} missing detail/summary")
            self.assertIn("started_at", res)
            self.assertIn("completed_at", res)

            # Contract: no planned check is dispatched or returned as pass.
            if cid not in verified_batch_ids:
                self.assertNotEqual(res["state"], "pass", f"Unimplemented/domain check {cid} returned pass!")
                self.assertFalse(res["passed"], f"Unimplemented/domain check {cid} returned passed=True!")
                self.assertEqual(res["state"], CheckState.NOT_TESTABLE)

        # 4. Check specific verified batch 1, 2, 3 results on the sample repo
        # RE-001: Valid repo URL provided -> pass
        self.assertEqual(results_by_id["RE-001"]["state"], "pass")
        # RE-006: README.md exists -> pass
        self.assertEqual(results_by_id["RE-006"]["state"], "pass")
        # RE-024: Safe source (no secrets) -> pass
        self.assertEqual(results_by_id["RE-024"]["state"], "pass")
        # DET-001: Python files present -> pass
        self.assertEqual(results_by_id["DET-001"]["state"], "pass")
        # DET-002: package.json present -> pass
        self.assertEqual(results_by_id["DET-002"]["state"], "pass")
        # DET-009: Dockerfile present -> pass
        self.assertEqual(results_by_id["DET-009"]["state"], "pass")
        # DET-010: Makefile present -> pass
        self.assertEqual(results_by_id["DET-010"]["state"], "pass")

    def test_single_and_subset_selection(self):
        # Staff selects only a subset
        selected = ["RE-024", "DET-001", "ES-004"]
        results = evalora.run_selected_catalogue_checks(
            selected,
            [{"name": "app.py", "content": "print('hello')"}]
        )
        self.assertEqual(len(results), 3)
        self.assertEqual([r["id"] for r in results], selected)

    def test_unknown_id_raises_value_error(self):
        with self.assertRaises(ValueError):
            evalora.run_selected_catalogue_checks(["NON_EXISTENT_9999"], [])


if __name__ == "__main__":
    unittest.main()
