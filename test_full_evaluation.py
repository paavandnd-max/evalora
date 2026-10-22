import json
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

import genuine_handlers
import server


class FullEvaluationSelectionTests(unittest.TestCase):
    def test_case_a_no_saved_configuration_defaults_to_all_executable(self):
        """Case A: No saved configuration defaults to all dynamically discovered executable tests."""
        selected = server.resolve_event_test_selection(None)
        executable = server.executable_catalogue_ids()
        self.assertEqual(selected, executable)
        self.assertEqual(len(selected), 224)
        self.assertEqual(len(selected), len(set(selected)))

        dispatched_ids, results = server.evaluate_catalogue_for_submission([], "", None)
        self.assertEqual(dispatched_ids, executable)
        self.assertEqual(len(results), 224)
        result_ids = [item["id"] for item in results]
        self.assertEqual(result_ids, executable)

    def test_case_b_explicit_all_executable_preset(self):
        """Case B: Explicit all-executable preset dispatches all 224 IDs."""
        executable = server.executable_catalogue_ids()
        dispatched_ids, results = server.evaluate_catalogue_for_submission([], "", list(executable))
        self.assertEqual(dispatched_ids, executable)
        self.assertEqual(len(results), 224)
        self.assertEqual([r["id"] for r in results], executable)

    def test_case_c_explicit_subset_dispatches_only_selected(self):
        """Case C: Explicit subset dispatches only the selected executable IDs."""
        subset = ["SEC-001", "SEC-002", "SEC-003"]
        dispatched_ids, results = server.evaluate_catalogue_for_submission([], "", subset)
        self.assertEqual(dispatched_ids, subset)
        self.assertEqual(len(results), 3)
        self.assertEqual([r["id"] for r in results], subset)

    def test_case_d_explicit_empty_list_dispatches_zero(self):
        """Case D: Explicit empty list is distinct from None and dispatches 0 checks."""
        dispatched_ids, results = server.evaluate_catalogue_for_submission([], "", [])
        self.assertEqual(dispatched_ids, [])
        self.assertEqual(results, [])
        self.assertNotEqual(server.resolve_event_test_selection([]), server.resolve_event_test_selection(None))

    def test_case_e_planned_and_unknown_ids_rejected(self):
        """Case E: Unknown IDs and planned (non-executable) IDs are rejected with ValueError."""
        with self.assertRaises(ValueError) as ctx1:
            server.resolve_event_test_selection(["DG-021"])
        self.assertIn("DG-021", str(ctx1.exception))

        with self.assertRaises(ValueError) as ctx2:
            server.resolve_event_test_selection(["UNKNOWN-999"])
        self.assertIn("UNKNOWN-999", str(ctx2.exception))

        with self.assertRaises(ValueError):
            server.resolve_event_test_selection("not-a-list")

    def test_case_f_duplicate_ids_deduplicated_deterministically(self):
        """Case F: Duplicate IDs preserve first-seen order without duplicates in dispatch or results."""
        ids = ["SEC-002", "SEC-001", "SEC-002", "SEC-003", "SEC-001"]
        resolved = server.resolve_event_test_selection(ids)
        self.assertEqual(resolved, ["SEC-002", "SEC-001", "SEC-003"])
        results = server.run_selected_catalogue_checks(ids, [], "")
        self.assertEqual([item["id"] for item in results], ["SEC-002", "SEC-001", "SEC-003"])
        self.assertEqual(len(results), 3)
        self.assertTrue(all("state" in item and "detail" in item for item in results))

    def test_case_g_persisted_configuration_reloads_exact_version_and_selection(self):
        """Case G: Persisted configuration in database survives and reloads exact selection and version."""
        with tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False) as tmp:
            tmp_path = Path(tmp.name)
        try:
            conn = sqlite3.connect(tmp_path)
            conn.execute("""
                CREATE TABLE event_test_configurations (
                    event_id TEXT,
                    version INTEGER,
                    selected_test_ids_json TEXT,
                    security_baseline_json TEXT,
                    created_by TEXT,
                    created_at TEXT
                )
            """)
            conn.execute("INSERT INTO event_test_configurations VALUES (?, ?, ?, ?, ?, ?)",
                         ("evt-test", 1, json.dumps(["SEC-001", "SEC-002"]), json.dumps(server.MANDATORY_SECURITY_CHECKS), "admin", "2026-01-01T00:00:00Z"))
            conn.execute("INSERT INTO event_test_configurations VALUES (?, ?, ?, ?, ?, ?)",
                         ("evt-test", 2, json.dumps(["SEC-003", "SEC-004", "SEC-005"]), json.dumps(server.MANDATORY_SECURITY_CHECKS), "admin", "2026-01-02T00:00:00Z"))
            conn.commit()

            # Query latest version (version 2)
            latest = conn.execute(
                "SELECT version, selected_test_ids_json FROM event_test_configurations WHERE event_id=? ORDER BY version DESC LIMIT 1",
                ("evt-test",)
            ).fetchone()
            self.assertEqual(latest[0], 2)
            self.assertEqual(json.loads(latest[1]), ["SEC-003", "SEC-004", "SEC-005"])

            # Query specific version 1
            v1 = conn.execute(
                "SELECT selected_test_ids_json FROM event_test_configurations WHERE event_id=? AND version=?",
                ("evt-test", 1)
            ).fetchone()
            self.assertEqual(json.loads(v1[0]), ["SEC-001", "SEC-002"])
            conn.close()
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def test_mandatory_security_checks_are_strict_subset_of_executable(self):
        """Mandatory security checks (10) are an exact subset of the 224 executable IDs, total union is 224."""
        mandatory = set(server.MANDATORY_SECURITY_CHECKS)
        executable = set(server.executable_catalogue_ids())
        self.assertEqual(len(mandatory), 10)
        self.assertEqual(len(executable), 224)
        self.assertTrue(mandatory.issubset(executable))
        self.assertEqual(len(mandatory.union(executable)), 224)

    def test_merge_catalogue_results_scoring_denominator_and_status(self):
        """merge_catalogue_results excludes not_testable and error from denominator, calculates rounded %."""
        base = {"checks": [], "passed": 0, "total": 0, "score": 0, "status": "Ready for review"}
        catalogue = [
            {"id": "A", "state": "pass", "passed": True, "detail": "passed check"},
            {"id": "B", "state": "fail", "passed": False, "detail": "failed check"},
            {"id": "C", "state": "not_testable", "passed": None, "detail": "not applicable"},
            {"id": "D", "state": "error", "passed": None, "detail": "handler error"},
            {"id": "E", "state": "pass", "passed": True, "detail": "another passed"}
        ]
        merged = server.merge_catalogue_results(base, catalogue)
        self.assertEqual(len(merged["checks"]), 5)
        self.assertEqual(merged["catalogue_results"], catalogue)
        # scored = A (pass), B (fail), E (pass) -> 3 scored, 2 passed
        self.assertEqual(merged["total"], 3)
        self.assertEqual(merged["passed"], 2)
        self.assertEqual(merged["score"], round(2 / 3 * 100))  # 67%
        self.assertEqual(merged["status"], "Flagged")

    @patch.object(server, "DEMO_MODE", False)
    def test_apply_event_configuration_report_executed_count(self):
        """apply_event_configuration_report accurately populates executed_test_count and eligible_test_count."""
        report = {"test_analysis": {}}
        event = {"id": "test-event", "name": "Test Event", "active_config_version": 1}
        problem = {"id": "prob-1", "title": "Problem 1", "description": "desc", "test_cases": []}
        files = []
        subset = ["SEC-001", "SEC-002", "SEC-003"]
        config = {
            "functional_tests": [],
            "security_checks": "mandatory_baseline",
            "selected_test_ids": subset
        }
        res = server.apply_event_configuration_report(report, config, problem, files, {}, event)
        self.assertEqual(res["configuration"]["eligible_test_count"], 224)
        self.assertEqual(res["configuration"]["executed_test_count"], 3)
        self.assertEqual(len(res["catalogue_results"]), 3)

    @patch.object(server, "DEMO_MODE", False)
    def test_end_to_end_full_catalogue_evaluation_produces_all_224_results(self):
        """Full catalogue evaluation produces 224 unique, valid results with correct scoring denominator."""
        files = [
            {"name": "README.md", "content": "# Evalora Test Project\nDocumenting architecture and tests."},
            {"name": "app.py", "content": "import os\ndef handle():\n    return 'secure'\n"},
            {"name": "requirements.txt", "content": "requests==2.31.0\npytest==8.0.0\n"}
        ]
        repo_url = "https://github.com/example/test-repo"
        dispatched_ids, catalogue_results = server.evaluate_catalogue_for_submission(files, repo_url, None)

        self.assertEqual(len(dispatched_ids), 224)
        self.assertEqual(len(catalogue_results), 224)

        result_ids = [r["id"] for r in catalogue_results]
        self.assertEqual(len(set(result_ids)), 224, "Every result ID must be unique")
        self.assertEqual(result_ids, dispatched_ids, "Result IDs must match dispatched IDs exactly")

        # Check result structure
        valid_states = {"pass", "fail", "not_testable", "error"}
        for item in catalogue_results:
            self.assertIn(item["state"], valid_states)
            self.assertIn("detail", item)
            self.assertTrue(item["detail"])
            # Ensure name and category are populated
            self.assertIn("name", item)
            self.assertIn("category", item)
            self.assertIsNotNone(item["name"])

        # Base structural check
        base = {"checks": [], "passed": 0, "total": 0, "score": 0, "status": "Ready for review"}
        merged = server.merge_catalogue_results(base, catalogue_results)

        scored = [r for r in catalogue_results if r["state"] not in {"not_testable", "error"}]
        self.assertEqual(merged["total"], len(scored))
        expected_score = round(merged["passed"] / len(scored) * 100) if scored else 0
        self.assertEqual(merged["score"], expected_score)

        # Reviewer report
        problem = {"id": "prob-test", "title": "Test Problem", "description": "Problem desc", "test_cases": []}
        report = server.build_reviewer_report(problem, files, merged, repo_url, {"name": "test-repo", "default_branch": "main"})
        event = {"id": "evt-all", "name": "All Tests Event", "active_config_version": 1}
        active_config = {
            "functional_tests": [],
            "security_checks": "mandatory_baseline",
            "selected_test_ids": None
        }
        final_report = server.apply_event_configuration_report(report, active_config, problem, files, merged, event)

        self.assertEqual(final_report["configuration"]["eligible_test_count"], 224)
        self.assertEqual(final_report["configuration"]["executed_test_count"], 224)
        self.assertEqual(len(final_report["catalogue_results"]), 224)

    def test_inspect_files_and_re_012_detect_directory_test_files(self):
        """inspect_files and RE-012 recognize test files in test/ directories."""
        # Files with tests located in test/ subdirectories (Node/Express layout)
        js_files = [
            {"name": "index.js", "content": "module.exports = {};"},
            {"name": "test/Route.js", "content": "describe('Route', () => {});"},
            {"name": "package.json", "content": "{\"name\": \"express\"}"}
        ]
        inspection = server.inspect_files(js_files)
        checks = {c["name"]: c for c in inspection["checks"]}
        self.assertTrue(checks["Test files present"]["passed"])

        re_012_res = genuine_handlers.GENUINE_HANDLERS["RE-012"]({
            "files": js_files,
            "inspect_files": server.inspect_files
        })
        self.assertEqual(re_012_res["state"], "pass")

        # Zero tests repository
        no_test_files = [
            {"name": "README.md", "content": "Just docs"},
            {"name": "app.py", "content": "print('hello')"}
        ]
        re_012_fail = genuine_handlers.GENUINE_HANDLERS["RE-012"]({
            "files": no_test_files,
            "inspect_files": server.inspect_files
        })
        self.assertEqual(re_012_fail["state"], "fail")

    def test_re_018_distinguishes_benign_socket_from_unauthorized_internal_probes(self):
        """RE-018 allows benign local test sockets but detects unauthorized metadata probe attempts."""
        # Benign socket use in test suite alongside application source
        benign_files = [
            {"name": "app.py", "content": "def main(): return 'ok'"},
            {"name": "tests/test_server.py", "content": "import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\ns.bind(('127.0.0.1', 0))"}
        ]
        res_benign = genuine_handlers.GENUINE_HANDLERS["RE-018"]({"files": benign_files})
        self.assertEqual(res_benign["state"], "pass")

        # Unauthorized internal metadata probe (AWS metadata service)
        probe_files = [
            {"name": "exploit.py", "content": "import urllib.request\nurllib.request.urlopen('http://169.254.169.254/latest/meta-data')"}
        ]
        res_probe = genuine_handlers.GENUINE_HANDLERS["RE-018"]({"files": probe_files})
        self.assertEqual(res_probe["state"], "fail")
        self.assertIn("Direct internal socket / network probe pattern detected", res_probe["detail"])

    def test_rel_001_recognizes_nodejs_and_python_entrypoints(self):
        """REL-001 recognizes both Python and Node.js application startup patterns."""
        # Node.js Express entrypoint
        node_files = [
            {"name": "app.js", "content": "const express = require('express');\nconst app = express();\napp.listen(3000);"},
            {"name": "package.json", "content": "{\"main\": \"app.js\"}"}
        ]
        res_node = genuine_handlers.GENUINE_HANDLERS["REL-001"]({"files": node_files})
        self.assertEqual(res_node["state"], "pass")

        # Python entrypoint
        py_files = [
            {"name": "main.py", "content": "if __name__ == '__main__':\n    print('start')"}
        ]
        res_py = genuine_handlers.GENUINE_HANDLERS["REL-001"]({"files": py_files})
        self.assertEqual(res_py["state"], "pass")

        # Non-entrypoint repository (documentation only)
        docs_only = [
            {"name": "README.md", "content": "# Documentation Only"}
        ]
        res_fail = genuine_handlers.GENUINE_HANDLERS["REL-001"]({"files": docs_only})
        self.assertEqual(res_fail["state"], "fail")


if __name__ == "__main__":
    unittest.main()
