import unittest
import json
import uuid
import hashlib
import zipfile
from io import BytesIO
import tempfile
import time
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock
import server


class TestRealTelemetryPipeline(unittest.TestCase):
    def setUp(self):
        server.DEMO_MODE = True
        server.load_demo_database()

    def test_01_artifact_checksum_and_source_revision(self):
        """Verify SHA-256 checksum and revision are computed from submitted files."""
        files = [
            {"name": "solution.py", "content": "def add(a, b):\n    return a + b\n"},
            {"name": "test_solution.py", "content": "import unittest\nfrom solution import add\nclass TestAdd(unittest.TestCase):\n    def test_add(self):\n        self.assertEqual(add(1, 2), 3)\n"}
        ]
        repo_url = "https://github.com/real-team/real-repo"
        metadata = {"commit_sha": "a1b2c3d4e5f6789012345678901234567890abcd"}
        
        res = server.run_telemetry_evaluation_pipeline(
            files=files,
            problem={"id": "test-prob", "title": "Test Problem"},
            repository_url=repo_url,
            metadata=metadata
        )
        
        self.assertEqual(res["source_revision"], "a1b2c3d4e5f6789012345678901234567890abcd")
        self.assertEqual(len(res["artifact_checksum"]), 64)  # SHA-256 hex string
        self.assertEqual(res["artifact_status"], "validated")
        self.assertEqual(res["telemetry"]["artifact_checksum"], res["artifact_checksum"])
        self.assertEqual(res["telemetry"]["source_revision"], "a1b2c3d4e5f6789012345678901234567890abcd")

    def test_02_ast_latency_measurement(self):
        """Verify AST parsing latency is measured on real Python files."""
        files = [
            {"name": "module1.py", "content": "class A:\n    pass\n"},
            {"name": "module2.py", "content": "def compute():\n    return [x * 2 for x in range(100)]\n"},
            {"name": "readme.md", "content": "# Documentation\n"}
        ]
        res = server.run_telemetry_evaluation_pipeline(
            files=files,
            problem={"id": "test-prob", "title": "Test Problem"},
            repository_url="https://github.com/team/ast-check"
        )
        
        self.assertEqual(res["telemetry"]["ast_files_analyzed"], 2)
        self.assertGreaterEqual(res["telemetry"]["ast_latency_ms"], 0.0)
        self.assertIn("AST abstract syntax tree analysis", res["terminal_log"])

    def test_03_ast_syntax_error_detection(self):
        """Verify Python syntax errors are caught during AST parsing and reflected in vectors."""
        files = [
            {"name": "broken.py", "content": "def invalid syntax :::: ((((\n"}
        ]
        res = server.run_telemetry_evaluation_pipeline(
            files=files,
            problem={"id": "test-prob", "title": "Test Problem"},
            repository_url="https://github.com/team/broken-syntax"
        )
        
        ast_vec = next((v for v in res["vectors"] if v["id"] == "AST-001"), None)
        self.assertIsNotNone(ast_vec)
        self.assertEqual(ast_vec["status"], "failed")
        self.assertTrue("line 1" in ast_vec["detail"] or "broken.py" in ast_vec["detail"])
        self.assertEqual(res["telemetry"]["exit_code"], 1)

    def test_04_ephemeral_sandbox_unit_test_execution_pass(self):
        """Verify repository unit tests execute cleanly in isolated temp sandbox."""
        files = [
            {"name": "calculator.py", "content": "def multiply(x, y):\n    return x * y\n"},
            {"name": "test_calculator.py", "content": "import unittest\nfrom calculator import multiply\nclass TestCalc(unittest.TestCase):\n    def test_mult(self):\n        self.assertEqual(multiply(3, 4), 12)\n"}
        ]
        res = server.run_telemetry_evaluation_pipeline(
            files=files,
            problem={"id": "test-prob", "title": "Test Problem"},
            repository_url="https://github.com/team/passing-tests"
        )
        
        unit_vec = next((v for v in res["vectors"] if v["id"] == "UNIT-001"), None)
        self.assertIsNotNone(unit_vec)
        self.assertEqual(unit_vec["status"], "passed")
        self.assertTrue(unit_vec["passed"])
        self.assertIn("completed with exit code 0", unit_vec["detail"])

    def test_05_ephemeral_sandbox_unit_test_execution_fail(self):
        """Verify failing repository unit tests produce defect diff and exit code 1."""
        files = [
            {"name": "calculator.py", "content": "def multiply(x, y):\n    return x + y\n"},
            {"name": "test_calculator.py", "content": "import unittest\nfrom calculator import multiply\nclass TestCalc(unittest.TestCase):\n    def test_mult(self):\n        self.assertEqual(multiply(3, 4), 12)\n"}
        ]
        res = server.run_telemetry_evaluation_pipeline(
            files=files,
            problem={"id": "test-prob", "title": "Test Problem"},
            repository_url="https://github.com/team/failing-tests"
        )
        
        unit_vec = next((v for v in res["vectors"] if v["id"] == "UNIT-001"), None)
        self.assertIsNotNone(unit_vec)
        self.assertEqual(unit_vec["status"], "failed")
        self.assertFalse(unit_vec["passed"])
        self.assertTrue(res["diff"]["has_discrepancy"])
        self.assertIn("Discrepancy", res["diff"]["title"])
        self.assertEqual(res["telemetry"]["exit_code"], 1)

    def test_06_mandatory_security_baseline(self):
        """Verify SEC-001 through SEC-010 are evaluated and present in vectors."""
        files = [
            {"name": "app.py", "content": "import os\nprint('hello world')\n"}
        ]
        res = server.run_telemetry_evaluation_pipeline(
            files=files,
            problem={"id": "test-prob", "title": "Test Problem"},
            repository_url="https://github.com/team/sec-test"
        )
        
        sec_vectors = [v for v in res["vectors"] if v["id"] in server.MANDATORY_SECURITY_CHECKS]
        self.assertEqual(len(sec_vectors), 10)
        self.assertEqual(res["telemetry"]["mandatory_security_total"], 10)
        self.assertGreaterEqual(res["telemetry"]["mandatory_security_passed"], 1)

    def test_07_dynamic_vector_count_and_summary_reconciliation(self):
        """Verify vector count is dynamic and summary counts reconcile perfectly."""
        files = [
            {"name": "app.py", "content": "print('Dynamic count test')\n"}
        ]
        res = server.run_telemetry_evaluation_pipeline(
            files=files,
            problem={"id": "test-prob", "title": "Test Problem"},
            repository_url="https://github.com/team/reconcile"
        )
        
        vectors = res["vectors"]
        summary = res["summary"]
        self.assertEqual(summary["total"], len(vectors))
        self.assertEqual(
            summary["passed"] + summary["failed"] + summary["skipped"] + summary["error"],
            summary["total"]
        )

    def test_08_unique_marker_in_telemetry_log(self):
        """Verify custom repository identifier/marker appears in evaluation logs."""
        unique_marker = f"UNIQUE_REPO_MARKER_{uuid.uuid4().hex[:8]}"
        files = [
            {"name": "marker.py", "content": f"# {unique_marker}\n"}
        ]
        res = server.run_telemetry_evaluation_pipeline(
            files=files,
            problem={"id": "test-prob", "title": "Test Problem"},
            repository_url=f"https://github.com/team/{unique_marker}"
        )
        
        self.assertIn(unique_marker, res["terminal_log"])

    def test_09_archive_extraction_safety(self):
        """Verify archive extraction safely unpacks files and rejects path traversal."""
        buf = BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("clean.py", "x = 42\n")
            zf.writestr("sub/nested.py", "y = 100\n")
        raw_safe = buf.getvalue()
        
        extracted, checksum = server.extract_archive_files(raw_safe, "test.zip")
        self.assertEqual(len(extracted), 2)
        names = {f["name"] for f in extracted}
        self.assertIn("clean.py", names)
        self.assertIn("sub/nested.py", names)
        self.assertEqual(len(checksum), 64)
        
        # Malicious traversal zip
        buf_bad = BytesIO()
        with zipfile.ZipFile(buf_bad, "w") as zf:
            zf.writestr("../../../etc/passwd", "root:x:0:0\n")
        raw_bad = buf_bad.getvalue()
        
        with self.assertRaises(server.RepositoryUnavailable):
            server.extract_archive_files(raw_bad, "malicious.zip")

    def test_10_database_persistence_of_telemetry(self):
        """Verify telemetry, vectors, logs, and checksum persist into SQLite."""
        uid = uuid.uuid4().hex[:8]
        prob_id = f"prob-{uid}"
        event_id = f"event-{uid}"
        team_id = f"team-{uid}"
        now = datetime.now(timezone.utc).isoformat()
        
        test_files = [
            {"name": "solution.py", "content": "print('persisted')\n"}
        ]
        
        with patch("server.fetch_github_repository") as mock_fetch:
            mock_fetch.return_value = (f"https://github.com/team/{uid}", test_files, {"commit_sha": f"sha-{uid}"})
            
            with server.demo_db_connection() as conn:
                conn.execute("INSERT INTO problems (id,title,description,due_at,rubric_json,test_cases_json) VALUES (?,?,?,?,?,?)",
                             (prob_id, f"Problem {uid}", "Desc", "2029-01-01", "[]", "[]"))
                conn.execute("""INSERT INTO events (id,name,description,organizer,event_date,deadline,status,problem_id,
                                statement_text,statement_filename,statement_mime,statement_file,allow_resubmissions,
                                active_config_version,created_at,updated_at)
                                VALUES (?,?,?,?,?,?,'open',?,?,?,?,?,1,1,?,?)""",
                             (event_id, f"Event {uid}", "Desc", "Org", "2029-01-01", "2029-01-01T00:00:00Z",
                              prob_id, "Desc", "stmt.txt", "text/plain", None, now, now))
                conn.execute("INSERT INTO event_config_versions (event_id,version,config_json,approved,created_by,created_at) VALUES (?,1,'{\"approved\":true}',1,'admin',?)",
                             (event_id, now))
                conn.execute("INSERT INTO teams (id,name,members) VALUES (?,?,1)", (team_id, f"Team_{uid}"))
                conn.execute("INSERT INTO event_teams (id,event_id,team_id,team_name,created_at) VALUES (?,?,?,?,?)",
                             (f"et-{uid}", event_id, team_id, f"Team_{uid}", now))
            
            user = {"username": f"user_{uid}", "role": "team", "team": f"Team_{uid}"}
            sub_id = server.demo_create_repository_submission(
                user=user,
                event_id=event_id,
                team_name=f"Team_{uid}",
                repository_url=f"https://github.com/team/{uid}"
            )
            
            self.assertTrue(sub_id)
            
            with server.demo_db_connection() as conn:
                sub_row = conn.execute("SELECT artifact_checksum, source_revision, artifact_status, latest_evaluation_id FROM submissions WHERE id=?", (sub_id,)).fetchone()
                self.assertTrue(sub_row[0])
                self.assertEqual(sub_row[1], f"sha-{uid}")
                self.assertEqual(sub_row[2], "validated")
                
                eval_row = conn.execute("SELECT telemetry_json, vectors_json, logs_text, artifact_checksum, source_revision FROM submission_evaluations WHERE submission_id=?", (sub_id,)).fetchone()
                self.assertIsNotNone(eval_row)
                t_json = json.loads(eval_row[0])
                self.assertEqual(t_json["active_workers"], 4)
                self.assertGreaterEqual(t_json["ast_files_analyzed"], 1)
                vectors = json.loads(eval_row[1])
                self.assertGreaterEqual(len(vectors), 10)
                self.assertIn("evaluating repository target", eval_row[2])

    def test_11_telemetry_get_endpoint(self):
        """Verify GET /api/telemetry/<submission_id> returns valid structure."""
        handler = server.Handler.__new__(server.Handler)
        handler.current_user = MagicMock(return_value={"username": "reviewer", "role": "admin"})
        handler.require_roles = MagicMock(return_value={"username": "reviewer", "role": "admin"})
        handler.can_access_event = MagicMock(return_value=True)
        handler.send_json = MagicMock()
        
        # Test on historical or existing submission
        data = server.load_demo_database()
        if data["submissions"]:
            sub = data["submissions"][0]
            handler.path = f"/api/telemetry/{sub['id']}"
            handler.do_GET()
            
            self.assertTrue(handler.send_json.called)
            args, _ = handler.send_json.call_args
            response = args[0]
            self.assertIn("telemetry", response)
            self.assertIn("vectors", response)
            self.assertIn("diff", response)
            self.assertIn("summary", response)
            self.assertEqual(response["submission_id"], sub["id"])

    def test_12_telemetry_stats_endpoint(self):
        """Verify GET /api/telemetry/stats returns aggregate metrics."""
        handler = server.Handler.__new__(server.Handler)
        handler.current_user = MagicMock(return_value={"username": "reviewer", "role": "admin"})
        handler.require_roles = MagicMock(return_value={"username": "reviewer", "role": "admin"})
        handler.send_json = MagicMock()
        handler.path = "/api/telemetry/stats"
        handler.do_GET()
        
        self.assertTrue(handler.send_json.called)
        args, _ = handler.send_json.call_args
        stats = args[0]
        self.assertEqual(stats["active_workers"], 4)
        self.assertIn("avg_ast_latency_ms", stats)
        self.assertIn("sandbox_status", stats)
        self.assertIn("security_baseline_status", stats)

    def test_13_evaluation_runs_endpoints(self):
        """Verify GET /api/evaluation-runs lists runs and details."""
        handler = server.Handler.__new__(server.Handler)
        handler.current_user = MagicMock(return_value={"username": "reviewer", "role": "admin"})
        handler.require_roles = MagicMock(return_value={"username": "reviewer", "role": "admin"})
        handler.send_json = MagicMock()
        handler.path = "/api/evaluation-runs"
        handler.do_GET()
        
        self.assertTrue(handler.send_json.called)
        args, _ = handler.send_json.call_args
        res = args[0]
        self.assertIn("evaluation_runs", res)

    def test_14_authorization_and_permission_checks(self):
        """Verify non-owner teams are forbidden (403) from accessing another team's telemetry."""
        data = server.load_demo_database()
        if data["submissions"]:
            sub = data["submissions"][0]
            handler = server.Handler.__new__(server.Handler)
            # Team user with different team name
            handler.current_user = MagicMock(return_value={"username": "otherteam", "role": "team", "team": "OtherTeamXYZ"})
            handler.require_roles = MagicMock(return_value={"username": "otherteam", "role": "team", "team": "OtherTeamXYZ"})
            handler.can_access_event = MagicMock(return_value=True)
            handler.send_json = MagicMock()
            handler.path = f"/api/telemetry/{sub['id']}"
            handler.do_GET()
            
            self.assertTrue(handler.send_json.called)
            args, _ = handler.send_json.call_args
            response = args[0]
            status_code = args[1] if len(args) > 1 else 200
            self.assertEqual(status_code, 403)
            self.assertIn("permission", response.get("error", "").lower())

    def test_15_no_synthetic_traces_in_stdout(self):
        """Verify output diff does not contain synthetic cluster init strings."""
        files = [
            {"name": "main.py", "content": "print('actual real execution')\n"}
        ]
        res = server.run_telemetry_evaluation_pipeline(
            files=files,
            problem={"id": "prob1", "title": "P1"},
            repository_url="https://github.com/team/no-canned"
        )
        
        diff_str = json.dumps(res["diff"])
        self.assertNotIn("CLUSTER_INIT", diff_str)
        self.assertNotIn("HEARTBEAT term=4", diff_str)
        self.assertNotIn("PARTITION isolate=node_3", diff_str)
        self.assertNotIn("raft::consensus::check_quorum", res["terminal_log"])


if __name__ == "__main__":
    unittest.main()
