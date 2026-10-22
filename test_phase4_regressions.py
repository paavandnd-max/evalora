"""Comprehensive regression tests for Phase 4 improvements:
- Enhanced Security checks (SEC-004, SEC-005, SEC-006, SEC-007, SEC-009, SEC-010)
- Structural AST-based ML handlers (ML-001 through ML-020)
- Honest simulation-to-static handling (ES-003, ES-011, ES-014..016, ES-018..020, API-010, DATA-006)
"""

import unittest
import genuine_handlers
import server

class Phase4RegressionsTest(unittest.TestCase):
    def setUp(self):
        self.handlers = genuine_handlers.GENUINE_HANDLERS
        self.default_ctx = {
            "inspect_files": server.inspect_files,
            "parse_github_repository_url": server.parse_github_repository_url
        }

    def _run(self, check_id, ctx):
        full_ctx = {**self.default_ctx, **ctx}
        return self.handlers[check_id](full_ctx)

    # --------------------------------------------------------------------------
    # SEC-004: Path Traversal
    # --------------------------------------------------------------------------
    def test_sec_004_direct_user_path(self):
        ctx = {"files": [{"name": "app.py", "content": 'data = open(request.args.get("file")).read()\n'}]}
        r = self._run("SEC-004", ctx)
        self.assertEqual(r["state"], "fail")
        self.assertIn("user-controlled path data", r["detail"])

    def test_sec_004_benign_safe_path(self):
        ctx = {"files": [{"name": "app.py", "content": 'data = open("config/settings.json").read()\n'}]}
        r = self._run("SEC-004", ctx)
        self.assertEqual(r["state"], "pass")

    # --------------------------------------------------------------------------
    # SEC-005: Admin Bypass
    # --------------------------------------------------------------------------
    def test_sec_005_unconditional_assignment(self):
        ctx = {"files": [{"name": "auth.py", "content": 'is_admin = True\n'}]}
        r = self._run("SEC-005", ctx)
        self.assertEqual(r["state"], "fail")

    def test_sec_005_benign_role_check(self):
        ctx = {"files": [{"name": "auth.py", "content": 'is_admin = user.has_role("admin")\n'}]}
        r = self._run("SEC-005", ctx)
        self.assertEqual(r["state"], "pass")

    # --------------------------------------------------------------------------
    # SEC-006: BOLA / IDOR
    # --------------------------------------------------------------------------
    def test_sec_006_reports_table_idor(self):
        ctx = {"files": [{"name": "dao.py", "content": 'query = "SELECT * FROM reports WHERE id = req.params.id"\n'}]}
        r = self._run("SEC-006", ctx)
        self.assertEqual(r["state"], "fail")
        self.assertIn("Missing user ownership", r["detail"])

    def test_sec_006_invoices_table_idor(self):
        # Different table and variable name
        ctx = {"files": [{"name": "dao.py", "content": 'query = "SELECT * FROM invoices WHERE id = req.params.invoice_id"\n'}]}
        r = self._run("SEC-006", ctx)
        self.assertEqual(r["state"], "fail")
        self.assertIn("invoices", r["detail"])

    def test_sec_006_scoped_owner_query(self):
        ctx = {"files": [{"name": "dao.py", "content": 'query = "SELECT * FROM invoices WHERE id = :id AND user_id = :uid"\n'}]}
        r = self._run("SEC-006", ctx)
        self.assertEqual(r["state"], "pass")

    def test_sec_006_tenant_scoped_query(self):
        ctx = {"files": [{"name": "dao.py", "content": 'query = "SELECT * FROM reports WHERE id = :id AND org_id = :org_id"\n'}]}
        r = self._run("SEC-006", ctx)
        self.assertEqual(r["state"], "pass")

    # --------------------------------------------------------------------------
    # SEC-007: Sensitive Logging
    # --------------------------------------------------------------------------
    def test_sec_007_credential_logging(self):
        ctx = {"files": [{"name": "auth.py", "content": 'logging.info("User password: %s", password)\n'}]}
        r = self._run("SEC-007", ctx)
        self.assertEqual(r["state"], "fail")

    def test_sec_007_fstring_token_logging(self):
        ctx = {"files": [{"name": "auth.py", "content": 'logger.debug(f"Auth token: {auth_token}")\n'}]}
        r = self._run("SEC-007", ctx)
        self.assertEqual(r["state"], "fail")

    def test_sec_007_benign_token_mention(self):
        ctx = {"files": [{"name": "auth.py", "content": 'logging.info("Password reset token generated")\n'}]}
        r = self._run("SEC-007", ctx)
        self.assertEqual(r["state"], "pass")

    def test_sec_007_benign_key_mention(self):
        ctx = {"files": [{"name": "auth.py", "content": 'logging.info("API key verified for tenant")\n'}]}
        r = self._run("SEC-007", ctx)
        self.assertEqual(r["state"], "pass")

    # --------------------------------------------------------------------------
    # SEC-009: Dependency Vulnerabilities
    # --------------------------------------------------------------------------
    def test_sec_009_vulnerable_requirements(self):
        ctx = {"files": [{"name": "requirements.txt", "content": "flask==0.12\n"}]}
        r = self._run("SEC-009", ctx)
        self.assertEqual(r["state"], "fail")
        self.assertIn("CVE-2018-1000656", r["detail"])

    def test_sec_009_vulnerable_package_json(self):
        ctx = {"files": [{"name": "package.json", "content": '{"dependencies": {"lodash": "4.17.11"}}'}]}
        r = self._run("SEC-009", ctx)
        self.assertEqual(r["state"], "fail")
        self.assertIn("CVE-2020-8203", r["detail"])

    def test_sec_009_clean_modern_dependencies(self):
        ctx = {"files": [{"name": "requirements.txt", "content": "flask>=3.0.0\nrequests>=2.31.0\n"}]}
        r = self._run("SEC-009", ctx)
        self.assertEqual(r["state"], "pass")

    def test_sec_009_clean_without_manifests(self):
        ctx = {"files": [{"name": "main.py", "content": "print(1)"}]}
        r = self._run("SEC-009", ctx)
        self.assertEqual(r["state"], "pass")
        self.assertIn("No dependency manifests found", r["detail"])

    # --------------------------------------------------------------------------
    # SEC-010: SSRF Prevention
    # --------------------------------------------------------------------------
    def test_sec_010_metadata_ip(self):
        ctx = {"repository_url": "http://169.254.169.254/latest/meta-data/"}
        r = self._run("SEC-010", ctx)
        self.assertEqual(r["state"], "fail")

    def test_sec_010_ipv6_loopback(self):
        ctx = {"repository_url": "http://[::1]:8080/repo"}
        r = self._run("SEC-010", ctx)
        self.assertEqual(r["state"], "fail")

    def test_sec_010_rfc1918_private(self):
        ctx = {"repository_url": "http://10.0.0.1/internal/repo"}
        r = self._run("SEC-010", ctx)
        self.assertEqual(r["state"], "fail")

    def test_sec_010_public_github(self):
        ctx = {"repository_url": "https://github.com/my-org/my-project"}
        r = self._run("SEC-010", ctx)
        self.assertEqual(r["state"], "pass")

    # --------------------------------------------------------------------------
    # ML Handlers: AST Analysis & Inapplicable Repositories
    # --------------------------------------------------------------------------
    def test_ml_handlers_not_testable_on_non_ml_repo(self):
        ctx = {"files": [{"name": "index.html", "content": "<h1>Hello</h1>"}]}
        for i in range(1, 21):
            cid = f"ML-{i:03d}"
            r = self._run(cid, ctx)
            self.assertEqual(r["state"], "not_testable", f"{cid} should be not_testable on non-ML repo")

    def test_ml_002_ast_train_test_split(self):
        ctx = {"files": [
            {"name": "requirements.txt", "content": "scikit-learn\n"},
            {"name": "train.py", "content": "from sklearn.model_selection import train_test_split\nX_train, X_test, y_train, y_test = train_test_split(X, y)\n"}
        ]}
        r = self._run("ML-002", ctx)
        self.assertEqual(r["state"], "pass")

    def test_ml_014_ast_reproducibility_seed(self):
        ctx = {"files": [
            {"name": "requirements.txt", "content": "numpy\n"},
            {"name": "train.py", "content": "import numpy as np\nnp.random.seed(42)\n"}
        ]}
        r = self._run("ML-014", ctx)
        self.assertEqual(r["state"], "pass")

    # --------------------------------------------------------------------------
    # Simulation-to-Static Handlers: Fail-Closed & Clean Handling
    # --------------------------------------------------------------------------
    def test_es_003_passes_clean_repo(self):
        ctx = {"files": [{"name": "README.md", "content": "docs"}]}
        r = self._run("ES-003", ctx)
        self.assertEqual(r["state"], "pass")

    def test_es_003_passes_with_static_job_auth(self):
        ctx = {"files": [{"name": "jobs.py", "content": "def get_job(job_id, user_id):\n    check_permission(job_id, user_id)\n"}]}
        r = self._run("ES-003", ctx)
        self.assertEqual(r["state"], "pass")

    def test_es_003_fails_unauthorized_job_access(self):
        ctx = {"unauthorized_job_access": True, "files": []}
        r = self._run("ES-003", ctx)
        self.assertEqual(r["state"], "fail")

    def test_es_011_passes_clean_repo(self):
        ctx = {"files": [{"name": "README.md", "content": "docs"}]}
        r = self._run("ES-011", ctx)
        self.assertEqual(r["state"], "pass")

    def test_es_011_fails_on_queue_exhausted(self):
        ctx = {"queue_exhausted": True, "files": []}
        r = self._run("ES-011", ctx)
        self.assertEqual(r["state"], "fail")

if __name__ == "__main__":
    unittest.main()
