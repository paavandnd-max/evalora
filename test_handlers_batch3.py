import unittest
import server as evalora


class Batch3EsHandlerTests(unittest.TestCase):
    def test_es004_ssrf_pass_and_fail(self):
        res_pass = evalora.run_selected_catalogue_checks(["ES-004"], [], "https://github.com/my-org/repo")
        self.assertEqual(res_pass[0]["state"], "pass")
        self.assertTrue(res_pass[0]["passed"])

        res_fail = evalora.run_selected_catalogue_checks(["ES-004"], [], "https://internal.corp/repo")
        self.assertEqual(res_fail[0]["state"], "fail")
        self.assertFalse(res_fail[0]["passed"])

    def test_es005_dns_rebinding_pass_and_fail(self):
        res_pass = evalora.run_selected_catalogue_checks(["ES-005"], [], "https://github.com/my-org/repo")
        self.assertEqual(res_pass[0]["state"], "pass")
        self.assertTrue(res_pass[0]["passed"])

        res_http = evalora.run_selected_catalogue_checks(["ES-005"], [], "http://github.com/my-org/repo")
        self.assertEqual(res_http[0]["state"], "fail")

        res_loopback = evalora.run_selected_catalogue_checks(["ES-005"], [], "https://127.0.0.1/my-org/repo")
        self.assertEqual(res_loopback[0]["state"], "fail")

    def test_es008_log_forging_pass_and_fail(self):
        res_clean = evalora.run_selected_catalogue_checks(["ES-008"], [{"name": "app.py", "content": "1"}], "https://github.com/a/b")
        self.assertEqual(res_clean[0]["state"], "pass")

        res_forged = evalora.run_selected_catalogue_checks(["ES-008"], [{"name": "app\r\nINJECTED.py", "content": "1"}], "https://github.com/a/b")
        self.assertEqual(res_forged[0]["state"], "fail")

    def test_es009_html_markdown_injection_pass_and_fail(self):
        res_clean = evalora.run_selected_catalogue_checks(["ES-009"], [{"name": "README.md", "content": "# Overview"}])
        self.assertEqual(res_clean[0]["state"], "pass")

        res_injected = evalora.run_selected_catalogue_checks(["ES-009"], [{"name": "README.md", "content": "<script>alert(1)</script>"}])
        self.assertEqual(res_injected[0]["state"], "fail")

    def test_es010_secret_exposure_pass_and_fail(self):
        res_clean = evalora.run_selected_catalogue_checks(["ES-010"], [{"name": "config.py", "content": "TIMEOUT = 30"}])
        self.assertEqual(res_clean[0]["state"], "pass")

        res_secret = evalora.run_selected_catalogue_checks(["ES-010"], [{"name": "config.py", "content": 'secret = "my-super-secret-key-123"'}])
        self.assertEqual(res_secret[0]["state"], "fail")

    def test_es012_oversized_submissions_pass_and_fail(self):
        res_clean = evalora.run_selected_catalogue_checks(["ES-012"], [{"name": "main.py", "content": "print('ok')"}])
        self.assertEqual(res_clean[0]["state"], "pass")

        res_huge = evalora.run_selected_catalogue_checks(["ES-012"], [{"name": "big.txt", "content": "a" * 300_001}])
        self.assertEqual(res_huge[0]["state"], "fail")

    def test_es013_repeated_submission_abuse_pass_and_fail(self):
        # When idempotency key is valid
        res_pass = evalora.run_selected_catalogue_checks(["ES-013"], [])
        self.assertEqual(res_pass[0]["state"], "pass")


if __name__ == "__main__":
    unittest.main()
