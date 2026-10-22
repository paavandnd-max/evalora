import unittest
import json
import server as evalora
import test_registry


class Batch1HandlerTests(unittest.TestCase):
    def test_re001_public_valid_repo_pass_and_fail(self):
        res_pass = evalora.run_selected_catalogue_checks(["RE-001"], [], "https://github.com/octocat/Hello-World")
        self.assertEqual(res_pass[0]["state"], "pass")
        self.assertTrue(res_pass[0]["passed"])

        res_fail = evalora.run_selected_catalogue_checks(["RE-001"], [], "https://notgithub.com/bad/repo")
        self.assertEqual(res_fail[0]["state"], "fail")
        self.assertFalse(res_fail[0]["passed"])

        res_empty = evalora.run_selected_catalogue_checks(["RE-001"], [], "")
        self.assertEqual(res_empty[0]["state"], "fail")

    def test_re003_invalid_url_pass_and_fail(self):
        res_pass = evalora.run_selected_catalogue_checks(["RE-003"], [], "https://github.com/valid/repo")
        self.assertEqual(res_pass[0]["state"], "pass")
        self.assertTrue(res_pass[0]["passed"])

        res_fail = evalora.run_selected_catalogue_checks(["RE-003"], [], "ftp://invalid-url")
        self.assertEqual(res_fail[0]["state"], "fail")
        self.assertFalse(res_fail[0]["passed"])

    def test_re006_empty_repo_pass_and_fail(self):
        res_empty = evalora.run_selected_catalogue_checks(["RE-006"], [])
        self.assertEqual(res_empty[0]["state"], "fail")
        self.assertFalse(res_empty[0]["passed"])

        res_nonempty = evalora.run_selected_catalogue_checks(["RE-006"], [{"name": "README.md", "content": "# Hello"}])
        self.assertEqual(res_nonempty[0]["state"], "pass")
        self.assertTrue(res_nonempty[0]["passed"])

    def test_re007_unsupported_language_pass_and_fail(self):
        res_supported = evalora.run_selected_catalogue_checks(
            ["RE-007"], [{"name": "app.py", "content": "print(1)"}]
        )
        self.assertEqual(res_supported[0]["state"], "pass")
        self.assertTrue(res_supported[0]["passed"])

        res_unsupported = evalora.run_selected_catalogue_checks(
            ["RE-007"], [{"name": "data.bin", "content": "10101"}]
        )
        self.assertEqual(res_unsupported[0]["state"], "fail")
        self.assertFalse(res_unsupported[0]["passed"])

    def test_re008_dependency_manifest_pass_and_fail(self):
        res_found = evalora.run_selected_catalogue_checks(
            ["RE-008"], [{"name": "requirements.txt", "content": "requests==2.28.1\n"}]
        )
        self.assertEqual(res_found[0]["state"], "pass")
        self.assertTrue(res_found[0]["passed"])

        res_missing = evalora.run_selected_catalogue_checks(
            ["RE-008"], [{"name": "main.py", "content": "import sys\n"}]
        )
        self.assertEqual(res_missing[0]["state"], "fail")
        self.assertFalse(res_missing[0]["passed"])

    def test_re012_no_tests_supplied_pass_and_fail(self):
        res_with_tests = evalora.run_selected_catalogue_checks(
            ["RE-012"], [{"name": "test_app.py", "content": "def test_ok(): pass\n"}]
        )
        self.assertEqual(res_with_tests[0]["state"], "pass")
        self.assertTrue(res_with_tests[0]["passed"])

        res_no_tests = evalora.run_selected_catalogue_checks(
            ["RE-012"], [{"name": "app.py", "content": "def run(): pass\n"}]
        )
        self.assertEqual(res_no_tests[0]["state"], "fail")
        self.assertFalse(res_no_tests[0]["passed"])

    def test_re023_secret_scanning_pass_and_fail(self):
        res_clean = evalora.run_selected_catalogue_checks(
            ["RE-023"], [{"name": "config.py", "content": "DEBUG = True\n"}]
        )
        self.assertEqual(res_clean[0]["state"], "pass")
        self.assertTrue(res_clean[0]["passed"])

        res_secret = evalora.run_selected_catalogue_checks(
            ["RE-023"], [{"name": "secret.py", "content": 'api_key = "abcdef1234567890"\n'}]
        )
        self.assertEqual(res_secret[0]["state"], "fail")
        self.assertFalse(res_secret[0]["passed"])

    def test_re036_archive_limits_pass_and_fail(self):
        res_clean = evalora.run_selected_catalogue_checks(
            ["RE-036"], [{"name": "app.py", "content": "print('ok')\n"}]
        )
        self.assertEqual(res_clean[0]["state"], "pass")
        self.assertTrue(res_clean[0]["passed"])

        oversized_file = [{"name": "huge.txt", "content": "a" * 300_001}]
        res_oversized = evalora.run_selected_catalogue_checks(["RE-036"], oversized_file)
        self.assertEqual(res_oversized[0]["state"], "fail")
        self.assertFalse(res_oversized[0]["passed"])


if __name__ == "__main__":
    unittest.main()
