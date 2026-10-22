import unittest
import server as evalora


class Batch2DetHandlerTests(unittest.TestCase):
    def test_det001_python_api_pass_and_fail(self):
        files_pass = [{"name": "api/main.py", "content": "from fastapi import FastAPI\napp = FastAPI()\n"}]
        res_pass = evalora.run_selected_catalogue_checks(["DET-001"], files_pass)
        self.assertEqual(res_pass[0]["state"], "pass")
        self.assertTrue(res_pass[0]["passed"])

        files_fail = [{"name": "script.py", "content": "print('simple CLI')\n"}]
        res_fail = evalora.run_selected_catalogue_checks(["DET-001"], files_fail)
        self.assertEqual(res_fail[0]["state"], "fail")
        self.assertFalse(res_fail[0]["passed"])

    def test_det002_react_frontend_pass_and_fail(self):
        files_pass = [{"name": "src/App.jsx", "content": "export default function App() { return <div/>; }"}]
        res_pass = evalora.run_selected_catalogue_checks(["DET-002"], files_pass)
        self.assertEqual(res_pass[0]["state"], "pass")
        self.assertTrue(res_pass[0]["passed"])

        files_fail = [{"name": "main.py", "content": "x = 1"}]
        res_fail = evalora.run_selected_catalogue_checks(["DET-002"], files_fail)
        self.assertEqual(res_fail[0]["state"], "fail")

    def test_det003_react_python_fullstack_pass_and_fail(self):
        files_pass = [
            {"name": "backend/app.py", "content": "print('backend')"},
            {"name": "frontend/App.tsx", "content": "import React from 'react';"}
        ]
        res_pass = evalora.run_selected_catalogue_checks(["DET-003"], files_pass)
        self.assertEqual(res_pass[0]["state"], "pass")

        files_fail = [{"name": "backend/app.py", "content": "print('backend only')"}]
        res_fail = evalora.run_selected_catalogue_checks(["DET-003"], files_fail)
        self.assertEqual(res_fail[0]["state"], "fail")

    def test_det004_ml_notebook_pass_and_fail(self):
        files_pass = [{"name": "train.ipynb", "content": '{"cells": []}'}]
        res_pass = evalora.run_selected_catalogue_checks(["DET-004"], files_pass)
        self.assertEqual(res_pass[0]["state"], "pass")

        files_fail = [{"name": "main.py", "content": "def add(a, b): return a + b"}]
        res_fail = evalora.run_selected_catalogue_checks(["DET-004"], files_fail)
        self.assertEqual(res_fail[0]["state"], "fail")

    def test_det005_ai_agent_pass_and_fail(self):
        files_pass = [{"name": "agent.py", "content": "from langchain.agents import initialize_agent"}]
        res_pass = evalora.run_selected_catalogue_checks(["DET-005"], files_pass)
        self.assertEqual(res_pass[0]["state"], "pass")

        files_fail = [{"name": "util.py", "content": "def helper(): return True"}]
        res_fail = evalora.run_selected_catalogue_checks(["DET-005"], files_fail)
        self.assertEqual(res_fail[0]["state"], "fail")

    def test_det006_multiple_languages_pass_and_fail(self):
        files_multi = [
            {"name": "server.py", "content": "print('py')"},
            {"name": "app.ts", "content": "const x = 1;"}
        ]
        res_multi = evalora.run_selected_catalogue_checks(["DET-006"], files_multi)
        self.assertEqual(res_multi[0]["state"], "pass")

        files_single = [{"name": "server.py", "content": "print('py')"}]
        res_single = evalora.run_selected_catalogue_checks(["DET-006"], files_single)
        self.assertEqual(res_single[0]["state"], "fail")

    def test_det007_conflicting_indicators_pass_and_fail(self):
        files_conflict = [{"name": "package.json", "content": '{"name": "app"}'}]
        res_conflict = evalora.run_selected_catalogue_checks(["DET-007"], files_conflict)
        self.assertEqual(res_conflict[0]["state"], "fail")

        files_ok = [
            {"name": "package.json", "content": '{"name": "app"}'},
            {"name": "index.js", "content": "console.log('run');"}
        ]
        res_ok = evalora.run_selected_catalogue_checks(["DET-007"], files_ok)
        self.assertEqual(res_ok[0]["state"], "pass")

    def test_det008_misleading_readme_pass_and_fail(self):
        files_misleading = [{"name": "README.md", "content": "Comprehensive enterprise production platform ready to deploy with microservices architecture."}]
        res_misleading = evalora.run_selected_catalogue_checks(["DET-008"], files_misleading)
        self.assertEqual(res_misleading[0]["state"], "fail")

        files_ok = [
            {"name": "README.md", "content": "A minimal script."},
            {"name": "main.py", "content": "print('done')"}
        ]
        res_ok = evalora.run_selected_catalogue_checks(["DET-008"], files_ok)
        self.assertEqual(res_ok[0]["state"], "pass")


if __name__ == "__main__":
    unittest.main()
