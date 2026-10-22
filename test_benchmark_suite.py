"""Curated End-to-End Adversarial Benchmark Suite for Evalora.

Defines 6 complete synthetic submission scenarios:
1. scenario_valid: Clean, compliant, fully documented API service.
2. scenario_missing_config: Missing package.json/requirements.txt and config.
3. scenario_security_weakness: Contains hardcoded secrets, SQL injection, and debug mode.
4. scenario_missing_functionality: Empty code files lacking routes, error handling, models.
5. scenario_inconsistent_evidence: Declares dependencies but files syntax is broken.
6. scenario_adversarial_spoof: Superficial regex strings ("app.run", "pydantic") in comments, but no real logic.

Runs through the real pipeline: run_selected_catalogue_checks, evaluate_submission, build_reviewer_report.
"""

from typing import Any, Dict, List
import server as evalora


# Scenario 1: Valid compliant project
SCENARIO_VALID = {
    "name": "scenario_valid",
    "description": "Complete compliant API application with health endpoint, pydantic schema, and clean docs.",
    "files": [
        {"name": "README.md", "content": "# Valid Project\nComplete documentation and setup instructions.\n"},
        {"name": "requirements.txt", "content": "fastapi>=0.100\npydantic>=2.0\npytest>=7.0\n"},
        {"name": "main.py", "content": (
            "from fastapi import FastAPI, HTTPException, Request\n"
            "from pydantic import BaseModel\n"
            "app = FastAPI(title='Valid App')\n\n"
            "class Item(BaseModel):\n"
            "    id: int\n"
            "    name: str\n\n"
            "@app.get('/health')\n"
            "def health(): return {'status': 'ok'}\n\n"
            "@app.post('/items')\n"
            "def create_item(item: Item, request: Request):\n"
            "    auth = request.headers.get('authorization')\n"
            "    if not auth: raise HTTPException(status_code=403, detail='forbidden')\n"
            "    return {'item': item.model_dump(), 'headers': {'x-frame-options': 'DENY'}}\n"
        )},
        {"name": "tests/test_main.py", "content": "def test_ok(): assert 1 == 1\n"}
    ],
    "expected_status": "Ready for review",
    "expected_checks_passed": ["API-001", "API-002", "API-004", "RE-001", "RE-006", "RE-008", "RE-010"]
}

# Scenario 2: Missing configuration
SCENARIO_MISSING_CONFIG = {
    "name": "scenario_missing_config",
    "description": "Source files present but completely missing requirements/package manifest and config.",
    "files": [
        {"name": "README.md", "content": "# Untracked project\n"},
        {"name": "main.py", "content": "print('hello world')\n"}
    ],
    "expected_status": "Flagged",
    "expected_checks_failed": ["RE-008"]  # Missing dependency manifest
}

# Scenario 3: Security weakness
SCENARIO_SECURITY_WEAKNESS = {
    "name": "scenario_security_weakness",
    "description": "Contains hardcoded API keys, debug=True, and SQL string concatenation.",
    "files": [
        {"name": "README.md", "content": "# Vulnerable App\n"},
        {"name": "requirements.txt", "content": "flask==2.0\n"},
        {"name": "app.py", "content": (
            "import os\n"
            "api_key = '1234567890abcdef1234567890abcdef'\n"
            "def query(db, uid): return db.execute(f'SELECT * FROM users WHERE id = {uid}')\n"
            "if __name__ == '__main__': app.run(debug=True)\n"
        )}
    ],
    "expected_status": "Flagged",
    "expected_checks_failed": ["SEC-001", "SEC-002", "SEC-013"]
}

# Scenario 4: Missing required functionality
SCENARIO_MISSING_FUNCTIONALITY = {
    "name": "scenario_missing_functionality",
    "description": "Skeleton files present but devoid of routes, health checks, schemas, and test suites.",
    "files": [
        {"name": "README.md", "content": "# Skeleton\n"},
        {"name": "requirements.txt", "content": "requests\n"},
        {"name": "empty.py", "content": "# TODO: implement\npass\n"}
    ],
    "expected_status": "Flagged",
    "expected_checks_failed": ["API-001", "FUNC-012"]
}

# Scenario 5: Inconsistent evidence
SCENARIO_INCONSISTENT_EVIDENCE = {
    "name": "scenario_inconsistent_evidence",
    "description": "Declares dependencies and README, but Python source code has unparseable syntax errors.",
    "files": [
        {"name": "README.md", "content": "# Broken App\n"},
        {"name": "requirements.txt", "content": "fastapi\n"},
        {"name": "broken.py", "content": "def broken(:\n  return 1\n"}
    ],
    "expected_status": "Flagged",
    "expected_checks_failed": ["RE-010"]
}

# Scenario 6: Adversarial spoof
SCENARIO_ADVERSARIAL_SPOOF = {
    "name": "scenario_adversarial_spoof",
    "description": "Attempts to spoof checks by inserting keywords into comments or dead strings without actual implementation.",
    "files": [
        {"name": "README.md", "content": "# Spoofed App\n"},
        {"name": "requirements.txt", "content": "flask\n"},
        {"name": "spoof.py", "content": (
            "# This has pydantic and basemodel in comments\n"
            "# And while True: os.fork() is here:\n"
            "evil_command = 'while True: os.fork()'\n"
            "print('No genuine API route')\n"
        )}
    ],
    "expected_status": "Flagged",
    "expected_checks_failed": ["RE-016", "API-001"]
}

ALL_BENCHMARK_SCENARIOS = [
    SCENARIO_VALID,
    SCENARIO_MISSING_CONFIG,
    SCENARIO_SECURITY_WEAKNESS,
    SCENARIO_MISSING_FUNCTIONALITY,
    SCENARIO_INCONSISTENT_EVIDENCE,
    SCENARIO_ADVERSARIAL_SPOOF
]


def run_benchmark_scenario(scenario: Dict[str, Any]) -> Dict[str, Any]:
    """Execute a benchmark scenario through the complete Evalora pipeline."""
    problem = {"description": "Build an API service", "test_cases": []}
    files = scenario["files"]
    repo_url = f"https://github.com/benchmark-org/{scenario['name']}"

    # 1. Run evaluation
    eval_result = evalora.evaluate_submission(problem, files)
    
    # 2. Run selected catalogue checks
    check_ids = ["API-001", "API-002", "API-004", "RE-001", "RE-006", "RE-008", "RE-010", "RE-016", "SEC-001", "SEC-002", "SEC-013", "FUNC-012"]
    checks_run = evalora.run_selected_catalogue_checks(check_ids, files, repo_url)
    checks_dict = {c["id"]: c for c in checks_run}

    # 3. Generate reviewer report
    reviewer_report = evalora.build_reviewer_report(problem, files, eval_result, repo_url)

    # 4. Verify expected passes and failures
    verified_passes = []
    for cid in scenario.get("expected_checks_passed", []):
        r = checks_dict.get(cid)
        if r and r.get("state") == "pass":
            verified_passes.append(cid)

    verified_fails = []
    for cid in scenario.get("expected_checks_failed", []):
        r = checks_dict.get(cid)
        if r and r.get("state") in {"fail", "not_testable"} and r.get("passed") is False:
            verified_fails.append(cid)

    return {
        "scenario_name": scenario["name"],
        "description": scenario["description"],
        "files_count": len(files),
        "pipeline_status": eval_result.get("status"),
        "pipeline_score": eval_result.get("score"),
        "expected_status": scenario["expected_status"],
        "status_matched": eval_result.get("status") == scenario["expected_status"],
        "expected_checks_passed": scenario.get("expected_checks_passed", []),
        "verified_checks_passed": verified_passes,
        "expected_checks_failed": scenario.get("expected_checks_failed", []),
        "verified_checks_failed": verified_fails,
        "reviewer_summary_present": bool(reviewer_report.get("executive_summary")),
        "report_security_analysis": reviewer_report.get("test_analysis", {}).get("security", {})
    }


def execute_all_benchmarks() -> List[Dict[str, Any]]:
    return [run_benchmark_scenario(s) for s in ALL_BENCHMARK_SCENARIOS]


if __name__ == "__main__":
    results = execute_all_benchmarks()
    import json
    print(json.dumps(results, indent=2))
