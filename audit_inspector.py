"""Audit inspector script to analyze all 224 handlers independently."""

import inspect
import json
import re
from typing import Any, Mapping
import genuine_handlers
import server
from audit_generator import COMPLIANT_REPO_FILES, SPECIFIC_NEGATIVE_FIXTURES

def analyze_all():
    catalogue = {item["id"]: item for item in server.load_test_catalogue()}
    handlers = genuine_handlers.GENUINE_HANDLERS

    report = []
    verdicts = {"VERIFIED": 0, "PARTIALLY VERIFIED": 0, "UNVERIFIED": 0, "TEST FAILURE": 0}

    for cid, handler in sorted(handlers.items()):
        cat_meta = catalogue.get(cid, {})
        try:
            src = inspect.getsource(handler)
        except Exception:
            src = ""

        # Run positive test
        pos_ctx = {
            "files": COMPLIANT_REPO_FILES,
            "repository_url": "https://github.com/my-org/my-project",
            "inspect_files": server.inspect_files,
            "parse_github_repository_url": server.parse_github_repository_url,
            "results": [{"id": "GEN-01", "state": "pass", "passed": True}],
            "score": 100,
            "category_weights": {"general": 100},
            "scoring_weights": {"general": 10}
        }
        try:
            r_pos = handler(pos_ctx)
            pos_ok = (r_pos.get("state") == "pass" and r_pos.get("passed") is True)
        except Exception as e:
            r_pos = {"state": "error", "detail": str(e)}
            pos_ok = False

        # Run negative test
        neg_spec = SPECIFIC_NEGATIVE_FIXTURES.get(cid, {"files": [], "repository_url": ""})
        neg_ctx = {
            "files": [],
            "repository_url": "",
            "inspect_files": server.inspect_files,
            "parse_github_repository_url": server.parse_github_repository_url,
            **neg_spec
        }
        try:
            r_neg = handler(neg_ctx)
            neg_ok = (r_neg.get("state") in {"fail", "not_testable"} and not r_neg.get("passed"))
        except Exception as e:
            r_neg = {"state": "error", "detail": str(e)}
            neg_ok = False

        # Run edge test
        edge_ctx = {
            "files": [],
            "repository_url": "",
            "inspect_files": server.inspect_files,
            "parse_github_repository_url": server.parse_github_repository_url
        }
        try:
            r_edge = handler(edge_ctx)
            edge_ok = isinstance(r_edge, dict) and "state" in r_edge and r_edge.get("state") != "error"
        except Exception:
            edge_ok = False

        # Determine verification depth:
        # Check if the handler uses simulated runtime flags (e.g. context.get("concurrent_request_conflict"))
        has_simulated_flag = any(k in src for k in [
            "concurrent_request_conflict", "data_pipeline_not_idempotent",
            "unauthorized_job_access", "queue_exhausted", "idempotency_key",
            "cancellation_race_detected", "cache_cross_tenant_leak",
            "artifact_cross_tenant_leak", "stale_job_uncleaned",
            "orphaned_workers_detected", "resource_leak_detected",
            "empty_input_crash", "duplicate_request_conflict",
            "repeated_execution_divergence"
        ])

        # Check if it's purely a keyword search across all content
        has_keyword_heuristic_only = (
            "content_all" in src and
            not any(k in src for k in ["re.search", "re.findall", "inspector", "parse_github", "zipfile", "b\"%PDF", ".endswith", "os.path"])
        )

        if not pos_ok or not neg_ok:
            verdict = "TEST FAILURE"
        elif has_simulated_flag:
            verdict = "PARTIALLY VERIFIED" # Verified via simulated context flags, not end-to-end sandbox execution
        elif has_keyword_heuristic_only and cid.startswith(("ML-", "DATA-")):
            verdict = "PARTIALLY VERIFIED" # Verified via string presence heuristics rather than full AST validation
        else:
            verdict = "VERIFIED"

        verdicts[verdict] += 1

        report.append({
            "id": cid,
            "name": cat_meta.get("name", cid),
            "category": cat_meta.get("category", cid.split("-")[0]),
            "handler_name": getattr(handler, "__name__", "<lambda>"),
            "verdict": verdict,
            "positive_state": r_pos.get("state"),
            "negative_state": r_neg.get("state"),
            "edge_safe": edge_ok,
            "evidence_in_positive": bool(r_pos.get("detail")),
            "evidence_in_negative": bool(r_neg.get("detail")),
            "uses_simulated_flags": has_simulated_flag,
            "uses_keyword_heuristic": has_keyword_heuristic_only,
            "negative_fixture_keys": list(neg_spec.keys()),
            "audit_notes": (
                "Verified against static files and regex/AST pattern matching."
                if verdict == "VERIFIED" else
                "Partially verified: relies on simulated runtime/context flags or keyword substring heuristics."
            )
        })

    print("Independent Audit Summary:")
    print(f"Total Handlers: {len(report)}")
    for v, c in verdicts.items():
        print(f"  {v}: {c}")

    return report, verdicts

if __name__ == "__main__":
    analyze_all()
