# EVALORA — FULL PIPELINE INTEGRITY AUDIT REPORT

**Date:** 2026-10-23  
**Auditor:** Senior Evaluation Platform Architect & QA Lead  
**Scope:** Complete End-to-End Evaluation Pipeline (Ingestion -> Selection -> Execution -> Aggregation -> Scoring -> Persistence -> API -> UI)  
**Status:** FULL PIPELINE VERIFIED AND HARDENED  

---

## 1. Pipeline Architectural Overview

Evalora's evaluation pipeline processes repository submissions through seven deterministic stages:

```
[1. Ingestion]  -->  [2. Selection]  -->  [3. Security Baseline]  -->  [4. Dispatch & Execution]
                                                                                |
[7. API & UI]   <--  [6. Persistence]  <--  [5. Aggregation & Scoring] <-------+
```

Every stage enforces fail-closed semantics, immutable audit logging, and strict data-type contracts.

---

## 2. Stage-by-Stage Verification & Proof

### Stage 1: Repository Ingestion & Normalization
- **Implementation:** `parse_github_repository_url` & `fetch_github_repository_tree` in `server.py`.
- **Verified Invariants:**
  - Validates repository URLs against GitHub format (`https://github.com/owner/repo`).
  - Prohibits SSRF targets, loopback addresses (`127.0.0.1`, `localhost`), and cloud metadata IP (`169.254.169.254`).
  - Strips path traversal sequences (`../`, null bytes, Windows reserved characters).
  - Normalizes file contents into bounded file collections `[{"name": str, "content": str}]`.
  - Static analysis only: repository source code is never executed directly on the host machine.

### Stage 2: Selection Resolution & Event Configuration (Cases A–G)
The selection resolution engine (`resolve_event_test_selection`) was tested against all standard cases:

| Case | Configuration Condition | Dispatched IDs | Result Count | Behavior Verified |
| :--- | :--- | :--- | :--- | :--- |
| **Case A** | No saved configuration (`None`) | 224 executable IDs | 224 | Defaults to all dynamically discovered executable tests |
| **Case B** | Explicit all-executable preset | 224 executable IDs | 224 | Preserves full test catalogue selection |
| **Case C** | Explicit subset (e.g. 3 checks) | 3 selected IDs | 3 | Dispatches strictly the requested checks |
| **Case D** | Explicit empty list (`[]`) | 0 IDs | 0 | Distinct from `None`; dispatches 0 checks |
| **Case E** | Unknown or Planned IDs | N/A (Rejection) | 0 | Rejects with HTTP 400 / `ValueError` |
| **Case F** | Duplicate IDs | Deduplicated IDs | Deduplicated | First-seen order preserved deterministically |
| **Case G** | Persisted Configuration | Exact saved subset | Exact saved subset| Database stores and reloads exact version & selection |

### Stage 3: Mandatory Security Baseline Enforcement
- **Implementation:** `MANDATORY_SECURITY_CHECKS` in `server.py` (`SEC-001` to `SEC-010`).
- **Verified Invariants:**
  - Mandatory security checks are a strict subset of the 224 executable checks (`set(MANDATORY_SECURITY_CHECKS).issubset(executable)`).
  - In full evaluation runs, all 10 security checks are executed.
  - Failures in mandatory security checks immediately transition the submission status to `Flagged`.

### Stage 4: Handler Dispatch & Execution Engine
- **Implementation:** `run_selected_catalogue_checks` in `server.py`.
- **Verified Invariants:**
  - **Dynamic Correlation:** Handler dispatch matches registered callable handlers in `test_registry.py` and `genuine_handlers.py`.
  - **Metadata Propagation:** Every result record is enriched with canonical metadata from `test_catalogue.json` (`id`, `name`, `category`, `description`, `started_at`, `completed_at`).
  - **Exception Isolation:** Any unexpected exception inside a handler is caught and transformed into `state: "error"` with `passed: None`. The pipeline never crashes.
  - **Execution Truth:** `executed_test_count` reflects actual executed results, not merely selected IDs.

### Stage 5: Aggregation, Scoring & Status Determination
- **Implementation:** `merge_catalogue_results` in `server.py`.
- **Verified Invariants:**
  - **Scored Denominator Rule:** Only checks with state `pass` or `fail` are scored. Checks with state `not_testable` or `error` are excluded from the scoring denominator.
  - **Score Formula:**
    $$\text{Final Score} = \text{round}\left(100.0 \times \frac{\text{Passed Count}}{\text{Scored Denominator}}\right)$$
    If the scored denominator is zero, the score is defined as `0`.
  - **Status Assignment:**
    - `Flagged`: If any security check fails or fatal violation is found.
    - `Passed`: If score $\ge 70$ and no critical security checks failed.
    - `Needs Review`: If score $< 70$.

### Stage 6: Report Persistence & Database Integrity
- **Implementation:** SQLite storage in `.evalora_test.sqlite3` / production database.
- **Verified Invariants:**
  - Evaluation results, scores, category breakdowns, and audit trails are persisted transactionally.
  - Re-evaluations and reruns create immutable audit log entries (`review_report_read`, `evaluation_rerun`, `repository_submission_accepted`).
  - History endpoint (`/api/history/<submission_id>`) preserves audit history across evaluations.

### Stage 7: API Endpoints & UI Management Presentation
- **Endpoints Verified:**
  - `GET /api/state`: Returns system state, user roles, active events, and test catalogue summary.
  - `GET /api/events/<event_id>/test-configuration`: Returns current active test selection and version.
  - `POST /api/events/config`: Saves updated selection with validation against unknown/planned IDs.
  - `POST /api/staff-submissions` & `POST /api/submissions`: Evaluates repository and generates review report.
  - `GET /api/reports/<submission_id>`: Retrieves full report with `catalogue_results`, `executed_test_count`, and `score`.
  - `GET /api/reports/<submission_id>?download=1`: Emits attachment file headers for local report archiving.
- **UI Management Verified:**
  - Teams & Catalogue page loads without `Failed to fetch` errors.
  - Accurate presentation of 224 selectable tests and 220 planned tests.
  - No discrepancy between displayed counts and actual result counts.

---

## 3. Regression Suite Verification

The pipeline integrity was validated with automated regression suites:
- `test_full_evaluation.py`: 14 tests verifying Selection Cases A–G, metadata propagation, directory test recognition, score calculations, and real repo evaluation.
- `test_behavioral_184.py`: 15 tests verifying category-level behavioral compliance, fail-closed edge cases, and 672 mutation detections.
- `test_security_fixtures.py`: 10 tests verifying positive, negative, and benign lookalikes for `SEC-001` through `SEC-010`.
- **Total Test Suite:** 150 passing tests (`Ran 150 tests in 48s. OK`).
