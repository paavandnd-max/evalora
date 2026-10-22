# Evalora — Real Repository Verification & Handler Audit Report

**Catalogue Hash (SHA-256):** `6ffecec0285fd0a9df3e61b4e4955e9fd77a09600cbf054b1996cb39d26d85de`  
**Total Catalogue Entries:** 444  
**Executable Handlers Dispatched:** 224  
**Planned / Non-Executable Entries:** 220  

## 1. Repository Evaluation Summary Table

| Repository URL | Commit | Expected IDs | Actual Results | Unique IDs | Missing / Dup | State Distribution | Score (Numerator/Denominator) | Behavioral Status | Key Repository Characteristics & Limitations |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `https://github.com/octocat/Spoon-Knife` | `d0dd1f61b3` | 224 | 224 | 224 | 0 / 0 | Pass: 129, Fail: 95 | 60% (143/239) | Verified | Baseline repository (3 files: README, index.html, styles.css). 0 test files, 0 backend API files. |
| `https://github.com/pallets/flask` | `d086db856b` | 224 | 224 | 224 | 0 / 0 | Pass: 189, Fail: 35 | 84% (203/241) | Verified | Python WSGI web framework (140 files). Rich CLI, routing, and pytest test suite. Zero ML/DocGuard models. |
| `https://github.com/psf/requests` | `611c6162cb` | 224 | 224 | 224 | 0 / 0 | Pass: 194, Fail: 30 | 86% (207/240) | Verified | Python HTTP client library (76 files). Pytest suite, local socket testserver, adapter layer. Zero ML/DocGuard models. |
| `https://github.com/expressjs/express` | `0dee2c52c7` | 224 | 224 | 224 | 0 / 0 | Pass: 187, Fail: 37 | 83% (200/240) | Verified | Node.js web framework (176 files). 102 test files in `test/`, package.json main entrypoint, routing engine. |

## 2. Handler-Level Verification Matrix (All 224 Executable Handlers)

| Catalogue ID | Name | Category | Spoon-Knife Result | Flask Result | Requests Result | Express Result | Verification Status | Verification Evidence / Behavior |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `FUNC-001` | Valid input | Universal Functional Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Valid structured files accepted and processed. |
| `FUNC-002` | Empty input | Universal Functional Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Empty input checks or empty string guards present in source. |
| `FUNC-003` | Missing required field | Universal Functional Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Required field validation and exceptions present. |
| `FUNC-004` | Invalid data type | Universal Functional Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Data type checking and validation implemented. |
| `FUNC-005` | Boundary values | Universal Functional Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Numeric boundary value checks implemented. |
| `FUNC-006` | Very large input | Universal Functional Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Large input handled within resource constraints. |
| `FUNC-007` | Duplicate request | Universal Functional Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Duplicate request handling maintains idempotent state. |
| `FUNC-008` | Repeated execution | Universal Functional Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Repeated execution completes deterministically. |
| `FUNC-009` | Invalid operation | Universal Functional Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Invalid operations return appropriate error responses. |
| `FUNC-010` | State transition | Universal Functional Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | State machine transition logic detected. |
| `FUNC-011` | Data persistence | Universal Functional Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Data persistence operations detected. |
| `FUNC-012` | Regression testing | Universal Functional Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Regression test suite present (49 test files). |
| `API-001` | Health endpoint | API and Integration Tests | `fail` | `pass` | `fail` | `fail` | **VERIFIED** | Health endpoint route defined: "/status" |
| `API-002` | Valid request schema | API and Integration Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Request schema validation library or model definitions found. |
| `API-003` | Malformed JSON | API and Integration Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | All 2 JSON file(s) are syntactically valid. |
| `API-004` | Unsupported HTTP method | API and Integration Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | HTTP method restrictions and status routing enforced. |
| `API-005` | Missing content type | API and Integration Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Content-Type header inspection enforced. |
| `API-006` | Missing authentication | API and Integration Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | API authentication middleware or header check detected. |
| `API-007` | Insufficient permissions | API and Integration Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Permission checking and 403 status handling implemented. |
| `API-008` | Upstream service unavailable | API and Integration Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Upstream failure or timeout handling present. |
| `API-009` | Database unavailable | API and Integration Tests | `fail` | `pass` | `pass` | `fail` | **VERIFIED** | Database connection exception handling detected. |
| `API-010` | Concurrent requests | API and Integration Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | API handlers are reentrant and handle concurrent execution. |
| `API-011` | Request timeout | API and Integration Tests | `fail` | `pass` | `pass` | `fail` | **VERIFIED** | Explicit request timeouts configured on outbound calls. |
| `API-012` | Rate-limit threshold | API and Integration Tests | `fail` | `pass` | `pass` | `fail` | **VERIFIED** | Rate limiting policies or 429 status handling present. |
| `API-013` | Pagination | API and Integration Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Pagination parameters (limit/offset/page) supported. |
| `API-014` | Version compatibility | API and Integration Tests | `fail` | `fail` | `fail` | `pass` | **VERIFIED** | No API versioning prefix detected. |
| `API-015` | CORS configuration | API and Integration Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | CORS middleware or origin configuration present. |
| `SEC-001` | Hardcoded secret detection | Security and Privacy Tests | `pass` | `pass` | `pass` | `fail` | **VERIFIED** | No hardcoded credentials identified. |
| `SEC-002` | SQL injection | Security and Privacy Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Parameterized queries verified; no SQL concatenation. |
| `SEC-003` | Cross-site scripting (XSS) | Security and Privacy Tests | `pass` | `pass` | `pass` | `fail` | **VERIFIED** | No dangerous unescaped browser HTML sinks found. |
| `SEC-004` | Path traversal | Security and Privacy Tests | `pass` | `fail` | `fail` | `pass` | **VERIFIED** | File access may use user-controlled path data; validate paths stay within an allowed direc |
| `SEC-005` | Unauthorized access | Security and Privacy Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Access control validation checks enforced. |
| `SEC-006` | Broken object-level authorization | Security and Privacy Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Object-level queries enforce owner scoping. |
| `SEC-007` | Sensitive data in logs | Security and Privacy Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Log messages sanitize credential arguments. |
| `SEC-008` | Unsafe deserialization | Security and Privacy Tests | `pass` | `pass` | `fail` | `pass` | **VERIFIED** | No unsafe deserialization APIs used. |
| `SEC-009` | Dependency vulnerabilities | Security and Privacy Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | No known high-severity vulnerable package pins found. |
| `SEC-010` | Server-side request forgery (SSRF) | Security and Privacy Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Repository host github.com verified safe against SSRF. |
| `SEC-011` | Oversized payload | Security and Privacy Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Payload bounds verified (140 files, 630,712 bytes). |
| `SEC-012` | Security headers | Security and Privacy Tests | `fail` | `fail` | `pass` | `pass` | **VERIFIED** | No HTTP security headers or middleware detected. |
| `SEC-013` | Debug mode exposure | Security and Privacy Tests | `pass` | `fail` | `pass` | `pass` | **VERIFIED** | Production entrypoint exposes unconstrained debug mode. |
| `SEC-014` | Session handling | Security and Privacy Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Session attributes enforce secure cookie storage. |
| `SEC-015` | Sandbox isolation | Security and Privacy Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Execution environment maintains sandbox boundaries. |
| `REL-001` | Application startup | Reliability Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | A runnable entry point or application object is documented in source. |
| `REL-002` | Missing environment variables | Reliability Tests | `pass` | `fail` | `fail` | `pass` | **VERIFIED** | Required environment variables are read but no example configuration was supplied: FLASK_D |
| `REL-004` | Runtime exception handling | Reliability Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Structured exception handling is present in source. |
| `REL-005` | Process timeout | Reliability Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | A bounded timeout or deadline mechanism is present. |
| `DEP-001` | Fresh deployment | Deployment Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | A supported dependency manifest is present for reproducible setup. |
| `DEP-002` | Public URL accessibility | Deployment Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | A public HTTPS repository URL is available for deployment retrieval. |
| `DEP-003` | Frontend/backend connectivity | Deployment Tests | `fail` | `pass` | `fail` | `pass` | **VERIFIED** | Frontend and backend integration indicators are present (client submission/request path pl |
| `DEP-004` | Production configuration | Deployment Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Production configuration indicators are present. |
| `UX-001` | Primary navigation links | User Experience and Accessibility Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Primary navigation links or a navigation container are present. |
| `UX-002` | Form validation messages | User Experience and Accessibility Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Form validation or error messaging evidence is present. |
| `UX-003` | Loading states | User Experience and Accessibility Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | A loading or busy-state indicator is present. |
| `UX-004` | Empty states | User Experience and Accessibility Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | An empty-state message is present. |
| `UX-005` | Error recovery | User Experience and Accessibility Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Error recovery or retry messaging is present. |
| `UX-006` | Responsive layouts | User Experience and Accessibility Tests | `fail` | `fail` | `pass` | `pass` | **VERIFIED** | No responsive layout evidence was found. |
| `UX-007` | Keyboard navigation | User Experience and Accessibility Tests | `fail` | `pass` | `fail` | `pass` | **VERIFIED** | Keyboard/focus navigation evidence is present or native keyboard controls are used. |
| `UX-008` | Accessible control labels | User Experience and Accessibility Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Accessible control labels are present. |
| `UX-009` | Text contrast | User Experience and Accessibility Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Text/color styling evidence is present for review. |
| `UX-010` | Refresh and data persistence | User Experience and Accessibility Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Refresh or persistence handling evidence is present. |
| `UX-011` | Session expiry handling | User Experience and Accessibility Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Session expiry handling evidence is present. |
| `UX-012` | Browser console errors | User Experience and Accessibility Tests | `pass` | `fail` | `pass` | `fail` | **VERIFIED** | Console error calls were found in source. |
| `DG-001` | Valid clean PDF | DocGuard â€” Malicious File Detection | `fail` | `fail` | `fail` | `fail` | **VERIFIED** | No PDF file was supplied. |
| `DG-002` | Valid clean DOCX | DocGuard â€” Malicious File Detection | `fail` | `fail` | `fail` | `fail` | **VERIFIED** | No DOCX file was supplied. |
| `DG-003` | DOCM macro metadata detection | DocGuard â€” Malicious File Detection | `fail` | `fail` | `fail` | `fail` | **VERIFIED** | No .docm file was supplied. |
| `DG-004` | Embedded VBA project inspection | DocGuard â€” Malicious File Detection | `fail` | `fail` | `fail` | `fail` | **VERIFIED** | No .docm file was supplied. |
| `DG-005` | Benign macro false-positive handling | DocGuard â€” Malicious File Detection | `fail` | `fail` | `fail` | `fail` | **VERIFIED** | No .docx file was supplied. |
| `DG-006` | Suspicious script or embedded object detection | DocGuard â€” Malicious File Detection | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | No suspicious script or embedded-object members detected. |
| `DG-007` | Corrupt PDF or Office file | DocGuard â€” Malicious File Detection | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Supported PDF and Office containers passed structural integrity checks. |
| `DG-008` | File extension/MIME mismatch | DocGuard â€” Malicious File Detection | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | File extensions match the inspected signatures. |
| `DG-009` | Renamed executable detection | DocGuard â€” Malicious File Detection | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | No executable signature was found under a non-executable filename. |
| `DG-010` | Nested ZIP archives | DocGuard â€” Malicious File Detection | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | No nested archive members detected. |
| `DG-011` | ZIP path traversal | DocGuard â€” Malicious File Detection | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | No absolute or traversal archive paths detected. |
| `DG-012` | High-compression-ratio archive | DocGuard â€” Malicious File Detection | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Archive compression ratios are below the configured review threshold. |
| `DG-013` | Encrypted archive | DocGuard â€” Malicious File Detection | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | No encrypted archive members were detected. |
| `DG-014` | Unsupported file format | DocGuard â€” Malicious File Detection | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | All supplied file formats are in the safe inspection set. |
| `DG-015` | File without extension | DocGuard â€” Malicious File Detection | `pass` | `fail` | `fail` | `pass` | **VERIFIED** | Extensionless file(s) detected: docs/Makefile. |
| `DG-016` | Very large file | DocGuard â€” Malicious File Detection | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | All files are within the 10485760-byte inspection limit. |
| `DG-017` | Zero-byte file | DocGuard â€” Malicious File Detection | `pass` | `fail` | `fail` | `fail` | **VERIFIED** | Zero-byte file(s) detected: tests/test_apps/blueprintapp/apps/__init__.py, tests/test_apps |
| `DG-018` | Multiple files in one submission | DocGuard â€” Malicious File Detection | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Submission contains 140 file(s); multiple-file submission was detected. |
| `DG-019` | Duplicate file detection | DocGuard â€” Malicious File Detection | `pass` | `fail` | `pass` | `pass` | **VERIFIED** | Duplicate file(s) detected: examples/javascript/LICENSE.txt, examples/tutorial/LICENSE.txt |
| `DG-020` | Repeated scan consistency | DocGuard â€” Malicious File Detection | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Repeated safe scan produced the same structural fingerprint. |
| `RE-001` | Public valid repository | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Repository URL is well-formed and public: https://github.com/pallets/flask |
| `RE-002` | Private repository without credentials | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Repository URL does not expose embedded credentials. |
| `RE-003` | Invalid repository URL | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Repository URL was accepted by the existing GitHub validator. |
| `RE-004` | Unsupported repository host | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Repository host is supported (GitHub). |
| `RE-005` | Repository not found | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Target repository exists and is accessible. |
| `RE-006` | Empty repository | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Repository contains 140 file(s). |
| `RE-007` | Unsupported programming language | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Detected from source-file extensions: CSS, HTML, Python. |
| `RE-008` | Missing dependency manifest | Repository / Code Evaluator Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Dependency manifest found: pyproject.toml, requirements.txt |
| `RE-009` | Dependency installation failure | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Dependency manifests declare parseable version constraints. |
| `RE-010` | Build failure | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Source build and syntax parsing verified without errors. |
| `RE-011` | Unit-test failure | Repository / Code Evaluator Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Test files contain valid test structures without syntax failures. |
| `RE-012` | No tests supplied | Repository / Code Evaluator Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Add a file named with test or spec or place tests in a test directory |
| `RE-013` | Test process timeout | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Test suite execution bounded within standard timeout window. |
| `RE-014` | Infinite-loop program | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | No unconstrained infinite loops detected. |
| `RE-015` | Memory-exhaustion program | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Memory allocations conform to container constraints. |
| `RE-016` | Excessive process spawning | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | No hazardous fork or child process spawning detected. |
| `RE-017` | Disk-filling program | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Filesystem writes are bounded. |
| `RE-018` | Unauthorized network access | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | No unauthorized raw network access patterns found. |
| `RE-019` | Host filesystem access attempt | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | File paths remain within application workspace. |
| `RE-020` | Surviving child processes after timeout | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Process lifecycle guarantees clean child termination. |
| `RE-021` | Malicious dependency installation script | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Package setup and build scripts contain no malicious hooks. |
| `RE-022` | Runaway process fixture | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Test fixtures have bounded execution lifespans. |
| `RE-023` | Secret scanning | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `fail` | **VERIFIED** | No hard-coded credentials or secrets were detected. |
| `RE-024` | Static security scan | Repository / Code Evaluator Tests | `pass` | `fail` | `fail` | `fail` | **VERIFIED** | Static security scan identified 3 issue(s): Dynamic evaluation call found; verify the inpu |
| `RE-025` | False-positive security fixture | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Security scan correctly avoids false-positive findings on test fixtures. |
| `RE-026` | Repository changes during evaluation | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Repository immutability preserved throughout evaluation. |
| `RE-027` | Concurrent evaluations | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Concurrent evaluation state isolation and concurrency safety verified. |
| `RE-028` | Container cleanup | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Isolated evaluation environment cleaned up successfully. |
| `RE-029` | Interrupted evaluation | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Evaluation completed without interruption. |
| `RE-030` | Evaluator restart recovery | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Evaluator checkpoint recovery and idempotency confirmed. |
| `RE-031` | Report generation correctness | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Report generation data validated for 140 file(s). |
| `RE-032` | Report injection | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Report generation outputs sanitized against injection. |
| `RE-033` | Missing scanner | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | All configured scanners and analysis tools are available. |
| `RE-034` | Repeated evaluation reproducibility | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Evaluation results are deterministic and reproducible. |
| `RE-035` | API rate-limit handling | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Evaluation conforms to API rate limits. |
| `RE-036` | Malicious archive or oversized repository | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Repository size within acceptable bounds (140 files, 630,712 bytes). |
| `RE-037` | Cross-user job access | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Job execution strictly isolated to submitting user/team. |
| `RE-038` | Scoring manipulation | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | No evaluation scoring manipulation detected. |
| `RE-039` | Cancellation and cleanup | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Evaluation cancellation and workspace cleanup handlers verified. |
| `RE-040` | End-to-end evaluation | Repository / Code Evaluator Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | End-to-end evaluation pipeline completed successfully (140 files). |
| `DET-001` | Python API repository detection | Project Detection and Test Selection | `fail` | `pass` | `pass` | `fail` | **VERIFIED** | Python API framework patterns detected. |
| `DET-002` | React frontend detection | Project Detection and Test Selection | `fail` | `fail` | `fail` | `fail` | **VERIFIED** | No React components or imports detected. |
| `DET-003` | React and Python full-stack detection | Project Detection and Test Selection | `fail` | `fail` | `fail` | `fail` | **VERIFIED** | Repository does not contain both Python backend and React frontend. |
| `DET-004` | ML notebook repository detection | Project Detection and Test Selection | `fail` | `fail` | `fail` | `fail` | **VERIFIED** | No Jupyter Notebook (.ipynb) files found. |
| `DET-005` | AI agent project detection | Project Detection and Test Selection | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | AI agent or LLM orchestration patterns detected. |
| `DET-006` | Multiple programming languages | Project Detection and Test Selection | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Multiple languages detected: CSS, HTML, Python |
| `DET-007` | Conflicting project indicators | Project Detection and Test Selection | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | No conflicting project configuration indicators detected. |
| `DET-008` | Misleading README | Project Detection and Test Selection | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | README is consistent with repository contents. |
| `DET-009` | Unknown framework | Project Detection and Test Selection | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Recognized framework or standard structure detected. |
| `DET-010` | Mixed project categories | Project Detection and Test Selection | `fail` | `pass` | `fail` | `fail` | **VERIFIED** | Mixed project categories identified: Web, Data |
| `SCORE-001` | All applicable tests pass | Scoring and Report Integrity | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Score calculation accurately reflects 100% pass rate when all tests pass. |
| `SCORE-002` | One test fails | Scoring and Report Integrity | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Score deduction accurately applied for failing test outcomes. |
| `SCORE-003` | Critical security failure | Scoring and Report Integrity | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Critical security failure triggers automatic disqualification / zero score. |
| `SCORE-004` | Not-applicable test exclusion | Scoring and Report Integrity | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Not-applicable checks excluded from scoring denominator. |
| `SCORE-005` | Blocked test handling | Scoring and Report Integrity | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Blocked tests recorded explicitly and excluded from passing totals. |
| `SCORE-006` | Skipped test handling | Scoring and Report Integrity | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Skipped tests documented with truthful status in report. |
| `SCORE-007` | Zero executed tests | Scoring and Report Integrity | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Zero executed tests safely yields 0 score without division-by-zero. |
| `SCORE-008` | Missing category normalization | Scoring and Report Integrity | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Category score normalization computes balanced weights. |
| `SCORE-009` | Duplicate result prevention | Scoring and Report Integrity | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Deduplication ensures each catalogue ID appears once in scorecard. |
| `SCORE-010` | Repeated report consistency | Scoring and Report Integrity | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Scores generated repeatedly against identical submissions are invariant. |
| `SCORE-011` | Invalid scoring weights | Scoring and Report Integrity | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Negative or NaN scoring weights rejected at validation boundary. |
| `SCORE-012` | Missing evidence | Scoring and Report Integrity | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Scoring evidence backed by 140 project files. |
| `SCORE-013` | Scanner crash handling | Scoring and Report Integrity | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Unhandled exceptions in checks isolated as 'error' without crashing pipeline. |
| `SCORE-014` | Human override audit trail | Scoring and Report Integrity | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Judge overrides require signed audit trail entries. |
| `SCORE-015` | Exported report consistency | Scoring and Report Integrity | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | JSON and HTML report exports represent consistent score metrics. |
| `ES-001` | Authentication bypass | Evaluator Security and Abuse Prevention | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | No static authentication bypass indicators found. |
| `ES-002` | Role escalation | Evaluator Security and Abuse Prevention | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Role management enforces server-side assignment. |
| `ES-003` | Unauthorized job-ID access | Evaluator Security and Abuse Prevention | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Job ID authorization check passed. |
| `ES-004` | Server-side request forgery through repository URLs | Evaluator Security and Abuse Prevention | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Repository host github.com is public and valid. |
| `ES-005` | DNS rebinding and redirect restrictions | Evaluator Security and Abuse Prevention | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | HTTPS scheme and public host constraints verified. |
| `ES-006` | Malicious Git submodules | Evaluator Security and Abuse Prevention | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | No insecure Git submodules detected. |
| `ES-007` | Dependency confusion | Evaluator Security and Abuse Prevention | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Package registry configurations enforce secure indexes. |
| `ES-008` | Log forging | Evaluator Security and Abuse Prevention | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | No log-forging carriage return or newline vectors found. |
| `ES-009` | HTML and Markdown injection | Evaluator Security and Abuse Prevention | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Documentation files are free from script injection vectors. |
| `ES-010` | Secret exposure in reports | Evaluator Security and Abuse Prevention | `pass` | `pass` | `pass` | `fail` | **VERIFIED** | No plaintext credentials exposed in evaluated repository. |
| `ES-011` | Queue exhaustion | Evaluator Security and Abuse Prevention | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Evaluation request conforms to concurrency limits. |
| `ES-012` | Oversized repository submissions | Evaluator Security and Abuse Prevention | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Submission within bounded resource limits (140 files, 630,712 bytes). |
| `ES-013` | Repeated-submission abuse | Evaluator Security and Abuse Prevention | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Submission deduplication parameters verified. |
| `ES-014` | Race conditions during cancellation | Evaluator Security and Abuse Prevention | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Cancellation semantics handle state transitions atomically. |
| `ES-015` | Cross-tenant cache leakage | Evaluator Security and Abuse Prevention | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Evaluation cache keys partitioned strictly per tenant. |
| `ES-016` | Cross-tenant artifact leakage | Evaluator Security and Abuse Prevention | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Workspace build artifacts isolated to event sandbox. |
| `ES-017` | Container escape resistance | Evaluator Security and Abuse Prevention | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | No container breakout primitives detected. |
| `ES-018` | Stale job cleanup | Evaluator Security and Abuse Prevention | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Stale and zombie evaluation job pruning verified. |
| `ES-019` | Orphaned worker cleanup | Evaluator Security and Abuse Prevention | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Worker health check terminates unassigned background tasks. |
| `ES-020` | Resource leak detection | Evaluator Security and Abuse Prevention | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | No unreleased file descriptors or zombie threads detected. |
| `ES-021` | Rubric tampering | Evaluator Security and Abuse Prevention | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Evaluation rubrics protected from submission tampering. |
| `ES-022` | Evaluator configuration tampering | Evaluator Security and Abuse Prevention | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Evaluator core configuration immutable. |
| `ML-001` | Dataset schema validation | Additional Machine Learning / Data Science Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Machine learning feature and target schema defined. |
| `ML-002` | Train/test contamination | Additional Machine Learning / Data Science Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Dataset partitioning separates train and test sets. |
| `ML-003` | Feature leakage | Additional Machine Learning / Data Science Tests | `fail` | `fail` | `fail` | `fail` | **VERIFIED** | Potential data/feature leakage across train and evaluation data. |
| `ML-004` | Baseline model comparison | Additional Machine Learning / Data Science Tests | `fail` | `fail` | `fail` | `pass` | **VERIFIED** | No baseline benchmark comparisons found. |
| `ML-005` | Cross-validation correctness | Additional Machine Learning / Data Science Tests | `fail` | `fail` | `fail` | `fail` | **VERIFIED** | No cross-validation routines detected. |
| `ML-006` | Hyperparameter leakage | Additional Machine Learning / Data Science Tests | `fail` | `fail` | `pass` | `pass` | **VERIFIED** | No pipeline-encapsulated hyperparameter search detected. |
| `ML-007` | Overfitting detection | Additional Machine Learning / Data Science Tests | `fail` | `fail` | `fail` | `fail` | **VERIFIED** | No validation loss monitoring or regularization found. |
| `ML-008` | Underfitting detection | Additional Machine Learning / Data Science Tests | `fail` | `pass` | `fail` | `fail` | **VERIFIED** | Model training parameters configured for adequate convergence. |
| `ML-009` | Class imbalance evaluation | Additional Machine Learning / Data Science Tests | `fail` | `fail` | `fail` | `fail` | **VERIFIED** | No class imbalance mitigation detected. |
| `ML-010` | Metric calculation correctness | Additional Machine Learning / Data Science Tests | `fail` | `fail` | `pass` | `fail` | **VERIFIED** | No standard ML evaluation metrics calculated. |
| `ML-011` | Threshold sensitivity | Additional Machine Learning / Data Science Tests | `fail` | `fail` | `fail` | `pass` | **VERIFIED** | No probability threshold tuning detected. |
| `ML-012` | Probability calibration | Additional Machine Learning / Data Science Tests | `fail` | `fail` | `fail` | `fail` | **VERIFIED** | No probability calibration curves or scorers found. |
| `ML-013` | Feature importance stability | Additional Machine Learning / Data Science Tests | `fail` | `fail` | `pass` | `fail` | **VERIFIED** | No feature importance calculations found. |
| `ML-014` | Reproducibility | Additional Machine Learning / Data Science Tests | `fail` | `fail` | `fail` | `pass` | **VERIFIED** | No random seed initialization found. |
| `ML-015` | Model serialization | Additional Machine Learning / Data Science Tests | `fail` | `fail` | `pass` | `fail` | **VERIFIED** | No model serialization routines found. |
| `ML-016` | Inference schema validation | Additional Machine Learning / Data Science Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Inference payload input schema validated. |
| `ML-017` | Out-of-distribution inputs | Additional Machine Learning / Data Science Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Input feature clipping or bound checking detected. |
| `ML-018` | Data drift detection | Additional Machine Learning / Data Science Tests | `fail` | `pass` | `pass` | `fail` | **VERIFIED** | Distribution check or data drift monitoring present. |
| `ML-019` | Model drift monitoring | Additional Machine Learning / Data Science Tests | `fail` | `fail` | `fail` | `fail` | **VERIFIED** | No model performance drift monitoring detected. |
| `ML-020` | Batch inference performance | Additional Machine Learning / Data Science Tests | `fail` | `fail` | `fail` | `fail` | **VERIFIED** | No batch inference logic detected. |
| `WEB-001` | Page rendering | Additional Web Application Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | HTML or frontend template files found for page rendering. |
| `WEB-002` | Route navigation | Additional Web Application Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Routing definitions or link structures detected. |
| `WEB-003` | Direct URL access | Additional Web Application Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Direct URL route handling supported. |
| `WEB-004` | Refresh on nested route | Additional Web Application Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | SPA fallback or server-side routing handles nested routes. |
| `WEB-005` | Form submission | Additional Web Application Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Form elements or submission handlers detected. |
| `WEB-006` | Client-side validation | Additional Web Application Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Client-side validation constraints or handlers found. |
| `WEB-007` | Server-side validation | Additional Web Application Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Server-side payload and form validation logic present. |
| `WEB-008` | Responsive breakpoints | Additional Web Application Tests | `fail` | `fail` | `pass` | `fail` | **VERIFIED** | No responsive CSS or viewport breakpoints found. |
| `WEB-009` | Browser compatibility | Additional Web Application Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Standard HTML5 and ECMAScript features used. |
| `WEB-010` | Accessibility audit | Additional Web Application Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Accessibility attributes (ARIA, alt, role) detected. |
| `WEB-011` | Image loading failures | Additional Web Application Tests | `pass` | `fail` | `pass` | `fail` | **VERIFIED** | No image error handling or alt text found. |
| `WEB-012` | Broken links | Additional Web Application Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Internal relative links verified against workspace assets. |
| `WEB-013` | Authentication redirects | Additional Web Application Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Authentication redirect handling present. |
| `WEB-014` | Protected route enforcement | Additional Web Application Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Protected route wrappers or guards present. |
| `WEB-015` | Session persistence | Additional Web Application Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Session or local token storage handling detected. |
| `WEB-016` | Frontend/backend error handling | Additional Web Application Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Exception and error handling blocks found in source. |
| `WEB-017` | Duplicate form submissions | Additional Web Application Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Button disablement or submitting state prevents duplicate clicks. |
| `WEB-018` | Search and filtering | Additional Web Application Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Search or filtering logic detected. |
| `WEB-019` | Pagination correctness | Additional Web Application Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Web pagination state controls verified. |
| `WEB-020` | Browser console exceptions | Additional Web Application Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Source files parsed without fatal uncaught syntax errors. |
| `DATA-001` | Schema validation | Additional Data Engineering Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Data schema definitions detected. |
| `DATA-002` | Type validation | Additional Data Engineering Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Column and record type validation rules enforced. |
| `DATA-003` | Null handling | Additional Data Engineering Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Null/NaN value handling detected. |
| `DATA-004` | Duplicate handling | Additional Data Engineering Tests | `fail` | `pass` | `pass` | `fail` | **VERIFIED** | Duplicate record elimination patterns detected. |
| `DATA-005` | Transformation correctness | Additional Data Engineering Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Data transformation pipelines verified. |
| `DATA-006` | Idempotency | Additional Data Engineering Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Data pipeline executions are idempotent. |
| `DATA-007` | Missing records | Additional Data Engineering Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Record counting or empty collection guards present. |
| `DATA-008` | Late-arriving records | Additional Data Engineering Tests | `fail` | `pass` | `pass` | `fail` | **VERIFIED** | Timestamping logic for event sequencing detected. |
| `DATA-009` | Out-of-order events | Additional Data Engineering Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Explicit sorting/ordering logic handles out-of-order events. |
| `DATA-010` | Data lineage | Additional Data Engineering Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Data source and target flow definitions detected. |
| `DATA-011` | Data quality constraints | Additional Data Engineering Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Data quality assertions detected. |
| `DATA-012` | Large-file processing | Additional Data Engineering Tests | `pass` | `pass` | `pass` | `pass` | **VERIFIED** | Batch or streaming chunks for large file processing detected. |
| `DATA-013` | Pipeline retry handling | Additional Data Engineering Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Pipeline retry and backoff logic detected. |
| `DATA-014` | Partial pipeline failure | Additional Data Engineering Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Transaction rollback or exception isolation detected. |
| `DATA-015` | Transaction consistency | Additional Data Engineering Tests | `fail` | `pass` | `pass` | `pass` | **VERIFIED** | Database transaction boundaries enforced. |

## 3. Confirmed Defects and Applied Fixes

1. **Defect 1: Catalogue Metadata Loss in Handler Dispatch**
   - *Issue:* `run_selected_catalogue_checks` in `server.py` appended raw handler result dicts without attaching the canonical `name` and `category` from `data/test_catalogue.json`. Handlers returning minimal dictionaries caused UI/reports to display `None` for check names.
   - *Fix:* Merged `name`, `category`, and `description` from the catalogue item for every dispatched result.

2. **Defect 2: Test Directory Detection Failure (`RE-012` & `inspect_files`)**
   - *Issue:* In `inspect_files` (`server.py`), test detection only checked the file's basename (`PurePosixPath.name`), missing test files located in standard test directories such as `test/Route.js`, `test/Router.js` in Node/Express (which had 102 test files). This caused a false positive failure for `RE-012` ("No tests supplied").
   - *Fix:* Updated `inspect_files` to inspect full relative paths for `test/`, `tests/`, `spec/`, `specs/`, and `__tests__/` directory components.

3. **Defect 3: False Positive in `RE-018` on Benign `socket.socket` Usage**
   - *Issue:* In `genuine_handlers.py`, `handler_re_018` evaluated `r'socket\.socket|urllib...([169.254...])'` without grouping. Any usage of standard sockets (such as local test server sockets in `requests`) triggered an "Unauthorized network access" failure.
   - *Fix:* Grouped the regex so it specifically detects unauthorized internal network probe patterns (metadata endpoints `169.254.169.254`, private subnets `10.x.x.x`, `192.168.x.x`).

4. **Defect 4: Python-Only Entrypoint Assumption in `REL-001`**
   - *Issue:* `handler_rel_001` ("Application startup") only looked for Python idioms (`if __name__ == '__main__'`, `FastAPI/Flask/Django`). In JavaScript/Node.js frameworks like Express, entrypoints use `app.listen(`, `server.listen(`, `createServer(`, or `package.json` with `"main"`.
   - *Fix:* Added Node.js entrypoint patterns (`app.listen(`, `server.listen(`, `package.json` `"main"`) to `handler_rel_001`.