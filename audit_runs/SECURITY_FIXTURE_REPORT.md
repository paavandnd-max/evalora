# EVALORA — MANDATORY SECURITY CHECK FIXTURE REPORT (SEC-001 TO SEC-010)

**Date:** 2026-10-23  
**Status:** ALL 10 MANDATORY SECURITY CHECKS VERIFIED  
**Regression Test Suite:** `test_security_fixtures.py` (10/10 Passing)  
**Applicability:** Universal Mandatory Security Baseline across all evaluation events  

---

## 1. Executive Summary

Evalora enforces a mandatory baseline of 10 security checks (`SEC-001` through `SEC-010`) that cannot be disabled or bypassed by event configurations. This report proves that every mandatory security check:
1. **Accurately identifies genuine vulnerabilities (Positive Test)**, producing structured evidence with file path, matched rule, and actionable remediation guidance.
2. **Accepts compliant implementations (Negative Test)**, passing clean codebases without friction.
3. **Rejects benign lookalikes (False Positive Prevention)**, correctly distinguishing between genuine vulnerabilities and harmless idioms such as parameterization, comments, non-secret config keys, or test mocks.

---

## 2. Security Check Verification Matrix

| Check ID | Catalogue Name | Vulnerability Class | Positive (Detection) | Negative (Clean) | Benign Lookalike (No FP) | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **SEC-001** | Hardcoded secret detection | CWE-798 / Hardcoded Secrets | ❌ Fail (Secret detected with file) | ✅ Pass | ✅ Pass (Comment/Placeholder) | **VERIFIED** |
| **SEC-002** | SQL injection prevention | CWE-89 / SQL Injection | ❌ Fail (String concat / f-string) | ✅ Pass | ✅ Pass (Parameterized `:id`) | **VERIFIED** |
| **SEC-003** | Cross-site scripting (XSS) | CWE-79 / Stored & Reflected XSS | ❌ Fail (`innerHTML` sink) | ✅ Pass | ✅ Pass (`textContent` / Escaped) | **VERIFIED** |
| **SEC-004** | Path traversal prevention | CWE-22 / Directory Traversal | ❌ Fail (`open(request.args)`) | ✅ Pass | ✅ Pass (Safe joined static path) | **VERIFIED** |
| **SEC-005** | Unauthorized access control | CWE-285 / Authorization Bypass | ❌ Fail (`is_admin = True`) | ✅ Pass | ✅ Pass (`is_admin = check()`) | **VERIFIED** |
| **SEC-006** | Broken Object-Level Auth (BOLA) | OWASP API1 / BOLA/IDOR | ❌ Fail (`WHERE id = req.id`) | ✅ Pass | ✅ Pass (`WHERE id=:id AND user=:u`) | **VERIFIED** |
| **SEC-007** | Sensitive credential logging | CWE-532 / Information Leak | ❌ Fail (`logging.info(password)`) | ✅ Pass | ✅ Pass (`logging.info(user_id)`) | **VERIFIED** |
| **SEC-008** | Unsafe object deserialization | CWE-502 / Remote Code Execution | ❌ Fail (`pickle.loads(...)`) | ✅ Pass | ✅ Pass (`json.loads`, `yaml.safe_load`) | **VERIFIED** |
| **SEC-009** | Known vulnerable dependencies | CWE-1395 / Vulnerable Packages | ❌ Fail (`flask==0.12`, `django==1.11`)| ✅ Pass | ✅ Pass (`flask>=3.0.0`, comments) | **VERIFIED** |
| **SEC-010** | Server-Side Request Forgery | CWE-918 / SSRF | ❌ Fail (`169.254.169.254`, `localhost`)| ✅ Pass | ✅ Pass (`github.com/org/repo`) | **VERIFIED** |

---

## 3. Detailed Check-by-Check Evidence & Fixture Analysis

### SEC-001: Hardcoded Secret Detection
- **Target Condition:** Detection of plain-text passwords, tokens, API keys, or private secrets in source files.
- **Positive Fixture:**
  ```python
  # config.py
  api_key = "abcdef1234567890"
  ```
  - **Result:** `state: fail`, `passed: false`
  - **Evidence:** `Credential-like literal found; move secrets to environment variables or a secret store. (config.py)`
- **Negative Fixture:**
  ```python
  api_key = os.environ.get("API_KEY")
  ```
  - **Result:** `state: pass`, `detail: No hardcoded credentials identified.`
- **Benign Lookalike Fixture:**
  ```python
  # api_key should be set via env var
  api_key = "test"
  ```
  - **Result:** `state: pass` (Correctly avoids false positive on short test placeholders and comments).

---

### SEC-002: SQL Injection Prevention
- **Target Condition:** Interpolation or concatenation of unescaped variables directly into database query strings.
- **Positive Fixture:**
  ```python
  # db.py
  db.execute(f"SELECT * FROM users WHERE id = {user_id}")
  ```
  - **Result:** `state: fail`, `passed: false`
  - **Evidence:** `SQL query appears to interpolate or concatenate values; use parameterized queries. (db.py)`
- **Negative Fixture:**
  ```python
  db.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})
  ```
  - **Result:** `state: pass`, `detail: Parameterized queries verified; no SQL concatenation.`
- **Benign Lookalike Fixture:**
  ```python
  db.execute("SELECT * FROM users WHERE active = 1")
  ```
  - **Result:** `state: pass` (Static WHERE clause with literal comparison is safe).

---

### SEC-003: Cross-Site Scripting (XSS)
- **Target Condition:** Direct assignment of unsanitized content into unescaped browser DOM sinks (`innerHTML`, `document.write`, `dangerouslySetInnerHTML`).
- **Positive Fixture:**
  ```javascript
  // app.js
  element.innerHTML = userContent;
  ```
  - **Result:** `state: fail`, `passed: false`
  - **Evidence:** `HTML injection sink found; confirm untrusted content is escaped or sanitized. (app.js)`
- **Negative Fixture:**
  ```javascript
  element.textContent = userContent;
  ```
  - **Result:** `state: pass`, `detail: No dangerous unescaped browser HTML sinks found.`
- **Benign Lookalike Fixture:**
  ```javascript
  // Note: never assign directly to innerHTML
  element.textContent = sanitize(content);
  ```
  - **Result:** `state: pass` (Comments containing sink names do not trigger false alerts).

---

### SEC-004: Path Traversal Prevention
- **Target Condition:** Direct file I/O operations taking user parameters without containment checks.
- **Positive Fixture:**
  ```python
  # server.py
  open(request.args.get("path"), "r")
  ```
  - **Result:** `state: fail`, `passed: false`
  - **Evidence:** `File access may use user-controlled path data; validate paths stay within an allowed directory. (server.py)`
- **Negative Fixture:**
  ```python
  open(os.path.join(SAFE_DIR, "report.pdf"), "r")
  ```
  - **Result:** `state: pass`, `detail: File path operations guarded against directory traversal.`
- **Benign Lookalike Fixture:**
  ```python
  open("config/settings.json", "r")
  ```
  - **Result:** `state: pass` (Static config loading is permitted).

---

### SEC-005: Obvious Admin Bypass
- **Target Condition:** Hardcoded truthy assignments or short-circuit conditionals overriding authentication or authorization.
- **Positive Fixture:**
  ```python
  # auth.py
  is_admin = True
  ```
  - **Result:** `state: fail`, `passed: false`
  - **Evidence:** `A hard-coded admin/allow-all pattern was found; verify authorization is enforced per request. (auth.py)`
- **Negative Fixture:**
  ```python
  is_admin = user.has_role("admin")
  ```
  - **Result:** `state: pass`, `detail: Access control validation checks enforced.`
- **Benign Lookalike Fixture:**
  ```python
  is_admin = False
  ```
  - **Result:** `state: pass` (Default fail-closed flag is permitted).

---

### SEC-006: Broken Object-Level Authorization (BOLA/IDOR)
- **Target Condition:** Querying sensitive entities by raw record identifier without scoping to the requesting tenant or authenticated user.
- **Positive Fixture:**
  ```python
  # dao.py
  query = "SELECT * FROM reports WHERE id = req.params.id"
  ```
  - **Result:** `state: fail`, `passed: false`
  - **Evidence:** `Missing user ownership check in query (potential BOLA/IDOR).`
- **Negative Fixture:**
  ```python
  query = "SELECT * FROM reports WHERE id = :id AND user_id = :uid"
  ```
  - **Result:** `state: pass`, `detail: Object-level queries enforce owner scoping.`
- **Benign Lookalike Fixture:**
  ```python
  query = "SELECT * FROM reports WHERE id = :id AND org_id = :org_id"
  ```
  - **Result:** `state: pass` (Tenant/organization scoping is valid).

---

### SEC-007: Sensitive Data in Logs
- **Target Condition:** Writing sensitive authentication tokens, passwords, or secrets to standard logging frameworks.
- **Positive Fixture:**
  ```python
  # auth.py
  logging.info("Attempt with password: %s", password)
  ```
  - **Result:** `state: fail`, `passed: false`
  - **Evidence:** `Potential logging of sensitive credentials detected.`
- **Negative Fixture:**
  ```python
  logging.info("User %s signed in", user_id)
  ```
  - **Result:** `state: pass`, `detail: Log messages sanitize credential arguments.`
- **Benign Lookalike Fixture:**
  ```python
  logging.info("User identity verified successfully")
  ```
  - **Result:** `state: pass` (Audit events without secret exposure pass cleanly).

---

### SEC-008: Unsafe Object Deserialization
- **Target Condition:** Use of unsafe serialization formats (Python `pickle`, unsafe `yaml.load`, Java `ObjectInputStream`) on untrusted buffers.
- **Positive Fixture:**
  ```python
  # cache.py
  data = pickle.loads(raw_bytes)
  ```
  - **Result:** `state: fail`, `passed: false`
  - **Evidence:** `Unsafe deserialization API found; accept only trusted data or use a safe parser. (cache.py)`
- **Negative Fixture:**
  ```python
  data = json.loads(raw_text)
  ```
  - **Result:** `state: pass`, `detail: No unsafe deserialization APIs used.`
- **Benign Lookalike Fixture:**
  ```python
  data = yaml.safe_load(raw_yaml)
  ```
  - **Result:** `state: pass` (Using `safe_load` avoids code execution vulnerabilities).

---

### SEC-009: Known Vulnerable Dependencies
- **Target Condition:** Explicit version pins matching known critical CVE vulnerable dependencies.
- **Positive Fixture:**
  ```text
  # requirements.txt
  flask==0.12
  ```
  - **Result:** `state: fail`, `passed: false`
  - **Evidence:** `Known vulnerable dependency version detected: flask==0.12`
- **Negative Fixture:**
  ```text
  flask>=3.0.0
  ```
  - **Result:** `state: pass`, `detail: No known high-severity vulnerable package pins found.`
- **Benign Lookalike Fixture:**
  ```text
  flask>=2.3.0
  # upgraded from 0.12
  ```
  - **Result:** `state: pass` (Version comments do not trigger false alerts).

---

### SEC-010: Server-Side Request Forgery (SSRF)
- **Target Condition:** External repository URL pointing to internal network segments, link-local metadata endpoints (`169.254.169.254`), or loopback interfaces (`127.0.0.1`, `localhost`).
- **Positive Fixture:**
  ```python
  repository_url = "http://169.254.169.254/latest/meta-data/"
  ```
  - **Result:** `state: fail`, `passed: false`
  - **Evidence:** `SSRF target prohibited: 169.254.169.254`
- **Negative Fixture:**
  ```python
  repository_url = "https://github.com/my-org/my-project"
  ```
  - **Result:** `state: pass`, `detail: Repository host github.com verified safe against SSRF.`
- **Benign Lookalike Fixture:**
  ```python
  repository_url = "https://github.com/my-org/mock-localhost-tool"
  ```
  - **Result:** `state: pass` (Legitimate public repo names containing 'localhost' are allowed).

---

## 4. Verification and Enforcement Guarantee

1. **Mandatory Inclusion:** Evalora's `resolve_event_test_selection` and `run_selected_catalogue_checks` ensure that all 10 security checks are always executed or verified, regardless of customized event test presets.
2. **Deterministic Output:** Every security check outputs structured JSON with unambiguous `pass` / `fail` states and concrete textual evidence.
3. **Automated CI Regression:** The test suite `test_security_fixtures.py` is integrated directly into `unittest` discovery, preventing regressions in future releases.
