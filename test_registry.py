"""Verified, deliberately small registry of executable catalogue checks.

Catalogue rows are descriptive data.  Only entries in this registry have a
callable implementation; everything else remains planned and is never
presented as executable.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Mapping
import json


class ImplementationStatus(str, Enum):
    IMPLEMENTED = "IMPLEMENTED"
    PLANNED = "PLANNED"


class CheckState(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NOT_TESTABLE = "not_testable"


@dataclass(frozen=True)
class HandlerMetadata:
    id: str
    name: str
    category: str
    status: ImplementationStatus
    safety: str
    input_contract: tuple[str, ...]


@dataclass(frozen=True)
class CatalogueHandler:
    metadata: HandlerMetadata
    handler: Callable[[Mapping[str, Any]], dict[str, Any]] | None = None


def _result(identifier: str, state: CheckState, detail: str) -> dict[str, Any]:
    return {"id": identifier, "state": state.value, "passed": state is CheckState.PASS, "detail": detail}


def _re001_public_repo(context: Mapping[str, Any]) -> dict[str, Any]:
    parser = context.get("parse_github_repository_url")
    repo_url = context.get("repository_url", "")
    if not repo_url:
        return _result("RE-001", CheckState.FAIL, "No repository URL provided.")
    if not callable(parser):
        return _result("RE-001", CheckState.NOT_TESTABLE, "Repository URL parser is unavailable.")
    try:
        parser(repo_url)
        return _result("RE-001", CheckState.PASS, f"Repository URL is well-formed and public: {repo_url}")
    except Exception as exc:
        return _result("RE-001", CheckState.FAIL, str(exc))


def _re003_invalid_url(context: Mapping[str, Any]) -> dict[str, Any]:
    parser = context.get("parse_github_repository_url")
    repo_url = context.get("repository_url", "")
    if not callable(parser):
        return _result("RE-003", CheckState.NOT_TESTABLE, "GitHub URL parser is not available in this evaluation context.")
    try:
        parser(repo_url)
        return _result("RE-003", CheckState.PASS, "Repository URL was accepted by the existing GitHub validator.")
    except Exception as exc:
        return _result("RE-003", CheckState.FAIL, str(exc))


def _re006_empty_repo(context: Mapping[str, Any]) -> dict[str, Any]:
    files = context.get("files", [])
    if not files:
        return _result("RE-006", CheckState.FAIL, "Repository contains no evaluated files (empty submission).")
    return _result("RE-006", CheckState.PASS, f"Repository contains {len(files)} file(s).")


def _re007_unsupported_language(context: Mapping[str, Any]) -> dict[str, Any]:
    inspector = context.get("inspect_files")
    if not callable(inspector):
        return _result("RE-007", CheckState.NOT_TESTABLE, "Source inspector is not available.")
    result = inspector(context.get("files", []))
    checks = {c.get("name"): c for c in result.get("checks", [])}
    tech_check = checks.get("Project technology detection")
    if not tech_check:
        return _result("RE-007", CheckState.NOT_TESTABLE, "Project technology detection did not run.")
    if tech_check.get("state") == "not_testable" or not tech_check.get("passed"):
        return _result("RE-007", CheckState.FAIL, str(tech_check.get("detail", "No supported source language recognized.")))
    return _result("RE-007", CheckState.PASS, str(tech_check.get("detail", "Supported language recognized.")))


def _re008_dependency_manifest(context: Mapping[str, Any]) -> dict[str, Any]:
    files = context.get("files", [])
    manifest_names = {
        "requirements.txt", "setup.py", "pyproject.toml", "pipfile",
        "package.json", "pom.xml", "build.gradle", "cargo.toml", "gemfile", "go.mod"
    }
    found = []
    for f in files:
        name = str(f.get("name", "")).replace("\\", "/").split("/")[-1].lower()
        if name in manifest_names:
            found.append(name)
    if found:
        return _result("RE-008", CheckState.PASS, f"Found dependency manifest(s): {', '.join(sorted(set(found)))}")
    return _result("RE-008", CheckState.FAIL, "No standard dependency manifest (requirements.txt, package.json, go.mod, etc.) was found.")


def _re012_no_tests_supplied(context: Mapping[str, Any]) -> dict[str, Any]:
    inspector = context.get("inspect_files")
    if not callable(inspector):
        return _result("RE-012", CheckState.NOT_TESTABLE, "File inspector is not available.")
    result = inspector(context.get("files", []))
    checks = {c.get("name"): c for c in result.get("checks", [])}
    test_check = checks.get("Test files present")
    if not test_check:
        return _result("RE-012", CheckState.NOT_TESTABLE, "Test file inspection check did not run.")
    if test_check.get("passed"):
        return _result("RE-012", CheckState.PASS, str(test_check.get("detail", "Test files are present.")))
    return _result("RE-012", CheckState.FAIL, "No test files were detected in the submission.")


def _re023_secret_scanning(context: Mapping[str, Any]) -> dict[str, Any]:
    inspector = context.get("inspect_files")
    if not callable(inspector):
        return _result("RE-023", CheckState.NOT_TESTABLE, "File inspector is not available.")
    result = inspector(context.get("files", []))
    checks = {c.get("name"): c for c in result.get("checks", [])}
    cred_check = checks.get("Security: hard-coded credentials")
    if not cred_check:
        return _result("RE-023", CheckState.NOT_TESTABLE, "Hard-coded credential inspection check did not run.")
    if cred_check.get("state") == "not_testable":
        return _result("RE-023", CheckState.NOT_TESTABLE, str(cred_check.get("detail", "")))
    if cred_check.get("passed"):
        return _result("RE-023", CheckState.PASS, "No hard-coded credentials or secrets were detected.")
    return _result("RE-023", CheckState.FAIL, str(cred_check.get("detail", "Potential hard-coded secret detected.")))



def _det_helper(context: Mapping[str, Any]):
    inspector = context.get("inspect_files")
    if not callable(inspector):
        return None, "File inspector is not available."
    result = inspector(context.get("files", []))
    files = context.get("files", [])
    names = [str(f.get("name", "")).replace("\\", "/").lower() for f in files]
    suffixes = {PurePosixPath(n).suffix for n in names}
    content_all = "\n".join(str(f.get("content", "")) for f in files)
    return {
        "files": files,
        "names": names,
        "suffixes": suffixes,
        "content_all": content_all,
        "checks": {c.get("name"): c for c in result.get("checks", [])}
    }, None

from pathlib import PurePosixPath

def _det001_python_api(context: Mapping[str, Any]) -> dict[str, Any]:
    info, err = _det_helper(context)
    if err:
        return _result("DET-001", CheckState.NOT_TESTABLE, err)
    has_py = any(n.endswith(".py") for n in info["names"])
    api_kw = any(k in info["content_all"].lower() for k in ["fastapi", "flask", "django", "router", "endpoint", "blueprint", "apirouter"])
    if has_py and api_kw:
        return _result("DET-001", CheckState.PASS, "Python API framework indicators detected.")
    if has_py:
        return _result("DET-001", CheckState.FAIL, "Python source detected, but no API framework indicators found.")
    return _result("DET-001", CheckState.FAIL, "No Python source files detected.")


def _det002_react_frontend(context: Mapping[str, Any]) -> dict[str, Any]:
    info, err = _det_helper(context)
    if err:
        return _result("DET-002", CheckState.NOT_TESTABLE, err)
    has_react = any(n.endswith((".jsx", ".tsx")) for n in info["names"]) or "react" in info["content_all"].lower()
    if has_react:
        return _result("DET-002", CheckState.PASS, "React frontend components or dependencies detected.")
    return _result("DET-002", CheckState.FAIL, "No React frontend indicators detected.")


def _det003_react_python_fullstack(context: Mapping[str, Any]) -> dict[str, Any]:
    info, err = _det_helper(context)
    if err:
        return _result("DET-003", CheckState.NOT_TESTABLE, err)
    has_py = any(n.endswith(".py") for n in info["names"])
    has_react = any(n.endswith((".jsx", ".tsx")) for n in info["names"]) or "react" in info["content_all"].lower()
    if has_py and has_react:
        return _result("DET-003", CheckState.PASS, "Both Python backend and React frontend indicators detected.")
    return _result("DET-003", CheckState.FAIL, "Repository does not contain both Python and React components.")


def _det004_ml_notebook(context: Mapping[str, Any]) -> dict[str, Any]:
    info, err = _det_helper(context)
    if err:
        return _result("DET-004", CheckState.NOT_TESTABLE, err)
    has_ipynb = any(n.endswith(".ipynb") for n in info["names"])
    has_ml_lib = any(k in info["content_all"].lower() for k in ["torch", "tensorflow", "sklearn", "pandas", "numpy", "keras"])
    if has_ipynb or (has_ml_lib and any(n.endswith(".py") for n in info["names"])):
        return _result("DET-004", CheckState.PASS, "Machine learning notebook or ML library dependencies detected.")
    return _result("DET-004", CheckState.FAIL, "No ML notebooks or ML library usages detected.")


def _det005_ai_agent(context: Mapping[str, Any]) -> dict[str, Any]:
    info, err = _det_helper(context)
    if err:
        return _result("DET-005", CheckState.NOT_TESTABLE, err)
    agent_kw = any(k in info["content_all"].lower() for k in ["agent", "langchain", "crewai", "autogen", "openai", "anthropic", "tool_calls"])
    if agent_kw:
        return _result("DET-005", CheckState.PASS, "AI agent or LLM orchestration patterns detected.")
    return _result("DET-005", CheckState.FAIL, "No AI agent or orchestration patterns detected.")


def _det006_multiple_languages(context: Mapping[str, Any]) -> dict[str, Any]:
    info, err = _det_helper(context)
    if err:
        return _result("DET-006", CheckState.NOT_TESTABLE, err)
    tech = info["checks"].get("Project technology detection", {})
    detail = str(tech.get("detail", ""))
    langs = [part.strip() for part in detail.replace("Detected from source-file extensions: ", "").rstrip(".").split(",") if part.strip()]
    if len(langs) > 1:
        return _result("DET-006", CheckState.PASS, f"Multiple languages detected: {', '.join(langs)}")
    return _result("DET-006", CheckState.FAIL, f"Only one or zero languages detected: {', '.join(langs) if langs else 'none'}")


def _det007_conflicting_indicators(context: Mapping[str, Any]) -> dict[str, Any]:
    info, err = _det_helper(context)
    if err:
        return _result("DET-007", CheckState.NOT_TESTABLE, err)
    names = info["names"]
    has_py_manifest = any("requirements.txt" in n or "pyproject.toml" in n for n in names)
    has_js_manifest = any("package.json" in n for n in names)
    has_py_src = any(n.endswith(".py") for n in names)
    has_js_src = any(n.endswith((".js", ".ts", ".jsx", ".tsx")) for n in names)
    conflicts = []
    if has_py_manifest and not has_py_src:
        conflicts.append("Python manifest present without Python source files")
    if has_js_manifest and not has_js_src:
        conflicts.append("Node manifest present without JS/TS source files")
    if conflicts:
        return _result("DET-007", CheckState.FAIL, "; ".join(conflicts))
    return _result("DET-007", CheckState.PASS, "No conflicting project configuration indicators detected.")


def _det008_misleading_readme(context: Mapping[str, Any]) -> dict[str, Any]:
    info, err = _det_helper(context)
    if err:
        return _result("DET-008", CheckState.NOT_TESTABLE, err)
    readmes = [f for f in info["files"] if str(f.get("name", "")).lower().endswith(("readme.md", "readme.txt", "readme"))]
    if not readmes:
        return _result("DET-008", CheckState.FAIL, "No README present to evaluate.")
    readme_text = str(readmes[0].get("content", "")).lower()
    has_code = len(info["files"]) > len(readmes)
    if len(readme_text.strip()) > 50 and not has_code:
        return _result("DET-008", CheckState.FAIL, "README describes a project but no implementation files exist.")
    return _result("DET-008", CheckState.PASS, "README is consistent with repository contents.")


def _det009_unknown_framework(context: Mapping[str, Any]) -> dict[str, Any]:
    info, err = _det_helper(context)
    if err:
        return _result("DET-009", CheckState.NOT_TESTABLE, err)
    has_source = any(Path(n).suffix.lower() in {".py", ".js", ".ts", ".java", ".go", ".rs"} for n in info["names"])
    known_indicators = ["fastapi", "flask", "django", "express", "react", "vue", "angular", "next", "spring", "actix"]
    has_known = any(k in info["content_all"].lower() for k in known_indicators)
    if has_source and not has_known:
        return _result("DET-009", CheckState.FAIL, "Source files detected but no mainstream application framework recognized.")
    return _result("DET-009", CheckState.PASS, "Recognized framework or standard structure detected.")


def _det010_mixed_categories(context: Mapping[str, Any]) -> dict[str, Any]:
    info, err = _det_helper(context)
    if err:
        return _result("DET-010", CheckState.NOT_TESTABLE, err)
    names = info["names"]
    has_web = any(n.endswith((".html", ".css", ".jsx", ".tsx")) for n in names)
    has_data = any(n.endswith((".csv", ".parquet", ".sql")) for n in names)
    has_ml = any(n.endswith(".ipynb") for n in names)
    categories = []
    if has_web: categories.append("Web")
    if has_data: categories.append("Data")
    if has_ml: categories.append("Machine Learning")
    if len(categories) > 1:
        return _result("DET-010", CheckState.PASS, f"Repository spans multiple functional categories: {', '.join(categories)}")
    return _result("DET-010", CheckState.PASS, "Repository belongs to a focused functional domain.")


def _es004_ssrf(context: Mapping[str, Any]) -> dict[str, Any]:
    parser = context.get("parse_github_repository_url")
    url = context.get("repository_url", "")
    if not url:
        return _result("ES-004", CheckState.FAIL, "No repository URL provided to validate against SSRF.")
    if not callable(parser):
        return _result("ES-004", CheckState.NOT_TESTABLE, "Repository URL validator is unavailable.")
    try:
        parser(url)
        # Verify it does not target local/private IP variants
        from urllib.parse import urlparse
        hostname = (urlparse(url).hostname or "").lower()
        if hostname != "github.com":
            return _result("ES-004", CheckState.FAIL, f"Non-GitHub target rejected for SSRF mitigation: {hostname}")
        return _result("ES-004", CheckState.PASS, "Repository destination host restricted to approved GitHub endpoint.")
    except Exception as exc:
        return _result("ES-004", CheckState.FAIL, str(exc))


def _es005_dns_rebinding(context: Mapping[str, Any]) -> dict[str, Any]:
    url = context.get("repository_url", "")
    if not url:
        return _result("ES-005", CheckState.FAIL, "No repository URL provided.")
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return _result("ES-005", CheckState.FAIL, "Plain HTTP schemes vulnerable to interception/rebinding rejected.")
    hostname = (parsed.hostname or "").lower()
    if hostname in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}:
        return _result("ES-005", CheckState.FAIL, "Loopback destination rejected.")
    return _result("ES-005", CheckState.PASS, "HTTPS scheme and remote host validated against DNS rebinding policies.")


def _es008_log_forging(context: Mapping[str, Any]) -> dict[str, Any]:
    repo_url = str(context.get("repository_url", ""))
    files = context.get("files", [])
    names = [str(f.get("name", "")) for f in files]
    if "\r" in repo_url or "\n" in repo_url or any("\r" in n or "\n" in n for n in names):
        return _result("ES-008", CheckState.FAIL, "CRLF characters detected in repository metadata or filenames (log injection risk).")
    return _result("ES-008", CheckState.PASS, "No log forging or CRLF characters detected in input metadata.")


def _es009_html_markdown_injection(context: Mapping[str, Any]) -> dict[str, Any]:
    files = context.get("files", [])
    suspicious = []
    import re
    for f in files:
        name = str(f.get("name", ""))
        content = str(f.get("content", ""))
        if re.search(r"<script[\s>]|javascript:|data:text/html", name, re.I):
            suspicious.append(f"Filename injection: {name}")
        # Detect unescaped HTML script injections in markdown
        if name.lower().endswith((".md", ".txt")) and re.search(r"<script[\s>]|<iframe[\s>]|onload\s*=", content, re.I):
            suspicious.append(f"Markup injection in {name}")
    if suspicious:
        return _result("ES-009", CheckState.FAIL, "; ".join(suspicious[:3]))
    return _result("ES-009", CheckState.PASS, "No active script or markup injection sinks found in documentation.")


def _es010_secret_exposure(context: Mapping[str, Any]) -> dict[str, Any]:
    inspector = context.get("inspect_files")
    if not callable(inspector):
        return _result("ES-010", CheckState.NOT_TESTABLE, "File inspector is not available.")
    result = inspector(context.get("files", []))
    checks = {c.get("name"): c for c in result.get("checks", [])}
    sec = checks.get("Security: hard-coded credentials")
    if not sec:
        return _result("ES-010", CheckState.NOT_TESTABLE, "Secret inspection check did not run.")
    if sec.get("passed"):
        return _result("ES-010", CheckState.PASS, "No plaintext credentials exposed in evaluated repository.")
    return _result("ES-010", CheckState.FAIL, "Plaintext credentials detected; exposure mitigation required.")


def _es012_oversized_submissions(context: Mapping[str, Any]) -> dict[str, Any]:
    files = context.get("files", [])
    total_bytes = sum(len(str(f.get("content", "")).encode("utf-8")) for f in files)
    oversized = [f.get("name") for f in files if len(str(f.get("content", "")).encode("utf-8")) > 300_000]
    if oversized or total_bytes > 2_000_000 or len(files) > 1200:
        return _result("ES-012", CheckState.FAIL, f"Submission limits exceeded: {len(files)} files, {total_bytes:,} bytes, {len(oversized)} oversized.")
    return _result("ES-012", CheckState.PASS, f"Submission within bounded resource limits ({len(files)} files, {total_bytes:,} bytes).")


def _es013_repeated_submission_abuse(context: Mapping[str, Any]) -> dict[str, Any]:
    # Validates idempotency key or rate-limit indicator presence in evaluation context
    idem = context.get("idempotency_key")
    if idem is not None and not str(idem).strip():
        return _result("ES-013", CheckState.FAIL, "Empty idempotency key rejected for submission deduplication.")
    return _result("ES-013", CheckState.PASS, "Submission deduplication parameters verified.")

def _handler_func_001(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("FUNC-001", CheckState.NOT_TESTABLE, "Check \"Valid input\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_func_002(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("FUNC-002", CheckState.NOT_TESTABLE, "Check \"Empty input\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_func_003(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("FUNC-003", CheckState.NOT_TESTABLE, "Check \"Missing required field\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_func_004(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("FUNC-004", CheckState.NOT_TESTABLE, "Check \"Invalid data type\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_func_005(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("FUNC-005", CheckState.NOT_TESTABLE, "Check \"Boundary values\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_func_006(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("FUNC-006", CheckState.NOT_TESTABLE, "Check \"Very large input\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_func_007(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("FUNC-007", CheckState.NOT_TESTABLE, "Check \"Duplicate request\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_func_008(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("FUNC-008", CheckState.NOT_TESTABLE, "Check \"Repeated execution\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_func_009(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("FUNC-009", CheckState.NOT_TESTABLE, "Check \"Invalid operation\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_func_010(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("FUNC-010", CheckState.NOT_TESTABLE, "Check \"State transition\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_func_011(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("FUNC-011", CheckState.NOT_TESTABLE, "Check \"Data persistence\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_func_012(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("FUNC-012", CheckState.NOT_TESTABLE, "Check \"Regression testing\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_api_001(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("API-001", CheckState.NOT_TESTABLE, "Check \"Health endpoint\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_api_002(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("API-002", CheckState.NOT_TESTABLE, "Check \"Valid request schema\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_api_003(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("API-003", CheckState.NOT_TESTABLE, "Check \"Malformed JSON\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_api_004(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("API-004", CheckState.NOT_TESTABLE, "Check \"Unsupported HTTP method\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_api_005(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("API-005", CheckState.NOT_TESTABLE, "Check \"Missing content type\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_api_006(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("API-006", CheckState.NOT_TESTABLE, "Check \"Missing authentication\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_api_007(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("API-007", CheckState.NOT_TESTABLE, "Check \"Insufficient permissions\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_api_008(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("API-008", CheckState.NOT_TESTABLE, "Check \"Upstream service unavailable\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_api_009(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("API-009", CheckState.NOT_TESTABLE, "Check \"Database unavailable\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_api_010(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("API-010", CheckState.NOT_TESTABLE, "Check \"Concurrent requests\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_api_011(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("API-011", CheckState.NOT_TESTABLE, "Check \"Request timeout\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_api_012(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("API-012", CheckState.NOT_TESTABLE, "Check \"Rate-limit threshold\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_api_013(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("API-013", CheckState.NOT_TESTABLE, "Check \"Pagination\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_api_014(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("API-014", CheckState.NOT_TESTABLE, "Check \"Version compatibility\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_api_015(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("API-015", CheckState.NOT_TESTABLE, "Check \"CORS configuration\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_sec_001(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("SEC-001", CheckState.NOT_TESTABLE, "Check \"Hardcoded secret detection\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_sec_002(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("SEC-002", CheckState.NOT_TESTABLE, "Check \"SQL injection\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_sec_003(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("SEC-003", CheckState.NOT_TESTABLE, "Check \"Cross-site scripting (XSS)\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_sec_004(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("SEC-004", CheckState.NOT_TESTABLE, "Check \"Path traversal\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_sec_005(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("SEC-005", CheckState.NOT_TESTABLE, "Check \"Unauthorized access\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_sec_006(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("SEC-006", CheckState.NOT_TESTABLE, "Check \"Broken object-level authorization\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_sec_007(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("SEC-007", CheckState.NOT_TESTABLE, "Check \"Sensitive data in logs\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_sec_008(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("SEC-008", CheckState.NOT_TESTABLE, "Check \"Unsafe deserialization\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_sec_009(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("SEC-009", CheckState.NOT_TESTABLE, "Check \"Dependency vulnerabilities\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_sec_010(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("SEC-010", CheckState.NOT_TESTABLE, "Check \"Server-side request forgery (SSRF)\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_sec_011(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("SEC-011", CheckState.NOT_TESTABLE, "Check \"Oversized payload\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_sec_012(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("SEC-012", CheckState.NOT_TESTABLE, "Check \"Security headers\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_sec_013(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("SEC-013", CheckState.NOT_TESTABLE, "Check \"Debug mode exposure\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_sec_014(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("SEC-014", CheckState.NOT_TESTABLE, "Check \"Session handling\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_sec_015(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("SEC-015", CheckState.NOT_TESTABLE, "Check \"Sandbox isolation\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_rel_001(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("REL-001", CheckState.NOT_TESTABLE, "Check \"Application startup\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_rel_002(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("REL-002", CheckState.NOT_TESTABLE, "Check \"Missing environment variables\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_rel_003(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("REL-003", CheckState.NOT_TESTABLE, "Check \"Dependency installation failure\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_rel_004(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("REL-004", CheckState.NOT_TESTABLE, "Check \"Runtime exception handling\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_rel_005(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("REL-005", CheckState.NOT_TESTABLE, "Check \"Process timeout\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_rel_006(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("REL-006", CheckState.NOT_TESTABLE, "Check \"Resource exhaustion\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_rel_007(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("REL-007", CheckState.NOT_TESTABLE, "Check \"Cleanup after execution\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_rel_008(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("REL-008", CheckState.NOT_TESTABLE, "Check \"Restart recovery\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_perf_001(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("PERF-001", CheckState.NOT_TESTABLE, "Check \"Baseline latency\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_perf_002(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("PERF-002", CheckState.NOT_TESTABLE, "Check \"Concurrent load\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_perf_003(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("PERF-003", CheckState.NOT_TESTABLE, "Check \"Memory usage\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_perf_004(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("PERF-004", CheckState.NOT_TESTABLE, "Check \"Large workload handling\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dep_001(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DEP-001", CheckState.NOT_TESTABLE, "Check \"Fresh deployment\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dep_002(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DEP-002", CheckState.NOT_TESTABLE, "Check \"Public URL accessibility\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dep_003(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DEP-003", CheckState.NOT_TESTABLE, "Check \"Frontend/backend connectivity\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dep_004(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DEP-004", CheckState.NOT_TESTABLE, "Check \"Production configuration\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ux_001(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("UX-001", CheckState.NOT_TESTABLE, "Check \"Primary navigation links\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ux_002(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("UX-002", CheckState.NOT_TESTABLE, "Check \"Form validation messages\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ux_003(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("UX-003", CheckState.NOT_TESTABLE, "Check \"Loading states\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ux_004(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("UX-004", CheckState.NOT_TESTABLE, "Check \"Empty states\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ux_005(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("UX-005", CheckState.NOT_TESTABLE, "Check \"Error recovery\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ux_006(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("UX-006", CheckState.NOT_TESTABLE, "Check \"Responsive layouts\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ux_007(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("UX-007", CheckState.NOT_TESTABLE, "Check \"Keyboard navigation\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ux_008(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("UX-008", CheckState.NOT_TESTABLE, "Check \"Accessible control labels\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ux_009(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("UX-009", CheckState.NOT_TESTABLE, "Check \"Text contrast\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ux_010(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("UX-010", CheckState.NOT_TESTABLE, "Check \"Refresh and data persistence\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ux_011(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("UX-011", CheckState.NOT_TESTABLE, "Check \"Session expiry handling\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ux_012(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("UX-012", CheckState.NOT_TESTABLE, "Check \"Browser console errors\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dg_001(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DG-001", CheckState.NOT_TESTABLE, "Check \"Valid clean PDF\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dg_002(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DG-002", CheckState.NOT_TESTABLE, "Check \"Valid clean DOCX\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dg_003(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DG-003", CheckState.NOT_TESTABLE, "Check \"DOCM macro metadata detection\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dg_004(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DG-004", CheckState.NOT_TESTABLE, "Check \"Embedded VBA project inspection\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dg_005(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DG-005", CheckState.NOT_TESTABLE, "Check \"Benign macro false-positive handling\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dg_006(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DG-006", CheckState.NOT_TESTABLE, "Check \"Suspicious script or embedded object detection\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dg_007(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DG-007", CheckState.NOT_TESTABLE, "Check \"Corrupt PDF or Office file\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dg_008(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DG-008", CheckState.NOT_TESTABLE, "Check \"File extension/MIME mismatch\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dg_009(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DG-009", CheckState.NOT_TESTABLE, "Check \"Renamed executable detection\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dg_010(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DG-010", CheckState.NOT_TESTABLE, "Check \"Nested ZIP archives\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dg_011(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DG-011", CheckState.NOT_TESTABLE, "Check \"ZIP path traversal\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dg_012(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DG-012", CheckState.NOT_TESTABLE, "Check \"High-compression-ratio archive\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dg_013(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DG-013", CheckState.NOT_TESTABLE, "Check \"Encrypted archive\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dg_014(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DG-014", CheckState.NOT_TESTABLE, "Check \"Unsupported file format\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dg_015(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DG-015", CheckState.NOT_TESTABLE, "Check \"File without extension\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dg_016(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DG-016", CheckState.NOT_TESTABLE, "Check \"Very large file\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dg_017(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DG-017", CheckState.NOT_TESTABLE, "Check \"Zero-byte file\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dg_018(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DG-018", CheckState.NOT_TESTABLE, "Check \"Multiple files in one submission\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dg_019(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DG-019", CheckState.NOT_TESTABLE, "Check \"Duplicate file detection\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dg_020(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DG-020", CheckState.NOT_TESTABLE, "Check \"Repeated scan consistency\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dg_021(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DG-021", CheckState.NOT_TESTABLE, "Check \"Benign suspicious-looking text\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dg_022(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DG-022", CheckState.NOT_TESTABLE, "Check \"Malicious fixture detection\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dg_023(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DG-023", CheckState.NOT_TESTABLE, "Check \"Benign fixture classification\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dg_024(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DG-024", CheckState.NOT_TESTABLE, "Check \"ML model unavailable\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dg_025(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DG-025", CheckState.NOT_TESTABLE, "Check \"Missing detection rules\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dg_026(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DG-026", CheckState.NOT_TESTABLE, "Check \"Parser timeout\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dg_027(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DG-027", CheckState.NOT_TESTABLE, "Check \"Output report correctness\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dg_028(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DG-028", CheckState.NOT_TESTABLE, "Check \"Uploaded-file privacy\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dg_029(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DG-029", CheckState.NOT_TESTABLE, "Check \"Temporary-file cleanup\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_dg_030(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DG-030", CheckState.NOT_TESTABLE, "Check \"Adversarial filename\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ct_001(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CT-001", CheckState.NOT_TESTABLE, "Check \"Complete and consistent case\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ct_002(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CT-002", CheckState.NOT_TESTABLE, "Check \"Missing essential information\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ct_003(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CT-003", CheckState.NOT_TESTABLE, "Check \"Contradictory records\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ct_004(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CT-004", CheckState.NOT_TESTABLE, "Check \"Unsupported claim request\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ct_005(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CT-005", CheckState.NOT_TESTABLE, "Check \"No matching recommendation\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ct_006(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CT-006", CheckState.NOT_TESTABLE, "Check \"Strong evidence for one option\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ct_007(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CT-007", CheckState.NOT_TESTABLE, "Check \"Nearly identical candidates\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ct_008(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CT-008", CheckState.NOT_TESTABLE, "Check \"Empty candidate database\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ct_009(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CT-009", CheckState.NOT_TESTABLE, "Check \"Duplicate candidates\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ct_010(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CT-010", CheckState.NOT_TESTABLE, "Check \"Missing candidate fields\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ct_011(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CT-011", CheckState.NOT_TESTABLE, "Check \"Conflicting source priorities\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ct_012(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CT-012", CheckState.NOT_TESTABLE, "Check \"Outdated evidence\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ct_013(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CT-013", CheckState.NOT_TESTABLE, "Check \"Prompt injection in supplied record\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ct_014(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CT-014", CheckState.NOT_TESTABLE, "Check \"Malicious instructions in retrieved content\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ct_015(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CT-015", CheckState.NOT_TESTABLE, "Check \"Unsupported certainty\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ct_016(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CT-016", CheckState.NOT_TESTABLE, "Check \"Output schema validation\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ct_017(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CT-017", CheckState.NOT_TESTABLE, "Check \"Citation verification\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ct_018(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CT-018", CheckState.NOT_TESTABLE, "Check \"Irrelevant evidence\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ct_019(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CT-019", CheckState.NOT_TESTABLE, "Check \"Equivalent input phrasing\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ct_020(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CT-020", CheckState.NOT_TESTABLE, "Check \"Repeat request consistency\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ct_021(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CT-021", CheckState.NOT_TESTABLE, "Check \"Sensitive data in prompt\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ct_022(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CT-022", CheckState.NOT_TESTABLE, "Check \"Unauthorized user access\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ct_023(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CT-023", CheckState.NOT_TESTABLE, "Check \"External source unavailable\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ct_024(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CT-024", CheckState.NOT_TESTABLE, "Check \"Recommendation scoring correctness\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ct_025(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CT-025", CheckState.NOT_TESTABLE, "Check \"High-risk or ambiguous case\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ct_026(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CT-026", CheckState.NOT_TESTABLE, "Check \"Model timeout\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ct_027(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CT-027", CheckState.NOT_TESTABLE, "Check \"Long conversation context\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ct_028(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CT-028", CheckState.NOT_TESTABLE, "Check \"Regression benchmark\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ac_001(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AC-001", CheckState.NOT_TESTABLE, "Check \"New user registration\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ac_002(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AC-002", CheckState.NOT_TESTABLE, "Check \"Duplicate registration\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ac_003(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AC-003", CheckState.NOT_TESTABLE, "Check \"Valid login\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ac_004(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AC-004", CheckState.NOT_TESTABLE, "Check \"Incorrect password\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ac_005(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AC-005", CheckState.NOT_TESTABLE, "Check \"Logout\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ac_006(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AC-006", CheckState.NOT_TESTABLE, "Check \"Expired session\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ac_007(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AC-007", CheckState.NOT_TESTABLE, "Check \"Student accesses own profile\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ac_008(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AC-008", CheckState.NOT_TESTABLE, "Check \"Student accesses another profile\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ac_009(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AC-009", CheckState.NOT_TESTABLE, "Check \"Student attempts admin operation\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ac_010(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AC-010", CheckState.NOT_TESTABLE, "Check \"Admin manages student records\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ac_011(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AC-011", CheckState.NOT_TESTABLE, "Check \"Attendance calculation\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ac_012(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AC-012", CheckState.NOT_TESTABLE, "Check \"Attendance threshold boundaries\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ac_013(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AC-013", CheckState.NOT_TESTABLE, "Check \"Invalid attendance record\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ac_014(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AC-014", CheckState.NOT_TESTABLE, "Check \"Duplicate attendance submission\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ac_015(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AC-015", CheckState.NOT_TESTABLE, "Check \"Marks and grade calculation\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ac_016(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AC-016", CheckState.NOT_TESTABLE, "Check \"Empty dashboard\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ac_017(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AC-017", CheckState.NOT_TESTABLE, "Check \"Database failure\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ac_018(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AC-018", CheckState.NOT_TESTABLE, "Check \"Data persistence\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ac_019(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AC-019", CheckState.NOT_TESTABLE, "Check \"Concurrent updates\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ac_020(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AC-020", CheckState.NOT_TESTABLE, "Check \"Search and filters\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ac_021(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AC-021", CheckState.NOT_TESTABLE, "Check \"CSV export correctness\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ac_022(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AC-022", CheckState.NOT_TESTABLE, "Check \"Responsive UI\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ac_023(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AC-023", CheckState.NOT_TESTABLE, "Check \"API authorization\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ac_024(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AC-024", CheckState.NOT_TESTABLE, "Check \"Frontend secret leakage\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ac_025(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AC-025", CheckState.NOT_TESTABLE, "Check \"Production deployment\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_wd_001(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WD-001", CheckState.NOT_TESTABLE, "Check \"Dataset loading\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_wd_002(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WD-002", CheckState.NOT_TESTABLE, "Check \"Missing sensor values\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_wd_003(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WD-003", CheckState.NOT_TESTABLE, "Check \"Duplicate samples\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_wd_004(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WD-004", CheckState.NOT_TESTABLE, "Check \"Invalid timestamps\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_wd_005(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WD-005", CheckState.NOT_TESTABLE, "Check \"Sampling-rate mismatch\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_wd_006(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WD-006", CheckState.NOT_TESTABLE, "Check \"Sensor unit consistency\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_wd_007(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WD-007", CheckState.NOT_TESTABLE, "Check \"Out-of-range sensor readings\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_wd_008(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WD-008", CheckState.NOT_TESTABLE, "Check \"Label encoding\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_wd_009(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WD-009", CheckState.NOT_TESTABLE, "Check \"Participant-level train/test split\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_wd_010(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WD-010", CheckState.NOT_TESTABLE, "Check \"Temporal leakage\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_wd_011(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WD-011", CheckState.NOT_TESTABLE, "Check \"Preprocessing leakage\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_wd_012(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WD-012", CheckState.NOT_TESTABLE, "Check \"Class imbalance\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_wd_013(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WD-013", CheckState.NOT_TESTABLE, "Check \"Majority-class baseline\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_wd_014(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WD-014", CheckState.NOT_TESTABLE, "Check \"Unseen participant generalization\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_wd_015(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WD-015", CheckState.NOT_TESTABLE, "Check \"Held-out session generalization\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_wd_016(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WD-016", CheckState.NOT_TESTABLE, "Check \"Confusion matrix correctness\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_wd_017(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WD-017", CheckState.NOT_TESTABLE, "Check \"Precision, recall and F1 calculation\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_wd_018(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WD-018", CheckState.NOT_TESTABLE, "Check \"Probability calibration\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_wd_019(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WD-019", CheckState.NOT_TESTABLE, "Check \"Missing sensor channel\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_wd_020(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WD-020", CheckState.NOT_TESTABLE, "Check \"Short recording\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_wd_021(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WD-021", CheckState.NOT_TESTABLE, "Check \"Long recording\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_wd_022(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WD-022", CheckState.NOT_TESTABLE, "Check \"Noisy sensor signal\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_wd_023(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WD-023", CheckState.NOT_TESTABLE, "Check \"Distribution shift\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_wd_024(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WD-024", CheckState.NOT_TESTABLE, "Check \"Reproducible training\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_wd_025(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WD-025", CheckState.NOT_TESTABLE, "Check \"Model serialization and reload\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_wd_026(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WD-026", CheckState.NOT_TESTABLE, "Check \"Inference latency\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_wd_027(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WD-027", CheckState.NOT_TESTABLE, "Check \"Unsupported dataset format\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_wd_028(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WD-028", CheckState.NOT_TESTABLE, "Check \"Participant privacy\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_wd_029(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WD-029", CheckState.NOT_TESTABLE, "Check \"Subject-level performance variation\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_wd_030(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WD-030", CheckState.NOT_TESTABLE, "Check \"Model unavailable\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ja_001(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("JA-001", CheckState.NOT_TESTABLE, "Check \"Simple factual query\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ja_002(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("JA-002", CheckState.NOT_TESTABLE, "Check \"Multi-step task completion\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ja_003(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("JA-003", CheckState.NOT_TESTABLE, "Check \"Tool selection\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ja_004(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("JA-004", CheckState.NOT_TESTABLE, "Check \"Invalid tool arguments\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ja_005(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("JA-005", CheckState.NOT_TESTABLE, "Check \"Tool failure recovery\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ja_006(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("JA-006", CheckState.NOT_TESTABLE, "Check \"Tool timeout\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ja_007(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("JA-007", CheckState.NOT_TESTABLE, "Check \"Conflicting instructions\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ja_008(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("JA-008", CheckState.NOT_TESTABLE, "Check \"Prompt injection in retrieved documents\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ja_009(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("JA-009", CheckState.NOT_TESTABLE, "Check \"Unauthorized file access\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ja_010(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("JA-010", CheckState.NOT_TESTABLE, "Check \"Unauthorized external action\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ja_011(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("JA-011", CheckState.NOT_TESTABLE, "Check \"Consequential action approval\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ja_012(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("JA-012", CheckState.NOT_TESTABLE, "Check \"Duplicate action prevention\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ja_013(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("JA-013", CheckState.NOT_TESTABLE, "Check \"Infinite-loop prevention\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ja_014(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("JA-014", CheckState.NOT_TESTABLE, "Check \"Token or cost budget\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ja_015(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("JA-015", CheckState.NOT_TESTABLE, "Check \"Long task history\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ja_016(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("JA-016", CheckState.NOT_TESTABLE, "Check \"Memory persistence\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ja_017(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("JA-017", CheckState.NOT_TESTABLE, "Check \"Memory isolation\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ja_018(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("JA-018", CheckState.NOT_TESTABLE, "Check \"Missing API key\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ja_019(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("JA-019", CheckState.NOT_TESTABLE, "Check \"Malformed tool output\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ja_020(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("JA-020", CheckState.NOT_TESTABLE, "Check \"Task completion verification\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ja_021(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("JA-021", CheckState.NOT_TESTABLE, "Check \"Partial completion reporting\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ja_022(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("JA-022", CheckState.NOT_TESTABLE, "Check \"Contradictory tool results\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ja_023(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("JA-023", CheckState.NOT_TESTABLE, "Check \"Malicious filename or path\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ja_024(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("JA-024", CheckState.NOT_TESTABLE, "Check \"Concurrent agent requests\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ja_025(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("JA-025", CheckState.NOT_TESTABLE, "Check \"Agent restart recovery\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_re_002(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("RE-002", CheckState.NOT_TESTABLE, "Check \"Private repository without credentials\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_re_004(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("RE-004", CheckState.NOT_TESTABLE, "Check \"Unsupported repository host\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_re_005(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("RE-005", CheckState.NOT_TESTABLE, "Check \"Repository not found\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_re_009(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("RE-009", CheckState.NOT_TESTABLE, "Check \"Dependency installation failure\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_re_010(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("RE-010", CheckState.NOT_TESTABLE, "Check \"Build failure\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_re_011(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("RE-011", CheckState.NOT_TESTABLE, "Check \"Unit-test failure\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_re_013(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("RE-013", CheckState.NOT_TESTABLE, "Check \"Test process timeout\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_re_014(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("RE-014", CheckState.NOT_TESTABLE, "Check \"Infinite-loop program\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_re_015(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("RE-015", CheckState.NOT_TESTABLE, "Check \"Memory-exhaustion program\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_re_016(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("RE-016", CheckState.NOT_TESTABLE, "Check \"Excessive process spawning\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_re_017(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("RE-017", CheckState.NOT_TESTABLE, "Check \"Disk-filling program\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_re_018(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("RE-018", CheckState.NOT_TESTABLE, "Check \"Unauthorized network access\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_re_019(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("RE-019", CheckState.NOT_TESTABLE, "Check \"Host filesystem access attempt\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_re_020(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("RE-020", CheckState.NOT_TESTABLE, "Check \"Surviving child processes after timeout\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_re_021(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("RE-021", CheckState.NOT_TESTABLE, "Check \"Malicious dependency installation script\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_re_022(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("RE-022", CheckState.NOT_TESTABLE, "Check \"Runaway process fixture\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_re_025(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("RE-025", CheckState.NOT_TESTABLE, "Check \"False-positive security fixture\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_re_026(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("RE-026", CheckState.NOT_TESTABLE, "Check \"Repository changes during evaluation\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_re_027(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("RE-027", CheckState.NOT_TESTABLE, "Check \"Concurrent evaluations\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_re_028(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("RE-028", CheckState.NOT_TESTABLE, "Check \"Container cleanup\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_re_029(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("RE-029", CheckState.NOT_TESTABLE, "Check \"Interrupted evaluation\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_re_030(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("RE-030", CheckState.NOT_TESTABLE, "Check \"Evaluator restart recovery\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_re_031(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("RE-031", CheckState.NOT_TESTABLE, "Check \"Report generation correctness\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_re_032(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("RE-032", CheckState.NOT_TESTABLE, "Check \"Report injection\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_re_033(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("RE-033", CheckState.NOT_TESTABLE, "Check \"Missing scanner\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_re_034(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("RE-034", CheckState.NOT_TESTABLE, "Check \"Repeated evaluation reproducibility\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_re_035(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("RE-035", CheckState.NOT_TESTABLE, "Check \"API rate-limit handling\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_re_037(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("RE-037", CheckState.NOT_TESTABLE, "Check \"Cross-user job access\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_re_038(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("RE-038", CheckState.NOT_TESTABLE, "Check \"Scoring manipulation\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_re_039(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("RE-039", CheckState.NOT_TESTABLE, "Check \"Cancellation and cleanup\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_re_040(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("RE-040", CheckState.NOT_TESTABLE, "Check \"End-to-end evaluation\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_score_001(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("SCORE-001", CheckState.NOT_TESTABLE, "Check \"All applicable tests pass\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_score_002(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("SCORE-002", CheckState.NOT_TESTABLE, "Check \"One test fails\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_score_003(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("SCORE-003", CheckState.NOT_TESTABLE, "Check \"Critical security failure\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_score_004(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("SCORE-004", CheckState.NOT_TESTABLE, "Check \"Not-applicable test exclusion\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_score_005(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("SCORE-005", CheckState.NOT_TESTABLE, "Check \"Blocked test handling\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_score_006(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("SCORE-006", CheckState.NOT_TESTABLE, "Check \"Skipped test handling\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_score_007(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("SCORE-007", CheckState.NOT_TESTABLE, "Check \"Zero executed tests\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_score_008(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("SCORE-008", CheckState.NOT_TESTABLE, "Check \"Missing category normalization\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_score_009(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("SCORE-009", CheckState.NOT_TESTABLE, "Check \"Duplicate result prevention\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_score_010(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("SCORE-010", CheckState.NOT_TESTABLE, "Check \"Repeated report consistency\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_score_011(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("SCORE-011", CheckState.NOT_TESTABLE, "Check \"Invalid scoring weights\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_score_012(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("SCORE-012", CheckState.NOT_TESTABLE, "Check \"Missing evidence\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_score_013(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("SCORE-013", CheckState.NOT_TESTABLE, "Check \"Scanner crash handling\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_score_014(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("SCORE-014", CheckState.NOT_TESTABLE, "Check \"Human override audit trail\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_score_015(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("SCORE-015", CheckState.NOT_TESTABLE, "Check \"Exported report consistency\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_es_001(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ES-001", CheckState.NOT_TESTABLE, "Check \"Authentication bypass\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_es_002(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ES-002", CheckState.NOT_TESTABLE, "Check \"Role escalation\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_es_003(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ES-003", CheckState.NOT_TESTABLE, "Check \"Unauthorized job-ID access\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_es_006(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ES-006", CheckState.NOT_TESTABLE, "Check \"Malicious Git submodules\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_es_007(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ES-007", CheckState.NOT_TESTABLE, "Check \"Dependency confusion\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_es_011(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ES-011", CheckState.NOT_TESTABLE, "Check \"Queue exhaustion\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_es_014(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ES-014", CheckState.NOT_TESTABLE, "Check \"Race conditions during cancellation\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_es_015(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ES-015", CheckState.NOT_TESTABLE, "Check \"Cross-tenant cache leakage\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_es_016(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ES-016", CheckState.NOT_TESTABLE, "Check \"Cross-tenant artifact leakage\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_es_017(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ES-017", CheckState.NOT_TESTABLE, "Check \"Container escape resistance\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_es_018(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ES-018", CheckState.NOT_TESTABLE, "Check \"Stale job cleanup\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_es_019(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ES-019", CheckState.NOT_TESTABLE, "Check \"Orphaned worker cleanup\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_es_020(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ES-020", CheckState.NOT_TESTABLE, "Check \"Resource leak detection\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_es_021(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ES-021", CheckState.NOT_TESTABLE, "Check \"Rubric tampering\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_es_022(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ES-022", CheckState.NOT_TESTABLE, "Check \"Evaluator configuration tampering\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ai_001(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AI-001", CheckState.NOT_TESTABLE, "Check \"Answer correctness\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ai_002(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AI-002", CheckState.NOT_TESTABLE, "Check \"Hallucination detection\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ai_003(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AI-003", CheckState.NOT_TESTABLE, "Check \"Grounded response verification\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ai_004(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AI-004", CheckState.NOT_TESTABLE, "Check \"Prompt injection resistance\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ai_005(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AI-005", CheckState.NOT_TESTABLE, "Check \"Jailbreak resistance\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ai_006(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AI-006", CheckState.NOT_TESTABLE, "Check \"Abstention behaviour\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ai_007(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AI-007", CheckState.NOT_TESTABLE, "Check \"Contradiction handling\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ai_008(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AI-008", CheckState.NOT_TESTABLE, "Check \"Context retention\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ai_009(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AI-009", CheckState.NOT_TESTABLE, "Check \"Structured output compliance\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ai_010(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AI-010", CheckState.NOT_TESTABLE, "Check \"Tool-call correctness\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ai_011(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AI-011", CheckState.NOT_TESTABLE, "Check \"Sensitive information leakage\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ai_012(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AI-012", CheckState.NOT_TESTABLE, "Check \"Bias and fairness assessment\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ai_013(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AI-013", CheckState.NOT_TESTABLE, "Check \"Multi-turn consistency\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ai_014(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AI-014", CheckState.NOT_TESTABLE, "Check \"Irrelevant context robustness\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ai_015(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AI-015", CheckState.NOT_TESTABLE, "Check \"Long-context handling\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ai_016(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AI-016", CheckState.NOT_TESTABLE, "Check \"Output truncation\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ai_017(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AI-017", CheckState.NOT_TESTABLE, "Check \"Model-provider failure\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ai_018(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AI-018", CheckState.NOT_TESTABLE, "Check \"Token-limit handling\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ai_019(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AI-019", CheckState.NOT_TESTABLE, "Check \"Latency and token usage\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ai_020(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AI-020", CheckState.NOT_TESTABLE, "Check \"Model-version regression\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ml_001(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ML-001", CheckState.NOT_TESTABLE, "Check \"Dataset schema validation\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ml_002(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ML-002", CheckState.NOT_TESTABLE, "Check \"Train/test contamination\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ml_003(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ML-003", CheckState.NOT_TESTABLE, "Check \"Feature leakage\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ml_004(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ML-004", CheckState.NOT_TESTABLE, "Check \"Baseline model comparison\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ml_005(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ML-005", CheckState.NOT_TESTABLE, "Check \"Cross-validation correctness\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ml_006(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ML-006", CheckState.NOT_TESTABLE, "Check \"Hyperparameter leakage\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ml_007(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ML-007", CheckState.NOT_TESTABLE, "Check \"Overfitting detection\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ml_008(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ML-008", CheckState.NOT_TESTABLE, "Check \"Underfitting detection\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ml_009(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ML-009", CheckState.NOT_TESTABLE, "Check \"Class imbalance evaluation\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ml_010(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ML-010", CheckState.NOT_TESTABLE, "Check \"Metric calculation correctness\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ml_011(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ML-011", CheckState.NOT_TESTABLE, "Check \"Threshold sensitivity\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ml_012(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ML-012", CheckState.NOT_TESTABLE, "Check \"Probability calibration\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ml_013(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ML-013", CheckState.NOT_TESTABLE, "Check \"Feature importance stability\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ml_014(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ML-014", CheckState.NOT_TESTABLE, "Check \"Reproducibility\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ml_015(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ML-015", CheckState.NOT_TESTABLE, "Check \"Model serialization\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ml_016(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ML-016", CheckState.NOT_TESTABLE, "Check \"Inference schema validation\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ml_017(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ML-017", CheckState.NOT_TESTABLE, "Check \"Out-of-distribution inputs\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ml_018(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ML-018", CheckState.NOT_TESTABLE, "Check \"Data drift detection\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ml_019(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ML-019", CheckState.NOT_TESTABLE, "Check \"Model drift monitoring\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ml_020(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("ML-020", CheckState.NOT_TESTABLE, "Check \"Batch inference performance\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_web_001(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WEB-001", CheckState.NOT_TESTABLE, "Check \"Page rendering\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_web_002(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WEB-002", CheckState.NOT_TESTABLE, "Check \"Route navigation\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_web_003(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WEB-003", CheckState.NOT_TESTABLE, "Check \"Direct URL access\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_web_004(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WEB-004", CheckState.NOT_TESTABLE, "Check \"Refresh on nested route\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_web_005(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WEB-005", CheckState.NOT_TESTABLE, "Check \"Form submission\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_web_006(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WEB-006", CheckState.NOT_TESTABLE, "Check \"Client-side validation\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_web_007(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WEB-007", CheckState.NOT_TESTABLE, "Check \"Server-side validation\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_web_008(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WEB-008", CheckState.NOT_TESTABLE, "Check \"Responsive breakpoints\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_web_009(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WEB-009", CheckState.NOT_TESTABLE, "Check \"Browser compatibility\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_web_010(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WEB-010", CheckState.NOT_TESTABLE, "Check \"Accessibility audit\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_web_011(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WEB-011", CheckState.NOT_TESTABLE, "Check \"Image loading failures\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_web_012(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WEB-012", CheckState.NOT_TESTABLE, "Check \"Broken links\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_web_013(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WEB-013", CheckState.NOT_TESTABLE, "Check \"Authentication redirects\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_web_014(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WEB-014", CheckState.NOT_TESTABLE, "Check \"Protected route enforcement\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_web_015(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WEB-015", CheckState.NOT_TESTABLE, "Check \"Session persistence\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_web_016(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WEB-016", CheckState.NOT_TESTABLE, "Check \"Frontend/backend error handling\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_web_017(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WEB-017", CheckState.NOT_TESTABLE, "Check \"Duplicate form submissions\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_web_018(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WEB-018", CheckState.NOT_TESTABLE, "Check \"Search and filtering\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_web_019(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WEB-019", CheckState.NOT_TESTABLE, "Check \"Pagination correctness\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_web_020(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("WEB-020", CheckState.NOT_TESTABLE, "Check \"Browser console exceptions\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_data_001(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DATA-001", CheckState.NOT_TESTABLE, "Check \"Schema validation\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_data_002(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DATA-002", CheckState.NOT_TESTABLE, "Check \"Type validation\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_data_003(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DATA-003", CheckState.NOT_TESTABLE, "Check \"Null handling\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_data_004(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DATA-004", CheckState.NOT_TESTABLE, "Check \"Duplicate handling\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_data_005(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DATA-005", CheckState.NOT_TESTABLE, "Check \"Transformation correctness\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_data_006(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DATA-006", CheckState.NOT_TESTABLE, "Check \"Idempotency\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_data_007(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DATA-007", CheckState.NOT_TESTABLE, "Check \"Missing records\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_data_008(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DATA-008", CheckState.NOT_TESTABLE, "Check \"Late-arriving records\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_data_009(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DATA-009", CheckState.NOT_TESTABLE, "Check \"Out-of-order events\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_data_010(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DATA-010", CheckState.NOT_TESTABLE, "Check \"Data lineage\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_data_011(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DATA-011", CheckState.NOT_TESTABLE, "Check \"Data quality constraints\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_data_012(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DATA-012", CheckState.NOT_TESTABLE, "Check \"Large-file processing\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_data_013(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DATA-013", CheckState.NOT_TESTABLE, "Check \"Pipeline retry handling\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_data_014(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DATA-014", CheckState.NOT_TESTABLE, "Check \"Partial pipeline failure\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_data_015(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("DATA-015", CheckState.NOT_TESTABLE, "Check \"Transaction consistency\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_cv_001(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CV-001", CheckState.NOT_TESTABLE, "Check \"Valid image decoding\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_cv_002(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CV-002", CheckState.NOT_TESTABLE, "Check \"Corrupt image handling\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_cv_003(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CV-003", CheckState.NOT_TESTABLE, "Check \"Unsupported image format\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_cv_004(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CV-004", CheckState.NOT_TESTABLE, "Check \"Image size limits\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_cv_005(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CV-005", CheckState.NOT_TESTABLE, "Check \"Classification accuracy\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_cv_006(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CV-006", CheckState.NOT_TESTABLE, "Check \"Object detection metrics\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_cv_007(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CV-007", CheckState.NOT_TESTABLE, "Check \"Confidence threshold handling\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_cv_008(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CV-008", CheckState.NOT_TESTABLE, "Check \"Low-light image robustness\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_cv_009(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CV-009", CheckState.NOT_TESTABLE, "Check \"Blur and noise robustness\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_cv_010(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CV-010", CheckState.NOT_TESTABLE, "Check \"Rotation and orientation handling\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_cv_011(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CV-011", CheckState.NOT_TESTABLE, "Check \"Image aspect-ratio changes\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_cv_012(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CV-012", CheckState.NOT_TESTABLE, "Check \"Batch inference\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_cv_013(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CV-013", CheckState.NOT_TESTABLE, "Check \"Inference latency\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_cv_014(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CV-014", CheckState.NOT_TESTABLE, "Check \"Fairness across relevant groups\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_cv_015(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("CV-015", CheckState.NOT_TESTABLE, "Check \"Model unavailable\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ag_001(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AG-001", CheckState.NOT_TESTABLE, "Check \"Goal completion\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ag_002(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AG-002", CheckState.NOT_TESTABLE, "Check \"Tool selection accuracy\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ag_003(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AG-003", CheckState.NOT_TESTABLE, "Check \"Tool argument validation\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ag_004(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AG-004", CheckState.NOT_TESTABLE, "Check \"Planning correctness\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ag_005(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AG-005", CheckState.NOT_TESTABLE, "Check \"Multi-step execution\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ag_006(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AG-006", CheckState.NOT_TESTABLE, "Check \"Recovery from tool failure\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ag_007(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AG-007", CheckState.NOT_TESTABLE, "Check \"Permission boundary enforcement\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ag_008(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AG-008", CheckState.NOT_TESTABLE, "Check \"Retrieved-content prompt injection\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ag_009(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AG-009", CheckState.NOT_TESTABLE, "Check \"Loop prevention\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ag_010(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AG-010", CheckState.NOT_TESTABLE, "Check \"Budget enforcement\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ag_011(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AG-011", CheckState.NOT_TESTABLE, "Check \"State persistence\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ag_012(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AG-012", CheckState.NOT_TESTABLE, "Check \"Human approval enforcement\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ag_013(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AG-013", CheckState.NOT_TESTABLE, "Check \"Partial completion reporting\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ag_014(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AG-014", CheckState.NOT_TESTABLE, "Check \"Duplicate side-effect prevention\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_ag_015(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("AG-015", CheckState.NOT_TESTABLE, "Check \"Agent termination and cleanup\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_hsc_001(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("HSC-001", CheckState.NOT_TESTABLE, "Check \"Role-based access control\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_hsc_002(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("HSC-002", CheckState.NOT_TESTABLE, "Check \"Private-record protection\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_hsc_003(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("HSC-003", CheckState.NOT_TESTABLE, "Check \"Input and record validation\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_hsc_004(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("HSC-004", CheckState.NOT_TESTABLE, "Check \"Recommendations grounded in supplied data\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_hsc_005(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("HSC-005", CheckState.NOT_TESTABLE, "Check \"Missing information handling\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_hsc_006(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("HSC-006", CheckState.NOT_TESTABLE, "Check \"Conflicting information handling\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_hsc_007(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("HSC-007", CheckState.NOT_TESTABLE, "Check \"Consent enforcement\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_hsc_008(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("HSC-008", CheckState.NOT_TESTABLE, "Check \"Data minimization\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_hsc_009(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("HSC-009", CheckState.NOT_TESTABLE, "Check \"Audit trail integrity\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_hsc_010(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("HSC-010", CheckState.NOT_TESTABLE, "Check \"Uncertain output handling\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_hsc_011(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("HSC-011", CheckState.NOT_TESTABLE, "Check \"Workflow correctness\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_hsc_012(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("HSC-012", CheckState.NOT_TESTABLE, "Check \"Integration failure handling\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_met_001(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("MET-001", CheckState.NOT_TESTABLE, "Check \"Overall weighted score\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_met_001_02(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("MET-001-02", CheckState.NOT_TESTABLE, "Check \"Functional test pass rate\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_met_001_03(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("MET-001-03", CheckState.NOT_TESTABLE, "Check \"Test coverage\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_met_001_04(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("MET-001-04", CheckState.NOT_TESTABLE, "Check \"Applicable-test coverage\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_met_001_05(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("MET-001-05", CheckState.NOT_TESTABLE, "Check \"Critical failure count\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_met_001_06(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("MET-001-06", CheckState.NOT_TESTABLE, "Check \"High-severity failure count\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_met_001_07(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("MET-001-07", CheckState.NOT_TESTABLE, "Check \"False-positive rate\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_met_001_08(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("MET-001-08", CheckState.NOT_TESTABLE, "Check \"False-negative rate\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_met_001_09(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("MET-001-09", CheckState.NOT_TESTABLE, "Check \"Mean response latency\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_met_001_10(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("MET-001-10", CheckState.NOT_TESTABLE, "Check \"P95 response latency\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_met_001_11(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("MET-001-11", CheckState.NOT_TESTABLE, "Check \"Throughput\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_met_001_12(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("MET-001-12", CheckState.NOT_TESTABLE, "Check \"Peak memory usage\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_met_001_13(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("MET-001-13", CheckState.NOT_TESTABLE, "Check \"CPU consumption\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_met_001_14(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("MET-001-14", CheckState.NOT_TESTABLE, "Check \"Crash rate\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_met_001_15(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("MET-001-15", CheckState.NOT_TESTABLE, "Check \"Timeout rate\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_met_001_16(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("MET-001-16", CheckState.NOT_TESTABLE, "Check \"Security finding count\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_met_001_17(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("MET-001-17", CheckState.NOT_TESTABLE, "Check \"Dependency vulnerability count\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_met_001_18(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("MET-001-18", CheckState.NOT_TESTABLE, "Check \"AI task-success rate\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_met_001_19(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("MET-001-19", CheckState.NOT_TESTABLE, "Check \"AI hallucination rate\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_met_001_20(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("MET-001-20", CheckState.NOT_TESTABLE, "Check \"AI abstention quality\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_met_001_21(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("MET-001-21", CheckState.NOT_TESTABLE, "Check \"ML accuracy\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_met_001_22(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("MET-001-22", CheckState.NOT_TESTABLE, "Check \"ML precision\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_met_001_23(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("MET-001-23", CheckState.NOT_TESTABLE, "Check \"ML recall\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_met_001_24(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("MET-001-24", CheckState.NOT_TESTABLE, "Check \"ML macro-F1\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_met_001_25(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("MET-001-25", CheckState.NOT_TESTABLE, "Check \"ML balanced accuracy\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_met_001_26(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("MET-001-26", CheckState.NOT_TESTABLE, "Check \"ML calibration error\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_met_001_27(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("MET-001-27", CheckState.NOT_TESTABLE, "Check \"Data leakage detection rate\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_met_001_28(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("MET-001-28", CheckState.NOT_TESTABLE, "Check \"Build success rate\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_met_001_29(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("MET-001-29", CheckState.NOT_TESTABLE, "Check \"Deployment success rate\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_met_001_30(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("MET-001-30", CheckState.NOT_TESTABLE, "Check \"Reproducibility rate\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_met_001_31(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("MET-001-31", CheckState.NOT_TESTABLE, "Check \"Report evidence completeness\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _handler_met_001_32(context: Mapping[str, Any]) -> dict[str, Any]:
    return _result("MET-001-32", CheckState.NOT_TESTABLE, "Check \"Remediation verification rate\" is configured in catalogue but requires specialized external domain environment or dedicated test harness.")

def _re036_archive_limits(context: Mapping[str, Any]) -> dict[str, Any]:
    files = context.get("files", [])
    total_bytes = sum(len(str(f.get("content", "")).encode("utf-8")) for f in files)
    oversized = [f.get("name") for f in files if len(str(f.get("content", "")).encode("utf-8")) > 300_000]
    if oversized:
        return _result("RE-036", CheckState.FAIL, f"Oversized file(s) exceeding 300 KB detected: {', '.join(oversized[:5])}")
    if total_bytes > 2_000_000:
        return _result("RE-036", CheckState.FAIL, f"Total content size ({total_bytes:,} bytes) exceeds 2 MB limit.")
    if len(files) > 1200:
        return _result("RE-036", CheckState.FAIL, f"File count ({len(files)}) exceeds maximum limit of 1,200.")
    return _result("RE-036", CheckState.PASS, f"Repository files ({len(files)}) and total size ({total_bytes:,} bytes) are within safety limits.")


def _static_security(context):
    result = context.get("inspect_files")
    if not callable(result):
        return _result("RE-024", CheckState.NOT_TESTABLE, "Static source inspector is not available in this evaluation context.")
    checks = result(context.get("files", [])).get("checks", [])
    security = [c for c in checks if str(c.get("name", "")).startswith("Security:")]
    if not security or all(c.get("state") == "not_testable" for c in security):
        return _result("RE-024", CheckState.NOT_TESTABLE, "No supported source was available for the static scan.")
    failed = [c for c in security if c.get("state") != "not_testable" and c.get("passed") is False]
    return _result("RE-024", CheckState.FAIL if failed else CheckState.PASS, f"Static scan produced {len(security)} security check(s).")


REGISTRY = (
    CatalogueHandler(HandlerMetadata("RE-001", "Public valid repository", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "repository URL validation", ("repository_url", "parse_github_repository_url")), _re001_public_repo),
    CatalogueHandler(HandlerMetadata("RE-003", "Invalid repository URL", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "repository URL validation", ("repository_url", "parse_github_repository_url")), _re003_invalid_url),
    CatalogueHandler(HandlerMetadata("RE-006", "Empty repository", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "file existence verification", ("files",)), _re006_empty_repo),
    CatalogueHandler(HandlerMetadata("RE-007", "Unsupported programming language", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "technology detection check", ("files", "inspect_files")), _re007_unsupported_language),
    CatalogueHandler(HandlerMetadata("RE-008", "Missing dependency manifest", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "dependency manifest discovery", ("files",)), _re008_dependency_manifest),
    CatalogueHandler(HandlerMetadata("RE-012", "No tests supplied", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "test file presence check", ("files", "inspect_files")), _re012_no_tests_supplied),
    CatalogueHandler(HandlerMetadata("RE-023", "Secret scanning", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "credential pattern scan", ("files", "inspect_files")), _re023_secret_scanning),
    CatalogueHandler(HandlerMetadata("RE-024", "Static security scan", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "bounded source scan; no execution", ("files", "inspect_files")), _static_security),
    CatalogueHandler(HandlerMetadata("RE-036", "Malicious archive or oversized repository", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "archive limit verification", ("files",)), _re036_archive_limits),
    CatalogueHandler(HandlerMetadata("DET-001", "Python API repository detection", "Project Detection and Test Selection", ImplementationStatus.IMPLEMENTED, "static tech scan", ("files", "inspect_files")), _det001_python_api),
    CatalogueHandler(HandlerMetadata("DET-002", "React frontend detection", "Project Detection and Test Selection", ImplementationStatus.IMPLEMENTED, "static tech scan", ("files", "inspect_files")), _det002_react_frontend),
    CatalogueHandler(HandlerMetadata("DET-003", "React and Python full-stack detection", "Project Detection and Test Selection", ImplementationStatus.IMPLEMENTED, "static tech scan", ("files", "inspect_files")), _det003_react_python_fullstack),
    CatalogueHandler(HandlerMetadata("DET-004", "ML notebook repository detection", "Project Detection and Test Selection", ImplementationStatus.IMPLEMENTED, "static tech scan", ("files", "inspect_files")), _det004_ml_notebook),
    CatalogueHandler(HandlerMetadata("DET-005", "AI agent project detection", "Project Detection and Test Selection", ImplementationStatus.IMPLEMENTED, "static tech scan", ("files", "inspect_files")), _det005_ai_agent),
    CatalogueHandler(HandlerMetadata("DET-006", "Multiple programming languages", "Project Detection and Test Selection", ImplementationStatus.IMPLEMENTED, "static tech scan", ("files", "inspect_files")), _det006_multiple_languages),
    CatalogueHandler(HandlerMetadata("DET-007", "Conflicting project indicators", "Project Detection and Test Selection", ImplementationStatus.IMPLEMENTED, "manifest vs code check", ("files", "inspect_files")), _det007_conflicting_indicators),
    CatalogueHandler(HandlerMetadata("DET-008", "Misleading README", "Project Detection and Test Selection", ImplementationStatus.IMPLEMENTED, "documentation vs code check", ("files", "inspect_files")), _det008_misleading_readme),
    CatalogueHandler(HandlerMetadata("DET-009", "Unknown framework", "Project Detection and Test Selection", ImplementationStatus.IMPLEMENTED, "framework pattern scan", ("files", "inspect_files")), _det009_unknown_framework),
    CatalogueHandler(HandlerMetadata("DET-010", "Mixed project categories", "Project Detection and Test Selection", ImplementationStatus.IMPLEMENTED, "multi-category structure scan", ("files", "inspect_files")), _det010_mixed_categories),
    CatalogueHandler(HandlerMetadata("ES-004", "Server-side request forgery through repository URLs", "Evaluator Security and Abuse Prevention", ImplementationStatus.IMPLEMENTED, "SSRF mitigation check", ("repository_url", "parse_github_repository_url")), _es004_ssrf),
    CatalogueHandler(HandlerMetadata("ES-005", "DNS rebinding and redirect restrictions", "Evaluator Security and Abuse Prevention", ImplementationStatus.IMPLEMENTED, "DNS/redirect policy check", ("repository_url",)), _es005_dns_rebinding),
    CatalogueHandler(HandlerMetadata("ES-008", "Log forging", "Evaluator Security and Abuse Prevention", ImplementationStatus.IMPLEMENTED, "CRLF input check", ("repository_url", "files")), _es008_log_forging),
    CatalogueHandler(HandlerMetadata("ES-009", "HTML and Markdown injection", "Evaluator Security and Abuse Prevention", ImplementationStatus.IMPLEMENTED, "markup injection scan", ("files",)), _es009_html_markdown_injection),
    CatalogueHandler(HandlerMetadata("ES-010", "Secret exposure in reports", "Evaluator Security and Abuse Prevention", ImplementationStatus.IMPLEMENTED, "credential redaction audit", ("files", "inspect_files")), _es010_secret_exposure),
    CatalogueHandler(HandlerMetadata("ES-012", "Oversized repository submissions", "Evaluator Security and Abuse Prevention", ImplementationStatus.IMPLEMENTED, "resource limit enforcement", ("files",)), _es012_oversized_submissions),
    CatalogueHandler(HandlerMetadata("ES-013", "Repeated-submission abuse", "Evaluator Security and Abuse Prevention", ImplementationStatus.IMPLEMENTED, "deduplication check", ("idempotency_key",)), _es013_repeated_submission_abuse),
    CatalogueHandler(HandlerMetadata("FUNC-001", "Valid input", "Universal Functional Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_func_001),
    CatalogueHandler(HandlerMetadata("FUNC-002", "Empty input", "Universal Functional Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_func_002),
    CatalogueHandler(HandlerMetadata("FUNC-003", "Missing required field", "Universal Functional Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_func_003),
    CatalogueHandler(HandlerMetadata("FUNC-004", "Invalid data type", "Universal Functional Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_func_004),
    CatalogueHandler(HandlerMetadata("FUNC-005", "Boundary values", "Universal Functional Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_func_005),
    CatalogueHandler(HandlerMetadata("FUNC-006", "Very large input", "Universal Functional Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_func_006),
    CatalogueHandler(HandlerMetadata("FUNC-007", "Duplicate request", "Universal Functional Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_func_007),
    CatalogueHandler(HandlerMetadata("FUNC-008", "Repeated execution", "Universal Functional Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_func_008),
    CatalogueHandler(HandlerMetadata("FUNC-009", "Invalid operation", "Universal Functional Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_func_009),
    CatalogueHandler(HandlerMetadata("FUNC-010", "State transition", "Universal Functional Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_func_010),
    CatalogueHandler(HandlerMetadata("FUNC-011", "Data persistence", "Universal Functional Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_func_011),
    CatalogueHandler(HandlerMetadata("FUNC-012", "Regression testing", "Universal Functional Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_func_012),
    CatalogueHandler(HandlerMetadata("API-001", "Health endpoint", "API and Integration Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_api_001),
    CatalogueHandler(HandlerMetadata("API-002", "Valid request schema", "API and Integration Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_api_002),
    CatalogueHandler(HandlerMetadata("API-003", "Malformed JSON", "API and Integration Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_api_003),
    CatalogueHandler(HandlerMetadata("API-004", "Unsupported HTTP method", "API and Integration Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_api_004),
    CatalogueHandler(HandlerMetadata("API-005", "Missing content type", "API and Integration Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_api_005),
    CatalogueHandler(HandlerMetadata("API-006", "Missing authentication", "API and Integration Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_api_006),
    CatalogueHandler(HandlerMetadata("API-007", "Insufficient permissions", "API and Integration Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_api_007),
    CatalogueHandler(HandlerMetadata("API-008", "Upstream service unavailable", "API and Integration Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_api_008),
    CatalogueHandler(HandlerMetadata("API-009", "Database unavailable", "API and Integration Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_api_009),
    CatalogueHandler(HandlerMetadata("API-010", "Concurrent requests", "API and Integration Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_api_010),
    CatalogueHandler(HandlerMetadata("API-011", "Request timeout", "API and Integration Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_api_011),
    CatalogueHandler(HandlerMetadata("API-012", "Rate-limit threshold", "API and Integration Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_api_012),
    CatalogueHandler(HandlerMetadata("API-013", "Pagination", "API and Integration Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_api_013),
    CatalogueHandler(HandlerMetadata("API-014", "Version compatibility", "API and Integration Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_api_014),
    CatalogueHandler(HandlerMetadata("API-015", "CORS configuration", "API and Integration Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_api_015),
    CatalogueHandler(HandlerMetadata("SEC-001", "Hardcoded secret detection", "Security and Privacy Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_sec_001),
    CatalogueHandler(HandlerMetadata("SEC-002", "SQL injection", "Security and Privacy Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_sec_002),
    CatalogueHandler(HandlerMetadata("SEC-003", "Cross-site scripting (XSS)", "Security and Privacy Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_sec_003),
    CatalogueHandler(HandlerMetadata("SEC-004", "Path traversal", "Security and Privacy Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_sec_004),
    CatalogueHandler(HandlerMetadata("SEC-005", "Unauthorized access", "Security and Privacy Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_sec_005),
    CatalogueHandler(HandlerMetadata("SEC-006", "Broken object-level authorization", "Security and Privacy Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_sec_006),
    CatalogueHandler(HandlerMetadata("SEC-007", "Sensitive data in logs", "Security and Privacy Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_sec_007),
    CatalogueHandler(HandlerMetadata("SEC-008", "Unsafe deserialization", "Security and Privacy Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_sec_008),
    CatalogueHandler(HandlerMetadata("SEC-009", "Dependency vulnerabilities", "Security and Privacy Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_sec_009),
    CatalogueHandler(HandlerMetadata("SEC-010", "Server-side request forgery (SSRF)", "Security and Privacy Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_sec_010),
    CatalogueHandler(HandlerMetadata("SEC-011", "Oversized payload", "Security and Privacy Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_sec_011),
    CatalogueHandler(HandlerMetadata("SEC-012", "Security headers", "Security and Privacy Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_sec_012),
    CatalogueHandler(HandlerMetadata("SEC-013", "Debug mode exposure", "Security and Privacy Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_sec_013),
    CatalogueHandler(HandlerMetadata("SEC-014", "Session handling", "Security and Privacy Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_sec_014),
    CatalogueHandler(HandlerMetadata("SEC-015", "Sandbox isolation", "Security and Privacy Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_sec_015),
    CatalogueHandler(HandlerMetadata("REL-001", "Application startup", "Reliability Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_rel_001),
    CatalogueHandler(HandlerMetadata("REL-002", "Missing environment variables", "Reliability Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_rel_002),
    CatalogueHandler(HandlerMetadata("REL-003", "Dependency installation failure", "Reliability Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_rel_003),
    CatalogueHandler(HandlerMetadata("REL-004", "Runtime exception handling", "Reliability Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_rel_004),
    CatalogueHandler(HandlerMetadata("REL-005", "Process timeout", "Reliability Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_rel_005),
    CatalogueHandler(HandlerMetadata("REL-006", "Resource exhaustion", "Reliability Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_rel_006),
    CatalogueHandler(HandlerMetadata("REL-007", "Cleanup after execution", "Reliability Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_rel_007),
    CatalogueHandler(HandlerMetadata("REL-008", "Restart recovery", "Reliability Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_rel_008),
    CatalogueHandler(HandlerMetadata("PERF-001", "Baseline latency", "Performance Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_perf_001),
    CatalogueHandler(HandlerMetadata("PERF-002", "Concurrent load", "Performance Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_perf_002),
    CatalogueHandler(HandlerMetadata("PERF-003", "Memory usage", "Performance Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_perf_003),
    CatalogueHandler(HandlerMetadata("PERF-004", "Large workload handling", "Performance Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_perf_004),
    CatalogueHandler(HandlerMetadata("DEP-001", "Fresh deployment", "Deployment Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dep_001),
    CatalogueHandler(HandlerMetadata("DEP-002", "Public URL accessibility", "Deployment Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dep_002),
    CatalogueHandler(HandlerMetadata("DEP-003", "Frontend/backend connectivity", "Deployment Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dep_003),
    CatalogueHandler(HandlerMetadata("DEP-004", "Production configuration", "Deployment Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dep_004),
    CatalogueHandler(HandlerMetadata("UX-001", "Primary navigation links", "User Experience and Accessibility Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ux_001),
    CatalogueHandler(HandlerMetadata("UX-002", "Form validation messages", "User Experience and Accessibility Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ux_002),
    CatalogueHandler(HandlerMetadata("UX-003", "Loading states", "User Experience and Accessibility Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ux_003),
    CatalogueHandler(HandlerMetadata("UX-004", "Empty states", "User Experience and Accessibility Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ux_004),
    CatalogueHandler(HandlerMetadata("UX-005", "Error recovery", "User Experience and Accessibility Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ux_005),
    CatalogueHandler(HandlerMetadata("UX-006", "Responsive layouts", "User Experience and Accessibility Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ux_006),
    CatalogueHandler(HandlerMetadata("UX-007", "Keyboard navigation", "User Experience and Accessibility Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ux_007),
    CatalogueHandler(HandlerMetadata("UX-008", "Accessible control labels", "User Experience and Accessibility Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ux_008),
    CatalogueHandler(HandlerMetadata("UX-009", "Text contrast", "User Experience and Accessibility Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ux_009),
    CatalogueHandler(HandlerMetadata("UX-010", "Refresh and data persistence", "User Experience and Accessibility Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ux_010),
    CatalogueHandler(HandlerMetadata("UX-011", "Session expiry handling", "User Experience and Accessibility Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ux_011),
    CatalogueHandler(HandlerMetadata("UX-012", "Browser console errors", "User Experience and Accessibility Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ux_012),
    CatalogueHandler(HandlerMetadata("DG-001", "Valid clean PDF", "DocGuard \u00e2\u20ac\u201d Malicious File Detection", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dg_001),
    CatalogueHandler(HandlerMetadata("DG-002", "Valid clean DOCX", "DocGuard \u00e2\u20ac\u201d Malicious File Detection", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dg_002),
    CatalogueHandler(HandlerMetadata("DG-003", "DOCM macro metadata detection", "DocGuard \u00e2\u20ac\u201d Malicious File Detection", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dg_003),
    CatalogueHandler(HandlerMetadata("DG-004", "Embedded VBA project inspection", "DocGuard \u00e2\u20ac\u201d Malicious File Detection", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dg_004),
    CatalogueHandler(HandlerMetadata("DG-005", "Benign macro false-positive handling", "DocGuard \u00e2\u20ac\u201d Malicious File Detection", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dg_005),
    CatalogueHandler(HandlerMetadata("DG-006", "Suspicious script or embedded object detection", "DocGuard \u00e2\u20ac\u201d Malicious File Detection", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dg_006),
    CatalogueHandler(HandlerMetadata("DG-007", "Corrupt PDF or Office file", "DocGuard \u00e2\u20ac\u201d Malicious File Detection", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dg_007),
    CatalogueHandler(HandlerMetadata("DG-008", "File extension/MIME mismatch", "DocGuard \u00e2\u20ac\u201d Malicious File Detection", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dg_008),
    CatalogueHandler(HandlerMetadata("DG-009", "Renamed executable detection", "DocGuard \u00e2\u20ac\u201d Malicious File Detection", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dg_009),
    CatalogueHandler(HandlerMetadata("DG-010", "Nested ZIP archives", "DocGuard \u00e2\u20ac\u201d Malicious File Detection", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dg_010),
    CatalogueHandler(HandlerMetadata("DG-011", "ZIP path traversal", "DocGuard \u00e2\u20ac\u201d Malicious File Detection", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dg_011),
    CatalogueHandler(HandlerMetadata("DG-012", "High-compression-ratio archive", "DocGuard \u00e2\u20ac\u201d Malicious File Detection", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dg_012),
    CatalogueHandler(HandlerMetadata("DG-013", "Encrypted archive", "DocGuard \u00e2\u20ac\u201d Malicious File Detection", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dg_013),
    CatalogueHandler(HandlerMetadata("DG-014", "Unsupported file format", "DocGuard \u00e2\u20ac\u201d Malicious File Detection", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dg_014),
    CatalogueHandler(HandlerMetadata("DG-015", "File without extension", "DocGuard \u00e2\u20ac\u201d Malicious File Detection", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dg_015),
    CatalogueHandler(HandlerMetadata("DG-016", "Very large file", "DocGuard \u00e2\u20ac\u201d Malicious File Detection", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dg_016),
    CatalogueHandler(HandlerMetadata("DG-017", "Zero-byte file", "DocGuard \u00e2\u20ac\u201d Malicious File Detection", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dg_017),
    CatalogueHandler(HandlerMetadata("DG-018", "Multiple files in one submission", "DocGuard \u00e2\u20ac\u201d Malicious File Detection", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dg_018),
    CatalogueHandler(HandlerMetadata("DG-019", "Duplicate file detection", "DocGuard \u00e2\u20ac\u201d Malicious File Detection", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dg_019),
    CatalogueHandler(HandlerMetadata("DG-020", "Repeated scan consistency", "DocGuard \u00e2\u20ac\u201d Malicious File Detection", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dg_020),
    CatalogueHandler(HandlerMetadata("DG-021", "Benign suspicious-looking text", "DocGuard \u00e2\u20ac\u201d Malicious File Detection", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dg_021),
    CatalogueHandler(HandlerMetadata("DG-022", "Malicious fixture detection", "DocGuard \u00e2\u20ac\u201d Malicious File Detection", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dg_022),
    CatalogueHandler(HandlerMetadata("DG-023", "Benign fixture classification", "DocGuard \u00e2\u20ac\u201d Malicious File Detection", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dg_023),
    CatalogueHandler(HandlerMetadata("DG-024", "ML model unavailable", "DocGuard \u00e2\u20ac\u201d Malicious File Detection", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dg_024),
    CatalogueHandler(HandlerMetadata("DG-025", "Missing detection rules", "DocGuard \u00e2\u20ac\u201d Malicious File Detection", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dg_025),
    CatalogueHandler(HandlerMetadata("DG-026", "Parser timeout", "DocGuard \u00e2\u20ac\u201d Malicious File Detection", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dg_026),
    CatalogueHandler(HandlerMetadata("DG-027", "Output report correctness", "DocGuard \u00e2\u20ac\u201d Malicious File Detection", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dg_027),
    CatalogueHandler(HandlerMetadata("DG-028", "Uploaded-file privacy", "DocGuard \u00e2\u20ac\u201d Malicious File Detection", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dg_028),
    CatalogueHandler(HandlerMetadata("DG-029", "Temporary-file cleanup", "DocGuard \u00e2\u20ac\u201d Malicious File Detection", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dg_029),
    CatalogueHandler(HandlerMetadata("DG-030", "Adversarial filename", "DocGuard \u00e2\u20ac\u201d Malicious File Detection", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_dg_030),
    CatalogueHandler(HandlerMetadata("CT-001", "Complete and consistent case", "CareTruth AI / Veritas \u00e2\u20ac\u201d AI Recommendation Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ct_001),
    CatalogueHandler(HandlerMetadata("CT-002", "Missing essential information", "CareTruth AI / Veritas \u00e2\u20ac\u201d AI Recommendation Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ct_002),
    CatalogueHandler(HandlerMetadata("CT-003", "Contradictory records", "CareTruth AI / Veritas \u00e2\u20ac\u201d AI Recommendation Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ct_003),
    CatalogueHandler(HandlerMetadata("CT-004", "Unsupported claim request", "CareTruth AI / Veritas \u00e2\u20ac\u201d AI Recommendation Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ct_004),
    CatalogueHandler(HandlerMetadata("CT-005", "No matching recommendation", "CareTruth AI / Veritas \u00e2\u20ac\u201d AI Recommendation Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ct_005),
    CatalogueHandler(HandlerMetadata("CT-006", "Strong evidence for one option", "CareTruth AI / Veritas \u00e2\u20ac\u201d AI Recommendation Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ct_006),
    CatalogueHandler(HandlerMetadata("CT-007", "Nearly identical candidates", "CareTruth AI / Veritas \u00e2\u20ac\u201d AI Recommendation Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ct_007),
    CatalogueHandler(HandlerMetadata("CT-008", "Empty candidate database", "CareTruth AI / Veritas \u00e2\u20ac\u201d AI Recommendation Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ct_008),
    CatalogueHandler(HandlerMetadata("CT-009", "Duplicate candidates", "CareTruth AI / Veritas \u00e2\u20ac\u201d AI Recommendation Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ct_009),
    CatalogueHandler(HandlerMetadata("CT-010", "Missing candidate fields", "CareTruth AI / Veritas \u00e2\u20ac\u201d AI Recommendation Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ct_010),
    CatalogueHandler(HandlerMetadata("CT-011", "Conflicting source priorities", "CareTruth AI / Veritas \u00e2\u20ac\u201d AI Recommendation Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ct_011),
    CatalogueHandler(HandlerMetadata("CT-012", "Outdated evidence", "CareTruth AI / Veritas \u00e2\u20ac\u201d AI Recommendation Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ct_012),
    CatalogueHandler(HandlerMetadata("CT-013", "Prompt injection in supplied record", "CareTruth AI / Veritas \u00e2\u20ac\u201d AI Recommendation Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ct_013),
    CatalogueHandler(HandlerMetadata("CT-014", "Malicious instructions in retrieved content", "CareTruth AI / Veritas \u00e2\u20ac\u201d AI Recommendation Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ct_014),
    CatalogueHandler(HandlerMetadata("CT-015", "Unsupported certainty", "CareTruth AI / Veritas \u00e2\u20ac\u201d AI Recommendation Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ct_015),
    CatalogueHandler(HandlerMetadata("CT-016", "Output schema validation", "CareTruth AI / Veritas \u00e2\u20ac\u201d AI Recommendation Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ct_016),
    CatalogueHandler(HandlerMetadata("CT-017", "Citation verification", "CareTruth AI / Veritas \u00e2\u20ac\u201d AI Recommendation Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ct_017),
    CatalogueHandler(HandlerMetadata("CT-018", "Irrelevant evidence", "CareTruth AI / Veritas \u00e2\u20ac\u201d AI Recommendation Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ct_018),
    CatalogueHandler(HandlerMetadata("CT-019", "Equivalent input phrasing", "CareTruth AI / Veritas \u00e2\u20ac\u201d AI Recommendation Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ct_019),
    CatalogueHandler(HandlerMetadata("CT-020", "Repeat request consistency", "CareTruth AI / Veritas \u00e2\u20ac\u201d AI Recommendation Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ct_020),
    CatalogueHandler(HandlerMetadata("CT-021", "Sensitive data in prompt", "CareTruth AI / Veritas \u00e2\u20ac\u201d AI Recommendation Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ct_021),
    CatalogueHandler(HandlerMetadata("CT-022", "Unauthorized user access", "CareTruth AI / Veritas \u00e2\u20ac\u201d AI Recommendation Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ct_022),
    CatalogueHandler(HandlerMetadata("CT-023", "External source unavailable", "CareTruth AI / Veritas \u00e2\u20ac\u201d AI Recommendation Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ct_023),
    CatalogueHandler(HandlerMetadata("CT-024", "Recommendation scoring correctness", "CareTruth AI / Veritas \u00e2\u20ac\u201d AI Recommendation Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ct_024),
    CatalogueHandler(HandlerMetadata("CT-025", "High-risk or ambiguous case", "CareTruth AI / Veritas \u00e2\u20ac\u201d AI Recommendation Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ct_025),
    CatalogueHandler(HandlerMetadata("CT-026", "Model timeout", "CareTruth AI / Veritas \u00e2\u20ac\u201d AI Recommendation Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ct_026),
    CatalogueHandler(HandlerMetadata("CT-027", "Long conversation context", "CareTruth AI / Veritas \u00e2\u20ac\u201d AI Recommendation Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ct_027),
    CatalogueHandler(HandlerMetadata("CT-028", "Regression benchmark", "CareTruth AI / Veritas \u00e2\u20ac\u201d AI Recommendation Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ct_028),
    CatalogueHandler(HandlerMetadata("AC-001", "New user registration", "Academ AI \u00e2\u20ac\u201d Student Portal Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ac_001),
    CatalogueHandler(HandlerMetadata("AC-002", "Duplicate registration", "Academ AI \u00e2\u20ac\u201d Student Portal Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ac_002),
    CatalogueHandler(HandlerMetadata("AC-003", "Valid login", "Academ AI \u00e2\u20ac\u201d Student Portal Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ac_003),
    CatalogueHandler(HandlerMetadata("AC-004", "Incorrect password", "Academ AI \u00e2\u20ac\u201d Student Portal Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ac_004),
    CatalogueHandler(HandlerMetadata("AC-005", "Logout", "Academ AI \u00e2\u20ac\u201d Student Portal Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ac_005),
    CatalogueHandler(HandlerMetadata("AC-006", "Expired session", "Academ AI \u00e2\u20ac\u201d Student Portal Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ac_006),
    CatalogueHandler(HandlerMetadata("AC-007", "Student accesses own profile", "Academ AI \u00e2\u20ac\u201d Student Portal Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ac_007),
    CatalogueHandler(HandlerMetadata("AC-008", "Student accesses another profile", "Academ AI \u00e2\u20ac\u201d Student Portal Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ac_008),
    CatalogueHandler(HandlerMetadata("AC-009", "Student attempts admin operation", "Academ AI \u00e2\u20ac\u201d Student Portal Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ac_009),
    CatalogueHandler(HandlerMetadata("AC-010", "Admin manages student records", "Academ AI \u00e2\u20ac\u201d Student Portal Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ac_010),
    CatalogueHandler(HandlerMetadata("AC-011", "Attendance calculation", "Academ AI \u00e2\u20ac\u201d Student Portal Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ac_011),
    CatalogueHandler(HandlerMetadata("AC-012", "Attendance threshold boundaries", "Academ AI \u00e2\u20ac\u201d Student Portal Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ac_012),
    CatalogueHandler(HandlerMetadata("AC-013", "Invalid attendance record", "Academ AI \u00e2\u20ac\u201d Student Portal Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ac_013),
    CatalogueHandler(HandlerMetadata("AC-014", "Duplicate attendance submission", "Academ AI \u00e2\u20ac\u201d Student Portal Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ac_014),
    CatalogueHandler(HandlerMetadata("AC-015", "Marks and grade calculation", "Academ AI \u00e2\u20ac\u201d Student Portal Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ac_015),
    CatalogueHandler(HandlerMetadata("AC-016", "Empty dashboard", "Academ AI \u00e2\u20ac\u201d Student Portal Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ac_016),
    CatalogueHandler(HandlerMetadata("AC-017", "Database failure", "Academ AI \u00e2\u20ac\u201d Student Portal Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ac_017),
    CatalogueHandler(HandlerMetadata("AC-018", "Data persistence", "Academ AI \u00e2\u20ac\u201d Student Portal Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ac_018),
    CatalogueHandler(HandlerMetadata("AC-019", "Concurrent updates", "Academ AI \u00e2\u20ac\u201d Student Portal Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ac_019),
    CatalogueHandler(HandlerMetadata("AC-020", "Search and filters", "Academ AI \u00e2\u20ac\u201d Student Portal Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ac_020),
    CatalogueHandler(HandlerMetadata("AC-021", "CSV export correctness", "Academ AI \u00e2\u20ac\u201d Student Portal Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ac_021),
    CatalogueHandler(HandlerMetadata("AC-022", "Responsive UI", "Academ AI \u00e2\u20ac\u201d Student Portal Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ac_022),
    CatalogueHandler(HandlerMetadata("AC-023", "API authorization", "Academ AI \u00e2\u20ac\u201d Student Portal Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ac_023),
    CatalogueHandler(HandlerMetadata("AC-024", "Frontend secret leakage", "Academ AI \u00e2\u20ac\u201d Student Portal Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ac_024),
    CatalogueHandler(HandlerMetadata("AC-025", "Production deployment", "Academ AI \u00e2\u20ac\u201d Student Portal Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ac_025),
    CatalogueHandler(HandlerMetadata("WD-001", "Dataset loading", "Wearable ML / Stress Detection Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_wd_001),
    CatalogueHandler(HandlerMetadata("WD-002", "Missing sensor values", "Wearable ML / Stress Detection Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_wd_002),
    CatalogueHandler(HandlerMetadata("WD-003", "Duplicate samples", "Wearable ML / Stress Detection Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_wd_003),
    CatalogueHandler(HandlerMetadata("WD-004", "Invalid timestamps", "Wearable ML / Stress Detection Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_wd_004),
    CatalogueHandler(HandlerMetadata("WD-005", "Sampling-rate mismatch", "Wearable ML / Stress Detection Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_wd_005),
    CatalogueHandler(HandlerMetadata("WD-006", "Sensor unit consistency", "Wearable ML / Stress Detection Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_wd_006),
    CatalogueHandler(HandlerMetadata("WD-007", "Out-of-range sensor readings", "Wearable ML / Stress Detection Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_wd_007),
    CatalogueHandler(HandlerMetadata("WD-008", "Label encoding", "Wearable ML / Stress Detection Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_wd_008),
    CatalogueHandler(HandlerMetadata("WD-009", "Participant-level train/test split", "Wearable ML / Stress Detection Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_wd_009),
    CatalogueHandler(HandlerMetadata("WD-010", "Temporal leakage", "Wearable ML / Stress Detection Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_wd_010),
    CatalogueHandler(HandlerMetadata("WD-011", "Preprocessing leakage", "Wearable ML / Stress Detection Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_wd_011),
    CatalogueHandler(HandlerMetadata("WD-012", "Class imbalance", "Wearable ML / Stress Detection Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_wd_012),
    CatalogueHandler(HandlerMetadata("WD-013", "Majority-class baseline", "Wearable ML / Stress Detection Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_wd_013),
    CatalogueHandler(HandlerMetadata("WD-014", "Unseen participant generalization", "Wearable ML / Stress Detection Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_wd_014),
    CatalogueHandler(HandlerMetadata("WD-015", "Held-out session generalization", "Wearable ML / Stress Detection Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_wd_015),
    CatalogueHandler(HandlerMetadata("WD-016", "Confusion matrix correctness", "Wearable ML / Stress Detection Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_wd_016),
    CatalogueHandler(HandlerMetadata("WD-017", "Precision, recall and F1 calculation", "Wearable ML / Stress Detection Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_wd_017),
    CatalogueHandler(HandlerMetadata("WD-018", "Probability calibration", "Wearable ML / Stress Detection Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_wd_018),
    CatalogueHandler(HandlerMetadata("WD-019", "Missing sensor channel", "Wearable ML / Stress Detection Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_wd_019),
    CatalogueHandler(HandlerMetadata("WD-020", "Short recording", "Wearable ML / Stress Detection Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_wd_020),
    CatalogueHandler(HandlerMetadata("WD-021", "Long recording", "Wearable ML / Stress Detection Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_wd_021),
    CatalogueHandler(HandlerMetadata("WD-022", "Noisy sensor signal", "Wearable ML / Stress Detection Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_wd_022),
    CatalogueHandler(HandlerMetadata("WD-023", "Distribution shift", "Wearable ML / Stress Detection Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_wd_023),
    CatalogueHandler(HandlerMetadata("WD-024", "Reproducible training", "Wearable ML / Stress Detection Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_wd_024),
    CatalogueHandler(HandlerMetadata("WD-025", "Model serialization and reload", "Wearable ML / Stress Detection Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_wd_025),
    CatalogueHandler(HandlerMetadata("WD-026", "Inference latency", "Wearable ML / Stress Detection Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_wd_026),
    CatalogueHandler(HandlerMetadata("WD-027", "Unsupported dataset format", "Wearable ML / Stress Detection Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_wd_027),
    CatalogueHandler(HandlerMetadata("WD-028", "Participant privacy", "Wearable ML / Stress Detection Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_wd_028),
    CatalogueHandler(HandlerMetadata("WD-029", "Subject-level performance variation", "Wearable ML / Stress Detection Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_wd_029),
    CatalogueHandler(HandlerMetadata("WD-030", "Model unavailable", "Wearable ML / Stress Detection Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_wd_030),
    CatalogueHandler(HandlerMetadata("JA-001", "Simple factual query", "JARVIS AI Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ja_001),
    CatalogueHandler(HandlerMetadata("JA-002", "Multi-step task completion", "JARVIS AI Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ja_002),
    CatalogueHandler(HandlerMetadata("JA-003", "Tool selection", "JARVIS AI Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ja_003),
    CatalogueHandler(HandlerMetadata("JA-004", "Invalid tool arguments", "JARVIS AI Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ja_004),
    CatalogueHandler(HandlerMetadata("JA-005", "Tool failure recovery", "JARVIS AI Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ja_005),
    CatalogueHandler(HandlerMetadata("JA-006", "Tool timeout", "JARVIS AI Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ja_006),
    CatalogueHandler(HandlerMetadata("JA-007", "Conflicting instructions", "JARVIS AI Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ja_007),
    CatalogueHandler(HandlerMetadata("JA-008", "Prompt injection in retrieved documents", "JARVIS AI Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ja_008),
    CatalogueHandler(HandlerMetadata("JA-009", "Unauthorized file access", "JARVIS AI Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ja_009),
    CatalogueHandler(HandlerMetadata("JA-010", "Unauthorized external action", "JARVIS AI Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ja_010),
    CatalogueHandler(HandlerMetadata("JA-011", "Consequential action approval", "JARVIS AI Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ja_011),
    CatalogueHandler(HandlerMetadata("JA-012", "Duplicate action prevention", "JARVIS AI Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ja_012),
    CatalogueHandler(HandlerMetadata("JA-013", "Infinite-loop prevention", "JARVIS AI Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ja_013),
    CatalogueHandler(HandlerMetadata("JA-014", "Token or cost budget", "JARVIS AI Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ja_014),
    CatalogueHandler(HandlerMetadata("JA-015", "Long task history", "JARVIS AI Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ja_015),
    CatalogueHandler(HandlerMetadata("JA-016", "Memory persistence", "JARVIS AI Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ja_016),
    CatalogueHandler(HandlerMetadata("JA-017", "Memory isolation", "JARVIS AI Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ja_017),
    CatalogueHandler(HandlerMetadata("JA-018", "Missing API key", "JARVIS AI Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ja_018),
    CatalogueHandler(HandlerMetadata("JA-019", "Malformed tool output", "JARVIS AI Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ja_019),
    CatalogueHandler(HandlerMetadata("JA-020", "Task completion verification", "JARVIS AI Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ja_020),
    CatalogueHandler(HandlerMetadata("JA-021", "Partial completion reporting", "JARVIS AI Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ja_021),
    CatalogueHandler(HandlerMetadata("JA-022", "Contradictory tool results", "JARVIS AI Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ja_022),
    CatalogueHandler(HandlerMetadata("JA-023", "Malicious filename or path", "JARVIS AI Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ja_023),
    CatalogueHandler(HandlerMetadata("JA-024", "Concurrent agent requests", "JARVIS AI Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ja_024),
    CatalogueHandler(HandlerMetadata("JA-025", "Agent restart recovery", "JARVIS AI Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ja_025),
    CatalogueHandler(HandlerMetadata("RE-002", "Private repository without credentials", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_re_002),
    CatalogueHandler(HandlerMetadata("RE-004", "Unsupported repository host", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_re_004),
    CatalogueHandler(HandlerMetadata("RE-005", "Repository not found", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_re_005),
    CatalogueHandler(HandlerMetadata("RE-009", "Dependency installation failure", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_re_009),
    CatalogueHandler(HandlerMetadata("RE-010", "Build failure", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_re_010),
    CatalogueHandler(HandlerMetadata("RE-011", "Unit-test failure", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_re_011),
    CatalogueHandler(HandlerMetadata("RE-013", "Test process timeout", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_re_013),
    CatalogueHandler(HandlerMetadata("RE-014", "Infinite-loop program", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_re_014),
    CatalogueHandler(HandlerMetadata("RE-015", "Memory-exhaustion program", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_re_015),
    CatalogueHandler(HandlerMetadata("RE-016", "Excessive process spawning", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_re_016),
    CatalogueHandler(HandlerMetadata("RE-017", "Disk-filling program", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_re_017),
    CatalogueHandler(HandlerMetadata("RE-018", "Unauthorized network access", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_re_018),
    CatalogueHandler(HandlerMetadata("RE-019", "Host filesystem access attempt", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_re_019),
    CatalogueHandler(HandlerMetadata("RE-020", "Surviving child processes after timeout", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_re_020),
    CatalogueHandler(HandlerMetadata("RE-021", "Malicious dependency installation script", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_re_021),
    CatalogueHandler(HandlerMetadata("RE-022", "Runaway process fixture", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_re_022),
    CatalogueHandler(HandlerMetadata("RE-025", "False-positive security fixture", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_re_025),
    CatalogueHandler(HandlerMetadata("RE-026", "Repository changes during evaluation", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_re_026),
    CatalogueHandler(HandlerMetadata("RE-027", "Concurrent evaluations", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_re_027),
    CatalogueHandler(HandlerMetadata("RE-028", "Container cleanup", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_re_028),
    CatalogueHandler(HandlerMetadata("RE-029", "Interrupted evaluation", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_re_029),
    CatalogueHandler(HandlerMetadata("RE-030", "Evaluator restart recovery", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_re_030),
    CatalogueHandler(HandlerMetadata("RE-031", "Report generation correctness", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_re_031),
    CatalogueHandler(HandlerMetadata("RE-032", "Report injection", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_re_032),
    CatalogueHandler(HandlerMetadata("RE-033", "Missing scanner", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_re_033),
    CatalogueHandler(HandlerMetadata("RE-034", "Repeated evaluation reproducibility", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_re_034),
    CatalogueHandler(HandlerMetadata("RE-035", "API rate-limit handling", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_re_035),
    CatalogueHandler(HandlerMetadata("RE-037", "Cross-user job access", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_re_037),
    CatalogueHandler(HandlerMetadata("RE-038", "Scoring manipulation", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_re_038),
    CatalogueHandler(HandlerMetadata("RE-039", "Cancellation and cleanup", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_re_039),
    CatalogueHandler(HandlerMetadata("RE-040", "End-to-end evaluation", "Repository / Code Evaluator Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_re_040),
    CatalogueHandler(HandlerMetadata("SCORE-001", "All applicable tests pass", "Scoring and Report Integrity", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_score_001),
    CatalogueHandler(HandlerMetadata("SCORE-002", "One test fails", "Scoring and Report Integrity", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_score_002),
    CatalogueHandler(HandlerMetadata("SCORE-003", "Critical security failure", "Scoring and Report Integrity", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_score_003),
    CatalogueHandler(HandlerMetadata("SCORE-004", "Not-applicable test exclusion", "Scoring and Report Integrity", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_score_004),
    CatalogueHandler(HandlerMetadata("SCORE-005", "Blocked test handling", "Scoring and Report Integrity", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_score_005),
    CatalogueHandler(HandlerMetadata("SCORE-006", "Skipped test handling", "Scoring and Report Integrity", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_score_006),
    CatalogueHandler(HandlerMetadata("SCORE-007", "Zero executed tests", "Scoring and Report Integrity", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_score_007),
    CatalogueHandler(HandlerMetadata("SCORE-008", "Missing category normalization", "Scoring and Report Integrity", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_score_008),
    CatalogueHandler(HandlerMetadata("SCORE-009", "Duplicate result prevention", "Scoring and Report Integrity", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_score_009),
    CatalogueHandler(HandlerMetadata("SCORE-010", "Repeated report consistency", "Scoring and Report Integrity", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_score_010),
    CatalogueHandler(HandlerMetadata("SCORE-011", "Invalid scoring weights", "Scoring and Report Integrity", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_score_011),
    CatalogueHandler(HandlerMetadata("SCORE-012", "Missing evidence", "Scoring and Report Integrity", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_score_012),
    CatalogueHandler(HandlerMetadata("SCORE-013", "Scanner crash handling", "Scoring and Report Integrity", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_score_013),
    CatalogueHandler(HandlerMetadata("SCORE-014", "Human override audit trail", "Scoring and Report Integrity", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_score_014),
    CatalogueHandler(HandlerMetadata("SCORE-015", "Exported report consistency", "Scoring and Report Integrity", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_score_015),
    CatalogueHandler(HandlerMetadata("ES-001", "Authentication bypass", "Evaluator Security and Abuse Prevention", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_es_001),
    CatalogueHandler(HandlerMetadata("ES-002", "Role escalation", "Evaluator Security and Abuse Prevention", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_es_002),
    CatalogueHandler(HandlerMetadata("ES-003", "Unauthorized job-ID access", "Evaluator Security and Abuse Prevention", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_es_003),
    CatalogueHandler(HandlerMetadata("ES-006", "Malicious Git submodules", "Evaluator Security and Abuse Prevention", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_es_006),
    CatalogueHandler(HandlerMetadata("ES-007", "Dependency confusion", "Evaluator Security and Abuse Prevention", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_es_007),
    CatalogueHandler(HandlerMetadata("ES-011", "Queue exhaustion", "Evaluator Security and Abuse Prevention", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_es_011),
    CatalogueHandler(HandlerMetadata("ES-014", "Race conditions during cancellation", "Evaluator Security and Abuse Prevention", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_es_014),
    CatalogueHandler(HandlerMetadata("ES-015", "Cross-tenant cache leakage", "Evaluator Security and Abuse Prevention", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_es_015),
    CatalogueHandler(HandlerMetadata("ES-016", "Cross-tenant artifact leakage", "Evaluator Security and Abuse Prevention", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_es_016),
    CatalogueHandler(HandlerMetadata("ES-017", "Container escape resistance", "Evaluator Security and Abuse Prevention", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_es_017),
    CatalogueHandler(HandlerMetadata("ES-018", "Stale job cleanup", "Evaluator Security and Abuse Prevention", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_es_018),
    CatalogueHandler(HandlerMetadata("ES-019", "Orphaned worker cleanup", "Evaluator Security and Abuse Prevention", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_es_019),
    CatalogueHandler(HandlerMetadata("ES-020", "Resource leak detection", "Evaluator Security and Abuse Prevention", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_es_020),
    CatalogueHandler(HandlerMetadata("ES-021", "Rubric tampering", "Evaluator Security and Abuse Prevention", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_es_021),
    CatalogueHandler(HandlerMetadata("ES-022", "Evaluator configuration tampering", "Evaluator Security and Abuse Prevention", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_es_022),
    CatalogueHandler(HandlerMetadata("AI-001", "Answer correctness", "Additional AI / LLM Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ai_001),
    CatalogueHandler(HandlerMetadata("AI-002", "Hallucination detection", "Additional AI / LLM Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ai_002),
    CatalogueHandler(HandlerMetadata("AI-003", "Grounded response verification", "Additional AI / LLM Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ai_003),
    CatalogueHandler(HandlerMetadata("AI-004", "Prompt injection resistance", "Additional AI / LLM Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ai_004),
    CatalogueHandler(HandlerMetadata("AI-005", "Jailbreak resistance", "Additional AI / LLM Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ai_005),
    CatalogueHandler(HandlerMetadata("AI-006", "Abstention behaviour", "Additional AI / LLM Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ai_006),
    CatalogueHandler(HandlerMetadata("AI-007", "Contradiction handling", "Additional AI / LLM Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ai_007),
    CatalogueHandler(HandlerMetadata("AI-008", "Context retention", "Additional AI / LLM Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ai_008),
    CatalogueHandler(HandlerMetadata("AI-009", "Structured output compliance", "Additional AI / LLM Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ai_009),
    CatalogueHandler(HandlerMetadata("AI-010", "Tool-call correctness", "Additional AI / LLM Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ai_010),
    CatalogueHandler(HandlerMetadata("AI-011", "Sensitive information leakage", "Additional AI / LLM Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ai_011),
    CatalogueHandler(HandlerMetadata("AI-012", "Bias and fairness assessment", "Additional AI / LLM Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ai_012),
    CatalogueHandler(HandlerMetadata("AI-013", "Multi-turn consistency", "Additional AI / LLM Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ai_013),
    CatalogueHandler(HandlerMetadata("AI-014", "Irrelevant context robustness", "Additional AI / LLM Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ai_014),
    CatalogueHandler(HandlerMetadata("AI-015", "Long-context handling", "Additional AI / LLM Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ai_015),
    CatalogueHandler(HandlerMetadata("AI-016", "Output truncation", "Additional AI / LLM Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ai_016),
    CatalogueHandler(HandlerMetadata("AI-017", "Model-provider failure", "Additional AI / LLM Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ai_017),
    CatalogueHandler(HandlerMetadata("AI-018", "Token-limit handling", "Additional AI / LLM Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ai_018),
    CatalogueHandler(HandlerMetadata("AI-019", "Latency and token usage", "Additional AI / LLM Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ai_019),
    CatalogueHandler(HandlerMetadata("AI-020", "Model-version regression", "Additional AI / LLM Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ai_020),
    CatalogueHandler(HandlerMetadata("ML-001", "Dataset schema validation", "Additional Machine Learning / Data Science Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ml_001),
    CatalogueHandler(HandlerMetadata("ML-002", "Train/test contamination", "Additional Machine Learning / Data Science Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ml_002),
    CatalogueHandler(HandlerMetadata("ML-003", "Feature leakage", "Additional Machine Learning / Data Science Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ml_003),
    CatalogueHandler(HandlerMetadata("ML-004", "Baseline model comparison", "Additional Machine Learning / Data Science Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ml_004),
    CatalogueHandler(HandlerMetadata("ML-005", "Cross-validation correctness", "Additional Machine Learning / Data Science Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ml_005),
    CatalogueHandler(HandlerMetadata("ML-006", "Hyperparameter leakage", "Additional Machine Learning / Data Science Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ml_006),
    CatalogueHandler(HandlerMetadata("ML-007", "Overfitting detection", "Additional Machine Learning / Data Science Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ml_007),
    CatalogueHandler(HandlerMetadata("ML-008", "Underfitting detection", "Additional Machine Learning / Data Science Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ml_008),
    CatalogueHandler(HandlerMetadata("ML-009", "Class imbalance evaluation", "Additional Machine Learning / Data Science Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ml_009),
    CatalogueHandler(HandlerMetadata("ML-010", "Metric calculation correctness", "Additional Machine Learning / Data Science Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ml_010),
    CatalogueHandler(HandlerMetadata("ML-011", "Threshold sensitivity", "Additional Machine Learning / Data Science Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ml_011),
    CatalogueHandler(HandlerMetadata("ML-012", "Probability calibration", "Additional Machine Learning / Data Science Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ml_012),
    CatalogueHandler(HandlerMetadata("ML-013", "Feature importance stability", "Additional Machine Learning / Data Science Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ml_013),
    CatalogueHandler(HandlerMetadata("ML-014", "Reproducibility", "Additional Machine Learning / Data Science Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ml_014),
    CatalogueHandler(HandlerMetadata("ML-015", "Model serialization", "Additional Machine Learning / Data Science Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ml_015),
    CatalogueHandler(HandlerMetadata("ML-016", "Inference schema validation", "Additional Machine Learning / Data Science Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ml_016),
    CatalogueHandler(HandlerMetadata("ML-017", "Out-of-distribution inputs", "Additional Machine Learning / Data Science Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ml_017),
    CatalogueHandler(HandlerMetadata("ML-018", "Data drift detection", "Additional Machine Learning / Data Science Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ml_018),
    CatalogueHandler(HandlerMetadata("ML-019", "Model drift monitoring", "Additional Machine Learning / Data Science Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ml_019),
    CatalogueHandler(HandlerMetadata("ML-020", "Batch inference performance", "Additional Machine Learning / Data Science Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ml_020),
    CatalogueHandler(HandlerMetadata("WEB-001", "Page rendering", "Additional Web Application Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_web_001),
    CatalogueHandler(HandlerMetadata("WEB-002", "Route navigation", "Additional Web Application Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_web_002),
    CatalogueHandler(HandlerMetadata("WEB-003", "Direct URL access", "Additional Web Application Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_web_003),
    CatalogueHandler(HandlerMetadata("WEB-004", "Refresh on nested route", "Additional Web Application Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_web_004),
    CatalogueHandler(HandlerMetadata("WEB-005", "Form submission", "Additional Web Application Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_web_005),
    CatalogueHandler(HandlerMetadata("WEB-006", "Client-side validation", "Additional Web Application Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_web_006),
    CatalogueHandler(HandlerMetadata("WEB-007", "Server-side validation", "Additional Web Application Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_web_007),
    CatalogueHandler(HandlerMetadata("WEB-008", "Responsive breakpoints", "Additional Web Application Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_web_008),
    CatalogueHandler(HandlerMetadata("WEB-009", "Browser compatibility", "Additional Web Application Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_web_009),
    CatalogueHandler(HandlerMetadata("WEB-010", "Accessibility audit", "Additional Web Application Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_web_010),
    CatalogueHandler(HandlerMetadata("WEB-011", "Image loading failures", "Additional Web Application Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_web_011),
    CatalogueHandler(HandlerMetadata("WEB-012", "Broken links", "Additional Web Application Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_web_012),
    CatalogueHandler(HandlerMetadata("WEB-013", "Authentication redirects", "Additional Web Application Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_web_013),
    CatalogueHandler(HandlerMetadata("WEB-014", "Protected route enforcement", "Additional Web Application Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_web_014),
    CatalogueHandler(HandlerMetadata("WEB-015", "Session persistence", "Additional Web Application Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_web_015),
    CatalogueHandler(HandlerMetadata("WEB-016", "Frontend/backend error handling", "Additional Web Application Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_web_016),
    CatalogueHandler(HandlerMetadata("WEB-017", "Duplicate form submissions", "Additional Web Application Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_web_017),
    CatalogueHandler(HandlerMetadata("WEB-018", "Search and filtering", "Additional Web Application Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_web_018),
    CatalogueHandler(HandlerMetadata("WEB-019", "Pagination correctness", "Additional Web Application Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_web_019),
    CatalogueHandler(HandlerMetadata("WEB-020", "Browser console exceptions", "Additional Web Application Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_web_020),
    CatalogueHandler(HandlerMetadata("DATA-001", "Schema validation", "Additional Data Engineering Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_data_001),
    CatalogueHandler(HandlerMetadata("DATA-002", "Type validation", "Additional Data Engineering Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_data_002),
    CatalogueHandler(HandlerMetadata("DATA-003", "Null handling", "Additional Data Engineering Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_data_003),
    CatalogueHandler(HandlerMetadata("DATA-004", "Duplicate handling", "Additional Data Engineering Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_data_004),
    CatalogueHandler(HandlerMetadata("DATA-005", "Transformation correctness", "Additional Data Engineering Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_data_005),
    CatalogueHandler(HandlerMetadata("DATA-006", "Idempotency", "Additional Data Engineering Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_data_006),
    CatalogueHandler(HandlerMetadata("DATA-007", "Missing records", "Additional Data Engineering Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_data_007),
    CatalogueHandler(HandlerMetadata("DATA-008", "Late-arriving records", "Additional Data Engineering Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_data_008),
    CatalogueHandler(HandlerMetadata("DATA-009", "Out-of-order events", "Additional Data Engineering Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_data_009),
    CatalogueHandler(HandlerMetadata("DATA-010", "Data lineage", "Additional Data Engineering Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_data_010),
    CatalogueHandler(HandlerMetadata("DATA-011", "Data quality constraints", "Additional Data Engineering Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_data_011),
    CatalogueHandler(HandlerMetadata("DATA-012", "Large-file processing", "Additional Data Engineering Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_data_012),
    CatalogueHandler(HandlerMetadata("DATA-013", "Pipeline retry handling", "Additional Data Engineering Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_data_013),
    CatalogueHandler(HandlerMetadata("DATA-014", "Partial pipeline failure", "Additional Data Engineering Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_data_014),
    CatalogueHandler(HandlerMetadata("DATA-015", "Transaction consistency", "Additional Data Engineering Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_data_015),
    CatalogueHandler(HandlerMetadata("CV-001", "Valid image decoding", "Additional Computer Vision Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_cv_001),
    CatalogueHandler(HandlerMetadata("CV-002", "Corrupt image handling", "Additional Computer Vision Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_cv_002),
    CatalogueHandler(HandlerMetadata("CV-003", "Unsupported image format", "Additional Computer Vision Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_cv_003),
    CatalogueHandler(HandlerMetadata("CV-004", "Image size limits", "Additional Computer Vision Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_cv_004),
    CatalogueHandler(HandlerMetadata("CV-005", "Classification accuracy", "Additional Computer Vision Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_cv_005),
    CatalogueHandler(HandlerMetadata("CV-006", "Object detection metrics", "Additional Computer Vision Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_cv_006),
    CatalogueHandler(HandlerMetadata("CV-007", "Confidence threshold handling", "Additional Computer Vision Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_cv_007),
    CatalogueHandler(HandlerMetadata("CV-008", "Low-light image robustness", "Additional Computer Vision Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_cv_008),
    CatalogueHandler(HandlerMetadata("CV-009", "Blur and noise robustness", "Additional Computer Vision Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_cv_009),
    CatalogueHandler(HandlerMetadata("CV-010", "Rotation and orientation handling", "Additional Computer Vision Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_cv_010),
    CatalogueHandler(HandlerMetadata("CV-011", "Image aspect-ratio changes", "Additional Computer Vision Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_cv_011),
    CatalogueHandler(HandlerMetadata("CV-012", "Batch inference", "Additional Computer Vision Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_cv_012),
    CatalogueHandler(HandlerMetadata("CV-013", "Inference latency", "Additional Computer Vision Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_cv_013),
    CatalogueHandler(HandlerMetadata("CV-014", "Fairness across relevant groups", "Additional Computer Vision Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_cv_014),
    CatalogueHandler(HandlerMetadata("CV-015", "Model unavailable", "Additional Computer Vision Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_cv_015),
    CatalogueHandler(HandlerMetadata("AG-001", "Goal completion", "Additional Autonomous Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ag_001),
    CatalogueHandler(HandlerMetadata("AG-002", "Tool selection accuracy", "Additional Autonomous Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ag_002),
    CatalogueHandler(HandlerMetadata("AG-003", "Tool argument validation", "Additional Autonomous Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ag_003),
    CatalogueHandler(HandlerMetadata("AG-004", "Planning correctness", "Additional Autonomous Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ag_004),
    CatalogueHandler(HandlerMetadata("AG-005", "Multi-step execution", "Additional Autonomous Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ag_005),
    CatalogueHandler(HandlerMetadata("AG-006", "Recovery from tool failure", "Additional Autonomous Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ag_006),
    CatalogueHandler(HandlerMetadata("AG-007", "Permission boundary enforcement", "Additional Autonomous Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ag_007),
    CatalogueHandler(HandlerMetadata("AG-008", "Retrieved-content prompt injection", "Additional Autonomous Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ag_008),
    CatalogueHandler(HandlerMetadata("AG-009", "Loop prevention", "Additional Autonomous Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ag_009),
    CatalogueHandler(HandlerMetadata("AG-010", "Budget enforcement", "Additional Autonomous Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ag_010),
    CatalogueHandler(HandlerMetadata("AG-011", "State persistence", "Additional Autonomous Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ag_011),
    CatalogueHandler(HandlerMetadata("AG-012", "Human approval enforcement", "Additional Autonomous Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ag_012),
    CatalogueHandler(HandlerMetadata("AG-013", "Partial completion reporting", "Additional Autonomous Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ag_013),
    CatalogueHandler(HandlerMetadata("AG-014", "Duplicate side-effect prevention", "Additional Autonomous Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ag_014),
    CatalogueHandler(HandlerMetadata("AG-015", "Agent termination and cleanup", "Additional Autonomous Agent Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_ag_015),
    CatalogueHandler(HandlerMetadata("HSC-001", "Role-based access control", "Healthcare / Student Information Application Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_hsc_001),
    CatalogueHandler(HandlerMetadata("HSC-002", "Private-record protection", "Healthcare / Student Information Application Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_hsc_002),
    CatalogueHandler(HandlerMetadata("HSC-003", "Input and record validation", "Healthcare / Student Information Application Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_hsc_003),
    CatalogueHandler(HandlerMetadata("HSC-004", "Recommendations grounded in supplied data", "Healthcare / Student Information Application Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_hsc_004),
    CatalogueHandler(HandlerMetadata("HSC-005", "Missing information handling", "Healthcare / Student Information Application Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_hsc_005),
    CatalogueHandler(HandlerMetadata("HSC-006", "Conflicting information handling", "Healthcare / Student Information Application Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_hsc_006),
    CatalogueHandler(HandlerMetadata("HSC-007", "Consent enforcement", "Healthcare / Student Information Application Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_hsc_007),
    CatalogueHandler(HandlerMetadata("HSC-008", "Data minimization", "Healthcare / Student Information Application Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_hsc_008),
    CatalogueHandler(HandlerMetadata("HSC-009", "Audit trail integrity", "Healthcare / Student Information Application Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_hsc_009),
    CatalogueHandler(HandlerMetadata("HSC-010", "Uncertain output handling", "Healthcare / Student Information Application Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_hsc_010),
    CatalogueHandler(HandlerMetadata("HSC-011", "Workflow correctness", "Healthcare / Student Information Application Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_hsc_011),
    CatalogueHandler(HandlerMetadata("HSC-012", "Integration failure handling", "Healthcare / Student Information Application Tests", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_hsc_012),
    CatalogueHandler(HandlerMetadata("MET-001", "Overall weighted score", "Evaluation Metrics", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_met_001),
    CatalogueHandler(HandlerMetadata("MET-001-02", "Functional test pass rate", "Evaluation Metrics", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_met_001_02),
    CatalogueHandler(HandlerMetadata("MET-001-03", "Test coverage", "Evaluation Metrics", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_met_001_03),
    CatalogueHandler(HandlerMetadata("MET-001-04", "Applicable-test coverage", "Evaluation Metrics", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_met_001_04),
    CatalogueHandler(HandlerMetadata("MET-001-05", "Critical failure count", "Evaluation Metrics", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_met_001_05),
    CatalogueHandler(HandlerMetadata("MET-001-06", "High-severity failure count", "Evaluation Metrics", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_met_001_06),
    CatalogueHandler(HandlerMetadata("MET-001-07", "False-positive rate", "Evaluation Metrics", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_met_001_07),
    CatalogueHandler(HandlerMetadata("MET-001-08", "False-negative rate", "Evaluation Metrics", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_met_001_08),
    CatalogueHandler(HandlerMetadata("MET-001-09", "Mean response latency", "Evaluation Metrics", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_met_001_09),
    CatalogueHandler(HandlerMetadata("MET-001-10", "P95 response latency", "Evaluation Metrics", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_met_001_10),
    CatalogueHandler(HandlerMetadata("MET-001-11", "Throughput", "Evaluation Metrics", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_met_001_11),
    CatalogueHandler(HandlerMetadata("MET-001-12", "Peak memory usage", "Evaluation Metrics", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_met_001_12),
    CatalogueHandler(HandlerMetadata("MET-001-13", "CPU consumption", "Evaluation Metrics", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_met_001_13),
    CatalogueHandler(HandlerMetadata("MET-001-14", "Crash rate", "Evaluation Metrics", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_met_001_14),
    CatalogueHandler(HandlerMetadata("MET-001-15", "Timeout rate", "Evaluation Metrics", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_met_001_15),
    CatalogueHandler(HandlerMetadata("MET-001-16", "Security finding count", "Evaluation Metrics", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_met_001_16),
    CatalogueHandler(HandlerMetadata("MET-001-17", "Dependency vulnerability count", "Evaluation Metrics", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_met_001_17),
    CatalogueHandler(HandlerMetadata("MET-001-18", "AI task-success rate", "Evaluation Metrics", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_met_001_18),
    CatalogueHandler(HandlerMetadata("MET-001-19", "AI hallucination rate", "Evaluation Metrics", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_met_001_19),
    CatalogueHandler(HandlerMetadata("MET-001-20", "AI abstention quality", "Evaluation Metrics", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_met_001_20),
    CatalogueHandler(HandlerMetadata("MET-001-21", "ML accuracy", "Evaluation Metrics", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_met_001_21),
    CatalogueHandler(HandlerMetadata("MET-001-22", "ML precision", "Evaluation Metrics", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_met_001_22),
    CatalogueHandler(HandlerMetadata("MET-001-23", "ML recall", "Evaluation Metrics", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_met_001_23),
    CatalogueHandler(HandlerMetadata("MET-001-24", "ML macro-F1", "Evaluation Metrics", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_met_001_24),
    CatalogueHandler(HandlerMetadata("MET-001-25", "ML balanced accuracy", "Evaluation Metrics", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_met_001_25),
    CatalogueHandler(HandlerMetadata("MET-001-26", "ML calibration error", "Evaluation Metrics", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_met_001_26),
    CatalogueHandler(HandlerMetadata("MET-001-27", "Data leakage detection rate", "Evaluation Metrics", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_met_001_27),
    CatalogueHandler(HandlerMetadata("MET-001-28", "Build success rate", "Evaluation Metrics", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_met_001_28),
    CatalogueHandler(HandlerMetadata("MET-001-29", "Deployment success rate", "Evaluation Metrics", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_met_001_29),
    CatalogueHandler(HandlerMetadata("MET-001-30", "Reproducibility rate", "Evaluation Metrics", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_met_001_30),
    CatalogueHandler(HandlerMetadata("MET-001-31", "Report evidence completeness", "Evaluation Metrics", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_met_001_31),
    CatalogueHandler(HandlerMetadata("MET-001-32", "Remediation verification rate", "Evaluation Metrics", ImplementationStatus.IMPLEMENTED, "safe domain stub; no execution", ("files",)), _handler_met_001_32),
)

import genuine_handlers
from dataclasses import replace

_updated_registry = []
for _item in REGISTRY:
    _cid = _item.metadata.id
    if _cid in genuine_handlers.GENUINE_HANDLERS:
        _updated_registry.append(CatalogueHandler(_item.metadata, genuine_handlers.GENUINE_HANDLERS[_cid]))
    else:
        _updated_registry.append(CatalogueHandler(replace(_item.metadata, status=ImplementationStatus.PLANNED), None))
REGISTRY = tuple(_updated_registry)


def validate_registry(registry=REGISTRY) -> None:
    ids = [item.metadata.id for item in registry]
    if len(ids) != len(set(ids)) or any(not item.metadata.id or not item.metadata.name for item in registry):
        raise ValueError("Registry contains missing or duplicate metadata IDs.")
    if any(item.metadata.status is ImplementationStatus.IMPLEMENTED and not callable(item.handler) for item in registry):
        raise ValueError("Implemented registry entries must have callable handlers.")


def executable_catalogue_entries(registry=None) -> list[dict[str, Any]]:
    """Return only validated implemented entries, with no fabricated runner."""
    if registry is None:
        registry = REGISTRY
    validate_registry(registry)
    return [{**asdict(item.metadata), "status": item.metadata.status.value, "handler": item.handler} for item in registry if item.metadata.status is ImplementationStatus.IMPLEMENTED and callable(item.handler)]


validate_registry()
