"""Run the real Evalora dispatch path against a repository and emit audit artifacts.

This command intentionally uses ``server.run_selected_catalogue_checks`` rather
than calling handlers directly.  It performs static inspection only; no
submission code is executed.  Runtime-only requirements therefore remain
``PARTIALLY_VERIFIED``/inconclusive instead of being reported as passes.
"""
from __future__ import annotations

import argparse, json, subprocess, sys, time
from pathlib import Path
import server
from genuine_handlers import GENUINE_HANDLERS

ROOT = Path(__file__).resolve().parent

def read_files(target: Path):
    files = []
    for path in sorted(target.rglob("*")):
        if not path.is_file() or any(part in {".git", "__pycache__", ".evalora_reference"} for part in path.parts):
            continue
        if path.stat().st_size > server.MAX_REPOSITORY_FILE_BYTES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        files.append({"name": path.relative_to(target).as_posix(), "content": text})
        if len(files) >= server.MAX_REPOSITORY_FILES:
            break
    return files

def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=".")
    ap.add_argument("--output", default="data/repository_audit_report.json")
    args = ap.parse_args(argv)
    target = Path(args.target).resolve()
    files = read_files(target)
    ids = sorted(GENUINE_HANDLERS)
    started = time.monotonic()
    results = server.run_selected_catalogue_checks(ids, files)
    elapsed = time.monotonic() - started
    by_id = {r.get("id"): r for r in results}
    records = []
    for cid in ids:
        result = by_id.get(cid, {"id": cid, "state": "error", "detail": "No dispatch result."})
        runtime = cid.split("-")[0] in {"API", "FUNC", "RE", "SCORE", "WEB", "ES"}
        state = result.get("state")
        status = "VERIFIED" if state == "pass" and not runtime else "PARTIALLY_VERIFIED" if state == "pass" else "FAILED"
        records.append({"id": cid, "catalogue_requirement": next((x.get("name") for x in server.load_test_catalogue() if x["id"] == cid), ""),
                        "handler": getattr(GENUINE_HANDLERS[cid], "__name__", repr(GENUINE_HANDLERS[cid])),
                        "source": f"{GENUINE_HANDLERS[cid].__module__}.{GENUINE_HANDLERS[cid].__name__}",
                        "dispatch": "server.run_selected_catalogue_checks", "state": state,
                        "detail": result.get("detail", ""), "status": status,
                        "runtime_limitation": "Static source inspection; runtime execution is intentionally unavailable." if runtime else ""})
    report = {"target": str(target), "files_inspected": len(files), "elapsed_seconds": elapsed,
              "registry_count": len(ids), "catalogue_count": len(server.load_test_catalogue()),
              "unimplemented_catalogue_count": sum(1 for x in server.load_test_catalogue() if not x["selectable"]),
              "results": records}
    out = ROOT / args.output
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(out), "handlers": len(ids), "files": len(files), "elapsed_seconds": elapsed}))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
