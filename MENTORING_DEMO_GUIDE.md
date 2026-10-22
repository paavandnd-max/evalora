# Evalora Mentoring-Round Demo Guide

## What Evalora solves

Evalora gives university event reviewers a private, evidence-based workspace
for connecting a problem statement to a submitted repository, running approved
static checks, preserving the complete result set, and reviewing the evidence.

## Verified architecture

1. `server.py` is the application entry point and serves the dashboard and API.
2. `index.html` is the staff/participant dashboard.
3. `landing.html` is the public submission page.
4. `genuine_handlers.py` contains the 224 executable catalogue handlers.
5. `test_registry.py` holds catalogue metadata and the executable registry.
6. `server.run_selected_catalogue_checks` is the canonical dispatch path.
7. `data/test_catalogue.json` contains 444 stable catalogue IDs.
8. Event selection is stored in versioned `event_test_configurations` records.
9. Reports and rerun history are stored with the submission/evaluation records.

## Start the local demo

From the repository folder:

```bash
EVALORA_DEMO_MODE=1 python server.py
```

Health check:

```bash
curl http://127.0.0.1:8000/api/health
```

Open:

```text
http://127.0.0.1:8000/
http://127.0.0.1:8000/login
```

The local demo database requires a reviewer account. If needed, stop the
server and run `EVALORA_DEMO_MODE=1 python server.py --reset-demo-admin`.

## Three-to-five-minute demonstration

1. Sign in as the local reviewer/admin.
2. Create an event with a short problem statement.
3. Leave test selection unset, or choose **Select all executable**. Explain
   that the backend dynamically resolves all current executable IDs rather
   than using a fixed limit.
4. Approve the event configuration and open the event.
5. Use the controlled fixture in `demo_repository/` as the repository evidence
   source, or submit an accessible public repository URL when network access is
   available.
6. Open the submission details modal and show the complete result list,
   summary counts, status, score, and evidence details.
7. Point out the harmless missing retry/timeout evidence in `app.py`.
8. Run a rerun, open evaluation history, view the report, and download it.
9. Create a second event with a small explicit executable subset and explain
   that only those IDs are dispatched.

## Selection semantics

- Missing or `null` `selected_test_ids`: all executable tests.
- Non-empty list: only those validated executable IDs.
- Empty list: explicit zero-test selection; it is not silently converted to all.
- Planned or unknown IDs: rejected at the API boundary.
- Duplicate IDs: deduplicated before dispatch.

## Scoring semantics

The score is the number of passing scored checks divided by the number of
scored checks. `not_testable` and execution-error checks are not presented as
passes. An execution error flags the submission and is retained in the result
set. A zero-scored-check evaluation produces score 0 and does not divide by
zero.

## Security boundaries

- Submitted repository source is inspected as bounded data and is not executed
  on the host.
- File paths, archive structures, upload sizes, and request IDs are validated.
- Staff routes enforce roles and event access.
- Reports are filtered by event authorization.
- Static evidence is not claimed as proof of production runtime behavior.

## Mentor answers

**What is different from a linter?** Evalora combines event configuration,
problem context, a stable catalogue, registry-backed dispatch, evidence,
versioned selections, reviewer reports, and access-controlled history.

**How do you know tests execute?** Each executable ID is resolved from the
canonical registry and dispatched through `server.run_selected_catalogue_checks`;
the regression suite checks ID counts, deduplication, failures, and selection.

**What if evidence is missing?** The handler returns `fail`, `not_testable`, or
an execution error according to its contract; missing evidence is never silently
treated as a pass.

**How are scores calculated?** Only scored outcomes contribute to the
denominator. Passing outcomes form the numerator. Not-testable and error states
remain visible and errors flag the submission.

**How are malicious repositories handled?** Source is not executed. Uploads
are bounded, path-normalized, and inspected through safe structural checks.

**What is static versus runtime?** The current repository handlers primarily
inspect source, manifests, metadata, and structured evidence. The audit report
separates static, runtime-simulation, integration, and manual classifications.

**What is implemented versus planned?** The current repository has 224
executable handlers and 220 planned catalogue entries out of 444 total IDs.

## Backup plan

Keep the local server, this fixture, and a previously generated report ready.
If a live browser workflow fails, show the real saved report only as a clearly
identified prior run—not as a live evaluation—and explain the exact limitation.
