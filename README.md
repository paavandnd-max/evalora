# Evalora — local hackathon judge MVP

Evalora stores problem statements locally in `data.json`. Team submissions and evaluation results can use local storage or Supabase Postgres.

## Run it

1. Stop any old Evalora `server.py` processes so only one instance uses port 8000.
2. In PowerShell, run `cd "C:\Users\Paavan Sharma\OneDrive\Documents\ChatGPT\BuildLab"`.
3. Run `py .\server.py` and leave that window open.
4. Open `http://127.0.0.1:8000/` for the public participant page. Staff sign in at `/login`; the protected staff dashboard is `/dashboard`.

## Supabase setup

Evalora can use Supabase Auth and Postgres for accounts, code submissions, and evaluation results. Copy `.env.example` to `.env` and fill in the project URL, publishable key, and secret key from the Supabase dashboard. The secret key is read only by the Python server and is used for server-side user creation; it is never returned to the browser. Data requests use each signed-in user's Auth token and the publishable key.

The multi-event SQL in `supabase_schema.sql` has been applied to the connected BuildLab Supabase project. For another project, review and apply it using the Supabase SQL Editor before enabling multi-event mode. It creates event, statement-document, configuration-version, judge-assignment, team, submission-history, audit, submission, and shared rate-limit tables. RLS limits participant event visibility to open events and reserves configuration, submissions, reports, and evaluation history for admins or judges assigned to that event. Existing submissions are migrated to a closed legacy event only when such rows exist. Evalora roles are stored in Supabase Auth `app_metadata`, which only the server's admin API sets. Do not set roles in user-editable metadata. Re-running the script is designed to be safe; review the SQL and back up production data before applying it.

Create the first admin from the BuildLab folder with `py .\server.py --bootstrap-admin`; enter a username, display name, and password when prompted. Then start Evalora with `py .\server.py`. Admins can create judge and team accounts in **Manage accounts**. Users sign in with their username and the password the admin gave them; Evalora maps the username to an internal, non-mailbox Supabase Auth address.

In Supabase mode, only admins and judges assigned to an event can read its submissions and evaluation results. Team accounts receive only the neutral acknowledgment; report and history endpoints require event authorization. Event statement files are private to the server and event reviewers. Existing local `data.json` submissions are not automatically imported; keep a backup before switching modes. If the three Supabase variables are absent, Evalora continues in local mode.

In local mode, the first start prints one-time starter credentials for the administrator, judge, and sample team accounts. In Supabase mode, use the bootstrap command above to create the first administrator. Share each team's login privately.

For a temporary, local-only test workspace, set `EVALORA_DEMO_MODE=1` in `.env` and restart the server. Demo mode still requires sign-in: stop the server and run `py .\server.py --bootstrap-admin` once to create a local reviewer account. To rotate the existing local demo admin password, stop the server and run `py .\server.py --reset-demo-admin`; it prints a new one-time password. The reviewer can create team and judge accounts, manage tests, rerun checks, and record reviews. These changes are stored only in the isolated demo SQLite database; this mode does not read or write Supabase submissions or `data.json`. Set it back to `0` and restart to use normal authentication.

Demo mode creates and reads a separate `.evalora_test.sqlite3` SQLite database from `test_database.sql`. The fixture contains five sample teams, a PS-03 problem statement with the ten JSONL evaluator checks, ten security checks, two judges, five submissions, and linked reviews. Event, statement-version, judge-assignment, audit, and evaluation-history tables are migrated into that database. It does not use `data.json` or connect to Supabase. Delete `.evalora_test.sqlite3` while the server is stopped to recreate the original sample database on the next start.

## Events and configuration

Admins create independent events from the **Create event** button. A problem statement can be pasted or uploaded as PDF, DOCX, or TXT (maximum 5 MB). Text is extracted locally; files are never executed. OCR is not configured, so scanned/image-only PDFs are rejected with an explanation. Empty, malformed, unsupported, and unreadable documents are rejected.

Evalora drafts a deterministic, editable configuration from explicit requirement-like lines in the statement. It includes requirement IDs, evidence guidance, likely objectives and constraints, a heuristic analysis preview, the existing ten-test JSONL profile when the statement identifies PS-03/CareTruth, and the mandatory ten-check security baseline. This is a draft, not an AI or semantic proof of requirements. Admins should correct it and approve it. Configuration edits and problem-statement changes create new versions; existing submissions and reports remain linked to their original approved version. Events stay draft until a version is approved, and only open events accept submissions.

Judges are assigned by judge account username. The backend filters every event, report, history, re-evaluation, and review request by assignment; changing an event or submission ID does not grant access. Admins can see all events. Participant state includes only open event names and problem statements, never evaluator criteria, submissions, scores, security findings, reports, or reviewer comments.

Participants use the public landing page without a staff account, choose an open approved event, and provide a team name and full public GitHub repository URL. They receive only a neutral acknowledgment. Admins can also submit a manually selected team/repository from the staff dashboard; that form is restricted by a server-side admin role check. A team can submit once per event by default; admins can enable resubmissions when creating an event. Each evaluation retains its run history and exact configuration version. Submission status and evaluation status are separate so infrastructure problems can be marked `requires_manual_review` without calling the project itself failed.

The public page is `/`, staff authentication is `/login`, and `/dashboard` redirects unauthenticated or participant users to staff sign-in. Judges and mentors see only events assigned to them; admins can manage events and use the manual repository test form. The application currently runs as one Python HTTP service on `127.0.0.1:8000`; `/api/health` reports its mode and status.

## Result privacy

Team logins can submit only for the team assigned to that account. The server returns no submissions, results, test cases, review data, or security catalog in a team's `/api/state` response. The submission endpoint returns only `Thank you for your submission.`; report, evaluation, review, and account administration APIs require an authorized reviewer/admin. Judges can inspect and evaluate all teams. Admins can also create judge and team accounts. The server serves only the public UI; it does not expose `data.json` or source files over HTTP.

This is a local development MVP, not a hardened public deployment. Keep it bound to localhost and do not expose it to the public internet.

## Request protection and deployment boundary

State-changing requests reject a supplied cross-origin `Origin`; session cookies are `HttpOnly` and `SameSite=Strict`. Set `EVALORA_COOKIE_SECURE=1` only when the app is served over HTTPS. Responses include `nosniff`, frame denial, a restrictive same-origin CSP, referrer policy, and a permissions policy. JSON APIs reject chunked bodies, invalid or negative lengths, non-object JSON, and request bodies over their route limit (64 KB by default; 7.5 MB for event statement creation; 16 MB for problem/test configuration uploads).

Server-side fixed-window rate limits return HTTP 429 with `Retry-After`. Defaults are 8 login attempts per 300 seconds per source IP; 12 repository submissions per 600 seconds per IP and 6 per 3600 seconds per account; 500 submissions per event and 2,000 globally per hour; 10 event creations per hour per admin and 100 globally; 8 statement updates per hour per admin; 8 problem/test dataset uploads per hour per staff account (checked before reading the upload body); 60 staff mutations per hour per account; 8 evaluation reruns per 300 seconds per reviewer, 100 per event and 500 globally per hour; and 40 report reads per minute per reviewer. Override the corresponding `EVALORA_*_LIMIT` and `EVALORA_*_WINDOW_SECONDS` variables in `.env`. Event and global budgets reduce abuse by many accounts or addresses, while per-account and per-IP limits add finer controls. Local/demo mode uses a transactionally updated SQLite file shared by processes on the same filesystem; those counters survive a browser refresh and server restart. Supabase mode uses the atomic `evalora_consume_rate_limit` PostgreSQL RPC, with hashed identities and service-role-only access, so instances sharing the project use one limiter. If that shared store is unavailable, protected work fails closed with HTTP 503. Evalora currently binds to localhost and is intended for one development host.

## Current checks

Judges can record up to 20 JSON input/expected-output examples per problem from **Manage tests**. Evalora never executes uploaded repository code. These Python-style examples are retained as reviewer reference and reported as **N/A / not testable**; they do not affect the score. JSONL result files are parsed as data and checked against the applicable evaluator rules.

Each problem can also have its own private reference dataset (`.csv`, `.json`, or `.jsonl`, up to 15 MB). Attach it while creating a problem or in **Manage tests**. Evalora stores the file separately from the team-visible state and persists its private descriptor with the problem. It uses rows to resolve returned entity identities and verify cited source spans. JSONL records that include expected entity labels are compared against those expected results. Dataset files stay on the local machine and are excluded from version control. Dataset schemas vary by project, so identity lookup recognizes common keys such as `id`, `name`, `title`, and `code`; citation checks use each citation's `source_field` and exact `span`.

Without a reference dataset, Evalora still runs structural source checks and applicable JSONL consistency checks. Judge-authored input/expected-output examples remain **N/A** because submitted source is never executed. Checks that need absent ground truth, attack cases, or live API telemetry are also marked **N/A**. The evaluator cannot infer domain correctness or invent expected answers from an arbitrary problem statement alone, so judges must provide expected-label fixtures or live API evidence when those checks apply.

Repository evaluation is static: Evalora reads bounded text files, detects common technologies from source extensions, parses Python and JSON syntax, reports unsupported language parsers as **N/A**, scans for risky source patterns, and applies applicable JSONL result checks. It does not execute repository code, run the repository's own test command, or require Docker.

Uploads also receive basic structure checks: per-file and total size, README and test-file presence, and Python/JSON syntax. The score combines these checks and authored cases; it is an aid for judges, not a final determination that a prototype meets the challenge.

Source submissions also receive static security scans for credential-like literals, dynamic evaluation, shell execution, SQL interpolation, unsafe deserialization, browser injection sinks, user-controlled file paths, permissive security settings, and obvious hard-coded admin bypasses. These are pattern checks and can produce false positives or miss vulnerabilities. Evalora marks live admin login and endpoint authorization as **N/A** because source uploads do not provide a running target or credentials. To verify access control, judges need to test the running prototype with a team account and confirm admin pages and APIs are denied.

## CareTruth JSONL results

Teams can upload one `.jsonl` file instead of Python source to run the ten result checks. Each nonblank line must be a JSON object. Recommendation-style fields such as `facilities`, `results`, or `recommendations` are inspected when present. The upload limit is 300 KB and 1,000 records. The evaluator parses the file as data and never executes its contents.

When the file contains the official `ps03_g1_ananya`, `ps03_g2_contradiction`, `ps03_g3_abstain`, and `ps03_g4_injection` probes, Evalora applies the CareTruth PS-03 regression profile: expected g1/g2 recommendations and trust levels, g3 abstention/desert flag, g4 injection downgrade, citation grounding, dataset identity, ranking consistency, and explanation consistency. The profile uses the standard probe inputs and expectations documented by CareTruth. It does not execute the submitted output.

Evalora looks for the source CSV at `%USERPROFILE%\antigravity-team-workspace\caretruth-ai\data\raw\Hackathon_Dataset_India_Larg.csv`. Set `EVALORA_CARETRUTH_DATASET` before starting Evalora to use another copy. If the CSV is missing, citation source checks and authoritative facility lookup show as **N/A**. The live API check is optional; set `EVALORA_CARETRUTH_API_URL` to the CareTruth API base URL to check `/health` and replay all four standard probes against `/solve`. Without that setting, live API stability is **N/A**.

Checks that need data absent from a non-PS03 JSONL file remain **N/A** instead of counted as passing. Output-only records cannot establish clinical correctness, full prompt-injection resistance, or live API stability unless the relevant reference data, attack case, or endpoint is supplied.

## GitHub repository submissions

Participants submit a complete public GitHub URL. Evalora validates the host and path, resolves only GitHub API/Codeload destinations, rejects private or otherwise non-global DNS answers, retrieves repository metadata and an archive, enforces download and archive-size/member/content limits, and reads supported text files in memory. It does not invoke `git`, extract the archive to disk, or execute repository code. Private repositories and other Git hosts are unsupported. Duplicate canonical repository URLs are rejected per team/problem. The participant receives only the neutral acknowledgment; evaluation reports are reviewer-only.

## Automated checks for this project

The latest verification ran 47 tests successfully, including explicit missing-judge account creation, display-name judge assignment, and sensitive workspace-file route isolation.
The older 44-test parenthetical in the detailed inventory is historical; use the latest verification count above.

Run `py -m unittest -v` from this folder for the local regression suite (44 tests at the latest verification). It covers pasted text, PDF, DOCX, malformed/unsupported/oversized documents, compressed-stream parser limits, secure-cookie configuration, generated criteria and prompt-injection filtering, event creation and configuration versions, assigned-judge and cross-event isolation, historical reports, closed-event rejection, team identity, resubmission policy, duplicate submissions, participant privacy, reviewer report access and IDOR checks, public landing/staff login/protected dashboard routes, private/missing/unreachable GitHub responses, archive traversal/resource boundaries, DNS destination checks, end-to-end slow-client request timeouts, high-volume rate-limit contention, and anonymous public plus admin-only repository submission flows. Tests use temporary SQLite databases and mock GitHub retrieval; they do not contact the configured Supabase project, Docker, or GitHub.
