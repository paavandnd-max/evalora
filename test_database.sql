-- Local Evalora demo fixture. This file seeds only .evalora_test.sqlite3.
-- It is independent of data.json and the configured Supabase project.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS teams (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  members INTEGER NOT NULL CHECK (members > 0)
);

CREATE TABLE IF NOT EXISTS event_test_configurations (
  event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  selected_test_ids_json TEXT NOT NULL,
  security_baseline_json TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (event_id, version)
);

CREATE TABLE IF NOT EXISTS judges (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  specialty TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS demo_users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE COLLATE BINARY,
  name TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'judge', 'mentor', 'team')),
  team TEXT NOT NULL DEFAULT '',
  salt TEXT NOT NULL,
  password_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS problems (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  due_at TEXT NOT NULL,
  rubric_json TEXT NOT NULL,
  test_cases_json TEXT NOT NULL,
  reference_dataset_json TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE COLLATE NOCASE,
  description TEXT NOT NULL DEFAULT '',
  organizer TEXT NOT NULL DEFAULT '',
  event_date TEXT NOT NULL DEFAULT '',
  deadline TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL CHECK (status IN ('draft', 'open', 'closed')),
  problem_id TEXT NOT NULL UNIQUE REFERENCES problems(id),
  statement_text TEXT NOT NULL,
  statement_filename TEXT NOT NULL DEFAULT '',
  statement_mime TEXT NOT NULL DEFAULT 'text/plain',
  statement_file BLOB,
  allow_resubmissions INTEGER NOT NULL DEFAULT 0,
  active_config_version INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS event_config_versions (
  event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  config_json TEXT NOT NULL,
  approved INTEGER NOT NULL DEFAULT 0,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (event_id, version)
);

CREATE TABLE IF NOT EXISTS event_statement_versions (
  event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  statement_text TEXT NOT NULL,
  filename TEXT NOT NULL DEFAULT '',
  mime_type TEXT NOT NULL DEFAULT 'text/plain',
  original_file BLOB,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (event_id, version)
);

CREATE TABLE IF NOT EXISTS event_judges (
  event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  username TEXT NOT NULL COLLATE NOCASE,
  judge_name TEXT NOT NULL,
  assigned_by TEXT NOT NULL,
  assigned_at TEXT NOT NULL,
  PRIMARY KEY (event_id, username)
);

CREATE TABLE IF NOT EXISTS event_teams (
  id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  team_id TEXT NOT NULL REFERENCES teams(id),
  team_name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (event_id, team_name)
);

CREATE TABLE IF NOT EXISTS submission_evaluations (
  id TEXT PRIMARY KEY,
  submission_id TEXT NOT NULL REFERENCES submissions(id) ON DELETE CASCADE,
  event_id TEXT NOT NULL REFERENCES events(id),
  config_version INTEGER NOT NULL,
  evaluation_status TEXT NOT NULL,
  report_json TEXT NOT NULL,
  telemetry_json TEXT NOT NULL DEFAULT '{}',
  vectors_json TEXT NOT NULL DEFAULT '[]',
  logs_text TEXT NOT NULL DEFAULT '',
  artifact_checksum TEXT NOT NULL DEFAULT '',
  source_revision TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  event_id TEXT,
  actor_username TEXT NOT NULL,
  action TEXT NOT NULL,
  target_id TEXT NOT NULL DEFAULT '',
  detail_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evalora_migrations (
  name TEXT PRIMARY KEY,
  applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS submissions (
  id TEXT PRIMARY KEY,
  team_id TEXT NOT NULL REFERENCES teams(id),
  problem_id TEXT NOT NULL REFERENCES problems(id),
  submitted_at TEXT NOT NULL,
  status TEXT NOT NULL,
  score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
  checks_passed INTEGER NOT NULL CHECK (checks_passed >= 0),
  checks_total INTEGER NOT NULL CHECK (checks_total >= checks_passed),
  checks_json TEXT NOT NULL DEFAULT '[]',
  test_results_json TEXT NOT NULL DEFAULT '[]',
  files_json TEXT NOT NULL DEFAULT '[]',
  repository_url TEXT NOT NULL DEFAULT '',
  evaluation_report_json TEXT NOT NULL DEFAULT '{}',
  event_id TEXT REFERENCES events(id),
  event_team_id TEXT REFERENCES event_teams(id),
  config_version INTEGER NOT NULL DEFAULT 0,
  evaluation_status TEXT NOT NULL DEFAULT 'completed',
  idempotency_key TEXT NOT NULL DEFAULT '',
  artifact_checksum TEXT NOT NULL DEFAULT '',
  source_revision TEXT NOT NULL DEFAULT '',
  artifact_status TEXT NOT NULL DEFAULT 'validated',
  latest_evaluation_id TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS test_submission_event_team_repo_idx
  ON submissions(event_id, event_team_id, repository_url)
;

CREATE TRIGGER IF NOT EXISTS test_submission_duplicate_repo_guard
  BEFORE INSERT ON submissions
  WHEN NEW.event_id IS NOT NULL AND NEW.event_team_id IS NOT NULL AND NEW.repository_url <> ''
    AND EXISTS (SELECT 1 FROM events e WHERE e.id=NEW.event_id AND COALESCE(e.allow_resubmissions,0)=0)
    AND EXISTS (SELECT 1 FROM submissions s WHERE s.event_id=NEW.event_id
      AND s.event_team_id=NEW.event_team_id AND s.repository_url=NEW.repository_url)
  BEGIN SELECT RAISE(ABORT,'duplicate repository submission'); END;

CREATE TABLE IF NOT EXISTS reviews (
  id TEXT PRIMARY KEY,
  submission_id TEXT NOT NULL REFERENCES submissions(id),
  judge_id TEXT NOT NULL REFERENCES judges(id),
  decision TEXT NOT NULL CHECK (decision IN ('approve', 'revise', 'hold')),
  score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
  comment TEXT NOT NULL,
  reviewed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS test_case_results (
  submission_id TEXT NOT NULL REFERENCES submissions(id),
  test_case_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('pass', 'fail', 'not_testable')),
  detail TEXT NOT NULL,
  PRIMARY KEY (submission_id, test_case_id)
);

CREATE TABLE IF NOT EXISTS security_checks (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  method TEXT NOT NULL CHECK (method IN ('static scan', 'live test')),
  description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS submission_security_results (
  submission_id TEXT NOT NULL REFERENCES submissions(id),
  security_check_id TEXT NOT NULL REFERENCES security_checks(id),
  state TEXT NOT NULL CHECK (state IN ('pass', 'fail', 'not_testable')),
  detail TEXT NOT NULL,
  PRIMARY KEY (submission_id, security_check_id)
);

CREATE INDEX IF NOT EXISTS test_submissions_problem_idx ON submissions(problem_id, submitted_at);
CREATE INDEX IF NOT EXISTS test_reviews_submission_idx ON reviews(submission_id, reviewed_at);
CREATE INDEX IF NOT EXISTS test_event_judges_user_idx ON event_judges(username, event_id);
CREATE INDEX IF NOT EXISTS test_event_team_lookup_idx ON event_teams(event_id, team_name);
CREATE INDEX IF NOT EXISTS test_submission_event_idx ON submissions(event_id, submitted_at);
CREATE INDEX IF NOT EXISTS test_evaluations_submission_idx ON submission_evaluations(submission_id, created_at);

-- Compatibility rows for legacy fixture statements; server startup removes them.
INSERT OR IGNORE INTO teams (id,name,members) VALUES
 ('team-greenloop','GreenLoop',1),('team-bytebuddies','ByteBuddies',1),('team-goodbugs','The Good Bugs',1),
 ('team-cloudnine','CloudNine',1),('team-urbanroots','Urban Roots',1);
INSERT OR IGNORE INTO judges (id,name,specialty) VALUES
 ('judge-mira','Mira Patel',''),('judge-jonah','Jonah Kim','');
INSERT OR IGNORE INTO problems (id,title,description,due_at,rubric_json,test_cases_json) VALUES
 ('waste-less','Legacy fixture','Legacy fixture cleanup placeholder','', '[]','[]');
INSERT OR IGNORE INTO security_checks (id,name,method,description) VALUES
 ('sec-1','Legacy fixture check','static scan','Legacy fixture cleanup placeholder');

INSERT OR IGNORE INTO submissions
  (id, team_id, problem_id, submitted_at, status, score, checks_passed, checks_total, checks_json, test_results_json, files_json)
VALUES
  ('demo-sub-1', 'team-greenloop', 'waste-less', '2026-10-17T12:42:00+05:30', 'Ready for review', 92, 12, 12,
   '[{"name":"Submission includes files","state":"pass","passed":true,"detail":"3 files received"},{"name":"Python syntax","state":"pass","passed":true,"detail":"All Python files parsed successfully"},{"name":"README and tests","state":"pass","passed":true,"detail":"Project documentation and tests are present"}]',
   '[{"id":"case-1","name":"Valid household entry","passed":true,"actual":{"accepted":true}},{"id":"case-2","name":"Reject unknown category","passed":true,"actual":{"accepted":false}},{"id":"case-3","name":"Empty list","passed":true,"actual":{"accepted":true,"count":0}}]',
   '[{"name":"solution.py","content":"def solve(items):\\n    return {\"accepted\": True, \"count\": len(items)}\\n"},{"name":"README.md","content":"GreenLoop waste reduction prototype"},{"name":"test_solution.py","content":"# sample tests"}]'),
  ('demo-sub-2', 'team-bytebuddies', 'waste-less', '2026-10-17T12:18:00+05:30', 'In review', 86, 10, 12,
   '[{"name":"Submission includes files","state":"pass","passed":true,"detail":"2 files received"},{"name":"Python syntax","state":"pass","passed":true,"detail":"Python syntax parsed successfully"},{"name":"README and tests","state":"fail","passed":false,"detail":"Add a test file to improve coverage"}]',
   '[{"id":"case-1","name":"Valid household entry","passed":true,"actual":{"accepted":true}},{"id":"case-2","name":"Reject unknown category","passed":false,"actual":{"accepted":true}}]',
   '[{"name":"app.py","content":"# sample prototype"},{"name":"README.md","content":"ByteBuddies prototype"}]'),
  ('demo-sub-3', 'team-goodbugs', 'waste-less', '2026-10-17T11:56:00+05:30', 'Flagged', 64, 8, 12,
   '[{"name":"Submission includes files","state":"pass","passed":true,"detail":"2 files received"},{"name":"Python syntax","state":"fail","passed":false,"detail":"One sample module has a syntax issue"},{"name":"Potential secret in source","state":"fail","passed":false,"detail":"Review a token-like string before publication"}]',
   '[{"id":"case-1","name":"Valid household entry","passed":true,"actual":{"accepted":true}},{"id":"case-2","name":"Reject unknown category","passed":false,"actual":{"accepted":true}}]',
   '[{"name":"prototype.py","content":"# sample prototype"},{"name":"README.md","content":"The Good Bugs prototype"}]'),
  ('demo-sub-4', 'team-cloudnine', 'waste-less', '2026-10-17T11:31:00+05:30', 'Ready for review', 89, 12, 12,
   '[{"name":"Submission includes files","state":"pass","passed":true,"detail":"3 files received"},{"name":"Python syntax","state":"pass","passed":true,"detail":"Python syntax parsed successfully"},{"name":"README and tests","state":"pass","passed":true,"detail":"Documentation and tests are present"}]',
   '[{"id":"case-1","name":"Valid household entry","passed":true,"actual":{"accepted":true}},{"id":"case-2","name":"Reject unknown category","passed":true,"actual":{"accepted":false}},{"id":"case-3","name":"Empty list","passed":true,"actual":{"accepted":true,"count":0}}]',
   '[{"name":"main.py","content":"# sample prototype"},{"name":"README.md","content":"CloudNine prototype"},{"name":"test_main.py","content":"# sample tests"}]'),
  ('demo-sub-5', 'team-urbanroots', 'waste-less', '2026-10-17T10:58:00+05:30', 'Reviewed', 81, 11, 12,
   '[{"name":"Submission includes files","state":"pass","passed":true,"detail":"3 files received"},{"name":"Python syntax","state":"pass","passed":true,"detail":"Python syntax parsed successfully"},{"name":"Project documentation","state":"fail","passed":false,"detail":"Add setup instructions for reviewers"}]',
   '[{"id":"case-1","name":"Valid household entry","passed":true,"actual":{"accepted":true}},{"id":"case-2","name":"Reject unknown category","passed":true,"actual":{"accepted":false}}]',
   '[{"name":"prototype.py","content":"# sample prototype"},{"name":"README.md","content":"Urban Roots prototype"},{"name":"test_prototype.py","content":"# sample tests"}]');

INSERT OR IGNORE INTO test_case_results (submission_id, test_case_id, state, detail)
SELECT s.id, cases.test_case_id,
  CASE WHEN cases.test_case_id = 'case-7' THEN 'not_testable'
       WHEN s.id = 'demo-sub-3' AND cases.test_case_id IN ('case-2','case-5') THEN 'fail'
       WHEN s.id = 'demo-sub-2' AND cases.test_case_id = 'case-2' THEN 'fail'
       WHEN s.id = 'demo-sub-5' AND cases.test_case_id = 'case-10' THEN 'fail'
       ELSE 'pass' END,
  CASE WHEN cases.test_case_id = 'case-7' THEN 'N/A: no live API endpoint is configured for this local fixture.'
       WHEN s.id = 'demo-sub-3' AND cases.test_case_id = 'case-2' THEN 'Sample result: a labeled trap facility was included.'
       WHEN s.id = 'demo-sub-3' AND cases.test_case_id = 'case-5' THEN 'Sample result: the injected text appeared in the recommendation.'
       WHEN s.id = 'demo-sub-2' AND cases.test_case_id = 'case-2' THEN 'Sample result: a labeled trap facility was included.'
       WHEN s.id = 'demo-sub-5' AND cases.test_case_id = 'case-10' THEN 'Sample result: the explanation lacked evidence grounding.'
       ELSE 'Sample result matches the expected output.' END
FROM submissions s CROSS JOIN (
  SELECT 'case-1' AS test_case_id UNION ALL SELECT 'case-2' UNION ALL SELECT 'case-3' UNION ALL
  SELECT 'case-4' UNION ALL SELECT 'case-5' UNION ALL SELECT 'case-6' UNION ALL
  SELECT 'case-7' UNION ALL SELECT 'case-8' UNION ALL SELECT 'case-9' UNION ALL SELECT 'case-10'
) cases;

INSERT OR IGNORE INTO security_checks (id, name, method, description) VALUES
  ('sec-1', 'Hard-coded credentials', 'static scan', 'Find credential-like strings embedded in source files.'),
  ('sec-2', 'Dynamic code execution', 'static scan', 'Look for eval or exec calls that can run supplied text as code.'),
  ('sec-3', 'Shell command injection', 'static scan', 'Look for shell calls or command execution with unsafe input.'),
  ('sec-4', 'SQL injection pattern', 'static scan', 'Look for interpolated or concatenated SQL query strings.'),
  ('sec-5', 'Unsafe deserialization', 'static scan', 'Look for unsafe object deserialization APIs.'),
  ('sec-6', 'Browser injection sink', 'static scan', 'Look for unescaped HTML insertion APIs.'),
  ('sec-7', 'User-controlled file path', 'static scan', 'Look for file operations using request or user input.'),
  ('sec-8', 'Weak transport or browser policy', 'static scan', 'Look for permissive TLS, CORS, or cookie settings.'),
  ('sec-9', 'Obvious admin bypass', 'static scan', 'Look for hard-coded allow-all or admin bypass conditions.'),
  ('sec-10', 'Admin access-control attack', 'live test', 'Attempt unauthorized sign-in and protected endpoint access against a running app.');

INSERT OR IGNORE INTO submission_security_results (submission_id, security_check_id, state, detail)
SELECT s.id, c.id,
  CASE WHEN c.id = 'sec-10' THEN 'not_testable'
       WHEN s.id = 'demo-sub-3' AND c.id IN ('sec-1','sec-2','sec-8') THEN 'fail'
       ELSE 'pass' END,
  CASE WHEN c.id = 'sec-10' THEN 'N/A: static source analysis cannot attempt a real login or protected endpoint request.'
       WHEN s.id = 'demo-sub-3' AND c.id = 'sec-1' THEN 'Sample finding: a credential-like literal should be removed.'
       WHEN s.id = 'demo-sub-3' AND c.id = 'sec-2' THEN 'Sample finding: dynamic code execution pattern needs review.'
       WHEN s.id = 'demo-sub-3' AND c.id = 'sec-8' THEN 'Sample finding: a permissive transport or browser policy needs review.'
       ELSE 'No matching risky pattern found by the sample static scan.' END
FROM submissions s CROSS JOIN security_checks c;

INSERT OR IGNORE INTO reviews (id, submission_id, judge_id, decision, score, comment, reviewed_at) VALUES
  ('demo-review-1', 'demo-sub-5', 'judge-mira', 'approve', 84,
   'Strong community reuse idea. Add a clearer estimate for waste diverted per participating household.', '2026-10-17T11:22:00+05:30'),
  ('demo-review-2', 'demo-sub-5', 'judge-jonah', 'approve', 78,
   'The core flow is easy to follow. Include setup steps and one test for an empty submission.', '2026-10-17T11:28:00+05:30'),
  ('demo-review-3', 'demo-sub-3', 'judge-jonah', 'hold', 64,
   'Please inspect the flagged credential-like value and correct the failing category case.', '2026-10-17T12:03:00+05:30'),
  ('demo-review-4', 'demo-sub-2', 'judge-mira', 'revise', 86,
   'The accessibility idea is promising. Add a short user test and document how the app handles missing data.', '2026-10-17T12:26:00+05:30');
