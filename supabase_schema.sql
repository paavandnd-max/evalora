-- Evalora multi-event schema. Apply once in the Supabase SQL Editor.
-- Reviewer reports, repository content, evaluator configuration, and source documents are never
-- readable by participant accounts. Role and username claims must be stored in app_metadata.

create table if not exists public.events (
  id text primary key,
  name text not null unique,
  description text not null default '',
  organizer text not null default '',
  event_date text not null default '',
  deadline text not null default '',
  status text not null default 'draft' check (status in ('draft','open','closed')),
  problem_id text not null,
  statement_text text not null,
  allow_resubmissions boolean not null default false,
  active_config_version integer not null default 0,
  created_by uuid references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.event_documents (
  id text primary key,
  event_id text not null references public.events(id) on delete cascade,
  version integer not null,
  filename text not null,
  mime_type text not null,
  content_base64 text,
  created_at timestamptz not null default now(),
  unique (event_id,version)
);

create table if not exists public.event_config_versions (
  event_id text not null references public.events(id) on delete cascade,
  version integer not null check (version > 0),
  config jsonb not null,
  approved boolean not null default false,
  created_by uuid references auth.users(id),
  created_at timestamptz not null default now(),
  primary key (event_id, version)
);

create table if not exists public.event_judges (
  event_id text not null references public.events(id) on delete cascade,
  username text not null,
  judge_name text not null,
  assigned_by uuid references auth.users(id),
  assigned_at timestamptz not null default now(),
  primary key (event_id, username)
);

create table if not exists public.event_teams (
  id text primary key,
  event_id text not null references public.events(id) on delete cascade,
  owner_id uuid references auth.users(id) on delete cascade,
  team_name text not null,
  created_at timestamptz not null default now(),
  unique (event_id, team_name),
  unique (event_id, owner_id)
);

create table if not exists public.submissions (
  id text primary key,
  owner_id uuid references auth.users(id) on delete set null,
  team text not null,
  event_id text not null references public.events(id),
  event_team_id text not null references public.event_teams(id),
  problem_id text not null,
  problem text not null,
  members integer not null default 1 check (members > 0),
  submitted_at timestamptz not null default now(),
  status text not null default 'Submitted',
  evaluation_status text not null default 'queued'
    check (evaluation_status in ('queued','evaluating','completed','failed','requires_manual_review')),
  config_version integer not null,
  score integer not null default 0 check (score between 0 and 100),
  checks_passed integer not null default 0 check (checks_passed >= 0),
  checks_total integer not null default 0 check (checks_total >= checks_passed),
  checks jsonb not null default '[]'::jsonb,
  test_results jsonb not null default '[]'::jsonb,
  files jsonb not null default '[]'::jsonb,
  repository_url text not null,
  evaluation_report jsonb not null default '{}'::jsonb,
  reviewed boolean not null default false,
  idempotency_key text not null default ''
);

-- The original single-event schema enforced one repository per team/problem.
-- Event-level resubmission rules and idempotency now replace that global constraint.
drop index if exists public.submissions_team_problem_repo_unique_idx;

alter table public.submissions
  add column if not exists event_id text references public.events(id),
  add column if not exists event_team_id text references public.event_teams(id),
  add column if not exists evaluation_status text not null default 'completed',
  add column if not exists config_version integer not null default 0,
  add column if not exists idempotency_key text not null default '',
  add column if not exists repository_url text not null default '',
  add column if not exists evaluation_report jsonb not null default '{}'::jsonb;

-- Public participants and staff-assisted manual tests may submit without a team auth account.
-- Their rows remain private because the only read policy requires an assigned reviewer.
alter table public.event_teams alter column owner_id drop not null;
alter table public.submissions alter column owner_id drop not null;

create table if not exists public.submission_evaluations (
  id text primary key,
  submission_id text not null references public.submissions(id) on delete cascade,
  event_id text not null references public.events(id),
  config_version integer not null,
  evaluation_status text not null,
  report jsonb not null,
  created_at timestamptz not null default now()
);

create table if not exists public.audit_log (
  id text primary key,
  event_id text references public.events(id) on delete set null,
  actor_username text not null,
  action text not null,
  target_id text not null default '',
  detail jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

-- Shared fixed-window counters for Supabase-backed multi-instance deployments.
create table if not exists public.api_rate_limits (
  bucket text not null,
  identity_hash text not null check (identity_hash ~ '^[0-9a-f]{64}$'),
  window_started double precision not null,
  hits integer not null check (hits >= 0),
  primary key (bucket, identity_hash)
);
create index if not exists api_rate_limits_window_idx on public.api_rate_limits(bucket,window_started);

-- Preserve data from the former single-problem schema as a closed legacy event.
insert into public.events (id,name,description,organizer,event_date,deadline,status,problem_id,statement_text,active_config_version)
select 'legacy-event','Migrated legacy event','Existing submissions migrated from the single-event workspace.','', '', '', 'closed',
  'legacy-problem','The original problem statement was not stored in the previous schema.',1
where exists (select 1 from public.submissions)
on conflict (id) do nothing;
insert into public.event_config_versions (event_id,version,config,approved)
select 'legacy-event',1,'{"approved":true,"requirements":[{"id":"R001","requirement":"Review the migrated submission against the original event materials.","evidence":"Historical reviewer report and source repository."}],"security_checks":"mandatory_baseline","mandatory_security_check_count":10}',true
where exists (select 1 from public.events where id='legacy-event')
on conflict (event_id,version) do nothing;
insert into public.event_teams (id,event_id,owner_id,team_name)
select 'legacy-' || s.owner_id::text,'legacy-event',s.owner_id,s.team
from public.submissions s
where s.owner_id is not null and s.team is not null and s.team<>''
on conflict do nothing;
update public.submissions s set event_id='legacy-event',problem_id='legacy-problem',
  event_team_id=et.id,config_version=1
from public.event_teams et where et.event_id='legacy-event' and et.owner_id=s.owner_id and et.team_name=s.team
  and (s.event_id is null or s.event_id='');
insert into public.event_judges (event_id,username,judge_name,assigned_by)
select 'legacy-event',coalesce(u.raw_app_meta_data->>'username',split_part(u.email,'@',1)),
  coalesce(u.raw_user_meta_data->>'name',u.email),u.id
from auth.users u where u.raw_app_meta_data->>'role'='judge'
  and exists (select 1 from public.events where id='legacy-event')
on conflict (event_id,username) do nothing;

create or replace function public.evalora_can_review(p_event_id text)
returns boolean language sql stable security definer set search_path = '' as $$
  select coalesce(auth.jwt() -> 'app_metadata' ->> 'role','') = 'admin'
     or exists (select 1 from public.event_judges j
                 where j.event_id = p_event_id
                   and lower(j.username) = lower(coalesce(auth.jwt() -> 'app_metadata' ->> 'username','')))
$$;

create or replace function public.evalora_event_open(p_event_id text)
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.events e
    join public.event_config_versions c on c.event_id=e.id
      and c.version=e.active_config_version and c.approved=true
    where e.id=p_event_id and e.status='open'
  )
$$;

create or replace function public.evalora_config_approved(p_event_id text, p_version integer)
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.event_config_versions c
    where c.event_id=p_event_id and c.version=p_version and c.approved=true)
$$;

create or replace function public.evalora_config_is_active(p_event_id text, p_version integer)
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.events e join public.event_config_versions c
    on c.event_id=e.id and c.version=e.active_config_version and c.approved=true
    where e.id=p_event_id and e.active_config_version=p_version and e.status='open')
$$;

create or replace function public.evalora_consume_rate_limit(
  p_bucket text, p_identity_hash text, p_limit integer, p_window_seconds integer
)
returns table(allowed boolean, retry_after integer)
language plpgsql security definer set search_path = '' as $$
declare
  v_now double precision := extract(epoch from clock_timestamp());
  v_started double precision;
  v_hits integer;
  v_inserted integer;
begin
  if p_bucket is null or length(p_bucket) > 64
     or p_identity_hash is null or p_identity_hash !~ '^[0-9a-f]{64}$'
     or p_limit is null or p_limit < 1
     or p_window_seconds is null or p_window_seconds < 1 then
    raise exception 'invalid rate-limit arguments';
  end if;

  insert into public.api_rate_limits(bucket,identity_hash,window_started,hits)
  values (p_bucket,p_identity_hash,v_now,0)
  on conflict (bucket,identity_hash) do nothing;
  get diagnostics v_inserted = row_count;
  if v_inserted = 1 then
    delete from public.api_rate_limits r
      where r.bucket=p_bucket
        and r.window_started < v_now-greatest(p_window_seconds,86400);
  end if;

  select r.window_started,r.hits into v_started,v_hits
    from public.api_rate_limits r
    where r.bucket=p_bucket and r.identity_hash=p_identity_hash
    for update;

  if v_now >= v_started + p_window_seconds then
    v_started := v_now;
    v_hits := 0;
  end if;

  if v_hits >= p_limit then
    return query select false,greatest(1,ceil(v_started+p_window_seconds-v_now)::integer);
    return;
  end if;

  v_hits := v_hits + 1;
  update public.api_rate_limits r
    set window_started=v_started,hits=v_hits
    where r.bucket=p_bucket and r.identity_hash=p_identity_hash;
  return query select true,0;
end $$;

create or replace function public.evalora_block_duplicate_repository()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if new.event_id is not null and new.event_team_id is not null and coalesce(new.repository_url,'') <> ''
     and exists (select 1 from public.events e where e.id=new.event_id and coalesce(e.allow_resubmissions,false)=false)
     and exists (select 1 from public.submissions s where s.event_id=new.event_id
       and s.event_team_id=new.event_team_id and s.repository_url=new.repository_url) then
    raise exception 'duplicate repository submission' using errcode='23505';
  end if;
  return new;
end $$;

revoke all on function public.evalora_can_review(text) from public, anon;
revoke all on function public.evalora_event_open(text) from public, anon;
revoke all on function public.evalora_config_approved(text,integer) from public, anon;
revoke all on function public.evalora_config_is_active(text,integer) from public, anon;
revoke all on function public.evalora_consume_rate_limit(text,text,integer,integer) from public, anon, authenticated;
revoke all on function public.evalora_block_duplicate_repository() from public, anon, authenticated;
grant execute on function public.evalora_can_review(text) to authenticated;
grant execute on function public.evalora_event_open(text) to authenticated;
grant execute on function public.evalora_config_approved(text,integer) to authenticated;
grant execute on function public.evalora_config_is_active(text,integer) to authenticated;
grant execute on function public.evalora_consume_rate_limit(text,text,integer,integer) to service_role;

alter table public.events enable row level security;
alter table public.event_documents enable row level security;
alter table public.event_config_versions enable row level security;
alter table public.event_judges enable row level security;
alter table public.event_teams enable row level security;
alter table public.submissions enable row level security;
alter table public.submission_evaluations enable row level security;
alter table public.audit_log enable row level security;
alter table public.api_rate_limits enable row level security;

revoke all on public.events, public.event_documents, public.event_config_versions, public.event_judges,
  public.event_teams, public.submissions, public.submission_evaluations, public.audit_log from anon, authenticated;
grant all on public.events, public.event_documents, public.event_config_versions, public.event_judges,
  public.event_teams, public.submissions, public.submission_evaluations, public.audit_log to service_role;
revoke all on public.api_rate_limits from public, anon, authenticated;
grant all on public.api_rate_limits to service_role;
grant select on public.events to authenticated;
grant select on public.event_config_versions, public.event_judges, public.event_teams,
  public.submissions, public.submission_evaluations to authenticated;
grant insert on public.event_teams to authenticated;
grant insert (id, owner_id, team, event_id, event_team_id, problem_id, problem, members, submitted_at,
  status, repository_url, config_version, idempotency_key) on public.submissions to authenticated;
grant update (reviewed, status, score, checks_passed, checks_total, checks, test_results, files,
  evaluation_report, evaluation_status) on public.submissions to authenticated;
grant insert, update, delete on public.events, public.event_config_versions, public.event_judges to authenticated;

drop policy if exists events_reviewers_or_open_participants on public.events;
create policy events_reviewers_or_open_participants on public.events for select to authenticated
  using (public.evalora_can_review(id) or
    (coalesce(auth.jwt() -> 'app_metadata' ->> 'role','')='team' and public.evalora_event_open(id)));
drop policy if exists events_admin_manage on public.events;
create policy events_admin_manage on public.events for all to authenticated
  using (coalesce(auth.jwt() -> 'app_metadata' ->> 'role','')='admin')
  with check (coalesce(auth.jwt() -> 'app_metadata' ->> 'role','')='admin');

drop policy if exists event_documents_reviewer_only on public.event_documents;
create policy event_documents_reviewer_only on public.event_documents for all to authenticated
  using (public.evalora_can_review(event_id)) with check (public.evalora_can_review(event_id));

drop policy if exists event_config_reviewer_read on public.event_config_versions;
create policy event_config_reviewer_read on public.event_config_versions for select to authenticated
  using (public.evalora_can_review(event_id));
drop policy if exists event_config_admin_manage on public.event_config_versions;
create policy event_config_admin_manage on public.event_config_versions for all to authenticated
  using (coalesce(auth.jwt() -> 'app_metadata' ->> 'role','')='admin')
  with check (coalesce(auth.jwt() -> 'app_metadata' ->> 'role','')='admin');

drop policy if exists event_judges_self_or_admin on public.event_judges;
create policy event_judges_self_or_admin on public.event_judges for select to authenticated
  using (public.evalora_can_review(event_id));
drop policy if exists event_judges_admin_manage on public.event_judges;
create policy event_judges_admin_manage on public.event_judges for all to authenticated
  using (coalesce(auth.jwt() -> 'app_metadata' ->> 'role','')='admin')
  with check (coalesce(auth.jwt() -> 'app_metadata' ->> 'role','')='admin');

drop policy if exists event_teams_reviewer_read on public.event_teams;
create policy event_teams_reviewer_read on public.event_teams for select to authenticated
  using (public.evalora_can_review(event_id));
drop policy if exists event_teams_self_read on public.event_teams;
create policy event_teams_self_read on public.event_teams for select to authenticated
  using (owner_id=(select auth.uid()) and coalesce(auth.jwt() -> 'app_metadata' ->> 'role','')='team');
drop policy if exists event_teams_self_insert on public.event_teams;
create policy event_teams_self_insert on public.event_teams for insert to authenticated
  with check (owner_id=(select auth.uid())
    and coalesce(auth.jwt() -> 'app_metadata' ->> 'role','')='team'
    and team_name=coalesce(auth.jwt() -> 'app_metadata' ->> 'team','')
    and public.evalora_event_open(event_id));

drop policy if exists "Team members see their team's submissions; judges see all" on public.submissions;
drop policy if exists "Only reviewers can read submissions and reports" on public.submissions;
drop policy if exists "Teams submit only as themselves" on public.submissions;
drop policy if exists "Judges update evaluation results" on public.submissions;
drop policy if exists submissions_assigned_reviewers_read on public.submissions;
create policy submissions_assigned_reviewers_read on public.submissions for select to authenticated
  using (public.evalora_can_review(event_id));
drop policy if exists submissions_eligible_team_insert on public.submissions;
create policy submissions_eligible_team_insert on public.submissions for insert to authenticated
  with check (owner_id=(select auth.uid())
    and coalesce(auth.jwt() -> 'app_metadata' ->> 'role','')='team'
    and team=coalesce(auth.jwt() -> 'app_metadata' ->> 'team','')
    and status='Submitted'
    and public.evalora_event_open(event_id)
    and exists (select 1 from public.event_teams et where et.id=submissions.event_team_id
      and et.event_id=submissions.event_id and et.owner_id=(select auth.uid()) and et.team_name=submissions.team)
    and public.evalora_config_is_active(submissions.event_id,submissions.config_version)
    and exists (select 1 from public.events e where e.id=submissions.event_id
      and e.problem_id=submissions.problem_id and e.name=submissions.problem));
drop policy if exists submissions_reviewers_update on public.submissions;
create policy submissions_reviewers_update on public.submissions for update to authenticated
  using (public.evalora_can_review(event_id)) with check (public.evalora_can_review(event_id));

drop policy if exists evaluation_history_reviewers_read on public.submission_evaluations;
create policy evaluation_history_reviewers_read on public.submission_evaluations for select to authenticated
  using (public.evalora_can_review(event_id));
drop policy if exists audit_admin_read on public.audit_log;
create policy audit_admin_read on public.audit_log for select to authenticated
  using (coalesce(auth.jwt() -> 'app_metadata' ->> 'role','')='admin');

create index if not exists events_status_deadline_idx on public.events(status, deadline);
create index if not exists event_judges_username_idx on public.event_judges(lower(username),event_id);
create index if not exists event_teams_owner_idx on public.event_teams(owner_id,event_id);
create index if not exists submissions_event_submitted_idx on public.submissions(event_id,submitted_at desc);
create index if not exists submissions_team_event_idx on public.submissions(event_team_id,event_id,submitted_at desc);
create index if not exists evaluations_submission_history_idx on public.submission_evaluations(submission_id,created_at desc);
create unique index if not exists submissions_idempotency_idx on public.submissions(owner_id,idempotency_key)
  where idempotency_key<>'';
drop index if exists public.submissions_event_team_repo_unique_idx;
create index if not exists submissions_event_team_repo_idx
  on public.submissions(event_id,event_team_id,repository_url)
  where event_id is not null and event_team_id is not null and repository_url<>'';
drop trigger if exists submissions_duplicate_repository_guard on public.submissions;
create trigger submissions_duplicate_repository_guard
  before insert on public.submissions
  for each row execute function public.evalora_block_duplicate_repository();
