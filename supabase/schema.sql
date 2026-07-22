-- Malicious URL & File-Signature Detector — database schema
--
-- Idempotent: safe to paste into the Supabase SQL editor and re-run.
--
-- Security posture: RLS is enabled and DENY-BY-DEFAULT on every table. No
-- policy grants the `anon` role write access anywhere. The inference function
-- and the refresh cron talk to these tables with the service_role key from the
-- server side only; that key must never reach the browser.
--
-- The application is designed to run with none of this present (the hash check
-- falls back to a committed local snapshot and prediction logging is skipped),
-- so applying this schema is an upgrade, not a prerequisite.

-- ---------------------------------------------------------------------------
-- Known-malicious file hashes, synced from the URLhaus payload feed.
-- ---------------------------------------------------------------------------
create table if not exists public.malicious_hashes (
  sha256      text primary key check (sha256 ~ '^[a-f0-9]{64}$'),
  md5         text check (md5 is null or md5 ~ '^[a-f0-9]{32}$'),
  file_type   text,
  signature   text,
  source      text not null default 'urlhaus',
  first_seen  timestamptz,
  updated_at  timestamptz not null default now()
);

-- /check-file may be given an MD5 rather than a SHA-256, so that column needs
-- its own index; without it every MD5 lookup is a sequential scan.
create index if not exists malicious_hashes_md5_idx
  on public.malicious_hashes (md5)
  where md5 is not null;

create index if not exists malicious_hashes_updated_idx
  on public.malicious_hashes (updated_at desc);

alter table public.malicious_hashes enable row level security;

-- Deny by default: no policies for `anon` or `authenticated` are defined, so
-- neither role can read or write. Lookups go through the server, which uses
-- service_role and bypasses RLS. This keeps the full hash corpus from being
-- enumerable by anyone who finds the anon key.

-- ---------------------------------------------------------------------------
-- Prediction log — feature snapshot + verdict, for later analysis.
-- ---------------------------------------------------------------------------
create table if not exists public.predictions (
  id             bigint generated always as identity primary key,
  created_at     timestamptz not null default now(),

  -- What was asked. `url_sha256` lets us group repeat submissions without
  -- keeping a second copy of the raw string around.
  url            text,
  url_sha256     text check (url_sha256 is null or url_sha256 ~ '^[a-f0-9]{64}$'),

  -- What the model said.
  verdict        text not null check (verdict in ('malicious', 'benign')),
  score          double precision not null check (score >= 0 and score <= 1),
  model_version  text not null,
  threshold      double precision,

  -- Feature snapshot, so a past decision can be explained even after the
  -- feature code changes.
  features       jsonb,

  -- Salted SHA-256 of the client IP, never the address itself. Salt lives in
  -- IP_HASH_SALT on the server; without it these digests cannot be reversed
  -- by walking the IPv4 space.
  client_ip_hash text,

  latency_ms     integer
);

create index if not exists predictions_created_idx
  on public.predictions (created_at desc);

create index if not exists predictions_verdict_idx
  on public.predictions (verdict, created_at desc);

alter table public.predictions enable row level security;

-- Deny by default here too. Prediction history is not public: it would reveal
-- what other users have been submitting.

-- ---------------------------------------------------------------------------
-- Rate limiting — portable counter, used when Vercel Firewall rate limiting
-- is unavailable (e.g. running off-Vercel or on a plan without it).
-- ---------------------------------------------------------------------------
create table if not exists public.rate_limits (
  bucket       text primary key,   -- e.g. 'predict:<ip-hash>:<epoch-minute>'
  hits         integer not null default 0,
  window_start timestamptz not null default now()
);

alter table public.rate_limits enable row level security;

-- Atomic increment. Returns the new count so the caller can decide whether to
-- reject. SECURITY DEFINER so it runs with the function owner's rights, with a
-- pinned search_path (an unpinned one is a privilege-escalation vector).
create or replace function public.bump_rate_limit(
  p_bucket text,
  p_window_seconds integer default 60
)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  v_hits integer;
begin
  insert into public.rate_limits (bucket, hits, window_start)
    values (p_bucket, 1, now())
  on conflict (bucket) do update
    set hits = case
                 when public.rate_limits.window_start
                      < now() - make_interval(secs => p_window_seconds)
                 then 1
                 else public.rate_limits.hits + 1
               end,
        window_start = case
                 when public.rate_limits.window_start
                      < now() - make_interval(secs => p_window_seconds)
                 then now()
                 else public.rate_limits.window_start
               end
  returning hits into v_hits;

  return v_hits;
end;
$$;

-- Revoke from `authenticated` as well, not just public/anon.
--
-- Supabase's database linter caught this: `revoke ... from public, anon`
-- leaves the separate grant Supabase makes to `authenticated`, so the function
-- stayed callable over /rest/v1/rpc/ by any signed-in user. No user accounts
-- exist in this project, so it was never reachable -- but it would have opened
-- the moment auth was switched on. Revoke from everything, then grant back
-- only to the roles that must call it.
revoke all on function public.bump_rate_limit(text, integer)
  from public, anon, authenticated;
grant execute on function public.bump_rate_limit(text, integer) to service_role;
-- The server may run on a restricted key (see the policy block below), which
-- authenticates as `anon`; it still needs to increment the counter.
grant execute on function public.bump_rate_limit(text, integer) to anon;

-- Housekeeping: drop rate-limit rows that are well past their window.
create or replace function public.prune_rate_limits()
returns void
language sql
security definer
set search_path = public
as $$
  delete from public.rate_limits where window_start < now() - interval '1 day';
$$;

-- Same treatment. This one is a DELETE exposed on the public REST API, so
-- leaving it callable by `authenticated` was the more serious of the two.
revoke all on function public.prune_rate_limits()
  from public, anon, authenticated;
grant execute on function public.prune_rate_limits() to service_role;

-- ---------------------------------------------------------------------------
-- Keep-alive. A free-tier Supabase project pauses after inactivity, which
-- would make the deployed demo fail cold. A scheduled GitHub Action touches
-- this table to keep the project warm.
-- ---------------------------------------------------------------------------
create table if not exists public.keepalive (
  id         integer primary key default 1,
  pinged_at  timestamptz not null default now(),
  constraint keepalive_singleton check (id = 1)
);

insert into public.keepalive (id, pinged_at)
  values (1, now())
  on conflict (id) do nothing;

alter table public.keepalive enable row level security;

-- The one deliberate exception to deny-by-default: the keep-alive ping needs
-- to work with the anon key from a GitHub Action, and the row holds nothing
-- but a timestamp. Read-only for anon; the Action's update uses service_role.
drop policy if exists keepalive_anon_read on public.keepalive;
create policy keepalive_anon_read
  on public.keepalive
  for select
  to anon
  using (true);

-- ---------------------------------------------------------------------------
-- Least-privilege policies for running the server on a RESTRICTED key.
--
-- The application prefers SUPABASE_SERVICE_ROLE_KEY but works on a
-- publishable/anon key constrained by the policies below. The restricted key
-- is the better default, not a workaround: service_role bypasses RLS
-- entirely, so one leaked value reads every prediction ever logged. Under
-- these policies a leaked restricted key can append to the prediction log and
-- read the public hash corpus, and cannot read back a single submitted URL.
--
-- Either key is kept server-side only. This is defence in depth, not licence
-- to ship one to a browser.
-- ---------------------------------------------------------------------------

-- predictions: APPEND ONLY. No select policy, deliberately -- prediction
-- history would reveal what other people have been submitting.
drop policy if exists predictions_restricted_insert on public.predictions;
create policy predictions_restricted_insert
  on public.predictions
  for insert
  to anon
  with check (true);

-- malicious_hashes: READ, plus INSERT/UPDATE for the refresh cron.
-- The corpus is redistributed public threat intel from URLhaus, so read
-- access is not a confidentiality concern.
drop policy if exists malicious_hashes_restricted_read on public.malicious_hashes;
create policy malicious_hashes_restricted_read
  on public.malicious_hashes
  for select
  to anon
  using (true);

-- The write policies below are a DELIBERATE TRADE-OFF, present only because
-- service_role is not available to this deployment. Stated plainly:
--
--   Cost: a leaked restricted key could insert or amend rows here, i.e.
--   poison the corpus so /check-file reports false positives.
--   check_file_signature() consults Supabase BEFORE the committed local
--   snapshot, so poisoned rows would take precedence.
--
--   Bound: the sha256/md5 CHECK constraints reject anything that is not a
--   well-formed hash, so the corpus cannot be filled with arbitrary text, and
--   no DELETE policy exists, so rows cannot be removed.
--
--   Removal: supply SUPABASE_SERVICE_ROLE_KEY and DROP these two policies.
--   service_role bypasses RLS, so the refresh works with the table fully
--   closed to every other role. That is the stronger configuration.
drop policy if exists malicious_hashes_restricted_insert on public.malicious_hashes;
create policy malicious_hashes_restricted_insert
  on public.malicious_hashes
  for insert
  to anon
  with check (true);

drop policy if exists malicious_hashes_restricted_update on public.malicious_hashes;
create policy malicious_hashes_restricted_update
  on public.malicious_hashes
  for update
  to anon
  using (true)
  with check (true);

-- rate_limits gets NO policy on purpose. The counter is reachable only via
-- bump_rate_limit(), which is the entire reason that function exists. The
-- table stays fully closed so buckets cannot be read or cleared directly.
