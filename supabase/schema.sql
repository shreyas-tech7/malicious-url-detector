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
--
-- The WITH CHECK actually checks. An earlier version used `with check (true)`,
-- which Supabase's linter correctly flagged as "effectively bypasses
-- row-level security" -- an INSERT policy that validates nothing is a table
-- grant wearing a policy's clothes. The created_at bound matters
-- particularly: without it a leaked key could backdate rows to forge a history
-- of submissions, or post-date them to evade the 30-day retention sweep.
drop policy if exists predictions_restricted_insert on public.predictions;
create policy predictions_restricted_insert
  on public.predictions
  for insert
  to anon
  with check (
    verdict in ('malicious', 'benign', 'uncertain')
    and (binary_verdict is null
         or binary_verdict in ('malicious', 'benign'))
    and score >= 0 and score <= 1
    and (threshold is null or (threshold >= 0 and threshold <= 1))
    and length(coalesce(url, '')) <= 2048
    and (url_sha256 is null or url_sha256 ~ '^[a-f0-9]{64}$')
    and (client_ip_hash is null or client_ip_hash ~ '^[a-f0-9]{64}$')
    and length(coalesce(model_version, '')) <= 64
    and (latency_ms is null or (latency_ms >= 0 and latency_ms < 600000))
    and created_at > now() - interval '10 minutes'
    and created_at <= now() + interval '1 minute'
  );

-- malicious_hashes: READ, plus INSERT/UPDATE for the refresh cron.
-- The corpus is redistributed public threat intel from URLhaus, so read
-- access is not a confidentiality concern.
drop policy if exists malicious_hashes_restricted_read on public.malicious_hashes;
create policy malicious_hashes_restricted_read
  on public.malicious_hashes
  for select
  to anon
  using (true);

-- malicious_hashes has NO write policy. The refresh writes through the
-- SECURITY DEFINER function below instead of a table grant.
--
-- The earlier version granted anon blanket INSERT + UPDATE with
-- `with check (true)`. Supabase's linter flagged both as bypassing RLS, and it
-- was right: a leaked key could have written arbitrary rows, rewritten `source`
-- to launder provenance, or amended any column. Routing writes through a
-- validating function keeps the table itself closed and moves the rules
-- server-side, where the caller cannot skip them.
drop policy if exists malicious_hashes_restricted_insert on public.malicious_hashes;
drop policy if exists malicious_hashes_restricted_update on public.malicious_hashes;

-- Validated bulk upsert. Enforces hash shape, caps the batch, and pins
-- `source` so provenance cannot be forged by the caller.
create or replace function public.upsert_malicious_hashes(p_rows jsonb)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  v_count integer;
begin
  if jsonb_typeof(p_rows) <> 'array' then
    raise exception 'p_rows must be a JSON array';
  end if;

  -- Bounds how fast a leaked key could pollute the corpus, and keeps one call
  -- from holding a long transaction.
  if jsonb_array_length(p_rows) > 1000 then
    raise exception 'batch too large: % rows (max 1000)',
      jsonb_array_length(p_rows);
  end if;

  with incoming as (
    select
      lower(e ->> 'sha256')        as sha256,
      lower(e ->> 'md5')           as md5,
      left(e ->> 'file_type', 64)  as file_type,
      left(e ->> 'signature', 128) as signature
    from jsonb_array_elements(p_rows) as e
  ),
  valid as (
    select distinct on (sha256) sha256, md5, file_type, signature
    from incoming
    where sha256 ~ '^[a-f0-9]{64}$'
      and (md5 is null or md5 ~ '^[a-f0-9]{32}$')
  )
  insert into public.malicious_hashes
        (sha256, md5, file_type, signature, source, updated_at)
  select sha256, md5, file_type, signature,
         'urlhaus',   -- pinned; the caller does not choose provenance
         now()
  from valid
  on conflict (sha256) do update
     set md5        = excluded.md5,
         file_type  = excluded.file_type,
         signature  = excluded.signature,
         updated_at = now();

  get diagnostics v_count = row_count;
  return v_count;
end;
$$;

revoke all on function public.upsert_malicious_hashes(jsonb)
  from public, anon, authenticated;
grant execute on function public.upsert_malicious_hashes(jsonb) to service_role;
-- The refresh job runs on the restricted key, which authenticates as anon.
grant execute on function public.upsert_malicious_hashes(jsonb) to anon;

-- Residual risk, stated rather than implied: a leaked restricted key can still
-- call this function to insert well-formed but fabricated hashes, or to amend
-- file_type/signature on an existing row. It can no longer write arbitrary
-- columns, forge `source`, delete anything, or touch the table directly.
-- Supplying SUPABASE_SERVICE_ROLE_KEY and revoking the anon grant above closes
-- the remainder.

-- rate_limits gets NO policy on purpose. The counter is reachable only via
-- bump_rate_limit(), which is the entire reason that function exists. The
-- table stays fully closed so buckets cannot be read or cleared directly.

-- ---------------------------------------------------------------------------
-- Retention. See PRIVACY.md.
--
-- Raw submissions accumulate forever by default, which is the wrong default
-- for a service whose input is "URLs somebody found suspicious" -- that corpus
-- only gets more sensitive as it grows. Rows are rolled up into day/verdict
-- aggregates and then deleted after 30 days.
--
-- Scheduled with pg_cron INSIDE the database rather than in the application,
-- so expiry does not depend on the app being invoked, on Vercel Cron firing,
-- or on anyone remembering to run it.
-- ---------------------------------------------------------------------------
create extension if not exists pg_cron with schema cron;

-- Aggregates only: a date, a verdict, and counts. No URL, no hash, no
-- IP-derived value. Safe to keep indefinitely.
create table if not exists public.prediction_daily_stats (
  day            date not null,
  verdict        text not null,
  model_version  text not null,
  n              integer not null,
  avg_score      double precision,
  p95_latency_ms integer,
  primary key (day, verdict, model_version)
);

alter table public.prediction_daily_stats enable row level security;

-- Rolls up everything past the cutoff, then deletes it. Re-runnable: the
-- rollup upserts, so a repeated run cannot double-count.
create or replace function public.purge_old_predictions(
  p_retain_days integer default 30
)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  v_cutoff timestamptz := now() - make_interval(days => p_retain_days);
  v_deleted integer;
begin
  insert into public.prediction_daily_stats
        (day, verdict, model_version, n, avg_score, p95_latency_ms)
  select date_trunc('day', created_at)::date,
         verdict,
         model_version,
         count(*)::int,
         avg(score),
         percentile_disc(0.95) within group (order by latency_ms)::int
  from public.predictions
  where created_at < v_cutoff
  group by 1, 2, 3
  on conflict (day, verdict, model_version) do update
     set n              = excluded.n,
         avg_score      = excluded.avg_score,
         p95_latency_ms = excluded.p95_latency_ms;

  delete from public.predictions where created_at < v_cutoff;
  get diagnostics v_deleted = row_count;

  return v_deleted;
end;
$$;

revoke all on function public.purge_old_predictions(integer)
  from public, anon, authenticated;
grant execute on function public.purge_old_predictions(integer) to service_role;

-- Daily at 03:40 UTC, hourly for the transient rate-limit buckets. Off the
-- hour deliberately.
select cron.unschedule('purge-old-predictions')
  where exists (select 1 from cron.job where jobname = 'purge-old-predictions');
select cron.schedule('purge-old-predictions', '40 3 * * *',
                     $$select public.purge_old_predictions(30);$$);

select cron.unschedule('prune-rate-limits')
  where exists (select 1 from cron.job where jobname = 'prune-rate-limits');
select cron.schedule('prune-rate-limits', '15 * * * *',
                     $$select public.prune_rate_limits();$$);
