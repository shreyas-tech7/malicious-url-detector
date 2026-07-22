# Privacy

What this service stores, for how long, and who can read it.

The input to this tool is "URLs somebody found suspicious enough to check."
That is a more sensitive corpus than it first appears — it reveals what links
people receive, and submitted URLs routinely carry tokens in their query
strings. The design below follows from that.

---

## What is stored

One row per prediction, in Supabase Postgres:

| Field | Value | Note |
|---|---|---|
| `created_at` | timestamp | |
| `url` | submitted URL, **query string and fragment stripped** | see below |
| `url_sha256` | SHA-256 of the *full* URL | groups repeat submissions |
| `verdict` | `malicious` / `benign` | |
| `score` | 0–1 | |
| `model_version` | e.g. `20260721-c4ec03f8a7` | ties a decision to a model |
| `threshold` | decision threshold in force | |
| `features` | the **top 5** contributing features only | not the full vector |
| `client_ip_hash` | salted SHA-256 of the client IP | never the address |
| `latency_ms` | integer | operational |

**Not stored:** user-agent, referer, headers, cookies, the full feature vector,
the raw IP address, or anything identifying a person.

### Query strings are stripped before storage

`?token=...`, `#access_token=...` and similar are replaced with `[redacted]`
before the row is written:

```
https://app.example/reset?token=eyJhbGciOi...   (submitted)
https://app.example/reset?[redacted]            (stored)
```

Password-reset tokens, session identifiers, pre-signed object URLs and API keys
live in query strings. Storing them verbatim would turn the prediction log into
a secondary credential store — a more attractive target than anything else in
this project. The SHA-256 of the full URL is retained, so repeat submissions
are still detectable without keeping the secret.

Verified in production: a submission containing `?token=SHOULD_NOT_BE_STORED`
was persisted as `.../reset?[redacted]`.

### IP addresses are salted-hashed, or dropped

`client_ip_hash = SHA-256(IP_HASH_SALT + ":" + ip)`.

The salt is load-bearing. IPv4 has only ~4 billion addresses, so an *unsalted*
hash is reversible with a rainbow table in minutes — pseudonymisation in name
only. **If `IP_HASH_SALT` is unset, no IP-derived value is stored at all**
rather than storing something reversible.

Rate limiting uses a *separate*, unsalted digest that exists only in memory or
in a short-lived rate-limit bucket and is never written to the prediction log.
These were once the same value, which meant an unset salt silently disabled
rate limiting along with logging.

---

## Retention

| Data | Retained | Mechanism |
|---|---|---|
| Raw prediction rows (incl. redacted URL, IP hash) | **30 days** | `purge_old_predictions(30)`, pg_cron daily 03:40 UTC |
| Daily aggregates (day, verdict, count, avg score, p95 latency) | indefinite | `prediction_daily_stats` |
| Rate-limit buckets | ~1 day | `prune_rate_limits()`, pg_cron hourly |
| Known-malicious hashes | until refreshed | public threat intel, not user data |

Retention runs **in the database** via `pg_cron`, not in the application, so
expiry does not depend on the app being invoked, on Vercel Cron firing, or on
anyone remembering to run it.

Aggregates contain no URL, no hash and no IP-derived value, so keeping them
indefinitely carries no privacy cost while preserving long-run metrics.

Verified: running `purge_old_predictions(0)` deleted 3 rows and produced 2
rollup rows, with the aggregate counts intact and the raw rows gone.

---

## Who can read it

The server holds a **restricted** Supabase key (publishable/anon), not
`service_role`, and the RLS policies are what constrain it:

| Table | Restricted key can | Cannot |
|---|---|---|
| `predictions` | INSERT | **SELECT**, UPDATE, DELETE |
| `malicious_hashes` | SELECT, INSERT, UPDATE | DELETE |
| `rate_limits` | *nothing directly* | all — reachable only via `bump_rate_limit()` |
| `prediction_daily_stats` | nothing | all |
| `keepalive` | SELECT | write |

The important row is the first: **the key the server runs on cannot read back a
single submitted URL.** It can only append.

This is deliberate. `service_role` bypasses RLS entirely, so one leaked value
reads every prediction ever logged. The application still prefers
`SUPABASE_SERVICE_ROLE_KEY` when present, but the restricted key is the
better default and the one in use.

Verified rather than assumed: with the production key, reading `predictions`
returns `[]` while the table holds rows; `DELETE` returns HTTP 204 but removes
nothing; and `prune_rate_limits()` returns `permission denied`.

**No Supabase key of any kind reaches the browser.** Nothing is `NEXT_PUBLIC_*`.
The demo page talks only to this app's own `/scan` and `/check` routes.

---

## Known gaps

Stated because a privacy page that lists only the good parts is not useful.

1. **Vercel's own platform logs are outside this design.** Vercel records
   request metadata, which includes client IP, independently of what the
   application chooses to store. Nothing in this codebase writes an IP to
   stdout — the raw value is used only to derive the two hashes and is then
   discarded — but the platform's request logging is not something the
   application controls.

   *This one could not be verified from this environment.* The runtime-logs API
   returned `403 Forbidden` — because the API token in use lacks access to the
   `shreyas-tech` team scope, **not** because of a plan limitation, which is
   what an earlier draft of this file incorrectly claimed. Either way the logs
   were not inspected, so the exact contents and retention of Vercel's own
   request logging are described from Vercel's documented behaviour rather than
   from direct observation. Treat it as unconfirmed, and check it in the Vercel
   dashboard if it matters.

2. **A restricted key with write access to `malicious_hashes`** could be used
   to poison the threat-intel corpus (false positives on `/check-file`). The
   hash-format CHECK constraints bound what can be inserted and no DELETE
   policy exists. Supplying `SUPABASE_SERVICE_ROLE_KEY` allows those two write
   policies to be dropped entirely.

3. **30 days is a judgement call**, not a regulatory determination. This is a
   portfolio project with no users and no legal basis analysis behind it.

4. **No deletion-request mechanism.** There is no account system and no way to
   identify a submitter, so there is nothing to delete on request — which is a
   consequence of the design rather than a feature of it.
