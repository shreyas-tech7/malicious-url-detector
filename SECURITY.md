# Security Audit — SENTINEL

Three passes, newest first.

1. **Third pass** (below) — closed loose ends, narrowed database writes, and
   extended the audit to the Python dependency tree and error paths.
2. **Hardening pass** — re-verified the first pass against the live deployment
   after Supabase was wired up, and found three of its conclusions no longer
   true.
3. **First pass** — the original static review of the public attack surface.

Findings marked **[FIXED]** were remediated in the pass that found them.

---

## Third pass — loose ends and one more layer

### Database writes narrowed past a table grant **[FIXED]**

The hardening pass gave the restricted key blanket `INSERT`/`UPDATE` on
`malicious_hashes` and an `INSERT` on `predictions`, all with
`with check (true)`. Supabase's linter flagged all three as *"effectively
bypasses row-level security"*, which is the correct reading: an INSERT policy
that validates nothing is a table grant wearing a policy's clothes.

Now:

- `malicious_hashes` has **no write policy at all**. Writes go through
  `upsert_malicious_hashes(jsonb)`, a `SECURITY DEFINER` function that
  validates hash shape, caps batches at 1000, and pins `source` server-side.
- `predictions` keeps its INSERT policy, but the check validates value ranges,
  hash formats and field lengths, and **bounds `created_at`** — so rows cannot
  be backdated to forge a submission history, nor post-dated to slip past the
  30-day retention sweep.

Verified against the live database rather than assumed — and the "204 means it
worked" trap was checked twice, having already been a false alarm once:

| Probe | Result |
|---|---|
| Direct `INSERT` on `malicious_hashes` | `42501` RLS violation |
| `PATCH` against a row that **actually exists** | HTTP 204, row **unchanged** |
| Full policy set (`pg_policies`) | 3 policies: 2× SELECT, 1× validated INSERT. **No UPDATE or DELETE policy on any table.** |
| 3 malformed hashes via the function | 0 accepted |
| 1 valid + 2 malformed | exactly 1 accepted |
| 1500-row batch | rejected |
| `"source": "attacker"` in payload | row still reads `source=urlhaus` |

The three `rls_policy_always_true` warnings are gone. Two
`anon_security_definer_function_executable` warnings remain and are **accepted**:
the server runs on the restricted key, which authenticates as `anon`, and those
two functions are precisely what it must call. Narrow validated functions
callable by `anon` is the intended design, and is strictly better than the broad
table grants they replaced.

**Residual risk, stated plainly:** a leaked restricted key can still submit
well-formed but fabricated hashes, or amend `file_type`/`signature` on an
existing row. It can no longer write arbitrary columns, forge provenance, or
delete anything. Supplying `SUPABASE_SERVICE_ROLE_KEY` and revoking the `anon`
grant closes the rest.

### The `authenticated` grant gap, confirmed closed everywhere **[VERIFIED]**

The hardening pass fixed the one function the linter named. This pass checked
**all** of them by reading the ACLs directly, on the theory that the same
`revoke` line had probably been copy-pasted:

| Function | `anon` | `authenticated` | `service_role` |
|---|---|---|---|
| `bump_rate_limit` | ✔ *(intended)* | ✘ | ✔ |
| `prune_rate_limits` | ✘ | ✘ | ✔ |
| `purge_old_predictions` | ✘ | ✘ | ✔ |

### Fixed-window rate-limit burst **[FIXED]**

Previously documented as a known limitation. It turned out to be a one-line
fix: `bump_rate_limit` already resets on elapsed time, and the 2× burst came
entirely from the *caller* embedding an epoch-minute in the bucket key, which
manufactured a fresh counter at every wall-clock boundary. The key is now
`predict:{hash}` with no time component, so the window is anchored to the
caller's first request. The in-memory fallback carried the same bug and now
tracks `(window_start, hits)`.

Residual slack, stated exactly rather than hedged: spending the budget at the
end of one window and again at the start of the next approaches 2× over a short
span — but across a genuine 60-second gap, not at an exploitable clock tick. A
true sliding window needs a per-caller timestamp log, which is not worth the
write amplification here.

### Validation errors echoed attacker input back **[FIXED]**
- **Severity:** Low | **Classification:** CWE-1188 / response amplification

FastAPI's default validation handler includes an `input` key containing the
value that failed. Observed directly: a 3 KB `header_b64` was quoted **in full**
by the very 422 rejecting it for exceeding 512 characters. Free response
amplification and gratuitous reflection of attacker bytes.

Replaced with a handler that keeps `type`/`loc`/`msg`, drops `input`/`ctx`, and
caps at 10 errors. Also fixed the catch-all swallowing method mismatches:
`GET /api/predict` returned 404 and now returns 405 with an `Allow` header.

No error path leaks a stack trace, file path, or internal identifier — probed
with malformed JSON, wrong types, arrays-for-objects, missing content-type and
unknown routes, and asserted in the live suite against a leak list
(`traceback`, `/var/task`, `site-packages`, `.py", line`, `sqlstate`, …).

### Python dependencies audited **[FIXED]**

Everything before this pass was `npm audit` on the JavaScript side only.
`pip-audit` found `setuptools 79.0.1` (PYSEC-2026-3447) in the local
environment. Not in `api/requirements.txt` and never imported at runtime —
confirmed by AST-walking the runtime modules for `setuptools`/`pkg_resources`
imports — but *unreachable is weaker than absent*, the same standard applied to
`sharp`. Upgraded to 83.0.0; the environment is clean.

`api/requirements.txt` and `ml/requirements.txt` were both already clean. CI now
runs `pip-audit` on the deployed set as a **blocking** step and on the training
set non-blocking.

### Raw IPs in Vercel's platform logs — answered **[NON-ISSUE]**

Two earlier attempts to check this failed and each produced a *different* wrong
explanation for the failure while leaving the question open. Read through the
authenticated CLI, a real runtime log record contains:

```
id, timestamp, deploymentId, projectId, level, message, source, domain,
requestMethod, requestPath, responseStatusCode, environment, branch, cache,
traceId, logs
```

**No client-IP field.** The documented "known gap" did not exist; PRIVACY.md is
corrected. Scope: this is the runtime function log, not an edge/access log a
Log Drain on a higher plan might expose.

### CORS and security headers — both non-issues **[VERIFIED]**

- **CORS** is locked by omission: no `Access-Control-Allow-Origin` on preflight
  or response, so browsers block cross-origin reads entirely. Stricter than
  "locked to the known origin". Adding CORS middleware could only loosen it, so
  the change made was a regression test that fails if anyone adds one.
- **Headers** were already complete from Round 1's `vercel.json` — CSP with
  `frame-ancestors 'none'`, HSTS, `nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy`, `Permissions-Policy`. Now asserted live rather than assumed.

### Dependabot enabled

Split so the deployed Python set is tracked separately from training-only
dependencies — a bundle-affecting advisory should not be buried among dev ones.

---

## Hardening pass — what changed since the first review

Read this before the original findings; several of them are superseded.

### Rate limiting was silently dead again **[FIXED]**

The first pass fixed "no effective rate limiting" with an in-memory counter and
verified it live (30 × 200, then 429). Wiring up Supabase **reintroduced the
bug in a new form**:

`_supabase_post` sent `Prefer: return=minimal` on every call, including the
`bump_rate_limit` RPC whose return value is the entire point. PostgREST
honoured it and returned an empty body, the caller read that as "database
unavailable", and every request fell through to the per-instance in-memory
counter. The Postgres counters were incrementing correctly the whole time —
nothing ever read them.

Diagnosed by calling the RPC directly: with the header, `Content-Length: 1`
and an empty body; without it, `2`.

Also worth recording: the first re-test of this **looked** like a pass and was
not. 35 sequential requests returned 35 × 200, and the buckets showed 24 + 11 —
the Supabase round-trip had slowed the loop enough to straddle a minute
boundary, so no single window ever exceeded 30. A faster, parallel probe was
needed to test the thing being claimed.

Now verified properly: **40 parallel requests → exactly 30 × 200 and 10 × 429**,
with the bucket recording all 40 attempts. Parallelism is what makes this
meaningful — concurrent requests land on different instances, so an in-memory
counter could not produce that result. The shared counter is authoritative.

**Known limitation, not fixed:** the window is fixed, not sliding, so a caller
who straddles a minute boundary can burst up to 2× the limit. That is inherent
to fixed-window limiting and is an abuse deterrent, not a DoS control. Vercel
Firewall rate limiting at the edge would be the answer if this ever needed to
be one; it was not added because the Supabase counter now works across
instances, which was the actual gap.

### `npm audit` was no longer clean **[FIXED]**

The first pass documented "2 moderates, non-applicable". That reasoning had
gone stale: a **high**-severity advisory for `sharp <0.35.0` (four inherited
libvips CVEs) had since been published against the pinned Next version.

`sharp` reaches the tree only through `next`, and this app uses no
`next/image`, so it was not reachable — but "not reachable" is a weaker claim
than "not present". Pinning `sharp ^0.35.3` and `postcss ^8.5.10` via
`overrides` takes the tree to **0 vulnerabilities**, production and dev, with
the build unchanged and without npm's suggested downgrade of Next to 9.3.3.

CI now runs `npm audit --omit=dev --audit-level=high` so this cannot go stale
again unnoticed.

### A `SECURITY DEFINER` grant gap the first pass missed **[FIXED]**

Found by Supabase's database linter, not by the static review. The schema did
`revoke all ... from public, anon`, which leaves the separate grant Supabase
makes to `authenticated`, so both definer functions stayed callable over
`/rest/v1/rpc/`. `prune_rate_limits()` is a DELETE exposed on the public REST
API. No user accounts exist in this project, so it was never reachable — it
would have opened the moment auth was switched on. Now revoked from every role
and granted back explicitly.

### Bundle size now has a guard **[FIXED]**

Measured at **224.7 MB against Vercel's 250 MB limit — 25.3 MB of headroom**,
tighter than the ~210 MB estimated in the first pass. `scripts/check-bundle-size.mjs`
fails at 230 MB and runs in CI, so crossing the limit surfaces in a pull
request rather than as a failed production deploy.

### Regression tests for the bugs that unit tests could not see **[ADDED]**

`ml/tests/test_live_deployment.py` — 13 integration tests against the real
deployment, including:

- `/scan` returns a verdict rather than a Deployment Protection login page
  (the exact SSRF-fix regression, which passed every unit test and every build)
- the production alias is reachable with no cookie or auth header
- a non-routable host (`10.255.255.1`) and the cloud metadata address
  (`169.254.169.254`) both return a fast, ordinary classification — behavioural
  evidence that the service does not dereference submitted URLs
- security headers from `vercel.json` are actually applied

### Re-confirmed, unchanged

- **No server path fetches a submitted URL.** The only outbound calls are to
  Supabase (`api/index.py`, `ml/signatures.py`) and to the app's own inference
  backend (`lib/inference.ts`). Verified statically and behaviourally.
- **One secret comparison exists** (`CRON_SECRET`) and it uses
  `hmac.compare_digest`. No other secret or token comparison exists in
  first-party code.
- **The production alias is public**, verified by unauthenticated request.
  (Vercel's project-settings API returns 403 on this plan, so this is confirmed
  by behaviour rather than by reading the setting.)

---

## First pass — static review

Static, defensive review of the public attack surface.

> **Historical record.** Statements below about Supabase being unconfigured, or
> about the in-memory limiter being the active mechanism, were true when this
> section was written and are **superseded by the hardening pass above**.
> Supabase is now configured and the shared counter is authoritative.

---

## Executive Summary

**Scope.** `api/index.py` (FastAPI, public endpoints), `lib/inference.ts`,
`app/scan/route.ts`, `app/check/route.ts`, `ml/signatures.py`,
`ml/features.py`, `supabase/schema.sql`, `vercel.json`.

**Stack.** Next.js 16 (App Router, Node runtime) + a Python 3.12 FastAPI
Function on Vercel; optional Supabase Postgres. No user accounts, no
authentication, no payment path. Everything under `app/` and `api/` is
server-side; only `app/page.tsx` ships to the browser.

**Findings:** 0 Critical, 1 High, 3 Medium, 4 Low.

**Highest-impact risk:** the deployed service had **no effective rate limiting**.
The limiter was implemented only against Supabase, Supabase is not configured on
the live deployment, and the code returned "not limited" in that case — so two
unauthenticated endpoints that each run a gradient-boosted model were completely
unmetered. That is a denial-of-wallet and CPU-exhaustion exposure on a public
URL. **[FIXED]**

---

## Threat Model Summary

**Assets.** Vercel compute budget (metered), the Supabase service-role key
(server-side only), the prediction log (contains user-submitted URLs), and the
`CRON_SECRET` that gates a large upstream download.

**Entry points, all unauthenticated and internet-facing:**

| Entry point | Attacker-controlled |
|---|---|
| `POST /scan`, `POST /api/predict` | full JSON body, all headers |
| `POST /check`, `POST /api/check-file` | hash, filename, MIME, base64 header sample |
| `GET /api/refresh-hashes` | `Authorization` header |
| any unmatched path | the path itself |

**Top prioritized threats:**

1. **DoS / denial of wallet** — unmetered model inference on a public endpoint.
2. **Tampering (limit evasion)** — spoofing the identity the limiter keys on.
3. **Information disclosure** — user-submitted URLs persisted verbatim.
4. **SSRF** — the gateway makes a server-side request whose target is derived
   from a request header.
5. **Spoofing** — bypassing the cron secret.

There is deliberately **no IDOR/BOLA surface**: the service stores no per-user
objects and exposes no read endpoint over the prediction log. That removes the
single most common vulnerability class for this kind of app.

---

## Findings

### [HIGH] — No effective rate limiting on public inference endpoints **[FIXED]**
- **Severity:** High | **Confidence:** High
- **Classification:** OWASP API4:2023 Unrestricted Resource Consumption, CWE-770
- **Location:** `api/index.py::_rate_limited` (formerly line 217)

**Vulnerability Analysis.** The limiter opened with
`if not ip_hash or _supabase_cfg() is None: return False`. Live `/api/health`
reports `"supabase_configured": false`, so every request took that branch. The
Next gateway added no limiter of its own. Worse, `ip_hash` was the *salted*
hash used for logging, so a missing `IP_HASH_SALT` silently disabled rate
limiting as a side effect of disabling logging — two unrelated concerns wired to
one value.

**Attack Scenario.** `for i in $(seq 1 100000); do curl -s -XPOST $HOST/scan -d
'{"url":"https://a.example/x"}' & done`. Each request loads/scores a
HistGradientBoosting model. No credential, no CAPTCHA, no cap.

**Impact.** Unbounded Vercel function invocations and CPU-seconds on a metered
account, plus degraded latency for real users.

**Remediation.** Added a per-instance in-memory limiter used whenever the shared
Supabase counter is unavailable, and decoupled the rate-limit key from the
logging salt. The limiter also now falls back locally when a Supabase call
errors, instead of serving unlimited traffic.

```python
# before
if not ip_hash or _supabase_cfg() is None:
    return False

# after
if not ip_hash:
    return False
if _supabase_cfg() is None:
    return _rate_limited_local(ip_hash)
...
if res is None:
    return _rate_limited_local(ip_hash)
```

The in-memory counter is honestly a speed bump, not a control — serverless
instances are ephemeral and plural, so a distributed attacker gets one budget
per warm instance. It exists so an unconfigured deployment is not *completely*
unmetered. Durable limiting needs the Supabase counter or Vercel Firewall.

---

### [MEDIUM] — Rate limiter keyed on a client-controlled header **[FIXED]**
- **Severity:** Medium | **Confidence:** High
- **Classification:** OWASP API4:2023, CWE-290 (Spoofing by Impersonation)
- **Location:** `api/index.py::_client_ip` (formerly line 168)

**Vulnerability Analysis.** `forwarded.split(",")[0]` takes the **leftmost**
`X-Forwarded-For` entry. That entry is written by the client; trusted proxies
*append* on the right. Keying the limiter on it means the identity being limited
is chosen by the attacker.

**Attack Scenario.** `curl -H 'X-Forwarded-For: 1.2.3.4' ...` with a fresh random
value per request yields a new bucket every time — the limiter never fires. The
same value also poisons `client_ip_hash` in the prediction log, corrupting any
later abuse analysis.

**Remediation.** Prefer `x-real-ip` (set by the platform, not the request); fall
back to the **rightmost** XFF entry.

```python
if real_ip and real_ip.strip():
    return real_ip.strip()
if forwarded:
    parts = [p.strip() for p in forwarded.split(",") if p.strip()]
    if parts:
        return parts[-1]   # appended by the trusted proxy
```

---

### [MEDIUM] — Submitted URLs persisted verbatim, including query strings **[FIXED]**
- **Severity:** Medium | **Confidence:** High
- **Classification:** OWASP A02:2021 Cryptographic Failures / sensitive data at
  rest, CWE-532 (Insertion of Sensitive Information into Log File)
- **Location:** `api/index.py::predict` (formerly `url=body.url[:2048]`)

**Vulnerability Analysis.** The prediction log stored the full submitted URL.
URLs routinely carry password-reset tokens, session identifiers, pre-signed
object URLs and API keys in the query string. A tool whose entire purpose is to
receive suspicious links will be fed exactly those. This turned the log into a
secondary credential store — a more attractive target than anything else here.

**Attack Scenario.** A user pastes
`https://app.example/reset?token=eyJhbGciOi...`. It is stored in plaintext in
`public.predictions`. Anyone who later obtains the service-role key, or a
database backup, harvests live tokens.

**Remediation.** Strip the query and fragment before persisting. The full string
is still identified by its SHA-256 for grouping repeat submissions, so no
analytical capability is lost.

```python
url=_redact_url(body.url),   # "https://app.example/reset?[redacted]"
url_sha256=hashlib.sha256(body.url.encode()).hexdigest(),
```

---

### [MEDIUM] — Gateway derives its backend URL from the Host header **[FIXED]**
- **Severity:** Medium | **Confidence:** Medium
- **Classification:** OWASP A10:2021 SSRF, CWE-918
- **Location:** `lib/inference.ts::resolveInferenceBase`

**Vulnerability Analysis.** `new URL(request.url).origin` is derived from the
`Host` header. `callInference` then issues a server-side `fetch` to that origin.
If a forged Host ever reached the function, the gateway would make an outbound
request to an attacker-chosen host, carrying the request body — the exact SSRF
class this project's Scope section claims to avoid, reintroduced in the
gateway rather than the classifier.

Vercel validates `Host` against the deployment's aliases, so this is **not
exploitable on the current host**. The point is that the control lived in the
platform, not the application. Severity is Medium rather than High for that
reason.

**Remediation.** Allow-list the host before calling it: refuse non-https, and
refuse any hostname that is not `VERCEL_URL`, `VERCEL_PROJECT_PRODUCTION_URL`,
or a `*.vercel.app` host.

```ts
const parsed = new URL(origin);
if (parsed.protocol !== 'https:') {
  throw new Error('refusing to call a non-https inference backend');
}
const host = parsed.hostname.toLowerCase();
const allowed =
  host === process.env.VERCEL_URL?.trim().toLowerCase() ||
  host === process.env.VERCEL_PROJECT_PRODUCTION_URL?.trim().toLowerCase() ||
  host.endsWith('.vercel.app');
if (!allowed) {
  throw new Error(`refusing to call an unrecognised backend host: ${host}`);
}
return origin;
```

**Note on the first attempt.** The initial fix hard-pinned the backend to
`VERCEL_URL` instead of allow-listing the request origin. That broke `POST
/scan` in production: `VERCEL_URL` is the *deployment-specific* hostname, which
has Vercel Deployment Protection enabled, so the gateway's own server-side fetch
came back as a 401 "Protected deployment" page — which the gateway then returned
to callers. Only the stable alias is exempt from protection.

It was caught by re-testing the live endpoint after deploying, not by the build
or the test suite, both of which passed. Recorded here because "the security fix
broke the feature" is a normal outcome worth designing against, and because a
security control that takes the service down is not a working control.

---

### [LOW] — Non-constant-time comparison of the cron secret **[FIXED]**
- **Severity:** Low | **Confidence:** High
- **Classification:** CWE-208 (Observable Timing Discrepancy)
- **Location:** `api/index.py::refresh_hashes`

`presented != secret` short-circuits at the first differing byte, leaking the
secret's prefix through response timing. Impractical to exploit across the
public internet given network jitter, and trivial to remove.

```python
if not presented or not hmac.compare_digest(presented, secret):
    return JSONResponse(status_code=401, content={"error": "unauthorized"})
```

---

### [LOW] — Attacker-controlled path reflected in the 404 body
- **Severity:** Low | **Confidence:** High
- **Location:** `api/index.py::fallback`

The catch-all echoes `received_path` back to the caller. It is **not** XSS: the
response is `application/json` and `X-Content-Type-Options: nosniff` is set for
all routes in `vercel.json` (verified present on live responses). Retained
deliberately — it is what made the Vercel routing failure diagnosable — but it
is unnecessary reflection and would matter if a client ever rendered the body as
HTML.

---

### [LOW] — CSP permits `script-src 'unsafe-inline'`
- **Severity:** Low | **Confidence:** High
- **Location:** `vercel.json`

Weakens the CSP's value as an XSS backstop. Next.js needs per-request nonces to
drop `unsafe-inline`, which requires middleware. Accepted for now: the app
renders no user-supplied HTML and React escapes by default, so there is no known
injection point for the CSP to catch.

---

### [LOW] — The Next.js gateway is not a security boundary
- **Severity:** Low | **Confidence:** High
- **Location:** architecture

`/api/*` is directly reachable, so any control that exists only in
`app/scan` or `app/check` can be bypassed by calling the Python function
directly — for example the 413 on oversized `header_b64`. Validation *is*
duplicated in `api/index.py`, so this is currently a documentation issue rather
than an exploitable one. The README describes the gateway as "the public
contract," which slightly overstates it.

---

### [INFO] — `joblib.load` is a deserialization sink

`MODEL_PATH` is repo-controlled, never user-supplied, so this is not
attacker-reachable. Worth stating plainly: anyone who can write to
`ml/artifacts/` gets remote code execution in the function. Protect the repo and
the deploy pipeline accordingly.

---

## What the review found to be correct

Stated because an audit that only lists problems is not an accurate picture:

- **No SQL injection surface.** The only user value reaching PostgREST is a hash
  validated as hex by `classify_hash()` before use; everything else goes through
  parameterised JSON bodies.
- **RLS is deny-by-default** on `malicious_hashes`, `predictions` and
  `rate_limits`, with no `anon` policies. The single `anon` policy is a
  read-only select on `keepalive`, which holds one timestamp.
- **`bump_rate_limit` is `SECURITY DEFINER` with `set search_path = public`**
  and revoked from `public`/`anon` — the standard privilege-escalation vector
  for definer functions is closed.
- **No secret is exposed to the client.** Nothing is `NEXT_PUBLIC_*`; the
  service-role key is read server-side only.
- **Non-http(s) schemes are rejected, not scored**, so `javascript:` and `data:`
  URIs cannot be echoed back into a caller's page.
- **A hash miss is never reported as "clean,"** and a Supabase outage returns
  `None` rather than a false negative verdict.
- **FastAPI ships no CORS middleware**, so browsers block cross-origin reads by
  default.
- **ReDoS risk is low**: input is capped at 2048 characters and every regex in
  the request path is linear with no nested quantifiers.

---

## Systemic Recommendations

1. ~~**Put real rate limiting at the edge.**~~ **Done in the hardening pass** —
   the Supabase counter is now authoritative and verified across concurrent
   instances. Vercel Firewall remains the answer if this ever needs to be a DoS
   control rather than an abuse deterrent.
2. ~~**Configure Supabase or remove the code paths.**~~ **Done** — logging,
   durable rate limiting and the hash refresh are all live and verified against
   the database. Two of the three were silently broken when first switched on,
   which is precisely the "inert security code rots" failure this
   recommendation anticipated.
3. **Consider dropping the `url` column entirely** and keeping only
   `url_sha256`. Partially addressed: the query string is now stripped before
   storage. Not storing the path either would be stronger.
4. ~~**Add secret scanning and dependency review to CI.**~~ **Partially done** —
   CI now runs `npm audit --omit=dev --audit-level=high`. Secret scanning
   (`gitleaks`) and Dependabot are still worth adding; the pip side has no
   automated audit at all.
5. **Add a nonce-based CSP** if the demo page ever renders anything richer.
6. **Supply `SUPABASE_SERVICE_ROLE_KEY`** and drop the two
   `malicious_hashes` write policies. The restricted key is the better default
   for the read/append paths, but the hash refresh needs write access, and that
   is the one place where a leaked restricted key could do real damage
   (corpus poisoning).

---

## Residual Risk and Verification Constraints

- **Static review only.** No dynamic testing, no fuzzing, no authenticated
  scanning was performed against the live deployment beyond the functional
  endpoint checks in Phase 7.
- **The rate-limit fix is verified by unit test, not under real concurrency.**
  Behaviour across many simultaneous warm instances is untested and, by design,
  weaker than the single-instance test implies.
- **Supabase is unconfigured**, so the RLS policies, the `bump_rate_limit` RPC
  and the prediction-log schema were reviewed as source but never exercised
  against a live database. They should be re-verified after provisioning.
- **The Host-header SSRF finding rests on platform behaviour** documented by
  Vercel rather than on a test performed here. The fix removes the dependency
  regardless.
- **Model integrity is out of scope.** Adversarial evasion of the classifier is
  a model-robustness question, covered in `ml/reports/EVALUATION.md`, not a
  software vulnerability.
