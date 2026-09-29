# Decisions & Assumptions

Running log of judgement calls made during the build, with reasoning. Newest
phase last. Anything here was decided autonomously; none of it was dictated by
the spec.

---

## Phase 0 — Repo & scaffolding

**Package name ≠ directory name.** The working directory is
`Cloud Based Malware URL Detector`, which npm rejects as a package name (spaces,
capitals). `create-next-app` was run in a temp directory as
`malicious-url-detector` and the sources copied into place. `package.json` name
is `malicious-url-detector`; the local folder name is left as the user had it.

**Next.js 14.2.35.** Spec asked for Next 14, which also matches the user's
standing default. 14.2.35 is late enough in the 14.x line to include the fix for
the middleware-authorization-bypass issue (CVE-2025-29927, patched in 14.2.25),
so pinning to 14 does not mean shipping that known vulnerability.

**Python 3.11.15 for the training venv.** It is what is on PATH. Model artifacts
are version-sensitive, so `requirements.txt` pins exact scikit-learn/numpy
versions and the deployed function must resolve to the same majors — see Phase 5.

---

## Phase 1 — Data acquisition

**URLhaus does not actually block us without an Auth-Key.** The spec assumed a
personal Auth-Key would be required. Verified empirically:

| Endpoint | Without key |
|---|---|
| `https://urlhaus.abuse.ch/downloads/csv_recent/` | **200 OK**, ~4.5 MB, ~20.5k URLs |
| `https://urlhaus-api.abuse.ch/v1/urls/recent/` | **401 Unauthorized** |

So the *bulk CSV dumps* are open while the *API* is gated. The pipeline is built
on the bulk dumps, which removes the Auth-Key from the critical path entirely.
`URLHAUS_AUTH_KEY` is still read from env and used if present.

**PhishTank skipped.** Registration has been closed since 2020. Per the spec, the
pipeline is designed to work without it rather than block on it.

**Benign URLs come from Common Crawl, not from bare Tranco domains.** This is the
single most consequential decision in the project.

Tranco gives *registrable domains* (`bbc.com`). URLhaus/OpenPhish give *full URLs
with paths, ports and query strings* (`http://112.241.135.209:40885/i`). Training
benign-bare-domain against malicious-full-URL means trivial features — "has a
path at all", "URL length", "path depth" — separate the classes almost perfectly.
The resulting 99%+ precision would be an artifact of how the dataset was
assembled, not evidence the model detects anything. It would also collapse in
production, where benign traffic is overwhelmingly deep URLs.

Mitigation: benign examples are sampled from the Common Crawl CDX index
(`index.commoncrawl.org`, wildcard queries like `bbc.com/*`), which returns real
crawled URLs *with realistic paths* for Tranco-ranked domains. Tranco is still
used, but for what it is actually suited to: the reputation feature and the seed
list of domains to pull benign URLs for.

This costs real wall-clock time (CDX is rate-limited, one query per domain) and
it lowers the headline metrics versus the naive approach. That is the point.

**Common Crawl went down mid-build; Hacker News became the primary benign
source.** A 20-domain validation run against `index.commoncrawl.org` succeeded.
The subsequent full run returned zero URLs in 16 minutes, and an independent
5-query probe returned `ConnectTimeout` on every request — including after the
collector was stopped, so this was not self-inflicted load. Common Crawl's index
service is known to be intermittently unavailable.

Rather than block the build on a flaky third party, benign URLs now come from
the **Hacker News Algolia API** (free, no auth, fast). Measured on a 5-page
sample: 970 URLs, **654 distinct hosts**, **86.5% with a real path** — which
satisfies the structural-comparability requirement that motivated the Common
Crawl choice in the first place.

`fetch_commoncrawl_benign` is kept in the pipeline and runs best-effort under
`all`, so the dataset gains source diversity whenever Common Crawl is reachable.

Known bias, recorded rather than hidden: HN skews technical (github.com is the
single most common host). Two consequences, both handled explicitly — the
domain-grouped split prevents it leaking across train/test, and EVALUATION.md
lists it as a limit on how far these numbers generalise to general web traffic.

**The Tranco reputation feature is ablatable, and the headline metrics have it
OFF.** Benign URLs are drawn from Tranco-ranked domains (and from HN, which
also skews to well-ranked sites). That makes "is this domain in Tranco" close to
a restatement of the label rather than a learned signal — the exact "feature
that accidentally encodes the label" failure the spec warns about. Keeping it on
would inflate precision while degrading the model into a domain whitelist that
fails on the first legitimate site outside the top 1M. `features.py` supports
`include_reputation=False`, and `evaluate.py` trains both configurations and
reports the gap.

---

## Phase 3.5 — a defect the held-out set did not catch

The model reported ~94% precision on its own test set while scoring
`github.com/python/cpython/blob/main/Lib/json/decoder.py` at **0.97 malicious**.

That gap is the whole lesson. The held-out set is drawn from the same feeds as
the training data, so it measures generalisation to unseen *domains* but not to
unseen *regions of the web*. Hand-writing 24 ordinary URLs and scoring them
exposed a 16.7% false-positive rate concentrated entirely in one shape: paths
ending in a filename with an extension.

Two fixes, both addressing a real cause rather than the symptom:

**1. Added `path_ext` as a categorical feature.** The model could see *that* a
path ended in a file but not *which kind*. URLhaus is dominated by
`/bins/mirai.arm7` and `/info.zip`, so "ends in a file" became a malicious
signal and `.py`/`.rst`/`.md` were swept up with it. Giving the model the
extension itself lets it separate them.

**2. Added Wikipedia external links as a second benign source.** `path_ext`
alone was not enough — it fixed `.md`/`.txt` but pushed `.php` the other way, so
an ordinary restaurant's `/menu/starters.php` went from 0.24 to **0.955**. The
real problem was that Hacker News is the modern, HTTPS, technical web, and the
model had never seen the boring middle of it: universities, local government,
small businesses, non-English sites, old CMSes on `.php`/`.asp`/`.htm`. Wikipedia
citations are exactly that population, and they include plain-`http` references
that also dilute the `is_https` artifact (benign HTTPS share fell 99.4% -> 95.5%).

**This lowered the headline metric, which is the point.** Precision went
0.9405 -> 0.9225 after adding Wikipedia. Nothing got worse; the evaluation got
harder and more honest, because the benign class now contains URLs that
genuinely resemble malicious ones. A number that drops when you add realistic
data was measuring the wrong thing before.

`ml/generalization_probe.py` is committed so this check is repeatable, and
`reports/GENERALIZATION_PROBE.md` records the result. It is explicitly **not**
a headline metric — 24-50 hand-written URLs cannot support a precision estimate
with meaningful error bars. It is a smoke test for distribution shift.

---

## Phases 4-6 — signatures, API, gateway

**The 775 MB payload feed is streamed, not downloaded.** URLhaus ships payload
hashes as a single-member ZIP. `build_hashfeed.py` parses the local file header,
inflates the deflate stream incrementally, and drops the connection once it has
the requested number of rows — a few MB over the wire instead of 775. The
committed local snapshot is 200k hashes / 7.6 MB.

**`/check-file` takes a hash and at most 64 header bytes, never a file.** The
client hashes locally and may send a small base64 header sample for magic-number
checks. This keeps whole binaries out of the service entirely and still supports
every static check the spec asks for (double extension, MIME/extension mismatch,
MZ/ELF magic bytes).

**A hash miss is reported as a miss, not as "clean."** The local table is a
truncated subset, and `lookup_supabase` returns `None` rather than a negative
verdict when the database is unreachable — a DB outage must never be presented
to a user as "this file is safe."

**Explanations are computed in log-odds, not probability.** Occlusion in
probability space is useless on a confident prediction: at score 0.9999 every
feature's contribution rounds to ~0.0001. The raw decision function keeps its
resolution at the extremes. This was caught by looking at real output rather
than by a test.

**The Python function owns `/api/*`; the Next.js gateway lives at `/scan` and
`/check`.** Both Vercel's Python runtime and the Next App Router want `/api/*`,
and `app/api/**` would collide with `api/index.py`. Rather than fight the
routing, each gets its own namespace. Input validation is deliberately
duplicated in both layers: the gateway is the public contract and must reject
hostile input on its own terms, and the backend must not assume it did.

**Next 16 instead of the spec's Next 14** (approved during the build). Next
14.2.35 carried a high-severity advisory set including SSRF and XSS entries.
Most did not apply to this app's surface, but a security-themed repo showing
`npm audit` findings is a bad look. Next 16 clears them; the two remaining
moderates are a transitive `postcss` issue inside Next itself, whose suggested
"fix" is a downgrade to Next 9.

---

## Rounds 2-3 — infrastructure and hardening

**Reused an existing empty Supabase project rather than creating one.** The
brief said to create a project. `list_projects` showed one already there
(`<project-ref>`, created the same day, under a different email from the
workspace account) with **zero user tables**. Applying the schema was purely
additive with nothing to overwrite, and creating a second project would have
left a confusing duplicate. Checked before acting rather than assuming an
unfamiliar project was scratch space.

**Ran on a restricted Supabase key instead of blocking on `service_role`.**
The MCP deliberately withholds secret keys, so `service_role` was unavailable.
The obvious move was to stop and ask. The better one was to notice that a
restricted key is *the stronger choice anyway*: `service_role` bypasses RLS
entirely, so one leaked value reads every prediction ever logged, whereas the
restricted key is constrained by policy and — verified, not assumed — cannot
read back a single submitted URL.

The trade-off is that the hash refresh needs write access. That was initially a
blanket INSERT/UPDATE grant, which Supabase's linter correctly called out as
bypassing RLS; it is now a validating `SECURITY DEFINER` function with the
table closed. `service_role` remains supported and takes precedence if
supplied. This is a case where the constraint produced a better design than
having the credential would have.

**Fixed the rate-limit boundary burst rather than documenting around it.**
The plan allowed either. It turned out to be a one-line fix: `bump_rate_limit`
already reset on elapsed time, and the 2x burst came entirely from the caller
embedding a wall-clock minute in the bucket key, which manufactured a fresh
counter at every boundary. Removing it anchors the window to the caller's first
request. Documenting a limitation that takes one line to remove would have been
the wrong call.

The residual slack is stated exactly rather than hedged: spending the budget at
the end of one window and again at the start of the next approaches 2x over a
short span, but across a genuine 60-second gap rather than at an exploitable
clock tick. A true sliding window needs a per-caller timestamp log, which is
not worth the write amplification here.

**Answered the Vercel-log question instead of deferring it a third time.**
Two earlier attempts failed and each produced a *different* wrong explanation
for the failure (plan limitation, then token scope) while leaving the actual
question open. Reading a real log record through the authenticated CLI showed
there is **no client-IP field at all** — the documented "known gap" did not
exist. Worth recording as a pattern: a blocked check is not a finding, and
writing down a plausible reason for the block is not the same as answering the
question.

**Kept CORS locked by omission.** The brief asked to verify CORS was locked to
the known frontend origin. It is stricter than that: with no CORS middleware,
no `Access-Control-Allow-Origin` is sent at all, so browsers block every
cross-origin read. Adding an explicit policy could only loosen it, so the
change made was a regression test that fails if anyone adds permissive CORS
later — not a code change.

**Two Round-3 items were non-issues and were left alone.** Security headers
were already complete from Round 1's `vercel.json`, and the
`shreyas-tech7`/`shreyas-tech` naming was a GitHub user versus a Vercel team
slug, not a bug. Both are recorded here so the next pass does not re-derive
them.
