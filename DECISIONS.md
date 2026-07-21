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
