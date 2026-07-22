# Malicious URL & File-Signature Detector

A cloud-deployed gradient-boosted classifier that flags malicious and phishing
URLs from the URL string alone, plus a static file-signature checker backed by
known-bad hashes from URLhaus.

Built as a portfolio demonstration of a complete ML pipeline — data acquisition,
feature engineering, **leakage-aware evaluation**, and serverless deployment.
It is explicitly not a production security control; see
[Limitations](#limitations).

---

## What it does

| Endpoint | Input | Output |
|---|---|---|
| `POST /scan` | `{"url": "..."}` | `malicious` / `uncertain` / `benign`, score, per-prediction feature attributions |
| `POST /check` | `{"hash": "...", "filename": "...", "header_b64": "..."}` | known-bad hash lookup + static metadata findings |
| `GET /api/health` | — | model version, feature count, hash-table size, Supabase key kind |

A minimal demo page at `/` lets you paste a URL and see the verdict.

Companion documents:
[EVALUATION.md](ml/reports/EVALUATION.md) (measured performance and
limitations) · [SECURITY.md](SECURITY.md) (two audit passes and their fixes) ·
[PRIVACY.md](PRIVACY.md) (what is stored, for how long, who can read it) ·
[DATA_SOURCES.md](DATA_SOURCES.md) (every dataset and its terms) ·
[DECISIONS.md](DECISIONS.md) (judgement calls and why).

---

## Scope and non-goals

These are design constraints, not caveats bolted on afterwards.

**The service never fetches the URL you submit.** It does not resolve, request,
render, or follow it. Every feature is computed from the URL *string*. A backend
that fetches user-supplied URLs is an SSRF primitive — on a cloud host it can be
aimed at link-local metadata endpoints (`169.254.169.254`) or internal services.
"Show me what's actually at this link" is a separate product with its own
sandboxing requirements and is deliberately not built here.

**No file is ever downloaded, unpacked, or executed.** "File-signature checking"
means (a) hash lookup against known-bad hashes and (b) static metadata checks —
extension/MIME mismatch, double extensions like `invoice.pdf.exe`, and magic-byte
inspection. The API accepts a hash the client computed locally plus at most
**64 header bytes**; it does not accept file uploads.

**This is not enterprise threat intel.** It demonstrates the pipeline end to end.

---

## Architecture

```
                  browser
                     |
                     v
     Next.js App Router  (app/scan, app/check)      <- public contract:
                     |                                 validation, shaping
                     v
     Python Function  (api/index.py, FastAPI)       <- owns /api/*
          |                        |
          v                        v
   ml/features.py           ml/signatures.py
   ml/artifacts/model.joblib   known_bad_hashes.csv.gz
                                   |
                                   v
                          Supabase (optional)
                          hashes, prediction log, rate limits
```

Routing note: Vercel's Python runtime and the Next App Router both want
`/api/*`. The Python Function owns it, so the Next gateway lives at `/scan` and
`/check` and nothing collides.

`ml/features.py` is imported by **both** the training scripts and the serverless
function. There is deliberately no second copy — that is what prevents
train/serve skew.

```
├── ml/                        training pipeline (offline)
│   ├── data_acquisition.py    URLhaus, OpenPhish, Tranco, HN, Wikipedia
│   ├── build_dataset.py       label, dedupe, cap, balance, featurise
│   ├── features.py            SHARED feature extraction
│   ├── signatures.py          SHARED hash lookup + metadata checks
│   ├── build_hashfeed.py      streams the 775 MB URLhaus payload feed
│   ├── train.py               domain-grouped split + HistGradientBoosting
│   ├── evaluate.py            metrics, ablations, leakage audit
│   ├── generalization_probe.py  hand-written out-of-distribution check
│   ├── artifacts/             model.joblib, known_bad_hashes.csv.gz
│   └── reports/               EVALUATION.md, metrics.json
├── api/index.py               FastAPI inference function
├── app/                       Next.js App Router (gateway + demo page)
├── lib/inference.ts           gateway helpers
├── supabase/schema.sql        RLS-first, idempotent
└── vercel.json                function config, cron, security headers
```

---

## Results

Full detail in **[`ml/reports/EVALUATION.md`](ml/reports/EVALUATION.md)**. Every
number there is produced by executing `ml/evaluate.py` against a held-out set —
none are estimated.

On **19,636 held-out URLs across 10,459 registrable domains never seen during
training**:

| Metric | Value |
|---|---|
| **Precision** | **0.9225** |
| Recall | 0.9124 |
| F1 | 0.9174 |
| PR-AUC | 0.9795 |

### That 0.92 does not survive contact with a realistic base rate

Precision is a function of prevalence, and the evaluation set is **46.6%
malicious by construction**. Real traffic is overwhelmingly benign. Applying
Bayes' rule to the *measured* TPR and FPR:

```
precision = (p x TPR) / (p x TPR + (1 - p) x FPR)
```

| Threshold | FPR | p=0.5% | p=1% | p=5% | p=10% | p=46.6% (this eval) |
|---|---|---|---|---|---|---|
| 0.50 | 0.0670 | 0.064 | **0.121** | 0.418 | 0.602 | **0.922** |
| 0.70 | 0.0387 | 0.101 | 0.185 | 0.541 | 0.714 | 0.951 |
| 0.80 | 0.0240 | 0.148 | 0.259 | 0.646 | 0.794 | 0.968 |
| 0.90 | 0.0101 | 0.276 | 0.434 | 0.800 | 0.894 | 0.985 |
| 0.95 | 0.0055 | 0.391 | 0.564 | 0.871 | 0.934 | 0.991 |
| 0.99 | 0.0004 | 0.878 | **0.935** | 0.987 | 0.994 | 0.999 |

**At the default threshold and a 1% true malicious rate, precision is 0.121** —
about seven false alarms per real detection. That is not a flaw in the model;
it is what a 6.7% false-positive rate does when negatives outnumber positives
99 to 1.

The threshold is the lever, and the table shows it working: at t=0.99 the
false-positive rate falls to 0.0004, lifting precision at a 1% base rate to
**0.935**, at the cost of recall (0.547 vs 0.912). Any real deployment should
pick its operating point from this table and its own prevalence estimate, not
from the headline number.

### Verdicts are three-valued, not binary

Scores in **[0.20, 0.80)** are reported as `uncertain — worth a second look`
rather than forced into a call. The bounds are measured, not chosen: that band
is **14.1% of traffic but contains 65.9% of the model's errors**, so abstaining
there drops the error rate on the verdicts that *are* given from 7.7% to 3.04%.

The response also carries `binary_verdict` for callers that need a hard
decision.

### Why the split matters

The train/test split is **grouped by registrable domain (eTLD+1)**: every URL
sharing an eTLD+1 goes entirely into train or entirely into test. Phishing
campaigns emit hundreds of near-identical URLs on one host; under a naive
row-level split those siblings land on both sides and the model is graded on
URLs it effectively memorised.

The same model with a naive random split reports **+0.016 precision**. That
difference is not a better model — it is the number this project would have
claimed had the split been done carelessly.

### Leakage audit

| Check | Result |
|---|---|
| Exact duplicate URLs in dataset | 0 |
| Domains in both train and test | 0 |
| URL strings in both train and test | 0 |
| Highest single-feature AUC | 0.745 (`path_length`) |

The last row is the one that matters: no single feature comes close to solving
the task alone, so the dataset is not trivially separable by an artifact of how
it was assembled.

### A defect the held-out set did not catch

At one point the model reported ~94% precision while scoring
`github.com/python/cpython/blob/main/Lib/json/decoder.py` at **0.97 malicious**.

The held-out set is drawn from the same feeds as the training data, so it
measures generalisation to unseen *domains* but not to unseen *regions of the
web*. Hand-writing ordinary URLs exposed a false-positive cluster: paths ending
in a filename with an extension — because URLhaus is full of `/bins/mirai.arm7`
and the model had no feature for *which* extension.

Two fixes: a `path_ext` categorical feature, and a second benign source
(Wikipedia external links) covering the non-technical, older, plain-http web
that Hacker News lacks. That URL now scores 0.563 and the restaurant PHP page
that had hit 0.955 scores 0.652.

**This lowered headline precision from 0.9405 to 0.9225.** Nothing regressed —
the evaluation got harder and more honest, because the benign class now contains
URLs that genuinely resemble malicious ones. A metric that falls when you add
realistic data was measuring the wrong thing before.

`ml/generalization_probe.py` keeps the check repeatable
([results](ml/reports/GENERALIZATION_PROBE.md)). It is a smoke test for
distribution shift on a small hand-picked set, **not** a headline metric.

---

## Data sources

| Source | Class | Notes |
|---|---|---|
| [URLhaus](https://urlhaus.abuse.ch/) | malicious | Malware distribution. Bulk CSV needs **no** Auth-Key (only the API does). |
| [OpenPhish](https://github.com/openphish/public_feed) | malicious | The live feed is a ~300-URL rolling snapshot, so the script mines the feed repo's git history → 184,909 unique URLs. |
| [Hacker News](https://hn.algolia.com/api) (Algolia) | benign | Real submitted URLs with real paths. |
| [Wikipedia](https://en.wikipedia.org/w/api.php) (exturlusage) | benign | The long-tail web: universities, government, small business, non-English, plain http. |
| [Tranco](https://tranco-list.eu/) | reputation | Also the seed list for Common Crawl sampling. |
| [Common Crawl](https://commoncrawl.org/) | benign | Best-effort; its index was unavailable during this build. |

Licences and fetch timestamps are recorded in `ml/data/raw/MANIFEST.json`.

**Why benign URLs are deep URLs, not bare domains.** Pairing bare Tranco domains
against full malicious URLs would let "does this have a path at all" separate the
classes almost perfectly, producing a meaningless 99% precision that would
collapse in production. Benign examples must be structurally comparable to
malicious ones.

---

## Running it

### Train from scratch

```bash
python -m venv ml/.venv
ml/.venv/Scripts/pip install -r ml/requirements.txt   # POSIX: ml/.venv/bin/pip

python ml/data_acquisition.py all            # fetch every feed
python ml/build_dataset.py                   # label, dedupe, balance, featurise
python ml/evaluate.py                        # train + write reports/
python ml/generalization_probe.py            # out-of-distribution smoke test
python ml/build_hashfeed.py --limit 200000   # known-bad hash table
```

### Run locally

```bash
# Python inference function
ml/.venv/Scripts/uvicorn api.index:app --port 8000

# Next.js gateway + demo page
npm install && npm run dev
```

### Tests

```bash
ml/.venv/Scripts/python -m pytest ml/tests -q
```

Covers feature extraction (including malformed and hostile input), hash
classification, static metadata checks, and the full API surface.

---

## Configuration

Copy `.env.example`. Every value is optional — **the app runs with none of
them**, falling back to the committed local hash table and skipping logging.

| Variable | Purpose |
|---|---|
| `SUPABASE_URL` | Project URL. |
| `SUPABASE_PUBLISHABLE_KEY` / `SUPABASE_ANON_KEY` | The **restricted** key the server runs on. Constrained by RLS: it can append to the prediction log but cannot read it back. |
| `SUPABASE_SERVICE_ROLE_KEY` | Optional and **preferred if you have it** — takes precedence. Bypasses RLS, so the two `malicious_hashes` write policies can then be dropped. |
| `IP_HASH_SALT` | Salts the SHA-256 of client IPs. Without it, **no IP is logged at all** rather than logging a reversible digest. |
| `CRON_SECRET` | Authorises `GET /api/refresh-hashes`. |
| `URLHAUS_AUTH_KEY` | Optional; the bulk dumps used here do not need it. |
| `INFERENCE_BASE_URL` | Override the gateway's backend target. |
| `UNCERTAIN_LOW` / `UNCERTAIN_HIGH` | Bounds of the uncertain band (default 0.20 / 0.80). |

No secret is `NEXT_PUBLIC_*`; no Supabase key of any kind reaches the browser.
Apply `supabase/schema.sql` in the Supabase SQL editor — it is idempotent,
enables RLS deny-by-default on every table, and schedules retention via
`pg_cron`.

All credential resolution goes through `ml/supabase_cfg.py`. Reading
`SUPABASE_*` directly anywhere else is a test failure — three copies of that
logic previously drifted and silently disabled hash lookups.

---

## Limitations

The full list is in [`ml/reports/EVALUATION.md`](ml/reports/EVALUATION.md). The
ones that matter most:

1. **The 46.6% evaluation balance is not the real-world base rate.** This is no
   longer a hand-wave — see the table above. At a 1% true malicious rate and
   the default threshold, precision is **0.121**, not 0.92. The headline number
   describes discrimination ability, not deployed performance, and the
   threshold has to be raised substantially for the tool to be useful at
   realistic prevalence.

2. **Threat feeds are a biased sample of malice.** URLhaus and OpenPhish contain
   URLs that were *detected and reported*. Anything that evades detection is by
   definition absent, so real-world recall against a competent adversary is
   lower than measured.

3. **Legitimate hyphenated non-English domains still false-positive.**
   `clinicadental-sanchez.es` scores ~0.91 — above the uncertain band, so it
   gets a confident wrong answer rather than an abstention. This is close to
   the ceiling of string-only classification: nothing in the URL distinguishes
   a Spanish dental clinic from an impersonation of one. Fixing it needs domain
   reputation or registration age — signals outside the string. The uncertain
   band helps the borderline cases (a restaurant's `/menu/starters.php` at
   0.652 is now `uncertain` rather than `malicious`) but cannot help where the
   model is confidently wrong.

4. **Static analysis only.** The classifier sees the URL string. A malicious page
   on a clean-looking URL, or a compromised legitimate site, is invisible to it.

5. **No adversarial evaluation.** An attacker who knows these features can craft
   URLs to defeat them — HTTPS, short path, no keywords, plausible domain.

6. **The model decays.** Phishing infrastructure turns over fast. No drift
   monitoring is implemented.

---

## Licence

Data from URLhaus (CC0), OpenPhish (community feed), Tranco, Wikipedia and
Common Crawl remains under the terms of those projects — see
`ml/data/raw/MANIFEST.json`.
