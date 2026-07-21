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
| `POST /scan` | `{"url": "..."}` | verdict, score, per-prediction feature attributions |
| `POST /check` | `{"hash": "...", "filename": "...", "header_b64": "..."}` | known-bad hash lookup + static metadata findings |
| `GET /api/health` | — | model version, feature count, hash-table size |

A minimal demo page at `/` lets you paste a URL and see the verdict.

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

Precision is tunable upward: the threshold sweep reaches 0.985 precision at
0.768 recall (t=0.90), and 0.999 at 0.547 recall (t=0.99).

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
| `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` | Hash table, prediction log, rate limiting. Server-side only. |
| `SUPABASE_ANON_KEY` | Keep-alive GitHub Action. |
| `IP_HASH_SALT` | Salts the SHA-256 of client IPs. Without it, **no IP is logged at all** rather than logging a reversible digest. |
| `CRON_SECRET` | Authorises `GET /api/refresh-hashes`. |
| `URLHAUS_AUTH_KEY` | Optional; the bulk dumps used here do not need it. |
| `INFERENCE_BASE_URL` | Override the gateway's backend target. |

No secret is `NEXT_PUBLIC_*`. Apply `supabase/schema.sql` in the Supabase SQL
editor — it is idempotent and enables RLS deny-by-default on every table.

---

## Limitations

The full list is in [`ml/reports/EVALUATION.md`](ml/reports/EVALUATION.md). The
ones that matter most:

1. **The ~50/50 evaluation balance is not the real-world base rate.** Real
   traffic is overwhelmingly benign, and precision falls as the positive class
   gets rarer. At a 1% true malicious rate this model's precision would be far
   below 0.92. These numbers describe discrimination ability, not deployed
   performance.

2. **Threat feeds are a biased sample of malice.** URLhaus and OpenPhish contain
   URLs that were *detected and reported*. Anything that evades detection is by
   definition absent, so real-world recall against a competent adversary is
   lower than measured.

3. **Legitimate hyphenated non-English domains still false-positive.**
   `clinicadental-sanchez.es` scores ~0.91. This is close to the ceiling of
   string-only classification: nothing in the URL distinguishes a Spanish dental
   clinic from an impersonation of one. Fixing it needs domain reputation or
   registration age — signals outside the string.

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
