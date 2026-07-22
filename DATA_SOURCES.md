# Data Sources

Every dataset used to train or serve this model, with its terms of use and the
role it plays. Machine-readable provenance — exact endpoints, fetch timestamps
and row counts — lives in `ml/data/raw/MANIFEST.json`, written by the
acquisition script rather than by hand.

The original plan anticipated URLhaus, OpenPhish and Tranco. What the pipeline
actually ended up using is different: Tranco was demoted, Common Crawl was
dropped mid-build when its index stopped responding, and two benign sources
were added that were not in the plan at all. This page describes what is
actually used.

---

## Summary

| Source | Class | Rows used | Auth | Terms |
|---|---|---|---|---|
| [URLhaus](https://urlhaus.abuse.ch/) | malicious | 20,524 URLs + payload hashes | none | CC0 |
| [OpenPhish](https://github.com/openphish/public_feed) | malicious | 184,909 URLs | none | community, non-commercial + attribution |
| [Hacker News](https://hn.algolia.com/api) (Algolia) | benign | 70,285 URLs | none | public API |
| [Wikipedia](https://en.wikipedia.org/w/api.php) | benign | 14,325 URLs | none | CC BY-SA 4.0 content, free API |
| [Tranco](https://tranco-list.eu/) | reputation | 1,000,000 domains | none | research use, cite NDSS 2019 |
| [Common Crawl](https://commoncrawl.org/) | benign | 33 URLs (best-effort) | none | open corpus |

After deduplication, per-domain capping (25) and domain-level class balancing:
**97,416 rows across 52,294 registrable domains**, ~48% malicious.

---

## Malicious class

### URLhaus (abuse.ch)

- **Used for:** malware-distribution URLs, and the known-bad file-hash corpus
  behind `/check-file`.
- **Endpoints:** `downloads/csv_recent/` (URLs), `downloads/payloads/` (hashes).
- **Terms:** <https://urlhaus.abuse.ch/api/> — free for commercial and
  non-commercial use, data released as **CC0**.
- **Auth:** none. The bulk CSV dumps are open; only `urlhaus-api.abuse.ch`
  requires an Auth-Key (verified: the API returns 401, the dumps return 200).
- **Handling note:** the payload dump is a ~775 MB single-member ZIP. It is
  streamed and the connection dropped once enough rows are read, rather than
  downloaded in full. Only hashes and static metadata are ever handled — no
  sample is downloaded, unpacked or executed.

### OpenPhish Community Feed

- **Used for:** phishing URLs, which complement URLhaus's malware-distribution
  skew.
- **Endpoint:** the `openphish/public_feed` GitHub mirror.
- **Terms:** <https://openphish.com/terms.html> — the *community* feed is free
  for **non-commercial** use with attribution. The commercial feeds are not
  used here. This project is a non-commercial portfolio demonstration.
- **Auth:** none.
- **Handling note:** the live feed is only a ~300-URL rolling snapshot, which is
  too thin to train on. The acquisition script walks ~800 commits of the feed
  repository's git history and unions the snapshots, yielding 184,909 distinct
  URLs. This reads public git history at a normal clone rate; it does not
  circumvent any access control or paid tier.

---

## Benign class

The benign class is the part most likely to be got wrong, so the reasoning is
recorded here as well as in `DECISIONS.md`.

Benign examples must be **structurally comparable** to malicious ones. Pairing
bare domains (`bbc.com`) against full malicious URLs
(`http://1.2.3.4:8080/bins/x.arm7`) would let "does this have a path at all"
separate the classes almost perfectly and produce a meaningless 99% precision.

### Hacker News via Algolia

- **Used for:** the bulk of the benign class — real human-submitted URLs with
  real paths.
- **Endpoint:** `hn.algolia.com/api/v1/search_by_date`.
- **Terms:** <https://hn.algolia.com/api> — free public search API over HN
  submissions, no authentication, no registration.
- **Rate limiting:** requests are paced (0.4 s between pages) and paginated
  backwards through time.
- **Known bias:** HN skews technical and modern — `github.com`, documentation
  sites and tech blogs are over-represented, and submissions are almost
  entirely HTTPS. This bias caused a real defect (see below).

### Wikipedia external links

- **Used for:** the long-tail web that Hacker News does not contain.
- **Endpoint:** MediaWiki `list=exturlusage`, mainspace only, both `http` and
  `https`.
- **Terms:** <https://foundation.wikimedia.org/wiki/Policy:Terms_of_Use>. Article
  text is CC BY-SA 4.0; the external URLs used here are bare references, not
  Wikipedia's creative content. The API is free and unauthenticated.
- **Rate limiting:** 0.2 s between requests, well inside the API's limits.
- **Why it was added:** with HN as the only benign source, the model scored
  `github.com/python/cpython/blob/main/Lib/json/decoder.py` at **0.97
  malicious** and an ordinary restaurant's `/menu/starters.php` at **0.955** —
  because URLhaus is full of `/bins/mirai.arm7` and the benign class contained
  almost no ordinary `.php`/`.asp`/`.htm` sites. Wikipedia's citations are
  universities, government sites, small publishers, non-English pages and old
  CMSes, plus a large tail of plain-`http` references that dilute the
  HTTPS artefact (benign HTTPS share fell 99.4% → 95.5%).

### Common Crawl (best-effort, effectively unused)

- **Intended as** the primary benign source: real crawled URLs with real paths
  for Tranco-ranked domains, via the CDX index.
- **What happened:** a 20-domain validation run succeeded; the full run then
  returned zero URLs in 16 minutes, and an independent probe returned
  `ConnectTimeout` on every request — including after the collector was
  stopped, so it was not self-inflicted load. A later retry returned HTTP 502.
- **Status:** contributed 33 URLs and remains in the pipeline as a best-effort
  source that is skipped when unavailable.
- **Terms:** <https://commoncrawl.org/terms-of-use> — open corpus. Only the URL
  *index* is queried; page content (WARC records) is never fetched.

---

## Reputation

### Tranco Top 1M

- **Used for:** the `in_tranco` / `tranco_tier` reputation features, and as the
  seed domain list for Common Crawl sampling.
- **Terms:** <https://tranco-list.eu/> — freely downloadable, no registration,
  research-oriented. Cite Le Pochat et al., *Tranco: A Research-Oriented Top
  Sites Ranking Hardened Against Manipulation*, NDSS 2019.
- **Important:** these features are **disabled in the shipped model.** The
  benign class was sampled from Tranco-ranked domains, so "is this domain in
  Tranco" partly restates the label rather than being a learned signal. Keeping
  it would inflate precision while degrading the model into a domain whitelist
  that fails on the first legitimate site outside the list. `evaluate.py` trains
  both configurations and reports the gap (+0.007 precision, not trusted).

---

## Reproducing

```bash
python ml/data_acquisition.py all          # every source, resumable
python ml/build_hashfeed.py --limit 200000 # known-bad hash table
```

Each fetcher records its endpoint, timestamp, row count and licence into
`ml/data/raw/MANIFEST.json`, so provenance is generated rather than asserted.

## Redistribution

This repository does **not** redistribute any source dataset. `ml/data/` is
gitignored; only the acquisition scripts and the manifest are committed. The
one derived artefact that is committed is
`ml/artifacts/known_bad_hashes.csv.gz` — 119,226 SHA-256/MD5 hashes from
URLhaus, which is CC0 and therefore freely redistributable.
