"""Reproducible dataset build for the malicious-URL classifier.

Every source is fetched by this script — there are no manual download steps and
no notebook state. Re-running is safe: each fetcher writes to ml/data/raw/ and
records provenance in MANIFEST.json.

Sources and why each is here
----------------------------
URLhaus (abuse.ch)   malicious  malware-distribution URLs. Bulk CSV dumps are
                                reachable without an Auth-Key; only the API at
                                urlhaus-api.abuse.ch requires one.
OpenPhish community  malicious  phishing specifically, complements URLhaus's
                                malware-distribution skew. Rolling ~300-URL
                                snapshot, so we also mine the feed's git
                                history to accumulate past snapshots.
Tranco               benign     ranked registrable domains. Used as the seed
                                list for benign URL collection AND as the
                                reputation feature at inference time.
Common Crawl CDX     benign     real crawled URLs *with paths* for Tranco
                                domains.

On that last one — see DECISIONS.md. Using bare Tranco domains as the negative
class would let "does this URL have a path at all" separate the classes almost
perfectly, producing a meaningless 99% precision. Benign examples must be
structurally comparable to malicious ones, which means real deep URLs.

Usage
-----
    python ml/data_acquisition.py urlhaus
    python ml/data_acquisition.py openphish
    python ml/data_acquisition.py tranco
    python ml/data_acquisition.py benign --domains 3000 --per-domain 12
    python ml/data_acquisition.py all
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import random
import re
import sys
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

import requests

ROOT = Path(__file__).resolve().parent
RAW = ROOT / "data" / "raw"
MANIFEST_PATH = RAW / "MANIFEST.json"

USER_AGENT = (
    "malicious-url-detector/0.1 (research/portfolio project; "
    "contact: shreyas.tech7@gmail.com)"
)

# --------------------------------------------------------------------------
# Licensing / terms of use, recorded so the manifest is self-documenting.
# --------------------------------------------------------------------------
SOURCE_TERMS = {
    "urlhaus": {
        "name": "URLhaus (abuse.ch)",
        "terms_url": "https://urlhaus.abuse.ch/api/",
        "summary": (
            "Free for both commercial and non-commercial use. Data is provided "
            "as CC0. Bulk CSV dumps require no authentication."
        ),
    },
    "openphish": {
        "name": "OpenPhish Community Feed",
        "terms_url": "https://openphish.com/terms.html",
        "summary": (
            "Community feed is free for non-commercial use with attribution. "
            "Refreshed roughly every 12h; mirrored on GitHub."
        ),
    },
    "tranco": {
        "name": "Tranco Top 1M",
        "terms_url": "https://tranco-list.eu/",
        "summary": (
            "Research-oriented ranking, freely downloadable, no registration. "
            "Cite Le Pochat et al., NDSS 2019 when publishing."
        ),
    },
    "commoncrawl": {
        "name": "Common Crawl URL index (CDX)",
        "terms_url": "https://commoncrawl.org/terms-of-use",
        "summary": (
            "Open corpus, free to use. We query only the URL *index* — we never "
            "fetch page content (WARC records)."
        ),
    },
}


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})
    return s


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _update_manifest(key: str, **fields) -> None:
    """Record provenance for one source. Merges into the existing manifest."""
    RAW.mkdir(parents=True, exist_ok=True)
    manifest = {}
    if MANIFEST_PATH.exists():
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    entry = {"fetched_at": _now(), **SOURCE_TERMS.get(key, {}), **fields}
    manifest[key] = entry
    MANIFEST_PATH.write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )
    print(f"  manifest[{key}] updated")


# --------------------------------------------------------------------------
# URLhaus — malicious
# --------------------------------------------------------------------------
URLHAUS_RECENT = "https://urlhaus.abuse.ch/downloads/csv_recent/"
URLHAUS_FULL = "https://urlhaus.abuse.ch/downloads/csv/"


def fetch_urlhaus(full: bool = False) -> Path:
    """Download the URLhaus URL dump.

    `full=True` grabs the complete historical dump (zipped, large and slow);
    the default `csv_recent` is ~20k of the most recent URLs, which is plenty
    and keeps the build fast.

    An Auth-Key is used if URLHAUS_AUTH_KEY is set, but is not required for
    these bulk endpoints.
    """
    url = URLHAUS_FULL if full else URLHAUS_RECENT
    out = RAW / "urlhaus.csv"
    print(f"[urlhaus] GET {url}")

    s = _session()
    key = os.environ.get("URLHAUS_AUTH_KEY", "").strip()
    if key:
        s.headers["Auth-Key"] = key
        print("[urlhaus] using URLHAUS_AUTH_KEY from env")

    r = s.get(url, timeout=180)
    r.raise_for_status()
    body = r.content

    # The full dump ships as a zip containing a single csv.
    if full or body[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(body)) as zf:
            name = zf.namelist()[0]
            body = zf.read(name)

    text = body.decode("utf-8", errors="replace")

    # Strip the leading '#' comment banner, then parse the quoted CSV.
    lines = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
    reader = csv.reader(lines)
    cols = ["id", "dateadded", "url", "url_status", "last_online",
            "threat", "tags", "urlhaus_link", "reporter"]

    rows = []
    for row in reader:
        if len(row) < len(cols):
            continue
        rec = dict(zip(cols, row))
        if rec["url"].startswith(("http://", "https://")):
            rows.append(rec)

    with out.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    print(f"[urlhaus] wrote {len(rows):,} URLs -> {out.name}")
    _update_manifest(
        "urlhaus",
        endpoint=url,
        auth_key_used=bool(key),
        auth_key_required=False,
        rows=len(rows),
        file=out.name,
    )
    return out


# --------------------------------------------------------------------------
# OpenPhish — malicious (phishing)
# --------------------------------------------------------------------------
OPENPHISH_RAW = (
    "https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt"
)
OPENPHISH_COMMITS = (
    "https://api.github.com/repos/openphish/public_feed/commits"
)


def fetch_openphish(history_pages: int = 8) -> Path:
    """Fetch the OpenPhish community feed.

    The live feed is only a ~300-URL rolling snapshot, which is too thin to be
    useful on its own. Because the feed is published as a git repo, we also walk
    recent commits and pull each historical snapshot, union-ing them. That turns
    a 300-URL snapshot into several thousand distinct phishing URLs without
    touching any paid tier.
    """
    out = RAW / "openphish.csv"
    s = _session()
    seen: dict[str, str] = {}  # url -> first date we saw it

    print(f"[openphish] GET {OPENPHISH_RAW}")
    r = s.get(OPENPHISH_RAW, timeout=60)
    r.raise_for_status()
    for line in r.text.splitlines():
        line = line.strip()
        if line.startswith(("http://", "https://")):
            seen.setdefault(line, _now())

    print(f"[openphish] live snapshot: {len(seen):,} URLs")

    # Walk commit history for older snapshots.
    gh_headers = {}
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        gh_headers["Authorization"] = f"Bearer {token}"

    shas: list[tuple[str, str]] = []
    try:
        for page in range(1, history_pages + 1):
            cr = s.get(
                OPENPHISH_COMMITS,
                params={"per_page": 100, "page": page},
                headers=gh_headers,
                timeout=60,
            )
            if cr.status_code != 200:
                print(f"[openphish] commit list page {page} -> "
                      f"{cr.status_code}, stopping history walk")
                break
            batch = cr.json()
            if not batch:
                break
            for c in batch:
                shas.append((c["sha"], c["commit"]["committer"]["date"]))
    except requests.RequestException as exc:
        print(f"[openphish] history walk failed ({exc}); using live snapshot only")

    print(f"[openphish] walking {len(shas)} historical commits")

    def _one(item: tuple[str, str]) -> tuple[list[str], str]:
        sha, date = item
        u = (f"https://raw.githubusercontent.com/openphish/public_feed/"
             f"{sha}/feed.txt")
        try:
            rr = s.get(u, timeout=45)
            if rr.status_code != 200:
                return [], date
            return [
                ln.strip() for ln in rr.text.splitlines()
                if ln.strip().startswith(("http://", "https://"))
            ], date
        except requests.RequestException:
            return [], date

    added = 0
    with ThreadPoolExecutor(max_workers=6) as pool:
        for urls, date in pool.map(_one, shas):
            for u in urls:
                if u not in seen:
                    seen[u] = date
                    added += 1

    print(f"[openphish] +{added:,} from history -> {len(seen):,} unique")

    with out.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["url", "first_seen"])
        for u, d in seen.items():
            w.writerow([u, d])

    _update_manifest(
        "openphish",
        endpoint=OPENPHISH_RAW,
        history_commits_walked=len(shas),
        rows=len(seen),
        file=out.name,
    )
    return out


# --------------------------------------------------------------------------
# Tranco — benign domain seed list + reputation feature source
# --------------------------------------------------------------------------
TRANCO_LATEST = "https://tranco-list.eu/api/lists/date/latest"


def fetch_tranco() -> Path:
    """Download the latest Tranco top-1M list."""
    out = RAW / "tranco.csv"
    s = _session()

    print(f"[tranco] GET {TRANCO_LATEST}")
    meta = s.get(TRANCO_LATEST, timeout=60)
    meta.raise_for_status()
    j = meta.json()
    list_id = j.get("list_id")
    download = j.get("download") or f"https://tranco-list.eu/download/{list_id}/full"

    print(f"[tranco] list_id={list_id} -> {download}")
    r = s.get(download, timeout=300)
    r.raise_for_status()

    body = r.content
    if body[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(body)) as zf:
            body = zf.read(zf.namelist()[0])

    text = body.decode("utf-8", errors="replace")
    rows = [ln.split(",") for ln in text.splitlines() if "," in ln]

    with out.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["rank", "domain"])
        for parts in rows:
            if len(parts) >= 2 and parts[0].strip().isdigit():
                w.writerow([parts[0].strip(), parts[1].strip()])

    print(f"[tranco] wrote {len(rows):,} ranked domains -> {out.name}")
    _update_manifest(
        "tranco", list_id=list_id, endpoint=download,
        rows=len(rows), file=out.name,
    )
    return out


# --------------------------------------------------------------------------
# Common Crawl — benign URLs WITH realistic paths
# --------------------------------------------------------------------------
CC_COLLINFO = "https://index.commoncrawl.org/collinfo.json"


def _pick_cc_index(s: requests.Session, preferred: str | None = None) -> str:
    """Choose a Common Crawl index endpoint that actually answers queries."""
    if preferred:
        return f"https://index.commoncrawl.org/{preferred}-index"
    r = s.get(CC_COLLINFO, timeout=60)
    r.raise_for_status()
    collections = r.json()
    # The newest collection is sometimes still being built and 404s on query,
    # so probe a few and take the first that returns results.
    for c in collections[:6]:
        api = c["cdx-api"]
        try:
            probe = s.get(
                api,
                params={"url": "wikipedia.org/wiki/*", "output": "json",
                        "limit": 1},
                timeout=60,
            )
            if probe.status_code == 200 and probe.text.strip():
                print(f"[cc] using index {c['id']}")
                return api
        except requests.RequestException:
            continue
        time.sleep(1.0)
    raise RuntimeError("no responsive Common Crawl index found")


def fetch_commoncrawl_benign(
    n_domains: int = 3000,
    per_domain: int = 12,
    workers: int = 4,
    collection: str | None = None,
    rank_min: int = 200,
    rank_max: int = 120_000,
    seed: int = 20260721,
) -> Path:
    """Sample real benign URLs (with paths) for Tranco-ranked domains.

    Domains are sampled *randomly from a rank window*, not taken from the very
    top of the list. The top of Tranco is dominated by infrastructure hosts
    (googleapis.com, amazonaws.com, cloudflare.com, CDNs) whose crawled "URLs"
    are API endpoints and OAuth scope strings — not the kind of page URL a
    person would ever paste into a link checker. Sampling from rank
    ~200-120,000 yields ordinary content websites with ordinary deep paths,
    which is the benign population we actually need to discriminate against.

    Resumable: completed domains are checkpointed, so an interrupted run picks
    up where it left off rather than re-querying.
    """
    tranco = RAW / "tranco.csv"
    if not tranco.exists():
        raise SystemExit("run `python ml/data_acquisition.py tranco` first")

    out = RAW / "benign_cc.jsonl"
    ckpt = RAW / "benign_cc.checkpoint.json"

    pool_domains: list[tuple[int, str]] = []
    with tranco.open(encoding="utf-8") as fh:
        rd = csv.DictReader(fh)
        for row in rd:
            rk = int(row["rank"])
            if rank_min <= rk <= rank_max:
                pool_domains.append((rk, row["domain"]))

    rng = random.Random(seed)
    rng.shuffle(pool_domains)
    domains = pool_domains[:n_domains]
    print(f"[cc] sampled {len(domains):,} domains from Tranco ranks "
          f"{rank_min:,}-{rank_max:,} (seed={seed})")

    done: set[str] = set()
    if ckpt.exists():
        done = set(json.loads(ckpt.read_text(encoding="utf-8"))["done"])
        print(f"[cc] resuming — {len(done):,} domains already queried")

    todo = [(rk, d) for rk, d in domains if d not in done]
    print(f"[cc] {len(todo):,} domains to query "
          f"({per_domain} URLs each, {workers} workers)")

    s = _session()
    api = _pick_cc_index(s, collection)

    lock = Lock()
    fh_out = out.open("a", encoding="utf-8")
    counts = {"urls": 0, "domains_ok": 0, "domains_empty": 0, "errors": 0}

    def _query(item: tuple[int, str]) -> None:
        rank, domain = item
        # Politeness + backoff: CC's index rate-limits aggressively with 503.
        for attempt in range(4):
            try:
                r = s.get(
                    api,
                    params={"url": f"{domain}/*", "output": "json",
                            "limit": per_domain * 4},
                    timeout=90,
                )
            except requests.RequestException:
                time.sleep(2 ** attempt + random.random())
                continue

            if r.status_code == 404:
                with lock:
                    counts["domains_empty"] += 1
                    done.add(domain)
                return
            if r.status_code in (429, 503):
                time.sleep(2 ** attempt + random.random() * 2)
                continue
            if r.status_code != 200:
                with lock:
                    counts["errors"] += 1
                    done.add(domain)
                return

            urls: list[str] = []
            for line in r.text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                u = rec.get("url", "")
                if not u.startswith(("http://", "https://")):
                    continue
                # Skip crawler plumbing that isn't representative of the
                # URLs a user would ever paste into a checker.
                if re.search(r"/(robots\.txt|sitemap[^/]*\.xml|favicon\.ico)$",
                             u, re.I):
                    continue
                # Skip entries that aren't really URLs. Common Crawl
                # occasionally indexes concatenated OAuth scope strings and
                # similar junk. NOTE: this filter is deliberately narrow —
                # it drops *malformed* entries, not merely long or ugly ones.
                # Filtering benign URLs down to short, tidy ones would quietly
                # recreate the very structural bias this whole sampling
                # strategy exists to avoid.
                if re.search(r"[\s<>\"]", u) or re.search(r",https?:/", u):
                    continue
                urls.append(u)

            # Deduplicate, then keep a spread rather than the first N (which
            # tend to be near-identical paginated paths).
            urls = list(dict.fromkeys(urls))
            random.shuffle(urls)
            urls = urls[:per_domain]

            with lock:
                for u in urls:
                    fh_out.write(json.dumps(
                        {"url": u, "domain": domain, "tranco_rank": rank}
                    ) + "\n")
                counts["urls"] += len(urls)
                if urls:
                    counts["domains_ok"] += 1
                else:
                    counts["domains_empty"] += 1
                done.add(domain)
            return

        with lock:
            counts["errors"] += 1
            done.add(domain)

    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = [pool.submit(_query, it) for it in todo]
            for i, _ in enumerate(as_completed(futs), 1):
                if i % 100 == 0:
                    fh_out.flush()
                    ckpt.write_text(
                        json.dumps({"done": sorted(done)}), encoding="utf-8"
                    )
                    print(f"[cc] {i:,}/{len(todo):,} domains | "
                          f"{counts['urls']:,} URLs | "
                          f"empty={counts['domains_empty']:,} "
                          f"err={counts['errors']:,}", flush=True)
    finally:
        fh_out.close()
        ckpt.write_text(json.dumps({"done": sorted(done)}), encoding="utf-8")

    print(f"[cc] done: {counts}")
    _update_manifest(
        "commoncrawl",
        endpoint=api,
        domains_queried=len(done),
        urls=counts["urls"],
        per_domain=per_domain,
        file=out.name,
        note="URL index only; page content (WARC) never fetched.",
    )
    return out


# --------------------------------------------------------------------------
# Hacker News (Algolia) — benign URLs WITH realistic paths
# --------------------------------------------------------------------------
HN_SEARCH = "https://hn.algolia.com/api/v1/search_by_date"


def fetch_hackernews_benign(target: int = 60_000, workers: int = 1) -> Path:
    """Collect real, human-submitted URLs as benign examples.

    Why this source: it satisfies the same requirement Common Crawl does —
    benign URLs that are *structurally comparable* to the malicious ones (real
    paths, query strings, subdomains) — while being fast and reliable. Common
    Crawl's index began refusing connections partway through the build (see
    DECISIONS.md), so this is the primary benign source.

    Algolia caps how deep you can paginate within a single query, so we walk
    backwards through time: exhaust the available pages, then move the cursor
    to just before the oldest story seen and repeat. That gives effectively
    unlimited historical depth.

    Known bias, documented rather than hidden: HN skews technical, so
    github.com and similar are over-represented. The domain-grouped split stops
    that from leaking across train/test, and EVALUATION.md records it as a
    limitation on generalisation.
    """
    out = RAW / "benign_hn.jsonl"
    seen: set[str] = set()

    # Resume from whatever a previous run collected.
    if out.exists():
        with out.open(encoding="utf-8") as fh:
            for line in fh:
                try:
                    seen.add(json.loads(line)["url"])
                except (json.JSONDecodeError, KeyError):
                    continue
        print(f"[hn] resuming — {len(seen):,} URLs already collected")

    s = _session()
    fh_out = out.open("a", encoding="utf-8")
    cursor = int(time.time())
    rounds = 0

    try:
        while len(seen) < target:
            rounds += 1
            added_this_round = 0
            oldest = cursor

            for page in range(5):  # Algolia caps useful page depth
                try:
                    r = s.get(
                        HN_SEARCH,
                        params={
                            "tags": "story",
                            "hitsPerPage": 1000,
                            "page": page,
                            "numericFilters": f"created_at_i<{cursor}",
                        },
                        timeout=60,
                    )
                except requests.RequestException as exc:
                    print(f"[hn] request error: {exc}")
                    time.sleep(3)
                    continue

                if r.status_code == 429:
                    print("[hn] rate limited, backing off")
                    time.sleep(10)
                    continue
                if r.status_code != 200:
                    print(f"[hn] status {r.status_code}, stopping page loop")
                    break

                hits = r.json().get("hits", [])
                if not hits:
                    break

                for h in hits:
                    u = (h.get("url") or "").strip()
                    ts = h.get("created_at_i")
                    if isinstance(ts, int):
                        oldest = min(oldest, ts)
                    if not u.startswith(("http://", "https://")):
                        continue
                    if u in seen:
                        continue
                    seen.add(u)
                    added_this_round += 1
                    fh_out.write(json.dumps(
                        {"url": u, "created_at": ts,
                         "hn_id": h.get("objectID")}) + "\n")

                time.sleep(0.4)  # be polite to a free API

            fh_out.flush()
            print(f"[hn] round {rounds}: +{added_this_round:,} "
                  f"-> {len(seen):,}/{target:,} "
                  f"(cursor {datetime.fromtimestamp(cursor, timezone.utc).date()})",
                  flush=True)

            if oldest >= cursor or added_this_round == 0:
                # Ran out of history or stopped making progress.
                print("[hn] no further progress; stopping")
                break
            cursor = oldest - 1
    finally:
        fh_out.close()

    print(f"[hn] collected {len(seen):,} unique URLs")
    _update_manifest(
        "hackernews",
        name="Hacker News via Algolia Search API",
        terms_url="https://hn.algolia.com/api",
        summary=("Free public search API over HN submissions, no auth. Used as "
                 "a source of real human-submitted benign URLs with paths."),
        endpoint=HN_SEARCH,
        rows=len(seen),
        file=out.name,
        bias_note=("HN submissions skew technical; github.com and similar are "
                   "over-represented relative to general web traffic."),
    )
    return out


# --------------------------------------------------------------------------
def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("urlhaus").add_argument("--full", action="store_true")
    sub.add_parser("openphish").add_argument("--history-pages", type=int, default=8)
    sub.add_parser("tranco")

    b = sub.add_parser("benign")
    b.add_argument("--domains", type=int, default=3000)
    b.add_argument("--per-domain", type=int, default=12)
    b.add_argument("--workers", type=int, default=4)
    b.add_argument("--collection", default=None)
    b.add_argument("--rank-min", type=int, default=200)
    b.add_argument("--rank-max", type=int, default=120_000)
    b.add_argument("--seed", type=int, default=20260721)

    h = sub.add_parser("hn")
    h.add_argument("--target", type=int, default=60_000)

    a = sub.add_parser("all")
    a.add_argument("--domains", type=int, default=3000)
    a.add_argument("--per-domain", type=int, default=12)
    a.add_argument("--hn-target", type=int, default=60_000)

    args = p.parse_args()
    RAW.mkdir(parents=True, exist_ok=True)

    if args.cmd == "urlhaus":
        fetch_urlhaus(full=args.full)
    elif args.cmd == "openphish":
        fetch_openphish(history_pages=args.history_pages)
    elif args.cmd == "tranco":
        fetch_tranco()
    elif args.cmd == "benign":
        fetch_commoncrawl_benign(
            n_domains=args.domains, per_domain=args.per_domain,
            workers=args.workers, collection=args.collection,
            rank_min=args.rank_min, rank_max=args.rank_max, seed=args.seed,
        )
    elif args.cmd == "hn":
        fetch_hackernews_benign(target=args.target)
    elif args.cmd == "all":
        fetch_urlhaus()
        fetch_openphish()
        fetch_tranco()
        fetch_hackernews_benign(target=args.hn_target)
        # Common Crawl is best-effort: its index intermittently refuses
        # connections. The build must not fail because a secondary benign
        # source is down.
        try:
            fetch_commoncrawl_benign(n_domains=args.domains,
                                     per_domain=args.per_domain)
        except Exception as exc:  # noqa: BLE001 - best-effort by design
            print(f"[cc] skipped (best-effort source unavailable): {exc}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
