"""Assemble the labelled dataset from the raw feeds, then featurise it.

Run after data_acquisition.py. Produces:

    data/processed/dataset.csv    url, label, source, domain
    data/processed/features.*     the model-ready feature matrix

This script prints a lot of diagnostics on purpose. The interesting failure
mode for a URL classifier is not a bad model, it is a dataset whose two halves
differ in some incidental way the model can latch onto. The numbers printed here
(URLs per domain, domain overlap between classes, path-presence rates by class)
are what make that visible, and they are echoed into EVALUATION.md.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))

from features import (  # noqa: E402
    ReputationIndex,
    extract_features,
    feature_names,
    registrable_domain,
)

ROOT = Path(__file__).resolve().parent
RAW = ROOT / "data" / "raw"
PROC = ROOT / "data" / "processed"

SEED = 20260721


# --------------------------------------------------------------------------
def _load_urlhaus() -> list[tuple[str, int, str]]:
    p = RAW / "urlhaus.csv"
    if not p.exists():
        return []
    rows = []
    with p.open(encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            u = (r.get("url") or "").strip()
            if u.startswith(("http://", "https://")):
                rows.append((u, 1, "urlhaus"))
    return rows


def _load_openphish() -> list[tuple[str, int, str]]:
    p = RAW / "openphish.csv"
    if not p.exists():
        return []
    rows = []
    with p.open(encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            u = (r.get("url") or "").strip()
            if u.startswith(("http://", "https://")):
                rows.append((u, 1, "openphish"))
    return rows


def _load_jsonl(name: str, source: str, label: int) -> list[tuple[str, int, str]]:
    p = RAW / name
    if not p.exists():
        return []
    rows = []
    with p.open(encoding="utf-8") as fh:
        for line in fh:
            try:
                u = (json.loads(line).get("url") or "").strip()
            except json.JSONDecodeError:
                continue
            if u.startswith(("http://", "https://")):
                rows.append((u, label, source))
    return rows


# --------------------------------------------------------------------------
def _has_path(url: str) -> bool:
    try:
        return len(urlsplit(url).path.strip("/")) > 0
    except ValueError:
        return False


def _diagnose(df: pd.DataFrame, stage: str) -> dict:
    """Print (and return) the dataset-shape checks that matter for leakage."""
    print(f"\n{'=' * 68}\n{stage}\n{'=' * 68}")

    n = len(df)
    n_mal = int((df.label == 1).sum())
    n_ben = int((df.label == 0).sum())
    print(f"rows                  {n:>9,}")
    print(f"  malicious           {n_mal:>9,}  ({n_mal / max(n,1):.1%})")
    print(f"  benign              {n_ben:>9,}  ({n_ben / max(n,1):.1%})")

    print("\nby source:")
    for src, c in df.source.value_counts().items():
        print(f"  {src:<14} {c:>9,}")

    dom_mal = set(df.loc[df.label == 1, "domain"])
    dom_ben = set(df.loc[df.label == 0, "domain"])
    overlap = dom_mal & dom_ben
    print(f"\ndistinct domains      {df.domain.nunique():>9,}")
    print(f"  malicious-only      {len(dom_mal - dom_ben):>9,}")
    print(f"  benign-only         {len(dom_ben - dom_mal):>9,}")
    print(f"  in BOTH classes     {len(overlap):>9,}")

    # URLs per domain — a high mean on one side means that class is really a
    # handful of campaigns repeated, which shrinks the effective sample size.
    for label, name in ((1, "malicious"), (0, "benign")):
        sub = df[df.label == label]
        if sub.empty:
            continue
        per = sub.groupby("domain").size()
        print(f"\nURLs per domain ({name}):")
        print(f"  domains             {len(per):>9,}")
        print(f"  mean                {per.mean():>9.1f}")
        print(f"  median              {per.median():>9.1f}")
        print(f"  max                 {per.max():>9,}")

    # THE structural check: if benign URLs mostly lack a path while malicious
    # ones have one, "has a path" alone separates the classes and every metric
    # downstream is meaningless.
    print("\nstructural comparability (guards against leakage-by-construction):")
    for label, name in ((1, "malicious"), (0, "benign")):
        sub = df[df.label == label]
        if sub.empty:
            continue
        pct_path = sub.url.map(_has_path).mean()
        med_len = sub.url.str.len().median()
        pct_https = sub.url.str.startswith("https://").mean()
        print(f"  {name:<10} has-path {pct_path:6.1%} | "
              f"median len {med_len:5.0f} | https {pct_https:6.1%}")

    return {
        "rows": n, "malicious": n_mal, "benign": n_ben,
        "distinct_domains": int(df.domain.nunique()),
        "domains_in_both_classes": len(overlap),
    }


# --------------------------------------------------------------------------
def build(max_per_domain: int, balance: bool) -> None:
    PROC.mkdir(parents=True, exist_ok=True)
    rng = random.Random(SEED)

    rows: list[tuple[str, int, str]] = []
    rows += _load_urlhaus()
    rows += _load_openphish()
    rows += _load_jsonl("benign_hn.jsonl", "hackernews", 0)
    rows += _load_jsonl("benign_wikipedia.jsonl", "wikipedia", 0)
    rows += _load_jsonl("benign_cc.jsonl", "commoncrawl", 0)

    if not rows:
        raise SystemExit("no raw data found — run data_acquisition.py first")

    df = pd.DataFrame(rows, columns=["url", "label", "source"])
    print(f"loaded {len(df):,} raw rows")

    # Exact-duplicate URLs across sources would put the same string in train
    # and test. Drop them, keeping the malicious label if a URL somehow appears
    # in both (a benign feed listing a compromised page is the likelier error).
    before = len(df)
    df = df.sort_values("label", ascending=False).drop_duplicates(
        subset="url", keep="first")
    print(f"dropped {before - len(df):,} exact-duplicate URLs")

    print("computing registrable domains (eTLD+1)...")
    df["domain"] = df.url.map(registrable_domain)
    df = df[df.domain.astype(bool)]

    stats_raw = _diagnose(df, "STAGE 1 — after dedupe, before rebalancing")

    # Cap URLs per domain. Phishing campaigns generate hundreds of near-identical
    # URLs on one host; without a cap those dominate the loss and the model
    # overfits a few campaigns rather than learning general structure.
    if max_per_domain > 0:
        keep_idx = []
        for (_, _), grp in df.groupby(["domain", "label"], sort=False):
            idx = list(grp.index)
            if len(idx) > max_per_domain:
                idx = rng.sample(idx, max_per_domain)
            keep_idx += idx
        before = len(df)
        df = df.loc[keep_idx]
        print(f"\ncapped at {max_per_domain} URLs/domain: "
              f"{before:,} -> {len(df):,}")

    # Balance by DOMAIN, not by row. Sampling rows would keep a few huge
    # malicious domains and starve domain diversity, which the grouped split
    # then turns into a tiny effective test set.
    if balance:
        mal_domains = sorted(set(df.loc[df.label == 1, "domain"]))
        ben_domains = sorted(set(df.loc[df.label == 0, "domain"]))
        target = min(len(mal_domains), len(ben_domains))
        rng.shuffle(mal_domains)
        rng.shuffle(ben_domains)
        keep = set(mal_domains[:target]) | set(ben_domains[:target])
        before = len(df)
        df = df[df.domain.isin(keep)]
        print(f"balanced to {target:,} domains per class: "
              f"{before:,} -> {len(df):,} rows")

    df = df.sample(frac=1.0, random_state=SEED).reset_index(drop=True)
    stats_final = _diagnose(df, "STAGE 2 — final dataset")

    out_csv = PROC / "dataset.csv"
    df.to_csv(out_csv, index=False)
    print(f"\nwrote {out_csv.name} ({len(df):,} rows)")

    # ---- featurise -------------------------------------------------------
    # Reputation features are computed here and dropped at train time when
    # ablating, so we never pay the extraction cost twice.
    tranco = RAW / "tranco.csv"
    rep = ReputationIndex.from_tranco_csv(tranco) if tranco.exists() \
        else ReputationIndex()
    print(f"\nreputation index: {len(rep):,} domains")

    names = feature_names(include_reputation=True)
    print(f"extracting {len(names)} features for {len(df):,} URLs...")

    feats = []
    for i, u in enumerate(df.url, 1):
        feats.append(extract_features(u, reputation=rep, include_reputation=True))
        if i % 25_000 == 0:
            print(f"  {i:,}/{len(df):,}", flush=True)

    fdf = pd.DataFrame(feats, columns=names)
    fdf["label"] = df.label.values
    fdf["domain"] = df.domain.values
    fdf["source"] = df.source.values
    fdf["url"] = df.url.values

    try:
        out_f = PROC / "features.parquet"
        fdf.to_parquet(out_f, index=False)
    except Exception as exc:  # pyarrow missing -> CSV is fine, just larger
        print(f"parquet unavailable ({exc}); writing CSV")
        out_f = PROC / "features.csv"
        fdf.to_csv(out_f, index=False)
    print(f"wrote {out_f.name}  shape={fdf.shape}")

    (PROC / "dataset_stats.json").write_text(
        json.dumps({"after_dedupe": stats_raw, "final": stats_final},
                   indent=2), encoding="utf-8")
    print("wrote dataset_stats.json")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--max-per-domain", type=int, default=25,
                   help="cap URLs kept per (domain,label); 0 disables")
    p.add_argument("--no-balance", action="store_true",
                   help="skip domain-level class balancing")
    a = p.parse_args()
    build(max_per_domain=a.max_per_domain, balance=not a.no_balance)
    return 0


if __name__ == "__main__":
    sys.exit(main())
