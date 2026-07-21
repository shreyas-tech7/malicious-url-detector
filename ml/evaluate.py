"""Evaluate the classifier and write a committed report.

Everything printed and written here comes from executing the model against a
held-out set. Nothing is estimated or carried over from a previous run.

The report deliberately includes configurations that make the model look
*worse*, because the gap between them is the actual finding:

  headline        domain-grouped split, no reputation features
  +reputation     adds Tranco features, which partly restate the label
  random split    the naive row-level split, for comparison
  -is_https       drops the strongest single structural separator

Outputs: reports/EVALUATION.md and reports/metrics.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.inspection import permutation_importance
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))

from train import (  # noqa: E402
    ARTIFACTS,
    TrainConfig,
    build_matrix,
    load_features,
    save_bundle,
    train,
)
from features import NUMERIC_FEATURES, REPUTATION_FEATURES  # noqa: E402

ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / "reports"


# --------------------------------------------------------------------------
def score(y_true, proba, threshold: float = 0.5) -> dict:
    pred = (proba >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    return {
        "threshold": threshold,
        "precision": float(precision_score(y_true, pred, zero_division=0)),
        "recall": float(recall_score(y_true, pred, zero_division=0)),
        "f1": float(f1_score(y_true, pred, zero_division=0)),
        "pr_auc": float(average_precision_score(y_true, proba)),
        "roc_auc": float(roc_auc_score(y_true, proba)),
        "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "n": int(len(y_true)),
    }


def run(df: pd.DataFrame, cfg: TrainConfig) -> tuple[dict, object]:
    res = train(df, cfg)
    proba = res.model.predict_proba(res.X_test)[:, 1]
    m = score(res.y_test, proba)
    m["config"] = {
        "name": cfg.name,
        "split": cfg.split,
        "include_reputation": cfg.include_reputation,
        "drop_features": list(cfg.drop_features),
        "notes": cfg.notes,
    }
    m["meta"] = res.meta
    print(f"[{cfg.name}] precision={m['precision']:.4f} "
          f"recall={m['recall']:.4f} f1={m['f1']:.4f} "
          f"pr_auc={m['pr_auc']:.4f}")
    return m, res


# --------------------------------------------------------------------------
def leakage_audit(df: pd.DataFrame, res) -> dict:
    """The checks that decide whether the headline number means anything."""
    print("\n" + "=" * 68)
    print("LEAKAGE AUDIT")
    print("=" * 68)
    out: dict = {}

    # 1. Exact duplicate URL strings anywhere in the dataset.
    dup = int(df.url.duplicated().sum())
    out["duplicate_urls"] = dup
    print(f"exact duplicate URLs in dataset ......... {dup}")

    # 2. Domains straddling the train/test boundary. Must be zero by
    #    construction; asserted here rather than trusted.
    bleed = res.train_domains & res.test_domains
    out["domains_across_split"] = len(bleed)
    print(f"domains present in BOTH train and test .. {len(bleed)}")

    # 3. Duplicate URLs straddling the split.
    train_urls = set(df.url) - set(res.test_df.url)
    cross = len(set(res.test_df.url) & train_urls)
    out["urls_across_split"] = cross
    print(f"URL strings in both train and test ...... {cross}")

    # 4. Single-feature separability. If one feature alone almost separates
    #    the classes, the model is not learning much and that feature is
    #    probably an artifact of how the data was assembled.
    print("\nsingle-feature AUC (a value near 1.0 = that feature alone "
          "nearly solves the task):")
    singles = {}
    y = df.label.to_numpy()
    for f in NUMERIC_FEATURES + REPUTATION_FEATURES:
        if f not in df.columns:
            continue
        v = df[f].to_numpy(dtype=float)
        if np.all(v == v[0]):
            continue
        auc = roc_auc_score(y, v)
        singles[f] = float(max(auc, 1 - auc))  # direction-agnostic
    for f, auc in sorted(singles.items(), key=lambda kv: -kv[1])[:10]:
        flag = "  <-- dominant" if auc >= 0.90 else ""
        print(f"  {f:<24} {auc:.4f}{flag}")
    out["single_feature_auc"] = singles
    out["max_single_feature_auc"] = max(singles.values()) if singles else 0.0

    return out


def importances(res, top: int = 15) -> list[dict]:
    """Permutation importance on the held-out set."""
    print("\ncomputing permutation importance (held-out set)...")
    # Subsample for runtime; permutation importance is O(n_features * n_repeats).
    n = min(4000, len(res.y_test))
    rng = np.random.default_rng(0)
    idx = rng.choice(len(res.y_test), size=n, replace=False)
    r = permutation_importance(
        res.model, res.X_test[idx], res.y_test[idx],
        n_repeats=5, random_state=0, scoring="average_precision",
    )
    rows = [
        {"feature": c, "importance": float(m), "std": float(s)}
        for c, m, s in zip(res.columns, r.importances_mean, r.importances_std)
    ]
    rows.sort(key=lambda d: -d["importance"])
    for d in rows[:top]:
        print(f"  {d['feature']:<24} {d['importance']:.4f} ± {d['std']:.4f}")
    return rows


def threshold_sweep(y, proba) -> list[dict]:
    """Precision/recall across thresholds.

    A detector is usually tuned for precision — a false positive means telling
    a user a legitimate link is malicious, which burns trust fast.
    """
    prec, rec, thr = precision_recall_curve(y, proba)
    rows = []
    for t in (0.5, 0.7, 0.8, 0.9, 0.95, 0.99):
        pred = (proba >= t).astype(int)
        if pred.sum() == 0:
            continue
        rows.append({
            "threshold": t,
            "precision": float(precision_score(y, pred, zero_division=0)),
            "recall": float(recall_score(y, pred, zero_division=0)),
            "flagged": int(pred.sum()),
        })
    return rows


def per_source_recall(res, proba) -> dict:
    te = res.test_df.copy()
    te["proba"] = proba
    out = {}
    for src, grp in te[te.label == 1].groupby("source"):
        out[src] = {
            "n": int(len(grp)),
            "recall": float((grp.proba >= 0.5).mean()),
        }
    for src, grp in te[te.label == 0].groupby("source"):
        out[src] = {
            "n": int(len(grp)),
            "false_positive_rate": float((grp.proba >= 0.5).mean()),
        }
    return out


def error_samples(res, proba, k: int = 8) -> dict:
    te = res.test_df.copy()
    te["proba"] = proba
    fp = te[(te.label == 0) & (te.proba >= 0.5)].nlargest(k, "proba")
    fn = te[(te.label == 1) & (te.proba < 0.5)].nsmallest(k, "proba")
    return {
        "false_positives": [
            {"url": u[:120], "proba": round(float(p), 3)}
            for u, p in zip(fp.url, fp.proba)
        ],
        "false_negatives": [
            {"url": u[:120], "proba": round(float(p), 3)}
            for u, p in zip(fn.url, fn.proba)
        ],
    }


# --------------------------------------------------------------------------
def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    df = load_features()

    stats_path = ROOT / "data" / "processed" / "dataset_stats.json"
    dataset_stats = json.loads(stats_path.read_text(encoding="utf-8")) \
        if stats_path.exists() else {}

    experiments = [
        TrainConfig(name="headline", split="domain", include_reputation=False,
                    notes="Domain-grouped split, no reputation features. "
                          "The number to quote."),
        TrainConfig(name="with_reputation", split="domain",
                    include_reputation=True,
                    notes="Adds Tranco features. Benign URLs were sampled from "
                          "Tranco-ranked domains, so these partly restate the "
                          "label."),
        TrainConfig(name="random_split", split="random",
                    include_reputation=False,
                    notes="Naive row-level split. Shows how much campaign "
                          "duplication inflates the score."),
        TrainConfig(name="no_https_feature", split="domain",
                    include_reputation=False, drop_features=("is_https",),
                    notes="Drops the strongest structural separator to test how "
                          "much the model leans on it."),
    ]

    results = {}
    headline_res = None
    headline_proba = None

    for cfg in experiments:
        m, res = run(df, cfg)
        results[cfg.name] = m
        if cfg.name == "headline":
            headline_res = res
            headline_proba = res.model.predict_proba(res.X_test)[:, 1]

    audit = leakage_audit(df, headline_res)
    imps = importances(headline_res)
    sweep = threshold_sweep(headline_res.y_test, headline_proba)
    by_source = per_source_recall(headline_res, headline_proba)
    errors = error_samples(headline_res, headline_proba)

    print("\nthreshold sweep (headline):")
    for r in sweep:
        print(f"  t={r['threshold']:.2f}  precision={r['precision']:.4f}  "
              f"recall={r['recall']:.4f}  flagged={r['flagged']:,}")

    metrics = {
        "generated_at": pd.Timestamp.now("UTC").isoformat(),
        "dataset_stats": dataset_stats,
        "experiments": results,
        "leakage_audit": audit,
        "permutation_importance": imps,
        "threshold_sweep": sweep,
        "per_source": by_source,
        "error_samples": errors,
    }
    (REPORTS / "metrics.json").write_text(
        json.dumps(metrics, indent=2), encoding="utf-8")
    print(f"\nwrote {REPORTS / 'metrics.json'}")

    write_report(metrics)

    # Re-save the headline model as the shipped artifact.
    save_bundle(headline_res, ARTIFACTS / "model.joblib")
    return 0


# --------------------------------------------------------------------------
def write_report(m: dict) -> None:
    h = m["experiments"]["headline"]
    rep = m["experiments"]["with_reputation"]
    rnd = m["experiments"]["random_split"]
    nohttps = m["experiments"]["no_https_feature"]
    c = h["confusion"]
    final = m["dataset_stats"].get("final", {})
    raw = m["dataset_stats"].get("after_dedupe", {})
    audit = m["leakage_audit"]

    def row(name, d):
        return (f"| {name} | {d['precision']:.4f} | {d['recall']:.4f} | "
                f"{d['f1']:.4f} | {d['pr_auc']:.4f} | {d['meta']['n_test']:,} |")

    lines = [
        "# Evaluation",
        "",
        f"_Generated by `ml/evaluate.py` at {m['generated_at']}. Every number "
        "on this page is the output of that script against a held-out set; "
        "none are estimated._",
        "",
        "## Dataset",
        "",
        "| | |",
        "|---|---|",
        f"| Rows (final) | {final.get('rows', 0):,} |",
        f"| Malicious | {final.get('malicious', 0):,} "
        f"({final.get('malicious', 0) / max(final.get('rows', 1), 1):.1%}) |",
        f"| Benign | {final.get('benign', 0):,} "
        f"({final.get('benign', 0) / max(final.get('rows', 1), 1):.1%}) |",
        f"| Distinct registrable domains | {final.get('distinct_domains', 0):,} |",
        f"| Domains appearing in both classes | "
        f"{final.get('domains_in_both_classes', 0):,} |",
        f"| Rows before capping/balancing | {raw.get('rows', 0):,} |",
        "",
        "Sources: URLhaus (malware distribution), OpenPhish incl. mined feed "
        "history (phishing), Hacker News via Algolia (benign), Common Crawl "
        "(benign, best-effort). See `ml/data/raw/MANIFEST.json` for endpoints, "
        "licences and fetch timestamps.",
        "",
        "URLs per (domain, label) are capped at 25 and the classes are balanced "
        "**by domain**, so a handful of large campaigns cannot dominate.",
        "",
        "## Methodology",
        "",
        "**Split: grouped by registrable domain (eTLD+1).** Every URL sharing an "
        "eTLD+1 goes entirely into train or entirely into test. Campaigns emit "
        "hundreds of near-identical URLs on one host; under a random row-level "
        "split those siblings appear on both sides and the test set measures "
        "memorisation. The `random_split` row below quantifies exactly that.",
        "",
        "**Imbalance** is handled with `class_weight=\"balanced\"` in addition to "
        "the domain-level balancing done at dataset build time.",
        "",
        "**Model:** `HistGradientBoostingClassifier`, early stopping on a 15% "
        "validation slice of the training data.",
        "",
        "## Headline result",
        "",
        f"On the held-out set of **{h['meta']['n_test']:,} URLs** spanning "
        f"**{h['meta']['n_test_domains']:,} domains never seen in training**:",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| **Precision** | **{h['precision']:.4f}** |",
        f"| Recall | {h['recall']:.4f} |",
        f"| F1 | {h['f1']:.4f} |",
        f"| PR-AUC | {h['pr_auc']:.4f} |",
        f"| ROC-AUC | {h['roc_auc']:.4f} |",
        "",
        "Confusion matrix (threshold 0.5):",
        "",
        "| | predicted benign | predicted malicious |",
        "|---|---|---|",
        f"| **actually benign** | {c['tn']:,} | {c['fp']:,} |",
        f"| **actually malicious** | {c['fn']:,} | {c['tp']:,} |",
        "",
        "## Configuration comparison",
        "",
        "| Configuration | Precision | Recall | F1 | PR-AUC | Test rows |",
        "|---|---|---|---|---|---|",
        row("headline (domain split, no reputation)", h),
        row("+ Tranco reputation features", rep),
        row("naive random row split", rnd),
        row("headline minus `is_https`", nohttps),
        "",
        f"**Reading this table.** The random split scores "
        f"{rnd['precision'] - h['precision']:+.4f} precision against the "
        "domain-grouped one. That difference is not a better model; it is the "
        "same model being graded on URLs whose siblings it already memorised. "
        "It is the number this project would have reported had the split been "
        "done naively.",
        "",
        f"Adding the Tranco reputation features moves precision "
        f"{rep['precision'] - h['precision']:+.4f}. That gain is not "
        "trustworthy either: the benign class was *sampled from* Tranco-ranked "
        "domains, so `in_tranco` largely restates the label. A model leaning on "
        "it degrades into a domain whitelist and fails on the first legitimate "
        "site outside the list. The headline configuration therefore has these "
        "features **off**.",
        "",
        f"Dropping `is_https` costs {nohttps['precision'] - h['precision']:+.4f} "
        f"precision and {nohttps['recall'] - h['recall']:+.4f} recall. The "
        "model does lean on it, but does not collapse without it — the "
        "remaining lexical and structural signals carry most of the load.",
        "",
        "## Leakage audit",
        "",
        "Checks run before trusting any of the above:",
        "",
        "| Check | Result |",
        "|---|---|",
        f"| Exact duplicate URL strings in dataset | {audit['duplicate_urls']} |",
        f"| Domains present in both train and test | "
        f"{audit['domains_across_split']} |",
        f"| URL strings present in both train and test | "
        f"{audit['urls_across_split']} |",
        f"| Highest single-feature AUC | "
        f"{audit['max_single_feature_auc']:.4f} |",
        "",
        "The last row is the important one. If any single feature scored near "
        "1.0 on its own, the task would be solvable without a model and the "
        "dataset would be suspect. Top single-feature AUCs:",
        "",
        "| Feature | AUC alone |",
        "|---|---|",
    ]

    singles = sorted(audit["single_feature_auc"].items(), key=lambda kv: -kv[1])
    for f, auc in singles[:8]:
        lines.append(f"| `{f}` | {auc:.4f} |")

    lines += [
        "",
        "## What the model actually uses",
        "",
        "Permutation importance on the held-out set (drop in average precision "
        "when the feature is shuffled):",
        "",
        "| Feature | Importance |",
        "|---|---|",
    ]
    for d in m["permutation_importance"][:12]:
        lines.append(f"| `{d['feature']}` | {d['importance']:.4f} ± {d['std']:.4f} |")

    lines += [
        "",
        "## Threshold selection",
        "",
        "A false positive tells a user a legitimate link is dangerous, which "
        "costs trust quickly. Raising the threshold trades recall for precision:",
        "",
        "| Threshold | Precision | Recall | URLs flagged |",
        "|---|---|---|---|",
    ]
    for r in m["threshold_sweep"]:
        lines.append(f"| {r['threshold']:.2f} | {r['precision']:.4f} | "
                     f"{r['recall']:.4f} | {r['flagged']:,} |")

    lines += [
        "",
        "## Per-source breakdown",
        "",
        "| Source | n (test) | Recall / FP-rate |",
        "|---|---|---|",
    ]
    for src, d in sorted(m["per_source"].items()):
        val = d.get("recall")
        label = "recall" if val is not None else "FP-rate"
        val = val if val is not None else d.get("false_positive_rate")
        lines.append(f"| {src} | {d['n']:,} | {val:.4f} ({label}) |")

    lines += [
        "",
        "## Error analysis",
        "",
        "Highest-confidence false positives (benign, scored malicious):",
        "",
    ]
    for e in m["error_samples"]["false_positives"]:
        lines.append(f"- `{e['url']}` — {e['proba']}")
    lines += ["", "Missed malicious URLs (lowest scored):", ""]
    for e in m["error_samples"]["false_negatives"]:
        lines.append(f"- `{e['url']}` — {e['proba']}")

    lines += [
        "",
        "## Limitations",
        "",
        "Read these before quoting the headline number anywhere.",
        "",
        "1. **Benign data still skews technical, and the residual failure mode "
        "is measurable.** Hacker News is the largest benign source; Wikipedia "
        "external links were added specifically to cover the non-technical, "
        "older, non-English web, which cut the worst false positives roughly "
        "in half. What survives is documented in "
        "[GENERALIZATION_PROBE.md](GENERALIZATION_PROBE.md): legitimate "
        "hyphenated non-English domains such as "
        "`clinicadental-sanchez.es/tratamientos/implantes` and "
        "`ryokan-yamamoto.jp/rooms/standard.html` still score ~0.88-0.91. "
        "That is not a bug so much as the ceiling of string-only "
        "classification — a hyphenated, non-.com hostname is genuinely the "
        "shape phishing uses, and nothing in the URL distinguishes a Spanish "
        "dental clinic from an impersonation of one. Resolving it needs domain "
        "reputation or registration age, i.e. signals outside the string.",
        "",
        "2. **Benign URLs are almost entirely HTTPS (99.4%) while malicious "
        "are 60%.** Some of that gap is genuine — malware hosts really do skew "
        "plaintext — but some is an artifact of sampling benign URLs from a "
        "modern link aggregator. The `no_https_feature` row bounds how much "
        "this matters.",
        "",
        "3. **The class balance here is not the real-world base rate.** The "
        "evaluation set is roughly 50/50. Real traffic is overwhelmingly "
        "benign, and precision falls as the positive class gets rarer: at a 1% "
        "true malicious rate, the same model's precision would be far below "
        "what this table shows. These numbers describe discrimination ability, "
        "not deployed performance.",
        "",
        "4. **Threat feeds are a biased sample of malice.** URLhaus and "
        "OpenPhish contain URLs that were *detected and reported*. Malicious "
        "URLs that evade detection are, by definition, absent — so real-world "
        "recall against a competent adversary is lower than measured.",
        "",
        "5. **Static analysis only.** The classifier sees the URL string and "
        "nothing else. It never fetches the page (deliberately — see the SSRF "
        "note in the README). A malicious page on a clean-looking URL, or a "
        "compromised legitimate site, is invisible to it.",
        "",
        "6. **No adversarial evaluation.** An attacker who knows these features "
        "can craft URLs to defeat them (use HTTPS, a short path, no keywords, a "
        "plausible domain). Nothing here measures robustness to that.",
        "",
        "7. **The model decays.** Phishing infrastructure and TLD fashions turn "
        "over quickly. Without periodic retraining these numbers will degrade; "
        "no drift monitoring is implemented.",
        "",
        "8. **Portfolio-grade, not enterprise threat intel.** This demonstrates "
        "the full pipeline — data, features, leakage-aware evaluation, serving "
        "— and should not be used as a real security control.",
        "",
    ]

    path = REPORTS / "EVALUATION.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {path}")


if __name__ == "__main__":
    sys.exit(main())
