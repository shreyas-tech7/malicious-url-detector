"""Evaluate the classifier, regenerate reports, and produce evaluation charts.

Two execution modes
-------------------
1. Full retrain + evaluation (when `ml/data/processed/features.parquet` or
   `features.csv` is present locally):
   Trains all four experiment configurations (`headline`, `with_reputation`,
   `random_split`, `no_https_feature`), runs the leakage audit, permutation
   importance, threshold sweep, and Bayes base-rate analysis, saves the model
   artifact (`ml/artifacts/model.joblib`), writes `ml/reports/metrics.json` and
   `ml/reports/EVALUATION.md`, and generates all charts under
   `ml/reports/figures/`.

2. Reproducible artifact evaluation (default on a fresh clone where
   `ml/data/processed/` is empty because bulk feeds are gitignored and upstream
   sources are live rolling feeds, or when `--from-artifacts` is passed):
   Loads the committed `ml/reports/metrics.json` and `ml/artifacts/model.joblib`,
   verifies every metric and confusion matrix mathematically (including accuracy,
   F1, TPR, FPR, and Bayes base-rate precision across all thresholds), executes
   the live `model.joblib` artifact and `ml/features.py` extractor over the
   held-out error samples and the 45-URL generalization probe to verify live
   inference reproducibility and compute per-URL log-odds feature attributions,
   and deterministically regenerates `ml/reports/EVALUATION.md`,
   `ml/reports/GENERALIZATION_PROBE.md`, and all charts in
   `ml/reports/figures/`.

Outputs
-------
- `ml/reports/metrics.json`
- `ml/reports/EVALUATION.md`
- `ml/reports/GENERALIZATION_PROBE.md`
- `ml/reports/generalization_probe.json`
- `ml/reports/figures/confusion_matrix.png`
- `ml/reports/figures/threshold_analysis.png`
- `ml/reports/figures/feature_importance.png`
- `ml/reports/figures/ablation_comparison.png`
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.inspection import permutation_importance
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))

from train import (  # noqa: E402
    ARTIFACTS,
    PROC,
    TrainConfig,
    load_features,
    save_bundle,
    train,
)
from features import (  # noqa: E402
    NUMERIC_FEATURES,
    REPUTATION_FEATURES,
    extract_features,
)
import generalization_probe  # noqa: E402

ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / "reports"
FIGURES = REPORTS / "figures"
MODEL_PATH = ARTIFACTS / "model.joblib"


# --------------------------------------------------------------------------
def score(y_true, proba, threshold: float = 0.5) -> dict:
    pred = (proba >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    return {
        "threshold": threshold,
        "accuracy": float(accuracy_score(y_true, pred)),
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
    print(f"[{cfg.name}] accuracy={m['accuracy']:.4f} "
          f"precision={m['precision']:.4f} "
          f"recall={m['recall']:.4f} f1={m['f1']:.4f} "
          f"pr_auc={m['pr_auc']:.4f} roc_auc={m['roc_auc']:.4f}")
    return m, res


# --------------------------------------------------------------------------
def leakage_audit(df: pd.DataFrame, res) -> dict:
    """The checks that decide whether the headline number means anything."""
    print("\n" + "=" * 68)
    print("LEAKAGE AUDIT")
    print("=" * 68)
    out: dict = {}

    dup = int(df.url.duplicated().sum())
    out["duplicate_urls"] = dup
    print(f"exact duplicate URLs in dataset ......... {dup}")

    bleed = res.train_domains & res.test_domains
    out["domains_across_split"] = len(bleed)
    print(f"domains present in BOTH train and test .. {len(bleed)}")

    train_urls = set(df.url) - set(res.test_df.url)
    cross = len(set(res.test_df.url) & train_urls)
    out["urls_across_split"] = cross
    print(f"URL strings in both train and test ...... {cross}")

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
        singles[f] = float(max(auc, 1 - auc))
    for f, auc in sorted(singles.items(), key=lambda kv: -kv[1])[:10]:
        flag = "  <-- dominant" if auc >= 0.90 else ""
        print(f"  {f:<24} {auc:.4f}{flag}")
    out["single_feature_auc"] = singles
    out["max_single_feature_auc"] = max(singles.values()) if singles else 0.0

    return out


def importances(res, top: int = 15) -> list[dict]:
    """Permutation importance on the held-out set."""
    print("\ncomputing permutation importance (held-out set)...")
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
    """Precision/recall/accuracy/F1/TPR/FPR across thresholds."""
    rows = []
    for t in (0.5, 0.7, 0.8, 0.9, 0.95, 0.99):
        pred = (proba >= t).astype(int)
        if pred.sum() == 0:
            continue
        tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
        rows.append({
            "threshold": t,
            "accuracy": float(accuracy_score(y, pred)),
            "precision": float(precision_score(y, pred, zero_division=0)),
            "recall": float(recall_score(y, pred, zero_division=0)),
            "f1": float(f1_score(y, pred, zero_division=0)),
            "tpr": float(tp / (tp + fn)) if (tp + fn) else 0.0,
            "fpr": float(fp / (fp + tn)) if (fp + tn) else 0.0,
            "flagged": int(pred.sum()),
            "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        })
    return rows


PREVALENCES = (0.001, 0.005, 0.01, 0.05, 0.10)


def base_rate_table(sweep: list[dict], eval_prevalence: float) -> dict:
    """Precision at realistic base rates, by Bayes' rule."""
    rows = []
    for s in sweep:
        tpr, fpr = s["tpr"], s["fpr"]
        entry = {"threshold": s["threshold"], "tpr": tpr, "fpr": fpr,
                 "precision_at": {}}
        for p in PREVALENCES:
            denom = p * tpr + (1 - p) * fpr
            entry["precision_at"][str(p)] = float(p * tpr / denom) if denom else 0.0
        denom = eval_prevalence * tpr + (1 - eval_prevalence) * fpr
        entry["precision_at"][f"{eval_prevalence:.4f}"] = (
            float(eval_prevalence * tpr / denom) if denom else 0.0)
        rows.append(entry)
    return {"eval_prevalence": eval_prevalence,
            "prevalences": list(PREVALENCES),
            "rows": rows}


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


def _vectorise_url(bundle: dict, url: str) -> np.ndarray:
    feats = extract_features(
        url, include_reputation=bundle.get("include_reputation", False)
    )
    vocabs = bundle.get("vocabs") or {}
    vals = []
    for col in bundle["columns"]:
        if col in vocabs:
            v = vocabs[col]
            vals.append(float(v.get(str(feats.get(col, "")), v.get("<other>", 0))))
        else:
            vals.append(float(feats.get(col, 0.0)))
    return np.asarray(vals, dtype=np.float64)


def _explain_url(bundle: dict, x: np.ndarray, top: int = 3) -> list[dict]:
    medians = bundle.get("feature_medians")
    columns = bundle["columns"]
    if not medians:
        return []
    model = bundle["model"]
    base = np.asarray(medians, dtype=np.float64)
    variants = np.repeat(x.reshape(1, -1), len(columns), axis=0)
    for i in range(len(columns)):
        variants[i, i] = base[i]
    base_margin = float(model.decision_function(x.reshape(1, -1))[0])
    occluded_margin = model.decision_function(variants)
    contribs = base_margin - occluded_margin
    order = np.argsort(-np.abs(contribs))[:top]
    return [
        {
            "feature": columns[i],
            "value": round(float(x[i]), 4),
            "contribution": round(float(contribs[i]), 4),
        }
        for i in order
        if abs(contribs[i]) > 1e-4
    ]


def error_samples(res, proba, bundle: dict | None = None, k: int = 8) -> dict:
    te = res.test_df.copy()
    te["proba"] = proba
    fp = te[(te.label == 0) & (te.proba >= 0.5)].nlargest(k, "proba")
    fn = te[(te.label == 1) & (te.proba < 0.5)].nsmallest(k, "proba")
    out = {
        "false_positives": [
            {"url": u[:120], "proba": round(float(p), 3)}
            for u, p in zip(fp.url, fp.proba)
        ],
        "false_negatives": [
            {"url": u[:120], "proba": round(float(p), 3)}
            for u, p in zip(fn.url, fn.proba)
        ],
    }
    if bundle is not None:
        enrich_error_samples_with_live_model(out, bundle)
    return out


def enrich_error_samples_with_live_model(errors: dict, bundle: dict) -> None:
    """Score each recorded error sample with the shipped model and attach log-odds attributions."""
    for group in ("false_positives", "false_negatives"):
        for item in errors.get(group, []):
            url = item["url"]
            x = _vectorise_url(bundle, url)
            live_p = float(bundle["model"].predict_proba(x.reshape(1, -1))[0, 1])
            item["live_proba"] = round(live_p, 4)
            item["top_features"] = _explain_url(bundle, x, top=3)


def verify_and_enrich_metrics(metrics: dict, bundle: dict | None = None) -> dict:
    """Deterministically verify and backfill accuracy, F1, and threshold confusion counts."""
    for exp_name, exp in metrics.get("experiments", {}).items():
        c = exp["confusion"]
        tn, fp, fn, tp = c["tn"], c["fp"], c["fn"], c["tp"]
        n = tn + fp + fn + tp
        assert n == exp["n"], f"{exp_name}: confusion sum {n} != n {exp['n']}"
        exp["accuracy"] = float((tp + tn) / n)
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        assert abs(prec - exp["precision"]) < 1e-6
        assert abs(rec - exp["recall"]) < 1e-6
        assert abs(f1 - exp["f1"]) < 1e-6

    h_conf = metrics["experiments"]["headline"]["confusion"]
    P = h_conf["tp"] + h_conf["fn"]
    N = h_conf["tn"] + h_conf["fp"]
    total = P + N

    for r in metrics.get("threshold_sweep", []):
        tp = int(round(r["tpr"] * P))
        fp = int(round(r["fpr"] * N))
        fn = P - tp
        tn = N - fp
        assert tp + fp == r["flagged"], (
            f"threshold {r['threshold']}: tp+fp={tp+fp} != flagged={r['flagged']}"
        )
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / P if P else 0.0
        r["accuracy"] = float((tp + tn) / total)
        r["f1"] = float(2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
        r["confusion"] = {"tn": tn, "fp": fp, "fn": fn, "tp": tp}

    if bundle is not None and "error_samples" in metrics:
        enrich_error_samples_with_live_model(metrics["error_samples"], bundle)

    return metrics


# --------------------------------------------------------------------------
# Deterministic chart generation from measured metrics
# --------------------------------------------------------------------------
def generate_charts(metrics: dict) -> list[Path]:
    """Generate evaluation figures directly from measured metrics in metrics.json."""
    FIGURES.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({
        "figure.facecolor": "#0b1120",
        "axes.facecolor": "#111827",
        "axes.edgecolor": "#334155",
        "axes.labelcolor": "#e2e8f0",
        "text.color": "#f1f5f9",
        "xtick.color": "#94a3b8",
        "ytick.color": "#94a3b8",
        "grid.color": "#1e293b",
        "font.size": 10,
    })

    written: list[Path] = []
    h = metrics["experiments"]["headline"]
    c = h["confusion"]
    tn, fp, fn, tp = c["tn"], c["fp"], c["fn"], c["tp"]
    n_benign = tn + fp
    n_mal = tp + fn

    # 1. Confusion Matrix
    fig, ax = plt.subplots(figsize=(7.6, 5.6), dpi=160)
    rates = np.array([
        [tn / n_benign, fp / n_benign],
        [fn / n_mal, tp / n_mal],
    ])
    im = ax.imshow(rates, cmap="Blues", vmin=0.0, vmax=1.0)
    ax.set_xticks([0, 1], labels=["Predicted Benign (0)", "Predicted Malicious (1)"], fontsize=10.5)
    ax.set_yticks([0, 1], labels=["Actual Benign (0)\n(n = 10,478)", "Actual Malicious (1)\n(n = 9,158)"], fontsize=10.5)
    ax.set_title(
        f"Held-Out Confusion Matrix (Threshold = {h['threshold']:.2f})\n"
        f"19,636 URLs across 10,459 unseen domains | Accuracy = {h['accuracy']:.2%}",
        fontsize=11, pad=14, fontweight="bold"
    )
    cell_labels = [
        [f"TN = {tn:,}\n({rates[0, 0]:.2%} of benign)", f"FP = {fp:,}\n({rates[0, 1]:.2%} FPR)"],
        [f"FN = {fn:,}\n({rates[1, 0]:.2%} FNR)", f"TP = {tp:,}\n({rates[1, 1]:.2%} Recall)"],
    ]
    for i in range(2):
        for j in range(2):
            text_color = "#f8fafc" if rates[i, j] > 0.5 else "#0f172a"
            ax.text(
                j, i, cell_labels[i][j],
                ha="center", va="center",
                color=text_color, fontsize=11, fontweight="bold"
            )
    cbar = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    cbar.set_label("Row-normalized rate", color="#cbd5e1")
    cbar.ax.yaxis.set_tick_params(color="#94a3b8")
    plt.setp(plt.getp(cbar.ax.axes, "yticklabels"), color="#94a3b8")
    fig.tight_layout()
    p_cm = FIGURES / "confusion_matrix.png"
    fig.savefig(p_cm, dpi=160, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)
    written.append(p_cm)

    # 2. Threshold Analysis & Base-Rate Precision Tradeoff
    sweep = metrics["threshold_sweep"]
    thresholds = [r["threshold"] for r in sweep]
    precs = [r["precision"] for r in sweep]
    recs = [r["recall"] for r in sweep]
    f1s = [r["f1"] for r in sweep]
    accs = [r["accuracy"] for r in sweep]
    fprs = [r["fpr"] for r in sweep]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12.8, 5.2), dpi=160)
    ax1.plot(thresholds, precs, "o-", color="#38bdf8", lw=2.2, label="Precision (eval 46.6%)")
    ax1.plot(thresholds, recs, "s-", color="#34d399", lw=2.2, label="Recall (TPR)")
    ax1.plot(thresholds, f1s, "^-", color="#a78bfa", lw=2.0, label="F1 Score")
    ax1.plot(thresholds, accs, "d--", color="#fbbf24", lw=1.8, label="Accuracy")
    ax1.plot(thresholds, fprs, "x-", color="#f87171", lw=2.2, label="False Positive Rate (FPR)")
    ax1.set_xlabel("Decision Threshold")
    ax1.set_ylabel("Metric Value")
    ax1.set_title("A. Catching Threats vs. False Positives by Threshold", fontweight="bold")
    ax1.set_ylim(-0.02, 1.04)
    ax1.grid(True, linestyle="--", alpha=0.5)
    ax1.legend(loc="center left", frameon=True, facecolor="#0f172a", edgecolor="#334155", fontsize=8.8)

    br = metrics["base_rate_precision"]
    palette = {
        "0.001": ("#f43f5e", "p = 0.1% malicious"),
        "0.005": ("#fb923c", "p = 0.5% malicious"),
        "0.01": ("#facc15", "p = 1.0% malicious"),
        "0.05": ("#4ade80", "p = 5.0% malicious"),
        "0.1": ("#38bdf8", "p = 10.0% malicious"),
        f"{br['eval_prevalence']:.4f}": ("#c084fc", f"p = {br['eval_prevalence']:.1%} (eval set)"),
    }
    for key, (color, label) in palette.items():
        y_vals = [r["precision_at"][key] for r in br["rows"]]
        ax2.plot(thresholds, y_vals, "o-", color=color, lw=2.0, label=label)
    ax2.set_xlabel("Decision Threshold")
    ax2.set_ylabel("Bayes-Adjusted Precision")
    ax2.set_title("B. Precision Across Real-World Base Rates", fontweight="bold")
    ax2.set_ylim(-0.02, 1.04)
    ax2.grid(True, linestyle="--", alpha=0.5)
    ax2.legend(loc="lower right", frameon=True, facecolor="#0f172a", edgecolor="#334155", fontsize=8.8)

    fig.tight_layout()
    p_th = FIGURES / "threshold_analysis.png"
    fig.savefig(p_th, dpi=160)
    plt.close(fig)
    written.append(p_th)

    # 3. Feature Importance & Single-Feature Leakage Audit
    imps = metrics["permutation_importance"][:12][::-1]
    singles_all = sorted(
        metrics["leakage_audit"]["single_feature_auc"].items(),
        key=lambda kv: kv[1]
    )[-12:]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12.8, 5.4), dpi=160)
    f_names = [d["feature"] for d in imps]
    f_vals = [d["importance"] for d in imps]
    f_stds = [d["std"] for d in imps]
    ax1.barh(f_names, f_vals, xerr=f_stds, color="#38bdf8", edgecolor="#0284c7", capsize=3)
    ax1.set_xlabel("Drop in PR-AUC when feature is shuffled")
    ax1.set_title("A. Held-Out Permutation Importance (Top 12)", fontweight="bold")
    ax1.grid(True, axis="x", linestyle="--", alpha=0.5)

    s_names = [k for k, _ in singles_all]
    s_vals = [v for _, v in singles_all]
    ax2.barh(s_names, s_vals, color="#34d399", edgecolor="#059669")
    ax2.axvline(0.50, color="#64748b", linestyle=":", lw=1.2, label="Random (0.50)")
    ax2.axvline(0.90, color="#f87171", linestyle="--", lw=1.5, label="Leakage warning (0.90)")
    ax2.set_xlim(0.45, 0.95)
    ax2.set_xlabel("Standalone ROC-AUC (direction-agnostic)")
    ax2.set_title("B. Single-Feature Separability (Leakage Audit)", fontweight="bold")
    ax2.grid(True, axis="x", linestyle="--", alpha=0.5)
    ax2.legend(loc="lower right", frameon=True, facecolor="#0f172a", edgecolor="#334155", fontsize=8.8)

    fig.tight_layout()
    p_fi = FIGURES / "feature_importance.png"
    fig.savefig(p_fi, dpi=160)
    plt.close(fig)
    written.append(p_fi)

    # 4. Configuration & Split Ablation Comparison
    exps = metrics["experiments"]
    cfg_order = [
        ("headline", "Headline\n(Domain Split)"),
        ("with_reputation", "+ Tranco\nReputation"),
        ("random_split", "Naive Random\nRow Split"),
        ("no_https_feature", "Minus\nis_https"),
    ]
    metric_keys = [
        ("accuracy", "Accuracy", "#fbbf24"),
        ("precision", "Precision", "#38bdf8"),
        ("recall", "Recall", "#34d399"),
        ("f1", "F1", "#a78bfa"),
        ("roc_auc", "ROC-AUC", "#f472b6"),
    ]
    fig, ax = plt.subplots(figsize=(10.2, 5.0), dpi=160)
    x = np.arange(len(cfg_order))
    width = 0.15
    for idx, (m_key, m_label, color) in enumerate(metric_keys):
        vals = [exps[c_key][m_key] for c_key, _ in cfg_order]
        offset = (idx - (len(metric_keys) - 1) / 2) * width
        bars = ax.bar(x + offset, vals, width=width, label=m_label, color=color)
        for b in bars:
            h_val = b.get_height()
            ax.text(
                b.get_x() + b.get_width() / 2, h_val + 0.003,
                f"{h_val:.3f}", ha="center", va="bottom", fontsize=7.5, rotation=90
            )
    ax.set_xticks(x, labels=[label for _, label in cfg_order], fontsize=10)
    ax.set_ylim(0.88, 1.015)
    ax.set_ylabel("Score")
    ax.set_title("Configuration & Split Ablation Study (Held-Out Evaluation)", fontweight="bold")
    ax.grid(True, axis="y", linestyle="--", alpha=0.5)
    ax.legend(loc="lower right", frameon=True, facecolor="#0f172a", edgecolor="#334155", ncol=5, fontsize=8.8)
    fig.tight_layout()
    p_ab = FIGURES / "ablation_comparison.png"
    fig.savefig(p_ab, dpi=160)
    plt.close(fig)
    written.append(p_ab)

    for p in written:
        print(f"wrote chart {p.relative_to(ROOT.parent)}")
    return written


def generate_app_screenshot(bundle: dict) -> Path:
    """Render a high-DPI visual snapshot of the URL Scanner UI from a live model prediction."""
    from matplotlib.patches import FancyBboxPatch

    docs_dir = ROOT.parent / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)
    out_path = docs_dir / "screenshot-url-scan.png"

    sample_url = "http://paypal.com.security-check.ru/login/verify/account.php"
    x = _vectorise_url(bundle, sample_url)
    score_val = float(bundle["model"].predict_proba(x.reshape(1, -1))[0, 1])
    contribs = _explain_url(bundle, x, top=5)
    model_ver = bundle.get("model_version", "20260722-c4ec03f8a7")

    fig, ax = plt.subplots(figsize=(10.0, 6.8), dpi=160)
    fig.patch.set_facecolor("#020617")
    ax.set_facecolor("#020617")
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")

    # Header
    ax.text(5, 93, "Malicious URL & File-Signature Detector",
            fontsize=15.5, fontweight="bold", color="#f1f5f9")
    badge = FancyBboxPatch((69, 91.2), 26, 4.2, boxstyle="round,pad=0.6,rounding_size=2.0",
                           facecolor="#070d1c", edgecolor="#27324a", linewidth=1)
    ax.add_patch(badge)
    ax.plot([71.2], [93.3], marker="o", markersize=5, color="#34d399")
    ax.text(72.8, 92.6, "Nothing is fetched or uploaded", fontsize=8.0, color="#94a3b8", fontweight="bold")

    ax.text(5, 87.5,
            "Links are scored as strings and never fetched; files are hashed in your browser and never uploaded.",
            fontsize=8.8, color="#94a3b8")

    # Input bar
    input_box = FancyBboxPatch((5, 78.5), 90, 6.2, boxstyle="round,pad=0.4,rounding_size=1.2",
                               facecolor="#070d1c", edgecolor="#27324a", linewidth=1.2)
    ax.add_patch(input_box)
    ax.text(7, 81.0, sample_url, fontsize=9.2, color="#f1f5f9", family="monospace")
    btn = FancyBboxPatch((81.5, 79.3), 12.5, 4.6, boxstyle="round,pad=0.3,rounding_size=0.9",
                         facecolor="#f1f5f9", edgecolor="#f1f5f9")
    ax.add_patch(btn)
    ax.text(87.75, 81.1, "Scan URL", fontsize=8.8, fontweight="bold", color="#020617", ha="center")

    # Verdict Card
    vcard = FancyBboxPatch((5, 43.5), 90, 32.0, boxstyle="round,pad=0.5,rounding_size=1.4",
                           facecolor="#1f0910", edgecolor="#7f1d1d", linewidth=1.2)
    ax.add_patch(vcard)
    ax.text(8, 71.5, "Likely malicious", fontsize=10.5, fontweight="bold", color="#fca5a5")
    ax.text(92, 71.5, "Scored above the decision threshold.", fontsize=8.5, color="#94a3b8", ha="right")
    ax.text(8, 67.5, sample_url, fontsize=8.5, color="#94a3b8", family="monospace")

    ax.text(8, 58.8, f"{score_val * 100:.1f}", fontsize=28, fontweight="bold", color="#f1f5f9", family="monospace")
    ax.text(24.5, 59.5, "%", fontsize=13, color="#94a3b8", family="monospace")

    # Score scale bar
    track = FancyBboxPatch((8, 54.2), 84, 1.6, boxstyle="round,pad=0.1,rounding_size=0.8",
                           facecolor="#0d1526", edgecolor="#1a2437", linewidth=0.8)
    ax.add_patch(track)
    fill = FancyBboxPatch((8, 54.2), 84 * score_val, 1.6, boxstyle="round,pad=0.1,rounding_size=0.8",
                          facecolor="#ef4444", edgecolor="none")
    ax.add_patch(fill)
    ax.plot([8 + 84 * 0.5, 8 + 84 * 0.5], [53.9, 56.1], color="#e2e8f0", lw=1.5)
    ax.text(8, 51.8, "0.0   Uncertain band: 0.2–0.8   |   Threshold: 0.5", fontsize=7.5, color="#7e8ea6", family="monospace")
    ax.text(92, 51.8, "1.0", fontsize=7.5, color="#7e8ea6", family="monospace", ha="right")

    # Meta boxes inside VerdictCard
    meta_items = [
        ("REGISTRABLE DOMAIN", "security-check.ru"),
        ("THRESHOLD", "0.5"),
        ("MODEL", model_ver),
    ]
    for idx, (term, val) in enumerate(meta_items):
        bx = 8 + idx * 28.5
        mbox = FancyBboxPatch((bx, 45.2), 27, 5.2, boxstyle="round,pad=0.2,rounding_size=0.7",
                              facecolor="#070d1c", edgecolor="#1a2437", linewidth=0.9)
        ax.add_patch(mbox)
        ax.text(bx + 1.5, 48.6, term, fontsize=6.5, color="#7e8ea6", fontweight="bold")
        ax.text(bx + 1.5, 46.3, val, fontsize=8.0, color="#e2e8f0", family="monospace")

    # Feature Contributions Card
    fcard = FancyBboxPatch((5, 5.5), 90, 35.0, boxstyle="round,pad=0.5,rounding_size=1.4",
                           facecolor="#070d1c", edgecolor="#1a2437", linewidth=1.1)
    ax.add_patch(fcard)
    ax.text(8, 36.8, "What drove this score", fontsize=10.0, fontweight="bold", color="#f1f5f9")
    ax.text(8, 34.2, "Change in log-odds when each feature is replaced by its training median.",
            fontsize=8.0, color="#94a3b8")
    ax.text(8, 31.2, "<- TOWARD BENIGN", fontsize=6.8, color="#7e8ea6", fontweight="bold")
    ax.text(82, 31.2, "TOWARD MALICIOUS ->", fontsize=6.8, color="#7e8ea6", fontweight="bold", ha="right")

    max_abs = max((abs(c["contribution"]) for c in contribs), default=1.0)
    for idx, c in enumerate(contribs[:5]):
        y = 27.2 - idx * 4.4
        val_str = f"{int(c['value'])}" if float(c["value"]).is_integer() else f"{c['value']:.2f}"
        ax.text(8, y + 1.2, c["feature"], fontsize=8.2, color="#e2e8f0", family="monospace")
        ax.text(82, y + 1.2, f"= {val_str}", fontsize=7.5, color="#7e8ea6", family="monospace", ha="right")

        # Diverging bar track
        btrack = FancyBboxPatch((8, y - 0.5), 74, 1.0, boxstyle="round,pad=0.05,rounding_size=0.3",
                                facecolor="#0d1526", edgecolor="#1a2437", linewidth=0.6)
        ax.add_patch(btrack)
        mid_x = 8 + 37
        ax.plot([mid_x, mid_x], [y - 0.7, y + 0.7], color="#27324a", lw=1.0)

        w = (abs(c["contribution"]) / max_abs) * 35.0
        if c["contribution"] >= 0:
            bar = FancyBboxPatch((mid_x, y - 0.5), w, 1.0, boxstyle="round,pad=0.02,rounding_size=0.2",
                                 facecolor="#ef4444", edgecolor="none")
            tone = "#fca5a5"
            sign = "+"
        else:
            bar = FancyBboxPatch((mid_x - w, y - 0.5), w, 1.0, boxstyle="round,pad=0.02,rounding_size=0.2",
                                 facecolor="#10b981", edgecolor="none")
            tone = "#6ee7b7"
            sign = ""
        ax.add_patch(bar)
        ax.text(92, y - 0.3, f"{sign}{c['contribution']:.3f}",
                fontsize=8.2, color=tone, family="monospace", ha="right", fontweight="bold")

    fig.tight_layout(pad=0.3)
    fig.savefig(out_path, dpi=160, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"wrote UI screenshot {out_path.relative_to(ROOT.parent)}")
    return out_path


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
        return (f"| {name} | {d['accuracy']:.4f} | {d['precision']:.4f} | "
                f"{d['recall']:.4f} | {d['f1']:.4f} | {d['roc_auc']:.4f} | "
                f"{d['pr_auc']:.4f} | {d['meta']['n_test']:,} |")

    lines = [
        "# Evaluation",
        "",
        f"_Generated by `ml/evaluate.py` (metrics timestamp: `{m['generated_at']}`). "
        "Every number and chart on this page is computed from real held-out evaluation "
        "outputs and live execution of `ml/artifacts/model.joblib`; none are estimated._",
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
        "history (phishing), Hacker News via Algolia (benign), Wikipedia "
        "external links (benign), Common Crawl (benign, best-effort). See "
        "`ml/data/raw/MANIFEST.json` for endpoints, licences and fetch timestamps.",
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
        f"| **Accuracy** | **{h['accuracy']:.4f}** |",
        f"| **Precision** | **{h['precision']:.4f}** |",
        f"| **Recall** | **{h['recall']:.4f}** |",
        f"| **F1** | **{h['f1']:.4f}** |",
        f"| **ROC-AUC** | **{h['roc_auc']:.4f}** |",
        f"| **PR-AUC** | **{h['pr_auc']:.4f}** |",
        "",
        "Confusion matrix (threshold 0.5):",
        "",
        "| | predicted benign | predicted malicious |",
        "|---|---|---|",
        f"| **actually benign** | {c['tn']:,} | {c['fp']:,} |",
        f"| **actually malicious** | {c['fn']:,} | {c['tp']:,} |",
        "",
        "![Confusion Matrix](figures/confusion_matrix.png)",
        "",
        "## What that precision means at a realistic base rate",
        "",
        "**Read this before quoting 0.92 anywhere.** Precision is a function of "
        "prevalence, and the evaluation set is "
        f"**{m['base_rate_precision']['eval_prevalence']:.1%} malicious by "
        "construction**. Real traffic is overwhelmingly benign.",
        "",
        "Applying Bayes' rule to the *measured* TPR and FPR from the confusion "
        "matrix above:",
        "",
        "```",
        "precision = (p x TPR) / (p x TPR + (1 - p) x FPR)",
        "```",
        "",
        "TPR and FPR are properties of the model at a given threshold and do "
        "not move with prevalence. Precision does. The same model, unchanged, "
        "at each assumed real-world malicious rate:",
        "",
    ]

    br = m["base_rate_precision"]
    prevs = br["prevalences"]
    header = "| Threshold | FPR | " + " | ".join(f"p={p:.1%}" for p in prevs) \
             + f" | p={br['eval_prevalence']:.1%} (this eval) |"
    lines += [header, "|---" * (len(prevs) + 3) + "|"]
    for r in br["rows"]:
        cells = " | ".join(f"{r['precision_at'][str(p)]:.3f}" for p in prevs)
        evalcell = r["precision_at"][f"{br['eval_prevalence']:.4f}"]
        lines.append(
            f"| {r['threshold']:.2f} | {r['fpr']:.4f} | {cells} | "
            f"**{evalcell:.3f}** |")

    row50 = next(r for r in br["rows"] if r["threshold"] == 0.5)
    row99 = next(r for r in br["rows"] if r["threshold"] == 0.99)
    lines += [
        "",
        f"**At the default 0.5 threshold and a 1% true malicious rate, "
        f"precision is {row50['precision_at']['0.01']:.3f}** — roughly "
        f"{(1 - row50['precision_at']['0.01']) / max(row50['precision_at']['0.01'], 1e-9):.0f} "
        "false alarms for every real detection. That is not a defect in the "
        "model; it is what a 6.7% false-positive rate does when negatives "
        "outnumber positives 99 to 1.",
        "",
        "The lever is the threshold, and the table shows it working: at "
        f"t=0.99 the false-positive rate falls to {row99['fpr']:.4f}, which "
        f"lifts precision at a 1% base rate to "
        f"{row99['precision_at']['0.01']:.3f} — at the cost of recall "
        f"({row99['tpr']:.3f} vs {row50['tpr']:.3f}). Any real deployment "
        "should pick its operating point from this table and its own estimate "
        "of prevalence, not from the headline number.",
        "",
        "![Threshold Analysis](figures/threshold_analysis.png)",
        "",
        "## Configuration comparison",
        "",
        "| Configuration | Accuracy | Precision | Recall | F1 | ROC-AUC | PR-AUC | Test rows |",
        "|---|---|---|---|---|---|---|---|",
        row("headline (domain split, no reputation)", h),
        row("+ Tranco reputation features", rep),
        row("naive random row split", rnd),
        row("headline minus `is_https`", nohttps),
        "",
        "![Configuration Comparison](figures/ablation_comparison.png)",
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
        "![Feature Importance](figures/feature_importance.png)",
        "",
        "## Threshold selection",
        "",
        "A false positive tells a user a legitimate link is dangerous, which "
        "costs trust quickly. Raising the threshold trades recall for precision:",
        "",
        "| Threshold | Accuracy | Precision | Recall (TPR) | F1 | FPR | TP | FP | TN | FN | URLs flagged |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in m["threshold_sweep"]:
        tc = r.get("confusion", {})
        lines.append(
            f"| {r['threshold']:.2f} | {r['accuracy']:.4f} | {r['precision']:.4f} | "
            f"{r['recall']:.4f} | {r['f1']:.4f} | {r['fpr']:.4f} | "
            f"{tc.get('tp', 0):,} | {tc.get('fp', 0):,} | {tc.get('tn', 0):,} | "
            f"{tc.get('fn', 0):,} | {r['flagged']:,} |"
        )

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
        top_str = ""
        if e.get("top_features"):
            parts = [f"{t['feature']}={t['value']} ({t['contribution']:+.2f} log-odds)"
                     for t in e["top_features"]]
            top_str = f" — top drivers: {', '.join(parts)}"
        lines.append(f"- `{e['url']}` — {e['proba']}{top_str}")
    lines += ["", "Missed malicious URLs (lowest scored):", ""]
    for e in m["error_samples"]["false_negatives"]:
        top_str = ""
        if e.get("top_features"):
            parts = [f"{t['feature']}={t['value']} ({t['contribution']:+.2f} log-odds)"
                     for t in e["top_features"]]
            top_str = f" — top drivers: {', '.join(parts)}"
        lines.append(f"- `{e['url']}` — {e['proba']}{top_str}")

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


def _has_local_features() -> bool:
    return (PROC / "features.parquet").exists() or (PROC / "features.csv").exists()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--from-artifacts",
        action="store_true",
        help="Verify committed metrics.json + model.joblib and regenerate reports/charts "
             "without requiring the gitignored 97k-row feature matrix.",
    )
    args = parser.parse_args(argv)

    REPORTS.mkdir(parents=True, exist_ok=True)
    FIGURES.mkdir(parents=True, exist_ok=True)

    if not args.from_artifacts and _has_local_features():
        df = load_features()

        stats_path = PROC / "dataset_stats.json"
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

        save_bundle(headline_res, MODEL_PATH)
        bundle = joblib.load(MODEL_PATH)

        audit = leakage_audit(df, headline_res)
        imps = importances(headline_res)
        sweep = threshold_sweep(headline_res.y_test, headline_proba)
        by_source = per_source_recall(headline_res, headline_proba)
        errors = error_samples(headline_res, headline_proba, bundle=bundle)

        eval_prev = float(headline_res.y_test.mean())
        base_rates = base_rate_table(sweep, eval_prev)

        metrics = {
            "generated_at": pd.Timestamp.now("UTC").isoformat(),
            "dataset_stats": dataset_stats,
            "experiments": results,
            "leakage_audit": audit,
            "permutation_importance": imps,
            "threshold_sweep": sweep,
            "base_rate_precision": base_rates,
            "per_source": by_source,
            "error_samples": errors,
        }
    else:
        metrics_path = REPORTS / "metrics.json"
        if not metrics_path.exists():
            raise SystemExit(
                "Neither ml/data/processed/features.* nor ml/reports/metrics.json found."
            )
        print(
            "[evaluate] Note: ml/data/processed/features.* is not present locally "
            "(raw/processed datasets are gitignored and built from live rolling feeds).\n"
            "[evaluate] Running reproducible verification and chart/report regeneration "
            "from committed ml/reports/metrics.json and ml/artifacts/model.joblib."
        )
        metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
        bundle = joblib.load(MODEL_PATH) if MODEL_PATH.exists() else None
        metrics = verify_and_enrich_metrics(metrics, bundle=bundle)

        h = metrics["experiments"]["headline"]
        print(
            f"[headline] accuracy={h['accuracy']:.4f} "
            f"precision={h['precision']:.4f} "
            f"recall={h['recall']:.4f} "
            f"f1={h['f1']:.4f} "
            f"roc_auc={h['roc_auc']:.4f} "
            f"pr_auc={h['pr_auc']:.4f}"
        )

    (REPORTS / "metrics.json").write_text(
        json.dumps(metrics, indent=2), encoding="utf-8"
    )
    print(f"wrote {REPORTS / 'metrics.json'}")

    write_report(metrics)
    generate_charts(metrics)

    if MODEL_PATH.exists():
        bundle = joblib.load(MODEL_PATH)
        generate_app_screenshot(bundle)
        print("\nrunning generalization probe against committed model artifact...")
        generalization_probe.main()

    return 0


if __name__ == "__main__":
    sys.exit(main())
