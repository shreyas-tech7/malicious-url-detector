"""Tests for reproducible evaluation, documentation completeness, and secret hygiene."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import joblib
import pytest

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "ml"))

import evaluate  # noqa: E402


def test_metrics_json_is_mathematically_consistent():
    """Verify every recorded confusion matrix, accuracy, precision, recall, F1, and threshold."""
    metrics_path = _ROOT / "ml" / "reports" / "metrics.json"
    assert metrics_path.exists()
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    bundle = joblib.load(_ROOT / "ml" / "artifacts" / "model.joblib")

    verified = evaluate.verify_and_enrich_metrics(metrics, bundle=bundle)
    h = verified["experiments"]["headline"]

    assert h["accuracy"] == pytest.approx(18132 / 19636)
    assert h["precision"] == pytest.approx(8356 / (8356 + 702))
    assert h["recall"] == pytest.approx(8356 / (8356 + 802))
    assert h["roc_auc"] == pytest.approx(0.980384, abs=1e-5)

    # Live model predictions on held-out error samples must match recorded scores.
    for group in ("false_positives", "false_negatives"):
        for sample in verified["error_samples"][group]:
            assert "live_proba" in sample
            assert abs(sample["live_proba"] - sample["proba"]) <= 0.005
            assert isinstance(sample.get("top_features"), list)


def test_evaluation_figures_exist_and_are_non_empty():
    figures_dir = _ROOT / "ml" / "reports" / "figures"
    expected = (
        "confusion_matrix.png",
        "threshold_analysis.png",
        "feature_importance.png",
        "ablation_comparison.png",
    )
    for name in expected:
        p = figures_dir / name
        assert p.exists(), f"missing figure {p}"
        assert p.stat().st_size > 10_000, f"figure {p} looks empty"

    ui_shot = _ROOT / "docs" / "screenshot-url-scan.png"
    assert ui_shot.exists() and ui_shot.stat().st_size > 10_000


def test_required_project_docs_exist():
    for doc in ("MODEL_CARD.md", "README.md", "SECURITY.md", "LICENSE"):
        p = _ROOT / doc
        assert p.exists(), f"missing {doc}"
        assert p.stat().st_size > 500


def test_no_committed_secrets_or_env_files():
    """Ensure no .env files or live credential tokens are tracked in git."""
    tracked = subprocess.check_output(
        ["git", "ls-files"], cwd=_ROOT, text=True
    ).splitlines()

    for rel in tracked:
        name = Path(rel).name
        if name.startswith(".env") and name != ".env.example":
            pytest.fail(f"tracked environment file found in git: {rel}")
        assert not rel.endswith((".pem", ".key", ".p12", ".pfx")), (
            f"tracked key/certificate file found in git: {rel}"
        )

    secret_patterns = [
        re.compile(r"sbp_[a-f0-9]{30,}"),
        re.compile(r"sb_secret_[A-Za-z0-9_\-]{20,}"),
        re.compile(r"ghp_[A-Za-z0-9]{30,}"),
        re.compile(r"github_pat_[A-Za-z0-9_]{30,}"),
        re.compile(r"sk-[A-Za-z0-9]{32,}"),
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ]

    for rel in tracked:
        p = _ROOT / rel
        if not p.is_file() or p.suffix in (".gz", ".joblib", ".ico", ".woff", ".png"):
            continue
        text = p.read_text(encoding="utf-8", errors="ignore")
        for pat in secret_patterns:
            match = pat.search(text)
            assert match is None, f"potential secret matched {pat.pattern} in {rel}"
