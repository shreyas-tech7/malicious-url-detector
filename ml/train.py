"""Train the URL classifier.

Split methodology
-----------------
The split is **grouped by registrable domain (eTLD+1)**: every URL sharing an
eTLD+1 goes entirely into train or entirely into test.

Why grouped rather than random: phishing and malware campaigns emit hundreds of
near-identical URLs on one host. Under a random row-level split, sibling URLs
from the same campaign land on both sides, so the test set is substantially
memorisation rather than generalisation and precision comes out inflated.

Why grouped rather than time-based: a time split is also defensible, but the
timestamps here are not comparable across sources — URLhaus records
`dateadded`, the OpenPhish history gives commit dates, and HN gives submission
dates, all with different lags relative to when a URL actually appeared. Domain
grouping targets the duplication problem directly and does not depend on
cross-source clock alignment. `--split time` is implemented for comparison.

Model
-----
HistGradientBoostingClassifier — gradient boosted, natively handles the
categorical TLD feature and missing values, and is markedly faster than the
classic GradientBoostingClassifier at this row count.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.model_selection import GroupShuffleSplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

from features import (  # noqa: E402
    CATEGORICAL_FEATURES,
    NUMERIC_FEATURES,
    REPUTATION_FEATURES,
    feature_names,
)

ROOT = Path(__file__).resolve().parent
PROC = ROOT / "data" / "processed"
ARTIFACTS = ROOT / "artifacts"

SEED = 20260721

# HistGradientBoostingClassifier requires categorical codes to fit inside
# max_bins (255). There are well over a thousand TLDs, so keep the most common
# and fold the tail into a single "other" bucket.
MAX_TLD_VOCAB = 200


@dataclass
class TrainConfig:
    include_reputation: bool = False
    drop_features: tuple[str, ...] = ()
    split: str = "domain"
    test_size: float = 0.2
    seed: int = SEED
    max_iter: int = 400
    learning_rate: float = 0.08
    name: str = "default"
    notes: str = ""


@dataclass
class TrainResult:
    model: HistGradientBoostingClassifier
    config: TrainConfig
    columns: list[str]
    tld_vocab: dict[str, int]
    X_test: np.ndarray
    y_test: np.ndarray
    test_df: pd.DataFrame
    train_domains: set
    test_domains: set
    meta: dict = field(default_factory=dict)


def load_features() -> pd.DataFrame:
    for name in ("features.parquet", "features.csv"):
        p = PROC / name
        if p.exists():
            df = pd.read_parquet(p) if p.suffix == ".parquet" else pd.read_csv(p)
            print(f"loaded {name}  shape={df.shape}")
            return df
    raise SystemExit("no feature file — run build_dataset.py first")


def make_split(df: pd.DataFrame, cfg: TrainConfig):
    """Return boolean train/test masks."""
    if cfg.split == "domain":
        gss = GroupShuffleSplit(n_splits=1, test_size=cfg.test_size,
                                random_state=cfg.seed)
        tr_idx, te_idx = next(gss.split(df, df.label, groups=df.domain))
        train_mask = np.zeros(len(df), dtype=bool)
        train_mask[tr_idx] = True
        return train_mask, ~train_mask

    if cfg.split == "random":
        # Deliberately available so EVALUATION.md can show what the naive
        # split would have claimed. Not used for headline numbers.
        rng = np.random.default_rng(cfg.seed)
        r = rng.random(len(df))
        train_mask = r >= cfg.test_size
        return train_mask, ~train_mask

    raise ValueError(f"unknown split: {cfg.split}")


def build_matrix(df: pd.DataFrame, cfg: TrainConfig,
                 tld_vocab: dict[str, int] | None = None):
    """Assemble the feature matrix, encoding the categorical TLD column.

    The TLD vocabulary is built from TRAIN ROWS ONLY. Building it over the full
    dataset would let test-set information influence the encoding — a small
    leak, but the entire point of this project is not to have any.
    """
    cols = [c for c in feature_names(include_reputation=cfg.include_reputation)
            if c not in cfg.drop_features]

    numeric = [c for c in cols if c not in CATEGORICAL_FEATURES]
    has_tld = "tld" in cols

    if has_tld and tld_vocab is None:
        counts = df["tld"].value_counts()
        keep = list(counts.index[:MAX_TLD_VOCAB])
        tld_vocab = {t: i for i, t in enumerate(keep)}
        tld_vocab["<other>"] = len(tld_vocab)

    X_num = df[numeric].to_numpy(dtype=np.float64)

    if has_tld:
        other = tld_vocab["<other>"]
        codes = df["tld"].map(lambda t: tld_vocab.get(t, other)).to_numpy()
        X = np.column_stack([X_num, codes.astype(np.float64)])
        columns = numeric + ["tld"]
        cat_mask = np.array([False] * len(numeric) + [True])
    else:
        X = X_num
        columns = numeric
        cat_mask = np.zeros(len(numeric), dtype=bool)

    return X, columns, cat_mask, (tld_vocab or {})


def train(df: pd.DataFrame, cfg: TrainConfig) -> TrainResult:
    train_mask, test_mask = make_split(df, cfg)
    tr, te = df[train_mask], df[test_mask]

    X_tr, columns, cat_mask, tld_vocab = build_matrix(tr, cfg)
    X_te, _, _, _ = build_matrix(te, cfg, tld_vocab=tld_vocab)
    y_tr = tr.label.to_numpy()
    y_te = te.label.to_numpy()

    train_domains = set(tr.domain)
    test_domains = set(te.domain)
    bleed = train_domains & test_domains
    if bleed and cfg.split == "domain":
        raise AssertionError(
            f"domain-grouped split leaked {len(bleed)} domains across the "
            f"boundary — this must never happen")

    print(f"\n[{cfg.name}] train={len(tr):,} test={len(te):,} | "
          f"features={len(columns)} | "
          f"train domains={len(train_domains):,} test domains={len(test_domains):,}")
    print(f"[{cfg.name}] train pos-rate={y_tr.mean():.3f} "
          f"test pos-rate={y_te.mean():.3f}")

    model = HistGradientBoostingClassifier(
        max_iter=cfg.max_iter,
        learning_rate=cfg.learning_rate,
        categorical_features=cat_mask if cat_mask.any() else None,
        class_weight="balanced",   # explicit imbalance handling
        early_stopping=True,
        validation_fraction=0.15,
        n_iter_no_change=25,
        random_state=cfg.seed,
    )
    model.fit(X_tr, y_tr)
    print(f"[{cfg.name}] fitted in {model.n_iter_} boosting iterations")

    return TrainResult(
        model=model, config=cfg, columns=columns, tld_vocab=tld_vocab,
        X_test=X_te, y_test=y_te, test_df=te,
        train_domains=train_domains, test_domains=test_domains,
        meta={"n_train": len(tr), "n_test": len(te),
              "n_train_domains": len(train_domains),
              "n_test_domains": len(test_domains),
              "train_pos_rate": float(y_tr.mean()),
              "test_pos_rate": float(y_te.mean()),
              "n_iter": int(model.n_iter_)},
    )


def save_bundle(res: TrainResult, path: Path) -> Path:
    """Persist everything inference needs to reproduce training exactly."""
    import sklearn

    path.parent.mkdir(parents=True, exist_ok=True)
    bundle = {
        "model": res.model,
        "columns": res.columns,
        "tld_vocab": res.tld_vocab,
        "include_reputation": res.config.include_reputation,
        "drop_features": list(res.config.drop_features),
        "sklearn_version": sklearn.__version__,
        "numpy_version": np.__version__,
        "config": {
            "split": res.config.split,
            "test_size": res.config.test_size,
            "seed": res.config.seed,
            "max_iter": res.config.max_iter,
            "learning_rate": res.config.learning_rate,
        },
        "meta": res.meta,
    }
    joblib.dump(bundle, path, compress=3)
    print(f"saved model bundle -> {path} "
          f"({path.stat().st_size / 1e6:.2f} MB)")
    return path


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--split", default="domain", choices=["domain", "random"])
    p.add_argument("--with-reputation", action="store_true",
                   help="include Tranco features (see DECISIONS.md — off by "
                        "default because they partly encode the label)")
    p.add_argument("--drop", nargs="*", default=[])
    p.add_argument("--out", default=str(ARTIFACTS / "model.joblib"))
    a = p.parse_args()

    df = load_features()
    cfg = TrainConfig(
        include_reputation=a.with_reputation,
        drop_features=tuple(a.drop),
        split=a.split,
        name="headline",
    )
    res = train(df, cfg)

    from sklearn.metrics import classification_report
    proba = res.model.predict_proba(res.X_test)[:, 1]
    print("\n" + classification_report(res.y_test, (proba >= 0.5).astype(int),
                                       target_names=["benign", "malicious"],
                                       digits=4))
    save_bundle(res, Path(a.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
