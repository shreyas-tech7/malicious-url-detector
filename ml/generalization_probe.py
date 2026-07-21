"""Score hand-written URLs that appear in NO training source.

Why this exists
---------------
The held-out set in EVALUATION.md is drawn from the same feeds as the training
data. It answers "does the model generalise to unseen domains?" but not "does it
generalise to parts of the web my feeds never sampled?"

Those are different questions, and the second one caught a real defect. With
Hacker News as the only benign source, the model scored
`github.com/python/cpython/blob/main/Lib/json/decoder.py` at 0.97 and an
ordinary restaurant's `/menu/starters.php` at 0.955 — while reporting 94%
precision on its own test set.

Every URL below is written by hand. The benign ones are deliberately chosen from
shapes the training feeds under-represent: file paths in code hosts, old-web
`.asp`/`.htm`/`.php` pages, small businesses, non-English sites, plain http.
The malicious ones are constructed to look like real campaigns without being
copied from any feed.

This is a small, non-random sample. It cannot produce a precision estimate with
meaningful error bars, and it is NOT the headline metric — it is a smoke test
for distribution shift. Treat a regression here as a signal to look, not as a
measurement.

    python ml/generalization_probe.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))

from features import extract_features  # noqa: E402

ROOT = Path(__file__).resolve().parent
MODEL_PATH = ROOT / "artifacts" / "model.joblib"
REPORTS = ROOT / "reports"

# --------------------------------------------------------------------------
BENIGN: dict[str, list[str]] = {
    "code hosting (file paths with extensions)": [
        "https://github.com/scikit-learn/scikit-learn/blob/main/README.rst",
        "https://github.com/python/cpython/blob/main/Lib/json/decoder.py",
        "https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt",
        "https://gitlab.com/gitlab-org/gitlab/-/blob/master/README.md",
        "https://bitbucket.org/someteam/somerepo/src/master/setup.cfg",
    ],
    "documentation": [
        "https://docs.python.org/3/library/urllib.parse.html",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type",
        "https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.HistGradientBoostingClassifier.html",
        "https://nginx.org/en/docs/http/ngx_http_ssl_module.html",
    ],
    "news and reference": [
        "https://www.bbc.co.uk/news/world-us-canada-68123456",
        "https://www.nytimes.com/2026/07/21/technology/some-article.html",
        "https://en.wikipedia.org/wiki/Shannon_entropy",
        "https://stackoverflow.com/questions/4172131/what-is-shannon-entropy",
        "https://arxiv.org/abs/2301.00001",
    ],
    "old web (.asp/.htm/.php/.jsp, query strings)": [
        "https://www.doctrine.usmc.mil/aspweb/historical.asp",
        "http://www.vedamsbooks.com/no24331.htm",
        "https://www.tandoori-palace.co.uk/menu/starters.php",
        "http://www.parish-council.gov.uk/minutes/2019/march.php?id=44",
        "https://library.university.edu/search/results.jsp?query=entropy&page=2",
        "http://www.museum-of-local-history.org/exhibits/index.php?section=3",
    ],
    "small business and long tail": [
        "https://smallbakery.co.nz/our-menu/gluten-free",
        "https://joes-plumbing-dallas.com/services/emergency-repair",
        "http://www.dorfmetzgerei-mueller.de/produkte/wurstwaren.html",
        "https://clinicadental-sanchez.es/tratamientos/implantes",
        "https://www.ryokan-yamamoto.jp/rooms/standard.html",
    ],
    "apps with opaque paths and query strings": [
        "https://www.amazon.com/dp/B08N5WRWNW?ref_=ast_sto_dp",
        "https://drive.google.com/file/d/1a2b3c4d5e6f/view?usp=sharing",
        "https://open.spotify.com/track/4cOdK2wGLETKBW3PvgPWqT",
        "https://www.linkedin.com/in/some-person-12345678/",
        "https://www.reddit.com/r/programming/comments/abc123/some_post_title/",
    ],
}

MALICIOUS: dict[str, list[str]] = {
    "brand impersonation in subdomain/path": [
        "http://paypal.com.security-check.ru/login/verify/account.php",
        "http://appleid.apple.com.verify-account.tk/signin",
        "https://secure-microsoft-login.account-verify.cf/oauth/confirm",
        "http://netflix-billing-update.com/account/payment/verify.php",
    ],
    "typosquatting / homograph": [
        "https://paypa1.com/login/signin",
        "http://xn--pypal-4ve.com/signin/update-billing",
        "https://arnazon-security.com/account/verify",
        "http://g00gle-docs-share.com/document/view",
    ],
    "raw IP hosts and malware payload paths": [
        "http://192.168.14.99:8080/bins/mirai.arm7",
        "http://45.132.11.8/wp-content/uploads/2024/inv.php?id=8823",
        "http://185.220.101.44:4433/dl/payload.exe",
        "http://91.207.174.9/bin.sh",
    ],
    "credential harvesting shapes": [
        "https://secure-appleid-verify.tk/confirm?session=abc123",
        "http://account-suspended-verify-now.ml/unlock/login.php",
        "https://webmail-secure-login.gq/owa/auth/logon.aspx?replaceCurrent=1",
    ],
}


def load_bundle() -> dict:
    if not MODEL_PATH.exists():
        raise SystemExit("no model artifact — run ml/evaluate.py first")
    return joblib.load(MODEL_PATH)


def vectorise(bundle: dict, url: str) -> np.ndarray:
    feats = extract_features(
        url, include_reputation=bundle.get("include_reputation", False))
    vocabs = bundle.get("vocabs") or {}
    values = []
    for col in bundle["columns"]:
        if col in vocabs:
            v = vocabs[col]
            values.append(float(v.get(str(feats.get(col, "")),
                                      v.get("<other>", 0))))
        else:
            values.append(float(feats.get(col, 0.0)))
    return np.asarray(values, dtype=np.float64)


def score_all(bundle: dict, groups: dict[str, list[str]]) -> dict:
    out = {}
    for name, urls in groups.items():
        X = np.vstack([vectorise(bundle, u) for u in urls])
        probs = bundle["model"].predict_proba(X)[:, 1]
        out[name] = [{"url": u, "score": float(p)} for u, p in zip(urls, probs)]
    return out


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    bundle = load_bundle()
    threshold = 0.5

    ben = score_all(bundle, BENIGN)
    mal = score_all(bundle, MALICIOUS)

    n_ben = sum(len(v) for v in ben.values())
    n_mal = sum(len(v) for v in mal.values())
    fp = sum(1 for v in ben.values() for r in v if r["score"] >= threshold)
    fn = sum(1 for v in mal.values() for r in v if r["score"] < threshold)

    print(f"model_version: {bundle.get('model_version')}")
    print(f"\nfalse positives: {fp}/{n_ben} = {fp/n_ben:.1%}")
    print(f"false negatives: {fn}/{n_mal} = {fn/n_mal:.1%}")

    lines = [
        "# Generalisation probe",
        "",
        "_Generated by `ml/generalization_probe.py`. Hand-written URLs that "
        "appear in **no** training source._",
        "",
        f"Model version: `{bundle.get('model_version')}`",
        "",
        "## Why this exists",
        "",
        "The held-out set in EVALUATION.md is drawn from the same feeds as the "
        "training data, so it measures generalisation to unseen *domains*, not "
        "to unseen *parts of the web*. This probe covers shapes the feeds "
        "under-represent: code-host file paths, old-web `.asp`/`.htm`/`.php` "
        "pages, small businesses, non-English sites and plain http.",
        "",
        "It is a small, non-random sample. It is a smoke test for distribution "
        "shift, **not** a precision estimate — the headline metrics remain the "
        "ones in EVALUATION.md.",
        "",
        "## Result",
        "",
        "| | |",
        "|---|---|",
        f"| Benign URLs probed | {n_ben} |",
        f"| ...flagged malicious (false positives) | **{fp} ({fp/n_ben:.1%})** |",
        f"| Malicious URLs probed | {n_mal} |",
        f"| ...missed (false negatives) | **{fn} ({fn/n_mal:.1%})** |",
        f"| Threshold | {threshold} |",
        "",
        "## Benign URLs by category",
        "",
    ]

    for name, results in ben.items():
        flagged = sum(1 for r in results if r["score"] >= threshold)
        lines += [f"### {name} — {flagged}/{len(results)} flagged", "",
                  "| Score | Verdict | URL |", "|---|---|---|"]
        for r in sorted(results, key=lambda d: -d["score"]):
            verdict = "**FALSE POSITIVE**" if r["score"] >= threshold else "ok"
            lines.append(f"| {r['score']:.3f} | {verdict} | `{r['url'][:88]}` |")
        lines.append("")

    lines += ["## Malicious URLs by category", ""]
    for name, results in mal.items():
        missed = sum(1 for r in results if r["score"] < threshold)
        lines += [f"### {name} — {missed}/{len(results)} missed", "",
                  "| Score | Verdict | URL |", "|---|---|---|"]
        for r in sorted(results, key=lambda d: d["score"]):
            verdict = "**MISSED**" if r["score"] < threshold else "caught"
            lines.append(f"| {r['score']:.3f} | {verdict} | `{r['url'][:88]}` |")
        lines.append("")

    (REPORTS / "GENERALIZATION_PROBE.md").write_text(
        "\n".join(lines), encoding="utf-8")
    (REPORTS / "generalization_probe.json").write_text(
        json.dumps({"model_version": bundle.get("model_version"),
                    "threshold": threshold,
                    "false_positive_rate": fp / n_ben,
                    "false_negative_rate": fn / n_mal,
                    "benign": ben, "malicious": mal}, indent=2),
        encoding="utf-8")
    print(f"\nwrote {REPORTS / 'GENERALIZATION_PROBE.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
