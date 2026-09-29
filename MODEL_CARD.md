# Model Card — Malicious & Phishing URL Classifier

- **Model version:** `20260722-c4ec03f8a7`
- **Artifact:** `ml/artifacts/model.joblib` (`scikit-learn==1.9.0`, `numpy==2.4.6`)
- **Model type:** Gradient-boosted decision trees (`sklearn.ensemble.HistGradientBoostingClassifier`)
- **Task:** Binary and three-valued (`malicious` / `uncertain` / `benign`) classification of URL strings
- **Evaluation script:** `python ml/evaluate.py` and `python ml/generalization_probe.py`

> **Responsible-Use Notice:** This classifier is a research and defensive engineering demonstration. It scores URL strings statically without fetching page content, resolving DNS, or checking domain registration age. Do not use it as a standalone production security control or blocklist.

---

## 1. Problem Statement

Given a raw URL string submitted to `POST /scan` (or `POST /api/predict`), estimate the probability that the URL distributes malware or hosts a credential-harvesting phishing page.

### Why String-Only Classification
A cloud backend that fetches user-submitted URLs is a Server-Side Request Forgery (SSRF) primitive: an attacker can point it at cloud metadata endpoints (`http://169.254.169.254/latest/meta-data/`) or internal services. To eliminate SSRF by construction, this model never resolves DNS, opens a socket, or fetches HTTP content. Every feature is extracted deterministically from the URL string in `ml/features.py`.

### Decision Boundaries (`binary_verdict` vs. `verdict`)
The API returns both:
1. **`binary_verdict`** (`malicious` if `score >= 0.50`, else `benign`), evaluated across operating thresholds `0.50` to `0.99`.
2. **`verdict`** (three-valued):
   - `benign`: `score < 0.20`
   - `uncertain`: `0.20 <= score < 0.80`
   - `malicious`: `score >= 0.80`

On the held-out set, scores are strongly bimodal (`39.5%` fall below `0.05` and `33.3%` above `0.95`). The `[0.20, 0.80)` interval holds **14.1% of traffic** but **65.9% of all classification errors**; abstaining on that band lowers the error rate on hard verdicts from **7.66% to 3.04%**.

---

## 2. Datasets and Sources

Machine-readable provenance (exact endpoints, fetch timestamps, row counts, and licenses) is committed in [`ml/data/raw/MANIFEST.json`](ml/data/raw/MANIFEST.json) and documented in [`DATA_SOURCES.md`](DATA_SOURCES.md).

| Source | Class | Raw Rows Fetched | License / Terms | Role in Pipeline |
|---|---|---:|---|---|
| [URLhaus (abuse.ch)](https://urlhaus.abuse.ch/) ([bulk CSV](https://urlhaus.abuse.ch/downloads/csv_recent/), [API/terms](https://urlhaus.abuse.ch/api/)) | Malicious (`1`) | 20,524 | CC0 (Public Domain) | Malware distribution URLs (often raw IPs, non-standard ports, binary extensions like `.arm7`, `.exe`, `.sh`). |
| [OpenPhish Community Feed](https://openphish.com/terms.html) ([GitHub feed repo](https://github.com/openphish/public_feed)) | Malicious (`1`) | 184,909 | Non-commercial use with attribution | Credential-harvesting phishing URLs mined across 800 git commits of rolling feed snapshots. |
| [Hacker News Search API (Algolia)](https://hn.algolia.com/api) ([endpoint](https://hn.algolia.com/api/v1/search_by_date)) | Benign (`0`) | 70,285 | Public API | Human-submitted deep URLs with paths and query strings (`86.5%` have non-empty paths). |
| [Wikipedia External Links](https://www.mediawiki.org/wiki/API:Exturlusage) ([MediaWiki API](https://en.wikipedia.org/w/api.php), [terms](https://foundation.wikimedia.org/wiki/Policy:Terms_of_Use)) | Benign (`0`) | 14,325 | CC BY-SA 4.0 / Free API | Long-tail citations (universities, government, small business, non-English domains, `.php`/`.asp`/`.htm`, plain `http`). |
| [Common Crawl CDX Index](https://commoncrawl.org/) ([terms](https://commoncrawl.org/terms-of-use)) | Benign (`0`) | 33 | Open Corpus | Sampled deep URLs for ranked domains; upstream CDX index timed out after the initial 20-domain validation probe. |
| [Tranco Top 1M](https://tranco-list.eu/) ([list N29KW](https://tranco-list.eu/download/N29KW/1000000)) | Reputation | 1,000,000 | Research use (Le Pochat et al., NDSS 2019) | Used for the `+Tranco reputation` ablation (`in_tranco`, `tranco_tier`); **disabled in the shipped model** to prevent label leakage. |

*(Companion file-signature table: `ml/artifacts/known_bad_hashes.csv.gz` contains 119,226 unique SHA-256/MD5 hashes streamed from the [URLhaus Payload Feed](https://urlhaus.abuse.ch/downloads/payloads/) under CC0.)*

### Dataset Construction (`ml/build_dataset.py`)
1. **Structural comparability:** Bare Tranco domains (`bbc.com`) are never used as benign URLs. Pairing bare domains against full malicious URLs (`http://1.2.3.4:8080/bins/mirai.arm7`) lets `path_length > 0` separate the classes trivially (`>99%` precision in validation, collapsing in production). Both classes use full URLs with paths.
2. **Exact URL deduplication:** Sorting by `label` descending and dropping duplicate URL strings reduces raw rows to **290,164 unique URLs** (`205,433` malicious, `84,731` benign) across **82,903 registrable domains**.
3. **Per-domain capping (`max_per_domain = 25`):** Phishing campaigns generate hundreds of near-identical URLs on one host. Capping at 25 URLs per `(registrable_domain, label)` prevents single campaigns from dominating training loss.
4. **Domain-level class balancing:** Registrable domains are balanced equally between classes (`seed = 20260721`), producing the final dataset:
   - **Final rows:** **97,416**
   - **Malicious (`label = 1`):** **46,560** (`47.8%`)
   - **Benign (`label = 0`):** **50,856** (`52.2%`)
   - **Distinct registrable domains (`eTLD+1`):** **52,294** (`79` domains appear in both classes, e.g., shared hosting platforms)

### Note on Dataset Reproducibility
Raw and processed URL datasets (`ml/data/raw/*` and `ml/data/processed/*`) are excluded via `.gitignore` so the repository does not redistribute bulk third-party feeds (such as OpenPhish's non-commercial feed) or store hundreds of megabytes of tabular data in git. In addition, `URLhaus csv_recent`, `OpenPhish public_feed`, Hacker News, and Wikipedia are **live rolling feeds**: running `python ml/data_acquisition.py all` on a later date fetches a newer window of the web and produces different row counts.

To guarantee that anyone cloning the repo can reproduce every metric, table, live prediction, and chart with a single command:
- `ml/reports/metrics.json` records the exact confusion matrices, threshold sweeps, leakage audits, permutation importances, and error samples from the `97,416`-row evaluation run.
- `ml/artifacts/model.joblib` is committed and contains the exact trained `HistGradientBoostingClassifier` (`20260722-c4ec03f8a7`), feature vocabularies, and training medians.
- Running `python ml/evaluate.py` verifies all metrics mathematically from `metrics.json`, runs the live `model.joblib` artifact over the held-out error samples and the 45-URL generalization probe (`ml/generalization_probe.py`), and regenerates `ml/reports/EVALUATION.md`, `ml/reports/GENERALIZATION_PROBE.md`, and all PNG figures in `ml/reports/figures/`.

---

## 3. Features Used (`ml/features.py`)

Both training (`ml/train.py`) and serverless inference (`api/index.py`) import `extract_features()` from `ml/features.py` so train/serve skew cannot occur. Public-suffix parsing uses `tldextract` initialized with `suffix_list_urls=()` and `cache_dir=None` (offline bundled snapshot, zero network or disk writes).

The shipped model uses **28 features** (**26 numeric** + **2 categorical**). Two additional Tranco reputation features are implemented for ablation and disabled in the shipped model.

### Active Feature Set (28 Features)

| # | Feature | Type | Group | Definition | Single-Feature ROC-AUC | Permutation Importance (Drop in PR-AUC) |
|---:|---|---|---|---|---:|---:|
| 1 | `tld` | Categorical (`200 + <other>`) | Categorical | Public suffix (`eTLD`) extracted via `tldextract` (e.g. `com`, `ru`, `tk`, `co.uk`, `<none>`). | — | **0.1440 ± 0.0032** |
| 2 | `path_length` | Numeric (`float`) | Lexical | Character length of the URL path component. | **0.7450** | **0.0522 ± 0.0022** |
| 3 | `digit_ratio` | Numeric (`float`) | Lexical | Fraction of characters in the full URL that are ASCII digits (`0–9`). | 0.6024 | **0.0258 ± 0.0019** |
| 4 | `is_https` | Numeric (`0/1`) | Structural | `1.0` if scheme is `https`, else `0.0`. | 0.6760 | **0.0186 ± 0.0013** |
| 5 | `path_ext` | Categorical (`200 + <other>`) | Categorical | Lowercase alphanumeric file extension (`1–8` chars) of the final path segment (e.g. `php`, `exe`, `arm7`, `py`, `html`, `<none>`). | — | **0.0149 ± 0.0004** |
| 6 | `path_depth` | Numeric (`float`) | Lexical | Number of non-empty `/`-separated segments in the path. | 0.6967 | **0.0076 ± 0.0004** |
| 7 | `subdomain_count` | Numeric (`float`) | Lexical | Number of dot-separated labels in the subdomain prefix before `eTLD+1`. | 0.5296 | **0.0056 ± 0.0004** |
| 8 | `special_char_ratio` | Numeric (`float`) | Lexical | Fraction of non-alphanumeric characters (`[^A-Za-z0-9]`) in the URL. | 0.6232 | **0.0051 ± 0.0007** |
| 9 | `url_entropy` | Numeric (`float`) | Lexical | Shannon entropy (bits/character) of the full URL string. | 0.6237 | **0.0045 ± 0.0008** |
| 10 | `url_length` | Numeric (`float`) | Lexical | Total character length of the trimmed URL string. | 0.7042 | **0.0044 ± 0.0004** |
| 11 | `keyword_count` | Numeric (`float`) | Keyword | Count of credential/phishing keywords (`login`, `signin`, `verify`, `secure`, `account`, `confirm`, `update`, `banking`, `password`, `credential`, `auth`, `wallet`, `recover`, `unlock`, `suspend`, `billing`, `invoice`, `payment`, `webscr`, `session`) present in the URL-decoded string. | 0.5314 | **0.0035 ± 0.0006** |
| 12 | `hostname_entropy` | Numeric (`float`) | Lexical | Shannon entropy (bits/character) of the hostname. | 0.5979 | **0.0034 ± 0.0003** |
| 13 | `hyphen_count` | Numeric (`float`) | Structural | Count of `-` characters inside the hostname. | 0.6092 | **0.0033 ± 0.0001** |
| 14 | `longest_token_length` | Numeric (`float`) | Lexical | Length of the longest contiguous alphanumeric token in the URL. | 0.5705 | **0.0030 ± 0.0001** |
| 15 | `hostname_length` | Numeric (`float`) | Lexical | Character length of the lowercase hostname. | 0.5904 | **0.0029 ± 0.0004** |
| 16 | `brand_outside_domain` | Numeric (`0/1`) | Typosquatting | `1.0` if one of 39 tracked brand names (`paypal`, `apple`, `microsoft`, `google`, `amazon`, `dhl`, etc.) appears in the subdomain or path while the registrable domain does not own that brand. | 0.5035 | **0.0025 ± 0.0003** |
| 17 | `min_brand_distance` | Numeric (`0–6`) | Typosquatting | Minimum Levenshtein edit distance (clamped to `6`) between the registrable domain label and the 39 tracked brands (`0` = exact brand match, `1–2` = lookalike typosquat such as `paypa1`). | 0.5733 | **0.0011 ± 0.0002** |
| 18 | `query_length` | Numeric (`float`) | Lexical | Character length of the query string (after `?`). | 0.5030 | **0.0010 ± 0.0003** |
| 19 | `has_at_symbol` | Numeric (`0/1`) | Structural | `1.0` if `@` appears in the URL (authority userinfo obfuscation such as `http://google.com@evil.com`). | 0.5056 | **0.0009 ± 0.0003** |
| 20 | `num_query_params` | Numeric (`float`) | Lexical | Number of `&`-separated query parameters. | 0.5018 | **0.0003 ± 0.0001** |
| 21 | `has_hex_encoding` | Numeric (`0/1`) | Structural | `1.0` if `%` percent-encoding appears in the URL. | 0.5020 | `< 0.0001` |
| 22 | `has_port` | Numeric (`0/1`) | Structural | `1.0` if an explicit port (`:8080`, `:4433`) is present. | 0.5348 | `< 0.0001` |
| 23 | `has_punycode` | Numeric (`0/1`) | Structural | `1.0` if `xn--` internationalized domain punycode appears in the hostname. | 0.5004 | `< 0.0001` |
| 24 | `is_ip_host` | Numeric (`0/1`) | Structural | `1.0` if the hostname is a raw IPv4, hex IPv4, or bracketed IPv6 literal. | 0.5477 | `0.0000` |
| 25 | `has_non_ascii` | Numeric (`0/1`) | Structural | `1.0` if any character has code point `> 127`. | 0.5001 | `0.0000` |
| 26 | `double_slash_in_path` | Numeric (`0/1`) | Structural | `1.0` if `//` appears inside the URL path (open-redirect indicator). | 0.5003 | `0.0000` |
| 27 | `is_shortener` | Numeric (`0/1`) | Structural | `1.0` if `eTLD+1` is in a curated set of 27 URL shorteners (`bit.ly`, `tinyurl.com`, `t.co`, etc.). | 0.5005 | `0.0000` |
| 28 | `keyword_in_hostname` | Numeric (`0/1`) | Keyword | `1.0` if any phishing keyword appears inside the hostname. | 0.5169 | `0.0000` |

### Ablated Reputation Features (Disabled in Shipped Model)
| Feature | Definition | Single-Feature ROC-AUC | Why Disabled |
|---|---|---:|---|
| `in_tranco` | `1.0` if `eTLD+1` is in the Tranco Top 1M list. | 0.7171 | Benign URLs were sampled from Tranco/HN/Wikipedia domains; keeping `in_tranco` partly restates the label and turns the classifier into a top-1M domain allowlist. |
| `tranco_tier` | Coarse rank tier (`4`: `<=1k`, `3`: `<=10k`, `2`: `<=100k`, `1`: `<=1M`, `0`: unranked). | 0.7183 | Same as above (+0.0073 precision gain in ablation, deliberately rejected). |

![Feature Importance and Single-Feature Separability](ml/reports/figures/feature_importance.png)

---

## 4. Model Type and Training Details (`ml/train.py`)

- **Estimator:** `sklearn.ensemble.HistGradientBoostingClassifier`
- **Hyperparameters:**
  - `max_iter = 400` (fitted all `400` boosting iterations)
  - `learning_rate = 0.08`
  - `class_weight = "balanced"`
  - `early_stopping = True`, `validation_fraction = 0.15`, `n_iter_no_change = 25`
  - `categorical_features`: native categorical partitioning on `tld` and `path_ext`
  - `random_state = 20260721`
- **Leakage-free categorical vocabulary:** `HistGradientBoostingClassifier` caps categorical bins at `255`. For `tld` and `path_ext`, the top `200` most frequent values are learned **strictly on the training split**, and all rarer or unseen values map to code `200` (`"<other>"`).
- **Per-prediction explanations (log-odds occlusion):** The bundle stores `feature_medians` computed over the `77,780` training rows. At inference time (`api/index.py::_explain`), each feature is individually replaced with its training median and re-scored using `model.decision_function()` (raw log-odds margin). Attributing in log-odds rather than probability prevents saturation when predictions are near `0.000` or `1.000`.

---

## 5. Train / Test Split and Leakage Audit

### Domain-Grouped Split (`GroupShuffleSplit` on `eTLD+1`)
Phishing and malware campaigns routinely register or compromise one domain and emit dozens of sibling URLs (`/login/step1.php`, `/login/step2.php`). Under a standard random row split, sibling URLs from the same host land in both train and test, grading the model on memorized hostnames.

Every URL in this pipeline is mapped to its registrable domain (`eTLD+1`, or raw IP address for IP hosts) via `registrable_domain()`, and split with `GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=20260721)`:

| Split | Rows | Registrable Domains (`eTLD+1`) | Malicious Share | Shared Domains | Shared URLs |
|---|---:|---:|---:|---:|---:|
| **Train** | 77,780 | 41,835 | 48.09% | 0 | 0 |
| **Test (Held-Out)** | 19,636 | 10,459 | 46.64% | 0 | 0 |
| **Total** | 97,416 | 52,294 | 47.80% | **0** | **0** |

### Configuration & Split Ablation Study

| Configuration | Split | Accuracy | Precision | Recall | F1 | ROC-AUC | PR-AUC | Test Rows |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| **Headline (shipped)** | Domain (`eTLD+1`) | **0.9234** | **0.9225** | **0.9124** | **0.9174** | **0.9804** | **0.9795** | 19,636 |
| `+ Tranco reputation` | Domain (`eTLD+1`) | 0.9289 | 0.9298 | 0.9168 | 0.9232 | 0.9823 | 0.9815 | 19,636 |
| `Naive random row split` | Random row | 0.9420 | 0.9388 | 0.9381 | 0.9385 | 0.9883 | 0.9875 | 19,449 |
| `Headline minus is_https` | Domain (`eTLD+1`) | 0.9214 | 0.9153 | 0.9162 | 0.9158 | 0.9776 | 0.9765 | 19,636 |

- **Impact of domain grouping:** A naive random row split inflates accuracy by **+1.86 percentage points** (`0.9420` vs `0.9234`), precision by **+1.63 pp** (`0.9388` vs `0.9225`), and recall by **+2.57 pp** (`0.9381` vs `0.9124`). That gap is pure campaign memorization across the split boundary.
- **Impact of dropping `is_https`:** Removing `is_https` changes F1 by only `-0.0016` (`0.9158` vs `0.9174`), showing the tree ensemble relies primarily on lexical, TLD, extension, and structural signals rather than collapsing to an HTTP vs. HTTPS rule.

![Configuration and Split Ablation Comparison](ml/reports/figures/ablation_comparison.png)

---

## 6. Evaluation Results

### Headline Metrics (`n = 19,636` URLs across `10,459` unseen domains, threshold `0.50`)

| Metric | Measured Value | Notes |
|---|---:|---|
| **Accuracy** | **0.9234** (`92.34%`) | `18,132 / 19,636` held-out URLs classified correctly |
| **Precision** | **0.9225** (`92.25%`) | `8,356 / 9,058` flagged URLs are truly malicious (at `46.64%` eval prevalence) |
| **Recall (Sensitivity / TPR)** | **0.9124** (`91.24%`) | `8,356 / 9,158` malicious URLs caught |
| **F1 Score** | **0.9174** (`91.74%`) | Harmonic mean of precision and recall |
| **ROC AUC** | **0.9804** | Area under the Receiver Operating Characteristic curve |
| **PR AUC (Average Precision)** | **0.9795** | Area under the Precision-Recall curve |
| **Specificity (TNR)** | **0.9330** (`93.30%`) | `9,776 / 10,478` benign URLs correctly cleared |
| **False Positive Rate (FPR)** | **0.0670** (`6.70%`) | `702 / 10,478` benign URLs falsely flagged at threshold `0.50` |

### Confusion Matrix (Threshold = `0.50`)

| | Predicted Benign (`0`) | Predicted Malicious (`1`) | Row Total |
|---|---:|---:|---:|
| **Actual Benign (`0`)** | **TN = 9,776** (`93.30%`) | **FP = 702** (`6.70%`) | 10,478 |
| **Actual Malicious (`1`)** | **FN = 802** (`8.76%`) | **TP = 8,356** (`91.24%`) | 9,158 |
| **Column Total** | 10,578 | 9,058 | **19,636** |

![Held-Out Confusion Matrix](ml/reports/figures/confusion_matrix.png)

### Per-Source Performance on the Held-Out Set (Threshold = `0.50`)

| Source | Class | Test URLs (`n`) | Measured Metric | Value |
|---|---|---:|---|---:|
| **URLhaus** | Malicious | 1,200 | Recall (TPR) | **0.9708** (`97.08%`) |
| **OpenPhish** | Malicious | 7,958 | Recall (TPR) | **0.9036** (`90.36%`) |
| **Hacker News** | Benign | 8,259 | False Positive Rate (FPR) | **0.0595** (`5.95%`) |
| **Common Crawl** | Benign | 30 | False Positive Rate (FPR) | **0.0667** (`6.67%`) |
| **Wikipedia** | Benign | 2,189 | False Positive Rate (FPR) | **0.0955** (`9.55%`) |

---

## 7. Threshold Analysis: Catching Threats vs. False Positives

Raising the decision threshold reduces false positives (`FP`) and increases precision, at the cost of missed threats (`FN` / lower recall):

| Threshold | Accuracy | Precision (at 46.6% eval) | Recall (TPR) | F1 Score | False Positive Rate (FPR) | TP | FP | TN | FN | Total Flagged |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **0.50** | **0.9234** | 0.9225 | **0.9124** | **0.9174** | 0.0670 (`6.70%`) | 8,356 | 702 | 9,776 | 802 | 9,058 |
| **0.70** | 0.9174 | 0.9515 | 0.8671 | 0.9073 | 0.0387 (`3.87%`) | 7,941 | 405 | 10,073 | 1,217 | 8,346 |
| **0.80** | 0.9077 | 0.9680 | 0.8295 | 0.8934 | 0.0240 (`2.40%`) | 7,597 | 251 | 10,227 | 1,561 | 7,848 |
| **0.90** | 0.8862 | 0.9851 | 0.7676 | 0.8629 | 0.0101 (`1.01%`) | 7,030 | 106 | 10,372 | 2,128 | 7,136 |
| **0.95** | 0.8609 | 0.9911 | 0.7081 | 0.8261 | 0.0055 (`0.55%`) | 6,485 | 58 | 10,420 | 2,673 | 6,543 |
| **0.99** | 0.7886 | **0.9992** | 0.5472 | 0.7071 | **0.0004** (`0.04%`) | 5,011 | **4** | 10,474 | 4,147 | 5,015 |

### Base-Rate Adjusted Precision (Bayes' Rule)
The held-out test set is **46.64% malicious by construction**, whereas real web traffic is overwhelmingly benign (`0.1%–1%` malicious). While TPR and FPR depend only on the threshold, precision depends on the base rate $p$:

$$\text{Precision}(p) = \frac{p \cdot \text{TPR}}{p \cdot \text{TPR} + (1 - p) \cdot \text{FPR}}$$

| Threshold | FPR | Recall (TPR) | Precision @ `p=0.1%` | Precision @ `p=0.5%` | Precision @ `p=1.0%` | Precision @ `p=5.0%` | Precision @ `p=10.0%` | Precision @ `p=46.6%` (Eval) |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **0.50** | 0.0670 | 0.9124 | 0.013 | 0.064 | **0.121** | 0.418 | 0.602 | **0.922** |
| **0.70** | 0.0387 | 0.8671 | 0.022 | 0.101 | 0.185 | 0.541 | 0.714 | 0.951 |
| **0.80** | 0.0240 | 0.8295 | 0.034 | 0.148 | 0.259 | 0.646 | 0.794 | 0.968 |
| **0.90** | 0.0101 | 0.7676 | 0.071 | 0.276 | 0.434 | 0.800 | 0.894 | 0.985 |
| **0.95** | 0.0055 | 0.7081 | 0.114 | 0.391 | 0.564 | 0.871 | 0.934 | 0.991 |
| **0.99** | 0.0004 | 0.5472 | 0.589 | 0.878 | **0.935** | 0.987 | 0.994 | **0.999** |

**Operating takeaway:**
- At `t = 0.50` and a `1%` real-world malicious base rate, a `6.70%` FPR yields **12.1% precision** (~7 false alarms per real threat).
- At `t = 0.80` (the upper bound of the `uncertain` band where the UI begins issuing hard `malicious` verdicts), false positives drop from `702` to `251` (`FPR = 2.40%`) while retaining `82.95%` recall.
- For automated blocking at a `1%` base rate, raising the threshold to `t = 0.99` reduces false positives to **4 out of 10,478 benign URLs** (`FPR = 0.038%`), achieving **93.5% precision** at `1%` prevalence while still catching **54.7% of malicious URLs**.

![Threshold Analysis and Base-Rate Precision Tradeoff](ml/reports/figures/threshold_analysis.png)

---

## 8. Dedicated False-Positive Analysis

To understand *why* the model makes mistakes, we inspect the highest-confidence false positives from the **19,636-row held-out test set** (`ml/reports/metrics.json`) alongside the **45-URL out-of-distribution generalization probe** (`ml/reports/GENERALIZATION_PROBE.md`), using exact probabilities and log-odds feature occlusion attributions (`_explain`) computed by the shipped model (`20260722-c4ec03f8a7`).

### Failure Mode 1: Substring Collisions in Brand and Keyword Matching
`ml/features.py` checks whether any tracked brand (`BRANDS`) or phishing keyword (`PHISH_KEYWORDS`) is a substring of the URL (`any(b in ...)` / `if k in decoded`). Compound English words that happen to contain a short brand or keyword token trigger high-weight phishing signals on completely benign pages:

1. **`https://jorviksoftware.cc/utilities/rainbowapple`** — **Score: `0.9873`** (Held-out FP)
   - **Top log-odds drivers:** `special_char_ratio = 0.125` (`+2.49` log-odds), `brand_outside_domain = 1.0` (`+2.37` log-odds), `longest_token_length = 14` (`+0.52` log-odds).
   - **Why it failed:** The path segment `rainbowapple` contains the substring `"apple"` (in `BRANDS`), while the registrable domain is `jorviksoftware.cc`. Because `brand_outside_domain` uses substring matching rather than token boundaries, the model sees `"apple"` in a path hosted on a `.cc` country-code TLD—the exact structural signature of an Apple ID phishing page.

2. **`http://members.authorsguild.net/betsyhaynes/`** — **Score: `0.9871`** (Held-out FP)
   - **Top log-odds drivers:** `keyword_count = 1.0` (`+2.59` log-odds), `hostname_entropy = 3.89` (`+2.34` log-odds), `tld = net` (`-3.69` log-odds).
   - **Why it failed:** The domain `authorsguild.net` contains the substring `"auth"`, which is in `PHISH_KEYWORDS`. Combined with plain `http://` (`is_https = 0`), a `members.` subdomain, and high hostname entropy, the false `"auth"` keyword match tips the prediction to `0.987`.

### Failure Mode 2: Plain HTTP (`is_https = 0`) + Abused or Country-Code TLDs
While `95.5%` of benign training URLs use HTTPS, only `~60%` of malicious URLs do. When a legitimate site serves plain `http://` on a TLD that is heavily represented in URLhaus/OpenPhish (`.live`, `.cn`, `.cc`), the combined log-odds push the score near `1.0`:

3. **`http://replicated.live/blog/follow-up`** (**`0.9903`**) & **`http://replicated.live/blog/worktree`** (**`0.9869`**) (Held-out FPs)
   - **Top log-odds drivers:** `is_https = 0.0` (`+4.70` log-odds), `tld = live` (`+1.07` to `+1.17` log-odds), `subdomain_count = 0.0` (`+0.76` log-odds).
   - **Why it failed:** `.live` is disproportionately used by ephemeral phishing domains in OpenPhish, and the link was submitted to Hacker News with an `http://` scheme. The combination of plaintext HTTP and `.live` overwhelms the benign `/blog/...` path shape.

4. **`http://english.peopledaily.com.cn/data/people/zengqinghong.shtml`** — **Score: `0.9968`** (Held-out FP)
   - **Top log-odds drivers:** `is_https = 0.0` (`+1.11` log-odds), multi-part `.com.cn` suffix, and `.shtml` extension (`path_ext = shtml`, mapped to `<other>`).
   - **Why it failed:** Older archival news pages from Wikipedia citations use plain `http://`, deep `/data/people/` directories, and `.shtml` extensions that are rare in modern Hacker News links.

### Failure Mode 3: Extreme Token Lengths, Numeric Fragments, and SaaS Preview Hosts

5. **`http://thingsmygirlfriendandihavearguedabout.com/`** — **Score: `0.9985`** (Held-out FP)
   - **Top log-odds drivers:** `is_https = 0.0` (`+2.11` log-odds), `longest_token_length = 37.0` (`+1.38` log-odds), `tld = com` (`-1.41` log-odds).
   - **Why it failed:** A 37-character unbroken domain label with no hyphens looks statistically identical to concatenated multi-word phishing domains or DGA tokens, compounded by `http://`.

6. **`https://globalresearchspace.com/space#7.65/-16.827/42.731/-35.7/68`** — **Score: `0.9834`** (Held-out FP)
   - **Top log-odds drivers:** `digit_ratio = 0.2727` (`+2.96` log-odds), `subdomain_count = 0.0` (`+1.32` log-odds), `tld = com` (`-2.23` log-odds).
   - **Why it failed:** Map/viewport coordinates in the URL fragment (`#7.65/-16.827/42.731/-35.7/68`) make digits `27.3%` of the entire URL string. High digit density is a primary indicator of IP hosts, hex-encoded payloads, and randomized campaign URLs.

7. **`https://cogniflow-v2.emergent.host/`** — **Score: `0.9938`** (Held-out FP)
   - **Top log-odds drivers:** `hostname_length = 26.0` (`+1.51` log-odds), `digit_ratio = 0.0286` (`+1.04` log-odds), `hostname_entropy = 4.03` (`+0.89` log-odds).
   - **Why it failed:** App-hosting preview subdomains on `.host` with hyphenated version suffixes (`-v2`) share the exact lexical profile of disposable phishing infrastructure.

### Failure Mode 4: Non-English Hyphenated Small-Business Domains (Out-of-Distribution Probe)

8. **`https://clinicadental-sanchez.es/tratamientos/implantes`** (**`0.9104`**) & **`https://www.ryokan-yamamoto.jp/rooms/standard.html`** (**`0.8756`**) (Generalization Probe FPs)
   - **Why they failed:** Both are legitimate small-business URLs with hyphenated domain names (`hyphen_count = 1`), country-code TLDs (`.es`, `.jp`), and multi-segment paths. In string-only classification without domain age or WHOIS/DNS reputation, a hyphenated non-`.com` domain is structurally indistinguishable from a localized phishing domain.

### Failure Mode 5: Borderline `.php` and Code-Hosting File Paths (Caught by the `uncertain` Band)

9. **`https://www.tandoori-palace.co.uk/menu/starters.php`** (**`0.6519`**) & **`https://github.com/python/cpython/blob/main/Lib/json/decoder.py`** (**`0.5629`**) (Generalization Probe Binary FPs at `0.50`, reported as `uncertain` in production)
   - **Why they scored above `0.50`:** Before adding `path_ext` and Wikipedia external links, `decoder.py` scored `0.97` and `starters.php` scored `0.955` because URLhaus is dominated by paths ending in file extensions (`/bins/mirai.arm7`) and OpenPhish is full of `.php` scripts on compromised sites. Adding `path_ext` and Wikipedia citations lowered both into the `[0.20, 0.80)` uncertain band, where the API explicitly abstains (`verdict = "uncertain"`) rather than issuing a false `malicious` call.

### Notable False Negatives (Missed Malicious URLs)
On the held-out set, `802` of `9,158` malicious URLs scored below `0.50` (`8.76%` FNR). Inspecting the lowest-scored false negatives in `ml/reports/metrics.json` reveals a single dominant pattern:
- **`https://ricardo.erhalt24.com/ad_mart-item/lounge-set-in-top-zustand-sofa-2-clubsessel-tullow-fe837cb6`** (`score = 0.000`)
- **`https://dhlexpress.ee/blog/en/post/mission-critical-shipments-how-seven-businesses-found-solutions-that-were-right-for-t`** (`score = 0.001`)
- **`https://promocaodiasdopais.myshopify.com/products/cozinha-suspensa-65cm-escorredor-de-loucas-copos-talheres-organizador-`** (`score = 0.002`)
- **Why they were missed:** Phishing and scam pages hosted on reputable TLDs (`.com`, `.myshopify.com`, `.dev`, `.ee`) using HTTPS and long, natural-language e-commerce or blog slugs (`path_length = 73–99`, `tld = com` contributing `-5.6` to `-7.1` log-odds) look identical to ordinary Hacker News articles from the URL string alone. Catching these requires page content analysis or domain registration telemetry.
