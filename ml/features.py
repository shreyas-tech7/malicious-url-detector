"""Shared URL feature extraction — used at BOTH training and inference time.

This module is the single source of truth for how a URL becomes a feature
vector. Training imports it; the serverless inference function imports the same
file. If feature logic ever diverged between the two, the model would silently
score garbage in production (train/serve skew), so there is deliberately no
second implementation anywhere in this repo.

Dependencies are kept to the standard library plus `tldextract`, because this
module ships inside the serverless bundle.

A note on the reputation features
---------------------------------
`in_tranco` / `tranco_tier` are implemented because the spec calls for a
reputation signal, but they are **ablatable via `include_reputation=False`**,
and the honest headline metrics are the ones measured with them OFF.

Reason: the benign half of the training set is, by construction, sampled from
Tranco-ranked domains. So "is this domain in Tranco" is very nearly a restatement
of the label — not a learned signal. Leaving it on would inflate precision while
reducing the model to a domain whitelist that fails on the first benign site
outside the top 1M. evaluate.py trains both configurations and reports the gap.
"""

from __future__ import annotations

import csv
import gzip
import math
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit, unquote

import tldextract

# Use tldextract's bundled public-suffix snapshot rather than fetching the live
# list. A cold-starting serverless function must not make a network call just to
# parse a hostname, and a feature that changes when a remote file changes is not
# reproducible.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

# --------------------------------------------------------------------------
# Reference data
# --------------------------------------------------------------------------

# Brands most frequently impersonated in phishing. Used for a typosquatting
# edit-distance signal. Kept deliberately small and curated — a huge list would
# mostly add noise and cost latency (it is an O(len(BRANDS)) scan per URL).
BRANDS = (
    "paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook",
    "instagram", "whatsapp", "linkedin", "twitter", "outlook", "office365",
    "dropbox", "adobe", "chase", "wellsfargo", "bankofamerica", "citibank",
    "hsbc", "santander", "barclays", "coinbase", "binance", "metamask",
    "steam", "roblox", "discord", "spotify", "docusign", "dhl", "fedex",
    "ups", "usps", "irs", "hmrc", "netflix", "icloud", "gmail", "yahoo",
)

# Known URL shorteners — hide the true destination, a weak but real signal.
SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bl.ink", "lnkd.in", "shorte.st", "cutt.ly", "rebrand.ly",
    "tiny.cc", "rb.gy", "shorturl.at", "t.ly", "s.id", "clck.ru", "u.to",
    "qr.ae", "v.gd", "x.co", "mcaf.ee", "db.tt", "short.io", "1url.com",
})

# Terms disproportionately present in credential-harvesting URLs. Treated as
# weak evidence the model may weigh, never as a hard rule.
PHISH_KEYWORDS = (
    "login", "signin", "verify", "secure", "account", "confirm", "update",
    "banking", "password", "credential", "auth", "wallet", "recover",
    "unlock", "suspend", "billing", "invoice", "payment", "webscr", "session",
)

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_HEX_IPV4_RE = re.compile(r"^0x[0-9a-f]+$", re.I)
_SPECIAL_RE = re.compile(r"[^A-Za-z0-9]")


# --------------------------------------------------------------------------
# Primitives
# --------------------------------------------------------------------------
def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character.

    High entropy in a hostname suggests algorithmically generated domains
    (DGA) or random-looking campaign subdomains.
    """
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def levenshtein(a: str, b: str, cap: int = 6) -> int:
    """Edit distance with early exit once the distance exceeds `cap`.

    Only small distances matter for typosquatting ("paypa1" vs "paypal"), so
    bailing out early keeps this cheap inside a per-request hot path.
    """
    if a == b:
        return 0
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(
                prev[j] + 1,        # deletion
                cur[j - 1] + 1,     # insertion
                prev[j - 1] + (ca != cb),  # substitution
            ))
        if min(cur) > cap:
            return cap + 1
        prev = cur
    return prev[-1]


# --------------------------------------------------------------------------
# Reputation index
# --------------------------------------------------------------------------
class ReputationIndex:
    """Maps a registrable domain to a Tranco rank tier.

    Tiers are coarse on purpose — exact rank is noisy between list revisions,
    while "is this a top-1k site or a nobody" is stable.

        4 = rank <= 1_000
        3 = rank <= 10_000
        2 = rank <= 100_000
        1 = present but ranked worse than 100k
        0 = absent from the list entirely
    """

    def __init__(self, ranks: dict[str, int] | None = None):
        self._ranks: dict[str, int] = ranks or {}

    def __len__(self) -> int:
        return len(self._ranks)

    @classmethod
    def from_tranco_csv(cls, path: Path, limit: int | None = None):
        ranks: dict[str, int] = {}
        with Path(path).open(encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                rk = int(row["rank"])
                if limit and rk > limit:
                    break
                ranks[row["domain"].lower()] = rk
        return cls(ranks)

    @classmethod
    def from_compact(cls, path: Path):
        """Load the gzipped `rank,domain` file shipped with the model."""
        ranks: dict[str, int] = {}
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            for line in fh:
                rank, _, domain = line.partition(",")
                if domain:
                    ranks[domain.strip()] = int(rank)
        return cls(ranks)

    def write_compact(self, path: Path, limit: int = 100_000) -> int:
        """Write the top `limit` domains for shipping in the deploy bundle.

        The full 1M list is too large and too slow to load on a serverless cold
        start; 100k covers the overwhelming majority of real benign traffic.
        """
        rows = sorted(
            ((r, d) for d, r in self._ranks.items() if r <= limit),
            key=lambda t: t[0],
        )
        with gzip.open(path, "wt", encoding="utf-8", newline="") as fh:
            for rank, domain in rows:
                fh.write(f"{rank},{domain}\n")
        return len(rows)

    def tier(self, registrable_domain: str) -> int:
        rank = self._ranks.get(registrable_domain.lower())
        if rank is None:
            return 0
        if rank <= 1_000:
            return 4
        if rank <= 10_000:
            return 3
        if rank <= 100_000:
            return 2
        return 1


_EMPTY_REPUTATION = ReputationIndex()


# --------------------------------------------------------------------------
# Feature extraction
# --------------------------------------------------------------------------

#: Numeric features, in a fixed order. The model bundle stores this list so a
#: mismatch between a saved model and this module fails loudly instead of
#: silently reordering columns.
NUMERIC_FEATURES = (
    # lexical
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "url_entropy",
    "hostname_entropy",
    "digit_ratio",
    "special_char_ratio",
    "subdomain_count",
    "path_depth",
    "num_query_params",
    "longest_token_length",
    # structural
    "is_https",
    "is_ip_host",
    "has_at_symbol",
    "has_port",
    "is_shortener",
    "has_punycode",
    "has_non_ascii",
    "hyphen_count",
    "double_slash_in_path",
    "has_hex_encoding",
    # typosquatting
    "min_brand_distance",
    "brand_outside_domain",
    # keywords
    "keyword_count",
    "keyword_in_hostname",
)

#: Reputation features, split out so they can be ablated as a group.
REPUTATION_FEATURES = ("in_tranco", "tranco_tier")

#: Categorical features, passed to HistGradientBoostingClassifier's native
#: categorical support via integer codes.
CATEGORICAL_FEATURES = ("tld",)


def feature_names(include_reputation: bool = True) -> list[str]:
    names = list(NUMERIC_FEATURES)
    if include_reputation:
        names += list(REPUTATION_FEATURES)
    names += list(CATEGORICAL_FEATURES)
    return names


def extract_features(
    url: str,
    reputation: ReputationIndex | None = None,
    include_reputation: bool = True,
) -> dict[str, float | str]:
    """Turn one URL string into a feature dict.

    Pure string analysis. This function never performs a network request and
    never dereferences the URL — see the SSRF note in README/Scope.
    """
    raw = (url or "").strip()

    # Treat a scheme-less input as http:// so urlsplit finds the host rather
    # than parsing the whole thing as a path.
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", raw):
        parse_target = "http://" + raw
    else:
        parse_target = raw

    try:
        parts = urlsplit(parse_target)
        hostname = (parts.hostname or "").lower()
        path = parts.path or ""
        query = parts.query or ""
        port = parts.port
    except ValueError:
        # Malformed input (bad port, illegal IPv6 literal, ...). Degrade to
        # whole-string lexical features rather than raising — the caller is a
        # public endpoint and must not 500 on hostile input.
        hostname, path, query, port = "", raw, "", None
        parts = None

    ext = _EXTRACT(hostname) if hostname else None
    registrable = ""
    subdomain = ""
    tld = ""
    if ext:
        tld = (ext.suffix or "").lower()
        subdomain = (ext.subdomain or "").lower()
        registrable = ".".join(p for p in (ext.domain, ext.suffix) if p).lower()

    lower_url = raw.lower()
    decoded = unquote(lower_url)

    # --- lexical ---------------------------------------------------------
    digits = sum(c.isdigit() for c in raw)
    specials = len(_SPECIAL_RE.findall(raw))
    n = max(len(raw), 1)

    tokens = [t for t in re.split(r"[^A-Za-z0-9]+", raw) if t]
    longest_token = max((len(t) for t in tokens), default=0)

    # --- structural ------------------------------------------------------
    is_ip = bool(_IPV4_RE.match(hostname) or _HEX_IPV4_RE.match(hostname)
                 or (hostname.startswith("[") and hostname.endswith("]")))

    # Punycode marks an internationalised domain, the standard vehicle for
    # homograph attacks (аpple.com with a Cyrillic 'а').
    has_puny = "xn--" in hostname
    has_non_ascii = any(ord(c) > 127 for c in raw)

    # `//` inside the path is a classic open-redirect / filter-evasion trick.
    double_slash = "//" in path

    # --- typosquatting ---------------------------------------------------
    # Compare the *registrable domain's* label against known brands. A small
    # non-zero distance means "looks almost like PayPal but isn't".
    core = ext.domain.lower() if ext and ext.domain else hostname
    min_dist = 99
    for brand in BRANDS:
        d = levenshtein(core, brand)
        if d < min_dist:
            min_dist = d
            if min_dist == 0:
                break
    if min_dist > 6:
        min_dist = 6  # clamp; beyond this the exact value carries no signal

    # A brand name appearing in the subdomain or path but NOT owning the
    # registrable domain — e.g. paypal.com.security-check.ru/login — is one of
    # the strongest single phishing indicators there is.
    brand_outside = 0
    if registrable:
        owns_brand = any(b in registrable.split(".")[0] for b in BRANDS)
        elsewhere = any(b in subdomain for b in BRANDS) or \
                    any(b in decoded.split(registrable)[-1] for b in BRANDS)
        brand_outside = int(elsewhere and not owns_brand)

    # --- keywords --------------------------------------------------------
    kw_count = sum(1 for k in PHISH_KEYWORDS if k in decoded)
    kw_host = int(any(k in hostname for k in PHISH_KEYWORDS))

    feats: dict[str, float | str] = {
        "url_length": float(len(raw)),
        "hostname_length": float(len(hostname)),
        "path_length": float(len(path)),
        "query_length": float(len(query)),
        "url_entropy": shannon_entropy(raw),
        "hostname_entropy": shannon_entropy(hostname),
        "digit_ratio": digits / n,
        "special_char_ratio": specials / n,
        "subdomain_count": float(len([s for s in subdomain.split(".") if s])),
        "path_depth": float(len([p for p in path.split("/") if p])),
        "num_query_params": float(len([q for q in query.split("&") if q])),
        "longest_token_length": float(longest_token),

        "is_https": float(parts.scheme == "https" if parts else 0),
        "is_ip_host": float(is_ip),
        "has_at_symbol": float("@" in raw),
        "has_port": float(port is not None),
        "is_shortener": float(registrable in SHORTENERS),
        "has_punycode": float(has_puny),
        "has_non_ascii": float(has_non_ascii),
        "hyphen_count": float(hostname.count("-")),
        "double_slash_in_path": float(double_slash),
        "has_hex_encoding": float("%" in raw),

        "min_brand_distance": float(min_dist),
        "brand_outside_domain": float(brand_outside),

        "keyword_count": float(kw_count),
        "keyword_in_hostname": float(kw_host),

        "tld": tld or "<none>",
    }

    if include_reputation:
        rep = reputation or _EMPTY_REPUTATION
        tier = rep.tier(registrable) if registrable else 0
        feats["in_tranco"] = float(tier > 0)
        feats["tranco_tier"] = float(tier)

    return feats


def registrable_domain(url: str) -> str:
    """eTLD+1 for a URL — the grouping key for the leakage-safe split.

    All URLs sharing a registrable domain must land on the same side of the
    train/test split, otherwise near-duplicate URLs from one campaign leak
    across it and inflate the reported metrics.
    """
    raw = (url or "").strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", raw):
        raw = "http://" + raw
    try:
        host = urlsplit(raw).hostname or ""
    except ValueError:
        return ""
    if _IPV4_RE.match(host):
        return host  # group raw-IP hosts by the IP itself
    ext = _EXTRACT(host)
    return ".".join(p for p in (ext.domain, ext.suffix) if p).lower()
