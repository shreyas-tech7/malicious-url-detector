"""Unit tests for the shared feature extractor.

These use hand-written URLs with known properties rather than samples from the
dataset, so they assert what the features are *supposed* to mean instead of
just pinning current behaviour.
"""

import math

import pytest

from features import (
    BRANDS,
    NUMERIC_FEATURES,
    REPUTATION_FEATURES,
    ReputationIndex,
    extract_features,
    feature_names,
    levenshtein,
    registrable_domain,
    shannon_entropy,
)

# Hand-picked examples. The benign ones are deliberately *deep* URLs with
# paths, query strings and hyphens — not bare domains — because that is what
# the model will actually see in production.
BENIGN = [
    "https://en.wikipedia.org/wiki/Shannon_entropy",
    "https://www.bbc.co.uk/news/world-us-canada-68123456",
    "https://github.com/scikit-learn/scikit-learn/blob/main/README.rst",
    "https://stackoverflow.com/questions/4172131/what-is-shannon-entropy",
    "https://www.nytimes.com/2026/07/21/technology/some-article.html?smid=url-share",
]

MALICIOUS = [
    "http://192.168.14.99:8080/bins/mirai.arm7",
    "http://paypal.com.security-check.ru/login/verify/account.php",
    "https://secure-appleid-verify.com/confirm?session=abc123",
    "http://bit.ly/3xK9mQz",
    "http://xn--pypal-4ve.com/signin/update-billing",
]


# --------------------------------------------------------------------------
# Primitives
# --------------------------------------------------------------------------
def test_entropy_of_empty_and_uniform():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    # Four distinct equiprobable symbols = exactly 2 bits/char.
    assert shannon_entropy("abcd") == pytest.approx(2.0)


def test_entropy_ranks_random_above_repetitive():
    assert shannon_entropy("x7f2q9zk3v") > shannon_entropy("aaaaaaaaaa")


def test_levenshtein_basics():
    assert levenshtein("paypal", "paypal") == 0
    assert levenshtein("paypa1", "paypal") == 1
    assert levenshtein("payypal", "paypal") == 1
    # Early-exit cap: wildly different strings return cap+1, not the true cost.
    assert levenshtein("a" * 40, "paypal") == 7


# --------------------------------------------------------------------------
# Structural signals
# --------------------------------------------------------------------------
def test_ip_host_detected():
    f = extract_features("http://192.168.14.99:8080/bins/mirai.arm7")
    assert f["is_ip_host"] == 1.0
    assert f["has_port"] == 1.0
    assert f["is_https"] == 0.0


def test_normal_domain_is_not_ip_host():
    f = extract_features("https://en.wikipedia.org/wiki/Entropy")
    assert f["is_ip_host"] == 0.0
    assert f["has_port"] == 0.0
    assert f["is_https"] == 1.0


def test_at_symbol_flagged():
    # Everything before '@' is userinfo — the real host is evil.com.
    f = extract_features("http://google.com@evil.com/login")
    assert f["has_at_symbol"] == 1.0
    assert registrable_domain("http://google.com@evil.com/login") == "evil.com"


def test_shortener_flagged():
    assert extract_features("http://bit.ly/3xK9mQz")["is_shortener"] == 1.0
    assert extract_features("https://github.com/x/y")["is_shortener"] == 0.0


def test_punycode_flagged():
    f = extract_features("http://xn--pypal-4ve.com/signin")
    assert f["has_punycode"] == 1.0


def test_double_slash_in_path_flagged():
    f = extract_features("https://example.com//redirect//evil")
    assert f["double_slash_in_path"] == 1.0
    assert extract_features("https://example.com/a/b")["double_slash_in_path"] == 0.0


# --------------------------------------------------------------------------
# Typosquatting
# --------------------------------------------------------------------------
def test_brand_outside_domain_is_the_classic_phish_shape():
    """paypal.com.security-check.ru does not belong to PayPal."""
    f = extract_features("http://paypal.com.security-check.ru/login/verify")
    assert f["brand_outside_domain"] == 1.0


def test_real_brand_domain_not_flagged_as_impersonation():
    f = extract_features("https://www.paypal.com/us/signin")
    assert f["brand_outside_domain"] == 0.0
    assert f["min_brand_distance"] == 0.0


def test_near_miss_brand_has_small_edit_distance():
    f = extract_features("https://paypa1.com/login")
    assert 0 < f["min_brand_distance"] <= 2


def test_unrelated_domain_has_large_brand_distance():
    f = extract_features("https://en.wikipedia.org/wiki/Cat")
    assert f["min_brand_distance"] >= 4


# --------------------------------------------------------------------------
# Keywords
# --------------------------------------------------------------------------
def test_keyword_counting():
    f = extract_features(
        "https://secure-appleid-verify.com/confirm/account/login")
    assert f["keyword_count"] >= 3
    assert f["keyword_in_hostname"] == 1.0


def test_benign_article_url_has_few_keywords():
    f = extract_features("https://en.wikipedia.org/wiki/Shannon_entropy")
    assert f["keyword_in_hostname"] == 0.0


# --------------------------------------------------------------------------
# Grouping key (leakage-safe split depends on this being right)
# --------------------------------------------------------------------------
@pytest.mark.parametrize("url,expected", [
    ("https://www.bbc.co.uk/news/world-123", "bbc.co.uk"),
    ("https://en.wikipedia.org/wiki/Cat", "wikipedia.org"),
    ("http://a.b.c.example.com/x", "example.com"),
    ("http://192.168.14.99:8080/x", "192.168.14.99"),
    ("https://GITHUB.com/OWNER/repo", "github.com"),
])
def test_registrable_domain(url, expected):
    assert registrable_domain(url) == expected


def test_multipart_suffix_not_split_wrongly():
    """co.uk is a public suffix — the eTLD+1 is bbc.co.uk, not co.uk."""
    assert registrable_domain("https://bbc.co.uk/a") == "bbc.co.uk"


# --------------------------------------------------------------------------
# Reputation
# --------------------------------------------------------------------------
def test_reputation_tiers():
    rep = ReputationIndex({
        "google.com": 1,
        "midsize.com": 5_000,
        "smaller.com": 50_000,
        "obscure.com": 500_000,
    })
    assert rep.tier("google.com") == 4
    assert rep.tier("midsize.com") == 3
    assert rep.tier("smaller.com") == 2
    assert rep.tier("obscure.com") == 1
    assert rep.tier("never-heard-of-it.xyz") == 0


def test_reputation_features_can_be_ablated():
    with_rep = extract_features("https://github.com/a/b", include_reputation=True)
    without = extract_features("https://github.com/a/b", include_reputation=False)
    for name in REPUTATION_FEATURES:
        assert name in with_rep
        assert name not in without


def test_feature_names_match_extract_output():
    """The declared feature order must match what extraction actually emits."""
    for include in (True, False):
        names = feature_names(include_reputation=include)
        feats = extract_features(
            "https://example.com/a?b=c", include_reputation=include)
        assert set(names) == set(feats), (
            f"feature_names/extract_features mismatch (include={include})")


# --------------------------------------------------------------------------
# Robustness — this runs behind a public endpoint on untrusted input
# --------------------------------------------------------------------------
@pytest.mark.parametrize("bad", [
    "", "   ", "not a url at all", "http://", "://///",
    "http://[::1", "http://example.com:notaport/x",
    "javascript:alert(1)", "data:text/html,<script>alert(1)</script>",
    "ftp://files.example.com/pub", "a" * 5000,
    "http://exämple.com/ünïcode", "%%%%%", "http://.../..",
])
def test_malformed_input_never_raises(bad):
    feats = extract_features(bad)
    assert set(feats) == set(feature_names(include_reputation=True))
    for name in NUMERIC_FEATURES:
        v = feats[name]
        assert isinstance(v, float)
        assert not math.isnan(v) and not math.isinf(v), f"{name} = {v}"


def test_all_hand_labelled_examples_extract_cleanly():
    for url in BENIGN + MALICIOUS:
        feats = extract_features(url)
        assert feats["url_length"] > 0
        assert set(feats) == set(feature_names(include_reputation=True))


def test_brands_list_is_lowercase_and_unique_enough():
    assert all(b == b.lower() for b in BRANDS)
    assert len(set(BRANDS)) > 30


@pytest.mark.parametrize("url,expected_ext", [
    ("https://github.com/python/cpython/blob/main/Lib/json/decoder.py", "py"),
    ("http://192.168.14.99:8080/bins/mirai.arm7", "arm7"),
    ("https://www.tandoori-palace.co.uk/menu/starters.php?id=1", "php"),
    ("https://en.wikipedia.org/wiki/Shannon_entropy", "<none>"),
    ("https://example.com/v1.2.3/", "<none>"),
])
def test_path_ext_extraction(url, expected_ext):
    feats = extract_features(url)
    assert feats["path_ext"] == expected_ext
