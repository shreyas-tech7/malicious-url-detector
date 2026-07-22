"""Regression tests for Supabase credential resolution.

These exist because the same resolution logic was copy-pasted into three
modules and drifted. When the deployment switched from a service_role key to a
restricted key, `ml/signatures.py` was missed, so hash lookups quietly stopped
consulting the database and answered `known_malicious: false` for hashes that
were present in it. Nothing raised; the wrong answer just looked ordinary.

The important test here is `test_all_call_sites_agree` — it fails if any module
starts resolving credentials on its own again.
"""

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

from supabase_cfg import supabase_config, supabase_key_kind  # noqa: E402

ALL_VARS = (
    "SUPABASE_URL",
    "SUPABASE_SERVICE_ROLE_KEY",
    "SUPABASE_PUBLISHABLE_KEY",
    "SUPABASE_ANON_KEY",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for v in ALL_VARS:
        monkeypatch.delenv(v, raising=False)


def test_unconfigured_returns_none():
    assert supabase_config() is None
    assert supabase_key_kind() is None


def test_url_without_any_key_is_not_configured(monkeypatch):
    monkeypatch.setenv("SUPABASE_URL", "https://x.supabase.co")
    assert supabase_config() is None


@pytest.mark.parametrize("var,expected_kind", [
    ("SUPABASE_SERVICE_ROLE_KEY", "service_role"),
    ("SUPABASE_PUBLISHABLE_KEY", "publishable"),
    ("SUPABASE_ANON_KEY", "anon"),
])
def test_any_single_key_configures_the_client(monkeypatch, var, expected_kind):
    """A restricted key must configure the client, not just service_role.

    This is the exact assertion that would have caught the outage.
    """
    monkeypatch.setenv("SUPABASE_URL", "https://x.supabase.co")
    monkeypatch.setenv(var, "the-key")
    cfg = supabase_config()
    assert cfg == ("https://x.supabase.co", "the-key")
    assert supabase_key_kind() == expected_kind


def test_service_role_takes_precedence(monkeypatch):
    monkeypatch.setenv("SUPABASE_URL", "https://x.supabase.co")
    monkeypatch.setenv("SUPABASE_ANON_KEY", "anon-key")
    monkeypatch.setenv("SUPABASE_PUBLISHABLE_KEY", "pub-key")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "secret-key")
    assert supabase_config()[1] == "secret-key"
    assert supabase_key_kind() == "service_role"


def test_trailing_slash_is_normalised(monkeypatch):
    monkeypatch.setenv("SUPABASE_URL", "https://x.supabase.co/")
    monkeypatch.setenv("SUPABASE_ANON_KEY", "k")
    assert supabase_config()[0] == "https://x.supabase.co"


def test_whitespace_only_key_is_ignored(monkeypatch):
    monkeypatch.setenv("SUPABASE_URL", "https://x.supabase.co")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "   ")
    monkeypatch.setenv("SUPABASE_ANON_KEY", "real")
    assert supabase_config()[1] == "real"


def test_api_call_site_matches_shared_helper(monkeypatch):
    """api/index.py must return exactly what the shared resolver returns."""
    monkeypatch.setenv("SUPABASE_URL", "https://x.supabase.co")
    monkeypatch.setenv("SUPABASE_PUBLISHABLE_KEY", "restricted-key")

    expected = supabase_config()
    assert expected is not None, "a restricted key must configure the client"

    from api.index import _supabase_cfg
    assert _supabase_cfg() == expected


def test_no_module_reads_supabase_credentials_directly():
    """No call site may re-derive credentials from the environment itself.

    Matches the actual read pattern (`os.environ...("SUPABASE_...")`) rather
    than the bare variable name, so prose in comments does not trip it. This is
    the guard against the copy-paste drift that caused the original bug.
    """
    import re

    pattern = re.compile(
        r"""os\.environ(?:\.get)?\s*[\(\[]\s*["']SUPABASE_""")

    for rel in ("ml/signatures.py", "ml/build_hashfeed.py", "api/index.py"):
        src = (_ROOT / rel).read_text(encoding="utf-8")
        hits = pattern.findall(src)
        assert not hits, (
            f"{rel} reads SUPABASE_* from the environment directly; "
            f"import supabase_config() from supabase_cfg instead")

    # And the shared module is, of course, allowed to.
    shared = (_ROOT / "ml" / "supabase_cfg.py").read_text(encoding="utf-8")
    assert pattern.search(shared), "the shared resolver should read the env"
