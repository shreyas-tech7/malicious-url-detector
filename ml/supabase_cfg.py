"""Single source of truth for how Supabase credentials are resolved.

This module exists because the same six lines were duplicated in three places
— `api/index.py`, `ml/signatures.py` and `ml/build_hashfeed.py` — and drifted.
When the deployment moved from a service_role key to a restricted key, two of
the three copies were updated and one was not, so hash lookups silently fell
back to the local snapshot and reported `known_malicious: false` for hashes
that were sitting in the database. Nothing errored; the wrong answer just
looked like a normal answer.

Any new caller must import from here rather than reading the environment
directly.
"""

from __future__ import annotations

import os

#: Checked in order. service_role first because it is the strongest key when
#: present; the restricted keys are the normal configuration.
_KEY_VARS = (
    "SUPABASE_SERVICE_ROLE_KEY",
    "SUPABASE_PUBLISHABLE_KEY",
    "SUPABASE_ANON_KEY",
)


def supabase_config() -> tuple[str, str] | None:
    """Return (base_url, key) or None when Supabase is not configured.

    Returning None — rather than raising or substituting a blank key — is what
    lets every caller degrade gracefully to the committed local snapshot.
    """
    url = os.environ.get("SUPABASE_URL", "").strip()
    if not url:
        return None
    for var in _KEY_VARS:
        key = os.environ.get(var, "").strip()
        if key:
            return url.rstrip("/"), key
    return None


def supabase_key_kind() -> str | None:
    """Which credential is in use, for health reporting and diagnostics."""
    if not os.environ.get("SUPABASE_URL", "").strip():
        return None
    for var in _KEY_VARS:
        if os.environ.get(var, "").strip():
            return {
                "SUPABASE_SERVICE_ROLE_KEY": "service_role",
                "SUPABASE_PUBLISHABLE_KEY": "publishable",
                "SUPABASE_ANON_KEY": "anon",
            }[var]
    return None
