"""End-to-end tests for the inference API.

Uses FastAPI's TestClient, so these exercise the real routes, real validation
and the real model artifact — not mocks.
"""

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

from fastapi.testclient import TestClient  # noqa: E402

from api.index import app  # noqa: E402

client = TestClient(app)


# --------------------------------------------------------------------------
def test_health_reports_model_loaded():
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["model_loaded"] is True
    assert body["n_features"] > 20
    # The service advertises that it does not dereference submitted URLs.
    assert body["fetches_submitted_urls"] is False


# --------------------------------------------------------------------------
# /predict
# --------------------------------------------------------------------------
def test_predict_returns_well_formed_response():
    r = client.post("/api/predict",
                    json={"url": "https://en.wikipedia.org/wiki/Malware"})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] in ("malicious", "benign")
    assert 0.0 <= body["score"] <= 1.0
    assert body["registrable_domain"] == "wikipedia.org"
    assert body["model_version"]
    assert "did not fetch" in body["disclaimer"]


def test_predict_returns_per_prediction_explanations():
    r = client.post("/api/predict",
                    json={"url": "http://paypal.com.secure-verify.ru/login/"
                                 "confirm-account.php"})
    body = r.json()
    assert len(body["top_features"]) > 0
    for f in body["top_features"]:
        assert {"feature", "value", "contribution"} <= set(f)


@pytest.mark.parametrize("scheme", [
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "file:///etc/passwd",
    "ftp://files.example.com/x",
])
def test_non_web_schemes_are_rejected(scheme):
    """These are refused outright rather than scored.

    Echoing a javascript:/data: URL back into a page is an XSS vector, and the
    model has no meaningful opinion about them anyway.
    """
    r = client.post("/api/predict", json={"url": scheme})
    assert r.status_code == 422


def test_overlong_url_rejected():
    r = client.post("/api/predict", json={"url": "https://x.com/" + "a" * 5000})
    assert r.status_code == 422


def test_empty_url_rejected():
    assert client.post("/api/predict", json={"url": ""}).status_code == 422
    assert client.post("/api/predict", json={}).status_code == 422


def test_control_characters_rejected():
    r = client.post("/api/predict",
                    json={"url": "https://example.com/\r\nX-Injected: 1"})
    assert r.status_code == 422


def test_garbage_input_does_not_500():
    """Hostile/nonsense input must be a clean 4xx, never a stack trace."""
    for bad in ["not a url", "...", "%%%%", "http://", "@@@@"]:
        r = client.post("/api/predict", json={"url": bad})
        assert r.status_code in (200, 422), f"{bad!r} -> {r.status_code}"


def test_obvious_phish_scores_above_obvious_benign():
    """A relative-ordering check — more meaningful than pinning a threshold."""
    phish = client.post("/api/predict", json={
        "url": "http://paypal.com.account-verify-secure.tk/login/confirm.php"
    }).json()["score"]
    benign = client.post("/api/predict", json={
        "url": "https://en.wikipedia.org/wiki/Shannon_entropy"
    }).json()["score"]
    assert phish > benign


# --------------------------------------------------------------------------
# /check-file
# --------------------------------------------------------------------------
def test_check_file_requires_some_input():
    assert client.post("/api/check-file", json={}).status_code == 422


def test_check_file_rejects_invalid_hash():
    r = client.post("/api/check-file", json={"hash": "nonsense"})
    assert r.status_code == 422


def test_check_file_unknown_hash_is_hedged():
    r = client.post("/api/check-file", json={"hash": "0" * 64})
    assert r.status_code == 200
    body = r.json()
    assert body["hash_lookup"]["known_malicious"] is False
    assert "not proof the file is safe" in body["disclaimer"]


def test_check_file_detects_double_extension():
    r = client.post("/api/check-file", json={"filename": "invoice.pdf.exe"})
    assert r.status_code == 200
    assert r.json()["metadata"]["suspicion"] == "high"


def test_check_file_detects_disguised_executable():
    import base64
    r = client.post("/api/check-file", json={
        "filename": "statement.pdf",
        "header_b64": base64.b64encode(b"MZ\x90\x00").decode(),
    })
    meta = r.json()["metadata"]
    assert meta["suspicion"] == "high"
    assert any(f["check"] == "extension_content_mismatch"
               for f in meta["findings"])


def test_check_file_rejects_bad_base64():
    r = client.post("/api/check-file",
                    json={"filename": "a.pdf", "header_b64": "!!!not base64!!!"})
    assert r.status_code == 422


def test_check_file_truncates_oversized_header():
    """We refuse to ingest more of a file than the magic check needs."""
    import base64
    payload = base64.b64encode(b"MZ" + b"\x00" * 300).decode()
    r = client.post("/api/check-file",
                    json={"filename": "big.exe", "header_b64": payload})
    # Either accepted-and-truncated or rejected for length; must not crash.
    assert r.status_code in (200, 422)


def test_clean_document_is_not_flagged():
    import base64
    r = client.post("/api/check-file", json={
        "filename": "report.pdf",
        "mime_type": "application/pdf",
        "header_b64": base64.b64encode(b"%PDF-1.7").decode(),
    })
    assert r.json()["metadata"]["suspicion"] == "none"


# --------------------------------------------------------------------------
# Security behaviours (regression tests for the Phase 8 audit findings)
# --------------------------------------------------------------------------
def test_logged_url_has_query_string_redacted():
    """Query strings carry reset tokens and session ids; they must not persist."""
    from api.index import _redact_url

    out = _redact_url(
        "https://example.com/reset?token=SUPERSECRET123&user=alice")
    assert "SUPERSECRET123" not in out
    assert out.startswith("https://example.com/reset")
    assert "[redacted]" in out

    frag = _redact_url("https://example.com/p#access_token=SECRET")
    assert "SECRET" not in frag

    # A URL with no query is preserved intact.
    assert _redact_url("https://example.com/a/b") == "https://example.com/a/b"


def test_client_ip_ignores_attacker_supplied_leftmost_forwarded_for():
    """The leftmost XFF entry is client-written and must not be trusted.

    Trusting it would let anyone mint a fresh rate-limit bucket per request.
    """
    from api.index import _client_ip

    class _Req:
        client = None

    # Rightmost entry is the one the trusted proxy appended.
    assert _client_ip(_Req(), "1.2.3.4, 9.9.9.9") == "9.9.9.9"
    # x-real-ip, set by the platform, wins outright.
    assert _client_ip(_Req(), "1.2.3.4, 9.9.9.9", "8.8.8.8") == "8.8.8.8"


def test_local_rate_limiter_engages_without_a_database():
    """An unconfigured deployment must not be completely unmetered."""
    from api import index as api_index

    api_index._LOCAL_HITS.clear()
    limit = api_index.RATE_LIMIT_PER_MINUTE

    allowed = sum(
        0 if api_index._rate_limited_local("test-key") else 1
        for _ in range(limit + 5)
    )
    assert allowed == limit, f"expected {limit} allowed, got {allowed}"
    assert api_index._rate_limited_local("test-key") is True
    api_index._LOCAL_HITS.clear()


def test_cron_endpoint_rejects_missing_and_wrong_secret(monkeypatch):
    monkeypatch.setenv("CRON_SECRET", "correct-horse-battery-staple")

    assert client.get("/api/refresh-hashes").status_code == 401
    assert client.get(
        "/api/refresh-hashes",
        headers={"Authorization": "Bearer wrong"},
    ).status_code == 401

    # Correct secret gets past auth; without Supabase it reports 503 rather
    # than pretending to have refreshed anything.
    ok = client.get(
        "/api/refresh-hashes",
        headers={"Authorization": "Bearer correct-horse-battery-staple"},
    )
    assert ok.status_code == 503


def test_unknown_path_returns_json_404_not_a_stack_trace():
    r = client.get("/definitely/not/a/route")
    assert r.status_code == 404
    assert r.json()["received_path"] == "/definitely/not/a/route"
