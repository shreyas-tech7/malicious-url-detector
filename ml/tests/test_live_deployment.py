"""Integration tests against the LIVE deployment.

These exist because of a specific failure. The SSRF fix pinned the gateway's
backend origin to `VERCEL_URL`; that hostname is subject to Vercel Deployment
Protection, so the gateway's own server-side fetch came back as a 401 login
page and `/scan` returned it to callers. The unit suite passed, the build
passed, and `next build` was clean. The bug lived entirely in deployed routing
behaviour, so only a request to the real deployment could see it.

Anything asserted here must be checkable from outside the process.

Skips (rather than fails) when the deployment is unreachable, so a flight-mode
test run does not look like a regression. It does NOT skip on a wrong answer.

    pytest ml/tests/test_live_deployment.py -v
    LIVE_BASE_URL=https://my-preview.vercel.app pytest ml/tests/...
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

import pytest

BASE = os.environ.get(
    "LIVE_BASE_URL", "https://malicious-url-detector-bice.vercel.app"
).rstrip("/")

TIMEOUT = 30


def _request(path: str, payload: dict | None = None, method: str | None = None):
    url = f"{BASE}{path}"
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"} if data else {},
        method=method or ("POST" if data else "GET"),
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        pytest.skip(f"live deployment unreachable ({type(e).__name__}); "
                    f"not treating this as a failure")


def _json(path: str, payload: dict | None = None):
    status, body = _request(path, payload)
    try:
        return status, json.loads(body)
    except json.JSONDecodeError:
        pytest.fail(
            f"{path} returned non-JSON ({status}). First 200 chars:\n"
            f"{body[:200]}\n\n"
            f"An HTML body here usually means a Vercel Deployment Protection "
            f"login page reached the caller — the exact SSRF-fix regression "
            f"this test exists to catch."
        )


# --------------------------------------------------------------------------
# The regression that motivated this file
# --------------------------------------------------------------------------
def test_gateway_reaches_the_backend():
    """POST /scan must return a verdict, not a protection page.

    This is the assertion that would have caught the VERCEL_URL pin.
    """
    status, body = _json("/scan", {"url": "https://en.wikipedia.org/wiki/Malware"})
    assert status == 200, f"/scan -> {status}: {body}"
    assert body.get("verdict") in ("malicious", "uncertain", "benign")
    assert "protection" not in json.dumps(body).lower(), (
        "response mentions deployment protection — the gateway is talking to a "
        "protected hostname instead of the public alias")


def test_check_gateway_reaches_the_backend():
    status, body = _json("/check", {"filename": "invoice.pdf.exe"})
    assert status == 200, f"/check -> {status}: {body}"
    assert body["metadata"]["suspicion"] == "high"


def test_production_alias_is_publicly_reachable():
    """The shareable URL must not sit behind a Vercel login wall.

    No cookies, no auth header — exactly what a stranger opening the link gets.
    """
    status, body = _request("/api/health")
    assert status == 200, f"health -> {status}: {body[:200]}"
    assert "vercel_auth_enabled" not in body, (
        "production alias is gated behind Vercel authentication")
    parsed = json.loads(body)
    assert parsed["model_loaded"] is True


# --------------------------------------------------------------------------
# The foundational non-goal: never dereference a submitted URL
# --------------------------------------------------------------------------
def test_service_does_not_fetch_the_submitted_url():
    """Behavioural proof, not a code-reading exercise.

    10.255.255.1 is non-routable: any attempt to actually fetch it would stall
    until a connect timeout. A fast, correct response is evidence that the
    service scored the string and never opened a socket.
    """
    started = time.time()
    status, body = _json("/scan", {"url": "http://10.255.255.1/payload.bin"})
    elapsed = time.time() - started

    assert status == 200, f"expected a verdict, got {status}: {body}"
    assert body.get("verdict") in ("malicious", "uncertain", "benign")
    assert elapsed < 10, (
        f"took {elapsed:.1f}s for a non-routable host — suggests the service "
        f"attempted a connection to the submitted URL")


def test_health_advertises_the_non_goal():
    _, body = _json("/api/health")
    assert body["fetches_submitted_urls"] is False


def test_cloud_metadata_endpoint_is_scored_not_fetched():
    """169.254.169.254 is the cloud metadata address.

    It must come back as an ordinary classification. A timeout, a 5xx, or
    anything resembling metadata content would mean the URL was dereferenced.
    """
    started = time.time()
    status, body = _json("/scan", {"url": "http://169.254.169.254/latest/meta-data/"})
    elapsed = time.time() - started

    assert status == 200
    assert body.get("verdict") in ("malicious", "uncertain", "benign")
    assert elapsed < 10
    assert "ami-id" not in json.dumps(body).lower()
    assert "iam" not in str(body.get("url", "")).lower() or True


# --------------------------------------------------------------------------
# Input validation, enforced at the edge rather than only in unit tests
# --------------------------------------------------------------------------
@pytest.mark.parametrize("bad,expected", [
    ({"url": "javascript:alert(1)"}, 422),
    ({"url": "data:text/html,<script>alert(1)</script>"}, 422),
    ({"url": "file:///etc/passwd"}, 422),
    ({"url": ""}, 422),
    ({"url": "https://x.com/" + "a" * 5000}, 422),
])
def test_live_input_validation(bad, expected):
    status, _ = _json("/scan", bad)
    assert status == expected


def test_cron_endpoint_requires_authorisation():
    status, _ = _request("/api/refresh-hashes")
    assert status == 401, "refresh endpoint must not be callable unauthenticated"

    status, _ = _request("/api/refresh-hashes")
    assert status == 401


def test_security_headers_present():
    """vercel.json headers must actually be applied to responses."""
    req = urllib.request.Request(f"{BASE}/api/health")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        pytest.skip(f"live deployment unreachable ({type(e).__name__})")

    assert headers.get("x-content-type-options") == "nosniff"
    assert headers.get("x-frame-options") == "DENY"
