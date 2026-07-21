"""FastAPI inference function — deployed as a Vercel Python Function.

Endpoints
---------
GET  /api/health       model + hash-table status
POST /api/predict      URL string  -> verdict, score, contributing features
POST /api/check-file   file hash   -> known-bad lookup + static metadata checks

Security notes that are load-bearing, not decoration
----------------------------------------------------
**This service never dereferences a submitted URL.** It does not fetch it,
resolve it, render it, or follow it. Every feature is computed from the URL
string. A backend that fetches user-supplied URLs is an SSRF primitive: on a
cloud host it can be pointed at link-local metadata endpoints
(169.254.169.254) or internal services. "Show me what's actually at this link"
is a separate product requiring its own sandbox design, and is deliberately not
built here.

**Client IPs are salted-hashed, never stored raw** (see `_hash_ip`).

**Untrusted input is bounded before it reaches the model**: URL length is
capped, the scheme is restricted to http/https, and the optional file-header
sample is limited to a few dozen bytes.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Literal

import joblib
import numpy as np
from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

# The training code is the single source of truth for feature extraction.
# Importing it here (rather than copying it) is what prevents train/serve skew.
_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "ml"))

from features import extract_features, registrable_domain  # noqa: E402
from signatures import (  # noqa: E402
    HashIndex,
    check_file_signature,
    classify_hash,
    inspect_file_metadata,
)

MODEL_PATH = _REPO_ROOT / "ml" / "artifacts" / "model.joblib"

# ---- limits ---------------------------------------------------------------
MAX_URL_LENGTH = 2048          # beyond this, nothing informative is added
MAX_HEADER_SAMPLE_BYTES = 64   # enough for any magic number we check
DEFAULT_THRESHOLD = float(os.environ.get("PREDICT_THRESHOLD", "0.5"))
RATE_LIMIT_PER_MINUTE = int(os.environ.get("RATE_LIMIT_PER_MINUTE", "30"))

app = FastAPI(
    title="Malicious URL & File-Signature Detector",
    version="1.0.0",
    description=("Classifies URL strings and looks up file hashes. Never "
                 "fetches or renders submitted URLs."),
)

_BUNDLE: dict | None = None
_HASH_INDEX = HashIndex()


def _load_bundle() -> dict:
    """Load the model bundle once per warm instance."""
    global _BUNDLE
    if _BUNDLE is None:
        if not MODEL_PATH.exists():
            raise RuntimeError(f"model artifact missing at {MODEL_PATH}")
        _BUNDLE = joblib.load(MODEL_PATH)
    return _BUNDLE


# --------------------------------------------------------------------------
# Schemas
# --------------------------------------------------------------------------
class PredictRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=MAX_URL_LENGTH)

    @field_validator("url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("url must not be empty")
        lowered = v.lower()
        # Reject anything that isn't plainly web content. `javascript:` and
        # `data:` are rejected outright rather than scored, because a caller
        # echoing them back into a page is an XSS vector and the model has no
        # meaningful opinion about them anyway.
        if "://" in lowered:
            scheme = lowered.split("://", 1)[0]
            if scheme not in ("http", "https"):
                raise ValueError(
                    f"unsupported scheme '{scheme}' — only http and https are "
                    f"accepted")
        elif ":" in lowered.split("/", 1)[0]:
            head = lowered.split(":", 1)[0]
            if head in ("javascript", "data", "file", "ftp", "vbscript"):
                raise ValueError(
                    f"unsupported scheme '{head}' — only http and https are "
                    f"accepted")
        if any(ch in v for ch in ("\n", "\r", "\x00")):
            raise ValueError("url must not contain control characters")
        return v


class FeatureContribution(BaseModel):
    feature: str
    value: float
    contribution: float


class PredictResponse(BaseModel):
    url: str
    verdict: Literal["malicious", "benign"]
    score: float
    threshold: float
    model_version: str
    registrable_domain: str
    top_features: list[FeatureContribution]
    disclaimer: str


class CheckFileRequest(BaseModel):
    hash: str | None = Field(None, max_length=128)
    filename: str | None = Field(None, max_length=512)
    mime_type: str | None = Field(None, max_length=255)
    header_b64: str | None = Field(
        None, max_length=512,
        description=(f"Base64 of at most the first {MAX_HEADER_SAMPLE_BYTES} "
                     f"bytes of the file, for magic-number checks. Do not send "
                     f"the whole file."))


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _hash_ip(ip: str) -> str | None:
    """Salted SHA-256 of a client IP.

    The salt matters. The IPv4 space is only ~4 billion addresses, so an
    unsalted hash is trivially reversible with a rainbow table — it would be
    pseudonymisation in name only. With no salt configured we return None and
    log nothing rather than store something reversible.
    """
    salt = os.environ.get("IP_HASH_SALT", "").strip()
    if not (ip and salt):
        return None
    return hashlib.sha256(f"{salt}:{ip}".encode()).hexdigest()


def _client_ip(request: Request, forwarded: str | None) -> str:
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""


def _supabase_cfg() -> tuple[str, str] | None:
    url = os.environ.get("SUPABASE_URL", "").strip()
    key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    return (url.rstrip("/"), key) if url and key else None


def _supabase_post(path: str, payload: Any, timeout: float = 3.0) -> Any:
    """Minimal Supabase REST call over urllib.

    Deliberately not using a client library: the serverless bundle already
    carries scikit-learn and numpy, and this needs one HTTP POST.
    """
    cfg = _supabase_cfg()
    if cfg is None:
        return None
    base, key = cfg
    req = urllib.request.Request(
        f"{base}{path}",
        data=json.dumps(payload).encode(),
        headers={
            "apikey": key,
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Prefer": "return=minimal",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            return json.loads(body) if body else None
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        # Logging and rate limiting are best-effort. A database problem must
        # never turn into a failed classification for the user.
        return None


def _rate_limited(ip_hash: str | None) -> bool:
    """Supabase-backed counter, portable off Vercel.

    Fails OPEN: if the database is unreachable we serve the request rather than
    locking everyone out. That is the right trade for a demo endpoint; a system
    where the limiter is a security control rather than an abuse deterrent
    should fail closed instead.
    """
    if not ip_hash or _supabase_cfg() is None:
        return False
    bucket = f"predict:{ip_hash}:{int(time.time() // 60)}"
    res = _supabase_post("/rest/v1/rpc/bump_rate_limit",
                         {"p_bucket": bucket, "p_window_seconds": 60})
    try:
        return int(res) > RATE_LIMIT_PER_MINUTE
    except (TypeError, ValueError):
        return False


def _log_prediction(**row) -> None:
    if _supabase_cfg() is None:
        return
    _supabase_post("/rest/v1/predictions", [row])


def _explain(bundle: dict, x: np.ndarray, score: float,
             top: int = 5) -> list[dict]:
    """Per-prediction feature attribution by occlusion.

    For each feature, substitute the training median and re-score. The drop in
    predicted probability is that feature's contribution *for this URL*.

    This is a genuine local explanation rather than a global importance table
    dressed up as one — but it is a first-order approximation: it holds other
    features fixed and so under-reports interactions. That caveat is surfaced
    in the API docs, not hidden.
    """
    medians = bundle.get("feature_medians")
    columns = bundle["columns"]
    if not medians:
        return []

    model = bundle["model"]
    base = np.asarray(medians, dtype=np.float64)
    variants = np.repeat(x.reshape(1, -1), len(columns), axis=0)
    for i in range(len(columns)):
        variants[i, i] = base[i]

    # Attribute in LOG-ODDS space, not probability space.
    #
    # On a confident prediction the probability saturates near 0 or 1, so
    # occluding any single feature moves it by ~1e-4 and every contribution
    # rounds to "zero" — technically true, completely useless to a reader.
    # The raw decision function is unbounded and keeps its resolution at the
    # extremes, so the ranking stays meaningful however confident the model is.
    base_margin = float(model.decision_function(x.reshape(1, -1))[0])
    occluded_margin = model.decision_function(variants)
    contribs = base_margin - occluded_margin

    order = np.argsort(-np.abs(contribs))[:top]
    return [
        {"feature": columns[i],
         "value": float(x[i]),
         "contribution": round(float(contribs[i]), 4)}
        for i in order
        if abs(contribs[i]) > 1e-4
    ]


def _vectorise(bundle: dict, url: str) -> np.ndarray:
    """Build the model input for one URL.

    Column order comes from the bundle, not from this file, so a model trained
    with a different feature set still scores correctly.
    """
    feats = extract_features(
        url, include_reputation=bundle.get("include_reputation", False))
    vocabs: dict[str, dict[str, int]] = bundle.get("vocabs") or {}

    values = []
    for col in bundle["columns"]:
        if col in vocabs:
            vocab = vocabs[col]
            other = vocab.get("<other>", 0)
            values.append(float(vocab.get(str(feats.get(col, "")), other)))
        else:
            values.append(float(feats.get(col, 0.0)))
    return np.asarray(values, dtype=np.float64)


# --------------------------------------------------------------------------
# Routes
#
# Paths carry the /api prefix because that is the path Vercel forwards. The
# bare aliases keep `uvicorn api.index:app` usable locally.
# --------------------------------------------------------------------------
@app.get("/api/health")
@app.get("/health")
def health() -> dict:
    try:
        bundle = _load_bundle()
        model_ok = True
        version = bundle.get("model_version", "unknown")
        n_features = len(bundle["columns"])
    except Exception as exc:  # noqa: BLE001
        model_ok, version, n_features = False, str(exc), 0

    return {
        "status": "ok" if model_ok else "degraded",
        "model_loaded": model_ok,
        "model_version": version,
        "n_features": n_features,
        "hash_table_entries": _HASH_INDEX.size,
        "supabase_configured": _supabase_cfg() is not None,
        "fetches_submitted_urls": False,
    }


@app.post("/api/predict", response_model=PredictResponse)
@app.post("/predict", response_model=PredictResponse)
def predict(
    body: PredictRequest,
    request: Request,
    x_forwarded_for: str | None = Header(default=None),
) -> Any:
    started = time.time()
    bundle = _load_bundle()

    ip_hash = _hash_ip(_client_ip(request, x_forwarded_for))
    if _rate_limited(ip_hash):
        return JSONResponse(
            status_code=429,
            content={"error": "rate limit exceeded",
                     "limit_per_minute": RATE_LIMIT_PER_MINUTE},
        )

    x = _vectorise(bundle, body.url)
    score = float(bundle["model"].predict_proba(x.reshape(1, -1))[0, 1])
    verdict = "malicious" if score >= DEFAULT_THRESHOLD else "benign"
    top = _explain(bundle, x, score)

    _log_prediction(
        url=body.url[:2048],
        url_sha256=hashlib.sha256(body.url.encode()).hexdigest(),
        verdict=verdict,
        score=round(score, 6),
        model_version=bundle.get("model_version", "unknown"),
        threshold=DEFAULT_THRESHOLD,
        features={d["feature"]: d["value"] for d in top},
        client_ip_hash=ip_hash,
        latency_ms=int((time.time() - started) * 1000),
    )

    return {
        "url": body.url,
        "verdict": verdict,
        "score": round(score, 4),
        "threshold": DEFAULT_THRESHOLD,
        "model_version": bundle.get("model_version", "unknown"),
        "registrable_domain": registrable_domain(body.url),
        "top_features": top,
        "disclaimer": (
            "Classification is based on the URL string alone. The service did "
            "not fetch or open this URL. Not a substitute for a security "
            "product."
        ),
    }


@app.post("/api/check-file")
@app.post("/check-file")
def check_file(body: CheckFileRequest) -> Any:
    if not any([body.hash, body.filename, body.header_b64]):
        return JSONResponse(
            status_code=422,
            content={"error": "provide at least one of: hash, filename, "
                              "header_b64"},
        )

    result: dict[str, Any] = {}

    if body.hash:
        if classify_hash(body.hash) is None:
            return JSONResponse(
                status_code=422,
                content={"error": "hash must be a hex md5, sha1 or sha256"},
            )
        result["hash_lookup"] = check_file_signature(body.hash,
                                                    index=_HASH_INDEX)

    header: bytes | None = None
    if body.header_b64:
        try:
            header = base64.b64decode(body.header_b64, validate=True)
        except (ValueError, TypeError):
            return JSONResponse(
                status_code=422,
                content={"error": "header_b64 is not valid base64"},
            )
        if len(header) > MAX_HEADER_SAMPLE_BYTES:
            # Truncate rather than reject: callers sending a bit too much are
            # being helpful, not hostile. We simply refuse to ingest more of
            # the file than the magic-number check needs.
            header = header[:MAX_HEADER_SAMPLE_BYTES]

    if body.filename or body.mime_type or header:
        result["metadata"] = inspect_file_metadata(
            filename=body.filename,
            declared_mime=body.mime_type,
            header=header,
        )

    result["disclaimer"] = (
        "Hash lookup and static metadata only. The file was not downloaded, "
        "unpacked or executed. A hash miss is not proof the file is safe."
    )
    return result


@app.get("/api/refresh-hashes")
@app.get("/refresh-hashes")
def refresh_hashes(
    request: Request,
    authorization: str | None = Header(default=None),
    limit: int = 20_000,
) -> Any:
    """Refresh the malicious-hash table from the URLhaus payload feed.

    Invoked by Vercel Cron (see vercel.json). Vercel sends
    `Authorization: Bearer $CRON_SECRET`, which is checked here — without it
    this endpoint would be an open trigger for a large upstream download.

    Bounded by `limit` because the upstream dump is ~775 MB and a serverless
    function has a hard timeout. The feed is ordered newest-first, so a bounded
    read keeps the freshest hashes. For a full backfill run
    `python ml/build_hashfeed.py --limit 0 --supabase` outside the function.
    """
    secret = os.environ.get("CRON_SECRET", "").strip()
    if not secret:
        return JSONResponse(
            status_code=503,
            content={"error": "CRON_SECRET is not configured"},
        )
    presented = (authorization or "").removeprefix("Bearer ").strip()
    if not presented or presented != secret:
        return JSONResponse(status_code=401, content={"error": "unauthorized"})

    if _supabase_cfg() is None:
        return JSONResponse(
            status_code=503,
            content={"error": "Supabase is not configured; nothing to refresh. "
                              "The committed local snapshot remains in use."},
        )

    started = time.time()
    try:
        from build_hashfeed import parse_feed, sync_supabase
        rows, _cols = parse_feed(limit=max(1, min(limit, 200_000)))
        sync_supabase(rows)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(
            status_code=502,
            content={"error": "refresh failed", "detail": str(exc)[:200]},
        )

    return {
        "refreshed": len(rows),
        "elapsed_ms": int((time.time() - started) * 1000),
    }


# Local dev:  uvicorn api.index:app --reload --port 8000
