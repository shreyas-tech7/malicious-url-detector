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
import hmac
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
from fastapi.exceptions import RequestValidationError
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
from supabase_cfg import supabase_config, supabase_key_kind  # noqa: E402

MODEL_PATH = _REPO_ROOT / "ml" / "artifacts" / "model.joblib"

# ---- limits ---------------------------------------------------------------
MAX_URL_LENGTH = 2048          # beyond this, nothing informative is added
MAX_HEADER_SAMPLE_BYTES = 64   # enough for any magic number we check
DEFAULT_THRESHOLD = float(os.environ.get("PREDICT_THRESHOLD", "0.5"))
RATE_LIMIT_PER_MINUTE = int(os.environ.get("RATE_LIMIT_PER_MINUTE", "30"))

# --- "uncertain" band -----------------------------------------------------
# Scores between these bounds are reported as `uncertain` rather than forced
# into a binary call.
#
# The bounds are measured, not guessed. On the held-out set the score
# distribution is strongly bimodal: 39.5% of predictions land below 0.05 and
# 33.3% above 0.95, and those confident regions are right ~99% of the time.
# The errors sit in the middle:
#
#   band          share of traffic   share of all errors
#   [0.20, 0.80)        14.1%               65.9%
#
# So abstaining on 14% of inputs removes two thirds of the mistakes, and the
# error rate on everything still given a hard verdict falls from 7.7% to 3.04%.
#
# This is a presentation change, not a model change. Two rounds of feature
# engineering in this project each fixed one false-positive class and created
# another; declining to answer where the model is genuinely unsure is a more
# honest response than a third round.
UNCERTAIN_LOW = float(os.environ.get("UNCERTAIN_LOW", "0.20"))
UNCERTAIN_HIGH = float(os.environ.get("UNCERTAIN_HIGH", "0.80"))


def classify_score(score: float) -> str:
    """Map a probability to malicious / uncertain / benign."""
    if score >= UNCERTAIN_HIGH:
        return "malicious"
    if score < UNCERTAIN_LOW:
        return "benign"
    return "uncertain"

app = FastAPI(
    title="Malicious URL & File-Signature Detector",
    version="1.0.0",
    description=("Classifies URL strings and looks up file hashes. Never "
                 "fetches or renders submitted URLs."),
)

_BUNDLE: dict | None = None
_HASH_INDEX = HashIndex()

#: Endpoints this function serves, used to answer 405 rather than 404 when the
#: path is right but the method is wrong.
_KNOWN_ROUTES: dict[str, tuple[str, ...]] = {
    "/api/health": ("GET",),
    "/api/predict": ("POST",),
    "/api/check-file": ("POST",),
    "/api/refresh-hashes": ("GET",),
    "/health": ("GET",),
    "/predict": ("POST",),
    "/check-file": ("POST",),
    "/refresh-hashes": ("GET",),
}


@app.exception_handler(RequestValidationError)
async def _validation_handler(request: Request,
                              exc: RequestValidationError) -> JSONResponse:
    """Return validation errors WITHOUT echoing the offending input back.

    FastAPI's default handler includes an `input` key containing the value that
    failed. That means a caller who posts 500 KB in a field gets all 500 KB
    reflected in the error body — free response amplification, and gratuitous
    reflection of attacker-controlled bytes. Observed directly: a 2 KB
    `header_b64` was echoed in full by the very response rejecting it for
    exceeding 512 characters.

    `type`, `loc` and `msg` are kept, so the response still tells an honest
    caller exactly which field is wrong and why.
    """
    detail = [
        {
            "type": e.get("type"),
            "loc": [str(p) for p in e.get("loc", [])],
            "msg": str(e.get("msg", ""))[:200],
        }
        for e in exc.errors()[:10]   # cap: a fuzzer can generate many errors
    ]
    return JSONResponse(status_code=422,
                        content={"error": "validation failed",
                                 "detail": detail})


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
    #: Three-valued. `uncertain` means the model declined to call it rather
    #: than that it scored exactly 0.5 — see UNCERTAIN_LOW/HIGH.
    verdict: Literal["malicious", "uncertain", "benign"]
    #: The strict >= threshold call, kept so callers that need a binary
    #: decision are not forced to re-derive it from the score.
    binary_verdict: Literal["malicious", "benign"]
    score: float
    threshold: float
    uncertain_band: list[float]
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


def _client_ip(request: Request, forwarded: str | None,
               real_ip: str | None = None) -> str:
    """Best available client IP.

    Deliberately NOT the leftmost X-Forwarded-For entry. That value is written
    by the client, so trusting it lets anyone mint a fresh rate-limit bucket per
    request simply by varying the header — the limiter becomes decorative. The
    trustworthy entry is the one the last proxy appended, i.e. the RIGHTMOST.

    Vercel also sets x-real-ip itself, which is preferable to parsing at all.
    """
    if real_ip and real_ip.strip():
        return real_ip.strip()
    if forwarded:
        parts = [p.strip() for p in forwarded.split(",") if p.strip()]
        if parts:
            return parts[-1]
    return request.client.host if request.client else ""


def _redact_url(url: str) -> str:
    """Drop the query string and fragment before a URL is persisted.

    Query strings routinely carry password-reset tokens, session identifiers,
    signed object URLs and API keys. Storing submitted URLs verbatim would turn
    the prediction log into a secondary credential store — a more attractive
    target than anything else in this project. The full string is still
    represented by its SHA-256 for grouping repeat submissions.
    """
    raw = (url or "")[:2048]
    for sep in ("?", "#"):
        idx = raw.find(sep)
        if idx != -1:
            raw = raw[:idx] + sep + "[redacted]"
            break
    return raw


def _supabase_cfg() -> tuple[str, str] | None:
    """Supabase URL + key, or None when unconfigured.

    Delegates to the shared resolver so this file cannot drift from
    ml/signatures.py and ml/build_hashfeed.py — which is exactly what happened
    once already and silently disabled hash lookups.
    """
    return supabase_config()


def _supabase_post(path: str, payload: Any, timeout: float = 3.0,
                   want_response: bool = False) -> Any:
    """Minimal Supabase REST call over urllib.

    Deliberately not using a client library: the serverless bundle already
    carries scikit-learn and numpy, and this needs one HTTP POST.

    `want_response` controls the Prefer header, and it matters more than it
    looks. `return=minimal` makes PostgREST send an empty body — including for
    RPC calls whose return value is the entire point. The rate limiter used to
    send it unconditionally, so `bump_rate_limit` always came back as None, the
    caller read that as "database unavailable", and every request quietly fell
    through to the in-memory counter. The counters in Postgres were incrementing
    correctly the whole time; nothing ever read them.
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
            "Prefer": "return=representation" if want_response
                      else "return=minimal",
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


#: Per-instance fallback counter: {key: (window_start_epoch, hits)}.
_LOCAL_HITS: dict[str, tuple[float, int]] = {}

#: Length of the rate-limit window, in seconds.
RATE_LIMIT_WINDOW_SECONDS = 60


def _rate_limited_local(ip_hash: str) -> bool:
    """In-process limiter used when no database is configured.

    Honest about what this is: serverless instances are ephemeral and there may
    be many of them, so an in-memory counter is a speed bump, not a control — a
    distributed attacker gets one full budget per warm instance. It exists so
    that an unconfigured deployment is not completely unmetered, which is
    otherwise exactly what happens.

    Real limiting comes from the Supabase counter below, or from Vercel
    Firewall rate limiting at the edge.

    The window is anchored to the caller's first request, not to a wall-clock
    minute — see the note on bucket keys in `_rate_limited`.
    """
    now = time.time()
    if len(_LOCAL_HITS) > 2048:
        _LOCAL_HITS.clear()  # bound memory; drops counters, never blocks

    started, hits = _LOCAL_HITS.get(ip_hash, (now, 0))
    if now - started >= RATE_LIMIT_WINDOW_SECONDS:
        started, hits = now, 0        # window elapsed, start a fresh one
    hits += 1
    _LOCAL_HITS[ip_hash] = (started, hits)
    return hits > RATE_LIMIT_PER_MINUTE


def _rate_limited(ip_hash: str | None) -> bool:
    """Rate limit a caller, preferring the shared Supabase counter.

    Fails OPEN on database error: a DB outage should not lock every user out of
    a demo endpoint. A system where the limiter is a security control rather
    than an abuse deterrent should fail closed instead.
    """
    if not ip_hash:
        return False
    if _supabase_cfg() is None:
        return _rate_limited_local(ip_hash)

    # The bucket key carries NO wall-clock component.
    #
    # It used to be `predict:{hash}:{epoch_minute}`, which manufactured a fresh
    # counter at every minute boundary — so a caller could spend a full budget
    # at 11:59:59 and another at 12:00:01, reaching 2x the stated limit. The
    # SQL function already resets on elapsed time (`window_start < now() -
    # interval`), so removing the minute from the key is all that was needed:
    # the window is now anchored to the caller's FIRST request and resets 60s
    # after it, and the boundary-straddling burst is gone.
    #
    # This is a fixed window anchored to first use, not a true sliding window.
    # The remaining slack is the ordinary one: a caller can spend the budget at
    # the end of one window and again at the start of the next, so the
    # worst-case burst over a short span approaches 2x — but only across a
    # genuine 60s gap, not at an exploitable clock boundary. A true sliding
    # window would need a timestamp log per caller, which is not worth the
    # write amplification here.
    bucket = f"predict:{ip_hash}"
    res = _supabase_post("/rest/v1/rpc/bump_rate_limit",
                         {"p_bucket": bucket,
                          "p_window_seconds": RATE_LIMIT_WINDOW_SECONDS},
                         want_response=True)
    if res is None:
        # Database unreachable — fall back to the local counter rather than
        # silently serving unlimited traffic.
        return _rate_limited_local(ip_hash)
    try:
        return int(res) > RATE_LIMIT_PER_MINUTE
    except (TypeError, ValueError):
        return _rate_limited_local(ip_hash)


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
        # Surfaced so a misconfigured key is visible from outside rather than
        # showing up as silently-degraded lookups.
        "supabase_key_kind": supabase_key_kind(),
        "fetches_submitted_urls": False,
    }


@app.post("/api/predict", response_model=PredictResponse)
@app.post("/predict", response_model=PredictResponse)
def predict(
    body: PredictRequest,
    request: Request,
    x_forwarded_for: str | None = Header(default=None),
    x_real_ip: str | None = Header(default=None),
) -> Any:
    started = time.time()
    bundle = _load_bundle()

    ip = _client_ip(request, x_forwarded_for, x_real_ip)

    # Two different keys on purpose.
    #
    # The rate-limit key is an unsalted digest held only in memory (or in a
    # short-lived Supabase bucket) and never persisted to the prediction log,
    # so it does not need the salt. The LOG key is salted and is None when no
    # salt is configured. Deriving both from `ip_hash` previously meant that a
    # missing IP_HASH_SALT silently disabled rate limiting as well as logging.
    rate_key = hashlib.sha256(ip.encode()).hexdigest() if ip else None
    ip_hash = _hash_ip(ip)

    if _rate_limited(rate_key):
        return JSONResponse(
            status_code=429,
            content={"error": "rate limit exceeded",
                     "limit_per_minute": RATE_LIMIT_PER_MINUTE},
            headers={"Retry-After": "60"},
        )

    x = _vectorise(bundle, body.url)
    score = float(bundle["model"].predict_proba(x.reshape(1, -1))[0, 1])
    verdict = classify_score(score)
    binary_verdict = "malicious" if score >= DEFAULT_THRESHOLD else "benign"
    top = _explain(bundle, x, score)

    _log_prediction(
        # Query string stripped: see _redact_url. The SHA-256 below still
        # identifies repeat submissions of the exact same URL.
        url=_redact_url(body.url),
        url_sha256=hashlib.sha256(body.url.encode()).hexdigest(),
        verdict=verdict,
        binary_verdict=binary_verdict,
        score=round(score, 6),
        model_version=bundle.get("model_version", "unknown"),
        threshold=DEFAULT_THRESHOLD,
        features={d["feature"]: d["value"] for d in top},
        client_ip_hash=ip_hash,
        latency_ms=int((time.time() - started) * 1000),
    )

    disclaimer = (
        "Classification is based on the URL string alone. The service did not "
        "fetch or open this URL. Not a substitute for a security product."
    )
    if verdict == "uncertain":
        disclaimer = (
            f"This URL scored {score:.2f}, inside the model's uncertain band "
            f"({UNCERTAIN_LOW}-{UNCERTAIN_HIGH}). Roughly two thirds of the "
            f"model's mistakes fall in this range, so treat it as 'worth a "
            f"second look' rather than a verdict. " + disclaimer
        )

    return {
        "url": body.url,
        "verdict": verdict,
        "binary_verdict": binary_verdict,
        "score": round(score, 4),
        "threshold": DEFAULT_THRESHOLD,
        "uncertain_band": [UNCERTAIN_LOW, UNCERTAIN_HIGH],
        "model_version": bundle.get("model_version", "unknown"),
        "registrable_domain": registrable_domain(body.url),
        "top_features": top,
        "disclaimer": disclaimer,
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
    # compare_digest, not `!=`: a plain comparison short-circuits on the first
    # differing byte, which leaks the shared secret's prefix through response
    # timing. Impractical over the public internet, trivial to avoid.
    if not presented or not hmac.compare_digest(presented, secret):
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
        upserted = sync_supabase(rows)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(
            status_code=502,
            content={"error": "refresh failed", "detail": str(exc)[:200]},
        )

    # `parsed` and `upserted` are reported SEPARATELY and the status reflects
    # the write, not the read. An earlier version returned the parsed count as
    # "refreshed", so the endpoint answered 200 {"refreshed": 5000} while
    # writing zero rows — a success response for a no-op.
    body = {
        "parsed": len(rows),
        "upserted": upserted,
        "elapsed_ms": int((time.time() - started) * 1000),
    }
    if upserted == 0 and rows:
        body["warning"] = (
            "parsed rows but wrote none — check the Supabase key's write "
            "permission on malicious_hashes"
        )
        return JSONResponse(status_code=502, content=body)
    return body


@app.api_route("/{full_path:path}",
               methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
def fallback(full_path: str, request: Request) -> Any:
    """Catch-all for unmatched paths.

    Registered last, so it only runs when nothing above matched. It reports the
    path the ASGI app actually received, which is the one piece of information
    needed to debug Vercel's routing: a rewrite may deliver either the original
    request path or the rewrite destination, and the difference decides whether
    the real routes above are reachable.

    The received path is echoed back deliberately for that reason, but it is
    truncated — it is attacker-controlled, and there is no case where a
    multi-kilobyte path needs quoting in full.
    """
    path = "/" + full_path

    # A known path with the wrong method is 405, not 404. Without this the
    # catch-all swallows FastAPI's method-mismatch handling and reports a
    # perfectly valid endpoint as nonexistent.
    allowed = _KNOWN_ROUTES.get(path)
    if allowed and request.method not in allowed:
        return JSONResponse(
            status_code=405,
            content={"error": "method not allowed",
                     "path": path,
                     "allowed": list(allowed)},
            headers={"Allow": ", ".join(allowed)},
        )

    return JSONResponse(
        status_code=404,
        content={
            "error": "no such endpoint",
            "received_path": path[:200],
            "available": ["/api/health", "/api/predict", "/api/check-file",
                          "/api/refresh-hashes"],
        },
    )


# Local dev:  uvicorn api.index:app --reload --port 8000
