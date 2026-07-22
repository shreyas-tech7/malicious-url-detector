"""File-signature checking: known-bad hash lookup + static metadata analysis.

Shared by the training-side tooling and the inference function, same as
features.py.

Scope boundary (this is a hard line, not a preference)
-----------------------------------------------------
Nothing here downloads, unpacks, decodes, emulates or executes a file. The two
things it does are:

  1. look a hash up in a table of known-bad hashes
  2. reason about *metadata* — filename, declared MIME type, and at most the
     first few dozen bytes of a file, used only to read magic numbers

That is the whole of "file-signature checking" in this project. Dynamic
analysis is a sandboxing problem with a completely different threat model and
is explicitly out of scope.

Callers are expected to send a hash the client computed locally, optionally
with a small header sample. The API caps that sample (see api/index.py) so the
service never ingests whole binaries.
"""

from __future__ import annotations

import csv
import gzip
import os
import re
from dataclasses import dataclass, asdict
from pathlib import Path

ARTIFACTS = Path(__file__).resolve().parent / "artifacts"
DEFAULT_HASH_TABLE = ARTIFACTS / "known_bad_hashes.csv.gz"

_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")


def classify_hash(value: str) -> str | None:
    """Return 'sha256' | 'md5' | 'sha1' | None for a candidate hash string."""
    v = (value or "").strip()
    if _SHA256_RE.match(v):
        return "sha256"
    if _SHA1_RE.match(v):
        return "sha1"
    if _MD5_RE.match(v):
        return "md5"
    return None


# --------------------------------------------------------------------------
# Magic numbers
# --------------------------------------------------------------------------
#: (magic bytes, label, is_executable)
MAGIC_SIGNATURES: tuple[tuple[bytes, str, bool], ...] = (
    (b"MZ",                      "PE/DOS executable (Windows .exe/.dll)", True),
    (b"\x7fELF",                 "ELF executable (Linux/Unix)", True),
    (b"\xfe\xed\xfa\xce",        "Mach-O executable (32-bit)", True),
    (b"\xfe\xed\xfa\xcf",        "Mach-O executable (64-bit)", True),
    (b"\xcf\xfa\xed\xfe",        "Mach-O executable (64-bit, LE)", True),
    (b"\xca\xfe\xba\xbe",        "Java class / Mach-O fat binary", True),
    (b"#!",                      "script with shebang", True),
    (b"%PDF",                    "PDF document", False),
    (b"PK\x03\x04",              "ZIP archive (also .docx/.xlsx/.jar/.apk)", False),
    (b"Rar!\x1a\x07",            "RAR archive", False),
    (b"\x1f\x8b",                "gzip archive", False),
    (b"7z\xbc\xaf\x27\x1c",      "7-Zip archive", False),
    (b"\xd0\xcf\x11\xe0",        "legacy MS Office (OLE2)", False),
    (b"\x89PNG",                 "PNG image", False),
    (b"\xff\xd8\xff",            "JPEG image", False),
    (b"GIF8",                    "GIF image", False),
    (b"BM",                      "BMP image", False),
)

#: Extensions that execute (directly or via a script host) on a normal desktop.
EXECUTABLE_EXTENSIONS = frozenset({
    "exe", "dll", "scr", "com", "pif", "cpl", "msi", "msp", "jar", "app",
    "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh",
    "hta", "lnk", "sh", "bash", "elf", "so", "dylib", "apk", "reg", "inf",
})

#: Extensions users are conditioned to treat as harmless documents. A double
#: extension pairing one of these with an executable one is the classic
#: `invoice.pdf.exe` trick.
DECOY_EXTENSIONS = frozenset({
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv",
    "jpg", "jpeg", "png", "gif", "bmp", "mp3", "mp4", "avi", "zip", "rar",
    "html", "htm",
})

#: Minimal extension -> expected MIME map, for mismatch detection.
EXT_MIME = {
    "pdf": {"application/pdf"},
    "png": {"image/png"},
    "jpg": {"image/jpeg"}, "jpeg": {"image/jpeg"},
    "gif": {"image/gif"},
    "zip": {"application/zip", "application/x-zip-compressed"},
    "txt": {"text/plain"},
    "csv": {"text/csv", "text/plain"},
    "html": {"text/html"}, "htm": {"text/html"},
    "json": {"application/json"},
    "exe": {"application/x-msdownload", "application/vnd.microsoft.portable-executable",
            "application/octet-stream"},
    "docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    "xlsx": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
}


# --------------------------------------------------------------------------
@dataclass
class HashVerdict:
    known_malicious: bool
    hash_type: str | None
    source: str | None = None
    file_type: str | None = None
    signature: str | None = None
    lookup_backend: str = "none"

    def to_dict(self) -> dict:
        return asdict(self)


class HashIndex:
    """Known-bad hash lookup.

    Prefers Supabase when configured; falls back to the committed local table
    so /check-file works with zero configuration. The local table is a
    truncated snapshot, which the verdict reports honestly via
    `lookup_backend`.
    """

    def __init__(self, path: Path | None = None):
        self._path = Path(path) if path else DEFAULT_HASH_TABLE
        self._sha: dict[str, tuple[str, str]] | None = None
        self._md5: dict[str, tuple[str, str]] | None = None

    def _ensure_loaded(self) -> None:
        """Load lazily.

        /predict is the hot path and does not need this table; paying a few
        hundred milliseconds of cold start for it on every request would be
        wasteful.
        """
        if self._sha is not None:
            return
        self._sha, self._md5 = {}, {}
        if not self._path.exists():
            return
        with gzip.open(self._path, "rt", encoding="utf-8", newline="") as fh:
            for row in csv.DictReader(fh):
                meta = (row.get("file_type") or "", row.get("signature") or "")
                sha = (row.get("sha256") or "").lower()
                md5 = (row.get("md5") or "").lower()
                if sha:
                    self._sha[sha] = meta
                if md5:
                    self._md5[md5] = meta

    @property
    def size(self) -> int:
        self._ensure_loaded()
        return len(self._sha or {})

    def lookup_local(self, value: str) -> HashVerdict:
        kind = classify_hash(value)
        if kind is None:
            return HashVerdict(False, None, lookup_backend="local")
        self._ensure_loaded()
        v = value.strip().lower()
        table = self._sha if kind == "sha256" else (
            self._md5 if kind == "md5" else {})
        hit = (table or {}).get(v)
        if hit:
            return HashVerdict(True, kind, source="urlhaus",
                               file_type=hit[0] or None,
                               signature=hit[1] or None,
                               lookup_backend="local")
        return HashVerdict(False, kind, lookup_backend="local")


def lookup_supabase(value: str) -> HashVerdict | None:
    """Query Supabase for a hash. Returns None when not configured or on error.

    Returning None (rather than a negative verdict) matters: a database outage
    must not be reported to the caller as 'this file is clean'.
    """
    from supabase_cfg import supabase_config

    cfg = supabase_config()
    kind = classify_hash(value)
    if cfg is None or kind is None:
        return None
    url, key = cfg

    try:
        import requests
    except ImportError:
        return None

    column = {"sha256": "sha256", "md5": "md5"}.get(kind)
    if column is None:
        return None

    try:
        r = requests.get(
            f"{url.rstrip('/')}/rest/v1/malicious_hashes",
            params={column: f"eq.{value.strip().lower()}",
                    "select": "sha256,md5,file_type,signature,source",
                    "limit": 1},
            headers={"apikey": key, "Authorization": f"Bearer {key}"},
            timeout=5,
        )
        if r.status_code != 200:
            return None
        rows = r.json()
    except Exception:
        return None

    if not rows:
        return HashVerdict(False, kind, lookup_backend="supabase")
    row = rows[0]
    return HashVerdict(
        True, kind, source=row.get("source") or "urlhaus",
        file_type=row.get("file_type"), signature=row.get("signature"),
        lookup_backend="supabase",
    )


_DEFAULT_INDEX = HashIndex()


def check_file_signature(value: str, index: HashIndex | None = None) -> dict:
    """Look a hash up. Supabase first, then the committed local snapshot."""
    kind = classify_hash(value)
    if kind is None:
        return {
            "known_malicious": False,
            "hash_type": None,
            "error": "not a valid md5, sha1 or sha256 hash",
            "lookup_backend": "none",
        }

    remote = lookup_supabase(value)
    if remote is not None:
        return remote.to_dict()

    idx = index or _DEFAULT_INDEX
    verdict = idx.lookup_local(value)
    d = verdict.to_dict()
    if not d["known_malicious"]:
        # Be explicit that a miss against a truncated local snapshot is weak
        # evidence, not a clean bill of health.
        d["note"] = (
            "No match in the local snapshot, which is a truncated subset of "
            "the URLhaus payload feed. Absence of a match does not mean the "
            "file is safe."
        )
    return d


# --------------------------------------------------------------------------
# Static metadata analysis
# --------------------------------------------------------------------------
def split_extensions(filename: str) -> list[str]:
    name = (filename or "").strip().replace("\\", "/").split("/")[-1]
    parts = [p for p in name.split(".") if p != ""]
    return [p.lower() for p in parts[1:]] if len(parts) > 1 else []


def identify_magic(header: bytes) -> tuple[str | None, bool]:
    """Return (label, is_executable) for the leading bytes of a file."""
    for magic, label, is_exec in MAGIC_SIGNATURES:
        if header.startswith(magic):
            return label, is_exec
    return None, False


def inspect_file_metadata(
    filename: str | None = None,
    declared_mime: str | None = None,
    header: bytes | None = None,
) -> dict:
    """Static checks over filename / MIME / magic bytes.

    Returns findings plus a coarse `suspicion` level. This is heuristic triage,
    not a verdict — it is reported alongside the hash lookup, never instead
    of it.
    """
    findings: list[dict] = []
    exts = split_extensions(filename or "")
    final_ext = exts[-1] if exts else None

    magic_label, magic_is_exec = (None, False)
    if header:
        magic_label, magic_is_exec = identify_magic(header)

    # 1. Double extension with a document-looking decoy: invoice.pdf.exe
    if len(exts) >= 2 and final_ext in EXECUTABLE_EXTENSIONS:
        if any(e in DECOY_EXTENSIONS for e in exts[:-1]):
            findings.append({
                "check": "double_extension",
                "severity": "high",
                "detail": (f"Filename ends in .{final_ext} but is disguised "
                           f"with a preceding .{exts[-2]} extension — the "
                           f"classic invoice.pdf.exe pattern."),
            })

    # 2. Executable extension at all.
    if final_ext in EXECUTABLE_EXTENSIONS:
        findings.append({
            "check": "executable_extension",
            "severity": "medium",
            "detail": f".{final_ext} executes on a typical desktop.",
        })

    # 3. Magic bytes say executable.
    if magic_is_exec:
        findings.append({
            "check": "executable_magic_bytes",
            "severity": "medium",
            "detail": f"Header identifies the content as: {magic_label}.",
        })

    # 4. Extension vs magic bytes disagree — the strongest static signal here,
    #    because it means the filename is actively lying about the content.
    if magic_label and final_ext:
        looks_exec_content = magic_is_exec
        claims_doc = final_ext in DECOY_EXTENSIONS
        if looks_exec_content and claims_doc:
            findings.append({
                "check": "extension_content_mismatch",
                "severity": "high",
                "detail": (f"File is named .{final_ext} but its magic bytes "
                           f"identify it as {magic_label}."),
            })

    # 5. Declared MIME vs extension.
    if declared_mime and final_ext:
        expected = EXT_MIME.get(final_ext)
        mime = declared_mime.split(";")[0].strip().lower()
        if expected and mime not in expected and mime != "application/octet-stream":
            findings.append({
                "check": "mime_extension_mismatch",
                "severity": "medium",
                "detail": (f"Declared MIME {mime} does not match the .{final_ext} "
                           f"extension (expected one of "
                           f"{', '.join(sorted(expected))})."),
            })

    severities = {f["severity"] for f in findings}
    if "high" in severities:
        suspicion = "high"
    elif "medium" in severities:
        suspicion = "medium"
    elif findings:
        suspicion = "low"
    else:
        suspicion = "none"

    return {
        "suspicion": suspicion,
        "extensions": exts,
        "magic": magic_label,
        "magic_is_executable": magic_is_exec,
        "findings": findings,
        "note": ("Static metadata only. The file was neither executed nor "
                 "unpacked."),
    }
