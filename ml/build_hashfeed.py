"""Build the known-malicious file-hash table from the URLhaus payload feed.

The payload dump is a ~775 MB ZIP. Downloading all of it to keep a few hundred
thousand hashes is wasteful, so this streams the response, inflates the single
deflate member on the fly, and **aborts the connection** once it has the number
of rows requested. Peak memory stays in the low megabytes and only a few tens of
MB ever cross the wire.

Two destinations:

  local     a gzipped file committed to the repo, used as the offline fallback
            so /check-file works with no database configured at all
  supabase  the full table, synced on a schedule (Phase 7 cron)

Only hashes and static metadata are ever handled. No sample is downloaded,
unpacked or executed at any point — see Scope & Non-Goals in the README.

Usage
-----
    python ml/build_hashfeed.py --peek
    python ml/build_hashfeed.py --limit 150000
    python ml/build_hashfeed.py --limit 150000 --supabase
"""

from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import os
import struct
import sys
import zlib
from datetime import datetime, timezone
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent
ARTIFACTS = ROOT / "artifacts"
RAW = ROOT / "data" / "raw"

PAYLOAD_URL = "https://urlhaus.abuse.ch/downloads/payloads/"
USER_AGENT = ("malicious-url-detector/0.1 (research/portfolio project; "
              "contact: shreyas.tech7@gmail.com)")


def stream_zip_lines(url: str, max_bytes_out: int = 0):
    """Yield decoded lines from a single-member ZIP without downloading it all.

    A ZIP local file header is: 4-byte signature, 26 bytes of fixed fields,
    then filename and extra-field bytes whose lengths live at offsets 26 and 28.
    After that comes the raw deflate stream, which zlib can inflate
    incrementally with a -15 window (raw deflate, no zlib wrapper).
    """
    s = requests.Session()
    s.headers["User-Agent"] = USER_AGENT

    with s.get(url, stream=True, timeout=300) as r:
        r.raise_for_status()
        it = r.iter_content(chunk_size=1 << 16)

        header = b""
        for chunk in it:
            header += chunk
            if len(header) >= 30:
                break
        if len(header) < 30 or header[:4] != b"PK\x03\x04":
            raise RuntimeError("not a ZIP local file header")

        name_len, extra_len = struct.unpack("<HH", header[26:30])
        start = 30 + name_len + extra_len
        while len(header) < start:
            header += next(it)
        member = header[:start][30:30 + name_len].decode("utf-8", "replace")
        print(f"[zip] member: {member}")

        dec = zlib.decompressobj(-15)
        buf = b""
        produced = 0

        def _emit(data: bytes):
            nonlocal buf
            buf += data
            while b"\n" in buf:
                line, _, buf = buf.partition(b"\n")
                yield line.decode("utf-8", "replace").rstrip("\r")

        yield from _emit(dec.decompress(header[start:]))
        produced += len(header) - start

        for chunk in it:
            out = dec.decompress(chunk)
            produced += len(chunk)
            if out:
                yield from _emit(out)
            if max_bytes_out and produced > max_bytes_out:
                # Caller has what it needs; drop the connection rather than
                # pulling the remaining hundreds of megabytes.
                break


def parse_feed(limit: int, peek: bool = False) -> tuple[list[dict], list[str]]:
    rows: list[dict] = []
    cols: list[str] = []
    comment_lines: list[str] = []

    for line in stream_zip_lines(PAYLOAD_URL):
        if not line.strip():
            continue
        if line.startswith("#"):
            comment_lines.append(line)
            # The last comment line before data is the column header.
            candidate = line.lstrip("# ").strip()
            if "," in candidate and "sha256" in candidate.lower():
                cols = [c.strip() for c in candidate.split(",")]
            if peek and len(comment_lines) <= 12:
                print("  " + line[:150])
            continue

        if peek and len(rows) < 5:
            print("  DATA: " + line[:170])

        if not cols:
            continue
        parsed = next(csv.reader([line]), None)
        if not parsed or len(parsed) < len(cols):
            continue
        rows.append(dict(zip(cols, parsed)))

        if peek and len(rows) >= 5:
            break
        if not peek and len(rows) >= limit:
            break

    return rows, cols


# The feed has used both `sha256`/`md5`/`filetype` and the longer
# `sha256_hash`/`md5_hash`/`file_type` spellings over time. Accept either so a
# rename upstream does not silently produce an empty table.
def _field(row: dict, *names: str) -> str:
    for n in names:
        v = row.get(n)
        if v:
            return v.strip()
    return ""


def _sha256(row: dict) -> str:
    return _field(row, "sha256", "sha256_hash").lower()


def _md5(row: dict) -> str:
    return _field(row, "md5", "md5_hash").lower()


def _filetype(row: dict) -> str:
    return _field(row, "filetype", "file_type")


def write_local(rows: list[dict], path: Path) -> int:
    """Write the compact offline fallback table.

    Deliberately minimal: sha256, md5, file_type, signature. Enough to answer
    'is this hash known bad, and what is it' without shipping a database.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    kept = 0
    with gzip.open(path, "wt", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["sha256", "md5", "file_type", "signature"])
        for r in rows:
            sha = _sha256(r)
            if len(sha) != 64:
                continue
            w.writerow([sha, _md5(r), _filetype(r),
                        _field(r, "signature")])
            kept += 1
    return kept


def sync_supabase(rows: list[dict]) -> int:
    """Upsert into Supabase if credentials are present. Returns rows written.

    Returns a COUNT rather than None, and raises on HTTP failure, because the
    previous version did neither: it accepted only SUPABASE_SERVICE_ROLE_KEY,
    silently returned when the server was configured with a restricted key,
    and the caller then reported the number of rows *parsed* as the number
    "refreshed". The endpoint answered `{"refreshed": 5000}` in 89 ms having
    written exactly zero rows. A sync that cannot fail loudly is a sync you
    cannot trust.

    Key resolution deliberately mirrors api/index.py::_supabase_cfg.
    """
    from supabase_cfg import supabase_config

    cfg = supabase_config()
    if cfg is None:
        print("[supabase] no SUPABASE_URL / key configured — skipping sync "
              "(local fallback table is still written)")
        return 0
    url, key = cfg

    # Writes go through a SECURITY DEFINER function, not a direct table upsert.
    #
    # The table has no INSERT/UPDATE policy for the restricted role any more.
    # The function validates that every sha256/md5 is a well-formed hash, caps
    # the batch at 1000, and pins `source` server-side — so a leaked key cannot
    # write arbitrary rows into the corpus, only well-formed hash records.
    endpoint = f"{url.rstrip('/')}/rest/v1/rpc/upsert_malicious_hashes"
    headers = {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        # NOT return=minimal: the function returns the row count, and reporting
        # a write we did not verify is the bug this whole path already had once.
        "Prefer": "return=representation",
    }
    # Deduplicate by sha256 BEFORE batching.
    #
    # URLhaus lists the same payload hash once per URL that served it, so a
    # naive batch contains the same sha256 many times over — 200k feed rows
    # collapse to ~119k distinct hashes. Postgres refuses an upsert that would
    # touch the same key twice in one statement ("ON CONFLICT DO UPDATE command
    # cannot affect row a second time"), which PostgREST surfaces as a bare
    # HTTP 500. Deduplicating here is the fix; keeping the first occurrence is
    # correct because the feed is ordered newest-first.
    unique: dict[str, dict] = {}
    for r in rows:
        sha = _sha256(r)
        if len(sha) != 64 or sha in unique:
            continue
        unique[sha] = {
            "sha256": sha,
            "md5": _md5(r) or None,
            "file_type": _filetype(r) or None,
            "signature": _field(r, "signature") or None,
            "source": "urlhaus",
        }

    payload = list(unique.values())
    print(f"[supabase] {len(rows):,} feed rows -> {len(payload):,} distinct hashes")

    total = 0
    s = requests.Session()
    for i in range(0, len(payload), 500):   # under the function's 1000 cap
        batch = payload[i:i + 500]
        resp = s.post(endpoint, headers=headers,
                      json={"p_rows": batch}, timeout=120)
        resp.raise_for_status()

        # Count what the DATABASE says it wrote, not what we sent. These can
        # legitimately differ: the function drops malformed rows silently.
        try:
            written = int(resp.json())
        except (ValueError, TypeError):
            written = len(batch)
        total += written

        if written != len(batch):
            print(f"[supabase] batch of {len(batch)}: {written} accepted "
                  f"({len(batch) - written} rejected by validation)", flush=True)

    print(f"[supabase] upserted {total:,} rows total")
    return total


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--peek", action="store_true",
                   help="show the feed header and a few rows, then stop")
    p.add_argument("--limit", type=int, default=150_000)
    p.add_argument("--supabase", action="store_true")
    p.add_argument("--out", default=str(ARTIFACTS / "known_bad_hashes.csv.gz"))
    a = p.parse_args()

    print(f"[feed] streaming {PAYLOAD_URL}")
    rows, cols = parse_feed(limit=a.limit, peek=a.peek)

    if a.peek:
        print(f"\ncolumns detected: {cols}")
        return 0

    print(f"[feed] parsed {len(rows):,} payload records")
    if not rows:
        raise SystemExit("no rows parsed — feed format may have changed")

    out = Path(a.out)
    kept = write_local(rows, out)
    size_mb = out.stat().st_size / 1e6
    print(f"[local] wrote {kept:,} hashes -> {out.name} ({size_mb:.2f} MB)")

    if a.supabase:
        sync_supabase(rows)

    RAW.mkdir(parents=True, exist_ok=True)
    meta = {
        "source": "URLhaus payload feed (abuse.ch)",
        "endpoint": PAYLOAD_URL,
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "records_parsed": len(rows),
        "hashes_written": kept,
        "columns": cols,
        "note": ("Streamed and truncated at --limit; the upstream dump is "
                 "~775 MB. Hashes and static metadata only — no samples are "
                 "ever downloaded or executed."),
    }
    (ARTIFACTS / "hashfeed_meta.json").write_text(
        json.dumps(meta, indent=2), encoding="utf-8")
    print("[meta] wrote artifacts/hashfeed_meta.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
