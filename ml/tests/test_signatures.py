"""Unit tests for hash lookup and static file-metadata analysis."""

import csv
import gzip

import pytest

from signatures import (
    DEFAULT_HASH_TABLE,
    HashIndex,
    check_file_signature,
    classify_hash,
    identify_magic,
    inspect_file_metadata,
    split_extensions,
)


# --------------------------------------------------------------------------
# Hash classification
# --------------------------------------------------------------------------
@pytest.mark.parametrize("value,expected", [
    ("a" * 64, "sha256"),
    ("F" * 64, "sha256"),
    ("b" * 40, "sha1"),
    ("c" * 32, "md5"),
    ("", None),
    ("not-a-hash", None),
    ("a" * 63, None),
    ("g" * 64, None),          # non-hex
    ("  " + "a" * 64 + "  ", "sha256"),  # surrounding whitespace tolerated
])
def test_classify_hash(value, expected):
    assert classify_hash(value) == expected


def test_invalid_hash_is_rejected_not_guessed():
    res = check_file_signature("definitely not a hash")
    assert res["known_malicious"] is False
    assert "error" in res


# --------------------------------------------------------------------------
# Filename parsing
# --------------------------------------------------------------------------
@pytest.mark.parametrize("name,expected", [
    ("invoice.pdf.exe", ["pdf", "exe"]),
    ("report.pdf", ["pdf"]),
    ("archive.tar.gz", ["tar", "gz"]),
    ("noextension", []),
    ("C:\\Users\\x\\payload.scr", ["scr"]),
    ("/tmp/a/b/thing.TXT", ["txt"]),
])
def test_split_extensions(name, expected):
    assert split_extensions(name) == expected


# --------------------------------------------------------------------------
# Magic bytes
# --------------------------------------------------------------------------
@pytest.mark.parametrize("header,is_exec", [
    (b"MZ\x90\x00", True),
    (b"\x7fELF\x02\x01", True),
    (b"#!/bin/sh\n", True),
    (b"%PDF-1.7", False),
    (b"\x89PNG\r\n", False),
    (b"PK\x03\x04", False),
])
def test_identify_magic(header, is_exec):
    label, exec_flag = identify_magic(header)
    assert label is not None
    assert exec_flag is is_exec


def test_unknown_magic_returns_none():
    label, exec_flag = identify_magic(b"\x00\x01\x02\x03")
    assert label is None
    assert exec_flag is False


# --------------------------------------------------------------------------
# Static metadata analysis
# --------------------------------------------------------------------------
def test_double_extension_is_high_suspicion():
    res = inspect_file_metadata(filename="invoice.pdf.exe")
    assert res["suspicion"] == "high"
    assert any(f["check"] == "double_extension" for f in res["findings"])


def test_plain_pdf_is_not_suspicious():
    res = inspect_file_metadata(filename="report.pdf",
                                declared_mime="application/pdf",
                                header=b"%PDF-1.7")
    assert res["suspicion"] == "none"
    assert res["findings"] == []


def test_exe_content_named_as_pdf_is_caught():
    """Filename claims PDF, magic bytes say Windows executable."""
    res = inspect_file_metadata(filename="statement.pdf", header=b"MZ\x90\x00")
    assert res["suspicion"] == "high"
    assert any(f["check"] == "extension_content_mismatch"
               for f in res["findings"])


def test_mime_extension_mismatch_flagged():
    res = inspect_file_metadata(filename="photo.png",
                                declared_mime="text/html")
    assert any(f["check"] == "mime_extension_mismatch"
               for f in res["findings"])


def test_octet_stream_does_not_trigger_mime_mismatch():
    """application/octet-stream is a generic fallback, not a contradiction."""
    res = inspect_file_metadata(filename="report.pdf",
                                declared_mime="application/octet-stream",
                                header=b"%PDF-1.7")
    assert not any(f["check"] == "mime_extension_mismatch"
                   for f in res["findings"])


def test_bare_executable_is_medium_not_high():
    res = inspect_file_metadata(filename="setup.exe", header=b"MZ\x90\x00")
    assert res["suspicion"] == "medium"


def test_empty_input_is_handled():
    res = inspect_file_metadata()
    assert res["suspicion"] == "none"
    assert res["extensions"] == []


def test_metadata_result_states_no_execution():
    assert "neither executed nor" in inspect_file_metadata(
        filename="x.exe")["note"]


# --------------------------------------------------------------------------
# Hash table lookup (against the real committed snapshot)
# --------------------------------------------------------------------------
@pytest.mark.skipif(not DEFAULT_HASH_TABLE.exists(),
                    reason="hash table not built; run ml/build_hashfeed.py")
def test_known_bad_hash_is_found():
    """Take a real hash out of the shipped table and confirm it is flagged."""
    with gzip.open(DEFAULT_HASH_TABLE, "rt", encoding="utf-8") as fh:
        row = next(csv.DictReader(fh))
    sha = row["sha256"]

    idx = HashIndex()
    verdict = idx.lookup_local(sha)
    assert verdict.known_malicious is True
    assert verdict.hash_type == "sha256"
    assert verdict.lookup_backend == "local"


@pytest.mark.skipif(not DEFAULT_HASH_TABLE.exists(),
                    reason="hash table not built; run ml/build_hashfeed.py")
def test_unknown_hash_is_not_flagged_but_is_hedged():
    idx = HashIndex()
    verdict = idx.lookup_local("0" * 64)
    assert verdict.known_malicious is False

    res = check_file_signature("0" * 64, index=idx)
    # A miss against a truncated snapshot must not read as "this is safe".
    assert res["known_malicious"] is False
    assert "note" in res and "does not mean the file is safe" in res["note"]


@pytest.mark.skipif(not DEFAULT_HASH_TABLE.exists(),
                    reason="hash table not built; run ml/build_hashfeed.py")
def test_hash_table_is_populated():
    assert HashIndex().size > 1000
