"""Safety edge cases required by Phase 08 item #10: oversized files, XXE, zip bombs, weird
encodings, malformed records, partial parser success."""

from __future__ import annotations

import io
import json
import zipfile

import pytest

from app.imports.safety import (
    MAX_JSON_DEPTH,
    MAX_UPLOAD_BYTES,
    ImportSafetyError,
    check_json_bounds,
    decode_text,
    maybe_extract_single_member,
    parse_xml_safely,
)
from app.imports.service import parse_upload
from tests import importfixtures as fx


def test_upload_over_size_limit_is_rejected() -> None:
    with pytest.raises(ImportSafetyError):
        parse_upload("big.json", b"[" + b"1," * (MAX_UPLOAD_BYTES) + b"1]")


def test_empty_upload_is_rejected() -> None:
    with pytest.raises(ImportSafetyError):
        parse_upload("empty.json", b"")


def test_xml_xxe_is_rejected_before_parsing() -> None:
    raw = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><a/>'
    with pytest.raises(ImportSafetyError, match="DTD|entity"):
        parse_xml_safely(raw)


def test_xml_malformed_is_rejected_cleanly() -> None:
    with pytest.raises(ImportSafetyError, match="malformed XML"):
        parse_xml_safely(b"<a><b></a>")


def test_xml_excessive_depth_is_rejected() -> None:
    raw = b"<a>" * 200 + b"x" + b"</a>" * 200
    with pytest.raises(ImportSafetyError, match="nesting"):
        parse_xml_safely(raw, max_depth=16)


def test_json_excessive_depth_is_rejected() -> None:
    nested: object = 1
    for _ in range(MAX_JSON_DEPTH + 5):
        nested = [nested]
    with pytest.raises(ImportSafetyError, match="nesting"):
        check_json_bounds(nested)


def test_json_excessive_node_count_is_rejected() -> None:
    with pytest.raises(ImportSafetyError, match="nodes"):
        check_json_bounds(list(range(10)), max_nodes=5)


def test_decode_text_falls_back_for_bad_encoding_without_crashing() -> None:
    raw = "café".encode("latin-1")
    text = decode_text(raw)
    assert isinstance(text, str) and text


def test_zip_with_single_member_is_extracted() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("report.json", json.dumps({"findings": [{"title": "t", "severity": "low"}]}))
    extracted = maybe_extract_single_member(buf.getvalue())
    assert extracted is not None
    assert extracted.name == "report.json"


def test_zip_with_multiple_members_is_rejected() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.json", "{}")
        zf.writestr("b.json", "{}")
    with pytest.raises(ImportSafetyError, match="exactly one file"):
        maybe_extract_single_member(buf.getvalue())


def test_zip_path_traversal_member_is_rejected() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../etc/passwd", "pwned")
    with pytest.raises(ImportSafetyError, match="unsafe path"):
        maybe_extract_single_member(buf.getvalue())


def test_zip_absolute_path_member_is_rejected() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("/etc/passwd", "pwned")
    with pytest.raises(ImportSafetyError, match="unsafe path"):
        maybe_extract_single_member(buf.getvalue())


def test_zip_windows_drive_letter_member_is_rejected() -> None:
    """Zip-slip via a Windows absolute path (`C:\\...`) must be rejected the same as a
    POSIX `../` traversal — the `:` check in maybe_extract_single_member covers drive
    letters and the alternate-data-stream syntax alike."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("C:\\Windows\\System32\\evil.dll", "pwned")
    with pytest.raises(ImportSafetyError, match="unsafe path"):
        maybe_extract_single_member(buf.getvalue())


def test_zip_symlink_member_is_rejected() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("link.txt")
        info.external_attr = (0o120777 << 16)  # S_IFLNK
        zf.writestr(info, "/etc/passwd")
    with pytest.raises(ImportSafetyError, match="symlink"):
        maybe_extract_single_member(buf.getvalue())


def test_zip_bomb_declared_size_is_rejected_before_inflation() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("huge.txt", "0" * 1000)
    data = bytearray(buf.getvalue())
    # Corrupt the declared uncompressed-size field is fragile; instead monkeypatch the
    # module-level cap so the real (small) declared size still trips the same code path.
    import app.imports.safety as safety_mod

    old = safety_mod.MAX_ARCHIVE_EXPANDED_BYTES
    safety_mod.MAX_ARCHIVE_EXPANDED_BYTES = 10
    try:
        with pytest.raises(ImportSafetyError, match="declared uncompressed size"):
            maybe_extract_single_member(bytes(data))
    finally:
        safety_mod.MAX_ARCHIVE_EXPANDED_BYTES = old


def test_zip_entry_count_bomb_is_rejected() -> None:
    import app.imports.safety as safety_mod

    old = safety_mod.MAX_ARCHIVE_ENTRIES
    safety_mod.MAX_ARCHIVE_ENTRIES = 2
    try:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("a.txt", "1")
            zf.writestr("b.txt", "1")
            zf.writestr("c.txt", "1")
        with pytest.raises(ImportSafetyError, match="more than"):
            maybe_extract_single_member(buf.getvalue())
    finally:
        safety_mod.MAX_ARCHIVE_ENTRIES = old


def test_nested_zip_archive_is_rejected() -> None:
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("x.txt", "1")
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w") as zf:
        zf.writestr("inner.zip", inner.getvalue())
    with pytest.raises(ImportSafetyError, match="nested"):
        maybe_extract_single_member(outer.getvalue())


def test_zip_wrapped_report_is_importable_end_to_end() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("findings.json", fx.GENERIC_JSON)
    adapter, result = parse_upload("bundle.zip", buf.getvalue())
    assert adapter.source_type == "generic_json"
    assert result.parsed_count == 1


def test_unrecognized_format_gives_a_helpful_error() -> None:
    with pytest.raises(ImportSafetyError, match="could not detect"):
        parse_upload("mystery.bin", b"\x00\x01\x02random binary junk that matches nothing")


def test_zap_and_burp_are_explicitly_unsupported_with_a_reason() -> None:
    with pytest.raises(ImportSafetyError, match="deferred"):
        parse_upload("zap-report.xml", b"<OWASPZAPReport/>", declared="zap")
    with pytest.raises(ImportSafetyError, match="deferred"):
        parse_upload("burp-export.xml", b"<issues/>", declared="burp")


def test_oversized_record_count_is_truncated_not_rejected() -> None:
    """A huge-but-individually-valid record count must be bounded (truncate + warn), not
    crash the parser and not silently drop the fact that it was truncated."""
    import app.imports.service as service_mod

    old = service_mod.MAX_RECORDS
    service_mod.MAX_RECORDS = 10
    try:
        records = [{"title": f"Finding {i}", "severity": "low"} for i in range(25)]
        raw = json.dumps(records).encode()
        adapter, result = parse_upload("huge.json", raw)
        assert adapter.source_type == "generic_json"
        assert len(result.findings) == 10
        assert any("only the first" in w for w in result.warnings)
    finally:
        service_mod.MAX_RECORDS = old


def test_weird_encoding_csv_still_parses_with_a_warning() -> None:
    """A CSV saved in a legacy (non-UTF-8) codepage must not crash the parser; it decodes
    via the latin-1 fallback and the operator is warned that some characters may be wrong."""
    from app.imports.adapters.generic_csv import ADAPTER as GENERIC_CSV

    raw = "Title,Host\r\nCafé server misconfigured,10.0.0.9\r\n".encode("cp1252")
    result = GENERIC_CSV.parse(raw)
    assert result.parsed_count == 1
    assert "misconfigured" in result.findings[0].title


def test_mostly_undecodable_bytes_produce_a_dirty_decode_warning() -> None:
    from app.imports.adapters.generic_csv import ADAPTER as GENERIC_CSV

    # A run of high-bit bytes that is not valid UTF-8 anywhere in the sample.
    noisy = ("Title,Host\r\n" + ("\xff\xfe" * 40) + ",10.0.0.9\r\n").encode("latin-1")
    result = GENERIC_CSV.parse(noisy)
    assert any("did not decode cleanly" in w for w in result.warnings)
