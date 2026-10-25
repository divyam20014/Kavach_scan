"""PDF import: best-effort text extraction only (MASTER_SPEC §8.2 item 3).

A PDF report's prose cannot be reliably split into discrete findings without inventing
structure that was never actually there. This adapter therefore never attempts to guess a
severity, a CVE, a CWE, or a standards mapping, and never splits the document into multiple
findings. It extracts the text (bounded pages/characters, one bad page skipped rather than
failing the whole file) and produces exactly one `needs_review` draft record carrying the
excerpt, so a human can read it and create/edit findings manually. Extraction coverage
(pages read vs. total, and a truncation flag) is reported so the operator knows how much of
the document they are actually seeing.
"""

from __future__ import annotations

from typing import Any

from app.imports.base import Adapter, ParsedFinding, ParseResult, truncate
from app.imports.safety import ImportSafetyError
from app.models.common import Confidence, Severity

PARSER_VERSION = "vapt-import-pdf-text 1.0.0"
MAX_PAGES = 300
MAX_TOTAL_CHARS = 400_000
MAX_EXCERPT_CHARS = 8000  # matches the evidence excerpt cap used elsewhere in the app


class PdfTextAdapter:
    source_type = "pdf_text"
    label = "PDF (best-effort text extraction)"
    parser_version = PARSER_VERSION

    def sniff(self, filename: str, raw: bytes) -> bool:
        return filename.lower().endswith(".pdf") or raw[:5] == b"%PDF-"

    def parse(self, raw: bytes, *, options: dict[str, Any] | None = None) -> ParseResult:
        import io

        try:
            from pypdf import PdfReader
            from pypdf.errors import PdfReadError
        except ImportError as exc:  # pragma: no cover - dependency is always installed
            raise ImportSafetyError("PDF support is not available in this build") from exc
        result = ParseResult()
        try:
            reader = PdfReader(io.BytesIO(raw), strict=False)
        except (PdfReadError, ValueError, OSError) as exc:
            raise ImportSafetyError(f"could not open PDF: {exc}") from exc
        if getattr(reader, "is_encrypted", False):
            try:
                reader.decrypt("")  # best effort: only succeeds for an empty/owner-only password
            except Exception:  # noqa: BLE001, S110 - fall through to the clear error below
                pass
            if reader.is_encrypted:
                raise ImportSafetyError("PDF is password-protected; it cannot be read")
        total_pages = len(reader.pages)
        pages_read = min(total_pages, MAX_PAGES)
        chunks: list[str] = []
        total_chars = 0
        truncated = total_pages > MAX_PAGES
        for i in range(pages_read):
            try:
                text = reader.pages[i].extract_text() or ""
            except Exception as exc:  # noqa: BLE001 - one unreadable page must not fail the import
                result.warn(f"page {i + 1}: text extraction failed ({type(exc).__name__}); skipped")
                continue
            if total_chars + len(text) > MAX_TOTAL_CHARS:
                text = text[: max(0, MAX_TOTAL_CHARS - total_chars)]
                truncated = True
            chunks.append(text)
            total_chars += len(text)
            if total_chars >= MAX_TOTAL_CHARS:
                truncated = True
                break
        full_text = "\n\n".join(c for c in chunks if c.strip())
        if not full_text.strip():
            result.warn(
                "no extractable text was found (the PDF may be scanned images with no "
                "OCR layer); nothing was imported"
            )
            return result
        meta_title = ""
        try:
            meta = reader.metadata
            meta_title = str(meta.title) if meta and meta.title else ""
        except Exception:  # noqa: BLE001, S110 - metadata is optional
            pass
        coverage = f"{pages_read} of {total_pages} page(s) read" + (
            " (truncated)" if truncated else ""
        )
        result.warn(
            f"extracted {coverage}; automatic extraction cannot reliably identify "
            "discrete findings - review the text below and create/edit findings manually"
        )
        result.findings.append(
            ParsedFinding(
                title=truncate(meta_title or "Imported PDF report (needs manual review)", 300),
                severity=Severity.INFORMATIONAL,  # never guessed from unstructured text
                confidence=Confidence.NEEDS_REVIEW,
                summary=truncate(
                    "Automatically extracted text from a PDF upload. No severity, CVE, or CWE was "
                    "inferred; review this excerpt and create or edit findings manually.\n\n"
                    + full_text[:MAX_EXCERPT_CHARS],
                    MAX_EXCERPT_CHARS + 400,
                ),
                technical_detail=truncate(f"Extraction coverage: {coverage}.", 500),
                category="needs-manual-review",
                rule_id="pdf-text-extract",
                source_finding_id="pdf-text",
            )
        )
        result.parsed_count += 1
        return result


ADAPTER: Adapter = PdfTextAdapter()
