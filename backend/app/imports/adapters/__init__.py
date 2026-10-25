"""Import adapters, in the release order decided by TBD-023.

Each adapter module exports a single `ADAPTER` instance implementing `app.imports.base.Adapter`.
A format ships only once it has fixtures and tests (TBD-023); unsupported formats are
listed in `UNSUPPORTED` with the reason, surfaced by the API's format-detection error.
"""

from __future__ import annotations

from app.imports.adapters.generic_csv import ADAPTER as GENERIC_CSV
from app.imports.adapters.generic_json import ADAPTER as GENERIC_JSON
from app.imports.adapters.nessus import ADAPTER as NESSUS
from app.imports.adapters.nmap_xml import ADAPTER as NMAP_XML
from app.imports.adapters.nuclei_jsonl import ADAPTER as NUCLEI_JSONL
from app.imports.adapters.pdf_text import ADAPTER as PDF_TEXT
from app.imports.adapters.sarif import ADAPTER as SARIF
from app.imports.base import Adapter

# Order matters: more specific/structured formats are sniffed before the generic fallbacks.
ADAPTERS: list[Adapter] = [
    NMAP_XML,
    NESSUS,
    NUCLEI_JSONL,
    SARIF,
    GENERIC_CSV,
    GENERIC_JSON,
    PDF_TEXT,
]

UNSUPPORTED: dict[str, str] = {
    "zap": "OWASP ZAP export (JSON/XML/HTML): deferred. ZAP's own export schema varies "
    "materially across versions and scan profiles; shipping it without representative "
    "sample exports to build fixtures from would risk silently mis-mapping findings. "
    "Workaround: use the generic JSON adapter with a column_map, or the generic CSV "
    "adapter if exporting ZAP alerts as CSV.",
    "burp": "Burp Suite export (XML/JSON): deferred for the same reason as ZAP (export "
    "shape depends on the Burp edition/version and the exporting extension). Workaround: "
    "the generic JSON/CSV adapters with a column_map.",
}


def detect(filename: str, raw: bytes) -> Adapter | None:
    for adapter in ADAPTERS:
        if adapter.sniff(filename, raw):
            return adapter
    return None
