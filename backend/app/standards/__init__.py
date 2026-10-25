"""Versioned local standards catalogs (MASTER_SPEC Module 9, TBD-020).

Every catalog carries its own version, independent of the others (OWASP Web Top 10 and
OWASP API Security Top 10 are tracked separately, per TBD-020), plus provenance: where it
came from and when this codebase's copy of it was written. No catalog is fetched over the
network (TBD-018: external lookups are disabled by default) and nothing here is a complete
reproduction of an external standard — each catalog documents exactly what it covers and
anything it does not.

A `Finding.mappings` entry (`app.models.finding.StandardMapping`) copies the catalog_version
and title it was created with, so an existing finding's recorded mapping never changes
retroactively when a catalog here is later updated to a new version — a documented
PROPOSED decision in TBD_DECISIONS.md.
"""

from __future__ import annotations

from app.scanners.apisec.rules import OWASP_API_TITLES, OWASP_API_VERSION
from app.scanners.webapp.rules import OWASP_TITLES, OWASP_VERSION
from app.standards.cwe import CWE_CATALOG_VERSION, CWE_IMPORTED_AT, CWE_SOURCE, CWE_TITLES
from app.standards.cwe import cwe_title as cwe_title


class CatalogInfo:
    def __init__(
        self,
        *,
        catalog: str,
        version: str,
        label: str,
        source: str,
        imported_at: str,
        entry_count: int,
        coverage_note: str,
    ) -> None:
        self.catalog = catalog
        self.version = version
        self.label = label
        self.source = source
        self.imported_at = imported_at
        self.entry_count = entry_count
        self.coverage_note = coverage_note


CATALOGS: dict[str, CatalogInfo] = {
    "owasp_top10": CatalogInfo(
        catalog="owasp_top10",
        version=OWASP_VERSION,
        label=f"OWASP Top 10:{OWASP_VERSION}",
        source="https://owasp.org/Top10/",
        imported_at="2026-10-21",  # when this codebase's category list was written (Phase 05)
        entry_count=len(OWASP_TITLES),
        coverage_note=(
            "Only the categories the web/surface rule catalogs actually assign to a check "
            f"are listed here ({len(OWASP_TITLES)} of 10); this is not the full published "
            "Top 10 list, and a rule's mapping is a related-category assignment, never a "
            "claimed one-to-one equivalence."
        ),
    ),
    "owasp_api_top10": CatalogInfo(
        catalog="owasp_api_top10",
        version=OWASP_API_VERSION,
        label=f"OWASP API Security Top 10:{OWASP_API_VERSION}",
        source="https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
        imported_at="2026-10-21",  # Phase 07
        entry_count=len(OWASP_API_TITLES),
        coverage_note=(
            f"Only the categories the API rule catalog assigns ({len(OWASP_API_TITLES)} of "
            "10) are listed; same related-category caveat as the web Top 10."
        ),
    ),
    "cwe": CatalogInfo(
        catalog="cwe",
        version=CWE_CATALOG_VERSION,
        label="CWE (curated subset)",
        source=CWE_SOURCE,
        imported_at=CWE_IMPORTED_AT,
        entry_count=len(CWE_TITLES),
        coverage_note=(
            f"Only the {len(CWE_TITLES)} CWE IDs this codebase's rule catalogs currently "
            "reference are titled here — not the full MITRE CWE list. A finding may carry "
            "a CWE ID with no title if it falls outside this subset; that is shown "
            "honestly, never invented."
        ),
    ),
}


def catalog_version(catalog: str) -> str:
    return CATALOGS[catalog].version
