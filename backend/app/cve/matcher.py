"""Storage-backed implementation of `app.scanners.webapp.components.CveCatalog`.

Matching is product-name exact match (case-insensitive) only — no fuzzy/substring matching,
since a wrong match would fabricate a vulnerability claim. Version matching distinguishes an
"exact" catalog entry (`version_spec == "==X"`, pinning one version) from a "range" entry;
callers (e.g. `components.cve_results`) use this to keep a range match at `needs_review`
confidence rather than ever presenting it as confirmed (the acceptance criterion: "If
ambiguous, create an observation or needs_review candidate, not confirmed vulnerability").
"""

from __future__ import annotations

from app.cve.version import is_exact_spec, version_satisfies_spec
from app.models.common import utc_now
from app.models.cve_catalog import CveCatalogRecord
from app.scanners.webapp.components import CveMatch
from app.storage.repository import StorageRepository


class StoredCveCatalog:
    """Reads the single active, operator-imported catalog from storage on every call.

    No in-process caching: catalogs are small enough (bounded to 20,000 entries) that a
    fresh read per scan is cheap, and it guarantees a newly imported catalog takes effect
    immediately without restarting the app. `catalog_id`/`catalog_version`/`updated_at`/
    `stale` are plain (not computed-property) attributes, refreshed by `_refresh()`, because
    the `CveCatalog` protocol declares them as settable attributes, matching `NoCveCatalog`."""

    reason = "No local CVE catalog has been imported; CVE matching was not performed."

    def __init__(self, repo: StorageRepository) -> None:
        self._repo = repo
        self.catalog_id = "none"
        self.catalog_version = ""
        self.updated_at = ""
        self.stale = False

    def _refresh(self) -> CveCatalogRecord | None:
        current = self._repo.get_cve_catalog()
        self.catalog_id = current.source if current else "none"
        self.catalog_version = current.catalog_version if current else ""
        self.updated_at = current.imported_at.isoformat() if current else ""
        # Same `age_days > stale_after_days` rule as `app/api/settings.py::_catalog_response`.
        age_days = (utc_now() - current.imported_at).days if current else 0
        self.stale = current is not None and age_days > current.stale_after_days
        return current

    @property
    def available(self) -> bool:
        return self._refresh() is not None

    def match(self, product: str, version: str) -> list[CveMatch]:
        current = self._refresh()
        if current is None:
            return []
        product_key = product.strip().lower()
        out: list[CveMatch] = []
        for entry in current.entries:
            if entry.product.strip().lower() != product_key:
                continue
            satisfied = version_satisfies_spec(version, entry.version_spec)
            if not satisfied:
                continue  # False (does not match) or None (unparseable) are both "no match"
            out.append(
                CveMatch(
                    cve_id=entry.cve_id,
                    component=entry.product,
                    version=version,
                    match="exact" if is_exact_spec(entry.version_spec) else "range",
                    affected_range=entry.version_spec,
                    catalog_id=current.source,
                    catalog_version=current.catalog_version,
                    catalog_date=current.imported_at.isoformat(),
                    references=tuple(entry.references),
                )
            )
        return out
