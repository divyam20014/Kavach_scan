# Standards Catalog — Module 9 (Phase 09)

> Code: `backend/app/standards/` (`__init__.py` for OWASP catalogs' provenance, `cwe.py` for the curated CWE title subset). Exposed via `GET /api/standards/catalogs`. Consumed by the scanner rule catalogs (`app/scanners/{webapp,surface,apisec}/rules.py`) when building a `Finding.mappings` entry.

## 1. Catalogs and independent versioning (TBD-020)

| Catalog | Version | Source |
|---|---|---|
| OWASP Top 10 (web) | **2025** | `app/scanners/webapp/rules.py::OWASP_TITLES`/`OWASP_VERSION` |
| OWASP API Security Top 10 | **2023** | `app/scanners/apisec/rules.py::OWASP_API_TITLES`/`OWASP_API_VERSION` |
| CWE | `curated-2026-10-25` | `app/standards/cwe.py::CWE_TITLES` |

Each catalog's version is tracked completely independently — bumping the web Top 10 to a future edition never touches the API Top 10's version or any CWE title, and vice versa.

## 2. Honesty about coverage

**No catalog here reproduces a full external standard.** Each one only covers what the rule catalogs actually assign:

- OWASP Top 10 (web): 6 of 10 categories are referenced by an implemented check (A01, A02, A03, A04, A05, A10). The other four have no rule mapped to them in this build and are simply absent — not claimed as "not applicable" or silently defaulted to a neighboring code.
- OWASP API Security Top 10: 8 of 10 categories are referenced (API1–API5, API7–API9).
- CWE: 24 IDs, exactly the set the three rule catalogs' `cwe` fields reference today (collected programmatically, not hand-picked) — titled by hand from the public MITRE CWE List, not fetched live (TBD-018: external lookups disabled by default).

`GET /api/standards/catalogs` returns each catalog's `coverage_note` field stating this explicitly, and `app/standards/__init__.py::CatalogInfo.entry_count` is a real count of what's covered, not a stand-in for "10" or "the whole standard."

A rule or an import with no sensible mapping simply has an empty `Finding.mappings` list (or a `cwe_ids` entry with no corresponding `StandardMapping`, if the CWE falls outside the curated subset) — shown as "no mapping" in the UI, never invented. MASTER_SPEC §9: "The catalog must not imply that every check is a one-to-one OWASP category mapping" — every `StandardMapping.rationale` reads "Related category assigned by the rule catalog (not a 1:1 mapping)" for OWASP entries, or "Weakness category assigned by the rule catalog" for CWE entries.

## 3. Provenance (TBD-029 pattern: source, version, import date)

Every catalog entry in `app/standards/__init__.py::CATALOGS` carries:
- `source`: a URL (OWASP) or a note that it was compiled from the public MITRE CWE List, not fetched live
- `imported_at`: the date **this codebase's copy** of the category list was written (not an external publication date this project cannot verify without a network fetch)
- `entry_count` and `coverage_note`: see above

## 4. Historical mappings are preserved automatically

A `Finding.mappings` entry (`app/models/finding.py::StandardMapping`) copies the `catalog_version` and `title` it was created with **at commit time**, directly into the immutable finding record. If a catalog here is later bumped to a new version, existing findings keep whatever version string they were tagged with when the mapping was made — they are never silently rewritten. This is a property of the storage model (each `Finding` is a self-contained JSON document), not a special migration step; `tests/test_standards_and_risk.py::test_catalogs_carry_independent_versions_and_provenance` checks the catalogs' own version independence, and the import/scanner test suites (`tests/test_import_service.py`, `tests/test_webapp_*`) exercise that a `StandardMapping` once written is returned unchanged on every subsequent read.

## 5. CWE title lookup (`cwe_title`)

`app/standards/cwe.py::cwe_title(cwe_id)` returns a title for the 24 curated IDs, or `""` for anything else — callers (currently `app/scanners/webapp/findings.py`, shared by the surface and API scanners) only add a `StandardMapping(catalog="cwe", ...)` entry when a title is known; an out-of-subset CWE id is still kept on `Finding.cwe_ids` (the raw number is never dropped), just without a titled mapping entry.
