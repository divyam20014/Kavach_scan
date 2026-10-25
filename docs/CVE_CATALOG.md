# Local CVE Catalog — Module 5.6 / 11 (Phase 11)

> Code: `backend/app/cve/` (`parser.py`, `matcher.py`, `version.py`), `backend/app/models/cve_catalog.py`, `backend/app/api/settings.py` (`/api/cve-catalog`). Consumed by `backend/app/scanners/webapp/components.py::cve_results` via the `CveCatalog` protocol defined in Phase 05.

## 1. Never fetched; always imported

No CVE data is bundled with this project and nothing is ever fetched automatically (TBD-028). An operator imports a JSON file (`POST /api/cve-catalog/import`); importing a new one replaces the previously active catalog. A scan remains fully functional with no catalog imported at all — `NoCveCatalog` (Phase 05) reports the CVE-matching check as `skipped`, with the reason, never a silent pass.

## 2. Catalog file format

A small, fully-specified, VAPT-Workbench-specific JSON schema (TBD-069) — not the real NVD feed format, which is complex enough that a partial parser would itself be a liability:

```json
{
  "source": "Internal curated export, 2026-10",
  "catalog_version": "2026.10",
  "stale_after_days": 180,
  "entries": [
    {
      "product": "jquery",
      "version_spec": "<1.12.4",
      "cve_id": "CVE-2015-9251",
      "summary": "optional free text",
      "references": ["https://nvd.nist.gov/vuln/detail/CVE-2015-9251"]
    }
  ]
}
```

`version_spec` is a comma-separated AND-list of conditions using `==`, `!=`, `<=`, `>=`, `<`, `>` and a dotted numeric version (e.g. `>=2.0,<2.3.1`). An entry whose `version_spec` doesn't parse, or whose `cve_id` doesn't match `CVE-YYYY-NNNN...`, is skipped with a warning — the rest of the file still imports. A structurally broken file (not JSON, not an object, no `entries` list, missing `source`/`catalog_version`) is rejected outright, before anything is stored.

## 3. Provenance and staleness

Every import records: `source` and `catalog_version` (operator-provided labels), `imported_at` (this app's clock, not an unverifiable external publish date), `file_sha256` (of the exact uploaded bytes), `file_name`, `parser_version`, and the per-entry count. `stale_after_days` (operator-set, default 180) turns into an honest `is_stale` flag computed from `imported_at`'s age — shown in the Integrations page so an operator knows when their catalog needs refreshing, without this app ever claiming to know whether new CVEs exist upstream.

## 4. Matching: defensible, never a guess

`StoredCveCatalog.match(product, version)` only matches an **exact, case-insensitive product name** — no fuzzy or substring matching, since a wrong match would fabricate a vulnerability claim. Version comparison uses a small, dependency-free dotted-version comparator (`app/cve/version.py`, TBD-069); a version or spec that doesn't parse cleanly is treated as **no match**, never a guess.

Every match carries: the CVE ID, the catalog's own `affected_range` string exactly as stated, whether it was an `exact` (single `==X` pin) or `range` match, the catalog's `source`/`catalog_version`/`catalog_date` (the catalog's own `imported_at`, not an unverifiable external publish date) as its data-source attribution, and any references the entry carried — satisfying "show match confidence, version range and data source" and the explicit verification check "CVE matches expose catalog source/version/date." All three are included in the generated finding's rationale text (`"CVE-... listed for ... (range match, catalog X Y, imported Z)"`).

## 5. Never a confirmed vulnerability

`components.py::cve_results` enforces the acceptance criterion directly: a `range` match keeps the rule's `needs_review` default confidence (an ambiguous candidate for analyst review); even an `exact` version-pin match on a strongly-detected component is only elevated to `probable` — `confirmed` is never used for a CVE match, because passive version detection never verifies actual exploitation. Combined with the existing Phase 09 guarantee that a `needs_review`-confidence finding can never reach the "critical" risk tier, an imported catalog can never cause this application to report a "confirmed critical vulnerability" from passive detection alone.
