# Report Builder & Exports — Module 10 (Phase 10)

> Code: `backend/app/reports/` (`builder.py`, `html_render.py`, `pdf_render.py`, `exports.py`), `backend/app/api/reports.py`. Frontend: `frontend/src/pages/ReportBuilderPage.tsx`.

## 1. One builder, two renderers, two exporters

`build_report_data(repo, filters) -> ReportData` is the single place that resolves findings, assets, scans, and limitations from operator-chosen filters (project, scan date range, modules, severity threshold, analyst states, asset-inventory/evidence toggles, or an explicit `finding_ids` override). Every output format — the HTML page, the PDF, the findings/assets JSON, the findings/assets CSV — is produced from that one `ReportData` object. There is no HTML→PDF conversion step and no per-format re-filtering: `html_render.render_html(data)`, `pdf_render.render_pdf(data)`, and `exports.findings_to_json/csv`/`assets_to_json/csv` all read the same resolved `ReportData`.

This is also the mechanism behind the Phase 10 acceptance criterion "the same selected findings appear consistently in preview and files": `POST /projects/{id}/reports/preview` and `POST /projects/{id}/reports` both call `build_report_data` with an identical filter object, so there is structurally no way for a preview to show one finding set and the generated files to contain another. `ReportMetadata.finding_ids`/`asset_ids` are resolved exactly once, at generation time, and stored immutably — a later catalog version bump or finding edit never retroactively changes what a previously generated report claims it covered.

## 2. Defense-in-depth redaction

Every finding/evidence record is already redacted at write time (TBD-041, enforced by the scanner/import write paths). The report builder redacts a **second time**, independently, right after resolving findings and evidence (`_redact_finding`/`_redact_evidence` in `builder.py`), because a record constructed directly — as every test fixture in this codebase does, and as a future code path conceivably could — bypasses the normal write-path redaction entirely. Without this second pass, such a record could carry a secret straight into a generated report. `tests/test_reports_builder.py::test_no_secret_assertions_across_html_pdf_json_csv` plants a realistic secret token across every text field (summary, technical detail, remediation, evidence request/response excerpts) and asserts it is absent from the generated HTML, the text extracted from the PDF, the JSON export, and the CSV export.

CVSS is never fabricated in an export: a finding with no `CvssRecord` always produces an empty `cvss_vector`/`cvss_base_score` CSV cell, never a placeholder or guessed value (`test_cvss_never_fabricated_in_csv_export`).

## 3. Honest limitations, never a claim of security

`build_report_data` always prepends two fixed disclaimer sentences to the limitations list: that the report reflects only checks that were actually executed, and that a finding's absence does not mean an area was proven free of weaknesses. It then adds genuine, scan-derived limitations: tools unavailable, checks skipped and why, partial scans, and low-confidence (`needs_review`) findings. A report with **zero** matching findings is valid output, not an error — removing an earlier overly strict validation that rejected this case was necessary to satisfy "a clean report must not claim the system is secure": the honest output for a clean scope is an empty findings section plus the standing limitations, not a refusal to generate.

## 4. HTML and PDF rendering

- **HTML** (`html_render.py`): semantic markup with an embedded print stylesheet (`@page` margins, `page-break-inside: avoid`, `thead { display: table-header-group }` for repeating table headers on print). Every operator- or scanner-supplied string is passed through `html.escape` before being written into the page — proven by `test_html_response_escapes_a_script_tag_in_the_title` and the frontend's own HTML-injection test (`frontend/src/test/reports.test.tsx`).
- **PDF** (`pdf_render.py`): built with `fpdf2` (TBD-031) — pure Python, no native/system dependencies, producing real searchable/selectable text (verified in tests via `pypdf.PdfReader.extract_text()`, not just "a PDF was written"). Supports page numbering, a repeating classification-label footer, and repeated table headers. `fpdf2`'s built-in font is Latin-1-only, so every string reaching it is passed through a module-level `_ascii_safe()` helper first.

Both renderers compute the same internal risk score (`app/services/risk.py`, never CVSS) per finding, consistently labelled "not CVSS" in the output, using the same asset-criticality lookups.

## 5. Exports and standalone routes

`app/reports/exports.py` wraps findings/assets in a schema-versioned JSON envelope (`schema_version`, `project_id`, `generated_at`, `filters`, `count`, records) or a fixed-column CSV. Standalone export routes (`GET /projects/{id}/export/{findings,assets}.{json,csv}`) exist independent of report generation, reflecting all current findings/assets by default (no filter required).

CSV cells are passed through `_csv_safe()` (added during Phase 10 verification, TBD-066), which prefixes a value starting with `=`/`+`/`-`/`@` with a neutralizing quote. Without this, a finding title or asset locator containing content from an imported, attacker-influenced scan report could execute as a spreadsheet formula (OWASP CSV injection) when the client opens the export in Excel/Sheets — the content itself still survives, just no longer live as a formula.

## 6. Downloads

`GET /projects/{id}/reports/{report_id}/download/{fmt}` returns the stored bytes with `Content-Disposition: attachment`; `fmt` is restricted to the set the report was actually generated with (`metadata.formats`) — requesting a format that was never generated is a 404, not a silently-regenerated file. Every generate/download is audited (`AuditAction.REPORT_GENERATED`/`REPORT_DOWNLOADED`).

## 7. What this does not do

No drag-and-drop report-template editor exists beyond the fixed template structure (cover, executive summary, scope/authorization, methodology, tools/versions, scan coverage, risk distribution, findings, attack surface, API coverage, limitations, appendices) — not required by the Phase 10 acceptance criteria. No E2E coverage exists yet for the report builder (frontend/backend integration tests cover it; no browser-driven check was added this phase).
