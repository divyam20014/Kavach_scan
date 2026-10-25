# Reporting — VAPT Workbench

> Operator-facing guide to generating and exporting reports. For the implementation details (renderer internals, redaction mechanism, file formats), see `docs/REPORTS.md`.

## 1. What a report contains

Cover page, executive summary, scope and authorization statement, methodology (modules run, tool versions, standards catalog versions), scan coverage, finding details (severity, confidence, evidence, remediation, standards mapping, references), attack surface inventory, API coverage, a **Scan health and limitations** section, and an appendix. See `MASTER_SPEC.md` §10.1 for the full structural requirement.

## 2. Building a report

1. Open a project → **Reports**.
2. Choose filters: scan date range, modules, minimum severity, which analyst states to include, and whether to include the asset inventory and evidence excerpts.
3. **Preview** — shows the exact finding/asset count and severity breakdown the generated files will contain, plus the limitations text that will appear. The preview and the generated files are guaranteed to agree (they're built from the identical filtered data), so what you see in preview is exactly what downloads.
4. Choose formats (HTML, PDF, or both) and **Generate**. Download each format from the report list below the builder.

## 3. Formats

- **HTML** — semantic markup with a print stylesheet (page breaks, repeating table headers). Open it in a browser or print to PDF yourself if you want a different PDF pipeline.
- **PDF** — generated directly (not a screenshot of the HTML), so text stays selectable and searchable.
- **JSON / CSV** — normalized findings/assets exports, independent of the HTML/PDF report, for feeding into another tool or spreadsheet. CSV cells are sanitized against spreadsheet-formula injection (a title starting with `=`/`+`/`-`/`@` is neutralized, not executed, when opened in Excel/Sheets).

## 4. What a report never contains

- Credentials, cookies, access tokens, or full raw response bodies — evidence is excerpted and redacted a second time at report-generation time, independent of the redaction already applied when the finding was first recorded.
- Local absolute file paths or internal exception traces.
- A CVSS score that wasn't independently verified against its vector — if no valid score exists, the field is blank, never guessed.
- A claim that the system is secure. A report with zero findings states plainly that the checks executed found nothing, with the limitations that follow from that.

## 5. Project backup and restore

Alongside reports, a project page offers a full **backup export** (a single `.zip` with every canonical record and, optionally, evidence blobs) and, from **Settings**, a **restore** control. Restoring always previews the archive first (showing what it contains and whether it would collide with an existing project) and never overwrites existing data unless you explicitly confirm an overwrite. This is a real backup/restore mechanism, not a report format — use it to move a project between machines or recover from data loss, not to generate a client deliverable.

## 6. Versioning and provenance

Every generated report records: a file checksum, the generator version, which standards-catalog versions (OWASP Top 10, CWE) were in effect, and exactly which finding/asset IDs it covers. A later catalog-version bump never retroactively changes what an already-generated report claims — it was accurate for the data and catalog versions in effect when it was built.
