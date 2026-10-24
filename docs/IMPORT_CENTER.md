# Import Center — Module 8 (Option D, normalize/dedupe)

> Code: `backend/app/imports/` (adapters, safety, dedup, service) and routes in `backend/app/api/imports.py`. UI: `frontend/src/pages/ImportsPage.tsx`. Report generation from imported + scan findings is a separate deliverable (Phase 10) and is not covered here.

Every import is **offline**: it parses bytes already on disk, sends zero network requests, and never executes uploaded content (no shelling out, no `eval`/`exec`, no unsafe YAML/XML/pickle loaders). Uploaded bytes are stored opaquely as `raw.bin` and re-parsed from storage on every later read or commit — never trusted from a client-supplied cache.

## 1. Pipeline: upload → dry-run preview → explicit commit

1. `POST /api/projects/{id}/imports` (multipart upload, optional `source_type` override, optional `options_json`) — detects the format, parses it under the bounds in §3, computes a dry-run preview against the project's **existing** findings/assets, and stores an `ImportArtifact` (hash, sanitized filename, parser version, warnings, counts, the resolved `options`). **No `Finding` or `Asset` is written at this step.**
2. `GET /api/projects/{id}/imports` / `GET .../imports/{import_id}` — list / re-read. The detail route re-parses the stored raw bytes with the import's stored `source_options`, so the preview shown is always reproducible and never depends on an in-memory cache.
3. `POST /api/projects/{id}/imports/{import_id}/commit` (`{"confirmed": true, "expected_revision": N}`) — re-parses and writes normalized `Finding`/`Asset` records. A second commit of the same import is rejected with 409, not silently re-applied.
4. `GET /api/imports/formats` — the supported-format list and the unsupported-format list with reasons (no project context needed).

Preview-never-writes is the Phase 08 acceptance criterion; it is a structural property, not a run-time check: `service.preview()` only reads existing findings/assets and never calls a `repo.create_*`/`repo.update_*` method (verified by `tests/test_import_service.py::test_preview_does_not_write_any_canonical_record`).

## 2. Supported formats (TBD-023)

| Format | Adapter | Notes |
|---|---|---|
| Nmap XML (`nmap -oX`) | `nmap_xml` | Open ports become asset inventory; only database/admin/cleartext exposure classes (same rule tables as the Attack Surface Mapper, `app/scanners/surface/rules.py`) and disclosed service versions become findings — an open port alone is never a vulnerability. |
| Nessus `.nessus` XML | `nessus` | Full fidelity: plugin id/name, risk factor, CVEs, CWE xrefs (`CWE:123` and `CWE-123` both recognized), host/port. |
| Nessus CSV export | — (`generic_csv`) | **Not** a separate adapter: its header names already match the generic CSV alias table. |
| Nuclei JSONL (`nuclei -jsonl`) | `nuclei_jsonl` | One JSON object per line; a malformed line is skipped (partial success), not fatal. |
| SARIF 2.1.0 | `sarif` | Static-analysis tool output; `level` maps to severity, `ruleId`/rule metadata to title/CWE/description. |
| Generic CSV | `generic_csv` | Case-insensitive header aliases (title/severity/host/url/...); operator `options.column_map` overrides when headers don't match. A row with no usable title is rejected, not invented. |
| Generic JSON | `generic_json` | Top-level array, or an object with a `findings`/`results`/`vulnerabilities`/`issues`/`alerts` key; `options.field_map` supports dotted-path overrides. |
| PDF (text only) | `pdf_text` | **Best-effort only** — see §4. |

**Deferred** (`app/imports/adapters/__init__.py::UNSUPPORTED`, reason returned to the operator on upload): OWASP ZAP export (JSON/XML/HTML) and Burp Suite export (XML/JSON). Both tools' export shape varies materially across versions/editions, and no representative sample exports were available to build safe fixtures from — this project ships a format only once it has fixtures and tests (TBD-023). Workaround: the generic CSV/JSON adapters with a `column_map`/`field_map` override.

## 3. Input safety (`app/imports/safety.py`, TBD-009/TBD-060)

Every adapter runs untrusted bytes through the same shared checks before parsing:

| Check | Bound |
|---|---|
| Upload size | 25 MiB |
| Archive (ZIP) expansion | 250 MiB declared uncompressed / 10,000 entries, checked from the central directory **before** any inflation (zip-bomb protection) |
| Archive shape | Exactly one member (no manifest-less multi-file archives); traversal (`..`, absolute, drive-letter) and symlink entries rejected; nested archives rejected |
| JSON | depth ≤ 64, ≤ 500,000 nodes |
| XML | DTD/`<!ENTITY>` rejected before parsing (XXE/billion-laughs), depth ≤ 64, ≤ 500,000 elements |
| Records per import | 20,000 (excess truncated with a warning) |
| CSV/JSONL row | 1 MiB |
| Encoding | UTF-8 (with/without BOM) tried first, then Latin-1 as a non-failing fallback; a dirty decode is warned, never silently corrupted |

A fatal, whole-file problem raises `ImportSafetyError` (surfaced to the operator, the artifact is still recorded with `status="parse_failed"` for audit continuity). A bad **individual** record inside an otherwise-good file is skipped with `rejected_count += 1` and a warning — partial success, never a crash and never a silently dropped row.

## 4. PDF import — best-effort, never invented

A PDF's prose cannot be reliably split into discrete findings without inventing structure that was never there. The adapter therefore:

- Extracts text only (`pypdf`, BSD-3-Clause, TBD-024), bounded to 300 pages / 400,000 characters; a single unreadable page is skipped with a warning, not fatal.
- Produces **exactly one** draft record per PDF: `severity=INFORMATIONAL`, `confidence=NEEDS_REVIEW`, carrying the extracted excerpt and a warning stating the extraction coverage (e.g. "12 of 12 page(s) read (truncated)").
- **Never** guesses a severity, CVE, CWE, or standards mapping from the text.
- Returns no finding at all (with a warning) if no text could be extracted (e.g. a scanned-image PDF with no OCR layer) — it does not invent a placeholder finding.
- An encrypted PDF is opened only with a best-effort empty/owner-password decrypt; otherwise it is a fatal, clearly reported error.

## 5. Normalization and provenance

- `normalize_severity`/`normalize_confidence` (`app/imports/base.py`) map every tool's own scale onto the project's `Severity`/`Confidence` enums, **keeping the original value** (`original_severity`/`original_confidence` on the `Finding`'s `FindingSource`) for provenance. An unrecognized value maps to `INFORMATIONAL`, never guessed upward.
- A record with weak evidence (e.g. a Nuclei match whose matcher didn't actually fire, or any PDF-extracted draft) is marked `Confidence.NEEDS_REVIEW`, which maps to `AnalystStatus.NEEDS_REVIEW` on commit.
- Every tool-derived free-text field (title, summary, technical detail, remediation, parameter, component) is run through `redact_text` (TBD-041) **before** it is shown in a preview and again before it is written on commit — the same mechanism the live scanners already use, so a secret embedded in an imported report never reaches disk or the screen either way.
- Each commit appends a `FindingSource` (tool, tool_version, rule_id, source_finding_id, original_severity/confidence, `import_id`, `observed_at`) to the `Finding.sources` list, so provenance accumulates across re-imports rather than being overwritten.

## 6. Duplicate detection (TBD-060)

Two tiers, deliberately different from "same title":

- **Strong fingerprint** (`app/imports/dedup.py::fingerprint`): a SHA-256 of `project_id | canonical host | canonical path | method | parameter | (source_finding_id or rule_id) | sorted CWE ids`. A record whose fingerprint matches an existing `Finding.fingerprint` is the same underlying observation and is **re-observed** on commit (a new `FindingSource` appended, a `DedupEvent(action="reobserved")` recorded) — never duplicated, regardless of how differently its title reads.
- **Weak title-only candidates** (`title_only_candidates`): records that share only a normalized title (with no other matching signal) are surfaced in the dry-run preview's `duplicate_candidates` list for the operator to review. They are **never auto-merged** — each becomes its own new `Finding` on commit unless the operator intervenes.

## 7. Generic CSV/JSON mapping (TBD-060, acceptance criterion #9)

Rather than a drag-and-drop mapping UI, this release ships a **documented mapping config**: the generic CSV adapter's `ALIASES` table (`app/imports/adapters/generic_csv.py`) already recognizes common header names case-insensitively (`"Vulnerability Name"`, `"Risk"`, `"CVE ID"`, …). When an export's headers don't match, the operator supplies `options.column_map` (CSV) or `options.field_map` (JSON, dotted-path) as a small JSON object — in the UI, a single "Optional column/field map" text field on the Import Center page. The resolved options are persisted on `ImportArtifact.source_options`, so a later `GET` or `commit` reproduces the exact same parse without re-supplying them.
