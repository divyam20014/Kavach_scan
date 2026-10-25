# User Guide — VAPT Workbench

> Audience: an operator running assessments through the UI. For developer/contributor setup, see `docs/DEVELOPMENT.md`. For what this tool deliberately does not do, read `docs/LIMITATIONS.md` first — a clean result is never a claim of security.

## 1. Before you start

Only test systems you are explicitly authorized to test. This application records an operator attestation when you create a project, but **that attestation is not legal verification** — you are responsible for having real authorization.

## 2. Starting the app

See `docs/DEVELOPMENT.md` for first-time setup. Day to day:

```bash
cd backend
poetry run python -m app serve   # http://127.0.0.1:8765, serves the built frontend too
```

The app binds to `127.0.0.1` only by default; see §7 for what that means and why.

## 3. Create a project

1. **Projects → New project.** Fill in name, client name, and the authorization record (organization, target owner, authorized-by, an authorization window, and the attestation checkbox).
2. **Scope.** List the hosts, schemes, and ports you're authorized to test. Preview the scope before saving — the create form requires a scope-preview hash so you cannot save a scope you haven't looked at.
3. Internal/private IP ranges (RFC 1918, loopback, cloud metadata addresses) are **blocked by default** and cannot be overridden inline. If you genuinely need to test an internal target, use the project's **internal-target override** control — it is narrow (an explicit IP range), time-bound (an expiry you set), and audited.

## 4. Run a scan

From a project's page, **Run a scan**, pick a module:

- **Web Application Scanner** — a bounded, same-origin crawl plus passive checks (headers, cookies, TLS, version/component detection, passive injection indicators). See `docs/SAFE_SCAN_RUNBOOK.md` and `docs/WEB_RULES.md`.
- **Attack Surface Mapper** — discovers hosts/ports/services in scope and maps them into an asset inventory. Discovering something does not add it to scope by itself.
- **API Security Scanner** — upload an OpenAPI/Swagger spec first (**API specs** tab), then run an inventory-only or baseline scan against it.

Every scan shows a profile preview (what will run, what's skipped and why, the rate/concurrency/duration limits) before you confirm. You can cancel a running scan at any time, and a visible **kill switch** stops all active scans immediately if you need it.

## 5. Review findings

**Findings** is the cross-project workbench: search, filter, and sort by severity, confidence, status, source, module, CWE/OWASP mapping, and more. Opening a finding shows its evidence (sanitized — no secrets, no raw response bodies by default), an internal risk score (clearly labelled, never CVSS), and its standards mappings. You can:
- set an analyst status (confirmed / false positive / accepted risk / fixed / retest needed), business impact, and priority — these are kept separate from the scanner's own severity/confidence, which is never silently overwritten;
- comment on a finding (comments always show as "local-operator" — there are no user accounts);
- merge a confirmed duplicate into another finding (nothing is deleted; it stays reachable and un-mergeable later).

## 6. Import external scan results

**Imports** accepts Nmap XML, Nessus `.nessus`, Nuclei JSONL, SARIF 2.1.0, generic CSV/JSON, and best-effort PDF text extraction. Every import is a **dry-run preview first** — nothing is written to your findings until you explicitly commit. The preview shows parsed/rejected counts, warnings, duplicate candidates, and any column-mapping gaps.

## 7. Generate and export a report

**Reports** (from a project page): choose which findings/severities/modules to include, preview the result, then generate HTML and/or PDF. The same preview and the generated files always show the same finding set. JSON/CSV exports and a full project backup archive are also available. See `docs/REPORTING.md`.

## 8. Backup, restore, and diagnostics

**Settings** has: storage diagnostics, a project backup/restore control (restoring always previews the archive first and never silently overwrites existing data), the Integrations & CVE catalog page, and a **diagnostic support bundle** download for troubleshooting (redacted; never includes evidence; never a restorable backup — see `docs/TROUBLESHOOTING.md`).

## 9. Try it with demo data (no scanning required)

```bash
cd backend
poetry run python scripts/generate_demo_project.py --data-dir /path/to/a/throwaway/dir
VAPT_DATA_DIR=/path/to/a/throwaway/dir poetry run python -m app serve
```

This creates one project with a handful of synthetic findings/assets so you can explore the UI immediately — no network access, no real target, no real scan. See the script's own docstring for details.

## 10. Where to go next

- `docs/SAFE_SCAN_RUNBOOK.md` — a step-by-step safe-scanning procedure.
- `docs/REPORTING.md` — report contents, formats, and what's excluded.
- `docs/INTEGRATIONS.md` / `docs/CVE_CATALOG.md` — optional external tools and CVE data.
- `docs/TROUBLESHOOTING.md` — common problems and fixes.
- `docs/LIMITATIONS.md` — what this tool deliberately does not do.
