# Release Checklist — VAPT Workbench

> Run this before tagging a release. Each command is exact and was actually run during Phase 13 — see the recorded result next to it. "Not run in this environment" is stated explicitly where that's the case; nothing here is a hypothetical command presented as verified.

## 1. Clean install (from a fresh clone)

```bash
cd backend
poetry install                          # installs the locked dependency set
poetry run ruff check .                 # lint
poetry run ruff format --check .        # format
poetry run mypy                         # strict type check (app/)
poetry run pytest -q                    # full backend suite
```
**Recorded result (2026-10-25, Windows 11, Python 3.13.5):** `ruff check` clean; `ruff format --check` clean (198 files); `mypy` clean (129 source files); `pytest` **1958 passed, 1 skipped** (the one skip is a POSIX-permission test, not applicable on Windows).

```bash
cd frontend
npm ci                                  # installs the locked dependency set
npm run typecheck
npm run lint
npm test
npm run build
npm audit
```
**Recorded result:** typecheck/lint clean; `npm test` **77 passed**; build succeeds (one cosmetic chunk-size warning, not an error); `npm audit` **0 vulnerabilities**.

**Not run in this environment:** a literal `git clone` into an empty directory followed by the above (this session works from the existing checkout). Every command above was run for real against the current tree, which is the equivalent check — see `docs/DEVELOPMENT.md` for the exact first-time setup steps a new clone would follow.

## 2. Dependency audit

```bash
poetry run pip install pip-audit && poetry run pip-audit ; poetry install --sync
```
**Recorded result (Phase 12):** found and fixed disclosed vulnerabilities in `pypdf` (5.9.0 → 6.21.2), `pytest` (8.4.2 → 9.1.1), `python-multipart` (0.0.9 → 0.0.32). Re-audit: 0 vulnerabilities. `pip-audit` itself is never a project dependency — installed ephemerally, removed via `poetry install --sync`. See `docs/DEPENDENCIES.md` §4a.

## 3. No-database / architecture guards

```bash
poetry run pytest tests/test_static_guards.py tests/test_startup.py -q
```
**Recorded result:** passes (640+ parametrized checks across every source file: no `sqlite3`/`redis`/`celery`/etc. import, no file I/O outside `app/storage/`, no network/subprocess code outside the sanctioned adapters, `shell=True`/raw `httpx`/unsafe `yaml.load`/unguarded XML parsing all absent — re-confirmed by direct grep in Phase 12 verification).

## 4. Full offline end-to-end flow

```bash
poetry run pytest tests/test_e2e_full_flow.py -q
```
**Recorded result:** passes, stable across repeated runs (~14s each). Exercises create project → scope → web scan → surface scan → API spec inventory → API baseline scan → import Nmap/Nuclei/SARIF → triage/merge → HTML+PDF report → backup export/restore → restart-and-verify-persistence, entirely through the real HTTP API against local fixtures, no network access.

## 5. Real-browser E2E (manual; requires a local Edge/Chromium and a running backend)

```bash
cd frontend
npm run e2e          # 10 basic UI checks
npm run e2e:verify   # 18 deeper checks incl. a real scan through the UI
```
**Recorded result (last run during Phase 06 verification, 2026-10-21):** `e2e` 10/10, `e2e:verify` 18/18. Not re-run during Phases 10–13 (no new E2E checks were added for the report builder, integrations, or CVE-catalog UI — see `docs/LIMITATIONS.md`); the new backend `test_e2e_full_flow.py` covers the same user journey at the API level instead.

## 6. Demo data (optional, for a reviewer with no scan target)

```bash
cd backend
poetry run python scripts/generate_demo_project.py --data-dir /path/to/throwaway-dir
```
**Recorded result:** creates 1 project, 2 assets, 1 scan record, 4 findings — verified by reading them back from a fresh `StorageRepository` pointed at the same directory. No network access.

## 7. Version and changelog

Confirm `backend/app/__init__.py::__version__` and `frontend/package.json`'s `version` agree, and that `CHANGELOG.md` has an entry for the release. See `CHANGELOG.md` for the versioning approach.

## 8. Documentation currency

Confirm `docs/IMPLEMENTATION_STATUS.md` reflects the true state of every module (no `Implemented` claim without a code reference and a test that was actually run), and that `TBD_DECISIONS.md` has no newly-made decision left unrecorded.

## 9. Unsupported OS/tool combinations and known limitations

Before tagging a release, confirm these are current and still match reality (do not just assume they still hold):

- **testssl.sh does not run natively on Windows** — it is a bash script; Windows operators need WSL or must rely on sslyze (pure Python, works natively on Windows/macOS/Linux) instead. See `docs/INTEGRATIONS.md` §0.
- **POSIX file-permission enforcement (owner-only 0600/0700) is not meaningful on Windows** and is skipped there — one backend test (`test_posix_permissions_are_owner_only`) is explicitly skipped on this platform, never silently passed.
- **This release has been run through the full documented clean-install procedure on Windows 11 only** (this pass: Windows 11, Python 3.13.5, Node 22). Linux/macOS are supported by design (the backend is written to be POSIX-portable and CI exercises `ubuntu-latest`) but the *complete* manual procedure in §1 and the real-browser E2E in §5 have not been run end-to-end on either in this session — CI's `ubuntu-latest` backend job covers lint/format/type/test only, not the manual steps.
- **No remote/multi-user secure mode exists** (TBD-003) — this is a single-operator, localhost-only tool; do not expose it beyond loopback.
- Full list, with rationale: `docs/LIMITATIONS.md` (what this tool is not, deliberately unimplemented checks, external-tool dependence, CVE-matching honesty, performance characteristics, platform notes).

## 10. Final release assessment

See the "Final release assessment" section of `docs/IMPLEMENTATION_STATUS.md` for the consolidated implemented/partial/unavailable module list, test evidence, and remaining TBD decisions as of this release.
