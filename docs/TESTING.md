# Testing Strategy — VAPT Workbench

> **Status:** Phase 01 (2026-10-20). 20 backend test files / 466 tests. Use the fixtures in `backend/tests/conftest.py` (`settings`, `repo`, `client`, `make_project/finding/asset`): each test gets a temporary data root. API test clients must use `base_url="http://127.0.0.1"` and `client=("127.0.0.1", <port>)`, because the guards reject Starlette's default `testserver` host and `testclient` peer.

## 1. Ground rules

1. **No internet, no third-party targets.** Every test runs offline against mocks or local fixture servers on loopback. Tests must never resolve or contact public hosts.
2. **Never claim a check passed unless it was run** and the output was observed. Phase reports quote the exact command and result.
3. **Isolated data roots.** Every storage, job, or API test uses a fresh `tmp_path` as `VAPT_DATA_DIR`. Tests never touch the operator's real data dir or the repository.
4. **Deterministic.** Fake clocks for expiry and backoff. Seeded randomness. No sleeps longer than needed (prefer event or condition waits).
5. **Skipped is not passed.** Platform-dependent tests (symlinks on Windows, POSIX modes) use `pytest.skip(reason=...)` so skips appear in `-ra` output.

## 2. Commands

Run from `backend/` (see [DEVELOPMENT.md](DEVELOPMENT.md) for setup):

| Purpose | Command |
|---|---|
| Unit tests | `poetry run pytest` |
| Lint | `poetry run ruff check .` |
| Format check | `poetry run ruff format --check .` |
| Type check (strict, `app/`) | `poetry run mypy` |

Frontend (Phase 02+, planned): `npm test` (Vitest), `npm run lint` (ESLint), `npm run typecheck` (`tsc --noEmit`), `npm run build`.

### Results recorded at Phase 06 verification (2026-10-21)

| Command | Result |
|---|---|
| `poetry run pytest` | **1364 passed, 1 skipped** (adds `test_surface_verification.py`, 10 tests) |
| `poetry run pytest tests/test_surface_verification.py` | 10/10: re-resolution each scan + private rebind blocked and never connected; out-of-scope host never resolved; exact Nmap argv captured from a fixture (no shell/`-A`/`-sV`/`-sS`/`-sU`/NSE/range/UDP); Nmap timeout and oversized XML -> TCP-connect fallback (partial XML never trusted); partial Nmap scan marks unreported ports honestly; coverage lists exactly the ports tested and never claims "all ports"; TCP probe sends zero bytes to the service; banner secrets never reach outputs/evidence; Nmap absence and crt.sh are disclosed |
| `ruff check` / `ruff format --check` / `mypy` | clean / all formatted / no issues in 85 source files |
| `npm test` / `build` / `audit` | 48 passed / built / 0 vulnerabilities |
| `npm run e2e:verify` / `npm run e2e` | 19/19 / 10/10 |

### Results recorded at Phase 06 (2026-10-21)

| Command | Result |
|---|---|
| `poetry run pytest` | **1354 passed, 1 skipped** (adds `test_surface_nmap.py`, `test_surface_core.py`, `test_surface_scan.py`, `test_surface_api.py`) |
| `ruff check` / `ruff format --check` / `mypy` | clean / all files formatted / no issues in 85 source files |
| `npm test` (2 runs) / `typecheck` / `lint` / `build` / `audit` | 48 passed both runs / pass / pass / built / 0 vulnerabilities |
| `npm run e2e:verify` / `npm run e2e` | **19/19** (new check 14: attack-surface scan via the UI against a local fixture; hosts/ports, web origins, asset graph with priority) / 10/10 |

Phase 06 fixtures (`backend/tests/surfacefixtures.py`): loopback TCP banner services (counted connections), a records-capable fake DNS (A/AAAA/CNAME, including a private and a cloud-metadata answer that must be blocked and never connected), and an out-of-scope host that must never be resolved. Nmap integration is tested with a fixture script (safe argv + pinned IP asserted inside it) and malformed/absent output; web-origin probing reuses the Phase 05 local HTTP app.

### Results recorded at Phase 05 verification (2026-10-21)

| Command | Result |
|---|---|
| `poetry run pytest` | **1242 passed, 1 skipped** |
| `poetry run pytest tests/test_webapp_verification.py` | 9/9: scanner sends only GET and only query strings that appeared in crawled links (no crafted input), only header added is the fixed CORS test Origin; catalog has no active rules and no "confirmed executable" XSS claim; `active_*` parameters rejected (422) with zero traffic; response cap → page `truncated`, non-HTML not parsed; redirect into an excluded path recorded, never followed; 503 `Retry-After` honoured; cancel during a 25 s `Retry-After` wait ends the job in < 8 s with no further request; every evidence record ≤ 8 KiB, bounded body window, no blobs, no session secret in evidence/findings/outputs/events/console, no structural field wiped by redaction; raw TLS-tool output redacted; absent tool → `skipped` with reason |
| `ruff check` / `ruff format --check` / `mypy` | clean / 112 files formatted / no issues in 73 files |
| `npm test` ×2 / `typecheck` / `lint` / `build` / `audit` | 45 passed both runs / pass / pass / built / 0 vulnerabilities |
| `npm run e2e:verify` / `npm run e2e` | **18/18** (check 13 now also asserts readable outcome counts and the TLS-tool row shown as skipped) / 10/10 |

### Results recorded at Phase 05 (2026-10-21)

| Command | Result |
|---|---|
| `poetry run pytest` | **1229 passed, 1 skipped** (adds `test_http_adapters.py` 36, `test_webapp_scan.py` 14, `test_webapp_units.py` 27, new static guards) |
| `ruff check` / `ruff format --check` / `mypy` | clean / 111 files formatted / no issues in 73 files |
| `npm test` (2 consecutive runs) / `typecheck` / `lint` / `build` / `audit` | 45 passed / pass / pass / built / 0 vulnerabilities |
| `npm run e2e:verify` / `npm run e2e` | **18/18** (new check 13: web scan started in the UI against a local Node fixture app; profile shown, pages/findings/coverage tabs, global findings filtered by scan, robots respected, cookie value never stored) / 10/10 |

Fixture apps (`backend/tests/webfixtures.py`): a LAB app with pages for missing headers, cookies, version banners, directory listing, default page, traceback, DB error text, escaped and unescaped reflection, off-scope redirect, robots-disallowed area, excluded path, crawler trap, 429 rate limiting, CORS reflection, oversized body, gzip bomb, slow and drip responses; a VICTIM server that must receive zero requests; HTTPS servers with runtime-generated valid / expired / wrong-host / expiring certificates (throwaway CA via `cryptography`, dev only; no key material committed).

### Results recorded at Phase 04 verification (2026-10-21)

| Command | Result |
|---|---|
| `poetry run pytest` | **1076 passed, 1 skipped** |
| `poetry run pytest tests/test_jobs_verification.py` ×3 | 12/12 each run: 10 concurrent same-key submits → 1 job; cancel inside the claim window → cancelled; restart during validating / with a persisted cancel flag; corrupt spool entry and corrupt scan record do not stop dispatch; cancel / kill switch / shutdown each kill the child **and grandchild** process; 65 MB console log tailed with < 20 MB peak memory; event pages byte-bounded (4 MiB); secrets written raw into logs are redacted by the tail endpoints; kill switch prevents dispatch of jobs queued before it |
| `ruff check` / `ruff format --check` / `mypy` | clean / formatted / no issues in 57 files |
| `npm test` / `typecheck` / `lint` / `build` / `audit` | 40 passed / pass / pass / built / 0 vulnerabilities |
| `npm run e2e:verify` / `npm run e2e` | 17/17 / 10/10 |

### Results recorded at Phase 04 (2026-10-20)

| Command | Result |
|---|---|
| `cd backend && poetry run pytest` | **1064 passed, 1 skipped** (adds `test_jobs.py`, `test_process.py`, `test_api_jobs.py`) |
| `poetry run ruff check .` / `ruff format --check .` / `mypy` | clean / 90 files formatted / no issues in 57 files |
| `cd frontend && npm test` | **40 passed** (2 consecutive runs; per-test timeout 15 s) |
| `npm run typecheck` / `lint` / `build` / `npm audit` | pass / pass / built / 0 vulnerabilities |
| `npm run e2e:verify` | **17/17**: adds self-test job started through the UI confirmation with live progress; cancel from the job page; **hard crash (process-tree kill) mid-job → restart → job shown Interrupted, not replayed**; kill switch from the header blocks new jobs |
| `npm run e2e` | 10/10 |

Process-tree kill is verified for real on Windows: a child spawns a grandchild; on timeout and on cancellation both are gone afterwards (`tests/test_process.py`).

### Results recorded at Phase 03 verification (2026-10-20)

| Command | Result |
|---|---|
| `poetry run pytest` | **965 passed, 1 skipped** |
| `poetry run pytest tests/test_scope_ssrf_suite.py` | **60 passed**: 38 redirect attacks + 8 direct attacks against two real loopback servers (LAB, reachable only via an audited override; VICTIM, must never be reached). VICTIM received **0 requests**. Covers loopback/private/link-local/metadata redirects (incl. IPv4-mapped, NAT64, decimal/hex/octal/short hosts), user-info, protocol-relative, backslash, suffix confusion, IDN look-alike, fullwidth dot, zone IDs, non-HTTP schemes, encoded/double-encoded/semicolon traversal, port and path exclusions, CRLF/whitespace smuggling, DNS rebinding (between requests and inside a redirect chain), mixed DNS answers, expired/absent/unattested authorization, expired override, discovered subdomains |
| Mutation check: `validate_redirect` forced to approve | **12 attacks followed → suite fails**; the other 26 were still stopped by independent layers (canonicalization, IP policy, scheme). Restored code: 60/60 |
| `ruff` / `ruff format --check` / `mypy` | clean / 78 files formatted / no issues in 49 files |
| `npm test` / `typecheck` / `lint` / `build` / `audit` | 33 passed / pass / pass / built / 0 vulnerabilities |
| `npm run e2e:verify` / `npm run e2e` | 13/13 / 10/10 |

### Results recorded at Phase 03 (2026-10-20)

| Command | Result |
|---|---|
| `cd backend && poetry run pytest` | **905 passed, 1 skipped** (adds ~270 scope tests: canonical, IP policy, engine, guard with a real local fixture server, Hypothesis properties, API) |
| `poetry run ruff check .` / `mypy` | clean / no issues in 49 files |
| `cd frontend && npm test` | **33 passed** (adds scope policy card, URL checker, override form) |
| `npm run typecheck` / `lint` / `build` | pass |
| `npm run e2e:verify` | **13/13** (adds: suffix-confusion host and metadata IP blocked, in-scope URL allowed via the real policy card) |
| `npm run e2e` | 10/10 |

Hypothesis found 4 real defects during this phase (all fixed, with regression tests): local-use NAT64 not blocked; 6to4 not blocked; metadata embedded in 6to4 was overridable; `authorize_connect` wrongly applied URL path rules to raw connections.

### Results recorded at Phase 02 verification (2026-10-20)

| Command | Result |
|---|---|
| `cd backend && poetry run pytest` / `ruff` / `mypy` | 608 passed, 1 skipped / clean / clean |
| `cd frontend && npm test` | **28 passed** (adds keyboard, source-hygiene, hostile-content tests) |
| `npm run typecheck` / `lint` / `build` / `npm audit` | pass / pass / built / 0 vulnerabilities |
| `npm run e2e:verify` (Edge, real backend) | **12/12**: empty states; 8 KPIs equal the captured `/api/dashboard/summary` response; tampered response changes the UI; create/edit survive reload; backend offline alert + retry; backend 422 field message; stale-edit 409; delete confirmation (disabled until exact name, cancel safe, audited); keyboard-only navigation with visible focus; no console/CSP errors |
| `npm run e2e` | 10/10 |
| Mutation check: delete regression test with the old hook | fails as expected; passes with the fix |

### Results recorded at Phase 02 (2026-10-20, Windows 11, Python 3.13.5, Node 22.16)

| Command | Result |
|---|---|
| `cd backend && poetry run pytest` | **608 passed, 1 skipped** |
| `poetry run ruff check .` / `mypy` | passed / no issues in 43 files |
| `cd frontend && npm test` (Vitest 4 + Testing Library, jsdom) | **21 passed** (3 consecutive runs) |
| `npm run typecheck` / `npm run lint` / `npm run build` | pass / pass / built (517 kB JS, size warning only) |
| `npm audit` (all deps) | 0 vulnerabilities |
| `npm run e2e`: real Edge, backend serving `frontend/dist`, temp data dir | **10/10 checks**: honest zeros; attestation enforced; preview errors shown; create via UI; reload persists; edit via UI; backend restart persists; dashboard counter; audit events; no console/CSP errors |

Frontend tests mock `fetch` per route (`src/test/utils.tsx`); unmatched requests fail with a 404, so no test can reach a network. The E2E script contacts only `127.0.0.1`.

### Results recorded at Phase 01 verification (2026-10-20, Windows 11, Python 3.13.5)

| Command | Result |
|---|---|
| `poetry run pytest -ra` | **543 passed, 1 skipped** (POSIX permission bits, N/A on Windows) |
| `poetry run ruff check .` / `ruff format --check .` / `mypy` | passed / 58 files formatted / no issues in 37 files |
| Race test repeated 15× (`test_writes_racing_project_delete_never_resurrect_it`) | 15/15 passed |
| Live: request with `Authorization: Bearer …`, `Cookie: sid=…`, `?password=…` | 0 secret occurrences in the server log |
| Live: second `python -m app` on same data dir | refused, exit 3 |

### Results recorded at Phase 01 (2026-10-20)

| Command | Result |
|---|---|
| `poetry run pytest` | **465 passed, 1 skipped** (`test_posix_permissions_are_owner_only`: not applicable on Windows), 1 warning (Starlette TestClient deprecation) |
| `poetry run ruff check .` | All checks passed |
| `poetry run ruff format --check .` | 57 files already formatted |
| `poetry run mypy` | Success: no issues found in 37 source files |
| Live: `VAPT_DATA_DIR=<tmp> poetry run python -m app` + `curl` | readiness `ready`; diagnostics show `~/…` path and `held_by_this_process`; Host `evil.example` → 403 `invalid_host`; server log is JSON lines with correlation IDs; `access_token` value redacted (0 occurrences in log) |
| Live: second `python -m app` on the same data dir | `error: Another VAPT Workbench instance is already using this data directory (pid …)`, exit 3 |
| Live: `python -m app diagnose` while the server runs | `"instance_lock": "held_by_another_process"`, `"ready": true` |

Symlink/junction escape tests ran on Windows using a directory junction (symlink creation needs privileges here). They pass, so junction escapes are rejected.

### Results recorded at Phase 00 verification (2026-10-20)

| Command | Result |
|---|---|
| `poetry run pytest` | 99 passed, 1 warning (Starlette TestClient `httpx` deprecation notice) |
| `poetry run ruff check .` | All checks passed |
| `poetry run ruff format --check .` | 14 files already formatted |
| `poetry run mypy` | Success: no issues found in 8 source files |
| Manual: `poetry run python -m app` + `curl 127.0.0.1:8765/api/health` and `/api/version` | `{"status":"ok"}` and the version payload; `netstat` showed the listener on `127.0.0.1:8765` only |
| Manual: `VAPT_HOST="[::1]" VAPT_PORT=8766 poetry run python -m app` + `curl -g http://[::1]:8766/api/health` | `{"status":"ok"}`; listener `[::1]:8766` only |
| Manual: `VAPT_HOST=0.0.0.0 poetry run python -m app` | Refused with message, exit code 2 |
| Mutation check: health router mounted **without** `LoopbackOnlyMiddleware`, remote peer | 200 (with the guard: 403), so the guard tests depend on the guard |

Not live-tested: a real remote client against `uvicorn app.main:app --host 0.0.0.0`. Opening an all-interfaces listener was deliberately avoided. The guard is covered at the ASGI level in `test_loopback_guard.py`.

## 3. Test layers

| Layer | Tooling | Scope | Location |
|---|---|---|---|
| Unit | `pytest` | Models, storage primitives, scope engine, redactor, parsers, fingerprints, scoring | `backend/tests/<package>/` |
| Property | `hypothesis` (add in Phase 03) | Scope matching, URL canonicalization, path normalization, IP classification | `backend/tests/scope/` |
| API / integration | FastAPI `TestClient` + temp data root | Route contracts, error format, end-to-end use cases in-process | `backend/tests/api/` |
| Fixture-network | Local fixture HTTP server (§4) | Adapters, crawler, web checks, API checks, SSRF/zero-request proofs | `backend/tests/integration/` |
| Subprocess adapters | Fake executables (small Python scripts invoked as argv) plus recorded tool outputs | Timeouts, kill, output caps, version parsing, argv allowlists | `backend/tests/integrations/` |
| Parsers | Fixture files: valid, malformed, oversized, malicious (XXE, zip-slip, bombs, XSS strings) | Import adapters, OpenAPI loader, archive restore | `backend/tests/fixtures/` |
| Frontend | Vitest + Testing Library (+ MSW for API mocks) | Forms, validation messages, empty/error/loading states, a11y labels | `frontend/src/**/*.test.tsx` |
| E2E | Playwright (Phase 12, if feasible) against the locally running app + fixture targets | Full workflow in MASTER_SPEC §8 | `e2e/` |

## 4. Local fixture-server approach

- **Server:** a small ASGI or `http.server` app started per test session on `127.0.0.1` with an **ephemeral port**. It serves canned scenarios: security headers, directory listing marker, default page, escaped vs unescaped XSS marker reflection, generic error page, SPA-style 200-for-everything 404, off-scope redirect, 429/503 with `Retry-After`, oversized and compressed bodies, slow responses.
- **Request log:** the fixture records every request (method, path, headers after redaction). Tests assert on it, including **"this blocked URL received zero requests"**.
- **Loopback vs scope policy:** loopback is blocked by default ([SCAN_SAFETY.md](SCAN_SAFETY.md) §5). Fixture tests must go through the real policy:
  1. A test project with an **explicit internal-target override** for `127.0.0.1/32`, created through the same audited override path as production, **or**
  2. An **injected test resolver** mapping synthetic names (`app.fixture.test`) to `127.0.0.1`, combined with the override.
  
  There is **no** global "disable scope" flag for tests. Scope bypass tests confirm that an un-overridden project cannot reach the fixture.
- **TLS fixtures:** self-signed and expired certificates generated at test time with `cryptography` (Phase 05). Never use real certificates.
- **DNS:** mocked resolver for rebinding (first answer public, second answer private), CNAME chains, NXDOMAIN, IPv6-only.

## 5. Network isolation guard (implemented, Phase 01)

`tests/conftest.py::_offline_guard` (autouse) patches `socket.socket.connect`, so any connection to a non-loopback IP or to a hostname fails the test immediately. Loopback stays allowed for fixture servers. Subprocesses spawned by tests are not covered by this in-process patch; they only run app code that has no network imports (enforced by `tests/test_static_guards.py`).

## 6. Phase-specific must-have tests

| Phase | Must test |
|---|---|
| 00 | Health/version, version consistency, localhost default + canonicalization, non-loopback refusal before uvicorn starts, loopback-peer guard, no other routes, 404/405 for unimplemented, `.gitignore` coverage incl. fixture/source false positives (**done**) |
| 01 | **done:** CRUD, atomic replace (failed replace, partial write/disk full), thread + process concurrent writers, truncated JSON, invalid schema, `../` / absolute / encoded / reserved-name / symlink / junction escapes, stale locks + crash release, second-instance refusal, index rebuild (missing/corrupt/out-of-sync/stale revision), restart persistence, audit/log redaction, migrations with backup, integrity checks, first-run/version refusal, static architecture guards |
| 02 | Project form validation, reload persistence, dashboard counters from API (no constants), empty/offline/error states, keyboard navigation |
| 03 | Each blocked range row, suffix confusion, IDN, IPv6, user-info, non-HTTP schemes, encoded paths, port/path exclusions, redirect to private, rebinding, expiry boundaries (fake clock) |
| 04 | State transitions, duplicate submission, claim race, queue cap, cancel, subprocess timeout/kill, restart → interrupted, kill switch |
| 05–07 | Fixture scans per check, injection disabled by default, escaped-vs-unescaped XSS, response caps, backoff, Nmap argv, missing tools → skipped, OpenAPI malicious specs, IDOR prerequisites |
| 08–10 | Parser fixtures + malformed + XXE/zip-slip/bombs, dry-run immutability, dedupe correctness, report escaping and no-secret assertions, archive round trip |
| 11–13 | Missing/invalid tools, stale catalogs, offline E2E, clean-install check |

## 7. Coverage and CI (TBD-027)

- Coverage goal: ≥ 80% line coverage for `storage/`, `scope/`, and `jobs/`. No global gate until Phase 04.
- CI (proposed GitHub Actions): Windows and Ubuntu runners × Python 3.12/3.13 → `ruff check`, `ruff format --check`, `mypy`, `pytest`. Frontend lint/typecheck/test/build when it exists. No network-dependent jobs.
