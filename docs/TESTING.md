# Testing Strategy — VAPT Workbench

> **Status:** Phase 00 (2026-10-20). Backend unit tests exist for the health/version skeleton, bind policy, entry point, loopback-peer guard, and `.gitignore` hygiene. Test clients must pass `client=("127.0.0.1", <port>)`, because the guard rejects Starlette's default `testclient` peer. Everything else here is the plan each phase must follow.

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

### Results recorded at Phase 00 verification (2026-10-20, Windows 11, Python 3.13.5)

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

## 5. Network isolation guard (planned, Phase 01)

Add a `conftest.py` autouse fixture that patches `socket.socket.connect` / `getaddrinfo` so that any connection to a non-loopback address fails the test immediately. The fixture-network layer is still allowed loopback. This proves the suite is offline and catches accidental real traffic.

## 6. Phase-specific must-have tests

| Phase | Must test |
|---|---|
| 00 | Health/version, version consistency, localhost default + canonicalization, non-loopback refusal before uvicorn starts, loopback-peer guard, no other routes, 404/405 for unimplemented, `.gitignore` coverage incl. fixture/source false positives (**done**) |
| 01 | CRUD, atomic replace, concurrent writers, truncated JSON, invalid schema, `../` / absolute / encoded / symlink escapes, stale locks, second-instance refusal, index rebuild, restart persistence, log redaction |
| 02 | Project form validation, reload persistence, dashboard counters from API (no constants), empty/offline/error states, keyboard navigation |
| 03 | Each blocked range row, suffix confusion, IDN, IPv6, user-info, non-HTTP schemes, encoded paths, port/path exclusions, redirect to private, rebinding, expiry boundaries (fake clock) |
| 04 | State transitions, duplicate submission, claim race, queue cap, cancel, subprocess timeout/kill, restart → interrupted, kill switch |
| 05–07 | Fixture scans per check, injection disabled by default, escaped-vs-unescaped XSS, response caps, backoff, Nmap argv, missing tools → skipped, OpenAPI malicious specs, IDOR prerequisites |
| 08–10 | Parser fixtures + malformed + XXE/zip-slip/bombs, dry-run immutability, dedupe correctness, report escaping and no-secret assertions, archive round trip |
| 11–13 | Missing/invalid tools, stale catalogs, offline E2E, clean-install check |

## 7. Coverage and CI (TBD-027)

- Coverage goal: ≥ 80% line coverage for `storage/`, `scope/`, and `jobs/`. No global gate until Phase 04.
- CI (proposed GitHub Actions): Windows and Ubuntu runners × Python 3.12/3.13 → `ruff check`, `ruff format --check`, `mypy`, `pytest`. Frontend lint/typecheck/test/build when it exists. No network-dependent jobs.
