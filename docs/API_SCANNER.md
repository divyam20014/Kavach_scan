# API Security Scanner — Module 7 (Option C)

> Code: `backend/app/scanners/apisec/` and routes in `backend/app/api/apisec.py`. Rule catalog: `vapt-api-rules` 1.0.0 (`app/scanners/apisec/rules.py`), registered in the shared registry. Mappings use **OWASP API Security Top 10:2023** (tracked independently from the web Top 10).

## 1. Spec import and validation (offline)

- **Formats:** OpenAPI 3.0/3.1 and Swagger 2.0, JSON or YAML. JSON via stdlib `json`; YAML via `yaml.safe_load` **only** (no object construction, no code execution — enforced by `tests/test_static_guards.py::test_yaml_is_loaded_safely`).
- **Bounds (reject, not truncate):** raw size ≤ 8 MB, ≤ 200k nodes, nesting ≤ 64, ≤ 3000 operations.
- **`$ref`:** local pointers (`#/...`) resolved with cycle detection and a depth cap; a cycle is broken (recorded), never looped. **Remote/URL `$ref` is never fetched** (disabled by default, TBD-058); each is recorded as an unresolved remote reference with a warning.
- **Storage:** the raw upload is stored verbatim as `raw.bin` (never executed); the display filename is sanitized; `source_type="openapi_spec"`.
- **Server URLs** are extracted (OpenAPI `servers` with variable expansion; Swagger `host`+`basePath`+`schemes`) and **validated against project scope** before any request. A server is never trusted just because it is in the spec. Warnings cover ambiguous server variables, missing/unresolved refs, and no-server specs.

Endpoints (all offline, zero network): `POST /api/projects/{id}/api-specs` (upload+parse+inventory), `GET .../api-specs` (list), `GET .../api-specs/{import}` (detail inventory), `GET .../api-specs/{import}/validate` (servers in/out of scope, refs, warnings).

## 2. Inventory (dry mode)

Per operation: operationId, method, path, tags, summary, deprecated, auth scheme(s), `security_required`, parameters (name/location/required/type), request content types, request-schema properties and required fields, response codes/content types, and **mutability** (GET/HEAD/OPTIONS = read-only; everything else = potentially mutating). Operations can be excluded or explicitly selected. "Inventory only" mode (default) makes **zero** network requests — proven by `tests/test_apisec_scan.py::test_inventory_only_makes_zero_requests`.

## 3. Safety posture (scan parameters)

Parameters are validated at submit (unknown keys rejected, 422). Defaults are safe:

| Area | Default | Gate to enable |
|---|---|---|
| `inventory_only` | **true** (no requests) | operator turns it off and picks an in-scope server |
| error-leakage / config / mass-assignment inventory | on (offline+passive or bounded GET) | — |
| unauthenticated baseline | off | select it |
| **BOLA/IDOR** | off | ≥2 test identities + object-ownership map + `risk_ack`; read-only ops only |
| **mass-assignment write** | off | test-safe ops + fixture + cleanup + `risk_ack` (live writes never performed; skipped with reason) |
| **rate-limit probe** | off | designated safe operation; small cap (≤20), backs off on 429/503/latency |

**Credentials** are referenced by env/keychain alias only (`env:NAME`), resolved at request time and **never stored**; evidence and outputs are redacted. Auth material in the scan parameters is a `secret_ref` alias, not a value.

## 4. Network checks (only when not inventory-only and the server is in scope)

Every request goes through `HttpService → ScopeGuard → budgeted pinned transport`; requests only ever reach the approved server (`tests/test_apisec_scan.py::test_network_checks_only_hit_approved_server`, `::test_out_of_scope_server_is_never_contacted`).

- **Config / transport (API-CFG-001/002/003, API-INFO-001):** missing `nosniff`/HSTS, plain-HTTP server, permissive CORS (reflected untrusted Origin **with credentials** = finding; `*` = observation only — no over-claim), version disclosure.
- **Error leakage (API-ERR-001/002):** stack-trace/framework-exception signatures (Python, Java, PHP, .NET, Node, Rails) in responses; short redacted excerpt only.
- **Auth baseline (API-AUTH-001/002):** unauthenticated requests to protected read-only ops; a 2xx is reported with the explicit caveat that **status alone is not proof**.
- **BOLA/IDOR (API-BOLA-001/000):** with two identities and an ownership map, a bounded owner-vs-other comparison per mapped object (read-only). Same object returned to the other identity = possible BOLA; different bodies = manual review; otherwise pass. **No ID guessing/enumeration; no mutation of another user's resource.** Prerequisites absent → skipped with reason.
- **Mass assignment (API-MASS-001/000):** request schemas are inventoried for sensitive writable properties (role/admin/owner/tenant/balance/price…) as a **low/potential** finding, distinct from a verified unauthorized change. The write probe is never run against live systems in this build (skipped with reason).
- **Rate limit (API-RATE-001/000):** a small capped benign sequence on one designated safe operation; backs off immediately on 429/503 or high latency; a probe that doesn't trip a limit is explicitly **not** proof none exists.

## 5. Report & outputs

`work/inventory.json`, `work/summary.json` (spec kind/version/hash via import, server, inventory-only flag, operations total/tested/skipped-with-reasons, requests sent, auth aliases by name, check-outcome counts as a **list**, findings, warnings, remote refs, limitations), `work/coverage.json` (every rule: pass/observation/finding/skipped/error with rationale — a skipped precondition is never a pass). Findings are normalized with sanitized evidence and mapped to CWE + OWASP API Top 10:2023 with confidence. All outputs are redacted at write and on read.

## Limitations

HTTP status is never treated as proof; BOLA uses only provided identities/IDs (no enumeration); live mutating writes are not performed; a passed rate probe doesn't prove a limit exists; remote `$ref` is not fetched; CVE mapping needs an imported catalog (Phase 11).
