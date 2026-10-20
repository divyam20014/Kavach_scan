# Security Model — VAPT Workbench

> **Status:** Updated for Phase 01 (2026-10-20). Implemented controls are marked **Implemented** with test references below; earlier Phase 00 controls: the **loopback-only bind policy** (`backend/app/core/config.py`; `tests/test_bind_policy.py`, `tests/test_main_entrypoint.py`), the **loopback-peer guard** (`backend/app/core/loopback_guard.py`; `tests/test_loopback_guard.py`), and the **`.gitignore` safety net** (`tests/test_repo_hygiene.py`). Every other control below is a design commitment, owned by the phase listed.

## 1. Security objectives

1. The Workbench must never become a tool for attacking systems the operator is not authorized to test (scope is a product control, not a disclaimer).
2. Client data (targets, findings, evidence, reports) stays on the operator's machine unless the operator exports it.
3. Secrets (target credentials, API keys for optional data sources) never appear in plaintext records, logs, evidence, exports, or reports.
4. Untrusted input (target responses, uploaded reports, API specs, archives) cannot execute code, read arbitrary files, or inject content into the UI or reports.
5. The Workbench's own local API cannot be driven by other users on the network or by malicious web pages in the operator's browser.

## 2. Assets

| Asset | Sensitivity | Where it lives |
|---|---|---|
| Client/project metadata, scope, authorization records | Confidential | `VAPT_DATA_DIR/projects/<id>/project.json` |
| Findings, evidence excerpts, asset inventories | Confidential (may describe exploitable weaknesses) | Project subdirectories |
| Uploaded third-party scan reports and API specs | Confidential, untrusted content | `projects/<id>/imports/`, `api-specs/` |
| Generated reports and exports | Confidential; leaves the system by design | `projects/<id>/reports/`, operator-chosen export path |
| Test-identity credentials, data-source API keys | **Secret** | **Not stored**. Referenced as `env:NAME` aliases (TBD-010) |
| Audit log | Integrity-critical | `audit/*.jsonl` |
| The Workbench process and host | Integrity | Operator workstation |

## 3. Actors

| Actor | Trust |
|---|---|
| Operator (single local user) | Trusted to act within an authorization they attest to; not trusted to bypass safety controls by accident |
| Target systems | **Untrusted.** Responses may be malicious (XSS payloads, huge bodies, redirect tricks, DNS rebinding) |
| Authors of imported reports and specs | **Untrusted** (XXE, zip bombs, script injection, path traversal) |
| Other local OS users | Untrusted. Must not read the data dir (permissions) or use the API (localhost binding is not user isolation, see §5.1) |
| Network peers | Untrusted. Cannot reach the API under the default bind |
| Malicious web pages in the operator's browser | Untrusted (CSRF / DNS-rebinding against `127.0.0.1`) |
| Optional external tools (nmap, sslyze, testssl.sh) | Semi-trusted binaries. Output is treated as untrusted data |
| Optional external data providers (CVE feeds, CT logs) | Untrusted data sources. Disabled by default (TBD-018) |
| Report recipients (clients) | Trusted to receive the selected content only |

## 4. Trust boundaries and controls

### B1 — Browser ↔ local API

| Threat | Control | Status |
|---|---|---|
| Remote network access to the API | Bind to `127.0.0.1` by default; `localhost` is mapped to `127.0.0.1` (no hosts-file dependence). Non-loopback bind refused at startup until secure mode exists (TBD-003). | **Implemented** (`core/config.py`; `test_bind_policy.py`, `test_main_entrypoint.py`; manual smoke test refused `0.0.0.0` with exit 2) |
| Bypass by launching the ASGI app directly (`uvicorn app.main:app --host 0.0.0.0`) | `LoopbackOnlyMiddleware` returns 403 (HTTP) or closes with 1008 (WebSocket) for any peer that is not a loopback IP literal. `X-Forwarded-For` is ignored. | **Implemented** (`core/loopback_guard.py`; `test_loopback_guard.py`). Residual: a same-host reverse proxy appears as loopback (§5). |
| CSRF from a malicious page to `127.0.0.1` | Require `Content-Type: application/json` on state-changing routes (forces CORS preflight), strict CORS allowlist (no `*`), custom header / CSRF token if cookies are introduced | Design, Phase 01/12 |
| DNS rebinding against the local API | Validate the `Host` header against an allowlist (`127.0.0.1:<port>`, `localhost:<port>`) | **Implemented** (`core/loopback_guard.py`; `tests/test_loopback_guard.py`) |
| XSS in UI from imported or target-derived content | React default escaping; never use `dangerouslySetInnerHTML` for untrusted data; CSP on the UI | Design, Phase 02/12 |
| Oversized or malformed requests | Request size limits, Pydantic validation, consistent error format without stack traces | **Implemented** (`core/request_guards.py`, `core/errors.py`; `tests/test_api_system.py`) |
| Remote mode (future) | Argon2id local password file, secure session cookies, CSRF, strict CORS, TLS, startup refusal if any prerequisite is missing | Design, Phase 12 |

### B2 — Application ↔ filesystem (data root)

| Threat | Control | Status |
|---|---|---|
| Path traversal / absolute paths / symlink escape via IDs or filenames | IDs generated server-side with a strict regex; filenames never used as paths (opaque names); every resolved path checked to be under the data root after `resolve()`; symlinks rejected | **Implemented** (`storage/`; `tests/test_{paths,atomic,locking,repository}.py`; POSIX modes untested on Windows) |
| Half-written or corrupt records | Atomic temp-file + fsync + `os.replace`; validation on read; corrupt records reported, not fatal to other projects | **Implemented** (`storage/`; `tests/test_{paths,atomic,locking,repository}.py`; POSIX modes untested on Windows) |
| Concurrent writers / second instance | Per-record locks; exclusive `instance.lock` | **Implemented** (`storage/`; `tests/test_{paths,atomic,locking,repository}.py`; POSIX modes untested on Windows) |
| Other local users reading data | POSIX `0700`/`0600`; Windows per-user `%LOCALAPPDATA%` ACL inheritance (documented limitation) | **Implemented** (`storage/`; `tests/test_{paths,atomic,locking,repository}.py`; POSIX modes untested on Windows) |
| Evidence committed to Git | Data dir outside repo by default; `.gitignore` safety net | **Implemented** (`.gitignore`; `test_repo_hygiene.py`) |

### B3 — Application ↔ target systems (outbound network)

| Threat | Control | Status |
|---|---|---|
| Scanning unauthorized hosts (typos, redirects, discovered links, spec `servers`) | Mandatory scope gate before every request, redirect, DNS result, port probe, and subprocess target. Deny by default. | Design, Phase 03 (see [SCAN_SAFETY.md](SCAN_SAFETY.md)) |
| SSRF into internal networks / cloud metadata | Block private, loopback, link-local, multicast, reserved, and metadata IPs after resolution. Re-check on every connection and redirect. | Design, Phase 03/05 |
| Disruption of targets | Low default rate, concurrency, and budgets; backoff on 429/503; no DoS/fuzzing; injection probes off by default | Design, Phase 04/05 |
| Malicious responses (huge, compressed, slow) | Byte caps, decompression caps, timeouts, content-type allowlist | Design, Phase 05 |
| Unauthorized expiry | Authorization window checked at start and during the run | Design, Phase 03/04 |

### B4 — Application ↔ external scanner processes

| Threat | Control | Status |
|---|---|---|
| Command injection | Argument arrays only, never `shell=True`; executable allowlist; argument allowlist per tool | Design, Phase 05/06/11 |
| Runaway processes | Timeouts, kill-tree on cancel, output byte caps | Design, Phase 04/05 |
| Malicious tool output | Parse as untrusted (hardened XML, bounded JSON), from an isolated temp dir | Design, Phase 06/11 |
| Executing uploaded files | Never. Uploaded content is not executable and is never placed on an executable path. | Design, Phase 08 |

### B5 — Uploaded files (reports, API specs, archives)

| Threat | Control | Status |
|---|---|---|
| XXE / billion laughs | `defusedxml` (or an equivalent hardened parser); no DTD or entity resolution | Design, Phase 08 |
| Zip bombs / zip-slip | Entry count and expanded-size caps; reject absolute paths, `..`, and symlinks | Design, Phase 08/10 |
| YAML code execution | `yaml.safe_load` only | Design, Phase 07 |
| Remote `$ref` SSRF | Remote refs disabled by default; if enabled, scope-checked and capped | Design, Phase 07 |
| Stored XSS via imported titles/evidence | Escape at render in UI and reports; sanitize allowed HTML | Design, Phase 08/10 |

### B6 — Secrets

| Rule | Status |
|---|---|
| Secrets referenced as `env:NAME` aliases; values resolved at use time and never persisted | Partial: `SecretRef` type (`env:NAME`) in `models/common.py`; resolution in Phase 05/07 (TBD-010) |
| Central redactor applied before every log, event, evidence, and export write (Authorization, Cookie, Set-Cookie, `*token*`, `*secret*`, `*password*`, API-key patterns, JWTs, query-string secrets) | **Implemented** for logs, audit and evidence excerpts (`core/redaction.py`; `tests/test_redaction.py`, `tests/test_audit_jsonl.py`); exports in Phase 10 |
| Settings API never returns secret values (write-only fields) | Design, Phase 11 |
| `.env` and key files are git-ignored; only `.env.example` is tracked | **Implemented** (`.gitignore`; `test_repo_hygiene.py`) |

### B7 — Optional external data providers

All disabled by default (TBD-018). When enabled: explicit configuration, rate limits, disclosure in scan metadata, and **no target credentials, response contents, or client identifiers** sent beyond the minimum query (e.g., a domain for CT logs, which is itself a disclosure the operator must accept).

### B8 — Report recipients

Reports contain only the selected findings and assets. They exclude secrets, raw sensitive bodies, local absolute paths, and stack traces. They state limitations honestly and never claim "secure" (Phase 10). Report files carry a checksum, and their generation is audited.

## 5. Residual risks and limitations

0. **Same-host proxies defeat the peer guard.** A reverse proxy, SSH tunnel, or dev proxy on the same machine presents remote clients as `127.0.0.1`. Do not expose the app that way until secure mode exists.
1. **Localhost is not user isolation.** On a shared multi-user host, other local users can reach `127.0.0.1:<port>`. The first release assumes a single-user workstation. Remote or multi-user use requires the TBD-003 secure mode.
2. **Windows file permissions** rely on the per-user profile ACL rather than explicit mode bits.
3. **Operator attestation is not legal verification.** The tool records it and makes it visible. It cannot prove authorization.
4. **Scope controls are only as good as the scope entered.** A wrongly entered in-scope host will be scanned.
5. **DNS rebinding** is mitigated by pinning the resolved, validated IP per connection (Phase 05). Residual risk remains if the adapter is bypassed, which is why direct network imports outside `integrations/` will be lint- and test-checked.
