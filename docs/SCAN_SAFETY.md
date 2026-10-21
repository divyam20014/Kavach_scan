# Scan Safety Policy — VAPT Workbench

> **Status:** §2–5 **implemented in Phase 03** (`backend/app/scope/`); §6–8 are enforced from Phase 04/05 on. **No scanning capability exists yet**: there is still no HTTP client, DNS resolver or subprocess code; Phase 05 adapters must call `ScopeGuard`.
>
> Original baseline note: There is no HTTP client, DNS resolver, socket, or subprocess usage in `backend/app/`, and `/api/version` reports `scanning_available: false`. This document is the binding policy that Phases 03–07 must implement and test. Default values marked *(TBD-0xx)* are proposals awaiting owner confirmation.

## 1. Principles

1. **Deny by default.** If a target, redirect, IP, port, or path cannot be parsed, resolved, and positively matched to scope, it is blocked.
2. **One gate, no bypass.** Every outbound action passes through the shared scope engine (`backend/app/scope/`, Phase 03), called by the shared adapters (`backend/app/integrations/`, Phase 05). Scanner modules cannot import raw network or process libraries.
3. **Blocked is an event, not a silence.** Each block produces a structured `scope_blocked` event with target, rule, and reason, and increments a counter shown in the UI and report.
4. **Conservative, visible, stoppable.** Low defaults, every limit displayed before start, live progress, and cancellation at any time.
5. **No offensive tradecraft.** See §9 for prohibited behaviors.

## 2. Authorization

| Requirement | Design |
|---|---|
| Authorization record per project | Client/org, target owner, authorized-by, reference, start/end window (UTC), notes, attestation event ID |
| Operator attestation | Explicit confirmation labelled **"Operator attestation"** (not legal verification), stored as a timestamped audit event with a scope hash |
| Scan-start confirmation | Confirmation screen showing normalized targets, exclusions, enabled checks, limits, and active-probe toggles. Confirming writes an audit event. |
| `require_active_authorization` | Called at job creation and again at `validating`. Absent, not-yet-started, or expired → job state `expired_authorization`, no traffic. |
| Expiry during a run | Worker checks the window before each scheduling step. When the end is crossed: stop scheduling, cancel in-flight work, final state `expired_authorization` with partial results preserved. |
| Scope change | Requires a new preview and a new audit event. Running jobs keep their **snapshot** (hash stored in the job). |

## 3. Scope model

| Element | Rule |
|---|---|
| Schemes | Web/API: `http`, `https` only. `file:`, `ftp:`, `gopher:`, `javascript:`, `data:`, and anything else are rejected. |
| Exact hosts | Lowercase. IDNA → punycode (A-label). Trailing dot stripped. Default ports stripped for comparison. |
| Wildcard domains | `*.example.com` matches `a.example.com` and `a.b.example.com`. It does **not** match `example.com` unless that is listed separately. Matching is label-boundary based, so `trusted.example` never matches `nottrusted.example` or `trusted.example.attacker.test`. |
| IP / CIDR | Only when explicitly supplied. IPv4 and IPv6, canonical form. |
| Ports | Allowlist per project. Default `80, 443` for web. Port-scan list per TBD-012. |
| Path prefixes | Normalized: percent-decoding of unreserved characters, dot-segment removal. Prefix match on segment boundaries (`/api` does not match `/apiary`). Encoded traversal (`%2e%2e`, `%2f`) is normalized before matching or rejected as ambiguous. |
| Exclusions | Hosts, CIDRs, ports, and path prefixes. **Exclusions always win** over inclusions. |
| User-info in URL | `https://user:pass@host` is **rejected** (credential leak plus host-confusion trick). |
| API server URLs | Must independently match scope. A server URL is never trusted because it appears in a spec. |

## 4. Allow/deny decision procedure

Every candidate action runs these checks in order. The first failure blocks the action and records its reason.

```text
1. kill switch engaged?                         → block (kill_switch)
2. authorization active for project?            → else block (authorization_expired / absent)
3. parse + canonicalize target                  → failure: block (unparseable / ambiguous)
4. scheme allowed?                              → else block (scheme_not_allowed)
5. user-info present?                           → block (userinfo_in_url)
6. host matches inclusion (exact/wildcard/IP)?  → else block (host_out_of_scope)
7. host/IP matches an exclusion?                → block (excluded)
8. port allowed?                                → else block (port_not_allowed)
9. path allowed and not excluded?               → else block (path_out_of_scope)
10. resolve DNS → for EVERY resulting IP:
      IP in default-blocked ranges (§5)?        → block unless a project internal-override covers it
      IP inside an excluded CIDR?               → block
      (when the scope is IP-based) IP in allowed CIDR? → else block
11. budget available (rate / request / time)?   → else defer or stop (budget_exhausted)
→ ALLOW. The decision records target, resolved IP, rule matched, scope hash, and decision ID.
```

The connection is then made **to the validated IP** (pinned, with the original Host header and SNI) so a second DNS answer cannot redirect it (DNS-rebinding defense). Redirects re-enter at step 3. Discovered links, subdomains, and hosts re-enter at step 3 **and** are never auto-admitted into scope. Subdomain candidates stay `pending_approval` until the operator admits them.

## 5. Default-blocked address ranges

Blocked by default. They are reachable only through an explicit project-level **internal-target override**, which needs the specific CIDR or host, a reason, an expiry, and an audit event. The override is never accepted from a per-request payload or a hidden config flag.

| Range | Why |
|---|---|
| `0.0.0.0/8`, `::/128` | Unspecified / "this network" |
| `127.0.0.0/8`, `::1/128` | Loopback |
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | RFC 1918 private |
| `100.64.0.0/10` | Carrier-grade NAT (also Alibaba metadata `100.100.100.200`) |
| `169.254.0.0/16`, `fe80::/10` | Link-local (includes the AWS/GCP/Azure metadata address `169.254.169.254`) |
| `168.63.129.16/32` | Azure platform/wire server |
| `fd00:ec2::254/128` | AWS IMDS over IPv6 |
| `fc00::/7` | IPv6 unique-local |
| `224.0.0.0/4`, `ff00::/8` | Multicast |
| `240.0.0.0/4`, `255.255.255.255/32` | Reserved / broadcast |
| `192.0.0.0/24`, `198.18.0.0/15` | IETF protocol assignments / benchmarking |
| `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32` | Documentation |
| `::ffff:0:0/96`, `64:ff9b::/96`, `2002::/16` | IPv4-mapped / NAT64 / 6to4. The **embedded IPv4 address is extracted and re-checked** |

**Implemented:** `app/scope/ip_policy.py` (`BLOCKED_RANGES`; TBD-037 decided). Property testing added `64:ff9b:1::/48`, `2002::/16` (whole), `3fff::/20` and `5f00::/16`. A non-overridable metadata match always wins over an overridable prefix (e.g. metadata embedded in 6to4). The UI shows the list in the wizard preview and on each project's scope policy card.

## 6. Conservative defaults *(TBD-011, TBD-012, TBD-017 — proposals)*

| Limit | Default | Hard cap |
|---|---|---|
| Active jobs (global) | 1 | 4 |
| Concurrent requests per job | 2 | 8 |
| Request rate per host | 2 req/s | 10 req/s |
| Connect / read timeout | 5 s / 15 s | 30 s / 60 s |
| Redirects followed (each validated) | 5 | 10 |
| Crawl depth / pages | 3 / 200 | 10 / 2,000 |
| Response bytes read | 1 MiB | 10 MiB |
| Decompressed bytes | 5 MiB | 20 MiB |
| Max scan duration | 30 min | 8 h |
| Per-target request budget | 2,000 | 20,000 |
| TCP ports | the 20-port list in TBD-012; never `1-65535`, never UDP | — |
| Rate-limit probe | 20 requests, ≤5 req/s, stop on first 429/503 or latency >3× baseline | 50 |
| Injection probes per parameter | 0 (disabled). When enabled: ≤ 6 | 12 |

Backoff: on 429/503 honor `Retry-After` (capped), otherwise exponential backoff per host. Three consecutive network failures for a host pause that host.

## 7. Cancellation and kill switch (design, Phase 04)

- **Cancel (per job):** set the cancellation flag → stop scheduling immediately → cancel in-flight requests at the next await point → terminate the child process tree (graceful, then forced after a grace period) → flush partial results → final state `cancelled`. The UI shows elapsed time, current stage, request count, and the stop control.
- **Kill switch (global):** persisted flag in the data root. Engaging it blocks all new active jobs (step 1 of §4) and requests cancellation of every running job. It survives restart until disengaged. Both actions are audited.
- **Restart:** jobs found `running` or `validating` without a live claim become `interrupted`. They are **never auto-replayed**. The operator may start a new scan after review.

## 8. Evidence minimization and redaction

| Rule | Detail |
|---|---|
| Minimize retrieval | Responses are capped (`max_response_bytes`; decoded bytes at most 2x) and static assets are never fetched. Sensitive-file probing is not built in (TBD-050). Never download archives or backups. |
| Store excerpts, not bodies | Evidence holds status, content-type, bytes read, matched signature, and a ≤ 8 KiB redacted excerpt (TBD-009), plus a truncation flag and SHA-256 of what was read. |
| Redact before write | Headers `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, and any `*token*`/`*secret*`/`*session*` header. Query/body keys matching `pass(word)?|secret|token|api[_-]?key|session|auth`. Values matching JWT, AWS key IDs, private-key PEM blocks, generic high-entropy bearer tokens. Operator-configurable extra patterns. |
| Secret-file hits | Report **that** a signature matched (e.g., "`.env` file served, contains `KEY=`-style lines"), never the values. |
| Escaped vs executable | No XSS test input is sent (TBD-049). A crawled parameter value reflected HTML-escaped is a *pass*; reflected unencoded is a *potential* indicator (`WEB-REFL-001`). Executable XSS is never claimed. |
| Opaque storage | Evidence files have random IDs, restrictive permissions, and are referenced by ID only. |

## 9. Prohibited behaviors (never implemented)

- Stealth or evasion: SYN/stealth scans, decoys, fragmentation, IP rotation, proxy chaining for concealment, WAF bypass, CAPTCHA bypass, user-agent spoofing to evade detection.
- Exploitation: exploit chains, shells, persistence, privilege escalation, lateral movement.
- Credential attacks: brute force, password guessing or spraying, credential stuffing, token theft.
- Destructive or extractive payloads: time-delay SQLi, stacked or destructive SQL, data extraction, file read/write, command execution, out-of-band callbacks.
- Denial of service: stress or load testing, race-condition floods, high-rate fuzzing, huge payloads, endless recursion.
- Nmap: `-sS`, `-sU`, `-A`, `-O`, `--script` with intrusive/vuln/brute/dos/exploit categories, `-p-`, timing above `-T3`.
- Automatic scanning of discovered or unapproved hosts; following out-of-scope redirects; brute-force subdomain enumeration by default.
- Mutating API requests by default; ID guessing or enumeration for IDOR.

## 10. Enforcement points (to be verified by tests)

| Entry point | Required check | Phase / test |
|---|---|---|
| Job creation API | authorization + target scope + module availability + kill switch | 04 |
| HTTP adapter (each request and redirect hop) | full §4 decision with IP pinning | 03 / 05, fixture-server zero-request tests |
| DNS adapter | IP policy on every answer | 03 / 05 |
| TCP connect probe (`app/integrations/tcp.py`) | host + IP + port decision; pinned IP only; nothing sent | **06 (implemented)** |
| Subprocess adapter (nmap, sslyze) | each target argument + argv allowlist (`validate_argv`) | **05/06 (implemented)** / 11 |
| OpenAPI server URL / remote `$ref` | scope decision; remote refs never fetched; server validated before any request | **07 (implemented)**, `tests/test_apisec_scan.py` |
| Static guard | no `httpx`/`requests`/`socket`/`ssl`/`subprocess`/`dns`/`asyncio` imports outside the three adapters; scanners never construct transports or resolve DNS | **05 (implemented)** / 12 |

## 13. API security scanner request path (implemented, Phase 07)

1. Spec import, validation and inventory are **offline** (zero network). YAML is parsed with `safe_load` only; remote `$ref` is never fetched; local refs are cycle/depth bounded; size/depth/operation limits reject oversized specs.
2. A server URL from the spec is contacted only when the operator turns off inventory-only AND the chosen server passes `ScopeGuard.is_target_in_scope`. Every request then goes through `HttpService -> ScopeGuard -> budgeted pinned transport`; nothing else is contacted.
3. Credentials are env/keychain aliases resolved at request time and never stored; evidence and outputs are redacted.
4. BOLA/IDOR runs only with two operator identities and an explicit object-ownership map (read-only, bounded owner-vs-other; no enumeration, no mutation of another user's resource). Mass-assignment writes against live systems are never performed. The rate probe is a small capped benign sequence on one designated safe operation and backs off on 429/503/latency.
5. Coverage reports tested/skipped operations with reasons; a skipped precondition is never a pass; HTTP status alone is never treated as proof.

## 12. Attack surface mapper request path (implemented, Phase 06)

1. Candidates come from targets, the manual/imported `hosts` list, and (opt-in) crt.sh. crt.sh is disclosed in the summary, rate-limited, and contacted only on its public pinned IPs; the target is never contacted for passive discovery.
2. Each candidate is classified DNS-free (`classify_discovered_host`). **Only `in_scope` hosts are resolved for scanning and port-checked/probed**; pending/out-of-scope/excluded candidates are inventoried but never connected. A pending host is admitted only by explicit, audited operator approval.
3. DNS returns A/AAAA/CNAME; every resolved address is validated by the IP policy. Private/link-local/loopback(without override)/cloud-metadata addresses are inventoried as excluded and never connected.
4. Port checks test only ports that are both requested and in scope (explicit conservative list; no ranges). TCP connect opens a full connection to a pinned IP and reads the greeting passively (nothing sent). Optional Nmap runs through the subprocess adapter with a fixed safe argv validated by `validate_argv`; XML parsing rejects DTD/entities and caps size; failure falls back to TCP connect, never a crash. No SYN/stealth, UDP, full-range, `-A/-O/-sV`, or NSE/vuln scripts.
5. Banners are sanitized (printable, redacted, capped); no login is attempted. Web origins reuse Module 5's pinned transport and passive checks.
6. Coverage is reported honestly: which ports/hosts were tested and which were not, with reasons.

## 11. Web scanner request path (implemented, Phase 05)

1. `HttpService.fetch(url)` → `ScopeGuard.authorize_request(url)`: kill switch, authorization window, static scope, DNS via the per-job `CachingResolver`, **every** answer validated, IPs pinned. Blocked → recorded decision, zero traffic.
2. Budgeted transport (`JobContext.requester`): per-target request budget, per-host token bucket, concurrency slot; counted as `requests_sent`.
3. `PinnedHttpTransport`: connects only to a pinned IP; `Host`/SNI = canonical hostname; never resolves, never follows redirects, never uses proxies (proxy environment variables are ignored by construction); connect/read/total timeouts; raw and decoded byte caps; request headers validated (no CR/LF/NUL, no `Host`/framing/hop-by-hop overrides); methods limited to GET/HEAD/OPTIONS/POST (the scanner itself only uses GET).
4. Redirects: each hop is re-authorized with `authorize_redirect` (resolve + validate from scratch). An out-of-scope destination is recorded (`redirects_blocked`) and **not requested**.
5. 429/503: `Retry-After` honoured (at most 30 s) and the host enters a backoff window; at most 2 retries; connection errors are retried only for idempotent methods. Every retry consumes budget; every wait is interruptible.
6. Crawl: same-scope links only (static scope check before queueing), robots.txt honoured by default, depth/page caps, canonical dedup, query-variant cap (10 per path), repeated-segment trap detection, static assets not fetched.
7. External TLS tool: only after `authorize_connect(host, port)`; given the pinned IP (`host:port{ip}` / `--ip`); protocol enumeration and certificate info only; timeout 300 s, output cap 4 MiB, process-tree kill on cancel.
8. Extra probe requests are fixed and small: HTTPS/HTTP root (per host), one CORS request per origin with `Origin: https://vapt-cors-check.invalid`, `robots.txt` per origin.
9. Safe mode is always on: no injection test input (TBD-049) and no sensitive-file probing (TBD-050).

**Current guard (Phase 00):** `backend/tests/test_health.py::test_only_system_routes_exist` fails if any route besides `/api/health` and `/api/version` is added, so no scan-triggering endpoint can appear unnoticed before Phase 04.
