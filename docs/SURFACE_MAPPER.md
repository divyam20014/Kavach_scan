# Attack Surface Mapper — Module 6 (Option B)

> Code: `backend/app/scanners/surface/` and the adapters `app/integrations/{dns,tcp,nmap,passive_sources}.py`. Rule catalog: `vapt-surface-rules` 1.0.0 in `app/scanners/surface/rules.py`, registered into the shared rule registry alongside the web rules.

## Pipeline

`profile → candidates → classification → DNS → port checks → banners → web origins → inventory/findings/coverage → snapshot + change comparison → summary`.

Every outbound action passes `ScopeGuard`: the kill switch, the authorization window, static scope, DNS validation of **every** resolved IP, and IP pinning. Scanners never open sockets or resolve DNS themselves; they use `JobContext` and the `app/integrations` adapters (enforced by `tests/test_static_guards.py`).

## 1. Setup / candidates

- **Targets**: in-scope hostnames, authorized root domains (scope hosts or wildcard bases), or IP literals inside an approved IP range (`check_targets`). Rejected targets block the start with a per-target reason.
- **Manual / imported hosts**: `hosts` parameter (newline/comma separated; URLs reduced to host; `*.x` to `x`); invalid entries are reported, not silently dropped.
- **Passive sources** (`passive_crtsh`, off by default): crt.sh Certificate Transparency. Each authorized **root** is sent to crt.sh (disclosed in the summary); the target is never contacted. The source is rate-limited (one query per root, minimum interval) and connects only to crt.sh's **public** IPs through the pinned transport. Results are untrusted candidates, canonicalized and classified by scope.

## 2. Candidate status (discovery ≠ permission)

Every candidate is classified by `ScopeGuard.classify_discovered_host` (DNS-free): `in_scope`, `pending_approval` (a subdomain of an authorized host/root), `out_of_scope`, `excluded`, or `unresolved` (DNS failed). **Only `in_scope` hosts are port-checked or probed.** Pending/out-of-scope/excluded candidates are inventoried as assets and listed in `hosts_not_checked` with the reason. A pending host is admitted only by explicit operator approval (`POST /api/projects/{id}/assets/{asset}/approve`), which adds it to the scope and writes `asset_approved` + `scope_changed` audit events.

## 3. DNS

A/AAAA and CNAME via the OS resolver (`app/integrations/dns.py::system_records`). TTL is not exposed by the OS resolver, so it is recorded as "unknown". **Every** resolved address is validated against the IP policy; blocked addresses (private, link-local, loopback without override, cloud metadata) are inventoried as excluded IPs and **never connected**. Source/timestamp are recorded.

## 4. Port checks

- Explicit, conservative default list (TBD-055): `21,22,23,25,80,110,143,443,445,993,995,1433,3306,3389,5432,5900,6379,8000,8080,8443,9200,27017`. The operator may override with an explicit list (no ranges; ≤ 100 ports). Only ports that are **both requested and allowed by the project scope** are tested; every requested-but-untested port is reported with the reason (`ports_not_tested`, `SURF-COV-001`).
- **TCP connect** (`app/integrations/tcp.py`): full connect to a pinned IP only, no raw/SYN sockets. Nothing is sent; the service's own greeting is read passively, capped and closed.
- **Nmap** (optional, `app/integrations/nmap.py`): used when installed and `port_method` is `auto`/`nmap`. Fixed safe argv only — `-sT -Pn -n --unprivileged --max-retries {0,1} --host-timeout ≤300s --max-rate ≤50 -p <explicit list> -oX -` and guard-pinned IP literals. `validate_argv` rejects anything else (`-sS/-sU/-A/-O/-sV/--script/-sC/-p-/-T4/-T5/-D/-f/...`). No shell. XML parsing rejects DTD/entity declarations and enforces a size cap; malformed/absent/failed Nmap falls back to TCP connect with a warning, never a failure.
- **Diagnostics**: the profile shows whether Nmap was found; the summary records the method and tool version.

## 5. Services / banners

Port number + passively read greeting → simple service id (`app/scanners/surface/services.py`). Banners are decoded as Latin-1, reduced to printable characters, whitespace-collapsed, **passed through the secret redactor** and capped at 200 chars. No login is attempted and no secret is stored.

## 6. Web origins

Open ports that map to web schemes (or answer with an HTTP banner, or are silent unknown ports) are probed as HTTP(S) origins, reusing Module 5: a verified-TLS root fetch (status, title, headers, TLS basics, certificate expiry) and a tiny same-origin crawl (`web_max_pages`, depth 1) whose responses run the web scanner's passive checks and component detection. The request service caches plain GETs per run so pages are not fetched twice.

## 7. Asset graph & change comparison

Assets form a graph: `domain → hostname → IP → port/service → web origin → endpoint`. `parent_asset_id` is the primary edge; `related_asset_ids` holds extra edges (an IP serving several hostnames). Assets are canonical filesystem records (`Asset` + Phase-06 fields `related_asset_ids`, `attributes`, `resolution_status`, `criticality`), so relationships, first/last-seen and attributes **persist across restarts**; a re-observed asset is updated (last_seen advances), never duplicated. Each scan writes a snapshot (`inventory.json`); the next scan compares against the most recent completed surface snapshot (`changes.json`): new/not-observed hosts, status and IP changes, opened/closed ports (closed only if re-tested), new/not-observed origins. A host absent this scan is "not observed", never "removed".

## 8. Risk ranking (transparent, not CVSS)

`app/scanners/surface/ranking.py`: `score = operator criticality + worst open finding on the asset or any descendant + exposure (+10 for a reachable database/admin/cleartext service)`. Every term is listed in `priority_factors`. Only `confirmed`/`probable` findings that are not false-positive/fixed/accepted count. **Discovery alone scores 0** and says so. Criticality is operator-entered per asset (`PATCH /api/projects/{id}/assets/{asset}`, audited).

## 9. Findings & outputs

Findings (`SURF-SVC-001/002/003` reachable database/admin/cleartext service, `SURF-BANNER-001` version in a greeting) are exposure facts with sanitized evidence; discovery/coverage are observations. Re-observation dedup is shared with Module 5. Outputs under `work/`: `profile.json`, `summary.json` (candidates by status, sources + disclosure, DNS stats, port method + tested/untested, open services, web origins, outcome counts, change counts, tool versions, limitations), `coverage.json`, `inventory.json` (snapshot), `changes.json`, `hosts.json` (per-host DNS and port states). All outputs are redacted at write and again on read.

## API

- `GET /api/projects/{id}/surface-scan-profile` — preview (ports tested/untested, sources, Nmap availability, target problems).
- `GET /api/projects/{id}/surface` — asset graph/table with filters (type, status, search), transparent priority, parent/related edges.
- `PATCH /api/projects/{id}/assets/{asset}` — set/clear operator criticality (audited).
- `POST /api/projects/{id}/assets/{asset}/approve` — add a pending-approval discovered host to scope (confirmed, audited).

## Limitations

TCP only (no UDP, no SYN/stealth, no full-range); no DNS wordlist brute force; no authenticated or logged-in service interaction; CVE matching needs an imported catalog (Phase 11); web probing reuses the web scanner's passive checks only.
