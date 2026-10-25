# Safe Scan Runbook — VAPT Workbench

> A step-by-step procedure for running a scan safely. If you only read one section, read §1 and §6.

## 1. Authorization first, every time

Do not scan anything without explicit, current, written authorization. When you create a project, record:
- the organization, target owner, and who authorized the test;
- an authorization window (start/end) — a scan outside that window is blocked, not just warned about;
- the operator attestation checkbox. This is a recorded statement, **not legal verification** — you are responsible for having real authorization.

If authorization lapses mid-engagement, update the project's authorization window before scanning again; an expired-authorization scan attempt is refused and logged.

## 2. Define scope narrowly

List only the hosts/schemes/ports you are authorized to test. Prefer explicit hostnames over wildcard domains where possible. Add path-prefix exclusions for anything explicitly out of bounds (e.g. a `/private` admin area you were told not to touch).

**Private/internal IP ranges, loopback, and cloud metadata addresses are blocked by default and cannot be scanned via ordinary scope.** This is intentional — it is the single strongest protection against accidentally scanning infrastructure you don't control. If a specific internal range is genuinely in scope for this engagement, use the project's internal-target override (narrow IP range, an explicit reason, a time-bound expiry) — every use of it is audited.

## 3. Preview before you run

Every scan module shows a profile preview before you confirm:
- what will run and what will be skipped (and why — e.g. "sslyze and testssl.sh not installed");
- the rate limit, concurrency, max pages/duration, and request budget that will be enforced;
- for the API scanner, exactly which operations are in scope.

Read it. If something looks wrong (wrong host, unexpected module enabled), fix the project's scope/policy before confirming.

## 4. Start conservative

- **Web scanner:** leave `tls_verify` on and `respect_robots` on unless you have a specific, documented reason to change them. Active injection probes do not exist in this build (TBD-049) — passive indicators only.
- **Attack surface mapper:** the default port list is a conservative, explicit set, not a full 1–65535 sweep. Widen it deliberately, not by default.
- **API scanner:** start with `inventory_only` to confirm the spec/server mapping is correct (it sends zero requests) before running baseline checks. IDOR/BOLA checks require you to supply two real test identities and an explicit ownership map — they are refused, not guessed, without both.

## 5. Watch it run

The scan detail page shows live progress, a stage timeline, counters, and warnings. You can cancel at any point — cancellation is immediate and the partial results up to that point are kept, clearly marked incomplete. The visible **kill switch** (in the header) stops every active scan across every project at once if you need an emergency stop.

## 6. What this build will never do during a scan

- Send an active exploit payload (SQLi, XSS, or otherwise) — passive indicators only (TBD-049).
- Probe for sensitive files by guessing paths (TBD-050).
- Perform a mutating/destructive API write, even when a check is "enabled" — schema inventory only (Module 7.5).
- Use stealth/SYN scanning, OS fingerprinting, or NSE scripts via Nmap — TCP-connect only, a fixed safe argument list.
- Follow a redirect out of scope, or resolve a target to a private/metadata IP without your explicit internal-target override.
- Send credentials you didn't explicitly configure, or log a secret value anywhere (request headers, response bodies, evidence, and logs are all redacted before storage).

## 7. After the scan

- Review findings in the workbench; set analyst status/priority as you triage.
- Check the **Scan health and limitations** section before trusting a quiet result — it lists what was skipped and why. A zero-finding scan is phrased as "no findings detected by the checks executed," never "secure."
- Generate a report when ready (`docs/REPORTING.md`) and export/back up the project data as needed.

## 8. If something goes wrong

- **Scan stuck or misbehaving:** cancel it from the scan detail page, or use the kill switch.
- **Suspect the tool contacted something out of scope:** check **Audit** (every scope decision, including blocked attempts, is logged) and the scan's own event log.
- **Need help troubleshooting:** download a diagnostic support bundle from Settings (`docs/TROUBLESHOOTING.md`) — it's redacted and safe to share with a developer.
