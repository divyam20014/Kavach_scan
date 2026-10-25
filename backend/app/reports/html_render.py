"""Semantic HTML report rendering (MASTER_SPEC §10.1/§10.2).

Every piece of operator/scanner-derived text is passed through `html.escape` before being
placed in the page — titles, notes, evidence excerpts and imported content are never trusted
as markup (Phase 08/09's "never render raw HTML" rule applies here too). The same `ReportData`
object also drives the PDF renderer and the JSON/CSV exporters, so a reader comparing the
HTML to a CSV export sees the identical finding set.
"""

from __future__ import annotations

from html import escape as _e

from app.models.common import Severity
from app.models.finding import Finding
from app.reports.builder import ReportData
from app.services.findings import module_for
from app.services.risk import score_finding

_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFORMATIONAL,
]

_STYLE = """
:root { color-scheme: light; }
body { font-family: -apple-system, 'Segoe UI', Roboto, Arial, sans-serif; color: #1a1a1a;
  margin: 0; line-height: 1.5; }
header.cover { padding: 4rem 2rem; text-align: center; border-bottom: 4px solid #1a1a1a; }
header.cover h1 { font-size: 2rem; margin-bottom: 0.25rem; }
.classification { display: inline-block; padding: 0.25rem 0.75rem; background: #b00020;
  color: #fff; font-weight: 700; letter-spacing: 0.05em; border-radius: 4px; }
main { max-width: 960px; margin: 0 auto; padding: 1rem 2rem 4rem; }
section { margin: 2.5rem 0; page-break-inside: avoid; }
h2 { border-bottom: 2px solid #ccc; padding-bottom: 0.25rem; }
table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
th, td { border: 1px solid #ccc; padding: 0.5rem; text-align: left; vertical-align: top; }
thead { display: table-header-group; } /* repeats on each printed page */
tr { page-break-inside: avoid; }
.sev-critical { color: #b00020; font-weight: 700; }
.sev-high { color: #d2691e; font-weight: 700; }
.sev-medium { color: #b8860b; }
.sev-low { color: #2a6fa3; }
.sev-informational { color: #555; }
.finding { border: 1px solid #ddd; border-radius: 6px; padding: 1rem; margin: 1rem 0;
  page-break-inside: avoid; }
.finding h3 { margin-top: 0; }
.muted { color: #666; font-size: 0.9em; }
.evidence { background: #f6f6f6; border-left: 4px solid #999; padding: 0.75rem;
  white-space: pre-wrap; font-family: ui-monospace, Consolas, monospace; font-size: 0.85em; }
footer.page-footer { text-align: center; color: #888; font-size: 0.8em; padding: 1rem; }
@media print {
  @page { margin: 2cm; }
  a { color: inherit; text-decoration: none; }
  .finding { break-inside: avoid; }
  section { break-inside: avoid-page; }
}
"""


def _sev_class(sev: str) -> str:
    return f"sev-{sev}"


def _fmt(dt: object) -> str:
    return _e(str(dt)) if dt else "—"


def _cover(data: ReportData) -> str:
    p = data.project
    window = ""
    if p.authorization:
        window = (
            f"Authorized window: {_fmt(p.authorization.window_start)} "
            f"to {_fmt(p.authorization.window_end)}"
        )
    return f"""
<header class="cover">
  <p class="classification">{_e(data.filters.classification_label)}</p>
  <h1>{_e(data.filters.title)}</h1>
  <p>{_e(p.client_name)} — {_e(p.name)}</p>
  <p class="muted">Generated {_fmt(data.generated_at.isoformat())}</p>
  <p class="muted">{_e(window)}</p>
</header>
"""


def _executive_summary(data: ReportData) -> str:
    total = len(data.findings)
    confirmed = data.status_counts.get("confirmed", 0)
    rows = "".join(
        f'<tr><td class="{_sev_class(s.value)}">{_e(s.value.title())}</td>'
        f"<td>{data.severity_counts.get(s.value, 0)}</td></tr>"
        for s in _SEVERITY_ORDER
    )
    return f"""
<section aria-labelledby="exec-h">
  <h2 id="exec-h">Executive summary</h2>
  <p>This assessment identified <strong>{total}</strong> finding(s) meeting the selected
  criteria, of which <strong>{confirmed}</strong> are analyst-confirmed. The table below shows
  the distribution by severity, as reported by the checks that were actually executed.</p>
  <table aria-label="Findings by severity">
    <thead><tr><th scope="col">Severity</th><th scope="col">Count</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <p><strong>This report does not claim the assessed system is secure.</strong> It reflects
  only the checks executed within the configured scope and limits — see "Limitations" below.</p>
</section>
"""


def _scope_section(data: ReportData) -> str:
    p = data.project
    auth = p.authorization
    auth_html = "<p>No authorization record is present for this project.</p>"
    if auth:
        auth_html = f"""
    <table aria-label="Authorization">
      <tbody>
        <tr><th scope="row">Organization</th><td>{_e(auth.organization)}</td></tr>
        <tr><th scope="row">Target owner</th><td>{_e(auth.target_owner)}</td></tr>
        <tr><th scope="row">Authorized by</th><td>{_e(auth.authorized_by)}</td></tr>
        <tr><th scope="row">Reference</th><td>{_e(auth.reference or "—")}</td></tr>
        <tr><th scope="row">Window</th>
          <td>{_fmt(auth.window_start)} – {_fmt(auth.window_end)}</td></tr>
      </tbody>
    </table>
"""
    scope = p.scope
    hosts = ", ".join(_e(h) for h in scope.hosts) or "—"
    ports = ", ".join(str(x) for x in scope.ports) or "—"
    return f"""
<section aria-labelledby="scope-h">
  <h2 id="scope-h">Scope and authorization</h2>
  {auth_html}
  <table aria-label="Scope definition">
    <tbody>
      <tr><th scope="row">Hosts</th><td>{hosts}</td></tr>
      <tr><th scope="row">Ports</th><td>{ports}</td></tr>
      <tr><th scope="row">Schemes</th><td>{", ".join(_e(s) for s in scope.schemes)}</td></tr>
    </tbody>
  </table>
</section>
"""


def _methodology_section(data: ReportData) -> str:
    modules = sorted({s.scan.module.value for s in data.scans}) or ["none executed"]
    tool_rows = (
        "".join(
            f"<tr><td>{_e(k)}</td><td>{_e(v)}</td></tr>"
            for k, v in sorted(data.tool_versions.items())
        )
        or '<tr><td colspan="2">No external tool versions were recorded.</td></tr>'
    )
    return f"""
<section aria-labelledby="method-h">
  <h2 id="method-h">Methodology</h2>
  <p>Modules exercised: {", ".join(_e(m) for m in modules)}.</p>
  <table aria-label="Tool versions">
    <thead><tr><th scope="col">Tool</th><th scope="col">Version</th></tr></thead>
    <tbody>{tool_rows}</tbody>
  </table>
</section>
"""


def _coverage_section(data: ReportData) -> str:
    rows = (
        "".join(
            f"<tr><td>{_e(s.scan.scan_id[:12])}…</td><td>{_e(s.scan.module.value)}</td>"
            f"<td>{_e(s.scan.state.value)}</td><td>{s.coverage_total}</td>"
            f"<td>{s.coverage_skipped}</td><td>{s.coverage_errors}</td></tr>"
            for s in data.scans
        )
        or '<tr><td colspan="6">No scans matched the selected filters.</td></tr>'
    )
    return f"""
<section aria-labelledby="coverage-h">
  <h2 id="coverage-h">Scan coverage</h2>
  <table aria-label="Scan coverage">
    <thead><tr><th scope="col">Scan</th><th scope="col">Module</th><th scope="col">State</th>
    <th scope="col">Checks</th><th scope="col">Skipped</th><th scope="col">Errors</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</section>
"""


def _finding_html(data: ReportData, f: Finding) -> str:
    assets_by_id = {a.asset_id: a for a in data.assets}
    linked_assets = [assets_by_id[aid] for aid in f.affected_asset_ids if aid in assets_by_id]
    breakdown = score_finding(f, linked_assets)
    mappings = (
        "".join(
            f"<li>{_e(m.catalog)} {_e(m.catalog_version)} — {_e(m.entry_id)}"
            f"{f': {_e(m.title)}' if m.title else ''}"
            f' <span class="muted">({_e(m.rationale)})</span></li>'
            for m in f.mappings
        )
        or "<li>No standards mapping assigned.</li>"
    )
    cvss_html = ""
    if f.cvss:
        cvss_html = (
            f"<p><strong>CVSS {_e(f.cvss.version)}:</strong> "
            f"<code>{_e(f.cvss.vector)}</code> — base score {f.cvss.base_score} "
            f"(verified by {_e(f.cvss.calculator or 'cvss')})</p>"
        )
    refs = "".join(f'<li><a href="{_e(r)}">{_e(r)}</a></li>' for r in f.references)
    evidence = data.evidence_by_finding.get(f.finding_id, [])
    evidence_html = "".join(
        f'<div class="evidence">{_e(ev.request_excerpt)}\n\n{_e(ev.response_excerpt)}</div>'
        for ev in evidence
    )
    sources = "".join(
        f"<li>{_e(s.tool)} {_e(s.tool_version)} — rule {_e(s.rule_id or '—')}"
        f"{f', original rating: {_e(s.original_severity)}' if s.original_severity else ''}</li>"
        for s in f.sources
    )
    reproduction = ""
    if f.technical_detail:
        reproduction = (
            "<p><strong>Reproduction / technical detail:</strong></p>"
            f'<div class="evidence">{_e(f.technical_detail)}</div>'
        )
    url_line = f"<p><strong>Affected URL/endpoint:</strong> {_e(f.url)}</p>" if f.url else ""
    impact_line = (
        f"<p><strong>Business impact:</strong> {_e(f.business_impact)}</p>"
        if f.business_impact
        else ""
    )
    refs_block = f"<p><strong>References:</strong></p><ul>{refs}</ul>" if refs else ""
    status_line = (
        f"Confidence: {_e(f.confidence.value)} · "
        f"Analyst status: {_e(f.analyst_status.value)} · "
        f"Module: {_e(module_for(f))} · "
        f"Internal risk score: {breakdown.score}/100 ({_e(breakdown.tier)}) — not CVSS"
    )
    return f"""
<article class="finding" id="finding-{_e(f.finding_id)}">
  <h3><span class="{_sev_class(f.severity.value)}">{_e(f.severity.value.upper())}</span>
  {_e(f.title)}</h3>
  <p class="muted">{status_line}</p>
  {url_line}
  <p>{_e(f.summary) or "<em>No summary provided.</em>"}</p>
  {reproduction}
  {evidence_html}
  {impact_line}
  <p><strong>Remediation:</strong> {_e(f.remediation) or "Not yet documented."}</p>
  {cvss_html}
  <p><strong>Standards mapping:</strong></p><ul>{mappings}</ul>
  {refs_block}
  <p><strong>Source provenance:</strong></p><ul>{sources}</ul>
</article>
"""


def _findings_section(data: ReportData) -> str:
    if not data.findings:
        body = (
            "<p>No findings were detected by the checks executed, within the selected "
            "criteria and the scan limits described below. This report does not claim the "
            "assessed system is secure — see Scan health and limitations.</p>"
        )
    else:
        body = "".join(_finding_html(data, f) for f in data.findings)
    return f"""
<section aria-labelledby="findings-h">
  <h2 id="findings-h">Finding details ({len(data.findings)})</h2>
  {body}
</section>
"""


def _assets_section(data: ReportData) -> str:
    if not data.assets:
        return ""
    rows = "".join(
        f"<tr><td>{_e(a.locator)}</td><td>{_e(a.asset_type.value)}</td>"
        f"<td>{_e(a.scope_status.value)}</td><td>{_e(a.criticality or '—')}</td></tr>"
        for a in data.assets
    )
    return f"""
<section aria-labelledby="assets-h">
  <h2 id="assets-h">Attack surface inventory ({len(data.assets)})</h2>
  <table aria-label="Asset inventory">
    <thead><tr><th scope="col">Locator</th><th scope="col">Type</th><th scope="col">Scope</th>
    <th scope="col">Criticality</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</section>
"""


def _limitations_section(data: ReportData) -> str:
    items = "".join(f"<li>{_e(x)}</li>" for x in data.limitations)
    return f"""
<section aria-labelledby="limits-h">
  <h2 id="limits-h">Scan health and limitations</h2>
  <ul>{items}</ul>
</section>
"""


def _appendix_section(data: ReportData) -> str:
    from app.standards import CATALOGS

    catalog_rows = "".join(
        f"<tr><td>{_e(c.label)}</td><td>{_e(c.version)}</td><td>{_e(c.source)}</td></tr>"
        for c in CATALOGS.values()
    )
    return f"""
<section aria-labelledby="appendix-h">
  <h2 id="appendix-h">Appendix</h2>
  <h3>Standards catalogs referenced</h3>
  <table aria-label="Standards catalogs">
    <thead><tr><th scope="col">Catalog</th><th scope="col">Version</th>
    <th scope="col">Source</th></tr></thead>
    <tbody>{catalog_rows}</tbody>
  </table>
  <h3>Severity and confidence definitions</h3>
  <p>Severity reflects the technical impact a scanner or imported report assigned, never
  recalculated by this application. Confidence reflects how certain the detection mechanism
  was (Confirmed, Probable, Potential, Needs review). An internal risk score, shown separately
  and never labelled CVSS, additionally weighs asset criticality, exposure, and verification
  evidence for triage — see the in-app Risk Scoring documentation.</p>
  <p class="muted">Report generated by VAPT Workbench {_e(data.filters.classification_label)}
  at {_fmt(data.generated_at.isoformat())}.</p>
</section>
"""


def render_html(data: ReportData) -> str:
    sections = "".join(
        [
            _executive_summary(data),
            _scope_section(data),
            _methodology_section(data),
            _coverage_section(data),
            _findings_section(data),
            _assets_section(data),
            _limitations_section(data),
            _appendix_section(data),
        ]
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(data.filters.title)} — {_e(data.project.name)}</title>
<style>{_STYLE}</style>
</head>
<body>
{_cover(data)}
<main>
{sections}
</main>
<footer class="page-footer">{_e(data.filters.classification_label)} —
do not distribute outside the authorized recipients.</footer>
</body>
</html>
"""
