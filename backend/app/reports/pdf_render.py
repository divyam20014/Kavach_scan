"""Searchable/text PDF rendering via the maintained `fpdf2` library (MASTER_SPEC §10.1/§10.2,
TBD-065). Content mirrors `html_render.py` section-for-section so the HTML and PDF never
diverge on what they include — both are driven by the same `ReportData` snapshot.

Text is written with `multi_cell`/`cell`, never an image of a page, so the resulting PDF
keeps selectable/searchable text (no screenshots).
"""

from __future__ import annotations

from fpdf import FPDF, XPos, YPos

from app.models.finding import Finding
from app.reports.builder import ReportData
from app.services.findings import module_for
from app.services.risk import score_finding

_MARGIN = 15


class ReportPDF(FPDF):
    def __init__(self, title: str, classification: str) -> None:
        super().__init__(format="A4", unit="mm")
        self._title = title
        self._classification = classification
        self.set_margins(_MARGIN, _MARGIN, _MARGIN)
        self.set_auto_page_break(auto=True, margin=_MARGIN)

    def header(self) -> None:
        if self.page_no() == 1:
            return  # the cover page draws its own heading
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(90, 90, 90)
        self.cell(0, 6, _ascii_safe(self._title), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(200, 200, 200)
        self.line(_MARGIN, self.get_y(), 210 - _MARGIN, self.get_y())
        self.ln(2)
        self.set_text_color(0, 0, 0)

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 8, _ascii_safe(f"{self._classification} - Page {self.page_no()}"), align="C")
        self.set_text_color(0, 0, 0)


def _ascii_safe(text: str) -> str:
    """fpdf2's built-in Helvetica font is latin-1 only; non-latin-1 characters (smart
    quotes, the bullet middot, emoji…) are replaced rather than raising, since a report must
    still generate even when source text contains characters outside that range."""
    return text.encode("latin-1", "replace").decode("latin-1")


def _h2(pdf: ReportPDF, text: str) -> None:
    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, _ascii_safe(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", size=10)


def _p(pdf: ReportPDF, text: str) -> None:
    pdf.multi_cell(0, 5.5, _ascii_safe(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1)


def _table(pdf: ReportPDF, headers: list[str], rows: list[list[str]], widths: list[int]) -> None:
    pdf.set_font("Helvetica", "B", 9)
    for h, w in zip(headers, widths, strict=True):
        pdf.cell(w, 7, _ascii_safe(h), border=1)
    pdf.ln()
    pdf.set_font("Helvetica", size=9)
    for row in rows:
        for cell, w in zip(row, widths, strict=True):
            pdf.cell(w, 7, _ascii_safe(cell)[:60], border=1)
        pdf.ln()
    if not rows:
        pdf.cell(sum(widths), 7, "None.", border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _finding_block(pdf: ReportPDF, data: ReportData, f: Finding) -> None:
    assets_by_id = {a.asset_id: a for a in data.assets}
    linked = [assets_by_id[aid] for aid in f.affected_asset_ids if aid in assets_by_id]
    breakdown = score_finding(f, linked)
    pdf.set_font("Helvetica", "B", 11)
    pdf.multi_cell(
        0,
        6,
        _ascii_safe(f"[{f.severity.value.upper()}] {f.title}"),
        new_x=XPos.LMARGIN,
        new_y=YPos.NEXT,
    )
    pdf.set_font("Helvetica", "I", 9)
    _p(
        pdf,
        f"Confidence: {f.confidence.value} | Analyst status: {f.analyst_status.value} | "
        f"Module: {module_for(f)} | Internal risk: {breakdown.score}/100 "
        f"({breakdown.tier}) - not CVSS",
    )
    pdf.set_font("Helvetica", size=9)
    if f.url:
        _p(pdf, f"Affected: {f.url}")
    if f.summary:
        _p(pdf, f.summary)
    if f.technical_detail:
        _p(pdf, f"Technical detail: {f.technical_detail}")
    if f.business_impact:
        _p(pdf, f"Business impact: {f.business_impact}")
    _p(pdf, f"Remediation: {f.remediation or 'Not yet documented.'}")
    if f.cvss:
        _p(
            pdf,
            f"CVSS {f.cvss.version}: {f.cvss.vector} (base score {f.cvss.base_score}, "
            f"verified by {f.cvss.calculator or 'cvss'})",
        )
    for m in f.mappings:
        _p(
            pdf,
            f"Mapping: {m.catalog} {m.catalog_version} {m.entry_id}"
            f"{' - ' + m.title if m.title else ''}",
        )
    for s in f.sources:
        _p(
            pdf,
            f"Source: {s.tool} {s.tool_version} rule={s.rule_id or '-'}"
            f"{' original=' + s.original_severity if s.original_severity else ''}",
        )
    pdf.ln(3)


def render_pdf(data: ReportData) -> bytes:
    pdf = ReportPDF(data.filters.title, data.filters.classification_label)

    pdf.add_page()
    pdf.set_font("Helvetica", "B", 20)
    pdf.ln(40)
    pdf.cell(
        0,
        12,
        _ascii_safe(data.filters.classification_label),
        align="C",
        new_x=XPos.LMARGIN,
        new_y=YPos.NEXT,
    )
    pdf.set_font("Helvetica", "B", 18)
    pdf.multi_cell(
        0, 10, _ascii_safe(data.filters.title), align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT
    )
    pdf.set_font("Helvetica", size=12)
    pdf.cell(
        0,
        8,
        _ascii_safe(f"{data.project.client_name} - {data.project.name}"),
        align="C",
        new_x=XPos.LMARGIN,
        new_y=YPos.NEXT,
    )
    pdf.set_font("Helvetica", "I", 10)
    pdf.cell(
        0,
        8,
        _ascii_safe(f"Generated {data.generated_at.isoformat()}"),
        align="C",
        new_x=XPos.LMARGIN,
        new_y=YPos.NEXT,
    )

    pdf.add_page()
    _h2(pdf, "Executive summary")
    total = len(data.findings)
    confirmed = data.status_counts.get("confirmed", 0)
    _p(
        pdf,
        f"This assessment identified {total} finding(s) meeting the selected criteria, "
        f"of which {confirmed} are analyst-confirmed.",
    )
    _table(
        pdf,
        ["Severity", "Count"],
        [
            [s, str(data.severity_counts.get(s, 0))]
            for s in ("critical", "high", "medium", "low", "informational")
        ],
        [60, 30],
    )
    _p(
        pdf,
        "This report does not claim the assessed system is secure. It reflects only the "
        "checks executed within the configured scope and limits.",
    )

    _h2(pdf, "Scope and authorization")
    auth = data.project.authorization
    if auth:
        _p(
            pdf,
            f"Organization: {auth.organization} | Target owner: {auth.target_owner} | "
            f"Authorized by: {auth.authorized_by}",
        )
        _p(pdf, f"Window: {auth.window_start.isoformat()} to {auth.window_end.isoformat()}")
    else:
        _p(pdf, "No authorization record is present for this project.")
    scope = data.project.scope
    _p(
        pdf,
        f"Hosts: {', '.join(scope.hosts) or '-'} | Ports: "
        f"{', '.join(str(p) for p in scope.ports) or '-'}",
    )

    _h2(pdf, "Methodology")
    modules = sorted({s.scan.module.value for s in data.scans}) or ["none executed"]
    _p(pdf, f"Modules exercised: {', '.join(modules)}.")
    _table(
        pdf,
        ["Tool", "Version"],
        [[k, v] for k, v in sorted(data.tool_versions.items())],
        [90, 90],
    )

    _h2(pdf, "Scan coverage")
    _table(
        pdf,
        ["Scan", "Module", "State", "Checks", "Skipped", "Errors"],
        [
            [
                s.scan.scan_id[:12],
                s.scan.module.value,
                s.scan.state.value,
                str(s.coverage_total),
                str(s.coverage_skipped),
                str(s.coverage_errors),
            ]
            for s in data.scans
        ],
        [35, 30, 25, 20, 20, 20],
    )

    _h2(pdf, f"Finding details ({len(data.findings)})")
    if not data.findings:
        _p(
            pdf,
            "No findings were detected by the checks executed, within the selected "
            "criteria and the scan limits described below. This is not a claim that the "
            "assessed system is secure.",
        )
    for f in data.findings:
        _finding_block(pdf, data, f)

    if data.assets:
        _h2(pdf, f"Attack surface inventory ({len(data.assets)})")
        _table(
            pdf,
            ["Locator", "Type", "Scope", "Criticality"],
            [
                [a.locator, a.asset_type.value, a.scope_status.value, a.criticality or "-"]
                for a in data.assets
            ],
            [70, 30, 30, 30],
        )

    _h2(pdf, "Scan health and limitations")
    for item in data.limitations:
        _p(pdf, f"- {item}")

    out = pdf.output()
    return bytes(out)
