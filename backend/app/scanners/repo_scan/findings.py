"""Turn parsed Semgrep/Gitleaks/Trivy results into canonical findings (roadmap Phase 2,
TBD-087). Mirrors `app/scanners/zap_dast/findings.py`'s own shape (one writer, dedup by a
locally-computed fingerprint, re-observe on a second scan) adapted for three different
external tool shapes instead of one.

No `Asset` records are created here (unlike `ZapFindingWriter`): a file path or a
package name/version is not a network-reachable asset the way a URL is, and this
project's `Asset` model is URL/host-shaped (`app/models/asset.py`).
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterator

from app.core.redaction import redact_text
from app.models.common import Confidence, Severity, new_id
from app.models.finding import DedupEvent, Finding, FindingSource, StandardMapping
from app.scanners.repo_scan.gitleaks_adapter import GitleaksFinding
from app.scanners.repo_scan.semgrep_adapter import SemgrepFinding
from app.scanners.repo_scan.trivy_adapter import TrivyFinding
from app.standards.cwe import CWE_CATALOG_VERSION, cwe_title
from app.storage.repository import StorageRepository

log = logging.getLogger("app.scanners.repo_scan")
PAGE = 200
MAX_EXISTING = 20_000


def _iter_findings(repo: StorageRepository, project_id: str) -> Iterator[Finding]:
    offset = 0
    while offset < MAX_EXISTING:
        page = repo.list_findings(project_id, offset=offset, limit=PAGE)
        yield from page.items
        offset += PAGE
        if offset >= page.total:
            return


def _cwe_mappings(cwe_ids: list[int], rationale: str) -> list[StandardMapping]:
    mappings: list[StandardMapping] = []
    for cwe_id in cwe_ids:
        title = cwe_title(cwe_id)
        if title:
            mappings.append(
                StandardMapping(
                    catalog="cwe",
                    catalog_version=CWE_CATALOG_VERSION,
                    entry_id=f"CWE-{cwe_id}",
                    title=title,
                    rationale=rationale,
                    confidence=Confidence.PROBABLE,
                )
            )
    return mappings


class RepoScanFindingWriter:
    def __init__(
        self,
        repo: StorageRepository,
        project_id: str,
        scan_id: str,
    ) -> None:
        self.repo = repo
        self.project_id = project_id
        self.scan_id = scan_id
        self._existing = {
            f.fingerprint: f.finding_id for f in _iter_findings(repo, project_id) if f.fingerprint
        }
        self.created: list[str] = []
        self.reobserved: list[str] = []

    def _write(
        self,
        *,
        fp: str,
        source: FindingSource,
        title: str,
        summary: str,
        technical_detail: str,
        category: str,
        component: str,
        severity: Severity,
        confidence: Confidence,
        cwe_ids: list[int],
        mappings: list[StandardMapping],
        references: list[str],
        rule_id: str,
        remediation: str = "",
    ) -> str:
        existing_id = self._existing.get(fp)
        if existing_id is not None:

            def apply(current: Finding) -> Finding:
                return current.model_copy(
                    update={
                        "sources": (current.sources + [source])[-200:],
                        "dedup_history": (
                            current.dedup_history
                            + [DedupEvent(action="reobserved", note=f"scan {self.scan_id}")]
                        )[-500:],
                        "scan_id": self.scan_id,
                    }
                )

            try:
                self.repo.update_finding(self.project_id, existing_id, apply)
                self.reobserved.append(existing_id)
                return existing_id
            except Exception:  # noqa: BLE001 - deleted meanwhile: fall through and create
                log.debug("finding %s vanished; creating a new one", existing_id)
        finding_id = new_id("finding")
        finding = Finding(
            finding_id=finding_id,
            project_id=self.project_id,
            scan_id=self.scan_id,
            fingerprint=fp,
            title=title[:200] or rule_id,
            summary=redact_text(summary, max_chars=2000),
            technical_detail=redact_text(technical_detail, max_chars=19_000),
            category=category,
            component=component[:200],
            severity=severity,
            confidence=confidence,
            cwe_ids=cwe_ids,
            mappings=mappings,
            remediation=redact_text(remediation, max_chars=4000),
            references=[r for r in references if r.startswith(("http://", "https://"))][:50],
            rule_id=rule_id[:200],
            sources=[source],
        )
        self.repo.create_finding(finding)
        self.created.append(finding_id)
        return finding_id

    def write_semgrep(self, f: SemgrepFinding, *, tool_version: str) -> str:
        raw = f"{self.project_id}|semgrep-{f.check_id}|{f.path}|{f.start_line}"
        fp = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        source = FindingSource(
            tool="Semgrep",
            tool_version=tool_version,
            rule_id=f.check_id,
            scan_id=self.scan_id,
            original_severity=f.severity_raw,
            original_confidence=f.confidence_raw,
        )
        return self._write(
            fp=fp,
            source=source,
            title=f.check_id.rsplit(".", 1)[-1].replace("-", " "),
            summary=f.message,
            technical_detail=f"{f.message}\n\nLocation: {f.path}:{f.start_line}-{f.end_line}",
            category="repo_scan_semgrep",
            component=f"{f.path}:{f.start_line}",
            severity=f.severity,
            confidence=f.confidence,
            cwe_ids=f.cwe_ids,
            mappings=_cwe_mappings(f.cwe_ids, "Weakness category reported directly by Semgrep"),
            references=f.references + ([f.source_url] if f.source_url else []),
            rule_id=f.check_id,
        )

    def write_gitleaks(self, f: GitleaksFinding, *, tool_version: str) -> str:
        raw = f"{self.project_id}|gitleaks-{f.fingerprint_key}"
        fp = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        source = FindingSource(
            tool="Gitleaks",
            tool_version=tool_version,
            rule_id=f.rule_id,
            scan_id=self.scan_id,
        )
        return self._write(
            fp=fp,
            source=source,
            title=f"Potential secret: {f.rule_id.replace('-', ' ')}",
            summary=f.description,
            # Deliberately never includes the matched secret text itself -- `GitleaksFinding`
            # has no field for it at all (see app/scanners/repo_scan/gitleaks_adapter.py).
            technical_detail=f"{f.description}\n\nLocation: {f.path}:{f.start_line}",
            category="repo_scan_gitleaks",
            component=f"{f.path}:{f.start_line}",
            severity=f.severity,
            confidence=f.confidence,
            cwe_ids=[],
            mappings=[],
            references=[],
            rule_id=f.rule_id,
        )

    def write_trivy(self, f: TrivyFinding, *, tool_version: str) -> str:
        raw = f"{self.project_id}|trivy-{f.fingerprint_key}"
        fp = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        source = FindingSource(
            tool="Trivy",
            tool_version=tool_version,
            rule_id=f.vulnerability_id,
            scan_id=self.scan_id,
            original_severity=f.severity_raw,
        )
        remediation = (
            f"Upgrade {f.pkg_name} to {f.fixed_version}" if f.fixed_version else "No fix available"
        )
        return self._write(
            fp=fp,
            source=source,
            title=f.title or f.vulnerability_id,
            summary=f"{f.vulnerability_id}: {f.pkg_name} {f.installed_version} ({f.status})",
            technical_detail=f"{f.title}\n\nPackage: {f.pkg_name} {f.installed_version}\n"
            f"Fixed in: {f.fixed_version or 'no fix available'}\nFile: {f.target}",
            category="repo_scan_trivy",
            component=f"{f.pkg_name}@{f.installed_version}",
            severity=f.severity,
            confidence=f.confidence,
            cwe_ids=f.cwe_ids,
            mappings=_cwe_mappings(f.cwe_ids, "Weakness category reported directly by Trivy"),
            references=f.references,
            rule_id=f.vulnerability_id,
            remediation=remediation,
        )
