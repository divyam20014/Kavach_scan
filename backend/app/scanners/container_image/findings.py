"""Turn parsed Trivy image-scan results into canonical findings (security/reliability/
scope roadmap Phase 3, TBD-110). Mirrors `app/scanners/repo_scan/findings.py`'s own shape
(one writer, dedup by a locally-computed fingerprint, re-observe on a second scan), but
namespaced separately (`container_image-trivy-...` fingerprints, `container_image_trivy`
category) so a package/CVE found in a project's repository and the same package/CVE found
in its built image are never silently merged into one finding across two different scan
modules -- Trivy's own `Target` field already embeds the image reference (confirmed
directly, TBD-110: `"alpine:3.18 (alpine 3.18.12)"`), so the dedup key below already
differentiates by image without any extra field.

No `Asset` records are created here (same reasoning as `RepoScanFindingWriter`): a package
name/version is not a network-reachable asset the way a URL is.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterator

from app.core.redaction import redact_text
from app.models.common import Confidence, new_id
from app.models.finding import DedupEvent, Finding, FindingSource, StandardMapping
from app.scanners.repo_scan.trivy_adapter import TrivyFinding
from app.standards.cwe import CWE_CATALOG_VERSION, cwe_title
from app.storage.repository import StorageRepository

log = logging.getLogger("app.scanners.container_image")
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


class ContainerImageFindingWriter:
    def __init__(self, repo: StorageRepository, project_id: str, scan_id: str) -> None:
        self.repo = repo
        self.project_id = project_id
        self.scan_id = scan_id
        self._existing = {
            f.fingerprint: f.finding_id for f in _iter_findings(repo, project_id) if f.fingerprint
        }
        self.created: list[str] = []
        self.reobserved: list[str] = []

    def write_trivy(self, f: TrivyFinding, *, tool_version: str) -> str:
        raw = f"{self.project_id}|container_image-trivy-{f.fingerprint_key}"
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
            title=(f.title or f.vulnerability_id)[:200],
            summary=redact_text(
                f"{f.vulnerability_id}: {f.pkg_name} {f.installed_version} ({f.status})",
                max_chars=2000,
            ),
            technical_detail=redact_text(
                f"{f.title}\n\nPackage: {f.pkg_name} {f.installed_version}\n"
                f"Fixed in: {f.fixed_version or 'no fix available'}\nImage: {f.target}",
                max_chars=19_000,
            ),
            category="container_image_trivy",
            component=f"{f.pkg_name}@{f.installed_version}"[:200],
            severity=f.severity,
            confidence=f.confidence,
            cwe_ids=f.cwe_ids,
            mappings=_cwe_mappings(f.cwe_ids, "Weakness category reported directly by Trivy"),
            remediation=redact_text(remediation, max_chars=4000),
            references=[r for r in f.references if r.startswith(("http://", "https://"))][:50],
            rule_id=f.vulnerability_id[:200],
            sources=[source],
        )
        self.repo.create_finding(finding)
        self.created.append(finding_id)
        return finding_id
