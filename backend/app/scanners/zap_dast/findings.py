"""Turn parsed ZAP alerts into canonical findings (mirrors `app/scanners/webapp/findings.py`
for the native scanner, adapted for ZAP's own alert shape instead of this project's static
rule catalog -- ZAP's rule set is the tool's own, external and dynamic, not a locally
curated `Rule`/`RULES` table).

One finding per (project, ZAP plugin id, site) -- the same aggregate-per-origin shape the
native scanner's header/cookie checks already use -- listing every affected instance URI,
rather than one finding per instance, which would fragment one real issue into many rows.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterator

from app.core.redaction import redact_text
from app.models.asset import Asset
from app.models.common import AssetType, Confidence, ScopeStatus, new_id
from app.models.evidence import EvidenceMetadata
from app.models.finding import DedupEvent, Finding, FindingSource, StandardMapping
from app.scanners.zap_dast.alerts import ZapAlert
from app.standards.cwe import CWE_CATALOG_VERSION, cwe_title
from app.storage.repository import StorageRepository

log = logging.getLogger("app.scanners.zap_dast")
TOOL_NAME = "OWASP ZAP"
PAGE = 200
MAX_EXISTING = 20_000
MAX_INSTANCES_LISTED = 20


def fingerprint(project_id: str, alert: ZapAlert) -> str:
    raw = f"{project_id}|zap-{alert.plugin_id}|{alert.site}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _iter_findings(repo: StorageRepository, project_id: str) -> Iterator[Finding]:
    offset = 0
    while offset < MAX_EXISTING:
        page = repo.list_findings(project_id, offset=offset, limit=PAGE)
        yield from page.items
        offset += PAGE
        if offset >= page.total:
            return


class ZapFindingWriter:
    def __init__(
        self,
        repo: StorageRepository,
        project_id: str,
        scan_id: str,
        *,
        tool_version: str,
    ) -> None:
        self.repo = repo
        self.project_id = project_id
        self.scan_id = scan_id
        self.tool_version = tool_version
        self._existing = {
            f.fingerprint: f.finding_id for f in _iter_findings(repo, project_id) if f.fingerprint
        }
        self.created: list[str] = []
        self.reobserved: list[str] = []

    def _asset_for(self, site: str) -> str | None:
        if not site.startswith(("http://", "https://")):
            return None
        try:
            asset = self.repo.create_asset(
                Asset(
                    asset_id=new_id("asset"),
                    project_id=self.project_id,
                    asset_type=AssetType.URL,
                    locator=site,
                    source_scan_id=self.scan_id,
                    confidence=Confidence.CONFIRMED,
                    scope_status=ScopeStatus.IN_SCOPE,
                    observations=["Observed by the ZAP engine"],
                )
            )
            return asset.asset_id
        except Exception:  # noqa: BLE001 - inventory write is best effort
            log.debug("could not record asset for %s", site)
            return None

    def _evidence(self, alert: ZapAlert, finding_id: str) -> list[str]:
        instance_lines = "\n".join(
            f"{i.method} {i.uri}" + (f" (param: {i.param})" if i.param else "")
            for i in alert.instances[:MAX_INSTANCES_LISTED]
        )
        saved = self.repo.save_evidence(
            EvidenceMetadata(
                evidence_id=new_id("evidence"),
                project_id=self.project_id,
                scan_id=self.scan_id,
                finding_ids=[finding_id],
                evidence_type="text_excerpt",
                source_stage="zap_passive_scan",
                source_tool=TOOL_NAME,
                response_excerpt=redact_text(instance_lines, max_chars=8000),
            )
        )
        return [saved.evidence_id]

    def write(self, alert: ZapAlert) -> str | None:
        fp = fingerprint(self.project_id, alert)
        source = FindingSource(
            tool=TOOL_NAME,
            tool_version=self.tool_version,
            rule_id=f"ZAP-{alert.plugin_id}",
            scan_id=self.scan_id,
            original_severity=alert.risk_code,
            original_confidence=alert.confidence_code,
        )
        existing_id = self._existing.get(fp)
        if existing_id is not None:
            evidence_ids = self._evidence(alert, existing_id)

            def apply(current: Finding) -> Finding:
                return current.model_copy(
                    update={
                        "sources": (current.sources + [source])[-200:],
                        "evidence_ids": (current.evidence_ids + evidence_ids)[-500:],
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
        evidence_ids = self._evidence(alert, finding_id)
        asset_id = self._asset_for(alert.site)
        mappings: list[StandardMapping] = []
        if alert.cwe_id is not None:
            title = cwe_title(alert.cwe_id)
            if title:
                mappings.append(
                    StandardMapping(
                        catalog="cwe",
                        catalog_version=CWE_CATALOG_VERSION,
                        entry_id=f"CWE-{alert.cwe_id}",
                        title=title,
                        rationale="Weakness category reported directly by ZAP",
                        confidence=Confidence.PROBABLE,
                    )
                )
        instance_list = "\n".join(
            f"- {i.method} {i.uri}" for i in alert.instances[:MAX_INSTANCES_LISTED]
        )
        more = len(alert.instances) - MAX_INSTANCES_LISTED
        technical = redact_text(
            "\n\n".join(
                p
                for p in (
                    alert.description,
                    f"Affected ({len(alert.instances)}):\n{instance_list}"
                    + (f"\n- ... and {more} more" if more > 0 else ""),
                )
                if p
            ),
            max_chars=19_000,
        )
        finding = Finding(
            finding_id=finding_id,
            project_id=self.project_id,
            scan_id=self.scan_id,
            fingerprint=fp,
            title=alert.alert or f"ZAP alert {alert.plugin_id}",
            summary=redact_text(alert.description, max_chars=2000),
            technical_detail=technical,
            category="zap_dast",
            affected_asset_ids=[asset_id] if asset_id else [],
            url=alert.instances[0].uri if alert.instances else None,
            parameter=alert.instances[0].param if alert.instances else "",
            severity=alert.severity,
            confidence=alert.confidence,
            evidence_ids=evidence_ids,
            cwe_ids=[alert.cwe_id] if alert.cwe_id is not None else [],
            mappings=mappings,
            remediation=redact_text(alert.solution, max_chars=4000),
            references=[r for r in alert.references if r.startswith(("http://", "https://"))][:50],
            rule_id=f"ZAP-{alert.plugin_id}",
            sources=[source],
        )
        self.repo.create_finding(finding)
        self.created.append(finding_id)
        return finding_id
