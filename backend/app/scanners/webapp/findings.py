"""Turn check results into canonical findings with sanitized evidence (Module 5.7).

- Only FINDING outcomes become `Finding` records; pass/observation/skipped/error results
  stay in the scan's coverage output.
- Each finding gets a stable fingerprint (project, rule, subject, parameter). When the
  project already has a finding with that fingerprint, it is re-observed (new source +
  dedup history entry) instead of duplicated, and the analyst status is preserved.
- All prose derived from target responses is passed through the redactor (TBD-041);
  evidence excerpts are redacted again by the storage layer and are size capped.
- Origins are recorded as URL assets so findings link to the inventory.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterator
from typing import Any

from app.core.redaction import redact_text
from app.models.asset import Asset
from app.models.common import AssetType, Confidence, ScopeStatus, new_id, utc_now
from app.models.evidence import EvidenceMetadata
from app.models.finding import DedupEvent, Finding, FindingSource, StandardMapping
from app.scanners.webapp.checks import origin_of
from app.scanners.webapp.rules import (
    CATALOG_ID,
    CATALOG_VERSION,
    OWASP_TITLES,
    OWASP_VERSION,
    CheckResult,
    Outcome,
)
from app.storage.repository import StorageRepository

log = logging.getLogger("app.scanners.webapp")
TOOL_NAME = "vapt-web-scanner"
PAGE = 200
MAX_EXISTING = 20_000


def fingerprint(project_id: str, result: CheckResult) -> str:
    raw = f"{project_id}|{result.rule_id}|{result.subject}|{result.parameter}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _iter_findings(repo: StorageRepository, project_id: str) -> Iterator[Finding]:
    offset = 0
    while offset < MAX_EXISTING:
        page = repo.list_findings(project_id, offset=offset, limit=PAGE)
        yield from page.items
        offset += PAGE
        if offset >= page.total:
            return


def _iter_assets(repo: StorageRepository, project_id: str) -> Iterator[Asset]:
    offset = 0
    while offset < MAX_EXISTING:
        page = repo.list_assets(project_id, offset=offset, limit=PAGE)
        yield from page.items
        offset += PAGE
        if offset >= page.total:
            return


class FindingWriter:
    def __init__(
        self,
        repo: StorageRepository,
        project_id: str,
        scan_id: str,
        *,
        tool_name: str = TOOL_NAME,
        tool_version: str = f"{CATALOG_ID} {CATALOG_VERSION}",
    ) -> None:
        self.tool_name = tool_name
        self.tool_version = tool_version
        self.repo = repo
        self.project_id = project_id
        self.scan_id = scan_id
        self._existing = {
            f.fingerprint: f.finding_id for f in _iter_findings(repo, project_id) if f.fingerprint
        }
        self._assets = {
            a.locator: a.asset_id
            for a in _iter_assets(repo, project_id)
            if a.asset_type == AssetType.URL
        }
        self.created: list[str] = []
        self.reobserved: list[str] = []

    def asset_for(self, url: str) -> str | None:
        if not url.startswith(("http://", "https://")):
            return None
        origin = origin_of(url)
        if origin in self._assets:
            asset_id = self._assets[origin]
            try:
                self.repo.update_asset(self.project_id, asset_id, {"last_seen": utc_now()})
            except Exception:  # noqa: BLE001 - inventory touch is best effort
                log.debug("could not update asset %s", asset_id)
            return asset_id
        asset = self.repo.create_asset(
            Asset(
                asset_id=new_id("asset"),
                project_id=self.project_id,
                asset_type=AssetType.URL,
                locator=origin,
                source_scan_id=self.scan_id,
                confidence=Confidence.CONFIRMED,
                scope_status=ScopeStatus.IN_SCOPE,
                observations=["Observed by the web scanner"],
            )
        )
        self._assets[origin] = asset.asset_id
        return asset.asset_id

    def _evidence(self, result: CheckResult, finding_id: str) -> list[str]:
        draft = result.evidence
        if draft is None:
            return []
        saved = self.repo.save_evidence(
            EvidenceMetadata(
                evidence_id=new_id("evidence"),
                project_id=self.project_id,
                scan_id=self.scan_id,
                finding_ids=[finding_id],
                evidence_type=draft.evidence_type,  # type: ignore[arg-type]
                source_stage=result.rule.category,
                source_tool=self.tool_name,
                request_excerpt=draft.request_excerpt,
                response_excerpt=draft.response_excerpt,
                excerpt_truncated=draft.truncated,
                bytes_observed=draft.bytes_observed,
                sha256=draft.sha256,
            )
        )
        return [saved.evidence_id]

    def write(self, result: CheckResult) -> str | None:
        if result.outcome != Outcome.FINDING:
            return None
        rule = result.rule
        fp = fingerprint(self.project_id, result)
        source = FindingSource(
            tool=self.tool_name,
            tool_version=self.tool_version,
            rule_id=rule.rule_id,
            scan_id=self.scan_id,
        )
        existing_id = self._existing.get(fp)
        if existing_id is not None:
            evidence_ids = self._evidence(result, existing_id)

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
        evidence_ids = self._evidence(result, finding_id)
        url = result.subject if result.subject.startswith(("http://", "https://")) else None
        asset_id = self.asset_for(url) if url else None
        mappings = []
        if rule.owasp and rule.owasp.startswith("API"):
            from app.scanners.apisec.rules import OWASP_API_TITLES, OWASP_API_VERSION

            mappings.append(
                StandardMapping(
                    catalog="owasp_api_top10",
                    catalog_version=OWASP_API_VERSION,
                    entry_id=rule.owasp,
                    title=OWASP_API_TITLES.get(rule.owasp, ""),
                    rationale="Related category assigned by the rule catalog (not a 1:1 mapping)",
                    confidence=Confidence.PROBABLE,
                )
            )
        elif rule.owasp:
            mappings.append(
                StandardMapping(
                    catalog="owasp_top10",
                    catalog_version=OWASP_VERSION,
                    entry_id=rule.owasp,
                    title=OWASP_TITLES.get(rule.owasp, ""),
                    rationale="Related category assigned by the rule catalog (not a 1:1 mapping)",
                    confidence=Confidence.PROBABLE,
                )
            )
        technical = redact_text(
            "\n\n".join(p for p in (result.rationale, result.detail) if p), max_chars=19_000
        )
        finding = Finding(
            finding_id=finding_id,
            project_id=self.project_id,
            scan_id=self.scan_id,
            fingerprint=fp,
            title=rule.title,
            summary=rule.summary,
            technical_detail=technical,
            category=rule.category,
            affected_asset_ids=list(
                result.data.get("asset_ids") or ([asset_id] if asset_id else [])
            ),
            url=url[:2048] if url else None,
            method=result.method if url else None,
            parameter=redact_text(result.parameter, max_chars=400),
            component=result.subject[:400] if not url else "",
            severity=result.severity or rule.severity,
            confidence=result.confidence or rule.confidence,
            verification_state="automated_evidence" if evidence_ids else "unverified",
            evidence_ids=evidence_ids,
            cwe_ids=list(rule.cwe),
            mappings=mappings,
            remediation=rule.remediation,
            references=list(rule.references),
            rule_id=rule.rule_id,
            sources=[source],
        )
        created = self.repo.create_finding(finding)
        self._existing[fp] = created.finding_id
        self.created.append(created.finding_id)
        return created.finding_id


def summarize_outcomes(results: list[CheckResult]) -> dict[str, Any]:
    by_outcome: dict[str, int] = {}
    by_rule: dict[str, dict[str, int]] = {}
    for r in results:
        by_outcome[r.outcome.value] = by_outcome.get(r.outcome.value, 0) + 1
        per = by_rule.setdefault(r.rule_id, {})
        per[r.outcome.value] = per.get(r.outcome.value, 0) + 1
    return {"by_outcome": by_outcome, "by_rule": by_rule}
