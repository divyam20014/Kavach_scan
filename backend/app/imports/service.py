"""Import Center service: detect -> parse (dry-run) -> commit.

Nothing here writes a canonical `Finding`/`Asset` until `commit()` is called explicitly.
`preview()` only reads existing project records (to compute duplicate candidates) and
returns derived, in-memory data — the acceptance criterion "Import preview does not modify
canonical project findings until commit" holds because no repository write method is
called anywhere in the detect/parse/preview path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.core.redaction import redact_text
from app.imports.adapters import ADAPTERS, UNSUPPORTED
from app.imports.base import Adapter, ParsedAsset, ParsedFinding, ParseResult
from app.imports.dedup import TitleCandidate, fingerprint, title_only_candidates
from app.imports.safety import (
    MAX_RECORDS,
    MAX_UPLOAD_BYTES,
    ImportSafetyError,
    maybe_extract_single_member,
)
from app.models.asset import Asset
from app.models.common import AnalystStatus, AssetType, Confidence, ScopeStatus, new_id, utc_now
from app.models.finding import DedupEvent, Finding, FindingSource
from app.storage.repository import StorageRepository

MAX_PREVIEW_SAMPLE = 50
MAX_LIST_PAGE = 200
MAX_LIST_PAGES = 200  # hard stop so a pathological project can't make this loop forever

# field -> max_chars matching the eventual Finding field's own length limit, so redaction's
# own default cap (4000) never truncates a legitimately long LongText field unnecessarily.
_REDACT_FIELDS: dict[str, int] = {
    "title": 200, "summary": 20_000, "technical_detail": 20_000, "remediation": 20_000,
    "parameter": 500, "component": 500,
}

_ASSET_TYPE_MAP = {
    "domain": AssetType.DOMAIN, "hostname": AssetType.HOSTNAME, "ip": AssetType.IP,
    "port": AssetType.PORT, "service": AssetType.SERVICE, "url": AssetType.URL,
    "api_operation": AssetType.API_OPERATION,
}


def _redacted(finding: ParsedFinding) -> ParsedFinding:
    """Return a copy with every tool-derived free-text field redacted (TBD-041). Applied
    before the record is shown in a preview AND before it is written on commit, so a
    secret never reaches disk or the screen either way."""
    import dataclasses

    return dataclasses.replace(
        finding,
        title=redact_text(finding.title, max_chars=_REDACT_FIELDS["title"]),
        summary=redact_text(finding.summary, max_chars=_REDACT_FIELDS["summary"]),
        technical_detail=redact_text(finding.technical_detail,
                                     max_chars=_REDACT_FIELDS["technical_detail"]),
        remediation=redact_text(finding.remediation, max_chars=_REDACT_FIELDS["remediation"]),
        parameter=redact_text(finding.parameter, max_chars=_REDACT_FIELDS["parameter"]),
        component=redact_text(finding.component, max_chars=_REDACT_FIELDS["component"]),
    )


def select_adapter(filename: str, raw: bytes, *, declared: str | None = None) -> Adapter:
    if declared:
        for adapter in ADAPTERS:
            if adapter.source_type == declared:
                return adapter
        if declared in UNSUPPORTED:
            raise ImportSafetyError(f"{declared}: {UNSUPPORTED[declared]}")
        raise ImportSafetyError(f"unknown source_type {declared!r}")
    for adapter in ADAPTERS:
        try:
            if adapter.sniff(filename, raw):
                return adapter
        except Exception:  # noqa: BLE001, S112 - a broken sniff must not crash detection
            continue
    name = filename.lower()
    for key, reason in UNSUPPORTED.items():
        if key in name:
            raise ImportSafetyError(f"{key}: {reason}")
    raise ImportSafetyError(
        "could not detect the report format. Supported: " +
        ", ".join(a.label for a in ADAPTERS) +
        ". For a CSV/JSON export from another tool, pass options.column_map / field_map."
    )


def parse_upload(filename: str, raw: bytes, *, declared: str | None = None,
                 options: dict[str, Any] | None = None) -> tuple[Adapter, ParseResult]:
    """Full offline pipeline: size check -> optional single-member zip extraction ->
    format detection -> bounded parse. Raises `ImportSafetyError` for a fatal, whole-file
    problem; a bad individual record inside an otherwise-good file is reported as a
    warning with `rejected_count` incremented (partial success), not a fatal error."""
    if len(raw) > MAX_UPLOAD_BYTES:
        raise ImportSafetyError(f"upload exceeds the {MAX_UPLOAD_BYTES} byte limit")
    if not raw:
        raise ImportSafetyError("the uploaded file is empty")
    extracted = maybe_extract_single_member(raw)
    if extracted is not None:
        filename, raw = extracted.name, extracted.data
    adapter = select_adapter(filename, raw, declared=declared)
    result = adapter.parse(raw, options=options)
    if len(result.findings) > MAX_RECORDS:
        result.warn(f"more than {MAX_RECORDS} records were parsed; only the first "
                   f"{MAX_RECORDS} are shown/committed")
        result.findings = result.findings[:MAX_RECORDS]
    return adapter, result


# ---------------------------------------------------------------------- read-only preview


def _iter_findings(repo: StorageRepository, project_id: str) -> list[Finding]:
    out: list[Finding] = []
    offset = 0
    for _ in range(MAX_LIST_PAGES):
        page = repo.list_findings(project_id, offset=offset, limit=MAX_LIST_PAGE)
        out.extend(page.items)
        offset += MAX_LIST_PAGE
        if offset >= page.total:
            break
    return out


def _iter_assets(repo: StorageRepository, project_id: str) -> list[Asset]:
    out: list[Asset] = []
    offset = 0
    for _ in range(MAX_LIST_PAGES):
        page = repo.list_assets(project_id, offset=offset, limit=MAX_LIST_PAGE)
        out.extend(page.items)
        offset += MAX_LIST_PAGE
        if offset >= page.total:
            break
    return out


@dataclass
class PreviewRecord:
    index: int
    title: str
    severity: str
    confidence: str
    host: str | None
    url: str | None
    rule_id: str
    # "new": no fingerprint match anywhere.
    # "update_existing": fingerprint matches a Finding already committed to the project.
    # "duplicate_in_import": fingerprint matches an earlier record in THIS SAME import (e.g.
    #   the same host/plugin reported twice in one report) — collapses to one Finding on
    #   commit, same as update_existing, but there is no existing_finding_id to show yet.
    action: str
    existing_finding_id: str | None = None
    duplicate_of_index: int | None = None


@dataclass
class DuplicateCandidate:
    title: str
    index_a: int
    index_b: int | None
    existing_finding_id: str | None


@dataclass
class ImportPreview:
    source_type: str
    label: str
    parser_version: str
    source_tool_version: str
    parsed_count: int
    rejected_count: int
    warnings: list[str]
    records: list[PreviewRecord] = field(default_factory=list)
    duplicate_candidates: list[DuplicateCandidate] = field(default_factory=list)
    mapping_gaps: list[str] = field(default_factory=list)
    asset_count: int = 0
    truncated_sample: bool = False


def preview(repo: StorageRepository, project_id: str, adapter: Adapter,
           result: ParseResult) -> ImportPreview:
    """Pure, read-only: looks at existing findings to classify records, writes nothing."""
    existing = _iter_findings(repo, project_id)
    existing_by_fp = {f.fingerprint: f.finding_id for f in existing if f.fingerprint}
    existing_titles = [(f.finding_id, f.title) for f in existing]
    redacted = [_redacted(f) for f in result.findings]
    records: list[PreviewRecord] = []
    unmatched_indices: list[int] = []
    # Tracks the first index at which each fingerprint appeared in this batch, so a second
    # record sharing a fingerprint with an earlier one in the SAME import (duplicate IDs
    # within a single report) is reported accurately — it will collapse into one Finding on
    # commit, exactly like a match against an already-committed Finding.
    seen_in_batch: dict[str, int] = {}
    for i, f in enumerate(redacted):
        fp = fingerprint(project_id, f)
        existing_id = existing_by_fp.get(fp)
        dup_index = seen_in_batch.get(fp)
        if existing_id:
            action = "update_existing"
        elif dup_index is not None:
            action = "duplicate_in_import"
        else:
            action = "new"
        records.append(PreviewRecord(
            index=i, title=f.title, severity=f.severity.value, confidence=f.confidence.value,
            host=f.host, url=f.url, rule_id=f.rule_id,
            action=action, existing_finding_id=existing_id, duplicate_of_index=dup_index,
        ))
        if existing_id is None and dup_index is None:
            unmatched_indices.append(i)
            seen_in_batch[fp] = i
    unmatched = [redacted[i] for i in unmatched_indices]
    raw_candidates: list[TitleCandidate] = title_only_candidates(unmatched, existing_titles)
    candidates = [
        DuplicateCandidate(
            title=c.title,
            index_a=unmatched_indices[c.index_a],
            index_b=unmatched_indices[c.index_b] if c.index_b is not None else None,
            existing_finding_id=c.existing_finding_id,
        )
        for c in raw_candidates
    ]
    truncated = len(records) > MAX_PREVIEW_SAMPLE
    return ImportPreview(
        source_type=adapter.source_type, label=adapter.label, parser_version=adapter.parser_version,
        source_tool_version=result.source_tool_version, parsed_count=result.parsed_count,
        rejected_count=result.rejected_count, warnings=list(result.warnings),
        records=records[:MAX_PREVIEW_SAMPLE], duplicate_candidates=candidates[:MAX_PREVIEW_SAMPLE],
        mapping_gaps=list(result.mapping_gaps),
        asset_count=len(result.assets), truncated_sample=truncated,
    )


# ---------------------------------------------------------------------- commit


@dataclass
class CommitSummary:
    findings_created: int = 0
    findings_reobserved: int = 0
    assets_created: int = 0
    assets_updated: int = 0


def _upsert_asset(repo: StorageRepository, project_id: str, import_id: str,
                  parsed: ParsedAsset, by_locator: dict[tuple[str, str], Asset],
                  summary: CommitSummary) -> None:
    asset_type = _ASSET_TYPE_MAP.get(parsed.asset_type)
    if asset_type is None:
        return
    key = (asset_type.value, parsed.locator[:2048])
    current = by_locator.get(key)
    observation = redact_text(parsed.observation) if parsed.observation else ""
    if current is None:
        asset = Asset(
            asset_id=new_id("asset"), project_id=project_id, asset_type=asset_type,
            locator=key[1], confidence=Confidence.PROBABLE,
            scope_status=ScopeStatus.PENDING_APPROVAL,
            observations=[observation] if observation else [],
        )
        created = repo.create_asset(asset)
        by_locator[key] = created
        summary.assets_created += 1
        return

    def apply(a: Asset) -> Asset:
        obs = list(a.observations)
        if observation and observation not in obs:
            obs = (obs + [observation])[-200:]
        return a.model_copy(update={"last_seen": utc_now(), "observations": obs})

    updated = repo.update_asset(project_id, current.asset_id, apply)
    by_locator[key] = updated
    summary.assets_updated += 1


def commit(repo: StorageRepository, project_id: str, import_id: str,
          adapter: Adapter, result: ParseResult) -> CommitSummary:
    """Writes normalized `Finding`/`Asset` records. Re-observes a Finding whose fingerprint
    already exists instead of duplicating it (same semantics as the live scanners'
    `FindingWriter`); everything else is created new. Every tool-derived text field is
    redacted before it is ever written (TBD-041)."""
    summary = CommitSummary()
    existing = _iter_findings(repo, project_id)
    existing_by_fp = {f.fingerprint: f.finding_id for f in existing if f.fingerprint}
    source_base = FindingSource(
        tool=adapter.label[:200], tool_version=result.source_tool_version[:500],
        import_id=import_id, observed_at=utc_now())
    for parsed in result.findings:
        clean = _redacted(parsed)
        fp = fingerprint(project_id, clean)
        source = source_base.model_copy(update={
            "rule_id": clean.rule_id[:500], "source_finding_id": clean.source_finding_id[:500],
            "original_severity": clean.original_severity[:500],
            "original_confidence": clean.original_confidence[:500],
        })
        existing_id = existing_by_fp.get(fp)
        if existing_id:
            def apply(current: Finding, _source: FindingSource = source) -> Finding:
                return current.model_copy(update={
                    "sources": (current.sources + [_source])[-200:],
                    "dedup_history": (current.dedup_history + [
                        DedupEvent(action="reobserved", note=f"import {import_id}")
                    ])[-500:],
                })

            repo.update_finding(project_id, existing_id, apply)
            summary.findings_reobserved += 1
            continue
        finding = Finding(
            finding_id=new_id("finding"), project_id=project_id, fingerprint=fp,
            title=clean.title, summary=clean.summary, technical_detail=clean.technical_detail,
            category=clean.category, url=clean.url, method=clean.method,
            parameter=clean.parameter, component=clean.component, severity=clean.severity,
            confidence=clean.confidence, verification_state="unverified",
            analyst_status=(AnalystStatus.NEEDS_REVIEW
                           if clean.confidence == Confidence.NEEDS_REVIEW
                           else AnalystStatus.NEW),
            cwe_ids=clean.cwe_ids, remediation=clean.remediation,
            references=[r for r in clean.references if r.startswith(("http://", "https://"))][:50],
            rule_id=clean.rule_id, sources=[source],
        )
        created = repo.create_finding(finding)
        existing_by_fp[fp] = created.finding_id
        summary.findings_created += 1
    by_locator = {(a.asset_type.value, a.locator): a for a in _iter_assets(repo, project_id)}
    for parsed_asset in result.assets:
        _upsert_asset(repo, project_id, import_id, parsed_asset, by_locator, summary)
    return summary
