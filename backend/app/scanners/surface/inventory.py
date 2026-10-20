"""Asset inventory for the surface mapper: upsert by (type, locator), graph edges,
per-scan snapshots and change comparison.

Graph: domain → hostname → IP → port/service → web origin (URL) → endpoint (URL).
`parent_asset_id` holds the primary edge; `related_asset_ids` holds extra edges (e.g. an
IP serving several hostnames). Assets are canonical filesystem records, so relationships,
`first_seen`/`last_seen` and attributes persist across restarts.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from app.models.asset import Asset
from app.models.common import AssetType, Confidence, ScopeStatus, new_id, utc_now
from app.storage.repository import StorageRepository

PAGE = 200
MAX_ASSETS = 50_000


def iter_assets(repo: StorageRepository, project_id: str) -> Iterator[Asset]:
    offset = 0
    while offset < MAX_ASSETS:
        page = repo.list_assets(project_id, offset=offset, limit=PAGE)
        yield from page.items
        offset += PAGE
        if offset >= page.total:
            return


def port_locator(ip: str, port: int) -> str:
    host = f"[{ip}]" if ":" in ip else ip
    return f"tcp://{host}:{port}"


class Inventory:
    def __init__(self, repo: StorageRepository, project_id: str, scan_id: str) -> None:
        self.repo = repo
        self.project_id = project_id
        self.scan_id = scan_id
        self.by_key: dict[tuple[str, str], Asset] = {
            (a.asset_type.value, a.locator): a for a in iter_assets(repo, project_id)
        }
        self.created = 0
        self.updated = 0

    def get(self, asset_type: AssetType, locator: str) -> Asset | None:
        return self.by_key.get((asset_type.value, locator))

    def upsert(
        self,
        asset_type: AssetType,
        locator: str,
        *,
        parent: str | None = None,
        related: list[str] | None = None,
        scope_status: ScopeStatus | None = None,
        confidence: Confidence = Confidence.CONFIRMED,
        attributes: dict[str, Any] | None = None,
        observation: str | None = None,
        resolution_status: str | None = None,
    ) -> str:
        key = (asset_type.value, locator[:2048])
        current = self.by_key.get(key)
        attrs = {k: v for k, v in (attributes or {}).items() if v is not None}
        if current is None:
            asset = Asset(
                asset_id=new_id("asset"),
                project_id=self.project_id,
                asset_type=asset_type,
                locator=key[1],
                parent_asset_id=parent,
                related_asset_ids=[r for r in (related or []) if r != parent][:200],
                source_scan_id=self.scan_id,
                confidence=confidence,
                scope_status=scope_status or ScopeStatus.PENDING_APPROVAL,
                observations=[observation[:480]] if observation else [],
                attributes=dict(list(attrs.items())[:60]),
                resolution_status=resolution_status,  # type: ignore[arg-type]
            )
            created = self.repo.create_asset(asset)
            self.by_key[key] = created
            self.created += 1
            return created.asset_id

        def apply(a: Asset) -> Asset:
            merged = {**a.attributes, **attrs}
            rel = list(dict.fromkeys([*a.related_asset_ids, *(related or [])]))
            rel = [r for r in rel if r != (a.parent_asset_id or parent)][:200]
            obs = list(a.observations)
            if observation and observation[:480] not in obs:
                obs = (obs + [observation[:480]])[-200:]
            update: dict[str, Any] = {
                "last_seen": utc_now(),
                "source_scan_id": self.scan_id,
                "attributes": dict(list(merged.items())[:60]),
                "related_asset_ids": rel,
                "observations": obs,
                "parent_asset_id": a.parent_asset_id or parent,
            }
            if scope_status is not None:
                update["scope_status"] = scope_status
            if resolution_status is not None:
                update["resolution_status"] = resolution_status
            return a.model_copy(update=update)

        updated = self.repo.update_asset(self.project_id, current.asset_id, apply)
        self.by_key[key] = updated
        self.updated += 1
        return updated.asset_id


# ---------------------------------------------------------------------- snapshots / changes


def diff_snapshots(previous: dict[str, Any] | None, current: dict[str, Any]) -> dict[str, Any]:
    """Compare two inventory snapshots. Hosts absent now are 'not observed', not 'gone'."""
    if not previous:
        return {"baseline": True, "previous_scan_id": None}
    prev_hosts: dict[str, Any] = previous.get("hosts", {})
    cur_hosts: dict[str, Any] = current.get("hosts", {})
    changes: dict[str, Any] = {
        "baseline": False,
        "previous_scan_id": previous.get("scan_id"),
        "new_hosts": sorted(set(cur_hosts) - set(prev_hosts)),
        "not_observed_hosts": sorted(set(prev_hosts) - set(cur_hosts)),
        "status_changes": [],
        "ip_changes": [],
        "opened_ports": [],
        "closed_ports": [],
        "new_origins": sorted(set(current.get("origins", [])) - set(previous.get("origins", []))),
        "not_observed_origins": sorted(
            set(previous.get("origins", [])) - set(current.get("origins", []))
        ),
    }
    for host in sorted(set(cur_hosts) & set(prev_hosts)):
        old, new = prev_hosts[host], cur_hosts[host]
        if old.get("status") != new.get("status"):
            changes["status_changes"].append(
                {"host": host, "from": old.get("status"), "to": new.get("status")}
            )
        if sorted(old.get("ips", [])) != sorted(new.get("ips", [])):
            changes["ip_changes"].append(
                {"host": host, "from": sorted(old.get("ips", [])), "to": sorted(new.get("ips", []))}
            )
        old_open = set(old.get("open_ports", []))
        new_open = set(new.get("open_ports", []))
        tested = set(new.get("tested_ports", []))
        for port in sorted(new_open - old_open):
            changes["opened_ports"].append({"host": host, "port": port})
        for port in sorted((old_open - new_open) & tested):  # only if re-tested this time
            changes["closed_ports"].append({"host": host, "port": port})
    return changes
