import json
import threading
from pathlib import Path

from app.core.correlation import set_correlation_id
from app.models import AuditAction, new_id
from app.models.audit import AuditEvent
from app.storage.audit import AuditLog
from app.storage.jsonl import JsonlLog
from app.storage.repository import StorageRepository


def _log(tmp_path: Path, rotate: int = 10 * 1024 * 1024) -> JsonlLog:
    return JsonlLog(tmp_path, "events", rotate_bytes=rotate, lock_timeout=5)


def test_append_and_read_newest_first(tmp_path: Path) -> None:
    log = _log(tmp_path)
    for i in range(5):
        log.append({"i": i})
    items, corrupt, more = log.read_newest(limit=3)
    assert [x["i"] for x in items] == [4, 3, 2] and corrupt == 0 and more
    items, _, more = log.read_newest(offset=3, limit=3)
    assert [x["i"] for x in items] == [1, 0] and not more


def test_corrupt_lines_skipped_and_counted(tmp_path: Path) -> None:
    log = _log(tmp_path)
    log.append({"i": 1})
    with open(log.current, "ab") as fh:
        fh.write(b"this is not json\n[1,2]\n\xff\xfe\n")
    log.append({"i": 2})
    items, corrupt, _ = log.read_newest(limit=10)
    assert [x["i"] for x in items] == [2, 1]
    assert corrupt == 3


def test_torn_final_line_does_not_swallow_next_event(tmp_path: Path) -> None:
    log = _log(tmp_path)
    log.append({"i": 1})
    with open(log.current, "ab") as fh:
        fh.write(b'{"i": 2, "partial')  # crash mid-append, no newline
    log.append({"i": 3})
    items, corrupt, _ = log.read_newest(limit=10)
    assert [x["i"] for x in items] == [3, 1]
    assert corrupt == 1


def test_rotation_by_size_and_reading_across_segments(tmp_path: Path) -> None:
    log = _log(tmp_path, rotate=200)
    for i in range(30):
        log.append({"i": i, "pad": "x" * 20})
    segments = log.segments()
    assert len(segments) >= 3
    assert all(p.stat().st_size <= 200 for p in segments)
    items, corrupt, more = log.read_newest(limit=100)
    assert [x["i"] for x in items] == list(range(29, -1, -1)) and corrupt == 0 and not more


def test_concurrent_appends_do_not_interleave(tmp_path: Path) -> None:
    log = _log(tmp_path, rotate=50_000)

    def work(t: int) -> None:
        for i in range(40):
            log.append({"t": t, "i": i, "pad": "y" * 200})

    threads = [threading.Thread(target=work, args=(t,)) for t in range(5)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    items, corrupt, _ = log.read_newest(limit=1000)
    assert corrupt == 0 and len(items) == 200


def test_audit_redacts_secrets_before_persistence(tmp_path: Path) -> None:
    audit = AuditLog(tmp_path, rotate_bytes=1024 * 1024, lock_timeout=5)
    set_correlation_id("corr-12345678")
    try:
        event = audit.record(
            AuditAction.TOOL_CONFIG_CHANGED,
            target_ids=["https://admin:hunter2@example.com/"],
            metadata={
                "headers": {
                    "Authorization": "Bearer abcdefghijklmnop",
                    "Cookie": "sid=xyz",
                    "Accept": "*/*",
                },
                "api_key": "sk_live_abcdefghijklmnop",
                "note": "retried with password=hunter2",
                "url": "https://example.com/cb?access_token=tok_secret_1",
            },
        )
    finally:
        set_correlation_id(None)
    raw = (tmp_path / "audit.jsonl").read_text("utf-8")
    for secret in ("hunter2", "abcdefghijklmnop", "sid=xyz", "sk_live", "tok_secret_1"):
        assert secret not in raw, secret
    assert "*/*" in raw
    assert event.correlation_id == "corr-12345678"
    page = audit.list()
    assert page.items[0].event_id == event.event_id and page.corrupt_lines == 0


def test_prebuilt_event_metadata_still_redacted(tmp_path: Path) -> None:
    audit = AuditLog(tmp_path, rotate_bytes=1024 * 1024, lock_timeout=5)
    audit.append(
        AuditEvent(
            event_id=new_id("event"),
            action=AuditAction.SETTINGS_CHANGED,
            metadata={"password": "plain", "Set-Cookie": "a=b"},
        )
    )
    line = json.loads((tmp_path / "audit.jsonl").read_text().splitlines()[0])
    assert line["metadata"] == {"password": "[REDACTED]", "Set-Cookie": "[REDACTED]"}


def test_audit_filtering_and_invalid_lines(repo: StorageRepository) -> None:
    pid = new_id("project")
    repo.audit.record(AuditAction.PROJECT_CREATED, project_id=pid)
    repo.audit.record(AuditAction.SCAN_STARTED, project_id=pid)
    with open(repo.paths.path("audit", "audit.jsonl"), "ab") as fh:
        fh.write(b'{"action": "drop_tables"}\n')
    page = repo.audit.list(project_id=pid)
    assert [e.action for e in page.items] == ["scan_started", "project_created"]
    assert page.corrupt_lines == 1
    assert [e.action for e in repo.audit.list(action=AuditAction.STORAGE_INITIALIZED).items] == [
        "storage_initialized"
    ]
