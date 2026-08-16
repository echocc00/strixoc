"""0.4.2.3: audit log rotation (RotatingFileHandler 10MB x 5)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from plugin import authz


@pytest.fixture(autouse=True)
def _release_audit_handles():
    yield
    authz._reset_audit_loggers()


def _cfg(log: Path) -> dict:
    return {"audit_log": str(log)}


def _write_records(log: Path, n: int) -> None:
    for i in range(n):
        authz.audit(_cfg(log), action="rotation-test", seq=i, pad="x" * 80)


def test_rotation_creates_backup_files(tmp_path, monkeypatch):
    log = tmp_path / "strix-audit.jsonl"
    monkeypatch.setattr(authz, "AUDIT_MAX_BYTES", 512)
    monkeypatch.setattr(authz, "AUDIT_BACKUP_COUNT", 3)
    _write_records(log, 40)  # ~9KB total -> several rotations

    assert log.exists()
    backups = sorted(p.name for p in tmp_path.glob("strix-audit.jsonl.*"))
    assert backups, "no rotated files appeared"
    # RotatingFileHandler naming: .1 is the most recent backup, bounded by count
    assert backups[-1] in {f"strix-audit.jsonl.{i}" for i in range(1, 4)}
    assert len(backups) <= 3


def test_rotated_content_is_complete_jsonl(tmp_path, monkeypatch):
    log = tmp_path / "strix-audit.jsonl"
    monkeypatch.setattr(authz, "AUDIT_MAX_BYTES", 1024)  # ~6 records per file
    monkeypatch.setattr(authz, "AUDIT_BACKUP_COUNT", 20)  # keep everything
    _write_records(log, 30)

    files = [log, *sorted(tmp_path.glob("strix-audit.jsonl.*"))]
    seqs = []
    for f in files:
        for line in f.read_text(encoding="utf-8").splitlines():
            if line.strip():
                seqs.append(json.loads(line)["seq"])
    # with ample backups every record survives exactly once
    assert sorted(seqs) == list(range(30))


def test_rotation_bounded_by_backup_count(tmp_path, monkeypatch):
    """Oldest records are dropped once backups are exhausted - bounded disk."""
    log = tmp_path / "strix-audit.jsonl"
    monkeypatch.setattr(authz, "AUDIT_MAX_BYTES", 256)
    monkeypatch.setattr(authz, "AUDIT_BACKUP_COUNT", 1)
    _write_records(log, 40)

    files = [log, *sorted(tmp_path.glob("strix-audit.jsonl.*"))]
    seqs = []
    for f in files:
        for line in f.read_text(encoding="utf-8").splitlines():
            if line.strip():
                seqs.append(json.loads(line)["seq"])
    assert sorted(seqs) == list(range(40))[-len(seqs) :]  # contiguous recent suffix
    assert len(seqs) < 40


def test_small_writes_do_not_rotate(tmp_path):
    log = tmp_path / "strix-audit.jsonl"
    _write_records(log, 3)
    assert log.exists()
    assert list(tmp_path.glob("strix-audit.jsonl.*")) == []


def test_independent_paths_get_independent_handlers(tmp_path):
    a = tmp_path / "a.jsonl"
    b = tmp_path / "b.jsonl"
    authz.audit(_cfg(a), action="one")
    authz.audit(_cfg(b), action="two")
    assert "one" in a.read_text(encoding="utf-8")
    assert "two" in b.read_text(encoding="utf-8")
    assert "one" not in b.read_text(encoding="utf-8")


def test_open_failure_stays_silent(tmp_path):
    # directory in place of the log file -> RotatingFileHandler cannot open
    blocked = tmp_path / "blocked.jsonl"
    blocked.mkdir()
    authz.audit(_cfg(blocked), action="check", target="t")  # must not raise
