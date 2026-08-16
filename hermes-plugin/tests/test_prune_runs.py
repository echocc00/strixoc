"""0.4.2.2: strix_runs retention (prune_runs.py).

The script is standalone (no plugin imports) so NAS cron can run it from a
minimal python; tests load it straight from scripts/.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "prune_runs", Path(__file__).resolve().parent.parent / "scripts" / "prune_runs.py"
)
prune_runs = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(prune_runs)

NOW = 1_800_000_000.0
DAY = 86400.0


def _make_run(
    root: Path, name: str, *, age_days: float, vulns: list | None = None, status: str = "completed"
) -> Path:
    d = root / name
    d.mkdir(parents=True)
    (d / "run.json").write_text(
        json.dumps(
            {
                "status": status,
                "started_at": "2026-08-01T00:00:00Z",
                "finished_at": "2026-08-01T00:30:00Z",
                "total_cost": 1.25,
            }
        ),
        encoding="utf-8",
    )
    (d / "vulnerabilities.json").write_text(
        json.dumps(
            vulns
            if vulns is not None
            else [
                {"id": "v1", "severity": "high"},
                {"id": "v2", "severity": "low"},
            ]
        ),
        encoding="utf-8",
    )
    stamp = NOW - age_days * DAY
    old = (stamp, stamp)
    import os

    os.utime(d / "run.json", old)
    os.utime(d / "vulnerabilities.json", old)
    os.utime(d, old)
    return d


@pytest.fixture
def runs_dir(tmp_path):
    rd = tmp_path / "strix_runs"
    rd.mkdir()
    yield rd


def test_dry_run_touches_nothing(runs_dir):
    _make_run(runs_dir, "strix-old", age_days=45)
    _make_run(runs_dir, "strix-new", age_days=3)

    res = prune_runs.prune(runs_dir, days=30, apply=False, now=NOW)

    assert [r["run_id"] for r in res["pruned"]] == ["strix-old"]
    assert res["kept"] == 1
    assert res["archived"] == 0
    assert (runs_dir / "strix-old").is_dir()  # untouched
    assert not (runs_dir / "index.jsonl").exists()


def test_apply_deletes_and_archives_summary(runs_dir):
    _make_run(runs_dir, "strix-old", age_days=45, vulns=[{"id": "v1", "severity": "high"}])
    _make_run(runs_dir, "strix-new", age_days=3)

    res = prune_runs.prune(runs_dir, days=30, apply=True, now=NOW)

    assert not (runs_dir / "strix-old").exists()
    assert (runs_dir / "strix-new").is_dir()
    assert res["archived"] == 1
    lines = (runs_dir / "index.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["run_id"] == "strix-old"
    assert rec["status"] == "completed"
    assert rec["vuln_count"] == 1
    assert rec["by_severity"] == {"high": 1}
    assert rec["total_cost"] == 1.25


def test_apply_is_idempotent(runs_dir):
    _make_run(runs_dir, "strix-old", age_days=45)
    prune_runs.prune(runs_dir, days=30, apply=True, now=NOW)
    res2 = prune_runs.prune(runs_dir, days=30, apply=True, now=NOW)
    assert res2["pruned"] == [] and res2["archived"] == 0


def test_non_run_dirs_are_never_pruned(runs_dir):
    manual = runs_dir / "backups"
    manual.mkdir()
    import os

    old = (NOW - 90 * DAY, NOW - 90 * DAY)
    os.utime(manual, old)
    # no run.json, no strix- prefix -> not a candidate even at 90d

    res = prune_runs.prune(runs_dir, days=30, apply=True, now=NOW)

    assert manual.is_dir()
    assert res["pruned"] == []


def test_missing_runs_dir_is_reported(tmp_path):
    res = prune_runs.prune(tmp_path / "nope", days=30, apply=True, now=NOW)
    assert "error" in res


def test_cli_dry_run_default(runs_dir, capsys, monkeypatch):
    monkeypatch.setattr(prune_runs.time, "time", lambda: NOW)
    _make_run(runs_dir, "strix-old", age_days=45)
    rc = prune_runs.main(["--runs-dir", str(runs_dir), "--days", "30"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "[dry-run]" in out and "strix-old" in out
    assert (runs_dir / "strix-old").is_dir()


def test_cli_apply_removes(runs_dir, capsys, monkeypatch):
    monkeypatch.setattr(prune_runs.time, "time", lambda: NOW)
    _make_run(runs_dir, "strix-old", age_days=45)
    rc = prune_runs.main(["--runs-dir", str(runs_dir), "--days", "30", "--apply"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "[dry-run]" not in out
    assert not (runs_dir / "strix-old").exists()
    assert "pruned: 1" in out


def test_cli_refuses_filesystem_root(capsys):
    rc = prune_runs.main(["--runs-dir", "/", "--apply"])
    assert rc == 2
