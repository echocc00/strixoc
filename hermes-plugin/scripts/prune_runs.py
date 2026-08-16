#!/usr/bin/env python3
"""Retention for ``strix_runs/<id>/`` directories (DEV_PLAN 2.2).

Run artifacts (reports, PoCs, SARIF) accumulate unboundedly on the NAS.
This script deletes run directories older than ``--days``, archiving a
one-line summary of each pruned run to ``<runs_dir>/index.jsonl`` first,
so trend data (status / vuln counts) survives the purge and can feed the
1.x trend-diff feature.

Standalone by design: imports nothing from the plugin package, so it runs
from any cron python (the NAS cron environment is minimal).

Usage:
  python scripts/prune_runs.py --days 30            # dry-run (default): show only
  python scripts/prune_runs.py --days 30 --apply    # archive summary + delete

NAS cron (weekly, Sunday 04:17):
  17 4 * * 0 cd /volume1/soft/Hermes && python3 hermes-plugin/scripts/prune_runs.py \
      --runs-dir strix_runs --days 30 --apply >> ~/.hermes/logs/prune_runs.log 2>&1
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from pathlib import Path
from typing import Any

SEVERITY_KEY = "severity"


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _dir_age_days(run_dir: Path, now: float) -> float:
    """Age of a run dir = time since its last write.  Creating files inside a
    dir bumps the dir mtime, but later in-place rewrites only bump the file's
    own mtime - so take the max over the dir and its landmark files."""
    stamps = [run_dir.stat().st_mtime]
    for name in ("run.json", "vulnerabilities.json"):
        try:
            stamps.append((run_dir / name).stat().st_mtime)
        except OSError:
            pass
    return max(0.0, (now - max(stamps)) / 86400.0)


def _candidate(run_dir: Path) -> bool:
    """Only prune dirs that look like scan output - never touch manually
    created subfolders (backups, scratch)."""
    return run_dir.name.startswith("strix-") or (run_dir / "run.json").exists()


def _summary(run_dir: Path, now: float) -> dict[str, Any]:
    """Best-effort one-line archive record; never raises."""
    rec: dict[str, Any] = {
        "run_id": run_dir.name,
        "run_dir": str(run_dir),
        "pruned_ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "age_days": round(_dir_age_days(run_dir, now), 1),
    }
    run_json = _load_json(run_dir / "run.json")
    if isinstance(run_json, dict):
        for key in ("status", "started_at", "finished_at", "target", "total_cost"):
            if key in run_json:
                rec[key] = run_json[key]
    vulns = _load_json(run_dir / "vulnerabilities.json")
    if isinstance(vulns, list):
        rec["vuln_count"] = len(vulns)
        by_severity: dict[str, int] = {}
        for v in vulns:
            if isinstance(v, dict):
                sev = str(v.get(SEVERITY_KEY, "info")).lower()
                by_severity[sev] = by_severity.get(sev, 0) + 1
        rec["by_severity"] = by_severity
    return rec


def prune(runs_dir: Path, days: float, apply: bool, now: float | None = None) -> dict[str, Any]:
    """Prune old run dirs.  Returns a result dict (also used by tests).

    ``dry-run`` computes exactly what ``apply`` would do - same candidates,
    same summaries - but touches nothing on disk.
    """
    now = time.time() if now is None else now
    result: dict[str, Any] = {"runs_dir": str(runs_dir), "pruned": [], "kept": 0, "archived": 0}
    if not runs_dir.is_dir():
        result["error"] = f"runs dir not found: {runs_dir}"
        return result
    index_path = runs_dir / "index.jsonl"
    lines: list[str] = []
    for entry in sorted(runs_dir.iterdir()):
        if not entry.is_dir() or entry.name == "index.jsonl":
            continue
        if not _candidate(entry):
            continue
        if _dir_age_days(entry, now) <= days:
            result["kept"] += 1
            continue
        rec = _summary(entry, now)
        result["pruned"].append(rec)
        if apply:
            lines.append(json.dumps(rec, ensure_ascii=False))
            shutil.rmtree(entry)
    if apply and lines:
        with index_path.open("a", encoding="utf-8") as f:
            f.write("".join(line + "\n" for line in lines))
        result["archived"] = len(lines)
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--runs-dir", default="strix_runs", type=Path, help="runs root (default ./strix_runs)"
    )
    ap.add_argument("--days", type=float, default=30.0, help="retention days (default 30)")
    ap.add_argument(
        "--apply",
        action="store_true",
        help="actually delete (default is dry-run: report only)",
    )
    args = ap.parse_args(argv)

    runs_dir = args.runs_dir.resolve()
    if runs_dir == runs_dir.anchor or runs_dir.parent == runs_dir:  # rmtree safety
        print(f"refusing unsafe runs dir: {runs_dir}", file=sys.stderr)
        return 2

    res = prune(runs_dir, args.days, apply=args.apply)
    if "error" in res:
        print(f"prune_runs: {res['error']}", file=sys.stderr)
        return 1
    prefix = "" if args.apply else "[dry-run] "
    for rec in res["pruned"]:
        vulns = rec.get("vuln_count", "?")
        status = rec.get("status", "?")
        print(f"{prefix}prune {rec['run_dir']} (age {rec['age_days']}d, {vulns} vulns, {status})")
    verb = "pruned" if args.apply else "would prune"
    print(f"{verb}: {len(res['pruned'])}, kept: {res['kept']}, archived: {res['archived']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
