#!/usr/bin/env python
"""Local release gate for hermes-plugin.

The golden hermes/strix integration suites skip silently when their host
package is missing, and CI can never install hermes (private local
framework).  This gate runs the full suite in the CURRENT venv and fails
on any skip, forcing releases to be cut from a complete environment:

    py -3.12 venv with BOTH strix-agent and hermes-agent installed

Usage (repo root, or hermes-plugin with --root):

    python scripts/release_gate.py            # run tests, fail on skips
    python scripts/release_gate.py --skip-check   # tests only (dev loop)
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PLUGIN_DIR = HERE.parent


def check_optional_imports() -> list[str]:
    missing = []
    for mod in ("strix", "hermes_cli"):
        if importlib.util.find_spec(mod) is None:
            missing.append(mod)
    return missing


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--skip-check", action="store_true", help="do not fail on skipped tests (debug only)"
    )
    args = parser.parse_args()

    missing = check_optional_imports()
    if missing:
        print(f"FAIL: release gate needs a complete venv; missing: {', '.join(missing)}")
        print("      golden suites would silently skip - install them and rerun")
        return 2

    print("[gate] environment OK (strix + hermes importable), running suite...")
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", str(PLUGIN_DIR / "tests"), "--tb=short", "-ra"],
        cwd=str(PLUGIN_DIR),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    out = proc.stdout + proc.stderr
    tail = "\n".join(out.splitlines()[-6:])
    print(tail)

    summary = re.search(r"^([0-9]+) passed(?:,\s*([0-9]+) skipped)?", out, re.M)
    failed = proc.returncode != 0
    skipped = int(summary.group(2) or 0) if summary else None

    if failed:
        print("FAIL: tests failed")
        return 1
    if not args.skip_check and skipped:
        print(f"FAIL: {skipped} test(s) skipped - release env incomplete")
        return 1
    if not summary:
        print("FAIL: could not parse pytest summary")
        return 1
    print(f"PASS: {summary.group(1)} passed, 0 skipped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
