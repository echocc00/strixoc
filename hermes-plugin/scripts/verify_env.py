#!/usr/bin/env python3
"""Strix x Hermes — Phase-0 style environment verifier.

Run inside the hermes environment (any python >= 3.11) and optionally point
STRIX_WORKER_PYTHON at the strix worker venv to verify the worker side
(strix import + docker reachability) from the same script.

Usage:
    python verify_env.py                # plugin-side checks only
    STRIX_WORKER_PYTHON=/opt/.../python python verify_env.py   # + worker checks
    DOCKER_HOST=ssh://user@nas python verify_env.py            # remote docker
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

PLUGIN_DIR = Path(__file__).resolve().parent.parent / "plugin"
OK, WARN, FAIL = "PASS", "WARN", "FAIL"

results: list[tuple[str, str, str]] = []


def check(name: str, ok: bool, detail: str, level: str | None = None) -> None:
    verdict = OK if ok else (level or FAIL)
    results.append((verdict, name, detail))
    print(f"[{verdict}] {name}: {detail}")


def main() -> int:
    print("== Strix x Hermes environment verification ==")

    # 1. interpreter
    check("interpreter", sys.version_info >= (3, 11), f"python {sys.version_info.major}.{sys.version_info.minor}")

    # 2/3. plugin import + config — only meaningful from the repo tree
    if PLUGIN_DIR.exists():
        try:
            sys.path.insert(0, str(PLUGIN_DIR))
            import config  # noqa: F401
            import authz  # noqa: F401
            import backends  # noqa: F401
            import runner  # noqa: F401
            import strix_tools  # noqa: F401
            import commands  # noqa: F401

            check("plugin import (no strix needed)", True, "all hermes-side modules import cleanly")
        except Exception as exc:  # noqa: BLE001
            check("plugin import (no strix needed)", False, f"{type(exc).__name__}: {exc}")

        try:
            cfg = config.load_config()
            check("config load", True, f"{config.config_path()}")
            check("allowlist non-empty", bool(cfg.get("allowed_targets")), f"{len(cfg.get('allowed_targets') or [])} rule(s)")
            check("confirm gate", bool(cfg.get("require_authorized_flag", True)),
                  "require_authorized_flag on")
        except Exception as exc:  # noqa: BLE001
            check("config load", False, f"{type(exc).__name__}: {exc}")
    else:
        check("plugin import (no strix needed)", True,
              f"plugin dir not present here ({PLUGIN_DIR}) — not a repo checkout", level=WARN)
        cfg: dict = {}

    # 4. worker interpreter
    wpy = os.environ.get("STRIX_WORKER_PYTHON") or str(cfg.get("worker_python") or "")
    if wpy and not Path(wpy).exists() and shutil.which(wpy) is None:
        check("worker python", False, f"not found: {wpy}")
    elif wpy:
        check("worker python", True, wpy)
        out = subprocess.run([wpy, "-V"], capture_output=True, text=True, timeout=30)
        check("worker python runs", out.returncode == 0, out.stdout.strip() or out.stderr.strip())
        ver = subprocess.run(
            [wpy, "-c", "import sys; print(sys.version_info >= (3, 12))"],
            capture_output=True, text=True, timeout=30,
        )
        check("worker python >= 3.12", ver.stdout.strip() == "True", "strix requires py3.12")
        imp = subprocess.run(
            [wpy, "-c", "import importlib.metadata as m; print(m.version('strix-agent'))"],
            capture_output=True, text=True, timeout=60,
        )
        check("worker strix installed", imp.returncode == 0, imp.stdout.strip() or imp.stderr.strip().splitlines()[-1])
        if imp.returncode == 0:
            docker_ok = subprocess.run(
                [wpy, "-c", "import docker; docker.from_env().ping(); print('docker ping OK')"
                            "; import json,os; print('DOCKER_HOST='+os.environ.get('DOCKER_HOST','(local)'))"],
                capture_output=True, text=True, timeout=60,
                env=dict(os.environ, DOCKER_HOST=os.environ.get("DOCKER_HOST", "")),
            )
            check("worker docker reachable", docker_ok.returncode == 0,
                  docker_ok.stdout.strip() or docker_ok.stderr.strip().splitlines()[-1][:200])
    else:
        check("worker python", False, "not configured — set worker_python in strix.yaml or STRIX_WORKER_PYTHON")

    # 5. deployed plugin
    hermes_home = Path(os.environ.get("HERMES_HOME") or (
        Path(os.environ.get("LOCALAPPDATA", "")) / "hermes" if sys.platform == "win32"
        else Path.home() / ".hermes"))
    deployed = hermes_home / "plugins" / "strix"
    if (deployed / "plugin.yaml").exists():
        check("hermes plugin deployed", True, str(deployed))
    else:
        check("hermes plugin deployed", True, f"not present at {deployed} (this host may be worker-only)", level=WARN)

    failed = sum(1 for v, _, _ in results if v == FAIL)
    print(f"\n== Summary: {sum(1 for v,_,_ in results if v==OK)} PASS "
          f"/ {sum(1 for v,_,_ in results if v==WARN)} WARN / {failed} FAIL ==")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())