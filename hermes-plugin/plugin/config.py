"""Strix x Hermes plugin configuration.

Loads ``~/.hermes/strix.yaml`` (override with ``HERMES_STRIX_CONFIG`` env var)
over a built-in default set.  YAML preferred, JSON accepted.  Missing file or
missing key -> defaults; malformed file -> clear error.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

DEFAULT_CONFIG: dict[str, Any] = {
    # Targets the operator authorizes scans against.  Exact host, ``*.domain``
    # suffix, ``prefix.*``, IPv4/IPv6 CIDR, or a full URL prefix.
    "allowed_targets": ["localhost", "127.0.0.1", "::1", "*.internal", "*.local"],
    # Chat ids allowed to start scans (CLI = "cli"). Empty list = any chat.
    "allowed_chats": [],
    # When true, every scan must explicitly confirm authorization via
    # strix_scan(confirm_authorized=true) or /pentest --confirm-authorized.
    "require_authorized_flag": True,
    "max_budget_default": 5.0,
    "max_budget_cap": 25.0,
    # Absolute path to the strix worker's Python 3.12 interpreter (its own
    # venv). Empty = resolve STRIX_WORKER_PYTHON env var, then PATH.
    "worker_python": "",
    "audit_log": "~/.hermes/logs/strix-audit.jsonl",
    "scans_db": "~/.hermes/logs/strix-scans.json",
    # Working directory the worker runs scans from (defaults to hermes cwd).
    # The strix sandbox config (~/.strix/cli-config.json) controls the image.
    "runs_cwd": "",
}


def config_path() -> Path:
    env = os.environ.get("HERMES_STRIX_CONFIG")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".hermes" / "strix.yaml"


def resolve_path(p: str) -> Path:
    return Path(os.path.expanduser(str(p)))


def load_config(path: Path | str | None = "auto") -> dict[str, Any]:
    """Merge config file over defaults. ``path=None`` skips the file (defaults
    only, used by tests). ``"auto"`` (default) uses the env/default location."""
    cfg: dict[str, Any] = dict(DEFAULT_CONFIG)
    if path == "auto":
        path = config_path()
    if path is None:
        return cfg
    p = Path(path).expanduser()
    if not p.exists():
        return cfg
    raw: Any
    if p.suffix.lower() == ".json":
        raw = json.loads(p.read_text(encoding="utf-8"))
    else:
        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError:
            raw = json.loads(p.read_text(encoding="utf-8"))
        else:
            raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"config {p} must be a mapping")
    cfg.update(raw)
    return cfg