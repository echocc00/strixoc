"""Strix x Hermes plugin configuration.

Loads ``~/.hermes/strix.yaml`` (override with ``HERMES_STRIX_CONFIG`` env var)
over a built-in default set.  YAML preferred, JSON accepted.  Missing file or
missing key -> defaults; malformed file -> clear error.
"""

from __future__ import annotations

import json
import os
import re
import sys
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
    # Extra env vars injected into the worker process.  Values may use the
    # ``@hermes:<field>`` token to pull a value from the hermes config.yaml
    # (e.g. api_key / base_url / model) so LLM keys live in exactly one
    # place and never have to be copied here.
    "worker_env": {},
    # Optional explicit path to the hermes config.yaml that ``@hermes:``
    # tokens read.  Set this when hermes runs with a named profile — profile
    # activation can move HERMES_HOME around and home-based resolution is
    # not reliable.  Empty = env HERMES_HOME -> platform default home.
    "hermes_config_path": "",
}


def config_path() -> Path:
    env = os.environ.get("HERMES_STRIX_CONFIG")
    if env:
        return Path(env).expanduser()
    hh = os.environ.get("HERMES_HOME")
    if hh:
        return Path(hh).expanduser() / "strix.yaml"
    return Path.home() / ".hermes" / "strix.yaml"


def resolve_path(p: str) -> Path:
    return Path(os.path.expanduser(str(p)))


def hermes_home() -> Path:
    """Match hermes' own resolution: HERMES_HOME env var, then platform default."""
    env = os.environ.get("HERMES_HOME")
    if env:
        return Path(env)
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", "")) if os.environ.get("LOCALAPPDATA") else Path.home() / "AppData" / "Local"
        return base / "hermes"
    return Path.home() / ".hermes"


def hermes_config_value(field: str, config_path: str | Path | None = None) -> str | None:
    """Read one scalar from the hermes config.yaml (api_key / base_url / model).
    Never raises.  Used by ``worker_env`` ``@hermes:<field>`` tokens.

    Resolution: explicit ``config_path`` (own option — set it when hermes runs
    under a named profile) -> env HERMES_HOME -> platform default home.  The
    fallback to the default home covers profile homes that lack credentials."""
    value = _hermes_config_value_from(field, Path(config_path).expanduser()) \
        if config_path else None
    if value is not None:
        return value
    value = _hermes_config_value_from(field, hermes_home() / "config.yaml")
    if value is not None:
        return value
    env_override = os.environ.get("HERMES_HOME")
    if env_override:
        default_home = _platform_default_home()
        if default_home != hermes_home():
            value = _hermes_config_value_from(field, default_home / "config.yaml")
    return value


def _platform_default_home() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", "")) if os.environ.get("LOCALAPPDATA") else Path.home() / "AppData" / "Local"
        return base / "hermes"
    return Path.home() / ".hermes"


def _hermes_config_value_from(field: str, config_file: Path) -> str | None:
    """Read one scalar from a hermes config.yaml file (full file path)."""
    cfg = config_file
    try:
        text = cfg.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    patterns = {
        "api_key": r"^\s*api_key:\s*(?:\"([^\"]+)\"|'([^']+)'|(\S+))",
        "base_url": r"^\s*base_url:\s*(?:\"([^\"]+)\"|'([^']+)'|(\S+))",
        "model": r"^\s*default:\s*(?:\"([^\"]+)\"|'([^']+)'|(\S+))",
    }
    pat = patterns.get(field)
    if not pat:
        return None
    m = re.search(pat, text, re.M)
    if not m:
        return None
    return next((g for g in m.groups() if g), None)


def resolve_worker_env(cfg: dict[str, Any]) -> dict[str, str]:
    """Expand ``worker_env`` values: ``@hermes:<field>`` tokens resolved from
    the hermes config, plain values passed through."""
    out: dict[str, str] = {}
    pinned = cfg.get("hermes_config_path") or None
    for key, value in (cfg.get("worker_env") or {}).items():
        sval = str(value)
        if sval.startswith("@hermes:"):
            resolved = hermes_config_value(sval[len("@hermes:"):], pinned)
            if resolved is not None:
                out[key] = resolved
        else:
            out[key] = sval
    return out


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