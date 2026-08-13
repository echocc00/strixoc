"""Config loading: defaults, file merge, path resolution, env override."""

import sys
from pathlib import Path

from plugin import config as cfgmod


def test_defaults_are_sane():
    c = cfgmod.load_config(path=None)
    assert "localhost" in c["allowed_targets"]
    assert "*.internal" in c["allowed_targets"]
    assert c["require_authorized_flag"] is True
    assert c["max_budget_default"] == 5.0
    assert c["max_budget_cap"] == 25.0
    assert isinstance(c["allowed_chats"], list)


def test_file_overrides_defaults(tmp_path):
    f = tmp_path / "strix.yaml"
    f.write_text(
        "allowed_targets:\n  - example.com\nrequire_authorized_flag: false\n"
        "max_budget_default: 2.5\n",
        encoding="utf-8",
    )
    c = cfgmod.load_config(path=f)
    assert c["allowed_targets"] == ["example.com"]
    assert c["require_authorized_flag"] is False
    assert c["max_budget_default"] == 2.5
    # untouched keys keep defaults
    assert "*.internal" not in c["allowed_targets"]
    assert c["max_budget_cap"] == 25.0


def test_json_config_accepted(tmp_path):
    f = tmp_path / "strix.json"
    f.write_text('{"allowed_targets": ["staging.app"], "worker_python": "py3.12"}', encoding="utf-8")
    c = cfgmod.load_config(path=f)
    assert c["allowed_targets"] == ["staging.app"]
    assert c["worker_python"] == "py3.12"


def test_missing_file_returns_defaults(tmp_path):
    c = cfgmod.load_config(path=tmp_path / "nope.yaml")
    assert c["allowed_targets"]


def test_resolve_path_expands_home(tmp_path, monkeypatch):
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    p = cfgmod.resolve_path("~/logs/x.json")
    assert p == Path(tmp_path) / "logs" / "x.json"


def test_env_override_config_path(tmp_path, monkeypatch):
    f = tmp_path / "custom.yaml"
    f.write_text("require_authorized_flag: false\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_STRIX_CONFIG", str(f))
    assert cfgmod.config_path() == f
    c = cfgmod.load_config()
    assert c["require_authorized_flag"] is False


def test_config_path_honors_hermes_home(tmp_path, monkeypatch):
    """Golden-path fix (2026-08-13): NAS runs with HERMES_HOME exported but
    HOME of the service user differs — the plugin must look for strix.yaml
    under HERMES_HOME, not the process HOME."""
    monkeypatch.delenv("HERMES_STRIX_CONFIG", raising=False)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hh"))
    monkeypatch.setenv("HOME", str(tmp_path / "elsewhere"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "elsewhere"))
    assert cfgmod.config_path() == tmp_path / "hh" / "strix.yaml"
    monkeypatch.delenv("HERMES_HOME")
    assert cfgmod.config_path() == tmp_path / "elsewhere" / ".hermes" / "strix.yaml"


# --- hermes config bridging (worker_env @hermes: tokens) ---------------------


def test_hermes_home_resolution(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hh"))
    assert cfgmod.hermes_home() == tmp_path / "hh"
    monkeypatch.delenv("HERMES_HOME")
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    if sys.platform == "win32":
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
        assert cfgmod.hermes_home() == tmp_path / "local" / "hermes"
    else:
        assert cfgmod.hermes_home() == tmp_path / ".hermes"


def test_hermes_config_token_resolution(tmp_path, monkeypatch):
    hh = tmp_path / "hh"
    monkeypatch.setenv("HERMES_HOME", str(hh))
    cfg_file = hh / "config.yaml"
    cfg_file.parent.mkdir(parents=True)
    cfg_file.write_text(
        "model:\n  default: MiniMax-M3\n  provider: custom\n"
        "  base_url: https://api.minimaxi.com/v1\n  api_key: sk-abc123\n",
        encoding="utf-8",
    )
    assert cfgmod.hermes_config_value("api_key") == "sk-abc123"
    assert cfgmod.hermes_config_value("base_url") == "https://api.minimaxi.com/v1"
    assert cfgmod.hermes_config_value("model") == "MiniMax-M3"
    assert cfgmod.hermes_config_value("nope") is None


def test_hermes_config_token_quoted_and_missing(tmp_path, monkeypatch):
    # isolate the fallback default home from the real host config
    monkeypatch.delenv("HERMES_HOME", raising=False)
    if sys.platform == "win32":
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    else:
        monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    hh = tmp_path / "hh"
    monkeypatch.setenv("HERMES_HOME", str(hh))
    cfg_file = hh / "config.yaml"
    cfg_file.parent.mkdir(parents=True)
    cfg_file.write_text('api_key: "sk-xyz"\nbase_url:  \n', encoding="utf-8")
    assert cfgmod.hermes_config_value("api_key") == "sk-xyz"
    assert cfgmod.hermes_config_value("base_url") is None

def test_hermes_config_value_pinned_path(monkeypatch, tmp_path):
    """hermes_config_path pins @hermes: token resolution regardless of the
    active profile/home env dance (P0-2: 401 ended the Feishu scan)."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "somewhere-none"))
    pin = tmp_path / "base" / "config.yaml"
    pin.parent.mkdir(parents=True)
    pin.write_text("api_key: sk-pinned-1\nbase_url: https://api.minimaxi.com/v1\n", encoding="utf-8")
    assert cfgmod.hermes_config_value("api_key", pin) == "sk-pinned-1"
    assert cfgmod.hermes_config_value("base_url", pin) == "https://api.minimaxi.com/v1"


def test_resolve_worker_env_uses_pinned_path(monkeypatch, tmp_path):
    from plugin import config

    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "nope"))
    pin = tmp_path / "cfg.yaml"
    pin.write_text("api_key: sk-pinned-2\n", encoding="utf-8")
    cfg = {"worker_env": {"MINIMAX_API_KEY": "@hermes:api_key"}, "hermes_config_path": str(pin)}
    assert config.resolve_worker_env(cfg) == {"MINIMAX_API_KEY": "sk-pinned-2"}
