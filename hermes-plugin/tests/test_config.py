"""Config loading: defaults, file merge, path resolution, env override."""

from pathlib import Path

import config as cfgmod


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