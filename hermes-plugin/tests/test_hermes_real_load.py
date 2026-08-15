"""Gold-standard integration: load the plugin the way hermes loads it, with
the REAL PluginManager, REAL PluginContext, and REAL tools registry — fully
isolated in a temp HERMES_HOME (skipped when hermes-agent isn't installed in
this venv)."""

import shutil
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent / "plugin"


@pytest.fixture()
def real_hermes(tmp_path, monkeypatch):
    try:
        from hermes_cli.plugins import PluginManager
    except ImportError as exc:
        pytest.skip(f"hermes-agent not installed in this venv: {exc}")
    from tools.registry import registry

    home = tmp_path / "hermes-home"
    plugin_home = home / "plugins" / "strix"
    plugin_home.mkdir(parents=True)
    for f in PLUGIN_DIR.iterdir():
        if f.is_file():
            shutil.copy2(f, plugin_home / f.name)
    (home / "config.yaml").write_text("plugins:\n  enabled:\n    - strix\n", encoding="utf-8")
    strix_cfg = tmp_path / "strix.yaml"
    strix_cfg.write_text("allowed_targets:\n  - localhost\n", encoding="utf-8")

    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_STRIX_CONFIG", str(strix_cfg))

    mgr = PluginManager()
    mgr.discover_and_load()
    return mgr, registry


def test_real_manager_registers_tools_and_commands(real_hermes):
    mgr, registry = real_hermes
    for name in (
        "strix_scan",
        "strix_status",
        "strix_report",
        "strix_cancel",
        "strix_history",
        "strix_health",
    ):
        assert name in mgr._plugin_tool_names, f"{name} not registered by plugin"
        assert registry.get_toolset_for_tool(name) == "strix"
        schema = registry.get_schema(name)
        assert schema is not None and schema.get("type") == "object"
    for cmd in ("pentest", "strix"):
        assert cmd in mgr._plugin_commands, f"/{cmd} not registered"
        assert callable(mgr._plugin_commands[cmd]["handler"])
    assert any(hook_name == "pre_tool_call" for hook_name in mgr._hooks)
    assert any(hook_name == "transform_tool_result" for hook_name in mgr._hooks)


def test_real_pre_tool_call_hook_blocks(real_hermes):
    mgr, _ = real_hermes
    results = mgr.invoke_hook(
        "pre_tool_call",
        tool_name="strix_scan",
        args={"target": "http://public.example.com", "confirm_authorized": True},
        session_id="sess-1",
    )
    blocks = [r for r in results if isinstance(r, dict) and r.get("action") == "block"]
    assert blocks, "strix hook must block an unauthorized scan through the real manager"
    results_ok = mgr.invoke_hook(
        "pre_tool_call",
        tool_name="strix_scan",
        args={"target": "http://localhost:3000", "confirm_authorized": True},
        session_id="sess-1",
    )
    assert not [r for r in results_ok if isinstance(r, dict) and r.get("action") == "block"]


def test_real_transform_tool_result_reminder(real_hermes):
    mgr, _ = real_hermes
    results = mgr.invoke_hook(
        "transform_tool_result", tool_name="strix_scan", result='{"ok": true}'
    )
    merged = "".join(str(r) for r in results if r is not None)
    assert "do NOT cancel it early" in merged
