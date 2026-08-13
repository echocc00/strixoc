"""Plugin registration against a ctx stub — proves register(ctx) declares
exactly the tool/command/hook surface the loader expects.

The plugin package is loaded the same way hermes loads it: a namespaced
module from plugin/__init__.py with submodule_search_locations set.
"""

import importlib.util
import json
import sys
import types
from pathlib import Path

PLUGIN_DIR = Path(__file__).resolve().parent.parent / "plugin"


def load_plugin_like_hermes():
    """Mirror hermes_cli.plugins._load_plugin_module discovery (spec_load)."""
    ns_name = "hermes_plugins__strix_test"
    if ns_name in sys.modules:
        del sys.modules[ns_name]
    spec = importlib.util.spec_from_file_location(
        ns_name, PLUGIN_DIR / "__init__.py",
        submodule_search_locations=[str(PLUGIN_DIR)],
    )
    mod = importlib.util.module_from_spec(spec)
    mod.__package__ = ns_name
    mod.__path__ = [str(PLUGIN_DIR)]
    sys.modules[ns_name] = mod
    spec.loader.exec_module(mod)
    return mod


class StubCtx:
    def __init__(self):
        self.tools = []
        self.commands = []
        self.hooks = []
        self.skills = []

    def register_tool(self, **kw):
        self.tools.append(kw)

    def register_command(self, name=None, **kw):
        self.commands.append({"name": name, **kw})

    def register_hook(self, hook_name, callback):
        self.hooks.append((hook_name, callback))

    def register_skill(self, **kw):
        self.skills.append(kw)


def test_register_declares_surface():
    mod = load_plugin_like_hermes()
    ctx = StubCtx()
    mod.register(ctx)

    names = [t["name"] for t in ctx.tools]
    assert names == [
        "strix_scan", "strix_status", "strix_report",
        "strix_cancel", "strix_history", "strix_health",
        "strix_delegate",
    ]
    for t in ctx.tools:
        assert t["toolset"] == "strix"
        assert t["is_async"] is True
        assert t["schema"]["type"] == "object"
        assert callable(t["handler"])

    scan_schema = ctx.tools[0]["schema"]
    assert "target" in scan_schema["properties"]
    assert "confirm_authorized" in scan_schema["properties"]

    cmds = {c["name"]: c for c in ctx.commands}
    assert "pentest" in cmds and "strix" in cmds
    assert "args_hint" in cmds["pentest"]
    assert callable(cmds["pentest"]["handler"])

    hooks = dict(ctx.hooks)
    assert "pre_tool_call" in hooks and "transform_tool_result" in hooks

    assert len(ctx.skills) == 1
    skill = ctx.skills[0]
    assert skill["name"] == "pentest"
    assert skill["path"].exists() and skill["path"].name == "SKILL.md"


def test_pre_tool_call_hook_blocks_via_ctx():
    """The hook registered by the plugin must block an unauthorized scan —
    end-to-end through the stub ctx (connectivity with authz layer)."""
    mod = load_plugin_like_hermes()
    ctx = StubCtx()
    mod.register(ctx)
    hooks = dict(ctx.hooks)
    block = hooks["pre_tool_call"](
        tool_name="strix_scan",
        args={"target": "http://public.example.com", "confirm_authorized": True},
        session_id="sess-1",
    )
    assert block is not None and block["action"] == "block"
    allowed = hooks["pre_tool_call"](
        tool_name="strix_scan",
        args={"target": "http://localhost:3000", "confirm_authorized": True},
        session_id="sess-1",
    )
    assert allowed is None


def test_handlers_invoke_as_tools_do(monkeypatch):
    """registry calls ``handler(args, **kw)`` — our async handlers must work
    under that exact call shape (validated via asyncio.run on the handler)."""
    import asyncio

    from strix_tools import HANDLERS

    mgr = type("M", (), {
        "get": lambda self, sid: None,
        "list_scans": lambda self, limit=10: [],
    })()
    from strix_tools import _status

    result = asyncio.run(_status({"scan_id": "x"}, session="s"))
    data = json.loads(result)
    assert data["ok"] is False


def test_plugin_yaml_shape():
    data = (PLUGIN_DIR / "plugin.yaml").read_text(encoding="utf-8")
    assert "name: strix" in data
    assert "hooks:" in data
    assert "pre_tool_call" in data and "transform_tool_result" in data