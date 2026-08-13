"""ScanManager: scan lifecycle, registry, cancellation, persistence, events."""

import ast
from pathlib import Path

import pytest

from runner import AuthError, ScanManager


class StubBackend:
    """Records whatever the manager hands it and emits canned events."""

    def __init__(self, events=None, outcome=None, fail=False):
        self.calls = []
        self.events = events or [
            ("phase", "waiting"),
            ("vuln", {"id": "vuln-0001", "severity": "high", "title": "T"}),
        ]
        self.outcome = outcome or type("O", (), {"ok": True, "run_dir": "/runs/a",
                                                 "error": None})()
        self.fail = fail

    async def start(self, request, sink, cancel_event):
        self.calls.append(request)
        for kind, payload in self.events:
            sink(kind, payload)
        if self.fail:
            return type("O", (), {"ok": False, "error": "boom", "run_dir": None})()
        return self.outcome


def make_manager(tmp_path, backend=None):
    import config as cfgmod

    cfg = cfgmod.load_config(path=None)
    cfg["allowed_targets"] = ["localhost"]
    cfg["scans_db"] = str(tmp_path / "scans.json")
    return ScanManager(cfg, backend=backend or StubBackend())


async def test_start_runs_to_finished(tmp_path):
    mgr = make_manager(tmp_path)
    rec = await mgr.start(
        target="http://localhost:3000", scan_mode="quick", budget=3.0,
        user_instructions="", chat_id="cli", user_id="u1", confirm=True,
    )
    assert rec.scan_id.startswith("strix-")
    assert mgr.get(rec.scan_id)["status"] == "running"
    await mgr.wait_idle(seconds=3)
    full = mgr.get(rec.scan_id)
    assert full["status"] == "finished"
    assert full["run_dir"] == "/runs/a"
    assert full["by_severity"] == {"high": 1}


async def test_authz_blocks_unauthorized(tmp_path):
    mgr = make_manager(tmp_path)
    with pytest.raises(AuthError) as ei:
        await mgr.start(
            target="http://evil.example.com", scan_mode="quick", budget=1.0,
            user_instructions="", chat_id="cli", user_id="u1", confirm=True,
        )
    assert ei.value.decision.reason == "target_not_allowed"


async def test_authz_requires_confirm(tmp_path):
    mgr = make_manager(tmp_path)
    with pytest.raises(AuthError) as ei:
        await mgr.start(
            target="http://localhost:3000", scan_mode="quick", budget=1.0,
            user_instructions="", chat_id="cli", user_id="u1", confirm=False,
        )
    assert ei.value.decision.reason == "confirm_required"


async def test_failed_scan_recorded(tmp_path):
    mgr = make_manager(tmp_path, backend=StubBackend(fail=True))
    rec = await mgr.start(target="http://localhost:1", scan_mode="quick", budget=1.0,
                          user_instructions="", chat_id="cli", user_id="u1", confirm=True)
    await mgr.wait_idle(seconds=3)
    assert mgr.get(rec.scan_id)["status"] == "failed"
    assert mgr.get(rec.scan_id)["error"] == "boom"


async def test_cancel_sets_cancel_event(tmp_path):
    mgr = make_manager(tmp_path)
    rec = await mgr.start(target="http://localhost:2", scan_mode="quick", budget=1.0,
                          user_instructions="", chat_id="cli", user_id="u1", confirm=True)
    assert mgr.cancel(rec.scan_id) is True
    assert mgr.cancel("nope") is False


async def test_history_and_persistence(tmp_path):
    mgr = make_manager(tmp_path)
    for i in range(3):
        await mgr.start(target=f"http://localhost:3{i}", scan_mode="quick", budget=1.0,
                        user_instructions="", chat_id="cli", user_id="u1", confirm=True)
    await mgr.wait_idle(seconds=3)
    hist = mgr.history(limit=2)
    assert len(hist) == 2 and hist[0]["status"] == "finished"
    # persistence: a fresh manager on the same scans_db sees the records
    mgr2 = make_manager(tmp_path)
    loaded = mgr2.history(limit=10)
    assert len(loaded) == 3
    assert loaded[0]["scan_id"] == hist[0]["scan_id"]


def _module_scope_imports(tree):
    """Return Import nodes at module scope only (function-level lazy imports
    are fine on py3.11 — they never run there)."""
    out = []

    def rec(node):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            out.append(node)
        for child in ast.iter_child_nodes(node):
            rec(child)

    rec(tree)
    return out


def test_no_top_level_strix_imports_in_hermes_modules():
    """hermes runs on py3.11 without strix — nothing the plugin imports at
    module scope may touch strix."""
    plugin_dir = Path(__file__).resolve().parent.parent / "plugin"
    scanned = []
    for fn in sorted(plugin_dir.glob("*.py")):
        if fn.name in {"worker.py", "worker_runtime.py"}:
            continue
        tree = ast.parse(fn.read_text(encoding="utf-8"))
        for node in _module_scope_imports(tree):
            names = [a.name for a in node.names]
            mod = getattr(node, "module", None) or ""
            if any(n in {"strix"} or n.startswith("strix.") for n in names) or \
               mod.startswith("strix"):
                names = [a.name for a in node.names]
                mod = getattr(node, "module", None) or ""
                if any(n in {"strix"} or n.startswith("strix.") for n in names) or \
                   mod.startswith("strix"):
                    raise AssertionError(
                        f"{fn.name}: top-level strix import would break on py3.11 "
                        f"(line {node.lineno})"
                    )
        scanned.append(fn.name)
    assert "runner.py" in scanned and "strix_tools.py" in scanned


async def test_subscribers_get_events(tmp_path):
    mgr = make_manager(tmp_path)
    seen = []
    rec = await mgr.start(target="http://localhost:4", scan_mode="quick", budget=1.0,
                          user_instructions="", chat_id="cli", user_id="u1", confirm=True)
    mgr.subscribe(rec.scan_id, lambda k, p: seen.append((k, p)))
    await mgr.wait_idle(seconds=3)
    kinds = [k for k, _ in seen]
    assert "vuln" in kinds and "finished" in kinds