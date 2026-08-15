"""Tools handlers + slash commands against a fake manager."""

import json

import pytest

from plugin import commands
from plugin import strix_tools as tools


class FakeMgr:
    """Minimal stand-in for ScanManager used by tools and commands."""

    def __init__(self, record=None, start_ok=True, authz_reason=None):
        self.record = record or {
            "scan_id": "strix-abc123",
            "status": "running",
            "target": "http://localhost:3000",
            "scan_mode": "quick",
            "budget": 3.0,
            "created_at": "2026-08-13T00:00:00+00:00",
            "updated_at": "2026-08-13T00:00:00+00:00",
            "phase": "",
            "vuln_count": 0,
            "by_severity": {},
            "error": None,
            "run_dir": None,
        }
        self.start_ok = start_ok
        self.authz_reason = authz_reason
        self.started = {}

    async def start(self, target, **kw):
        if not self.start_ok:
            from plugin.authz import AuthDecision
            from plugin.runner import AuthError

            raise AuthError(AuthDecision(False, self.authz_reason or "confirm_required"), "blocked")
        self.started = {"target": target, **kw}
        rec = type("R", (), dict(self.record))()
        rec.scan_id = self.record["scan_id"]
        return rec

    def authorize_or_raise(self, *, target, chat_id, user_id, confirm):
        if not self.start_ok:
            from plugin.authz import AuthDecision
            from plugin.runner import AuthError

            raise AuthError(AuthDecision(False, self.authz_reason or "confirm_required"), "blocked")

    def get(self, scan_id):
        return self.record if scan_id == self.record["scan_id"] else None

    def list_scans(self, limit=10):
        return [self.record]

    def history(self, limit=10):
        return [self.record]

    def cancel(self, scan_id):
        return scan_id == self.record["scan_id"]

    def health(self):
        return {
            "backend": "fake",
            "running_scans": [self.record],
            "worker_python_configured": True,
            "allowed_targets": ["localhost"],
            "max_budget_default": 5.0,
            "max_budget_cap": 25.0,
        }


@pytest.fixture(autouse=True)
def fake_manager(monkeypatch):
    mgr = FakeMgr()
    monkeypatch.setattr(tools, "get_manager", lambda cfg=None: mgr)
    monkeypatch.setattr(commands, "get_manager", lambda cfg=None: mgr)
    return mgr


# --- tools ----------------------------------------------------------------


async def test_strix_scan_ok():
    out = json.loads(
        await tools.HANDLERS["_scan"](
            {
                "target": "http://localhost:3000",
                "confirm_authorized": True,
                "scan_mode": "standard",
                "max_budget_usd": 3.0,
            },
            chat_id="cli",
        )
    )
    assert out["ok"] is True and out["scan_id"] == "strix-abc123"
    assert out["status"] == "running"


async def test_strix_scan_missing_target():
    out = json.loads(await tools.HANDLERS["_scan"]({"confirm_authorized": True}))
    assert out["ok"] is False and "required" in out["error"]


async def test_strix_scan_authz_block(fake_manager):
    fake_manager.start_ok = False
    fake_manager.authz_reason = "confirm_required"
    out = json.loads(
        await tools.HANDLERS["_scan"](
            {"target": "http://evil.example.com", "confirm_authorized": True}
        )
    )
    assert out["ok"] is False
    assert out["decision"] == "confirm_required"
    assert "confirm_authorized" in out["fix"]


async def test_strix_status_unknown_scan():
    out = json.loads(await tools.HANDLERS["_status"]({"scan_id": "nope"}))
    assert out["ok"] is False


async def test_strix_report_summary_with_run_dir(tmp_path, fake_manager):
    run_dir = tmp_path / "runs" / "abc"
    run_dir.mkdir(parents=True)
    (run_dir / "penetration_test_report.md").write_text("# S\nbody", encoding="utf-8")
    (run_dir / "vulnerabilities.json").write_text(
        json.dumps([{"id": "v1", "severity": "high"}]), encoding="utf-8"
    )
    fake_manager.record = dict(fake_manager.record, status="finished", run_dir=str(run_dir))
    out = json.loads(await tools.HANDLERS["_report"]({"scan_id": "strix-abc123"}))
    assert out["ok"] is True
    assert out["report_exists"] is True and out["vuln_count"] == 1
    assert out["by_severity"] == {"high": 1}
    raw = json.loads(
        await tools.HANDLERS["_report"](
            {"scan_id": "strix-abc123", "section": "report_md", "max_chars": 50}
        )
    )
    assert raw["ok"] is True and "body" in raw["content"]


async def test_strix_report_no_run_dir():
    out = json.loads(await tools.HANDLERS["_report"]({"scan_id": "strix-abc123"}))
    assert out["ok"] is False


async def test_strix_cancel_and_history():
    out = json.loads(await tools.HANDLERS["_cancel"]({"scan_id": "strix-abc123"}))
    assert out["cancelled"] is True
    hist = json.loads(await tools.HANDLERS["_history"]({"limit": 5}))
    assert hist["ok"] is True and hist["scans"][0]["scan_id"] == "strix-abc123"


async def test_strix_health():
    out = json.loads(await tools.HANDLERS["_health"]({}))
    assert out["ok"] is True and out["backend"] == "fake"


# --- commands -------------------------------------------------------------


async def test_pentest_parse_and_start(fake_manager):
    mgr = fake_manager
    text = await commands.handle_pentest(
        "http://localhost:3000 --mode deep --budget 4 --confirm-authorized"
    )
    assert "strix-abc123" in text and "🔒" in text
    assert mgr.started["target"] == "http://localhost:3000"
    assert mgr.started["scan_mode"] == "deep"
    assert mgr.started["budget"] == 4.0
    assert mgr.started["confirm"] is True


async def test_pentest_blocked(fake_manager):
    fake_manager.start_ok = False
    fake_manager.authz_reason = "confirm_required"
    text = await commands.handle_pentest("http://localhost:3000")
    assert "blocked" in text.lower() and "confirm" in text.lower()


async def test_pentest_usage_errors():
    assert "usage" in (await commands.handle_pentest(""))
    assert "usage" in (await commands.handle_pentest("--mode quick"))
    assert "usage" in (await commands.handle_pentest("http://x --mode turbo"))
    assert "usage" in (await commands.handle_pentest("http://x --budget ten"))


async def test_strix_command_state():
    text = await commands.handle_strix("")
    assert "strix-abc123" in text and "backend: fake" in text
    hist = await commands.handle_strix("history")
    assert "Recent scans" in hist
