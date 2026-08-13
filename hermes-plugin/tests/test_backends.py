"""scan_config builder + in-process/worker backends (protocol, cancel, python resolution)."""

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

from backends import (
    BackendConfigError,
    InProcessBackend,
    RunOutcome,
    WorkerBackend,
    build_scan_config,
    read_run_artifacts,
)


# --- build_scan_config ------------------------------------------------------


def test_scan_config_web_url():
    c = build_scan_config(
        target="http://app.example.com:8080/x", scan_mode="standard",
        user_instructions="only /api", run_name="r1", scan_id="sc-1",
    )
    assert c["targets"] == [
        {"type": "web_application", "details": {"target_url": "http://app.example.com:8080/x"}}
    ]
    assert c["scan_mode"] == "standard"
    assert c["non_interactive"] is True
    assert c["run_name"] == "r1" and c["scan_id"] == "sc-1"
    assert c["user_instructions"] == "only /api"
    assert c["scope_mode"] == "auto" and c["diff_scope"] == {"active": False}


def test_scan_config_ip_target():
    c = build_scan_config(target="10.20.30.40", scan_mode="quick", run_name="r2", scan_id="sc-2")
    assert c["targets"] == [{"type": "ip_address", "details": {"target_ip": "10.20.30.40"}}]


def test_scan_config_bad_mode_falls_back_to_quick():
    c = build_scan_config(target="http://a.test", scan_mode="ludicrous", run_name="r3", scan_id="sc-3")
    assert c["scan_mode"] == "quick"


# --- read_run_artifacts -----------------------------------------------------


def test_read_run_artifacts_on_missing_dir(tmp_path):
    out = read_run_artifacts(tmp_path / "nope")
    assert out["vuln_count"] == 0
    assert out["report_exists"] is False


def test_read_run_artifacts_parses_real_files(tmp_path):
    (tmp_path / "penetration_test_report.md").write_text("# S\nsummary body", encoding="utf-8")
    (tmp_path / "vulnerabilities.json").write_text(
        json.dumps([{"id": "v1", "severity": "critical"}, {"id": "v2", "severity": "low"}]),
        encoding="utf-8",
    )
    out = read_run_artifacts(tmp_path)
    assert out["report_exists"] is True
    assert out["vuln_count"] == 2
    assert out["by_severity"] == {"critical": 1, "low": 1}
    assert "summary body" in out["report_head"]


# --- InProcessBackend wiring (fake strix modules) ---------------------------


class FakeReportState:
    def __init__(self, run_name=None):
        self.run_name = run_name
        self.calls = []
        self.vulnerability_found_callback = None

    def set_scan_config(self, cfg):
        self.calls.append(("set_scan_config", cfg))

    def save_run_data(self, **kw):
        self.calls.append(("save_run_data", kw))

    def update_scan_final_fields(self, **kw):
        self.calls.append(("update_scan_final_fields", kw))

    def get_run_dir(self):
        return self.run_name

    def cleanup(self, status="stopped"):
        self.calls.append(("cleanup", status))


class FakeStrix:
    def __init__(self):
        self.global_state = None
        self.run_kwargs = None
        self.raise_in_scan = None
        self.states = []

    def install(self):
        self._mods = {}

        def make_state():
            name = "strix.report.state"
            m = type(sys)(name)
            inst = FakeReportState()
            self.states.append(inst)
            m.ReportState = lambda run_name=None: inst
            m.get_global_report_state = lambda: self.global_state
            m.set_global_report_state = lambda s: setattr(self, "global_state", s)
            self._mods[name] = m

        def make_runner():
            name = "strix.core.runner"

            async def run_strix_scan(**kw):
                self.run_kwargs = kw
                if self.raise_in_scan:
                    raise self.raise_in_scan
                st = self.global_state
                st.update_scan_final_fields(e=1)
                return None

            m = type(sys)(name)
            m.run_strix_scan = run_strix_scan
            self._mods[name] = m

        make_state()
        make_runner()
        for name, m in self._mods.items():
            sys.modules[name] = m

    def uninstall(self):
        for name in list(self._mods):
            sys.modules.pop(name, None)


@pytest.fixture()
def fake_strix():
    fs = FakeStrix()
    fs.install()
    yield fs
    fs.uninstall()


def make_request():
    cfg = build_scan_config(target="http://localhost:3000", run_name="sc-a", scan_id="sc-a")
    return dict(scan_id="sc-a", scan_config=cfg, image="kali:latest", max_budget_usd=5.0)


async def test_inprocess_wiring_and_artifact_outcome(fake_strix):
    events = []
    backend = InProcessBackend()
    outcome = await backend.start(
        make_request(), sink=lambda k, p: events.append((k, p)),
        cancel_event=asyncio.Event(),
    )
    assert outcome.ok
    state = fake_strix.states[0]
    assert any(c[0] == "set_scan_config" for c in state.calls)
    assert any(c[0] == "save_run_data" for c in state.calls)
    assert state.vulnerability_found_callback is not None
    assert fake_strix.global_state is state
    assert state.calls[-1][0] == "cleanup"
    kw = fake_strix.run_kwargs
    assert kw["scan_config"]["scan_id"] == "sc-a"
    assert kw["image"] == "kali:latest"
    assert kw["interactive"] is False
    assert kw["cleanup_on_exit"] is True
    assert kw["max_budget_usd"] == 5.0
    assert callable(kw["status_sink"]) and callable(kw["event_sink"])


async def test_inprocess_cleanup_on_scan_error(fake_strix):
    fake_strix.raise_in_scan = RuntimeError("sandbox died")
    backend = InProcessBackend()
    outcome = await backend.start(
        make_request(), sink=lambda k, p: None, cancel_event=asyncio.Event()
    )
    assert not outcome.ok
    assert "sandbox died" in (outcome.error or "")
    assert fake_strix.states[0].calls[-1][0] == "cleanup"


async def test_inprocess_cancel_stops_scan(fake_strix):
    started = asyncio.Event()

    async def run_strix_scan_blocking(**kw):
        started.set()
        await asyncio.sleep(30)

    fake_strix._mods["strix.core.runner"].run_strix_scan = run_strix_scan_blocking
    backend = InProcessBackend()
    cancel = asyncio.Event()
    task = asyncio.ensure_future(
        backend.start(make_request(), sink=lambda k, p: None, cancel_event=cancel)
    )
    await started.wait()
    cancel.set()
    outcome = await asyncio.wait_for(task, 5)
    assert not outcome.ok
    assert fake_strix.states[0].calls[-1][0] == "cleanup"


# --- WorkerBackend ----------------------------------------------------------


FAKE_WORKER_SOURCE = """\
import json, sys
for line in sys.stdin:
    pass
for ev in json.loads(open(__import__("sys").argv[1], encoding="utf-8").read()):
    print(json.dumps(ev, ensure_ascii=False), flush=True)
print(json.dumps({"type": "finished", "run_dir": "/runs/x", "vuln_count": 1,
                  "report_exists": True, "report_head": "head"}), flush=True)
"""


def write_fake_worker(tmp_path, events):
    p = tmp_path / "fake_worker.py"
    p.write_text(
        "import json, sys\n"
        f"events = {json.dumps(events)}\n"
        "for ev in events:\n    print(json.dumps(ev), flush=True)\n"
        "print(json.dumps({'type':'finished','run_dir':'/runs/x','vuln_count':2,"
        "'report_exists':True,'report_head':'ok'}), flush=True)\n",
        encoding="utf-8",
    )
    return p


def test_worker_python_resolution(monkeypatch):
    with pytest.raises(BackendConfigError):
        WorkerBackend(worker_python="")._resolve_python()
    b = WorkerBackend(worker_python="/opt/py312/bin/python")
    assert b._resolve_python() == "/opt/py312/bin/python"
    monkeypatch.setenv("STRIX_WORKER_PYTHON", "/env/py")
    assert WorkerBackend(worker_python="")._resolve_python() == "/env/py"


async def test_worker_protocol_events(tmp_path):
    events = [
        {"type": "phase", "phase": "waiting"},
        {"type": "vuln", "report": {"id": "vuln-0001", "severity": "high"}},
        {"type": "event", "agent_id": "root", "usage": {"total_tokens": 10}},
    ]
    script = write_fake_worker(tmp_path, events)
    got = []
    backend = WorkerBackend(worker_python=sys.executable, worker_path=str(script))
    outcome = await backend.start(
        make_request(), sink=lambda k, p: got.append((k, p)), cancel_event=asyncio.Event()
    )
    kinds = [k for k, _ in got]
    assert kinds == ["phase", "vuln", "event", "finished"]
    assert got[0][1] == "waiting"
    assert got[1][1]["severity"] == "high"
    assert outcome.ok
    assert outcome.run_dir == "/runs/x"


async def test_worker_cancel_message_delivered(tmp_path):
    script = tmp_path / "cancel_worker.py"
    script.write_text(
        "import sys, json\n"
        "line = sys.stdin.readline()\n"
        "print(json.dumps({'type':'phase','phase':'cancel-msg:'+line.strip()}), flush=True)\n"
        "print(json.dumps({'type':'finished','run_dir':'/r/c'}), flush=True)\n",
        encoding="utf-8",
    )
    cancel = asyncio.Event()
    backend = WorkerBackend(worker_python=sys.executable, worker_path=str(script))
    got = []

    async def main():
        t = asyncio.ensure_future(
            backend.start(make_request(), sink=lambda k, p: got.append((k, p)), cancel_event=cancel)
        )
        await asyncio.sleep(1.0)  # worker is up and blocked on stdin
        cancel.set()
        return await asyncio.wait_for(t, 5)

    outcome = await main()
    msgs = [p for k, p in got if k == "phase"]
    assert outcome.ok
    assert msgs and "cancel-msg:" in msgs[0]
    assert json.loads(msgs[0].split("cancel-msg:", 1)[1])["type"] == "cancel"


async def test_worker_eof_without_finished_is_error(tmp_path):
    script = tmp_path / "bye.py"
    script.write_text("import sys\nsys.exit(3)\n", encoding="utf-8")
    backend = WorkerBackend(worker_python=sys.executable, worker_path=str(script))
    outcome = await backend.start(
        make_request(), sink=lambda k, p: None, cancel_event=asyncio.Event()
    )
    assert not outcome.ok
    assert outcome.error