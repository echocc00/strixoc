"""The MPI-proving test: REAL strix ReportState + REAL artifact writers,
with ONLY run_strix_scan stubbed out.  Simulates exactly what the worker
does between start and finish, and what finish_scan does at the end.

Proves IMPL_PLAN §3.2: 自建 ReportState -> set_global_report_state ->
Strix agent calls add_vulnerability_report / finish_scan -> artifacts land
in strix_runs/<scan_id>/ and our reader picks them up.
"""

import asyncio
import json
import sys
from pathlib import Path

import pytest

strix = pytest.importorskip("strix", reason="strix not installed (requires py>=3.12)")
# fresh import of the worker runtime so it picks up our stubbing below
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "plugin"))
import worker_runtime

from plugin.backends import read_run_artifacts


@pytest.fixture()
def end_to_end_request(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = build_scan_config_local(
        "http://localhost:3000",
        "quick",
        "sc-e2e",
        "sc-e2e",
        user_instructions="authorized local test",
    )
    return {"scan_id": "sc-e2e", "scan_config": cfg, "image": "", "max_budget_usd": 5.0}


def build_scan_config_local(target, scan_mode, run_name, scan_id, user_instructions=""):
    return {
        "scan_id": scan_id,
        "targets": [{"type": "web_application", "details": {"target_url": target}}],
        "user_instructions": user_instructions,
        "run_name": run_name,
        "diff_scope": {"active": False},
        "scan_mode": scan_mode,
        "non_interactive": True,
        "local_sources": [],
        "scope_mode": "auto",
        "diff_base": None,
        "resume_instruction": "",
    }


def test_mvp_artifact_loop(end_to_end_request, tmp_path, monkeypatch, capsys):
    """Full worker-runtime loop against real strix with a stubbed runner.

    The stubbed run_strix_scan mimics the real Strix agent: it files one
    vulnerability (via the global ReportState, which is what the real
    create_vulnerability_report tool does) and then finishes the scan
    (what finish_scan does), all WITHOUT docker or an LLM.
    """
    from strix.core import runner as runner_mod

    calls = {"scan": 0}

    async def fake_run_strix_scan(**kw):
        calls["scan"] += 1
        if callable(kw.get("status_sink")):
            kw["status_sink"]("sandbox ready")  # what the real runner does
        from strix.report.state import get_global_report_state

        state = get_global_report_state()
        assert state is not None, "run_strix_scan must see the plugin-created ReportState"
        # --- what the real agent does via create_vulnerability_report ---
        state.add_vulnerability_report(
            title="SQL Injection in login",
            severity="critical",
            description="Parameterized query bypass in /login",
            impact="Full DB read",
            remediation_steps="Use parameterized queries",
            endpoint="/login",
            method="POST",
            cwe="CWE-89",
        )
        # --- what the real finish_scan tool does ---
        state.update_scan_final_fields(
            executive_summary="One critical finding.",
            methodology="OWASP WSTG.",
            technical_analysis="SQLi.",
            recommendations="Fix queries.",
        )
        return None

    monkeypatch.setattr(runner_mod, "run_strix_scan", fake_run_strix_scan)

    req = end_to_end_request
    emitted = []

    async def run():
        return await worker_runtime.execute(req, emit=emitted.append, cancel_event=asyncio.Event())

    rc = asyncio.run(run())
    assert rc["ok"] is True

    kinds = [ev["type"] for ev in emitted]
    assert "phase" in kinds and "finished" in kinds
    finish = next(ev for ev in emitted if ev["type"] == "finished")

    run_dir = Path(finish["run_dir"])
    assert run_dir == tmp_path / "strix_runs" / req["scan_id"]

    md = run_dir / "penetration_test_report.md"
    assert md.exists(), "finish_scan must persist penetration_test_report.md"
    text = md.read_text(encoding="utf-8")
    assert "Executive Summary" in text and "One critical finding." in text

    vulns = json.loads((run_dir / "vulnerabilities.json").read_text(encoding="utf-8"))
    assert len(vulns) == 1 and vulns[0]["severity"] == "critical"

    vuln_md = run_dir / "vulnerabilities" / "vuln-0001.md"
    assert vuln_md.exists()

    sarif = run_dir / "findings.sarif"
    assert sarif.exists()
    sarif_doc = json.loads(sarif.read_text(encoding="utf-8"))
    assert sarif_doc["version"] == "2.1.0"

    run_json = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    assert run_json["status"] == "completed"

    # our reader summarizes the artifacts
    summary = read_run_artifacts(run_dir)
    assert summary["vuln_count"] == 1
    assert summary["by_severity"] == {"critical": 1}
    assert summary["report_exists"] is True


class FakeVulnCallback:
    def __init__(self):
        self.reports = []

    def __call__(self, report):
        self.reports.append(report)


def test_worker_vuln_callback_realtime(tmp_path, monkeypatch):
    """vulnerability_found_callback must stream reports during the scan."""
    from strix.core import runner as runner_mod

    async def fake_run_strix_scan(**kw):
        if callable(kw.get("status_sink")):
            kw["status_sink"]("scanning")
        from strix.report.state import get_global_report_state

        get_global_report_state().add_vulnerability_report(
            title="XSS", severity="medium", description="Reflected"
        )
        return None

    monkeypatch.setattr(runner_mod, "run_strix_scan", fake_run_strix_scan)
    cfg = build_scan_config_local("http://localhost:1", "quick", "sc-x", "sc-x")
    req = {"scan_id": "sc-x", "scan_config": cfg, "image": "whatever", "max_budget_usd": 1.0}
    emitted = []
    rc = asyncio.run(worker_runtime.execute(req, emit=emitted.append, cancel_event=asyncio.Event()))
    assert rc["ok"]
    vulns = [ev for ev in emitted if ev["type"] == "vuln"]
    assert len(vulns) == 1
    assert vulns[0]["report"]["title"] == "XSS"
    assert "phase" in [ev["type"] for ev in emitted]


def test_worker_synthesizes_terminal_report_when_finish_scan_never_called(tmp_path, monkeypatch):
    """Real-golden-path behavior (2026-08-13, MiniMax): the root agent often
    ends with a text turn instead of calling finish_scan -> no executive
    report and run.json stuck at 'running'. The worker must synthesize a
    minimal terminal report so artifacts are always complete."""
    monkeypatch.chdir(tmp_path)
    from strix.core import runner as runner_mod

    async def fake_run_strix_scan(**kw):
        if callable(kw.get("status_sink")):
            kw["status_sink"]("scanning")
        from strix.report.state import get_global_report_state

        get_global_report_state().add_vulnerability_report(
            title="AuthZ gap", severity="high", description="BFLA", cwe="CWE-862"
        )
        # NOTE: no update_scan_final_fields — simulates the text-turn ending
        return None

    monkeypatch.setattr(runner_mod, "run_strix_scan", fake_run_strix_scan)
    cfg = build_scan_config_local("http://localhost:1", "quick", "sc-synth", "sc-synth")
    req = {"scan_id": "sc-synth", "scan_config": cfg, "image": "", "max_budget_usd": 1.0}
    emitted = []
    rc = asyncio.run(worker_runtime.execute(req, emit=emitted.append, cancel_event=asyncio.Event()))
    assert rc["ok"]
    run_dir = Path(tmp_path) / "strix_runs" / "sc-synth"
    md = run_dir / "penetration_test_report.md"
    assert md.exists(), "worker must synthesize the executive report"
    assert "high" in md.read_text(encoding="utf-8").lower()
    run_json = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    assert run_json["status"] == "completed"
    finish = next(ev for ev in emitted if ev["type"] == "finished")
    assert finish["vuln_count"] == 1 and finish["by_severity"] == {"high": 1}


def test_worker_resolves_image_from_settings_when_request_empty(tmp_path, monkeypatch):
    """Golden-path fix (2026-08-13): the plugin's scan request carried no
    image, and the worker passed image='' to run_strix_scan which hung in
    sandbox bring-up. The worker must fall back to its own strix settings
    (~/.strix/cli-config.json runtime.image)."""
    import strix.config.loader as loader_mod
    from strix.core import runner as runner_mod

    captured = {}

    async def fake_run_strix_scan(**kw):
        captured["image"] = kw.get("image")
        if callable(kw.get("status_sink")):
            kw["status_sink"]("ok")
        from strix.report.state import get_global_report_state

        get_global_report_state().update_scan_final_fields(
            executive_summary="e", methodology="m", technical_analysis="t", recommendations="r"
        )
        return None

    class FakeSettings:
        runtime = type("R", (), {"image": "ghcr.io/usestrix/strix-sandbox:1.3.0"})()

    monkeypatch.setattr(runner_mod, "run_strix_scan", fake_run_strix_scan)
    monkeypatch.setattr(loader_mod, "load_settings", lambda: FakeSettings())

    cfg = build_scan_config_local("http://localhost:1", "quick", "sc-img", "sc-img")
    req = {"scan_id": "sc-img", "scan_config": cfg, "image": "", "max_budget_usd": 1.0}
    emitted = []
    rc = asyncio.run(worker_runtime.execute(req, emit=emitted.append, cancel_event=asyncio.Event()))
    assert rc["ok"]
    assert captured["image"] == "ghcr.io/usestrix/strix-sandbox:1.3.0"
