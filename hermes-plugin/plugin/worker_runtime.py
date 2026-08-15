"""Worker-side scan runtime: the ReportState dance (IMPL_PLAN §3.2) around
``run_strix_scan``, streamed to the parent via ``emit``.

This module must stay free of sibling-package imports (it runs as a plain
script inside the strix Python-3.12 venv) and must only import strix
lazily — the plugin side of the deployment (hermes on Python 3.11) never
executes this module.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from typing import Any

Emit = Callable[[dict[str, Any]], None]


async def execute(request: dict, *, emit: Emit, cancel_event: asyncio.Event) -> dict[str, Any]:
    """Run one scan end-to-end inside the worker process.

    Key ordering (from strix/interface/cli.py:101-137 — the only place the
    shipped CLI builds the ReportState):

        1. ReportState(scan_id)                    -> artifacts under cwd/strix_runs/<id>
        2. set_scan_config(scan_config) + save_run_data()
        3. vulnerability_found_callback = streaming sink   (real-time findings)
        4. set_global_report_state(state)
        5. await run_strix_scan(...)               (agent talks to finish_scan tool)
        6. finally: state.cleanup()                (write run.json terminal state)

    Without step 4, finish_scan prints "results not persisted" and NO report
    files are written (strix/tools/finish/tool.py).
    """
    from backends import read_run_artifacts  # local import: worker venv has plugin dir on path

    scan_id = request["scan_id"]
    scan_config = request["scan_config"]
    from strix.core.runner import run_strix_scan
    from strix.report.state import ReportState, set_global_report_state

    # The plugin's scan request may carry no sandbox image; fall back to the
    # worker's own strix settings (~/.strix/cli-config.json runtime.image) —
    # the same resolution the strix CLI uses.
    image = request.get("image") or ""
    if not image:
        try:
            from strix.config.loader import load_settings

            image = load_settings().runtime.image or ""
        except Exception:
            image = ""

    state = ReportState(scan_id)
    state.hydrate_from_run_dir()  # idempotent on fresh runs; enables resume
    state.set_scan_config(scan_config)
    state.save_run_data()
    state.vulnerability_found_callback = lambda rep: emit({"type": "vuln", "report": rep})
    set_global_report_state(state)

    _last_emitted: dict[str, float] = {}

    def on_status_sink(phase: str) -> None:
        emit({"type": "phase", "phase": phase})

    def on_event_sink(agent_id: str, event: Any) -> None:
        now = time.monotonic()
        if now - _last_emitted.get(agent_id, 0.0) < 2.0:
            return
        _last_emitted[agent_id] = now
        usage = event.get("usage") if isinstance(event, dict) else None
        emit({"type": "event", "agent_id": agent_id, "event": {"usage": usage}})

    run_dir: str | None = None
    heartbeat = asyncio.ensure_future(_heartbeat_loop(emit))
    try:
        scan_task = asyncio.ensure_future(
            run_strix_scan(
                scan_config=scan_config,
                scan_id=scan_id,
                image=image,
                interactive=False,
                max_budget_usd=request.get("max_budget_usd"),
                max_turns=request.get("max_turns") or 500,
                event_sink=on_event_sink,
                status_sink=on_status_sink,
                cleanup_on_exit=True,
            )
        )
        cancel_proxy = asyncio.ensure_future(cancel_event.wait())
        done, _ = await asyncio.wait({scan_task, cancel_proxy}, return_when=asyncio.FIRST_COMPLETED)
        if cancel_proxy in done:
            scan_task.cancel()
        await scan_task
        run_dir = str(state.get_run_dir())
        _ensure_terminal_report(state)
        summary = read_run_artifacts(run_dir)
        emit({"type": "finished", "run_dir": run_dir, **summary})
        return {"ok": True, "run_dir": run_dir}
    except asyncio.CancelledError:
        run_dir = str(state.get_run_dir())
        emit({"type": "cancelled", "run_dir": run_dir})
        return {"ok": False, "error": "cancelled"}
    except Exception as exc:
        run_dir = str(state.get_run_dir())
        emit({"type": "failed", "run_dir": run_dir, "error": f"{type(exc).__name__}: {exc}"})
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        heartbeat.cancel()
        with _suppress(asyncio.CancelledError):
            try:
                result = state.cleanup()
                if asyncio.iscoroutine(result):
                    asyncio.get_event_loop().run_until_complete(result)
            except Exception:
                pass


async def _heartbeat_loop(emit: Emit, interval: float = 30.0) -> None:
    """Liveness beacon so the parent can tell a busy worker from a dead one
    (long scans emit no phase/event traffic for minutes at a time)."""
    while True:
        await asyncio.sleep(interval)
        emit({"type": "heartbeat", "ts": round(time.time(), 3)})


class _suppress:
    def __init__(self, *excs):
        self._excs = excs

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return exc_type is not None and issubclass(exc_type, self._excs)


def _ensure_terminal_report(state) -> None:
    """If the root agent ended without calling finish_scan (a recurring
    text-turn ending on some models), synthesize the terminal report so the
    artifact set is complete: penetration_test_report.md + run.json
    status=completed."""
    if getattr(state, "final_scan_result", None) is not None:
        return
    reports = list(getattr(state, "vulnerability_reports", []) or [])
    sev: dict[str, int] = {}
    for r in reports:
        s = str(r.get("severity", "info")).lower()
        sev[s] = sev.get(s, 0) + 1
    summary = (
        "Scan completed without an agent-authored final report. "
        f"Vulnerabilities filed: {len(reports)} "
        f"({', '.join(f'{k}={v}' for k, v in sorted(sev.items())) or 'none'})."
    )
    state.update_scan_final_fields(
        executive_summary=summary,
        methodology="Strix autonomous scan (quick/standard/deep); see vulnerabilities.json "
        "and findings.sarif for the authoritative evidence.",
        technical_analysis=summary,
        recommendations="Review each finding in vulnerabilities.json; remediation steps are "
        "attached per finding where available.",
    )
