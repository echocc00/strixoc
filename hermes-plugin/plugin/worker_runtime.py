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
from typing import Any, Callable

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
    from strix.report.state import ReportState, set_global_report_state
    from strix.core.runner import run_strix_scan

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
    try:
        scan_task = asyncio.ensure_future(
            run_strix_scan(
                scan_config=scan_config,
                scan_id=scan_id,
                image=request.get("image") or "",
                interactive=False,
                max_budget_usd=request.get("max_budget_usd"),
                max_turns=request.get("max_turns") or 500,
                event_sink=on_event_sink,
                status_sink=on_status_sink,
                cleanup_on_exit=True,
            )
        )
        cancel_proxy = asyncio.ensure_future(cancel_event.wait())
        done, _ = await asyncio.wait(
            {scan_task, cancel_proxy}, return_when=asyncio.FIRST_COMPLETED
        )
        if cancel_proxy in done:
            scan_task.cancel()
        await scan_task
        run_dir = str(state.get_run_dir())
        summary = read_run_artifacts(run_dir)
        emit({"type": "finished", "run_dir": run_dir, **summary})
        return {"ok": True, "run_dir": run_dir}
    except asyncio.CancelledError:
        run_dir = str(state.get_run_dir())
        emit({"type": "cancelled", "run_dir": run_dir})
        return {"ok": False, "error": "cancelled"}
    except Exception as exc:  # noqa: BLE001
        run_dir = str(state.get_run_dir())
        emit({"type": "failed", "run_dir": run_dir, "error": f"{type(exc).__name__}: {exc}"})
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        with _suppress(asyncio.CancelledError):
            try:
                result = state.cleanup()
                if asyncio.iscoroutine(result):
                    asyncio.get_event_loop().run_until_complete(result)
            except Exception:  # noqa: BLE001
                pass


class _suppress:
    def __init__(self, *excs):
        self._excs = excs

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return exc_type is not None and issubclass(exc_type, self._excs)