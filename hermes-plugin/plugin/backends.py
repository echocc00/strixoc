"""Scan backends: turn a ScanRequest into a finished run with artifacts.

Two implementations of the same interface:

- ``InProcessBackend``  — imports strix in-process (needs Python >= 3.12 and
  strix-agent in the environment).  Used for local dev/tests and future
  hermes-on-3.12 deployments.
- ``WorkerBackend``    — spawns the plugin's ``worker.py`` in a dedicated
  Python 3.12 venv (the strix environment) and streams events back over a
  JSON-lines protocol on stdout.  This is the production path: hermes runs
  on Python 3.11 while strix requires >= 3.12, and the worker process keeps
  the docker socket contained.

Per IMPL_PLAN §3.2 the caller must build-and-set the ReportState BEFORE
``run_strix_scan`` runs; otherwise ``finish_scan`` warns "not persisted"
and no report files land on disk.  Both backends do that dance.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

EventSink = Callable[[str, Any], None]  # ("phase"|"vuln"|"event"|"log"|"finished", payload)

VALID_SCAN_MODES = ("quick", "standard", "deep")
DEFAULT_MAX_TURNS = 500


class BackendConfigError(Exception):
    """Worker/python not resolvable — operator must set config."""


class BackendRuntimeError(Exception):
    """Scan failed at the backend level."""


@dataclass
class RunOutcome:
    ok: bool
    run_dir: str | None = None
    error: str | None = None


# ---------------------------------------------------------------------------
# scan_config construction (mirrors strix/interface/cli.py:87-99)
# ---------------------------------------------------------------------------


def build_scan_config(
    *,
    target: str,
    scan_mode: str = "quick",
    user_instructions: str = "",
    run_name: str,
    scan_id: str,
) -> dict[str, Any]:
    mode = scan_mode if scan_mode in VALID_SCAN_MODES else "quick"
    t = target.strip()
    proto, host = _split_proto_host(t)
    if proto in ("http", "https"):
        target_entry = {"type": "web_application", "details": {"target_url": t}}
    elif _looks_like_ip(host):
        target_entry = {"type": "ip_address", "details": {"target_ip": host}}
    else:
        target_entry = {"type": "web_application", "details": {"target_url": t}}
    return {
        "scan_id": scan_id,
        "targets": [target_entry],
        "user_instructions": user_instructions,
        "run_name": run_name,
        "diff_scope": {"active": False},
        "scan_mode": mode,
        "non_interactive": True,
        "local_sources": [],
        "scope_mode": "auto",
        "diff_base": None,
        "resume_instruction": "",
    }


def _split_proto_host(target: str) -> tuple[str | None, str]:
    if "://" in target:
        proto, rest = target.split("://", 1)
        return proto.lower(), rest.split("/", 1)[0].split(":", 1)[0]
    return None, target.split("/", 1)[0].split(":", 1)[0]


def _looks_like_ip(host: str) -> bool:
    import ipaddress

    h = host.strip("[]")
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# artifact reading (worker side files the artifacts; this summarizes them)
# ---------------------------------------------------------------------------


def read_run_artifacts(run_dir: Path | str) -> dict[str, Any]:
    """Summarize a finished run dir without pulling the whole files in."""
    d = Path(run_dir)
    out: dict[str, Any] = {
        "run_dir": str(d),
        "report_exists": False,
        "report_head": "",
        "vuln_count": 0,
        "by_severity": {},
        "sarif_exists": False,
        "status": "unknown",
    }
    md = d / "penetration_test_report.md"
    if md.exists():
        text = md.read_text(encoding="utf-8", errors="replace")
        out["report_exists"] = True
        out["report_head"] = text[:800]
    vulns = d / "vulnerabilities.json"
    if vulns.exists():
        try:
            data = json.loads(vulns.read_text(encoding="utf-8"))
            if isinstance(data, list):
                out["vuln_count"] = len(data)
                sev: dict[str, int] = {}
                for v in data:
                    s = str(v.get("severity", "info")).lower()
                    sev[s] = sev.get(s, 0) + 1
                out["by_severity"] = sev
        except (OSError, json.JSONDecodeError):
            pass
    if (d / "findings.sarif").exists():
        out["sarif_exists"] = True
    run_json = d / "run.json"
    if run_json.exists():
        try:
            out["status"] = str(
                json.loads(run_json.read_text(encoding="utf-8")).get("status", "unknown")
            )
        except (OSError, json.JSONDecodeError):
            pass
    return out


# ---------------------------------------------------------------------------
# InProcessBackend
# ---------------------------------------------------------------------------


def _safe_sink(sink: EventSink) -> EventSink:
    def wrapped(kind: str, payload: Any) -> None:
        try:
            sink(kind, payload)
        except Exception:
            pass

    return wrapped


class InProcessBackend:
    """Import strix in-process and run the ReportState dance plus
    run_strix_scan.  Requires Python >= 3.12 with strix-agent installed."""

    name = "inprocess"

    def __init__(self, worker_python: str = "", worker_path: str = "") -> None:
        # kept for interface parity with WorkerBackend
        self._worker_python = worker_python

    async def start(self, request: dict, sink: EventSink, cancel_event) -> RunOutcome:
        emit = _safe_sink(sink)
        from strix.core.runner import run_strix_scan
        from strix.report.state import ReportState, set_global_report_state

        scan_id = request["scan_id"]
        state = ReportState(scan_id)
        state.set_scan_config(request["scan_config"])
        state.save_run_data()
        state.vulnerability_found_callback = lambda rep: emit("vuln", rep)
        set_global_report_state(state)

        scan_task = None
        try:
            scan_task = asyncio_wrap(
                run_strix_scan(
                    scan_config=request["scan_config"],
                    scan_id=scan_id,
                    image=request.get("image") or "",
                    interactive=False,
                    max_budget_usd=request.get("max_budget_usd"),
                    max_turns=request.get("max_turns") or DEFAULT_MAX_TURNS,
                    event_sink=_throttled(lambda a, e: emit("event", {"agent_id": a, "event": e})),
                    status_sink=lambda ph: emit("phase", ph),
                    cleanup_on_exit=True,
                )
            )
            cancel_proxy = asyncio_wrap(cancel_event.wait())
            done, _pending = await asyncio_wait_first(scan_task, cancel_proxy)
            if cancel_proxy in done:
                scan_task.cancel()
                with suppress_cancelled():
                    await scan_task
                outcome = RunOutcome(ok=False, error="cancelled")
            else:
                await scan_task
                outcome = RunOutcome(ok=True, run_dir=str(state.get_run_dir()))
        except asyncio.CancelledError:
            outcome = RunOutcome(ok=False, error="cancelled")
        except Exception as exc:
            outcome = RunOutcome(ok=False, error=f"{type(exc).__name__}: {exc}")
        finally:
            with suppress_cancelled():
                try:
                    state.cleanup()
                except Exception:
                    pass
        if outcome.ok:
            emit(
                "finished",
                {"run_dir": outcome.run_dir, **read_run_artifacts(outcome.run_dir or "")},
            )
        return outcome


# small async helpers (kept local to avoid heavy deps)
import asyncio  # noqa: E402


def asyncio_wrap(awaitable):
    return asyncio.ensure_future(awaitable)


async def asyncio_wait_first(a, b):
    return await asyncio.wait({a, b}, return_when=asyncio.FIRST_COMPLETED)


class suppress_cancelled:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return exc_type is asyncio.CancelledError


def _throttled(fn: Callable[[str, Any], None], interval: float = 2.0) -> Callable:
    last: dict[str, float] = {}

    def wrapper(agent_id: str, event: Any) -> None:
        now = time.monotonic()
        if now - last.get(agent_id, 0.0) < interval:
            return
        last[agent_id] = now
        fn(agent_id, event)

    return wrapper


# ---------------------------------------------------------------------------
# WorkerBackend
# ---------------------------------------------------------------------------


def _spawn_flags() -> dict[str, Any]:
    """Worker must outlive the hermes session that spawned it (golden-path
    fix 2026-08-13): posix child sessions detach; win32 uses DETACHED_PROCESS."""
    return {
        "start_new_session": True,
        "creationflags": subprocess.DETACHED_PROCESS if os.name == "nt" else 0,
    }


class WorkerBackend:
    """Spawn strix's Python-3.12 worker and talk JSON-lines over stdio."""

    name = "worker"

    def __init__(self, worker_python: str = "", worker_path: str = "", runs_cwd: str = "") -> None:
        self._worker_python = worker_python
        self._worker_path = worker_path or str(Path(__file__).resolve().parent / "worker.py")
        self._runs_cwd = runs_cwd

    def _resolve_python(self) -> str:
        if self._worker_python:
            return self._worker_python
        env = os.environ.get("STRIX_WORKER_PYTHON")
        if env:
            return env
        found = shutil.which("strix-worker")
        if found:
            return found
        raise BackendConfigError(
            "no strix worker interpreter configured. Set worker.python in "
            "~/.hermes/strix.yaml or STRIX_WORKER_PYTHON to the Python-3.12 "
            "venv's python that has strix-agent installed."
        )

    async def start(self, request: dict, sink: EventSink, cancel_event) -> RunOutcome:
        emit = _safe_sink(sink)
        python = self._resolve_python()

        payload = {
            "scan_id": request["scan_id"],
            "scan_config": request["scan_config"],
            "image": request.get("image") or "",
            "max_budget_usd": request.get("max_budget_usd"),
            "max_turns": request.get("max_turns") or DEFAULT_MAX_TURNS,
            "extra_env": request.get("extra_env") or {},
        }
        # delete=False: the request file outlives this block (worker reads it,
        # then it is unlinked in the finally below).
        tf = tempfile.NamedTemporaryFile(  # noqa: SIM115
            "w", suffix=".json", encoding="utf-8", delete=False
        )
        try:
            json.dump(payload, tf, ensure_ascii=False)
            tf.close()
            reqfile = tf.name

            env = dict(os.environ)
            env["PYTHONPATH"] = str(Path(__file__).resolve().parent)
            env.update(payload["extra_env"])
            cwd = self._runs_cwd or os.getcwd()

            proc = await asyncio.create_subprocess_exec(
                python,
                self._worker_path,
                "--request-file",
                reqfile,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                cwd=cwd,
                **_spawn_flags(),
            )
        except FileNotFoundError as exc:
            raise BackendConfigError(f"worker interpreter not executable: {python}") from exc
        except Exception as exc:
            raise BackendRuntimeError(f"failed to launch worker: {exc}") from exc

        # all three pipes were requested above; narrow Optional for the type
        # checker (the runtime contract of PIPE guarantees them here).  Bind to
        # locals - attribute narrowing does not survive into the closures below.
        stdin_stream, stdout_stream = proc.stdin, proc.stdout
        stderr_stream = proc.stderr
        assert stdin_stream and stdout_stream and stderr_stream

        terminal: dict[str, Any] | None = None
        got_stdout_eof = False

        async def drain(stream, kind: str) -> None:
            nonlocal terminal, got_stdout_eof
            while True:
                line = await stream.readline()
                if not line:
                    break
                try:
                    ev = json.loads(line.decode("utf-8", errors="replace"))
                except json.JSONDecodeError:
                    emit("log", line.decode("utf-8", errors="replace").rstrip())
                    continue
                et = ev.get("type")
                if et == "finished":
                    terminal = ev
                    emit("finished", ev)
                elif et == "failed":
                    terminal = ev
                    emit("log", str(ev.get("error", "worker failed")))
                elif et == "cancelled":
                    terminal = ev
                    emit("log", "worker cancelled")
                elif et == "phase":
                    emit("phase", ev.get("phase", ""))
                elif et == "vuln":
                    emit("vuln", ev.get("report", {}))
                elif et == "event":
                    emit("event", {"agent_id": ev.get("agent_id"), "event": ev.get("event")})
                elif et == "heartbeat":
                    emit("heartbeat", {"ts": ev.get("ts")})
            got_stdout_eof = True

        async def tee_stderr() -> None:
            while True:
                line = await stderr_stream.readline()
                if not line:
                    return
                emit("log", line.decode("utf-8", errors="replace").rstrip())

        drain_task = asyncio.ensure_future(drain(stdout_stream, "stdout"))
        stderr_task = asyncio.ensure_future(tee_stderr())
        cancel_proxy = asyncio.ensure_future(cancel_event.wait())

        try:
            while True:
                done, _ = await asyncio.wait(
                    {drain_task, cancel_proxy},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if cancel_proxy in done:
                    # request cancellation: worker watches stdin
                    try:
                        stdin_stream.write(b'{"type": "cancel"}\n')
                        await stdin_stream.drain()
                        stdin_stream.close()
                    except (BrokenPipeError, OSError):
                        pass
                if drain_task in done:
                    break
                if proc.returncode is not None:
                    break
            await asyncio.wait_for(proc.wait(), timeout=10)
            await asyncio.wait_for(stderr_task, timeout=5)
        except asyncio.CancelledError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            raise
        finally:
            try:
                os.unlink(reqfile)
            except OSError:
                pass

        rc = proc.returncode
        if terminal is not None and terminal.get("type") in ("finished", "cancelled", "failed"):
            # cancelled/failed runs may still have written artifacts (vulnerabilities
            # are persisted live during the scan) — carry run_dir back so the record
            # can point strix_report at the on-disk files.
            return RunOutcome(
                ok=terminal.get("type") == "finished",
                run_dir=terminal.get("run_dir"),
                error=terminal.get("error") if terminal.get("type") != "finished" else None,
            )
        error = terminal.get("error") if terminal else None
        if not error and rc not in (0, None):
            error = f"worker exited with code {rc}"
        if not error:
            error = "worker finished without a result"
        return RunOutcome(ok=False, error=error)
