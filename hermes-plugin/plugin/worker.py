"""strix-worker entry point (run as ``<py3.12-venv>/bin/python worker.py
--request-file <path>`` by the WorkerBackend).

Protocol (stdout, JSON-lines, all messages ``{"type": ...}``):

  parent -> worker:  {"type": "cancel"} on stdin (only command)
  worker -> parent:  {"type": "phase",  "phase": "..."}
                     {"type": "vuln",   "report": {...}}
                     {"type": "event",  "agent_id": ..., "event": {...}}
                     {"type": "finished"/"failed"/"cancelled", ...}

The heavy lifting lives in worker_runtime.execute(); this file only owns
the process boundary (arg parse, stdout framing, stdin cancel watcher).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import threading
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))

from worker_runtime import execute  # noqa: E402

Emit = Callable[[dict], None]


def make_emit(stream) -> Emit:
    """Worker->parent event emitter.  If the parent is gone (closed pipe after
    the hermes session exited and the detached worker kept scanning), the scan
    must survive: events are best-effort, never fatal."""
    def emit(ev: dict) -> None:
        try:
            print(json.dumps(ev, ensure_ascii=False), file=stream, flush=True)
        except OSError:
            pass

    return emit


def _main() -> int:
    ap = argparse.ArgumentParser(prog="strix-worker")
    ap.add_argument("--request-file", required=True)
    args = ap.parse_args()

    with open(args.request_file, encoding="utf-8") as f:
        request = json.load(f)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    cancel_event = asyncio.Event()

    def watch_stdin() -> None:
        # py3.12: no current loop in a non-main thread — use the captured loop.
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                cmd = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(cmd, dict) and cmd.get("type") == "cancel":
                loop.call_soon_threadsafe(cancel_event.set)
                return

    t = threading.Thread(target=watch_stdin, daemon=True)
    t.start()

    emit = make_emit(sys.stdout)

    try:
        outcome = loop.run_until_complete(
            execute(request, emit=emit, cancel_event=cancel_event)
        )
        return 0 if outcome.get("ok") else 1
    except Exception as exc:  # noqa: BLE001
        emit({"type": "failed", "error": f"{type(exc).__name__}: {exc}"})
        return 1
    finally:
        loop.close()


if __name__ == "__main__":
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    raise SystemExit(_main())