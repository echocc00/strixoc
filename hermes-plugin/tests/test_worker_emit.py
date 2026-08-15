"""Worker process boundary: emit must never kill the scan (parent-gone pipe)."""

import contextlib
import json

from plugin.worker import make_emit


class BrokenStream:
    def write(self, s):
        raise OSError("Broken pipe")

    def flush(self):
        raise OSError("Broken pipe")


def test_emit_survives_broken_pipe():
    emit = make_emit(BrokenStream())
    emit({"type": "phase", "phase": "still scanning"})  # must not raise


class RecordingStream:
    def __init__(self):
        self.buf = []

    def write(self, s):
        self.buf.append(s)

    def flush(self):
        pass


def test_emit_writes_json_line():
    out = RecordingStream()
    emit = make_emit(out)
    emit({"type": "finished", "run_dir": "/runs/x"})
    line = "".join(out.buf)
    assert json.loads(line) == {"type": "finished", "run_dir": "/runs/x"}


async def test_heartbeat_loop_emits_periodically_and_stops():
    import asyncio

    from plugin import worker_runtime

    out = RecordingStream()
    emit = make_emit(out)
    task = asyncio.ensure_future(worker_runtime._heartbeat_loop(emit, interval=0.05))
    await asyncio.sleep(0.16)
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    events = [json.loads(ln) for ln in "".join(out.buf).splitlines()]
    heartbeats = [e for e in events if e["type"] == "heartbeat"]
    assert 1 <= len(heartbeats) <= 4  # ~3 intervals, jitter-tolerant
    assert all(isinstance(e["ts"], float) for e in heartbeats)
