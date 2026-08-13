"""Worker process boundary: emit must never kill the scan (parent-gone pipe)."""

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