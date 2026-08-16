"""0.4.2.4: failure alerting.

- ScanManager: worker-death detection (heartbeat stale / grace expired)
  fires once per scan, audits, and emits ``worker_dead``; done payload
  carries duration.
- broadcast: cancelled/failed terminal events and worker_dead render alert
  cards, gated by ``notify_on_failure``, routed to ``notify_chat_id``
  (fixed ops chat via send_to) or the latched channel.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest

from plugin import broadcast, runner
from plugin.runner import ScanManager, ScanRecord


def _rec(**over: Any) -> ScanRecord:
    base: dict[str, Any] = dict(
        scan_id="strix-dead01",
        status="running",
        target="http://10.0.0.5",
        scan_mode="quick",
        budget=1.0,
        chat_id="cli",
        user_id="u",
        created_at="2026-08-16T00:00:00+00:00",
    )
    base.update(over)
    return ScanRecord(**base)


class WorkerishBackend:
    name = "worker"

    async def start(self, request, emit, cancel_event):  # pragma: no cover - unused
        await asyncio.Event().wait()


@pytest.fixture
def mgr(tmp_path):
    m = ScanManager(
        cfg={
            "allowed_targets": ["10.0.0.5"],
            "audit_log": str(tmp_path / "audit.jsonl"),
            "scans_db": str(tmp_path / "scans.json"),
            "runs_cwd": str(tmp_path),
        },
        backend=WorkerishBackend(),
    )
    yield m
    runner._MANAGER = None
    broadcast._cfg_override = None


# --- runner: worker-death detection -----------------------------------------


def test_stale_heartbeat_fires_worker_dead_once(mgr, tmp_path):
    rec = _rec(last_heartbeat=str(time.time() - 200))  # stale > 90s
    mgr._records[rec.scan_id] = rec
    events: list[tuple[str, Any]] = []
    mgr.subscribe_all(lambda sid, kind, payload: events.append((kind, payload)))

    out1 = mgr._liveness(rec)
    out2 = mgr._liveness(rec)

    assert out1["worker_alive"] is False
    assert out1["heartbeat_age_s"] > 90
    assert rec.worker_dead_notified is True
    kinds = [k for k, _ in events]
    assert kinds.count("worker_dead") == 1  # exactly once
    assert events[0][1]["scan_id"] == rec.scan_id
    assert out2 == out1  # second poll stable

    audit_lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert any('"worker_dead"' in ln for ln in audit_lines)


def test_grace_expired_without_any_heartbeat_fires(mgr):
    rec = _rec(created_at="2026-08-15T00:00:00+00:00", last_heartbeat="")
    mgr._records[rec.scan_id] = rec
    events: list[tuple[str, Any]] = []
    mgr.subscribe_all(lambda sid, kind, payload: events.append((kind, payload)))

    out = mgr._liveness(rec)
    assert out["worker_alive"] is False
    assert any(k == "worker_dead" for k, _ in events)


def test_fresh_heartbeat_does_not_fire(mgr):
    rec = _rec(last_heartbeat=str(time.time() - 10))
    mgr._records[rec.scan_id] = rec
    events: list[tuple[str, Any]] = []
    mgr.subscribe_all(lambda sid, kind, payload: events.append((kind, payload)))

    out = mgr._liveness(rec)
    assert out["worker_alive"] is True
    assert events == []


def test_finished_scans_never_fire(mgr):
    rec = _rec(status="failed", last_heartbeat=str(time.time() - 500))
    mgr._records[rec.scan_id] = rec
    events: list[tuple[str, Any]] = []
    mgr.subscribe_all(lambda sid, kind, payload: events.append((kind, payload)))
    out = mgr._liveness(rec)
    assert out == {"worker_alive": None, "heartbeat_age_s": None}
    assert events == []


def test_watchdog_started_by_start(mgr):
    async def go():
        await mgr.start("http://10.0.0.5", confirm=True, chat_id="cli")
        assert mgr._watchdog_task is not None and not mgr._watchdog_task.done()
        mgr._watchdog_task.cancel()

    asyncio.run(go())


# --- runner: duration in done payload ----------------------------------------


def test_duration_s_computed_from_record():
    r = _rec(updated_at="2026-08-16T00:45:00+00:00")
    assert ScanManager._duration_s(r) == 2700.0
    assert ScanManager._duration_s(_rec(updated_at="garbage")) is None


# --- broadcast: alert rendering + routing ------------------------------------


def test_failure_card_contains_fields():
    card = broadcast.failure_card(
        "strix-x",
        {
            "status": "failed",
            "error": "boom",
            "duration_s": 755,
            "vuln_count": 2,
            "by_severity": {"high": 1, "low": 1},
        },
    )
    assert card.startswith("❌ Strix scan failed")
    assert "boom" in card and "12m35s" in card and "high=1" in card
    cancelled = broadcast.failure_card("strix-x", {"status": "cancelled"})
    assert cancelled.startswith("⚠️") and "cancelled" in cancelled


def test_worker_dead_text_renders():
    t = broadcast.worker_dead_text("strix-x", {"heartbeat_age_s": 130.5})
    assert "☠️" in t and "130.5s" in t
    t2 = broadcast.worker_dead_text("strix-x", {})
    assert "no heartbeat" in t2


@pytest.fixture
def clean_channel():
    broadcast.set_channel(None)

    def _restore():
        broadcast.set_channel(None)
        broadcast._cfg_override = None

    yield _restore
    _restore()


def test_failed_event_routes_to_channel_by_default(clean_channel):
    received: list[str] = []
    broadcast.set_channel(received.append)
    broadcast._on_scan_event("sc-1", "finished", {"status": "failed", "error": "boom"})
    assert len(received) == 1 and "boom" in received[0]


def test_notify_on_failure_false_silences(clean_channel):
    received: list[str] = []
    broadcast.set_channel(received.append)
    broadcast._cfg_override = {"notify_on_failure": False}
    broadcast._on_scan_event("sc-1", "finished", {"status": "failed", "error": "boom"})
    assert received == []


def test_notify_chat_id_routes_via_send_to(clean_channel):
    received: list[tuple[str, str]] = []
    broadcast.set_channel(
        lambda t: received.append(("channel", t)), lambda c, t: received.append((c, t))
    )
    broadcast._cfg_override = {"notify_on_failure": True, "notify_chat_id": "ops-chat"}
    broadcast._on_scan_event("sc-1", "finished", {"status": "failed", "error": "boom"})
    assert len(received) == 1 and received[0][0] == "ops-chat"


def test_send_to_falls_back_to_channel_when_not_latched(clean_channel):
    received: list[str] = []
    broadcast.set_channel(received.append)  # no send_to
    broadcast._cfg_override = {"notify_chat_id": "ops-chat"}
    broadcast._on_scan_event("sc-1", "finished", {"status": "failed", "error": "boom"})
    assert len(received) == 1  # fell back to the channel


def test_worker_dead_event_routes_with_same_gates(clean_channel):
    received: list[str] = []
    broadcast.set_channel(received.append)
    broadcast._on_scan_event("sc-1", "worker_dead", {"heartbeat_age_s": 200})
    assert len(received) == 1 and "worker appears dead" in received[0]

    received.clear()
    broadcast._cfg_override = {"notify_on_failure": False}
    broadcast._on_scan_event("sc-1", "worker_dead", {"heartbeat_age_s": 200})
    assert received == []


def test_finished_success_unaffected_by_alert_config(clean_channel):
    received: list[str] = []
    broadcast.set_channel(received.append)
    broadcast._cfg_override = {"notify_on_failure": True, "notify_chat_id": "ops"}
    broadcast._on_scan_event("sc-1", "finished", {"status": "finished", "vuln_count": 0})
    assert len(received) == 1 and received[0].startswith("✅")


def test_plugin_cfg_prefers_override_and_manager(clean_channel, mgr):
    assert broadcast._plugin_cfg() is not None
    broadcast._cfg_override = {"x": 1}
    assert broadcast._plugin_cfg() == {"x": 1}


# --- config defaults ----------------------------------------------------------


def test_notify_config_defaults():
    from plugin import config

    cfg = config.load_config(path=None)
    assert cfg["notify_on_failure"] is True
    assert cfg["notify_chat_id"] == ""
