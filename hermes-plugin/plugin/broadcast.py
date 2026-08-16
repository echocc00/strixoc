"""Realtime progress broadcast to the gateway chat that triggered a scan.

Phase 2 (IMPL_PLAN §3.4): worker events (phase / vuln / finished) stream into
ScanManager; this module renders them into plain-text chat messages and fans
them out through the gateway platform adapter captured at dispatch time
(``pre_gateway_dispatch`` hook — run.py fires it with ``event`` and
``gateway`` kwargs).  No platform plugin changes are needed: Feishu/Telegram/
Discord adapters already have ``async send(chat_id, content, ...)``.

Routing model: the chat that last sent a message (or triggered a scan via a
tool / slash command) receives the progress stream until another chat is
seen.  CLI sessions render to the plugin log instead.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)

Channel = Callable[[str], None]  # outbound text sink (sync wrapper over adapter.send)
SendTo = Callable[[str, str], None]  # (chat_id, text) sink for ops-alert routing

# module-level latching (gateway dispatch is a per-process singleton)
_channel: Channel | None = None
_send_to: SendTo | None = None
_installed_subscription = False
# test override for _plugin_cfg(); None = resolve from the ScanManager
_cfg_override: dict[str, Any] | None = None


def set_channel(channel: Channel | None, send_to: SendTo | None = None) -> None:
    global _channel, _send_to
    _channel = channel
    _send_to = send_to or (None if channel is None else _send_to)


def get_channel() -> Channel | None:
    return _channel


def get_send_to() -> SendTo | None:
    return _send_to


def _plugin_cfg() -> dict[str, Any]:
    """Config for alert routing (notify_on_failure / notify_chat_id).
    ScanManager is the source of truth; config-module defaults as fallback."""
    if _cfg_override is not None:
        return _cfg_override
    try:
        from . import runner

        return runner.get_manager().cfg
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def phase_text(scan_id: str, phase: str) -> str:
    return f"🔒 `{scan_id}` — {phase}"


def vuln_text(scan_id: str, report: dict[str, Any]) -> str:
    sev = str(report.get("severity", "info")).lower()
    icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(sev, "⚪")
    title = report.get("title") or report.get("name") or "(untitled finding)"
    rid = report.get("id", "")
    return f"{icon} [{sev}] {title} — `{scan_id}` {f'({rid})' if rid else ''}"


def finished_text(scan_id: str, payload: dict[str, Any]) -> str:
    sev = payload.get("by_severity") or {}
    counts = ", ".join(f"{k}={v}" for k, v in sorted(sev.items())) or "0"
    return (
        f"✅ `{scan_id}` finished — vulnerabilities: {payload.get('vuln_count', 0)} ({counts})\n"
        f"Full report: `strix_report(scan_id={scan_id})`"
    )


def failed_text(scan_id: str, error: str) -> str:
    return f"❌ `{scan_id}` failed — {error}"


def _fmt_duration(seconds: Any) -> str:
    if not isinstance(seconds, (int, float)) or seconds < 0:
        return "unknown"
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    return f"{h}h{m:02d}m" if h else f"{m}m{s:02d}s"


def failure_card(scan_id: str, payload: dict[str, Any]) -> str:
    """Alert card for cancelled/failed terminal states (DEV_PLAN 2.4)."""
    status = str(payload.get("status") or "failed")
    icon = "❌" if status == "failed" else "⚠️"
    counts = payload.get("by_severity") or {}
    counts_s = ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "0"
    parts = [
        f"{icon} Strix scan {status} - `{scan_id}`",
        f"reason: {payload.get('error') or 'unknown'}",
        f"duration: {_fmt_duration(payload.get('duration_s'))}",
        f"vulns seen: {payload.get('vuln_count', 0)} ({counts_s})",
    ]
    return chr(10).join(parts)


def worker_dead_text(scan_id: str, payload: dict[str, Any]) -> str:
    age = payload.get("heartbeat_age_s")
    age_s = f"{age}s stale" if isinstance(age, (int, float)) else "no heartbeat"
    return (
        f"☠️ `{scan_id}` worker appears dead ({age_s}) - scan is hung. "
        "Check `strix_status`, then `strix_cancel` to clean up."
    )


# ---------------------------------------------------------------------------
# event fan-out (subscribes to ScanManager once)
# ---------------------------------------------------------------------------


def _route_alert(text: str, cfg: dict[str, Any]) -> bool:
    """Send a failure alert: fixed ops chat (notify_chat_id) if configured,
    else the latched channel.  Returns True when delivered somewhere."""
    dest = str(cfg.get("notify_chat_id") or "")
    if dest:
        sink = get_send_to()
        if sink is not None:
            try:
                sink(dest, text)
                return True
            except Exception:
                logger.exception("broadcast alert send_to failed")
        logger.warning("broadcast: notify_chat_id set but no send_to latched - falling back")
    chan = _channel
    if chan is None:
        logger.info("broadcast: alert dropped - no channel latched")
        return False
    try:
        chan(text)
    except Exception:
        logger.exception("broadcast send failed")
        return False
    return True


def _on_scan_event(scan_id: str, kind: str, payload: Any) -> None:
    if kind == "worker_dead" and isinstance(payload, dict):
        cfg = _plugin_cfg()
        if not cfg.get("notify_on_failure", True):
            return
        _route_alert(worker_dead_text(scan_id, payload), cfg)
        return
    chan = _channel
    if chan is None:
        logger.info("broadcast: event %s/%s dropped — no channel latched", scan_id, kind)
        return
    try:
        if kind == "phase" and isinstance(payload, str):
            text = phase_text(scan_id, payload)
        elif kind == "vuln" and isinstance(payload, dict):
            text = vuln_text(scan_id, payload)
        elif kind == "finished" and isinstance(payload, dict):
            status = payload.get("status")
            if status in ("failed", "cancelled"):
                cfg = _plugin_cfg()
                if not cfg.get("notify_on_failure", True):
                    return
                _route_alert(failure_card(scan_id, payload), cfg)
                return
            text = finished_text(scan_id, payload)
        else:
            return
    except Exception:
        logger.exception("broadcast render failed")
        return
    try:
        chan(text)
    except Exception:
        logger.exception("broadcast send failed")


def ensure_subscription() -> None:
    """Attach the broadcast listener to the plugin-wide ScanManager once."""
    global _installed_subscription
    if _installed_subscription:
        return
    from . import runner

    try:
        runner.get_manager().subscribe_all(_on_scan_event)
        _installed_subscription = True
    except Exception:
        logger.exception("could not attach broadcast subscription")


# ---------------------------------------------------------------------------
# pre_gateway_dispatch hook: capture the outbound route
# ---------------------------------------------------------------------------


def pre_gateway_dispatch_hook(
    event: Any = None,
    gateway: Any = None,
    **kw: Any,
) -> dict[str, str] | None:
    """Latch (adapter, chat_id) so scans started from this chat stream
    progress into it.  Returns None (normal dispatch) always."""
    try:
        if event is None or gateway is None:
            logger.info("broadcast: dispatch hook fired without event/gateway — skip")
            return None
        # v0.19.1 MessageEvent carries identity on ``source`` (gateway/platforms/
        # base.py canonical pattern); newer builds may expose top-level attrs.
        source = getattr(event, "source", None)
        platform = getattr(source, "platform", None) or getattr(event, "platform", None)
        chat_id = getattr(source, "chat_id", None) or getattr(event, "chat_id", None)
        if platform is None or chat_id is None:
            logger.info(
                "broadcast: dispatch hook missing platform/chat "
                "(platform=%r chat=%r source=%r) — skip",
                platform,
                chat_id,
                bool(source),
            )
            return None
        adapters = getattr(gateway, "adapters", None)
        if not adapters or platform not in adapters:
            logger.info(
                "broadcast: no adapter for platform %s (adapters=%s) — skip",
                platform,
                list(adapters or {}).__class__.__name__ if adapters else None,
            )
            return None
        adapter = adapters[platform]
        logger.info("broadcast: latching gateway chat -> platform=%s chat=%s", platform, chat_id)

        def send(text: str) -> None:
            _spawn_send(adapter, chat_id, text)

        def send_to(dest_chat: str, text: str) -> None:
            _spawn_send(adapter, dest_chat, text)

        set_channel(send, send_to)
        ensure_subscription()
    except Exception:
        logger.exception("pre_gateway_dispatch hook failed")
    return None


def _spawn_send(adapter: Any, chat_id: Any, text: str) -> None:
    """Fire-and-forget adapter.send: progress pushes must never block the
    gateway dispatch path; failures only log."""
    try:
        logger.info("broadcast: sending to %s: %.120s", chat_id, text.replace("\n", " "))
        coro = adapter.send(chat_id, text)
        try:
            asyncio.get_running_loop().create_task(coro)
        except RuntimeError:
            asyncio.ensure_future(coro)  # noqa: RUF006
    except Exception:
        logger.exception("gateway broadcast send failed")
