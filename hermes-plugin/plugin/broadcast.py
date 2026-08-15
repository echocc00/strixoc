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

# module-level latching (gateway dispatch is a per-process singleton)
_channel: Channel | None = None
_installed_subscription = False


def set_channel(channel: Channel | None) -> None:
    global _channel
    _channel = channel


def get_channel() -> Channel | None:
    return _channel


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


# ---------------------------------------------------------------------------
# event fan-out (subscribes to ScanManager once)
# ---------------------------------------------------------------------------


def _on_scan_event(scan_id: str, kind: str, payload: Any) -> None:
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
            text = (
                finished_text(scan_id, payload)
                if status == "finished"
                else failed_text(scan_id, str(payload.get("error") or "unknown"))
            )
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
            try:
                logger.info("broadcast: sending to %s: %.120s", chat_id, text.replace("\n", " "))
                coro = adapter.send(chat_id, text)
                # fire-and-forget by design: progress pushes must never
                # block the gateway dispatch path; failures only log.
                try:
                    asyncio.get_running_loop().create_task(coro)
                except RuntimeError:
                    asyncio.ensure_future(coro)  # noqa: RUF006
            except Exception:
                logger.exception("gateway broadcast send failed")

        set_channel(send)
        ensure_subscription()
    except Exception:
        logger.exception("pre_gateway_dispatch hook failed")
    return None
