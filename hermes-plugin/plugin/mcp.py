"""Bridge hermes' MCP startup into the gateway process.

hermes v0.19/v0.20 bug (verified 2026-08-14): `gateway run` is excluded from
inline MCP discovery by ``_command_has_dedicated_mcp_startup``, yet the
gateway executor never starts it either — so configured ``mcp_servers`` are
never discovered and their tools never reach gateway sessions.  The plugin
runs inside the gateway process, so it triggers the same public startup the
dashboard/CLI paths use.  Idempotent, failure-safe, no hermes core changes.
"""

from __future__ import annotations

import logging
import threading

logger = logging.getLogger(__name__)

_started = False
_lock = threading.Lock()


def ensure_gateway_mcp_startup() -> None:
    """Start (and briefly wait for) hermes MCP tool discovery once.

    Async thread + bounded wait, mirroring hermes' dashboard startup path —
    a slow or dead MCP server must never block the gateway or a plugin load.
    """
    global _started
    with _lock:
        if _started:
            return
        _started = True
    try:
        from hermes_cli import mcp_startup  # type: ignore[import-not-found]

        mcp_startup.start_background_mcp_discovery(
            logger=logger,
            thread_name="strix-plugin-mcp-discovery",
        )
        try:
            mcp_startup.wait_for_mcp_discovery(timeout=5.0, single_query=False)
        except Exception:  # noqa: BLE001
            logger.debug("MCP discovery wait skipped (server may still be up)")
    except Exception:  # noqa: BLE001
        logger.warning("MCP discovery via plugin bridge skipped", exc_info=True)
