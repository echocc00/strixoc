"""Plugin-side MCP gateway bridge tests (hermes gateway-run MCP startup gap)."""

import importlib
import sys
import types

from plugin import mcp


class FakeMCPStartup:
    def __init__(self):
        self.started = []
        self.waited = []

    def start_background_mcp_discovery(self, **kw):
        self.started.append(kw)

    def wait_for_mcp_discovery(self, timeout, single_query):
        self.waited.append((timeout, single_query))


def _install(fake, monkeypatch):
    mod = types.ModuleType("hermes_cli.mcp_startup")
    mod.start_background_mcp_discovery = fake.start_background_mcp_discovery
    mod.wait_for_mcp_discovery = fake.wait_for_mcp_discovery
    sys.modules["hermes_cli.mcp_startup"] = mod
    # `from hermes_cli import mcp_startup` resolves the package attribute
    # first, so an already-imported real hermes_cli would bypass the fake.
    hermes_cli = sys.modules.get("hermes_cli")
    if hermes_cli is not None:
        monkeypatch.setattr(hermes_cli, "mcp_startup", mod, raising=False)
    return mod


def _cleanup():
    sys.modules.pop("hermes_cli.mcp_startup", None)


def test_ensure_starts_discovery_once(monkeypatch):
    fake = FakeMCPStartup()
    monkeypatch.setattr(mcp, "_started", False)
    try:
        _install(fake, monkeypatch)
        mcp.ensure_gateway_mcp_startup()
        mcp.ensure_gateway_mcp_startup()  # idempotent
        assert len(fake.started) == 1
        assert fake.started[0]["thread_name"] == "strix-plugin-mcp-discovery"
        assert fake.waited == [(5.0, False)]
    finally:
        _cleanup()
        monkeypatch.setattr(mcp, "_started", False)


def test_ensure_survives_missing_hermes(monkeypatch):
    monkeypatch.setattr(mcp, "_started", False)
    # A None sys.modules entry makes import raise ImportError (documented),
    # covering both fresh imports and already-imported real packages.
    monkeypatch.setitem(sys.modules, "hermes_cli", None)
    monkeypatch.setitem(sys.modules, "hermes_cli.mcp_startup", None)
    mcp.ensure_gateway_mcp_startup()  # must not raise
    monkeypatch.setattr(mcp, "_started", False)


def test_ensure_survives_wait_failure(monkeypatch):
    class FailingWait:
        def start_background_mcp_discovery(self, **kw):
            pass

        def wait_for_mcp_discovery(self, **kw):
            raise RuntimeError("server slow")

    monkeypatch.setattr(mcp, "_started", False)
    fake = FailingWait()
    try:
        _install(fake, monkeypatch)
        mcp.ensure_gateway_mcp_startup()  # must not raise
    finally:
        _cleanup()
        monkeypatch.setattr(mcp, "_started", False)
