"""Phase 2: realtime broadcast — rendering + dispatch latch + fan-out."""

import asyncio

from plugin import broadcast


class FakeEvent:
    def __init__(self, platform, chat_id, text=""):
        self.platform = platform
        self.chat_id = chat_id
        self.text = text


class FakeAdapter:
    def __init__(self):
        self.sent = []

    async def send(self, chat_id, content, **kw):
        self.sent.append((chat_id, content))


class FakeGateway:
    def __init__(self, adapter, platform="feishu"):
        self.adapters = {platform: adapter}
        self.platform = platform


# --- rendering --------------------------------------------------------------


def test_renderers():
    assert "waiting" in broadcast.phase_text("sc-1", "waiting")
    v = broadcast.vuln_text("sc-1", {"id": "vuln-0001", "severity": "critical",
                                     "title": "SQLi"})
    assert "critical" in v and "SQLi" in v and "🔴" in v
    f = broadcast.finished_text("sc-1", {"vuln_count": 2, "by_severity": {"critical": 1}})
    assert "finished" in f and "critical=1" in f


# --- fan-out ----------------------------------------------------------------


def test_no_channel_no_send():
    """Fan-out through the channel: phase/vuln/finished rendered and sent."""
    received = []
    from plugin.runner import get_manager

    mgr = get_manager()
    broadcast.set_channel(received.append)
    if broadcast._on_scan_event not in mgr._all_listeners:
        mgr.subscribe_all(broadcast._on_scan_event)
    fn = broadcast._on_scan_event
    try:
        fn("sc-1", "phase", "spin")
        fn("sc-1", "vuln", {"id": "v", "severity": "high", "title": "X"})
        fn("sc-1", "finished", {"status": "finished", "vuln_count": 1,
                                "by_severity": {"high": 1}})
        assert received and received[0].startswith("🔒")
        assert "🟠" in received[1]
        assert "✅" in received[2]
    finally:
        broadcast.set_channel(None)


def test_failed_scan_text():
    received = []
    broadcast.set_channel(received.append)
    try:
        broadcast._on_scan_event("sc-9", "finished", {"status": "failed", "error": "boom"})
        assert "❌" in received[0] and "boom" in received[0]
    finally:
        broadcast.set_channel(None)


# --- pre_gateway_dispatch latch ----------------------------------------------


async def test_dispatch_hook_captures_route():
    adapter = FakeAdapter()
    gw = FakeGateway(adapter)
    broadcast.set_channel(None)
    ret = broadcast.pre_gateway_dispatch_hook(event=FakeEvent("feishu", "chat-1", "/pentest x"),
                                              gateway=gw)
    assert ret is None  # never blocks dispatch
    assert broadcast.get_channel() is not None
    broadcast.get_channel()("hello")
    await asyncio.sleep(0.05)
    assert adapter.sent == [("chat-1", "hello")]
    broadcast.set_channel(None)


def test_dispatch_hook_ignores_other_platforms():
    class NoAdapterGateway:
        adapters = {}

    ret = broadcast.pre_gateway_dispatch_hook(
        event=FakeEvent("slack", "c2"), gateway=NoAdapterGateway()
    )
    assert ret is None and broadcast.get_channel() is None


def test_dispatch_hook_missing_args():
    assert broadcast.pre_gateway_dispatch_hook(event=None, gateway=None) is None
    assert broadcast.pre_gateway_dispatch_hook() is None