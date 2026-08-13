"""Authz: target allowlisting, chat allowlist, confirm gate, audit log, hooks."""

import json

from plugin import authz
from plugin import config as cfgmod


def _cfg(**over):
    base = cfgmod.load_config(path=None)
    base.update(over)
    return base


# --- target host extraction -------------------------------------------------


def test_extract_host_from_url():
    assert authz.hostname_of("http://app.example.com:8080/x?q=1") == "app.example.com"
    assert authz.hostname_of("https://localhost/") == "localhost"


def test_extract_host_bare_ip_and_port():
    assert authz.hostname_of("192.168.1.5:8080") == "192.168.1.5"
    assert authz.hostname_of("192.168.1.5") == "192.168.1.5"
    assert authz.hostname_of("[::1]:3000") == "::1"


def test_extract_host_bare_hostname():
    assert authz.hostname_of("app.internal") == "app.internal"
    assert authz.hostname_of(" example.com ") == "example.com"


# --- rule matching ----------------------------------------------------------


def test_exact_match():
    assert authz.target_allowed("localhost", ["localhost"]).allowed
    assert authz.target_allowed("127.0.0.1", ["127.0.0.1"]).allowed
    assert not authz.target_allowed("127.0.0.2", ["127.0.0.1"]).allowed


def test_suffix_wildcard():
    r = ["*.internal"]
    assert authz.target_allowed("app.internal", r).allowed
    assert authz.target_allowed("a.b.internal", r).allowed
    assert not authz.target_allowed("internal", r).allowed
    assert not authz.target_allowed("evilinternal", r).allowed
    assert not authz.target_allowed("internal.evil", r).allowed


def test_prefix_wildcard():
    r = ["staging.*"]
    assert authz.target_allowed("staging.foo.com", r).allowed
    assert authz.target_allowed("staging.other", r).allowed
    assert not authz.target_allowed("staging", r).allowed
    assert not authz.target_allowed("xstaging.foo.com", r).allowed


def test_subnet_rule():
    r = ["10.0.0.0/8", "192.168.0.0/16"]
    assert authz.target_allowed("10.1.2.3", r).allowed
    assert authz.target_allowed("192.168.1.1", r).allowed
    assert not authz.target_allowed("11.1.2.3", r).allowed
    assert not authz.target_allowed("192.169.0.1", r).allowed


def test_subnet_rule_skips_hostnames():
    # CIDR rules must never match a hostname (no DNS resolution; fail closed)
    assert not authz.target_allowed("app.example.com", ["10.0.0.0/8"]).allowed


def test_full_url_listed_as_rule():
    r = ["http://localhost:3000"]
    assert authz.target_allowed("http://localhost:3000/health", r).allowed


def test_default_deny():
    assert not authz.target_allowed("example.com", ["localhost"]).allowed
    assert authz.target_allowed("example.com", ["localhost"]).reason


# --- authorization decision -------------------------------------------------


def test_authorized_ok(default_config):
    c = _cfg(allowed_targets=["localhost"], require_authorized_flag=True)
    d = authz.check_authorization(c, chat_id="cli", user_id="u1",
                                  target="http://localhost:3000", confirm=True)
    assert d.allowed and d.reason == "ok"


def test_confirm_required_gate(default_config):
    c = _cfg(allowed_targets=["localhost"], require_authorized_flag=True)
    d = authz.check_authorization(c, chat_id="cli", user_id="u1",
                                  target="localhost", confirm=False)
    assert not d.allowed
    assert d.reason == "confirm_required"


def test_confirm_not_required_when_flag_off(default_config):
    c = _cfg(allowed_targets=["localhost"], require_authorized_flag=False)
    d = authz.check_authorization(c, chat_id="cli", user_id="u1",
                                  target="localhost", confirm=False)
    assert d.allowed


def test_chat_allowlist(default_config):
    c = _cfg(allowed_chats=["chat-1"], allowed_targets=["localhost"])
    assert authz.check_authorization(c, chat_id="chat-1", user_id="u1",
                                     target="localhost", confirm=True).allowed
    d = authz.check_authorization(c, chat_id="chat-9", user_id="u1",
                                  target="localhost", confirm=True)
    assert not d.allowed and d.reason == "chat_not_allowed"


def test_empty_chat_allowlist_allows_any(default_config):
    c = _cfg(allowed_chats=[], allowed_targets=["localhost"])
    assert authz.check_authorization(c, chat_id="whatever", user_id="u1",
                                     target="localhost", confirm=True).allowed


def test_target_deny_wins(default_config):
    c = _cfg(allowed_targets=["localhost"])
    d = authz.check_authorization(c, chat_id="cli", user_id="u1",
                                  target="http://evil.example.com", confirm=True)
    assert not d.allowed and d.reason == "target_not_allowed"


# --- audit log --------------------------------------------------------------


def test_audit_writes_jsonl_utf8(tmp_path):
    log = tmp_path / "strix-audit.jsonl"
    c = _cfg(audit_log=str(log))
    authz.audit(c, action="check", chat_id="cli", user_id="用户",
                target="localhost", decision="allowed", scan_id="scan-1")
    line = log.read_text(encoding="utf-8").strip()
    rec = json.loads(line)
    assert rec["action"] == "check"
    assert rec["user_id"] == "用户"
    assert "ts" in rec


def test_audit_never_raises_on_bad_dir(tmp_path):
    c = _cfg(audit_log=str(tmp_path / "no" / "such" / "dir" / "x.jsonl"))
    authz.audit(c, action="check", target="t")  # should not raise


# --- pre_tool_call hook -----------------------------------------------------


def test_hook_blocks_unauthorized_scan(default_config):
    c = _cfg(allowed_targets=["localhost"], require_authorized_flag=True)
    out = authz.pre_tool_call_hook(
        c, tool_name="strix_scan",
        args={"target": "http://evil.example.com", "confirm_authorized": True},
        session_id="s1")
    assert out is not None
    assert out["action"] == "block"
    assert "target_not_allowed" in out["message"]


def test_hook_passes_allowed_scan(default_config):
    c = _cfg(allowed_targets=["localhost"], require_authorized_flag=True)
    out = authz.pre_tool_call_hook(
        c, tool_name="strix_scan",
        args={"target": "http://localhost:3000", "confirm_authorized": True},
        session_id="s1")
    assert out is None


def test_hook_ignores_other_tools(default_config):
    c = _cfg(allowed_targets=["localhost"])
    assert authz.pre_tool_call_hook(
        c, tool_name="write_file", args={"path": "x"}, session_id="s1") is None


def test_hook_notes_missing_confirm_in_message(default_config):
    c = _cfg(allowed_targets=["localhost"], require_authorized_flag=True)
    out = authz.pre_tool_call_hook(
        c, tool_name="strix_scan",
        args={"target": "localhost"}, session_id="s1")
    assert out is not None and out["action"] == "block"