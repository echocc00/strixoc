"""Authorization: target allowlist, chat allowlist, confirm gate, audit log.

Security boundary #1/#2 from IMPL_PLAN: scans are only started for targets
the operator explicitly listed, by chats they allowed, and — unless the
operator opted out — only with an explicit ``confirm_authorized`` flag.
Every decision is written to the audit log.

All rules are static string/network matching.  This module NEVER resolves
DNS or talks to the network: a hostname that no rule matches fails closed.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

DEFAULT_AUDIT_LOG = "~/.hermes/logs/strix-audit.jsonl"


@dataclass
class AuthDecision:
    allowed: bool
    reason: str
    matched: str | None = None


@dataclass
class _RuleSet:
    exact: set[str] = field(default_factory=set)
    suffix: dict[str, None] = field(default_factory=dict)  # "*.domain"
    prefix: list[str] = field(default_factory=list)  # "prefix.*"
    urls: list[str] = field(default_factory=list)  # full URL prefixes
    subnets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list)

    @classmethod
    def from_rules(cls, rules: list[str]) -> _RuleSet:
        rs = cls()
        for r in rules:
            r = (r or "").strip()
            if not r:
                continue
            if r.startswith("*."):
                rs.suffix[r[2:]] = None
            elif r.endswith(".*"):
                rs.prefix.append(r[:-2])
            elif "://" in r:
                rs.urls.append(r)
            else:
                try:
                    rs.subnets.append(ipaddress.ip_network(r, strict=False))
                except ValueError:
                    rs.exact.add(r)
        return rs


def hostname_of(target: str) -> str:
    """Strip scheme/userinfo/port/path down to the bare host or IP."""
    t = target.strip()
    if "://" in t:
        t = urlparse(t).netloc or t
    if "@" in t:
        t = t.rsplit("@", 1)[1]
    if t.startswith("["):
        m = re.match(r"^\[([^\]]+)\]", t)
        t = m.group(1) if m else t
    else:
        t = t.split(":", 1)[0]
    return t.strip()


def _host_is_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def target_allowed(target: str, rules: list[str]) -> AuthDecision:
    t = target.strip()
    host = hostname_of(t)
    rs = _RuleSet.from_rules(rules)

    if host in rs.exact:
        return AuthDecision(True, "ok", matched=host)
    if host == "localhost" and "localhost" in rs.exact:
        return AuthDecision(True, "ok", matched="localhost")
    for domain in rs.suffix:
        if host.endswith("." + domain) and host != domain:
            return AuthDecision(True, "ok", matched=f"*.{domain}")
    for prefix in rs.prefix:
        if host.startswith(prefix + ".") and host != prefix:
            return AuthDecision(True, "ok", matched=f"{prefix}.*")
    ip = _host_is_ip(host)
    if ip is not None:
        for net in rs.subnets:
            if ip in net:
                return AuthDecision(True, "ok", matched=str(net))
    for url in rs.urls:
        if t == url or (t.startswith(url) and t[len(url) : len(url) + 1] in {"/", "?"}):
            return AuthDecision(True, "ok", matched=url)
    return AuthDecision(False, "target_not_allowed")


def check_authorization(
    cfg: dict[str, Any],
    *,
    chat_id: str,
    user_id: str,
    target: str,
    confirm: bool,
) -> AuthDecision:
    chats = cfg.get("allowed_chats") or []
    if chats and chat_id not in chats:
        return AuthDecision(False, "chat_not_allowed")
    d = target_allowed(str(target), cfg.get("allowed_targets") or [])
    if not d.allowed:
        return AuthDecision(False, "target_not_allowed", matched=d.matched)
    if cfg.get("require_authorized_flag", True) and not confirm:
        return AuthDecision(False, "confirm_required")
    return AuthDecision(True, "ok", matched=d.matched)


def audit(cfg: dict[str, Any], *, action: str, ts: str | None = None, **fields: Any) -> None:
    """Append one JSON line to the audit log.  Never raises — auditing must
    not be able to break the scan path."""
    path = Path(os.path.expanduser(str(cfg.get("audit_log") or DEFAULT_AUDIT_LOG)))
    rec = {
        "ts": ts or datetime.now(UTC).isoformat(),
        "action": action,
        **fields,
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass


def _hook_identity(kw: dict[str, Any]) -> tuple[str, str]:
    session = str(kw.get("session_id") or "")
    chat = str(kw.get("chat_id") or "") or session or "clihook"
    user = str(kw.get("user_id") or "") or session or "unknown"
    return chat, user


def pre_tool_call_hook(
    cfg: dict[str, Any],
    tool_name: str = "",
    args: Any = None,
    **kw: Any,
) -> dict[str, str] | None:
    """Hook: block ``strix_scan`` calls that are not authorized.

    Returns Hermes-canonical ``{"action": "block", "message": ...}`` or None.
    """
    if tool_name != "strix_scan" or not isinstance(args, dict):
        return None
    target = str(args.get("target") or "")
    if not target:
        return {"action": "block", "message": "strix_scan: target is required"}
    confirm = bool(args.get("confirm_authorized", False))
    chat_id, user_id = _hook_identity(kw)
    d = check_authorization(cfg, chat_id=chat_id, user_id=user_id, target=target, confirm=confirm)
    audit(
        cfg,
        action="tool_check",
        tool="strix_scan",
        chat_id=chat_id,
        user_id=user_id,
        target=target,
        decision="allowed" if d.allowed else d.reason,
    )
    if d.allowed:
        return None
    msg = f"strix_scan blocked: {d.reason} for target {target!r}"
    if d.reason == "confirm_required":
        msg += " — pass confirm_authorized=true (or /pentest --confirm-authorized)"
    elif d.reason == "target_not_allowed":
        msg += " — add it to allowed_targets in ~/.hermes/strix.yaml"
    return {"action": "block", "message": msg}


def transform_tool_result_hook(
    cfg: dict[str, Any],
    tool_name: str = "",
    result: Any = None,
    **kw: Any,
) -> str | None:
    """Hook: append a reminder to strix_scan results so the LLM doesn't
    cancel early or equate 'no findings' with 'no vulnerabilities'."""
    if tool_name != "strix_scan" or result is None:
        return None
    return (
        "\n\n---\nStrix scan best practice: a scan runs to completion on its own — "
        "do NOT cancel it early. 'No findings so far' is NOT 'no vulnerabilities'; "
        "the authoritative answer is the finished run's report. Check "
        "strix_status until status=finished, then read strix_report."
    )
