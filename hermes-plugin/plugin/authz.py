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
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

DEFAULT_AUDIT_LOG = "~/.hermes/logs/strix-audit.jsonl"

# Rotation (DEV_PLAN 2.3): 10MB x 5 keeps the audit trail bounded on the NAS
# while old audit remains readable (strix-audit.jsonl.1 ... .5).
AUDIT_MAX_BYTES = 10 * 1024 * 1024
AUDIT_BACKUP_COUNT = 5

_audit_loggers: dict[str, logging.Logger] = {}


def _audit_logger(path: Path) -> logging.Logger | None:
    """Logger with one rotating file handler per resolved audit path.  Cached:
    audit is hot-path adjacent and re-creating handlers per call would both
    leak fds and race the rotation.  None if the file cannot be opened -
    auditing must never break the scan path."""
    key = str(path)
    lg = _audit_loggers.get(key)
    if lg is not None:
        return lg
    lg = logging.getLogger(f"strix.audit.{key}")
    lg.setLevel(logging.INFO)
    lg.propagate = False  # audit lines go to the audit file only
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            path,
            maxBytes=AUDIT_MAX_BYTES,
            backupCount=AUDIT_BACKUP_COUNT,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        lg.addHandler(handler)
    except OSError:
        return None
    _audit_loggers[key] = lg
    return lg


def _reset_audit_loggers() -> None:
    """Close and drop cached audit loggers.  Test helper - also releases the
    Windows file handles RotatingFileHandler keeps open."""
    for lg in _audit_loggers.values():
        for h in list(lg.handlers):
            h.close()
            lg.removeHandler(h)
    _audit_loggers.clear()


@dataclass
class AuthDecision:
    allowed: bool
    reason: str
    matched: str | None = None


@dataclass
class _RuleSet:
    """Compiled allowlist.  Host-family rules carry an optional pinned port;
    URL rules are parsed to parts and matched component-wise."""

    exact: list[tuple[str, int | None]] = field(default_factory=list)
    suffix: dict[str, int | None] = field(default_factory=dict)  # "*.domain"
    prefix: list[tuple[str, int | None]] = field(default_factory=list)  # "prefix.*"
    urls: list[TargetParts] = field(default_factory=list)  # full URL prefixes
    subnets: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, int | None]] = field(
        default_factory=list
    )

    @classmethod
    def from_rules(cls, rules: list[str]) -> _RuleSet:
        rs = cls()
        for r in rules or []:
            r = (r or "").strip().lower()
            if not r:
                continue
            if "://" in r:
                pt = parse_target(r)
                if pt is not None and pt.scheme and pt.userinfo is None:
                    rs.urls.append(pt)
                continue
            host, port = _split_rule_hostport(r)
            if host is None:
                continue
            if host.startswith("*."):
                rs.suffix[host[2:]] = port
            elif host.endswith(".*"):
                rs.prefix.append((host[:-2], port))
            else:
                try:
                    rs.subnets.append((ipaddress.ip_network(host, strict=False), port))
                except ValueError:
                    rs.exact.append((host, port))
        return rs


def hostname_of(target: str) -> str:
    """Strip scheme/userinfo/port/path down to the bare host or IP.
    Display-only helper (logs / audit); authorization goes through
    ``parse_target`` + ``target_allowed`` instead."""
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
    return t.strip().rstrip(".").lower()


def _host_is_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


# --- normalization pipeline (DEV_PLAN 3.1) ------------------------------------
#
# Every target passes through this fixed-order pipeline before any rule
# matching.  No step resolves DNS: all decisions are made on the literal
# host string (DNS-rebinding safe).  Unparseable / suspicious forms fail
# closed with a distinct reason so the audit trail shows *why*.

SUPPORTED_SCHEMES = {"http", "https"}
DEFAULT_PORTS = {"http": 80, "https": 443}
# Host-family rules (host / wildcard / CIDR) allow these explicit ports
# without the rule naming them; anything else must be listed as host:port.
ALLOWED_DEFAULT_PORTS = {80, 443}
# Rule suffix ":*" = authorize every port on that host/subnet/wildcard
# (explicit full-surface grant for authorized environment scans).  Sentinel
# internal to the port matcher.
ANY_PORT = -1
_HOST_CHARS = re.compile(r"^[a-z0-9_.-]+$")


@dataclass(frozen=True)
class TargetParts:
    raw: str
    scheme: str  # "" for bare host[:port]
    userinfo: str | None  # non-None ("" counts) -> always deny
    host: str  # lowercased, trailing dots stripped
    port: int | None  # explicit port only
    path: str  # path component; query/hash are dropped


def parse_target(target: str) -> TargetParts | None:
    """Normalize a scan target.  Returns None for anything that must not be
    matched at all: embedded whitespace or backslashes (parser-confusion
    vectors), invalid ports, empty/charset-weird hosts."""
    raw = (target or "").strip()
    if not raw or "\\" in raw or any(ch.isspace() for ch in raw):
        return None
    userinfo: str | None = None
    scheme = ""
    host = ""
    port: int | None = None
    path = ""
    try:
        if "://" in raw:
            u = urlparse(raw)
            scheme = (u.scheme or "").lower()
            netloc = u.netloc
            if "@" in netloc:
                userinfo = netloc.rsplit("@", 1)[0]
            host = u.hostname or ""
            if u.port is not None:
                port = u.port
            path = u.path or ""
        else:
            # bare host / host:port / [v6]:port - no scheme, path, query, userinfo
            if any(c in raw for c in "/?#"):
                return None
            host_part = raw
            if "@" in raw:
                userinfo, host_part = raw.rsplit("@", 1)
            m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", host_part)
            if m:
                host = m.group(1)
                port = int(m.group(2)) if m.group(2) else None
            elif host_part.count(":") >= 2:  # bare IPv6 literal
                host = host_part
            elif ":" in host_part:
                hs, ps = host_part.rsplit(":", 1)
                if not ps.isdigit():
                    return None
                host, port = hs, int(ps)
            else:
                host = host_part
    except ValueError:  # urlsplit port range/format errors
        return None
    host = host.lower().rstrip(".")
    if host:
        if ":" in host:
            if _host_is_ip(host) is None:  # colons only valid inside IPv6 literals
                return None
        elif not _HOST_CHARS.match(host):
            return None
    return TargetParts(raw=raw, scheme=scheme, userinfo=userinfo, host=host, port=port, path=path)


def _split_rule_hostport(rule: str) -> tuple[str | None, int | None]:
    """Split an operator-written host rule into (host, port|ANY_PORT|None).
    Rules are operator-owned; unparseable rules are dropped (fail closed)."""
    if rule.startswith("["):
        m = re.match(r"^\[([^\]]+)\](?::(\d+|\*))?$", rule)
        if not m:
            return None, None
        if m.group(2) is None:
            return m.group(1).lower(), None
        return m.group(1).lower(), ANY_PORT if m.group(2) == "*" else int(m.group(2))
    if rule.count(":") >= 2:  # bare IPv6 rule
        return (rule, None) if _host_is_ip(rule) is not None else (None, None)
    if rule.count(":") == 1:
        hs, ps = rule.rsplit(":", 1)
        if ps == "*":
            return hs.lower().rstrip("."), ANY_PORT
        if ps.isdigit():
            return hs.lower().rstrip("."), int(ps)
    return rule.lower().rstrip("."), None


def _is_suspicious_numeric(host: str) -> bool:
    """Integer / hex / octal IPv4 encodings (0x7f000001, 2130706433,
    0177.0.0.1).  ip_address already rejects these; anything numeric-shaped
    it rejects is an address-form bypass attempt, not a hostname."""
    if _host_is_ip(host) is not None:
        return False
    if re.fullmatch(r"0x[0-9a-f]+", host) or host.isdigit():
        return True
    parts = host.split(".")
    if len(parts) in (2, 3, 4):
        return all(p.isdigit() or re.fullmatch(r"0x[0-9a-f]+", p) for p in parts)
    return False


def _port_matches(
    target_port: int | None,
    rule_port: int | None,
    scheme: str,
    extra_ports: frozenset[int] = frozenset(),
) -> bool:
    """Port allowlisting: ``:*`` rules permit every port; host-family rules
    permit no explicit port, the standard web ports, or a port named in the
    global ``allowed_ports`` config; a pinned rule port matches only itself
    (or the scheme default when the target omits the port)."""
    if rule_port == ANY_PORT:
        return True
    if rule_port is not None:
        if target_port == rule_port:
            return True
        return target_port is None and DEFAULT_PORTS.get(scheme) == rule_port
    return target_port is None or target_port in ALLOWED_DEFAULT_PORTS or target_port in extra_ports


def _rule_port_label(port: int | None) -> str:
    if port is None:
        return ""
    return ":*" if port == ANY_PORT else f":{port}"


def _effective_port(pt: TargetParts) -> int | None:
    return pt.port if pt.port is not None else DEFAULT_PORTS.get(pt.scheme)


def target_allowed(
    target: str,
    rules: list[str],
    extra_ports: list[int] | set[int] | None = None,
) -> AuthDecision:
    pt = parse_target(target)
    if pt is None:
        return AuthDecision(False, "invalid_target")
    if pt.userinfo is not None:
        # user@host is a classic SSRF bypass (OWASP SSRF Prevention Cheat
        # Sheet): never legitimate in a scan target - deny outright
        return AuthDecision(False, "userinfo_not_allowed")
    if pt.scheme and pt.scheme not in SUPPORTED_SCHEMES:
        return AuthDecision(False, "scheme_not_allowed")
    if not pt.host:
        return AuthDecision(False, "invalid_target")
    if _is_suspicious_numeric(pt.host):
        return AuthDecision(False, "suspicious_ip_form")
    xports = frozenset(
        int(p) for p in (extra_ports or []) if isinstance(p, (int, str)) and str(p).isdigit()
    )
    rs = _RuleSet.from_rules(rules)
    host, port = pt.host, pt.port
    for ehost, eport in rs.exact:
        if host == ehost and _port_matches(port, eport, pt.scheme, xports):
            return AuthDecision(True, "ok", matched=ehost + _rule_port_label(eport))
    for domain, rport in rs.suffix.items():
        if (
            host.endswith("." + domain)
            and host != domain
            and _port_matches(port, rport, pt.scheme, xports)
        ):
            return AuthDecision(True, "ok", matched=f"*.{domain}" + _rule_port_label(rport))
    for prefix, rport in rs.prefix:
        if (
            host.startswith(prefix + ".")
            and host != prefix
            and _port_matches(port, rport, pt.scheme, xports)
        ):
            return AuthDecision(True, "ok", matched=f"{prefix}.*" + _rule_port_label(rport))
    ip = _host_is_ip(host)
    if ip is not None:
        for net, rport in rs.subnets:
            if ip in net and _port_matches(port, rport, pt.scheme, xports):
                # single-host CIDRs keep the plain-host label for audit clarity
                label = str(net) if net.num_addresses > 1 else str(net.network_address)
                return AuthDecision(True, "ok", matched=label + _rule_port_label(rport))
    for rpt in rs.urls:
        if pt.scheme != rpt.scheme or host != rpt.host:
            continue
        if _effective_port(pt) != _effective_port(rpt):
            continue
        rpath = (rpt.path or "").rstrip("/")
        tpath = pt.path or "/"
        if tpath == rpath or tpath.startswith(rpath + "/"):
            matched = f"{rpt.scheme}://{rpt.host}" + (f":{rpt.port}" if rpt.port else "")
            return AuthDecision(True, "ok", matched=matched + (rpath or "/"))
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
    d = target_allowed(
        str(target), cfg.get("allowed_targets") or [], extra_ports=cfg.get("allowed_ports")
    )
    if not d.allowed:
        # keep the specific reason (userinfo_not_allowed, scheme_not_allowed,
        # ...) - DEV_PLAN 3.2: the audit trail must show *why*
        return AuthDecision(False, d.reason, matched=d.matched)
    if cfg.get("require_authorized_flag", True) and not confirm:
        return AuthDecision(False, "confirm_required")
    return AuthDecision(True, "ok", matched=d.matched)


_PLUGIN_VERSION: str | None = None


def plugin_version() -> str:
    """Plugin version from plugin.yaml, stamped into every audit record
    (DEV_PLAN 3.2) so audit trails stay interpretable across releases."""
    global _PLUGIN_VERSION
    if _PLUGIN_VERSION is None:
        try:
            text = (Path(__file__).parent / "plugin.yaml").read_text(encoding="utf-8")
            m = re.search(r'^\s*version:\s*"?([^"\s]+)"?', text, re.M)
            _PLUGIN_VERSION = m.group(1) if m else "unknown"
        except OSError:
            _PLUGIN_VERSION = "unknown"
    return _PLUGIN_VERSION


def audit(cfg: dict[str, Any], *, action: str, ts: str | None = None, **fields: Any) -> None:
    """Append one JSON line to the audit log.  Never raises — auditing must
    not be able to break the scan path."""
    path = Path(os.path.expanduser(str(cfg.get("audit_log") or DEFAULT_AUDIT_LOG)))
    rec = {
        "ts": ts or datetime.now(UTC).isoformat(),
        "action": action,
        "plugin": plugin_version(),
        **fields,
    }
    lg = _audit_logger(path)
    if lg is None:
        return
    lg.info(json.dumps(rec, ensure_ascii=False))


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
    # DEV_PLAN 3.2: log the target both as received and as normalized, so an
    # auditor can reconstruct exactly what the matcher saw (deny reasons like
    # userinfo_not_allowed refer to the raw form).
    pt = parse_target(target)
    normalized = None if pt is None else pt.host + (f":{pt.port}" if pt.port else "")
    audit(
        cfg,
        action="tool_check",
        tool="strix_scan",
        chat_id=chat_id,
        user_id=user_id,
        target=target,
        normalized_target=normalized,
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
