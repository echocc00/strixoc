"""The six Strix tools exposed to the model.

All handlers take ``(args: dict, **kw)`` (registry calls ``handler(args, **kw)``)
and return a JSON string — including error cases — so the model always gets a
readable, structured result.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .backends import read_run_artifacts
from .runner import AuthError, get_manager

EMOJI = {
    "strix_scan": "🔒",
    "strix_status": "📡",
    "strix_report": "📄",
    "strix_cancel": "⏹️",
    "strix_history": "🗂️",
    "strix_health": "🩺",
    "strix_delegate": "👥",
}

_SCAN_MODE_ENUM = {"type": "string", "enum": ["quick", "standard", "deep"], "default": "quick"}

TOOL_DEFS: list[dict[str, Any]] = [
    {
        "name": "strix_scan",
        "description": "Start an authorized Strix autonomous pentest scan. "
                       "Requires the target to be allowlisted in ~/.hermes/strix.yaml "
                       "and confirm_authorized=true. Returns a scan_id immediately; "
                       "the scan runs in the background.",
        "schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string",
                           "description": "URL / domain / IP to scan (e.g. http://localhost:3000)"},
                "scan_mode": _SCAN_MODE_ENUM,
                "max_budget_usd": {"type": "number", "description": "LLM budget cap in USD"},
                "user_instructions": {"type": "string",
                                      "description": "credentials, scope rules, focus areas"},
                "confirm_authorized": {"type": "boolean",
                                       "description": "MUST be true — operator authorization"},
            },
            "required": ["target", "confirm_authorized"],
        },
        "handler": "_scan",
    },
    {
        "name": "strix_status",
        "description": "Report scan status: running scans (default) or one scan by id.",
        "schema": {
            "type": "object",
            "properties": {
                "scan_id": {"type": "string"},
            },
        },
        "handler": "_status",
    },
    {
        "name": "strix_report",
        "description": "Read a finished scan's artifacts: summary (default), full "
                       "penetration_test_report.md, vulnerabilities.json, or findings.sarif.",
        "schema": {
            "type": "object",
            "properties": {
                "scan_id": {"type": "string"},
                "section": {"type": "string", "enum": ["summary", "report_md",
                                                       "vulns_json", "sarif"], "default": "summary"},
                "max_chars": {"type": "number", "default": 8000},
            },
            "required": ["scan_id"],
        },
        "handler": "_report",
    },
    {
        "name": "strix_cancel",
        "description": "Cancel a running scan by id.",
        "schema": {
            "type": "object",
            "properties": {"scan_id": {"type": "string"}},
            "required": ["scan_id"],
        },
        "handler": "_cancel",
    },
    {
        "name": "strix_history",
        "description": "Recent scans (id, target, status, severity counts).",
        "schema": {
            "type": "object",
            "properties": {"limit": {"type": "number", "default": 10}},
        },
        "handler": "_history",
    },
    {
        "name": "strix_health",
        "description": "Plugin/worker configuration health: backend, allowlist, caps.",
        "schema": {"type": "object", "properties": {}},
        "handler": "_health",
    },
    {
        "name": "strix_delegate",
        "description": "Delegate a pentest task to a leaf sub-agent (delegate_task, "
                       "role=leaf). Authorization gates the target first. Use for "
                       "parallel/focused investigation; the sub-agent can use the "
                       "strix tools itself.",
        "schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string",
                           "description": "URL / domain / IP the sub-agent may scan "
                                          "(checked against the allowlist)"},
                "goal": {"type": "string",
                         "description": "what the sub-agent should do; the pentest "
                                        "skill is inlined for you"},
                "confirm_authorized": {"type": "boolean",
                                       "description": "MUST be true"},
                "max_iterations": {"type": "number", "default": 8},
            },
            "required": ["target", "goal", "confirm_authorized"],
        },
        "handler": "_delegate",
    },
]


def _json(**kw: Any) -> str:
    return json.dumps(kw, ensure_ascii=False, default=str)


def _err(message: str, **kw: Any) -> str:
    return _json(ok=False, error=message, **kw)


async def _scan(args: dict, **kw: Any) -> str:
    target = str(args.get("target") or "").strip()
    if not target:
        return _err("target is required")
    confirm = bool(args.get("confirm_authorized", False))
    try:
        rec = await get_manager().start(
            target=target,
            scan_mode=str(args.get("scan_mode") or "quick"),
            budget=args.get("max_budget_usd"),
            user_instructions=str(args.get("user_instructions") or ""),
            chat_id=str(kw.get("chat_id") or "") or "cli",
            user_id=str(kw.get("user_id") or ""),
            confirm=confirm,
        )
    except AuthError as exc:
        return _err(
            f"scan blocked: {exc.decision.reason}",
            target=target, decision=exc.decision.reason, fix=_authz_fix(exc.decision.reason),
        )
    return _json(
        ok=True, scan_id=rec.scan_id, target=rec.target, scan_mode=rec.scan_mode,
        budget=rec.budget, status=rec.status,
        message="scan started — poll with strix_status until status=finished, "
                "then read with strix_report",
    )


def _authz_fix(reason: str) -> str:
    if reason == "target_not_allowed":
        return "add the target to allowed_targets in ~/.hermes/strix.yaml"
    if reason == "confirm_required":
        return "pass confirm_authorized=true"
    if reason == "chat_not_allowed":
        return "add this chat to allowed_chats in ~/.hermes/strix.yaml"
    return "see ~/.hermes/logs/strix-audit.jsonl"


def _pick(scan_id: str | None) -> list[dict[str, Any]]:
    if scan_id:
        row = get_manager().get(scan_id)
        return [row] if row else []
    return get_manager().list_scans(limit=10)


async def _status(args: dict, **kw: Any) -> str:
    scan_id = str(args.get("scan_id") or "").strip() or None
    rows = _pick(scan_id)
    if not rows:
        return _err("no matching scan", scan_id=scan_id)
    return _json(ok=True, scans=[
        {
            "scan_id": r["scan_id"], "status": r["status"], "target": r["target"],
            "scan_mode": r["scan_mode"], "phase": r.get("phase", ""),
            "vuln_count": r.get("vuln_count", 0), "by_severity": r.get("by_severity", {}),
            "error": r.get("error"), "run_dir": r.get("run_dir"),
            "created_at": r.get("created_at"), "updated_at": r.get("updated_at"),
        }
        for r in rows
    ])


async def _report(args: dict, **kw: Any) -> str:
    scan_id = str(args.get("scan_id") or "").strip()
    section = str(args.get("section") or "summary")
    max_chars = int(args.get("max_chars") or 8000)
    row = get_manager().get(scan_id)
    if not row:
        return _err("scan not found", scan_id=scan_id)
    run_dir = row.get("run_dir") or ""
    if not run_dir or not Path(run_dir).exists():
        if row.get("status") != "finished":
            return _err("scan has no artifacts yet", scan_id=scan_id, status=row.get("status"))
        return _err("scan finished but run dir missing", scan_id=scan_id, run_dir=run_dir)
    d = Path(run_dir)
    try:
        if section == "report_md":
            text = (d / "penetration_test_report.md").read_text(encoding="utf-8", errors="replace")
            return _json(ok=True, scan_id=scan_id, section="report_md",
                         content=text[:max_chars], truncated=len(text) > max_chars)
        if section == "vulns_json":
            data = (d / "vulnerabilities.json").read_text(encoding="utf-8", errors="replace")
            return _json(ok=True, scan_id=scan_id, section="vulns_json",
                         content=data[:max_chars], truncated=len(data) > max_chars)
        if section == "sarif":
            sarif = d / "findings.sarif"
            if not sarif.exists():
                return _err("no sarif artifact", scan_id=scan_id)
            data = sarif.read_text(encoding="utf-8", errors="replace")
            return _json(ok=True, scan_id=scan_id, section="sarif",
                         content=data[:max_chars], truncated=len(data) > max_chars)
        summary = read_run_artifacts(d)
        return _json(ok=True, scan_id=scan_id, section="summary", **summary)
    except OSError as exc:
        return _err(f"failed reading artifacts: {exc}", scan_id=scan_id)


async def _cancel(args: dict, **kw: Any) -> str:
    scan_id = str(args.get("scan_id") or "").strip()
    ok = get_manager().cancel(scan_id)
    return _json(cancelled=ok, scan_id=scan_id)


async def _history(args: dict, **kw: Any) -> str:
    limit = int(args.get("limit") or 10)
    rows = get_manager().history(limit=limit)
    return _json(ok=True, scans=[
        {"scan_id": r["scan_id"], "status": r["status"], "target": r["target"],
         "scan_mode": r["scan_mode"], "vuln_count": r.get("vuln_count", 0),
         "by_severity": r.get("by_severity", {}), "created_at": r.get("created_at")}
        for r in rows
    ])


async def _health(args: dict, **kw: Any) -> str:
    return _json(ok=True, **get_manager().health())


async def _delegate(args: dict, **kw: Any) -> str:
    from pathlib import Path

    target = str(args.get("target") or "").strip()
    goal = str(args.get("goal") or "").strip()
    confirm = bool(args.get("confirm_authorized", False))
    if not target or not goal:
        return _err("target and goal are required")
    try:
        get_manager().authorize_or_raise(
            target=target, chat_id=str(kw.get("chat_id") or "") or "cli",
            user_id=str(kw.get("user_id") or ""), confirm=confirm,
        )
    except AuthError as exc:
        return _err(f"delegate blocked: {exc.decision.reason}", target=target,
                    decision=exc.decision.reason, fix=_authz_fix(exc.decision.reason))

    skill_md = Path(__file__).resolve().parent / "skills" / "strix" / "SKILL.md"
    skill_text = skill_md.read_text(encoding="utf-8") if skill_md.exists() else ""
    full_goal = f"{goal}\n\n---\nPentest discipline (must follow):\n{skill_text}"
    try:
        # hermes' delegate_task — lazy import (plugin must load without hermes)
        from tools import delegate_tool  # type: ignore[import-not-found]

        result = delegate_tool.delegate_task(
            goal=full_goal,
            context=f"Authorized target to test: {target}",
            max_iterations=int(args.get("max_iterations") or 8),
            role="leaf",
            parent_agent=kw.get("parent_agent"),
        )
        return str(result) if result else _err("delegate_task returned no result")
    except Exception as exc:  # noqa: BLE001
        return _err(f"delegate_task failed: {type(exc).__name__}: {exc}")


HANDLERS = {
    "_scan": _scan, "_status": _status, "_report": _report,
    "_cancel": _cancel, "_history": _history, "_health": _health,
    "_delegate": _delegate,
}


def tool_defs() -> list[dict[str, Any]]:
    """Resolve handler strings to callables (keep module import tree flat)."""
    out = []
    for d in TOOL_DEFS:
        out.append({**d, "handler": HANDLERS[d["handler"]]})
    return out