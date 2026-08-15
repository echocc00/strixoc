"""Slash commands: ``/pentest <target> [--mode quick|standard|deep]
[--budget N] [--confirm-authorized]`` and ``/strix [status|history|health]``.

Handlers take ``(raw_args: str) -> str`` and may be async.  They work
verbatim from CLI and from gateway (Feishu/Telegram) sessions.
"""

from __future__ import annotations

import getpass
import shlex
from typing import Any

from .runner import AuthError, get_manager

PENTEST_ARGS_HINT = "<target> [--mode quick|standard|deep] [--budget 5] [--confirm-authorized]"
PENTEST_DESCRIPTION = "Run an authorized Strix autonomous pentest scan"


class _Usage(Exception):
    pass


def _parse_pentest(raw: str) -> dict[str, Any]:
    try:
        toks = shlex.split(raw or "")
    except ValueError as exc:
        raise _Usage(f"unparseable arguments: {exc}") from exc
    if not toks:
        raise _Usage(
            "no target given — usage: /pentest <target> [--mode ...] [--budget N] "
            "[--confirm-authorized]"
        )
    if toks[0].startswith("-"):
        raise _Usage("first argument must be the target")
    target = toks[0]
    mode, budget, confirm = "quick", None, False
    i = 1
    while i < len(toks):
        tok = toks[i]
        if tok == "--mode":
            i += 1
            mode = toks[i] if i < len(toks) else ""
            if mode not in ("quick", "standard", "deep"):
                raise _Usage(f"unknown scan mode {mode!r} (quick|standard|deep)")
        elif tok == "--budget":
            i += 1
            try:
                budget = float(toks[i]) if i < len(toks) else None
            except ValueError as exc:
                raise _Usage("--budget expects a number") from exc
        elif tok == "--confirm-authorized":
            confirm = True
        else:
            raise _Usage(f"unknown flag {tok!r}")
        i += 1
    return {"target": target, "mode": mode, "budget": budget, "confirm": confirm}


async def handle_pentest(raw_args: str = "", **kw: Any) -> str:
    try:
        p = _parse_pentest(raw_args)
    except _Usage as exc:
        return f"⛔ /pentest usage error: {exc}\n\nUsage: /pentest {PENTEST_ARGS_HINT}"
    user_id = str(kw.get("user_id") or "") or getpass.getuser()
    chat_id = str(kw.get("chat_id") or "") or "cli"
    try:
        rec = await get_manager().start(
            target=p["target"],
            scan_mode=p["mode"],
            budget=p["budget"],
            user_instructions="",
            chat_id=chat_id,
            user_id=user_id,
            confirm=p["confirm"],
        )
    except AuthError as exc:
        reason = exc.decision.reason
        fix = {
            "target_not_allowed": "add it to `allowed_targets` in ~/.hermes/strix.yaml",
            "confirm_required": "re-run with `--confirm-authorized` after confirming the "
            "target is yours / you are authorized to test it",
            "chat_not_allowed": "ask the operator to add this chat to `allowed_chats`",
            "budget_over_cap": "lower `--budget` below `max_budget_cap`",
        }.get(reason, "see ~/.hermes/logs/strix-audit.jsonl")
        return f"⛔ **Scan blocked** — {reason}.\nTarget: `{p['target']}`\nFix: {fix}"
    return (
        f"🔒 **Strix scan started**\n\n"
        f"- scan_id: `{rec.scan_id}`\n- target: `{rec.target}`\n"
        f"- mode: `{rec.scan_mode}` · budget: `${rec.budget or 0:g}`\n\n"
        f"Poll with `/strix status` or tell the agent to check `strix_status`; "
        f"read the report with `strix_report` once it is `finished`."
    )


async def handle_strix(raw_args: str = "", **kw: Any) -> str:
    sub = (raw_args or "").strip().split()[0] if (raw_args or "").strip() else ""
    mgr = get_manager()
    if sub == "history":
        rows = mgr.history(limit=10)
        if not rows:
            return "No scans recorded yet."
        lines = ["**Recent scans:**"]
        for r in rows:
            sev = ", ".join(f"{k}={v}" for k, v in r.get("by_severity", {}).items()) or "none"
            lines.append(
                f"- `{r['scan_id']}` · {r['status']} · {r['target']} · "
                f"{r['scan_mode']} · vulns: {r.get('vuln_count', 0)} ({sev})"
            )
        return "\n".join(lines)
    health = mgr.health()
    running = health.get("running_scans") or []
    lines = ["**Strix state**"]
    if running:
        lines += [f"- running: {r['scan_id']} -> {r['target']}" for r in running]
    else:
        lines.append("- running: none")
    lines.append(f"- backend: {health.get('backend')}")
    lines.append(f"- worker_python configured: {health.get('worker_python_configured')}")
    lines.append(f"- allowlist: {', '.join(health.get('allowed_targets') or [])}")
    lines.append(
        f"- budget: default ${health.get('max_budget_default')} "
        f"/ cap ${health.get('max_budget_cap')}"
    )
    lines.append("- commands: `/pentest <target> [--mode ...] [--budget N] [--confirm-authorized]`")
    return "\n".join(lines)
