"""Strix x Hermes plugin.

Registers (IMPL_PLAN §2):

- six ``strix_*`` tools via ``ctx.register_tool`` (toolset "strix")
- ``/pentest`` and ``/strix`` slash commands via ``ctx.register_command``
- ``pre_tool_call`` (authorization block) and ``transform_tool_result``
  (scan-reminder injection) hooks
- a ``strix:pentest`` opt-in skill via ``ctx.register_skill``

Loaded by hermes as a namespaced module — all internal imports are relative.
Nothing here imports strix at module scope, so the plugin also loads on
hermes' Python 3.11 (strix runs in its own 3.12 worker venv).
"""

from __future__ import annotations

from pathlib import Path


def register(ctx) -> None:
    from . import authz, broadcast, commands, config as cfgmod
    from . import strix_tools as tools

    cfg = cfgmod.load_config()

    ctx.register_command(
        name="pentest",
        handler=commands.handle_pentest,
        description=commands.PENTEST_DESCRIPTION,
        args_hint=commands.PENTEST_ARGS_HINT,
    )
    ctx.register_command(
        name="strix",
        handler=commands.handle_strix,
        description="Strix plugin state / health / history",
        args_hint="[status|history|health]",
    )

    for d in tools.tool_defs():
        ctx.register_tool(
            name=d["name"],
            toolset="strix",
            schema=d["schema"],
            handler=d["handler"],
            is_async=True,
            description=d["description"],
            emoji=tools.EMOJI.get(d["name"], ""),
        )

    skill_md = Path(__file__).resolve().parent / "skills" / "strix" / "SKILL.md"
    if skill_md.exists():
        ctx.register_skill(
            name="pentest",
            path=skill_md,
            description="Authorized Strix autonomous pentest — when to scan, "
                        "authorization discipline, result handling",
        )

    ctx.register_hook(
        "pre_tool_call",
        lambda *a, **kw: authz.pre_tool_call_hook(cfg, *a, **kw),
    )
    ctx.register_hook(
        "transform_tool_result",
        lambda *a, **kw: authz.transform_tool_result_hook(cfg, *a, **kw),
    )
    ctx.register_hook(
        "pre_gateway_dispatch",
        broadcast.pre_gateway_dispatch_hook,
    )