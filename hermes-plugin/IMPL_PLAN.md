# Strix × Hermes 集成 — 实现方案（已对拍真实 API）

> 整理日期: 2026-08-13 (Asia/Shanghai)
> 本文档 = 设计文档 `_research/HERMES_STRIX.md` 的**落地修正版**（设计文档在本地代码库，未随本仓库分发）
> 前置阅读: `PROJECT_OVERVIEW.md`（项目全景，本地）
> 源码参考: Hermes 源码仓库本地副本 / Strix 源码（即本 fork 的 strix/ 目录）
> 状态: 调研 + 设计已落地，实现尚未开始。本文档是动手前的最后一份核对稿。

---

## 0. 一句话总结

**目标不变**：Hermes-Agent 做用户入口/框架，Strix 做「自主渗透测试能力」，通过 plugin + skill + slash + delegate_task 五件套集成，一次集成全端复用（CLI/TUI/Desktop/Web/飞书/Telegram/...）。

**本文档的核心增量**：设计文档的 5 层架构方向正确，但里面有多处**伪代码会直接踩空**。本文逐条把「文档写的」对齐到「真实 API」，并补上了一个设计文档漏掉的**致命环节**（Strix 报告写入必须自建 `ReportState`）。

---

## 1. 现状核实：设计文档 vs 真实 API

> 这是动手前最关键的一节。下面每一项都已在源码里核对到具体文件 + 行号。

| # | HERMES_STRIX.md 写的 | 真实 API（已核对） | 后果 |
|---|---|---|---|
| 1 | `ctx.register_toolset("strix", [...])` | 无此方法。真实是逐工具 `ctx.register_tool(name, toolset, schema, handler, ...)`（`hermes_cli/plugins.py:439`） | 照抄直接 AttributeError |
| 2 | `from agent.tool import FunctionTool` | 无 `FunctionTool` / `@tool` 装饰器。真实是 `tools.registry.registry.register(...)`（`tools/registry.py:562`） | 工具定义方式整个错 |
| 3 | hook 名 `agent:start` | 真实是 `on_session_start`（`hermes_cli/plugins.py:161`） | 该 hook 静默不触发 |
| 4 | `/pentest` 写进 `COMMAND_REGISTRY`（改 core） | 插件可 `ctx.register_command(name, handler, description, args_hint)`（`hermes_cli/plugins.py:577`），无需改 core | 设计走了最重的路径 |
| 5 | `pentest_specialist` 子 agent 用 YAML | 子 agent 是运行时 `AIAgent()` 构造，经 `delegate_task(goal, role, ...)`（`tools/delegate_tool.py:3132`） | YAML 文件不会被加载 |
| 6 | `event_sink("vulnerability_found", ...)` 有自定义事件枚举 | `event_sink` 只透传 OpenAI Agents SDK **raw event**，签名 `Callable[[str, Any], None]`（`strix/core/runner.py:62`）；漏洞实时回调走 **`ReportState.vulnerability_found_callback`**（`strix/report/state.py:142`） | 实时推送逻辑整个错 |
| 7 | **漏了**：报告文件（`penetration_test_report.md` 等）怎么来的 | `ReportState` 只在 `cli.py:101` / `tui/runtime.py:90` 创建，`run_strix_scan()` **内部不创建**；`finish_scan` 工具拿不到时只 warn 不落盘（`strix/tools/finish/tool.py:50-58`） | **Hermes 直接调 `run_strix_scan` 扫完拿不到任何报告** |

### 1.1 真实 API 速查表（落地时直接照抄）

**Hermes 插件扩展点**（`hermes_cli/plugins.py`）：

```python
def register(ctx) -> None:
    # 工具：逐工具注册，toolset 会被 get_toolset() 自动合并
    ctx.register_tool(name=..., toolset="strix", schema={...},
                      handler=..., is_async=True, description=..., emoji=...)

    # slash 命令：handler(raw_args: str) -> str | None，可 async
    ctx.register_command("pentest", handler, description=..., args_hint="...")

    # hook：真实 hook 名见 VALID_HOOKS
    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
    ctx.register_hook("transform_tool_result", _on_transform_tool_result)
```

真实 hook 名（`hermes_cli/plugins.py:136-219`）：`pre_tool_call` / `post_tool_call` / `transform_tool_result` / `pre_llm_call` / `post_llm_call` / `on_session_start` / `on_session_end` / `subagent_start` / `subagent_stop` / ...（**无 `agent:start`**）。

**Strix Python API**（`strix/core/runner.py:111-127`）：

```python
async def run_strix_scan(
    *,
    scan_config: dict[str, Any],        # 必填
    scan_id: str | None = None,
    image: str,                          # 必填，无默认值
    local_sources: list[dict] | None = None,
    coordinator: AgentCoordinator | None = None,
    interactive: bool = False,
    max_turns: int = DEFAULT_MAX_TURNS,
    max_budget_usd: float | None = None,
    model: str | None = None,
    cleanup_on_exit: bool = True,
    event_sink: Callable[[str, Any], None] | None = None,   # (agent_id, raw_event)
    root_instructions_override: str | None = None,
    extra_system_prompt_context: dict[str, Any] | None = None,
    status_sink: Callable[[str], None] | None = None,       # (phase)
) -> RunResultBase | None:
```

> 注意：全部参数**关键字限定**，不能按位置传；`image` 必填。

---

## 2. 修正后的架构

方向不变（Hermes 入口 + Strix 能力 + 5 层），只改每个落点用的 API：

```
Hermes Gateway（已有，不动）
   │
   ├─ 插件 plugins/security/strix/plugin.yaml + __init__.py:register(ctx)
   │     ctx.register_tool(...)         ×6   ← 真实（替代 register_toolset）
   │     ctx.register_command("pentest", ...) ← 真实（slash 不用改 core）
   │     ctx.register_hook("pre_tool_call", ...)        ← 真实
   │     ctx.register_hook("transform_tool_result", ...) ← 真实
   │
   ├─ runner.py  StrixRunner（核心：包 run_strix_scan + 自建 ReportState）
   │
   ├─ skills/security/strix/SKILL.md（markdown，给 LLM 看）
   │
   ├─ delegate_task（真实机制，子 agent 运行时构造，非 YAML）
   │
   └─ 多端复用（Feishu 等 platform 已存在，零改动）
```

---

## 3. 技术设计（真实 API 逐条落地）

### 3.1 工具定义 — 用 `ctx.register_tool`

每个工具一个 schema dict + 一个 handler。以 `strix_scan` 为例：

```python
STRIX_SCAN_SCHEMA = {
    "name": "strix_scan",
    "description": "启动 Strix 自主渗透测试（需授权）",
    "parameters": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "URL/domain/IP/repo"},
            "scan_mode": {"type": "string", "enum": ["quick", "standard", "deep"],
                          "default": "quick"},
            "max_budget_usd": {"type": "number", "default": 5.0},
        },
        "required": ["target"],
    },
}

def register(ctx):
    ctx.register_tool(
        name="strix_scan", toolset="strix",
        schema=STRIX_SCAN_SCHEMA, handler=_handle_strix_scan,
        is_async=True, description="...", emoji="🔒",
    )
```

> **待 Phase 1 对拍**：handler 的精确签名（`args: dict` + `**kw`?）要和内置 async 工具范例对一遍。参考 `tools/delegate_tool.py:4339` 的注册写法 `lambda args, **kw: ...`。toolset 名 `"strix"` 会被 `get_toolset()` 的 `include_registry=True` 逻辑自动合并，无需手动写进 `TOOLSETS` 字典。

### 3.2 报告写入 — 必须自建 `ReportState`（第 7 项，最关键的修正）

`run_strix_scan` 不创建 `ReportState`，Hermes 必须自己复刻 `cli.py:101-137` 的初始化逻辑：

```python
from strix.report.state import ReportState, set_global_report_state
from strix.core.runner import run_strix_scan

async def _run_scan(scan_id, scan_config, image, max_budget, on_vuln, on_phase):
    # 关键三步：cli.py:101-137 的逻辑，Hermes 必须复刻
    report_state = ReportState(scan_id)          # run_name = scan_id
    report_state.set_scan_config(scan_config)
    report_state.save_run_data()
    report_state.vulnerability_found_callback = on_vuln   # 实时漏洞 → gateway
    set_global_report_state(report_state)

    try:
        await run_strix_scan(
            scan_config=scan_config,
            scan_id=scan_id,
            image=image,
            max_budget_usd=max_budget,
            max_turns=500,
            interactive=False,
            event_sink=on_event,     # (agent_id, raw_event)，只用来记 cost/调试
            status_sink=on_phase,    # (phase)："Waiting for the first model response" 等
            cleanup_on_exit=True,
        )
    finally:
        report_state.cleanup()
```

> 只要 `set_global_report_state()` 在 `run_strix_scan` 之前调用，Strix agent 内部调 `finish_scan` 工具时就会写到 `strix_runs/<scan_id>/` 下的 `penetration_test_report.md` / `vulnerabilities.json` / `findings.sarif` / `run.json`。

### 3.3 scan_config 的真实结构（`strix/core/inputs.py`）

`build_root_task()` 和 `set_scan_config()` 读取的字段：

```python
scan_config = {
    "targets": [
        {"type": "web_application", "details": {"target_url": target}},   # URL
        # {"type": "ip_address",    "details": {"target_ip": ...}},        # IP
        # {"type": "repository",    "details": {"target_repo": ...}},      # repo
        # {"type": "local_code",    "details": {"target_path": ...}},      # 本地代码
        # {"type": "api_spec",      "details": {"target_spec": ..., "base_urls": [...]}},
    ],
    "user_instructions": instruction,   # 凭据 / 重点 / scope 规则
    "scan_mode": scan_mode,             # quick / standard / deep
    "run_name": scan_id,
    "non_interactive": True,
}
```

> target 的 `type` 必须是这五选一，`details` 里的 key 要精确（`target_url` 不是 `url`）。错了 Strix agent 就不知道扫什么。

### 3.4 实时反馈 — 双通道，别再用杜撰的枚举

| 信息 | 真实来源 | 推给 Hermes 的方式 |
|---|---|---|
| 阶段（sandbox 就绪 / 首次响应 / compacting…） | `status_sink(phase: str)` | 直接 broadcast |
| **发现漏洞** | `ReportState.vulnerability_found_callback(report: dict)` | `on_vuln` → gateway |
| LLM cost | `event_sink(agent_id, raw_event)` 里 usage 字段 | 采样后供 `strix_status` 读 |
| 最终报告 | 扫完读 `strix_runs/<scan_id>/` | `strix_report` |

### 3.5 slash 命令 — 用 `ctx.register_command`，不碰 core

```python
def register(ctx):
    ctx.register_command(
        name="pentest",
        handler=handle_pentest,       # fn(raw_args: str) -> str，可 async
        description="Run a Strix pentest (requires authorization)",
        args_hint="<target> [--mode quick|standard|deep] [--budget 5]",
    )
```

比设计文档的路（改 `hermes_cli/commands.py`）轻得多，且 CLI 和 gateway（飞书/Telegram）**同时生效**。

### 3.6 子 agent — 用 `delegate_task`，不是 YAML

`delegate_task` 真实签名（`tools/delegate_tool.py:3132`）：

```python
delegate_task(goal=None, context=None, tasks=None, max_iterations=None,
              role=None, background=None, output_schema=None, parent_agent=None)
```

做法：把 SKILL.md 全文内联进 `goal`，`role="leaf"` 防递归委派。子 agent 的 toolset 范围靠 `DELEGATE_BLOCKED_TOOLS` 黑名单 + `role` 控制，**不是**靠 YAML 里的 `toolsets:` 字段。

### 3.7 授权 — `pre_tool_call` hook（逻辑保留，签名对拍）

设计文档的授权思路正确（chat 白名单 + target 正则 + audit log）。落地时：

- hook 名用 `pre_tool_call`（真实存在）
- 拦截返回 block 的字段名，**先拿 `plugins/security-guidance/__init__.py:257` 对拍**，别照抄文档里的 `{"action": "block", ...}`
- audit log 写 `~/.hermes/logs/strix-audit.jsonl`（`json.dumps(..., ensure_ascii=False)` 保证中文不乱码）

---

## 4. 数据流（修正版，一次 `/pentest app.example.com`）

```
[用户在飞书/Telegram/CLI 发 /pentest]
   ↓
[Hermes Gateway 路由到 session]（已有，不动）
   ↓
[插件注册的 /pentest handler]（ctx.register_command）
   ↓
[StrixRunner.start_scan() → asyncio.Task]
   ↓
[自建 ReportState(run_name=scan_id) + set_global_report_state]   ← 关键修正
   ↓
[run_strix_scan(scan_config, image=..., status_sink=on_phase)]
   ↓
[Docker Kali 沙箱启动 → 多 agent 编排]
   ↓
[on_phase(phase) → broadcast 阶段进度]                            ← status_sink
[on_vuln(report) → broadcast "🔴 Critical ×1"]                    ← vulnerability_found_callback
   ↓
[Strix agent 调 finish_scan → ReportState 写报告到 strix_runs/<id>/]
   ↓
[StrixRunner 收尾 → strix_report 读报告 → Hermes 发回飞书文件消息]
```

---

## 5. 安全边界（保留设计文档 5 道，补 Docker 决策）

1. `~/.hermes/strix.yaml` 显式白名单（默认只允许 localhost / staging / `.internal`）
2. `pre_tool_call` hook 直接 block 未授权 chat/target（不让 LLM 看到 result）
3. `transform_tool_result` 注入 reminder（不要早 cancel、不要把「扫完没东西」==「没漏洞」）
4. audit log 到 `~/.hermes/logs/strix-audit.jsonl`（含 ts / chat_id / user_id / target / action）
5. `max_budget_usd` 三档警告 + 强制 stop
6. **Docker socket**：Strix 用 `docker.from_env()`（`strix/runtime/backends.py:45`），需要宿主机 socket。**推荐 rootless docker 或独立 worker 进程**，别让 Hermes 直接挂 socket 拿主机 root。

---

## 6. 分阶段路线图（修正版）

### Phase 0 — 环境验证（半天，先做）
1. 确认能跑 `docker.from_env()`（需要 socket 可达）
2. 确认 `strix-agent` 可 pip 装、`run_strix_scan` 能跑通最小 scan
3. 确认 Hermes `hermes doctor` 能加载一个 plugin

### Phase 1 — MVP 单机闭环（1 周）
1. 建 `plugins/security/strix/` 骨架，**用 `security-guidance` 插件当模板**（不是照抄设计文档伪代码）
2. `runner.py` 里**先打通「自建 ReportState → run_strix_scan → 读 strix_runs 报告」**——最承重、最易被误导的点
3. 6 个 tool 用 `ctx.register_tool` 注册，先跑通 `strix_scan` → `strix_report`
4. `authz.py` 白名单 + audit log（逻辑照文档，签名对齐真实 hook）
5. `--confirm-authorized` 硬门槛

**MVP 验收**（比文档更聚焦）：CLI 里 `/pentest http://localhost:3000 --mode quick`，扫完**能读到 `penetration_test_report.md`**。这一步过了，整个方案才成立。

### Phase 2 — 飞书/Telegram 实时（1 周）
1. `vulnerability_found_callback` + `status_sink` → gateway broadcast
2. 飞书侧验证进度卡（复用已有 Feishu platform plugin，零代码）
3. e2e：飞书发 `/pentest` → 进度卡 → 报告文件

### Phase 3 — 子 agent + 授权加固（1 周）
1. `delegate_task` 版 pentest_specialist（`goal` 内联 skill，`role="leaf"`）
2. `pre_tool_call` 授权拦截对拍 `security-guidance`
3. Docker socket 安全加固

### Phase 4 — 高级（持续）
memory 复用 / Cron 周扫 / 飞书云文档 / MCP 化 / CI-CD

---

## 7. 三个待拍板决策点

1. **MVP 先 CLI 还是先飞书？** → 建议先 CLI：飞书进度卡依赖事件流，事件流依赖 MVP 数据流跑通，顺序不能反。
2. **Docker 在哪跑？** → NAS 为主要环境的话，用 rootless docker 或独立 worker，而非 Hermes 直接挂 socket。
3. **Strix 走 Python API 还是 subprocess CLI？** → 推荐 Python API（能拿到 `vulnerability_found_callback` + `status_sink`，实时反馈必需），代价是 `strix-agent` 要进 Hermes 依赖环境。

---

## 8. 关键代码引用索引

| 用途 | 路径 |
|---|---|
| 插件加载 / `register(ctx)` 入口 | `hermes_repo/hermes_cli/plugins.py:1903` |
| `ctx.register_tool` | `hermes_repo/hermes_cli/plugins.py:439` |
| `ctx.register_command`（slash） | `hermes_repo/hermes_cli/plugins.py:577` |
| `ctx.register_hook` + `VALID_HOOKS` | `hermes_repo/hermes_cli/plugins.py:1214` / `:136-219` |
| 现成插件范例（hook） | `hermes_repo/plugins/security-guidance/__init__.py:257` |
| 工具注册 `registry.register` | `hermes_repo/tools/registry.py:562` |
| `delegate_task` 签名 | `hermes_repo/tools/delegate_tool.py:3132` |
| Strix 主入口 `run_strix_scan` | `strix_repo/strix/core/runner.py:111-127` |
| `ReportState` / `vulnerability_found_callback` | `strix_repo/strix/report/state.py:104` / `:142` |
| `set_global_report_state` | `strix_repo/strix/report/state.py:97` |
| CLI 如何初始化 ReportState | `strix_repo/strix/interface/cli.py:101-137` |
| `scan_config` 结构 | `strix_repo/strix/core/inputs.py:82`（build_root_task） |
| `finish_scan` 落盘逻辑 | `strix_repo/strix/tools/finish/tool.py:48-58` |
| Docker socket 入口 | `strix_repo/strix/runtime/backends.py:45` |

---

## 9. 一句话总结

> 设计文档的方向对，但落地的关键是**别照抄它的伪代码**。真正的承重点只有一个：**Hermes 调 Strix 时必须自己 `ReportState` + `set_global_report_state`，否则扫完拿不到报告**；其余是工具/命令/子 agent/hook 四处 API 名字的纠正。按 §6 的 Phase 1 先跑通「自建 ReportState → run_strix_scan → 读报告」这条最小闭环，方案就成立。
