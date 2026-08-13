# Strix × Hermes — 集成插件

Hermes 插件，把 **Strix**（自主渗透测试 agent）接入 Hermes 的 CLI / Gateway（飞书 / Telegram / Web 等全端复用）。

**架构**（与 IMPL_PLAN.md 一致）：

```
Hermes (python >= 3.11)                  Strix worker (python >= 3.12)
┌─────────────────────────────┐          ┌──────────────────────────────┐
│ plugin (~/.hermes/plugins/  │  spawn   │ worker.py + strix-agent      │
│  strix/)                    │ ───────▶ │ (自己的 venv；own docker      │
│  ├ 6 strix_* tools          │  JSON-   │  socket，rootless docker 推荐)│
│  ├ /pentest /strix 命令     │  lines   │  ReportState → run_strix_scan│
│  ├ pre_tool_call 授权拦截   │ ◀─────── │  → strix_runs/<id>/ 报告文件  │
│  └ ScanManager 注册表/审计   │ phase/vuln/cost 流                     │
└─────────────────────────────┘          └──────────────────────────────┘
```

- 关键点：`run_strix_scan` **不会**自建 `ReportState`（strix/core/runner.py 只读全局）；worker 里先
  `ReportState` + `set_global_report_state` 再调 scan，否则 `finish_scan` 只 warn 不落盘、拿不到任何报告。
- 为什么 worker 独立进程：strix 要求 python>=3.12 且 `openai>=2.45`，hermes 装的是 python 3.11 + `openai==2.24` —— 双约束下无法同 venv 共存。
  详情见 `runbook/NAS_WORKER.md`。

## 目录

```
plugin/            Hermes 插件本体（部署时整个目录拷贝到 ~/.hermes/plugins/strix/）
  __init__.py      register(ctx)：工具/命令/hook/skill 注册
  config.py        ~/.hermes/strix.yaml 配置
  authz.py         白名单 + 授权决策 + 审计日志 + hook
  backends.py      InProcessBackend / WorkerBackend + scan_config 构建
  runner.py        ScanManager：生命周期 / 注册表 / 取消 / 持久化
  strix_tools.py   6 个工具（strix_scan/status/report/cancel/history/health）
  commands.py      /pentest 与 /strix
  worker.py        进程入口（worker venv 里跑）
  worker_runtime.py 核心：ReportState dance + 事件流 + 落盘读取
  skills/strix/SKILL.md  模型可见行为规范
tests/             pytest（含真实 hermes PluginManager 加载 + 真实 strix 落盘测试）
scripts/verify_env.py  环境验证（本机 + 可传 STRIX_WORKER_PYTHON 查 worker/docker）
runbook/           部署与 NAS 运维手册
```

## 快速开始

```bash
# 1) 部署插件（任何一台跑 hermes 的机器）
cp -r plugin/ ~/.hermes/plugins/strix/          # Windows: %LOCALAPPDATA%\hermes\plugins\strix\
hermes plugins enable strix

# 2) 配置 worker（见 runbook/NAS_WORKER.md 在 NAS 建 python3.12 venv + strix）
#    ~/.hermes/strix.yaml:
allowed_targets: [localhost, "127.0.0.1", "::1", "*.internal", "*.local"]
require_authorized_flag: true
max_budget_default: 5.0
max_budget_cap: 25.0
worker_python: /volume1/soft/StrixWorker/venv/bin/python   # 留空则查 STRIX_WORKER_PYTHON
audit_log: "~/.hermes/logs/strix-audit.jsonl"

# 3) 验证
python scripts/verify_env.py

# 4) 扫（CLI 或飞书里都一样）
/pentest http://localhost:3000 --mode quick --confirm-authorized
/strix status
```

## 开发 / 测试

```bash
py -3.12 -m venv .venv
.venv/Scripts/python -m pip install -e strix_repo pytest pytest-asyncio   # 真实 strix 落盘测试
.venv/Scripts/python -m pytest tests/
```

- `tests/test_artifacts_real.py` 是承重点测试：**真实** ReportState + 真实落盘，只桩掉 `run_strix_scan`；
  证明了「自建 ReportState → 扫完 → penetration_test_report.md / vulnerabilities.json /
  findings.sarif / run.json 全部落盘」这条 MVP 关键闭环。
- `tests/test_hermes_real_load.py` 用真实 `PluginManager`（HERMES_HOME 隔离）验证加载、工具注册和 hook 拦截。

## 安全边界

1. `allowed_targets` 静态白名单（exact / `*.domain` / `prefix.*` / CIDR / URL 前缀），默认deny，不解析 DNS
2. `pre_tool_call` hook 直接 block（不让 LLM 看到结果），`require_authorized_flag` 强制显式确认
3. `transform_tool_result` 注入 reminder：不要早 cancel、扫完没东西 ≠ 没漏洞
4. 全量审计 `~/.hermes/logs/strix-audit.jsonl`（ts/chat/user/target/decision/scan_id）
5. 预算三档：默认 `max_budget_default`、上限 `max_budget_cap`、`strix_cancel` 可随时停
6. Docker socket 只在 worker 进程可见（NAS 上 rootless docker 或 docker 组，见 runbook）