# Changelog

All notable changes to the `hermes-plugin` (Strix × Hermes integration) are
documented here.  Plugin version is independent of the vendored strix-agent
version (upstream tracks its own releases).

## [0.4.0] - 2026-08-16

### Ops automation（DEV_PLAN 0.4.0 全项落地）

- **systemd unit 模板入 repo**（`runbook/systemd/hermes-strix-feishu.service.in`
  + `scripts/install_service.sh`）：NAS 网关 unit 从手工维护改为 repo 渲染
  （占位符 HERMES_HOME/ENV_FILE/LOCK_DIR/HERMES_BIN/PROFILE），重装/换机
  恢复 = 跑一次脚本（render -> daemon-reload -> enable --now）；`--print`
  可无副作用预览。模板契约有测试钉死（占位符集合、渲染无残留、INI 结构）。
- **产物 retention**（`scripts/prune_runs.py`）：清理超过 N 天（默认 30）的
  `strix_runs/<id>/`（含 PoC）；删除前把 run 摘要（status/漏洞数/成本）
  归档进 `strix_runs/index.jsonl`（1.x 趋势 diff 数据源）。默认 dry-run，
  `--apply` 才删；非扫描目录（无 run.json 且非 strix- 前缀）永不触碰；
  拒绝对文件系统根操作。standalone 无插件依赖，NAS cron 直接可用。
- **审计日志轮转**：`authz.audit` 从裸 open/append 切换为按路径缓存的
  RotatingFileHandler（10MB × 5，`strix-audit.jsonl.1`...），磁盘占用有界，
  旧审计可查；写入失败仍静默（审计不破坏扫描路径）。
- **故障告警**：scan 终态 cancelled/failed -> broadcast 飞书告警卡片
  （状态/原因/时长/已见漏洞数）；worker 心跳死亡（90s 超时）由 30s 看门狗
  检测 -> 同路径 `worker_dead` 告警 + 审计留痕（≤2min 可见）。配置
  `notify_on_failure`（默认开）与 `notify_chat_id`（固定运维群，经
  dispatch latch 的 send_to 路由，未 latch 回退当前会话）。

### 基线数据

133 tests（+33），0 skip；coverage 85.51%；ruff/mypy 全绿。

## [0.3.0] - 2026-08-16

### Quality gates（DEV_PLAN 0.3.0 全项落地）

- **本地发布门禁 `scripts/release_gate.py`**：hermes-agent 是本地私有框架，
  CI 永远装不上、金标套件在 CI 必然 skip。门禁在当前 venv 跑全套件并
  **断言 0 skip**，强制发布在「strix + hermes 双依赖」环境执行（发布前
  必跑，见 README / DEV_PLAN §5）。
- **CI 三 job**：新增 lint job（ruff check + ruff format --check + mypy）；
  py3.12 job 加覆盖率（`--cov-fail-under=75`，实测 85.2%）；py3.11 job
  改 `-rs` 让所有 skip 在日志可见 + step summary 提示发布走本地门禁。
- **ruff / mypy 基线**：pyproject.toml 新增 `[tool.ruff]`（py311 target，
  根 repo 规则子集）、`[tool.mypy]`（宽松基线，每版本收紧）、
  `[tool.coverage]`。全量格式化 + 修复全部 92 处 lint 发现（含 3 个真实
  类型注解 bug：`_all_listeners` 循环变量复用、`from_dict` Optional splat、
  worker 子进程 Optional 流）。
- **worker 心跳**：worker 每 30s emit `heartbeat`（首拍在启动后 30s）；
  ScanManager 记录 `last_heartbeat`，`strix_status` 输出
  `worker_alive` / `heartbeat_age_s`（90s 超时 = 3 个周期；启动 90s 宽限
  覆盖 spawn + strix import；in-process 后端恒 alive）。僵尸 worker 从
  "扫完 reconcile 才发现" 变为 "status 实时可见"。

### 基线数据

100 tests（+4 心跳），0 skip；coverage 85.19%；ruff/mypy 全绿。

## [0.2.1] - 2026-08-16

### Fixes

- **MCP gateway bridge（新模块 `plugin/mcp.py`）**：hermes v0.19/v0.20 的
  `gateway run` 被 `_command_has_dedicated_mcp_startup` 排除在 inline MCP
  discovery 之外、gateway executor 又不启动它 -- 配置的 `mcp_servers` 永远
  不会被发现。插件在 gateway 进程内触发 dashboard/CLI 同款的
  `start_background_mcp_discovery`（幂等、失败安全、5s 有界等待）。
- `register()` 外层异常不再静默 `pass`，降级为 debug 日志（桥模块自身已
  warning，双层吞噬会掩盖插件安装损坏）。
- `plugin.yaml` 版本追平（0.1.0 -> 0.2.1；0.2.0 发布时漏 bump，只改了
  pyproject.toml）。
- `test_mcp.py` 测试隔离：真 hermes 已导入时 `from hermes_cli import
  mcp_startup` 走包属性、绕过 `sys.modules` 里的 fake（曾触发真实
  discovery 线程）；missing-hermes 用例改用 `sys.modules=None` 语义。

### Ops

- NAS_WORKER.md 新增 §10 进程托管：飞书网关 systemd 守护
  （`hermes-strix-feishu.service`，Restart=always，自愈已实测）。

## [0.2.0] - 2026-08-14

### Architecture (interface-agent doctrine)

- **Hermes = 接口/网关层，只做任务下发与汇报**；Strix = 执行层，方法学/多 agent
  编排/报告全部在 Strix 内部 —— 角色边界写入 README 与 SKILL.md。
- **删除 `strix_delegate` 工具**（委派/编排属于执行层）；工具集收敛为 6 个
  （scan/status/report/cancel/history/health）。
- SKILL.md 重写为「接口纪律」：原样下发、确认授权、不组装子任务、不早 cancel。

### Fixes (production hardening, all field-verified)

- **cancelled/failed 记录不再丢 run_dir**：worker 的 cancelled/failed 终态事件
  携带 run_dir 回写记录；reconcile 放宽为只要有盘上产物就挂 run_dir + 计数
  （修复飞书侧 `scan no artifacts yet` 但漏洞已在盘上的记录脱节）。
- **`@hermes:` 令牌解析钉死**：新增 `hermes_config_path` 配置项 + 默认 home 回退，
  适配 hermes 命名 profile 对 HERMES_HOME 的运行时改写（修复 401 无 key 扫描）。
- **broadcast source 布局兼容**：v0.19.1 MessageEvent 的身份字段在 `event.source`
  上（旧版直接读 `event.platform/chat_id` 会 skip，飞书进度推送因此失效）。
- **命令路径授权拒绝留痕**：`scan_start_denied` / `authz_denied` 写入审计。
- worker emit 断管容错、spawn 脱离会话（start_new_session）等黄金路径修复保留。

### CI

- GitHub Actions（`hermes-plugin-ci.yml`）：py3.12 + strix-agent（真实落盘套件） +
  py3.11（hermes 侧套件）。

## [0.1.0] - 2026-08-13

- 初始集成：6 工具 + `/pentest` `/strix` + 授权/审计 + worker 进程
  （ReportState 自建、事件流、报告读取）+ SKILL + NAS 部署 runbook。
- 双环境验收：NAS 真实扫描（11/9 个真实漏洞）、hermes v0.19.1 黄金路径会话、
  飞书全链路（下发 → 授权 → 扫描 → 汇报）。
- 测试：93+ 项（含真实 strix 落盘、真实 PluginManager 加载、无面包屑导入回归）。