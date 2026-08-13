# Changelog

All notable changes to the `hermes-plugin` (Strix × Hermes integration) are
documented here.  Plugin version is independent of the vendored strix-agent
version (upstream tracks its own releases).

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