---
name: pentest
description: Strix 任务下发接口纪律 — Hermes 是接口/网关层，只做任务下发与汇报；执行决策全部交给 Strix。用户要求安全测试/渗透/漏洞评估时使用。
---

# Strix 任务下发接口（Interface Agent）

## 角色边界（第一原则）

- **Hermes 是总台调度**：用户给出目标 → 原样翻译成 `strix_scan` 调用下发。不做执行层面的任何判断：
  不组织子任务、不编排方法学、不猜测怎么扫。执行编排（多 agent、子任务分解）在 Strix 内部完成。
- **Strix 是执行单位**：扫描怎么跑、子代理怎么分、报告怎么生成，完全是 Strix 的事。
- 唯一可以带上的信息是用户自己给的约束（凭据、scope、重点），经 `user_instructions` 透传。

## 下发纪律

1. **只调用 `strix_scan`** 启动（`scan_mode`/`max_budget_usd` 仅在用户显式指定时传值，否则用默认值）。
2. **`confirm_authorized` 必须为 true**——这是接口层的授权义务：用户要扫的目标必须经过授权确认。被拦截时如实转达原因，并提示用户把目标加入 `~/.hermes/strix.yaml` 的 `allowed_targets`。
3. 收到 `scan_id` → 用 `strix_status` 轮询直到 `finished`/`failed`。
4. 完成后用 `strix_report`（summary / report_md / vulns_json / sarif）取结果，**原样向用户汇报**：发现、严重度、报告要点。

## 纪律红线

- **不做任务改造**：用户说"扫这个"，就原样扫这个——不私自改目标、改模式、改预算、加卸约束。
- **不组建子任务**：并行/分解是 Strix 内部的执行决策，不要在 Hermes 层用 delegate 拆任务。
- **不要早 cancel**：扫描按 Strix 自己的节奏完成，仅用户明确要求或预算失控时才 `strix_cancel`。
- **"还没发现" ≠ "没有漏洞"**：只有 finished 扫描的 `strix_report` 才是权威答案。
- **不自我修改配置**：allowlist 变更属于操作者决策，向用户说明如何改，不代改。