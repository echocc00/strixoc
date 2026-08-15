# hermes-plugin 开发计划(版本化路线图)

> 基线: 0.2.1(2026-08-16 已发布,tag `hermes-plugin-v0.2.1`)
> 依据: EVALUATION.md 缺口分析 + 2026-08-16 项目优化分析
> 版本号独立于 vendored strix-agent(上游自己的 release 节奏)

---

## 0. 版本路线图总表

| 版本 | 主题 | 状态 | 预计工作量 |
|---|---|---|---|
| **0.2.1** | MCP gateway bridge + 发布卫生 | ✅ 已发布 2026-08-16 | - |
| **0.3.0** | 质量门禁:CI 金标修复 + lint/coverage + worker 心跳 | ✅ 已发布 2026-08-16 | - |
| **0.4.0** | 运维自动化:systemd 模板 + retention + 告警 | 规划中 | 2-3 天 |
| **0.5.0** | 安全强化:authz URL 规范化 + 审计加固 | 规划中 | 1-2 天 |
| **1.0.0** | 稳定性:上游嵌入式 API + 版本矩阵 + 跨平台验证 | 规划中 | 3-5 天 + 上游周期 |
| **1.x** | 产品化:定时扫描 / 趋势 diff / 修复闭环 | 远期 | 按需 |

发布节奏原则:**语义化版本,每个版本一个主题,发布 = commit + tag + push**(见 §5 发布流程)。

---

## 1. 0.3.0 - 质量门禁(P0)

### 目标

消灭三个已验证的质量盲区:
1. CI 里 hermes 金标测试静默 skip(hermes-agent 是本地私有包,CI 装不上)
2. hermes-plugin 无 lint / 类型检查 / 覆盖率
3. worker 僵尸进程检测慢(只能靠扫完后的 reconcile 兜底)

### 设计方案与实现细节

**1.1 本地发布门禁(替代 CI 金标)**

- 新增 `hermes-plugin/scripts/release_gate.py`:
  - 在当前 venv 跑 `pytest tests/ -q`,解析 summary 行
  - **assert 0 skipped**:hermes/strix 任一可选套件被 skip 即失败,强制发布者
    在装齐双依赖的环境(strix + hermes 的 py3.12 venv)执行
  - 退出码非 0 时禁止打 tag(文档约定,后续 0.4.0 可加 git hook 强制)
- CI 改造(`.github/workflows/hermes-plugin-ci.yml`):
  - py3.11 job 的 pytest 加 `-rs`(列出所有 skip 原因),静默跳过变成日志可见
  - 新增轻量断言步骤:统计 `SKIPPED` 行数写入 job summary,人工可查

**1.2 lint / 类型检查 / 覆盖率**

- `hermes-plugin/pyproject.toml` 增加 `[tool.ruff]`(对齐根 repo:py311 target,
  line-length 100,规则集取根配置子集,忽略与插件风格冲突项)
- 新增 `[tool.mypy]`:宽松起步(`ignore_missing_imports = true`,hermes 无
  stubs),每版本收紧一档
- dev 依赖加 `pytest-cov`;CI 两个 job 均加 `--cov=plugin --cov-report=term
  --cov-fail-under=75`(当前 11 个测试文件质量高,首版门槛 75%,1.0.0 提到 85%)
- CI 新增 `lint` job:ruff check + ruff format --check + mypy

**1.3 worker 心跳**

- `worker_runtime.py`:`execute()` 内启动 30s 间隔心跳协程,
  `emit({"type": "heartbeat", "ts": ...})`(用 `time.time()`,worker 侧无
  Date.now 限制),scan 结束时 cancel
- `backends.py` `WorkerBackend`:`_pump()` 记录最后心跳时间戳;
  `strix_status` 工具读取注册表时输出 `worker_alive: true/false`
  (超时阈值 90s = 3 个心跳周期)
- 不做主动 kill(保守):僵尸检测只暴露状态,`strix_cancel` 已有进程清理路径
- 测试:`test_worker_emit.py` 扩展心跳用例(fake 时钟);
  `test_backends.py` 补超时判定用例

### 验收标准

- [x] `scripts/release_gate.py` 在双依赖 venv 全绿(100 passed, 0 skipped)、缺依赖时明确报错退出
- [x] CI 三个 job(lint / py312+strix+cov / py311+skip-report)全绿
- [x] `ruff check plugin/ tests/ scripts/` 0 error(ruff format 同步收敛)
- [x] 心跳:`strix_status` 输出 `worker_alive`/`heartbeat_age_s`,90s 超时 + 启动宽限,单测覆盖全状态矩阵

---

## 2. 0.4.0 - 运维自动化(P1)

### 目标

NAS 部署从"能跑"升级为"可运营":配置不漂移、磁盘不爆、故障主动通知。

### 设计方案与实现细节

**2.1 systemd unit 模板入 repo**

- 新增 `hermes-plugin/runbook/systemd/hermes-strix-feishu.service.in`
  (占位符 `{{HERMES_HOME}}` / `{{ENV_FILE}}` / `{{LOCK_DIR}}`)
- `scripts/install_service.sh`:render + `systemctl daemon-reload + enable`
- 消除 NAS 上 `/etc/systemd/system/` 手工维护的漂移风险

**2.2 扫描产物 retention**

- 新增 `scripts/prune_runs.py --days 30 --dry-run/--apply`:
  清理 `strix_runs/<id>/`(产物含 PoC,默认 30 天)
- 挂 NAS cron(周执行);`run.json` 摘要(状态/漏洞数/成本)可选归档到
  `strix_runs/index.jsonl` 后再删目录,保趋势数据(为 1.x 做铺垫)

**2.3 审计日志轮转**

- `audit_log` 路径切换为 `logging.handlers.RotatingFileHandler`
  (10MB × 5);`authz.py` 写入路径改为走 logger 而非裸 open/append
- 兼容:轮转文件命名 `strix-audit.jsonl.1`,读取端(如有)只读主文件不变

**2.4 故障告警(复用 broadcast)**

- `runner.py` ScanManager 终态回调:cancelled/failed(排除正常 completed)
  时经 `broadcast.py` 发飞书卡片(标题/scan_id/原因/时长)
- 配置项 `notify_on_failure: true`(默认开)+ `notify_chat_id`
- worker 侧 OOM/断管:由 1.3 的心跳死亡检测触发同路径通知

### 验收标准

- [ ] NAS 重装场景:只跑 `install_service.sh` 即恢复服务
- [ ] prune dry-run 输出与实际删除一致;index.jsonl 保留摘要
- [ ] 审计文件超过 10MB 自动轮转,旧审计可查
- [ ] kill worker 进程,飞书 ≤2min 收到失败通知

---

## 3. 0.5.0 - 安全强化(P1)

### 目标

渗透工具自身的授权边界按最严标准审计,重点是 URL 解析规范化。

### 设计方案与实现细节

**3.1 authz URL 规范化审计**

- `authz.py` 目标匹配前置统一规范化管线(顺序固定、每步有测试):
  1. `urllib.parse.urlsplit` 拆解;**拒绝 userinfo**(`user@host` 一律 deny,
     防 `http://allowed.internal@evil.com/`)
  2. host 小写、去尾部 dot(`evil.com.` 防 FQDN 后缀绕过)
  3. **后缀锚定**:host 匹配 `== target` 或 `.endswith("." + target)`,
     禁止字符串前缀匹配(`evil-internal.com` 不得匹配 `*.internal`)
  4. port 纳入白名单语义(默认仅 80/443/自定义列出端口)
  5. scheme 白名单(http/https;拒绝 `file://` 等)
  6. 路径前缀匹配仅对 path 部分做前缀,query/hash 不参与
- **拒绝解析 DNS 的原则不变**(防 DNS rebinding),全部基于字面 host
- 新增 `tests/test_authz_url.py` 攻击用例集:
  userinfo 注入 / 尾 dot / 大小写 / 端口跳变 / path traversal(`/@evil`)/
  反斜杠混淆(`https:/\evil.com`)/ 八进制与十进制 IP(直接 deny 非
  点分十进制的 IP 形态,除非白名单显式给出)

**3.2 审计事件补全**

- `strix_scan` 每次调用(无论 allow/deny)记录规范化前后的 target 字符串,
  便于事后审计匹配逻辑是否被绕过
- 审计记录加 plugin version 字段(利用 0.2.1 已追平的 plugin.yaml 版本)

### 验收标准

- [ ] 攻击用例集全绿,每条用例注释攻击向量与 CVE/OWASP 对应
- [ ] `make security-review`(根 repo bandit)无新增告警
- [ ] 手工渗透演练:10 条绕过尝试全部 deny 且留痕

---

## 4. 1.0.0 - 稳定性里程碑(P1-P2)

### 目标

消除对 strix 上游内部实现的最大依赖面,建立上游同步机制,达到"生产长期运行"标准。

### 设计方案与实现细节

**4.1 上游嵌入式 API(结构性投资)**

- 向 usestrix/strix 提 issue + PR:暴露
  `strix.embed.run_scan_with_reports(scan_config, ...) -> ScanOutcome`
  (内部完成 ReportState 自建 + set_global_report_state + cleanup,
  返回 run_dir / 漏洞列表 / 成本)
- PR 理由(写给上游):所有第三方嵌入(CLI/TUI 之外的 hermes 类网关、
  CI 系统)都踩同一个坑;worker_runtime.py 的 docstring 已是现成论证
- 落地前过渡:`worker_runtime.py` 加启动时自检(探测
  `strix.report.state.ReportState` 与 `finish_scan` 行为,不匹配则
  emit 显式 warning 事件,飞书可见),上游破坏时不再静默无报告
- PR 合并后:worker_runtime 切换新 API,保留旧路径一版作回退

**4.2 strix 版本矩阵**

- CI py312 job 拆双矩阵:`strix-agent==1.5.3`(锁)与 `strix-agent`
  最新版(continue-on-error,前哨);前哨红了 = 上游 API 漂移,触发
  4.1 的自检排查
- 建立上游 release 同步节奏:上游每 release,跑前哨 + 本地金标,
  CHANGELOG 记 `sync: strix-agent v1.x.y`

**4.3 broadcast 跨平台验证**

- `scripts/verify_broadcast.py --platform feishu|telegram --chat-id ...`:
  发测试消息并断言 API 返回成功(对齐 verify_env.py 模式)
- Telegram 侧FakeAdapter 单测补齐 API 错误分支

**4.4 发布门禁强化**

- 覆盖率门槛 75% -> 85%
- git pre-push hook(可选):推送 tag 前自动跑 release_gate

### 验收标准

- [ ] 上游 issue/PR 已提交并获得回应(无论接受与否,自检兜底先落地)
- [ ] 前哨 job 稳定运行 ≥2 个上游 release 周期
- [ ] verify_broadcast 双平台冒烟通过
- [ ] 全套件 0 skip、cov ≥85%

---

## 5. 发布流程规范(自 0.2.1 起执行)

```
1. 改动收敛:所有测试本地全绿(py3.12 双依赖 venv)
2. 版本 bump:plugin.yaml + pyproject.toml 同步改(0.2.0 教训:漏 bump)
3. CHANGELOG.md 新版本条目(Keep-a-Changelog 风格)
4. release gate: scripts/release_gate.py(0.3.0 起)
5. commit: fix|feat(hermes-plugin): release X.Y.Z - <主题>
6. tag: hermes-plugin-vX.Y.Z(附注 tag)
7. push origin main hermes-plugin-vX.Y.Z
```

tag 命名固定前缀 `hermes-plugin-v`,与未来 strix 上游 tag(如 `v1.5.3`)
命名空间隔离。

---

## 6. 1.x 远期(产品方向,不承诺版本号)

- **定时扫描 + 趋势 diff**:cron -> Hermes 消息 -> strix_scan;结束后对比
  上次 run,仅推送新增/修复漏洞(依赖 0.4.0 的 index.jsonl 摘要数据)
- **修复闭环 `strix_fix(scan_id, vuln_id)`**:读漏洞 -> 生成 patch -> 复扫
  验证,对齐上游 fix-security-vulnerabilities-with-strix skill
- **多目标资产面板**:history 注册表升级为资产级视图(目标 -> 历史 -> 趋势)
