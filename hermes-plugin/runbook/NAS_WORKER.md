# NAS worker 部署手册（生产形态）

strix 要求 python>=3.12 + `openai>=2.45`，而 hermes 装的是 python 3.11 + `openai==2.24`
（pip 无法同 venv 共存）。所以 strix 跑在**独立 worker venv + 独立进程**里，经 stdio JSON-lines
流式回传 `phase / vuln / cost / finished` 事件 —— Python API 的实时回调能力完整保留，同时
Docker socket 只暴露给 worker，Hermes 进程不拿主机 root。

## 1. 本机（Windows）现状（已配置 2026-08-13）

- `hermes v0.20.0`（`%LOCALAPPDATA%\hermes`，venv python 3.11.15）
- 插件已部署并 enabled：`%LOCALAPPDATA%\hermes\plugins\strix\`
- dev venv：本地开发 venv（python 3.12.10 + strix 1.5.3 editable + hermes editable）
  —— 只用于测试；生产 worker 都在 NAS。

## 2. NAS（部署时填入 `<NAS_IP>`，Debian 12 类 NAS）—— 已配置

| 项 | 值 | 验证命令 |
|---|---|---|
| docker  | 29.4.3，`<SSH_USER>` 已加入 docker 组 | `docker info --format '{{.ServerVersion}} {{.OSType}}'`（新 ssh 会话生效） |
| worker venv | `/volume1/soft/StrixWorker/venv`（conda python 3.12.13） | `/volume1/soft/StrixWorker/venv/bin/python -V` |
| strix | 1.5.3（PyPI，worker venv 内） | `/volume1/soft/StrixWorker/venv/bin/strix --version` |
| 沙箱镜像 | `ghcr.io/usestrix/strix-sandbox:1.3.0`（`~/.strix/cli-config.json`） | |
| 遥测 | `telemetry.enabled: false`（同上文件） | |

> 注：GitHub 直连在该 NAS 网络不稳定（HTTP2 framing / empty reply），安装一律走
> `repo.anaconda.com`（conda）与 PyPI；后续 pull 沙箱镜像如遇问题可配镜像加速。

## 3. 表格上的填法（worker 如何找到 NAS）

任何 Hermione 所在机器，`~/.hermes/strix.yaml`：

```yaml
worker_python: ""            # 不填 → STRIX_WORKER_PYTHON 环境变量 → PATH 里的 strix-worker
```

带 Docker 的远端（NAS）若与 Hermes 不同机：

- 最简：Hermes 也跑在 NAS（同机 stdio spawn，零网络）。
- 跨机：worker 进程要在能访问 docker.sock 的主机上。两个选择：
  a) 在 NAS 上常驻一个 worker 服务（推荐，见 §4）；
  b) Hermes 本地 spawn 远程 python：`STRIX_WORKER_PYTHON` 指向 ssh 包装脚本
     `ssh <SSH_USER>@<NAS_IP> /volume1/soft/StrixWorker/venv/bin/python`，
     同时 `DOCKER_HOST` 相关能力在远端。事件流照常走 stdio（经 ssh）。
     ⚠️ ssh 包装会复用 strix_runs 于远端 cwd；`runs_cwd` 也要指到远端路径。

## 4. 常驻 worker（systemd，NAS 侧，推荐）

worker 本身是“按次 spawn”的（plugin 每次 scan 起一个进程）。需要“常驻”时用
`/pentest` 所在 hermes 同机即无需常驻；如需 NAS 端常驻供多端调用，给 NAS 加：

```ini
# /etc/systemd/system/strix-worker-proxy.service (示例：把 stdio 转成 unix socket 的多路复用不在本插件范围)
# 本仓库 Phase 1 不实现常驻代理 —— plugin 现在直接 spawn worker；多端并发由 hermes gateway 串行。
```

并发注意：plugin 默认每 scan 起独立 worker 进程，scan 间天然隔离。

## 5. LLM key（第一次真实扫描前必做）

strix 用 litellm/openai-agents 读环境变量（`ANTHROPIC_API_KEY` / `OPENAI_API_KEY` /
或 `LITELLM_MODEL` 通道）。worker spawn 时继承 hermes 进程环境；把 key 放进
`~/.hermes/strix.yaml` 的 `worker.env`（后续版本）或 hermes 启动环境。

> 不要在配置文件里明文存 key；用系统级 secret 或 service manager 注入。

## 6. 验收清单（在 NAS 上）

✅ **已于 2026-08-13 通过 MVP 验收**（真实扫描）：

- 目标：`http://<NAS_IP>:8042`（临时 python http.server，验收后已清理）
- 结果：strix_runs/strix-accept-1/ 下 `penetration_test_report.md` + `vulnerabilities.json` + `findings.sarif` + `run.json`（status=completed）全部落盘；18 分钟 quick 扫描，0 漏洞，报告含真实方法论与建议
- 事件流：phase / event（agent_id）/ finished 经 stdio 协议全链路工作

```bash
# 日常最小环境自检
STRIX_WORKER_PYTHON=/volume1/soft/StrixWorker/venv/bin/python \
  python scripts/verify_env.py

# 真实扫描（授权目标）
/pentest http://<你授权的测试目标> --mode quick --confirm-authorized
/strix status
/strix report
```

## 7. NAS 真实运行环境两个必知的坑（2026-08-13 实战验证）

1. **docker 端口发布报 `iptables: No chain/target/match by that name`**
   这是常见 NAS 厂商系统上 iptables-legacy 与 nft 双表共存的典型症状：dockerd 把 DOCKER 链建在 nft 表，容器 start 时 DNAT 插入打到空表。
   **修复 = `sudo systemctl restart docker`（重建链），不要装/切换 iptables-nft 与 legacy 的 alternatives。** 重启后 `docker run -p` 立即正常。

2. **MiniMax 直连 OpenAI 兼容 API 报 `400 invalid params, chat content is empty (2013)`**
   tool-call 回合的 assistant 消息 content 为空时 MiniMax 会拒绝；只有 litellm 的 minimax provider 会正确补 content。
   **必须用 litellm 桥**（worker 环境变量）：
   ```bash
   STRIX_LLM="litellm/minimax/MiniMax-M3"
   MINIMAX_API_KEY=<key>          # 从 /volume1/soft/Hermes/.hermes/config.yaml 读取，勿打印
   MINIMAX_API_BASE=https://api.minimaxi.com/v1
   ```
   直接 `STRIX_LLM=MiniMax-M3` + `LLM_API_KEY`/`LLM_API_BASE` 会 400。

## 8. Docker socket 安全（IMPL_PLAN §5.6）

- 推荐 rootless docker；其次是专用 worker 用户 + docker 组（现状：worker 用户在 docker 组）。
- Hermes 进程本身永远不接 docker socket —— socket 只被 worker venv 的 python 使用。
- 教训（2026-08-13）：在共享 NAS 上清理容器**必须按名字过滤**
  （`docker ps -aq --filter name=<pattern>`），绝不 `docker ps -aq | xargs docker rm -f`。
## 9. P0-1 黄金路径（2026-08-13 追加：真实 hermes 会话全链路验证）

✅ **已在 NAS hermes v0.19.1 真实会话里跑通完整生产调用链**（第五轮）：

`hermes chat -q(工具指令) → 插件加载 → strix_scan 工具 → pre_tool_call 授权通过(audit) →
ScanManager → WorkerBackend spawn(独立会话) → 真实 worker → 真实沙箱 → 真实多 agent 扫描
→ vulnerabilities.json 11 个真实漏洞落盘(CWE-862/200/22/639...) → strix_status 轮询 → 如实汇报`

过程中连环修掉 5 个生产级 bug（全部有回归测试）：
1. hermes 按 namespaced package 加载插件 → 插件模块必须**相对导入**（绝对导入在 hermes 里直接 load 失败）
2. `config_path()` 必须认 **HERMES_HOME**（服务用户 HOME 不可靠）
3. 插件 request 不带 image → worker 从 **strix settings 兜底**（cli-config runtime.image）
4. hermes 会话退出会杀 worker → worker spawn 用 **start_new_session 脱离会话** + emit 断管容错
5. root agent 常以纯文本回合结束不调 finish_scan → worker **自动合成最小终态报告**；
   hermes 重启后 ScanManager **从 artifacts 调和** 死掉的 running 记录

关键环境要求（NAS 生产部署）：`HERMES_HOME=/volume1/soft/Hermes/.hermes` 必须传给 hermes
进程；worker 独立 venv + docker 组 + ~/.strix 配置照旧。

## 10. 进程托管（systemd，2026-08-14 落地）

飞书网关由 **systemd 守护**（此前 nohup 手工进程：进程死/NAS 重启即失联、重启有锁冲突）：

```bash
systemctl status hermes-strix-feishu     # 状态（MainPID / active）
systemctl restart hermes-strix-feishu    # 统一重启入口（一键，避免 pkill+锁冲突）
journalctl -u hermes-strix-feishu -f     # 实时日志（feishu-gw.log 与其等价）
```

- unit：`/etc/systemd/system/hermes-strix-feishu.service`（root；`Restart=always` + `RestartSec=5`；
  `EnvironmentFile=/volume1/soft/Hermes/.feishu-gateway.env`（600）；锁目录独立
  `locks-feishu-p0` 与生产网关互不干扰；开机自启 `enable`）
- **自愈已验证**：`kill -9` 主进程 → 5s 后自动拉起（2026-08-14 实测 222429→222758）
- 与生产网关的关系不变：生产 = `hermes-gateway.service`（root，base home）；
  飞书测试/集成 = `hermes-strix-feishu.service`（profile feishu-p0）
- 配置/插件更新后：`systemctl restart hermes-strix-feishu`（不再手动 pkill）
- **unit 模板已入 repo**（0.4.0，消除手改漂移）：源 =
  `runbook/systemd/hermes-strix-feishu.service.in`；NAS 重装/换机恢复只需
  ```bash
  sudo scripts/install_service.sh \
    --hermes-home /volume1/soft/Hermes/.hermes \
    --env-file    /volume1/soft/Hermes/.feishu-gateway.env \
    --lock-dir    /volume1/soft/Hermes/locks-feishu-p0
  # 预览渲染（不动系统）：加 --print
  ```

## 11. 运维自动化（0.4.0，2026-08-16）

- **产物 retention**：`strix_runs/` 只保留最近 N 天（默认 30），删除前把
  run 摘要（status/漏洞数/成本）归档进 `strix_runs/index.jsonl`（1.x 趋势
  diff 的数据源）。默认 dry-run，`--apply` 才真删：
  ```bash
  python3 scripts/prune_runs.py --days 30           # 先看会删什么
  python3 scripts/prune_runs.py --days 30 --apply   # 归档摘要 + 删除
  # NAS cron（周日 04:17）：
  17 4 * * 0 cd /volume1/soft/Hermes && python3 hermes-plugin/scripts/prune_runs.py \
      --runs-dir strix_runs --days 30 --apply >> ~/.hermes/logs/prune_runs.log 2>&1
  ```
- **审计轮转**：`strix-audit.jsonl` 走 RotatingFileHandler（10MB × 5，
  旧文件 `strix-audit.jsonl.1`...），磁盘占用有界，无需 logrotate 配置。
- **故障告警**：scan cancelled/failed 或 worker 心跳死亡（90s 无心跳，看门狗
  30s 轮询 -> 飞书 ≤2min 收到卡片：原因/时长/已见漏洞数）。配置
  `notify_on_failure`（默认 true）与 `notify_chat_id`（固定运维群，空 =
  发起扫描的会话）。
