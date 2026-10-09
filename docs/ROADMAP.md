# IOC Rejudge — 开发路线与当前状态（ROADMAP）

> 本文件是"接着做"的入口：记录已完成的能力、当前工作区状态、待开发清单与验收纪律。
> 任何 AI 会话被问"还需要开发什么/做到哪了"，先读本文件，再按需读引用的规格与提示词包。
> 最后更新：2026-10-09（`2.9.1` 收口网页操作体验与一键启停）。

## 1. 当前状态快照

| 项 | 值 |
|---|---|
| 版本 | `2.9.1` |
| 测试基线 | `python -m pytest tests -q` = `1286 passed, 1 skipped`（2026-10-09） |
| 已发布能力 | judge 高频入口、统一任务队列、队列结果消费（results/export/explain/review/diff）和 Web 队列面板 |
| 已验收开发任务 | 12/12（提示词包 `docs/agent-prompts/product-surface/index.md`，gitignore 内，不进发布包） |
| 已实施规格 | `docs/superpowers/specs/2026-10-03-unified-job-queue-design.md`、`docs/superpowers/specs/2026-10-04-queue-consumer-completion-design.md`（gitignore 内） |
| 下次第一件事 | 按 §4 清单继续开发。历史遗留未跟踪文件勿动：`AI_HANDOFF.md`、`AI_SUPERVISOR_PROMPT.md`、`_tmp_summarize_share.py` |

## 2. 已完成能力（用户视角，2026-10-02 至 10-04 交付）

```powershell
# 终端直跑（高频入口，支持管道/文件/大输入）
python -m ioc_rejudge judge a.com 1.2.3.4 --offline
Get-Clipboard | python -m ioc_rejudge judge --stdin --offline

# 队列（Web/终端共享 .\jobs 存储）
python -m ioc_rejudge judge a.com --queue          # 入队返回 job_id
python -m ioc_rejudge jobs list / status <id>      # 查询（含 jobs dir 打印）
python -m ioc_rejudge jobs run <id>                # 前台执行，逐接口实时进度
python -m ioc_rejudge jobs cancel <id> / prune     # queued 即时取消 / 保留清理
python -m ioc_rejudge jobs results <id>            # 看研判行
python -m ioc_rejudge jobs export <id> --format xlsx  # 三格式导出
python -m ioc_rejudge jobs explain <id> --result-id R    # 解释
python -m ioc_rejudge jobs review <id> --ioc I --label approved  # 人工复核（幂等）
python -m ioc_rejudge jobs diff <id> --baseline <old_id>  # 结论迁移对比

# Web 工作台（唯一任务中心）
python -m ioc_rejudge ui    # 队列面板：粘贴入队/运行/进度/KPI 卡/解释/复核/导出/diff
```

关键语义（已在测试中钉死，改动前先读对应测试）：

- 离线 bare 研判 = 默认六源只读本机 provider-cache，命中即复现结论；零凭据零网络（fail-closed）。
- online 任务与 CLI 同参运行，凭据只来自环境/凭证文件，jobs 目录 sentinel 扫描零匹配。
- 取消诚实分层：queued 即时取消；running 只置 `cancel_requested`（启动前消费），不做不安全强杀。
- 复核只追加人工 overlay（`<job>/review.jsonl`，三值 approved/rejected/pending），永不改系统结论。
- 完整结果缓存 CLI/Web 共享；`preset=refresh` 绕过；保留最近 50 个 job，prune 永不删排队/运行中任务。
- workbench 旧面板默认隐藏（`--legacy-workbench` 可回看），后端未动，等最终退役（见 §4）。

## 3. 已知限制与设计决策（不要当 bug 修）

| 项 | 说明 |
|---|---|
| jobs 目录 cwd 相对 | 默认 `.\jobs`，换目录运行 `jobs list` 会看到不同队列；已缓解（输出打印实际目录），根治见 §4-P1 |
| 跨进程认领竞争 | 认领原子性以线程级测试覆盖；真双进程竞争未做进程级测试（mkdir 语义在 NTFS 应成立），属残余风险 |
| UI export_id 内存映射 | UI 重启后旧 export_id 失效（与 workbench 模式一致），重新导出即可 |
| UI 进度为轮询 | 约 1.2s 刷新，极短任务可能看不到中间行；契约保证结束态正确 |
| 运行中不可强杀 | pipeline 不可安全中断是既有约束；规格明确不做假装能杀的 UI |
| 真实 ICP 验收 | 沿用 CLAUDE.md §7 既有已知缺陷，与本轮无关 |

## 4. 待开发清单（问"还要开发什么"就看这里）

### P1 — 下一阶段首选（产品复盘确定，规格未写）

| # | 事项 | 内容与入口 | 验收要点 |
|---|---|---|---|
| 1 | 复核收件箱 | 队列任务结果的"必看优先"收件箱视图：排序（必看/冲突/provider 异常/新鲜度）、键盘流（j/k 切换、数字键打标）、批量标签。入口：`jobs_consumers.review_overlay` + `ui.html` 队列面板 + `result_summary` | 批量打标幂等；键盘流不与页面快捷键冲突；排序稳定可回归 |
| 2 | 自动运行 | `jobs run --next`（取最早 queued 执行）+ UI"入队即跑"开关。入口：`jobs_cli._cmd_run`、`ui.py` enqueue 后可选自动触发单实例 runner | 单实例闸不破坏；失败任务不自动重试 |
| 3 | cwd 陷阱根治 | 默认 jobs 目录改为可记忆位置（如 `~/.ioc-rejudge/jobs` 或本地配置文件），`--jobs-dir` 保持覆盖；迁移提示。入口：`job_queue.DEFAULT_JOBS_DIR` 及 ui/cli 参数默认值 | 旧 `.\jobs` 存在时提示而非静默换目录 |
| 4 | README 快速开始重排 | judge/jobs/ui 提到"快速开始"最前，旧快照模式后移。入口：`README.md` | 只描述可用命令（项目规则） |

### P2 — 锦上添花

| # | 事项 | 说明 |
|---|---|---|
| 5 | watch 目录自动入队 | 监控目录新文件自动 `judge --queue`，配合自动运行形成无人值守流水线 |
| 6 | 任务完成通知 | 终端响铃 / Windows toast（在线长任务挂机场景） |
| 7 | workbench 后端最终退役 | 队列消费端稳定一个版本周期后，删除 workbench 面板/后端遗留（先确认 review/export 迁移无遗漏） |
| 8 | 跨进程认领进程级测试 | 双 subprocess 同时 `jobs run` 同一 job，恰一执行 |
| 9 | 定时任务 / SIEM 对接 | 原产品分析 P2，需求出现再立项 |

### 发版事项

- judge 入口、统一队列和 Web 队列面板已收口为 `2.9.0`。下一次用户可见能力再走 pack/push，需用户明确授权。

## 5. 如何继续开发（给未来 AI 的操作指引）

1. **读序**：`CLAUDE.md` → 本文件 → 相关规格 → 提示词包 `docs/agent-prompts/product-surface/index.md`（任务表记录 12 单验收历史）。
2. **流程**：先写/改规格（用户批准）→ `plan-to-prompts` 拆单（validator 必须通过）→ 派发执行 → **监工独立复跑专项+全量 + 真实冒烟**（不采信自报；历史证明自报全绿仍可能藏着转义损坏、假回放、并发卡死）→ 更新 index 状态与 CLAUDE.md 进度。
3. **执行方偏好**（用户历史指令）：外部执行方用无头单轮模式跑提示词文档；监工保留架构、规格、审查、验收。派发时加技术兜底：禁子代理、禁网络搜索、轮次封顶、deny 规则挡 git 写操作与发布脚本。
4. **回归纪律**：全量 `python -m pytest tests -q`（当前 `1286 passed, 1 skipped`）；改 normalize/evidence/adjudicator 须跑人工校准与全量差异（CLAUDE.md §11）。
5. **红线**：不删断言宣布完成；复核不改系统结论；凭据零落盘；不做破坏性文件操作；发布需明确授权。
