# 前端高频使用优化说明

## 1. 目标

把本地 UI 从“share 脱敏助手 + 一组预留控件”提升为可反复使用的 IOC 研判工作台，完整覆盖：

```text
导入 -> 预检 -> 运行 -> 观察状态 -> 筛选结果 -> 查看解释 -> 人工复核 -> 对比变化 -> 导出
```

目标用户是每天处理批量 IOC、需要人工抽查和规则迭代的分析员。界面优先保证可观察、可恢复、可审计，不追求营销式视觉效果。

## 2. 当前现状

### 已有能力

- share key 解锁、IOC Info 查询、脱敏并复制、AI 返回还原和残留扫描已经有可用页面流程。
- 后端已经提供 workbench 的 staging、task、status、cancel、results、explanation、review、export API。
- 结果导出后端支持 JSONL、CSV、XLSX；离线 CLI 支持 history、health、cache、import-table、export-bundle 和 diff。

### 初始主要问题（本轮已闭环）

1. `ui.html` 中展示了研判工作台按钮，但页面脚本没有绑定 `workbench-*` 事件；浏览器点击无法调用已有 API，工作台从用户角度未交付。
2. `workbench_backend.py` 的 `start_task()` 同步执行 pipeline，不能提供可靠的进度刷新和取消语义；页面不能假装这是完整的后台任务系统。
3. 结果表缺少 route、处置范围、复核义务、缺失来源、证据解释和 diagnostics 快速入口。
4. 页面没有暴露上一版与当前版的 diff，AI 改规则后人工仍需回到 CLI 和文件中查变化。
5. share 助手与研判工作台都堆在一张长页面上，频繁使用时需要反复滚动，且明文研判与脱敏外发边界不够突出。
6. JSONL 结果按完整 JSON 树一次性渲染，没有分页或按需详情；大批量数据会增加浏览器内存和等待时间。

## 3. 本轮范围与交付状态

### 本轮必须完成：P0 工作台闭环

- 连接导入、启动、刷新、取消、加载结果、查看解释、提交复核和导出按钮。
- 复用现有 `/api/workbench/*` 契约，不改变后端数据字段和安全门。
- 导入后显示 `import_id`、文件名、字节数和行数；任务后显示 `task_id`、状态和结果数。
- 结果表支持 disposition 筛选和关键字筛选，点击一行加载解释详情。
- 复核提交后刷新当前行状态，并明确提示人工 overlay 不覆盖系统结论。
- 导出至少保留 JSONL；页面结构应为后续 CSV/XLSX 选择器预留位置。
- 增加前端契约测试或等价静态检查，防止 HTML 控件再次没有事件绑定。

### P1/P2 已交付

- P1：真正的后台任务执行、阶段进度、失败恢复、diagnostics 面板和取消语义。
- P1：结果队列视图、必看黑/待复核/灰快捷筛选、上一条/下一条复核、快捷键。
- P1：baseline diff 视图，展示黑白互转、转灰、转复核和 operational changes。
- P1：CSV/XLSX/diagnostics/diff/bundle 导出和受控下载；浏览器只接收 opaque `export_id`。
- P2：顶部模式导航（研判工作台 / 脱敏协作 / 运维历史），减少长页面滚动。
- P2：服务端分页、详情按需加载、输入文件拖放、移动端表格适配；结果页按 24 行/帧分块挂载并可取消过时渲染。当前没有引入完整滚动窗口虚拟列表，因为分页已经限制单次结果集，分块挂载也避免了主线程长时间同步阻塞。
- P2：明文复制、还原结果复制和 key 覆盖操作增加二次确认，统一键盘焦点和状态提示。
- P2：生成不含敏感数据的运行摘要，供后续 AI 读取版本、输入摘要、provider 状态、cache 命中和下一步建议。

## 4. 设计原则

- 结果优先：先让用户知道任务是否成功、哪些行需要处理，再展开原始 JSON。
- 状态真实：后端不可用、任务失败、provider error、no_data 和 disabled 必须区分展示。
- 系统结论与人工意见分层：人工复核只能追加 overlay，不覆盖系统 verdict。
- 安全默认：明文内容、key 覆盖、外发复制都需要明显的风险提示；脱敏结果和残留扫描优先。
- 低依赖：保持当前标准库 HTTP 服务和单文件页面，不新增前端构建链或外部 CDN。
- 机器可读：关键操作结果保留 JSON 字段，便于 CLI、测试和后续 AI 读取。

## 4.1 当前页面 API 约定

- 启动页面任务时发送 `POST /api/workbench/task`，请求体带 `options.background=true`；响应先返回 `queued` 或 `running`，页面通过 `GET /api/workbench/task/{task_id}` 轮询到终态。
- `cancel` 只承诺尚未进入 pipeline 的任务；运行中任务返回 `cancellable=false` 和取消边界说明，不伪造已经停止。
- `GET /api/workbench/task/{task_id}/diagnostics` 只返回结构化诊断，不返回本地输入、结果或诊断文件路径。
- `POST /api/workbench/diff` 接收 `task_id` 与 `baseline_task_id`，只允许比较两个已成功任务；页面展示 `compare_verdicts` 的迁移和 operational changes。
- `POST /api/workbench/results` 与 `POST /api/workbench/export` 可带 `provider_issues=true`，只匹配 provider error/disabled/failed/timeout 或缺失必要来源；`no_data` 保持独立语义。
- `POST /api/workbench/export` 仍只返回 opaque `export_id`；浏览器只能访问受控 download endpoint，不拼接本地路径。

## 5. 最终验收标准

1. 在真实 UI 页面选择一个合法 legacy JSONL 后，点击“导入 staging”能显示导入结果并启用启动按钮。
2. 点击“启动任务”后能显示任务状态；任务完成后能加载结果列表。
3. 点击结果行能显示解释详情；提交 approved/rejected/pending 后能看到成功反馈，并保持系统结论不变。
4. 结果筛选和关键字查询会传递到后端，页面显示总数和当前筛选条件。
5. 点击导出后能获得可下载 JSONL，下载路径仍受 workbench 根目录安全约束。
6. workbench API 不可用时，页面显示明确 unavailable，不出现“成功”假状态。
7. `python -m pytest tests/test_workbench_ui.py tests/test_ui_server.py -q` 通过；新增的页面契约检查通过。
8. `python -m pytest tests -q`、`python -m compileall -q ioc_rejudge` 通过。
9. 真实 Chromium 回归覆盖桌面和 390px 窄屏：导入、启动、结果加载、60 条结果分块挂载、移动端字段标签和明文复制确认均通过。

## 6. 风险与非目标

- 本轮不改变 adjudicator、provider、cache、结果字段和在线请求策略。
- 本轮不把同步 pipeline 直接伪装成可取消后台任务；若要实现真实取消，必须单独设计 worker 生命周期并增加并发测试。
- 不新增真实凭据、真实客户 IOC 或生产缓存作为测试数据。
- 不把 workbench 的人工 overlay 当成自动裁判规则。
- 当前不把服务端分页 + 分块挂载描述为完整的滚动窗口虚拟列表；若未来单页需要展示数千行，再单独引入可视窗口复用并增加滚动锚点测试。

## 7. 执行顺序

1. 完成 P0 前端 API wiring 和页面契约测试。
2. 主控检查 diff、运行专项和全量验收。
3. 已完成后台任务、diff、导出、导航、移动端和性能改造，并通过专项、全量和真实浏览器验收。

## 8. 当前实施状态

- P0 已完成：workbench 页面已接通导入、启动、状态、取消、结果筛选、解释、复核 overlay 和 JSONL 下载；新增页面契约测试。
- P1 已完成：本地页面使用后台模式启动任务并自动轮询；任务状态持久化并区分 queued/running/succeeded/failed/cancelled，服务重启不会伪造运行中；取消只承诺尚未开始的任务。结果区支持分页、快捷筛选、当前页复核导航和 JSONL/CSV/XLSX/diagnostics/diff/bundle 选择，diagnostics 与 baseline diff 通过受控 API 展示。
- 主控返修：修正筛选结果 `result_id` 与原始行序号不一致的问题；页面和任务 API 不向浏览器暴露本地结果/diagnostics 路径；活动任务禁止导出。
- P1 验证：workbench/UI 专项与回环 API 集成测试 `54 passed`；Node 页面脚本语法、Python `compileall` 和全量回归基线 `1148 passed, 1 skipped` 通过。
- P2 已完成基础导航：页面已增加研判工作台、脱敏协作、运维状态顶部锚点导航。
- P2 已完成本轮范围：输入文件拖放、明文/还原结果复制与 key 覆盖二次确认、无敏感运行摘要、结果字段摘要和 provider 异常/缺失快捷筛选。
- 本轮补齐：结果表在窄屏下转换为带字段标签的可点击卡片；结果行按帧分块增量挂载并可取消过时渲染，避免大批量结果一次性阻塞页面。真实 Chromium 已覆盖桌面与 390px 窄屏，验证导入、后台任务、结果列表、字段标签和明文复制二次确认。

## 9. 2026-09-22 缺口审计与补齐范围

这份审计对应高频用户提出的完整清单，避免把“控件存在”误认为“用户流程完成”：

| 用户能力 | 当前状态 | 补齐标准 |
|---|---|---|
| 顶部模式导航 | 已完成 | 三个入口能跳到研判、脱敏协作和运维状态 |
| 真实后台任务 | 已完成 | 页面发送 `background=true`，状态轮询和取消边界真实 |
| 结果分页/详情按需加载 | 已完成 | 结果 API 使用 offset/limit，详情单条请求 |
| 复核队列快捷筛选/导航 | 已完成基础版 | 黑、待复核、灰、误报快捷入口，当前页上一条/下一条 |
| diagnostics 面板 | 已完成基础版 | 结构化诊断可读且不泄露本地路径 |
| baseline diff | 已完成基础版 | 展示迁移、成员变化和 operational changes |
| 多格式导出 | 已完成 | JSONL/CSV/XLSX/diagnostics/diff/bundle 统一走受控 opaque 下载 |
| 任务运行上下文 | 已完成 | 安全 summary 返回版本、输入 hash、诊断、待复核统计和下一步建议 |
| 输入文件拖放 | 已完成 | 拖放和文件选择共用同一 staging 入口，不绕过后端校验 |
| 明文/key 高风险操作确认 | 已完成 | 明文查询、还原结果复制和覆盖 key 前二次确认，取消不会调用复制或 API |
| 结果字段可扫描性 | 已完成 | 直接展示 route、disposition、review suggestion、缺失 provider、provider 状态和保留 URL 摘要 |
| Provider 失败/缺失快捷筛选 | 已完成 | `provider_issues=true` 匹配 error/disabled/failed/timeout 与缺失必要来源；`no_data` 不误报为失败 |

本轮补齐已落实以下受控契约：

- `GET /api/workbench/task/{task_id}/summary`：只返回非敏感运行摘要，禁止返回输入/缓存/结果绝对路径、凭据和原始 provider 响应。
- `POST /api/workbench/export` 的 `format` 扩展为 `diagnostics`、`diff`、`bundle`；`diff`/`bundle` 必须带不同的 `baseline_task_id`，浏览器仍只使用 opaque `export_id` 下载。
- bundle 是单个受控下载文件，内部可包含 JSONL、CSV、XLSX、diagnostics 和可选 diff；不把临时目录路径返回页面。

## 10. 最终验收记录

- 页面契约与 workbench/UI 回环专项：`44 passed`（含移动端布局、字段标签、分块渲染和过时渲染取消）。
- 全量 Python 回归：`1153 passed, 1 skipped`；另有 `tests/test_ui_browser.py` 单用例和 `tests/browser_workbench_regression.py` 双视口回归脚本。
- 真实浏览器：390px 移动端加载 60 条合成结果，验证 staging 文件选择、任务启动、结果加载、`aria-busy` 收口、卡片字段标签、表格宽度不溢出和明文复制确认。
- 运行环境：仅使用临时 loopback server、合成 IOC 和本机 Chromium，不读取真实凭据/客户数据，不访问 provider 网络。
