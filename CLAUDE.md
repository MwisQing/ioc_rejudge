# IOC Rejudge CLI - 协作上下文

> 操作本项目前先读本文件。完成有意义的变更后，更新底部进度记录。
>
> 当前版本为 `2.2.6`。它保留 v1.4.1 离线快照兼容入口，并已完成六个默认在线 provider、按 IOC/证据需求分流、逐接口日期缓存、完整研判结果缓存、离线回放、mock 端到端验收和项目内独立凭证文件。

## 1. 阅读顺序

1. `CLAUDE.md`
2. `README.md`
3. `docs/ARCHITECTURE.md`
4. 与任务相关的 spec 和 plan
5. 相关源码和测试

当前权威文档：

- 产品说明：`README.md`
- 架构：`docs/ARCHITECTURE.md`
- 开发与验证：`docs/DEVELOPMENT.md`
- 历史：`docs/HISTORY.md`
- 更新日志：`CHANGELOG.md`
- 历史设计规格：`docs/superpowers/specs/2026-07-23-multi-source-ioc-adjudication-design.md`
- 核心计划：`docs/superpowers/plans/2026-07-23-multi-source-core.md`
- 在线计划：`docs/superpowers/plans/2026-07-23-live-providers.md`

## 2. 当前事实

| 项目 | 当前值 |
|---|---|
| 版本 | `2.2.6` |
| 项目类型 | Python CLI |
| 当前输入 | iocProducer 风格 JSONL 快照、裸 IOC 文件或重复 `--ioc` |
| 当前联网 | 裸 IOC 统一模式可按所选 provider 联网；`--offline` 与旧快照兼容模式不联网 |
| 当前结论 | 统一 pipeline 可按可靠 DGA-only 分类分路，并输出存活有效、失活有效、灰、误报、待复核 |
| 当前输出 | 带 route/disposition/scope/provider 契约的 JSONL、CSV、六表 Excel 和 diagnostics |
| Git | `push.py` 可在用户明确授权发布时按 allow-list 初始化并推送；禁止整目录暂存或 force push |
| 2.1.0 | 任务 1-22 与 H1-H3 高危修复全部完成；九场景 online mock、offline replay 和凭据安全已验收 |

ICP provider 已有固定响应契约并进入默认来源；缺少凭据时独立禁用。真实 endpoint、认证和生产响应仍需授权环境验收，不读取 `token_icp.txt`。

## 3. 产品目标

### 当前实现

同一 CLI 接受裸 IOC、IOC 文件或已有 IOC Info 快照，聚合所选 provider 后统一研判：

```text
bare IOC / JSONL snapshot
  -> parse and normalize
  -> provider factory / local sidecar
  -> discovery providers
  -> DGA-only or standard route
  -> rule-planned ICP / WHOIS / pDNS collection
  -> deterministic Observation merge
  -> adjudicate and export
```

当前 live provider：

- K01 compromises / DGA 分类
- IOC Info
- F-Dark
- WHOIS
- pDNS
- ICP（默认来源；domain 类当前状态验证，支持 live cache/replay 和本地 sidecar）

HTTP 状态仍未提供；ICP 使用 typed `icp_registration` positive/negative Observation，自动验收只使用 mock/cache。

## 4. 用户工作流

- 旧兼容模式：准备 JSONL 快照 -> 运行 CLI -> 合并和裁判 -> 导出 -> 人工审阅。
- 统一模式：输入裸 IOC/旧快照 -> provider 聚合 -> Observation -> DGA/普通分路 -> 统一输出 -> 离线回放。
- 当前命令接受旧快照、裸 IOC、重复 `--ioc` 和本地 `--provider-data`；统一模式支持 `--providers`、本地非密钥配置、独立 cache/run 目录及 offline replay。

## 5. 已确认业务语义

### 5.1 通用铁律

- 不打分、不平均、不让弱证据推翻强证据。
- `updatetime` 是情报记录时间，不是存活证据。
- `level` 是威胁等级，不是活跃状态。
- 普通情报必须由承载恶意上下文的同一条记录达到 `historical_malicious_level` 才能进入 A/C 黑证据裁判；高 level 只表示准入，不锁死最终结论。
- 误报表示恶意关联不成立，不是“现在不活了”。
- 失活有效仍是黑情报，仍可用于拦截。
- 同一 IOC 必须先聚合证据再裁判。
- provider `error/disabled` 不等于 `no_data`。
- 人工原因用于改写通用规则和回归测试，不是生产环境高优先级人工规则。

### 5.2 DGA

只有可靠 DGA-only 分类进入 DGA 专用裁判。

在确认没有关联恶意样本后，以下任一新鲜证据足以判白：

- WHOIS 未过期。
- 近 30 天存在 pDNS。
- 当前存在 ICP。

补充规则：

- `not-a-virus`、低 level、零 confidence 的关联项不算关联恶意样本。
- 样本 provider 未成功完成时不能自动判白。
- DGA 判白输出 `误报`，不输出 `灰`。
- 白证据均不成立、分类可靠、必要查询完整时，保留为失活有效。

### 5.3 非 DGA

- 非 DGA domain 未解决 ICP 时进入人工研判；clue-group evidence 无条件 standard block。
- 普通 operator source 与恶意上下文不能绕过 level，也不能跨记录借级；低等级 domain 若保留具体恶意 URL，则 domain 降灰并保留 path 级 URL。
- 高等级 operator 情报在强正常业务闭环、显式结构化资产变化且无威胁残留时仍可判误报。
- 非 DGA 的 WHOIS 未过期和近期 pDNS 不独立判白。
- 公开 APT 通过结构化字段组合建立历史恶意闭环，不通过“人工来源优先”例外。
- 英文恶意词使用词法边界，`rat` 不命中 `rate1/rate2`，`c2` 不命中更长字母数字串。
- `relate_url` 直接证明 URL，不自动扩大成当前 domain 强 A。

### 5.4 灰与作用范围

当前 `灰` 结论表示：当前作用范围不继续拦截，但也不能加入白名单。

典型场景：历史钓鱼情报可信，domain 已失活或过期，具体 URL 仍需保留。

目标输出字段：

- `route`
- `disposition`
- `scope_actions`
- `retained_urls`
- `provider_statuses`
- `evidence_origins`
- `missing_required_providers`

## 6. 当前代码调用链

```text
ioc_rejudge/cli.py
  -> legacy snapshot wrapper, or inputs.read_input_bundle
  -> providers.factory / providers.sidecar
  -> pipeline bounded ThreadPoolExecutor -> deterministic Observation merge
  -> routing
  -> dga.adjudicate_dga / adjudicator.adjudicate
  -> export.export_jsonl / export_csv / export_excel
```

当前模块：

| 文件 | 责任 |
|---|---|
| `parser.py` | JSONL 与时间解析 |
| `normalize.py` | IOC 归一化和记录合并 |
| `models.py` | Evidence、Dossier、Verdict |
| `observations.py` | IocTarget、Observation、route/status/disposition 类型 |
| `inputs.py` | 裸 IOC/快照输入识别、校验、去重与错误可见性 |
| `providers/base.py` | provider 协议、执行上下文和结果状态 |
| `providers/sidecar.py` | 确定性本地 JSONL sidecar provider |
| `providers/settings.py` | 不泄漏 secrets 的在线 provider 运行配置 |
| `providers/cache.py` | provider 独立目录、日期分片、旧格式兼容的 append-only JSONL 原始响应缓存和 TTL 状态 |
| `result_cache.py` | 规范化 IOC 完整研判结果、配置指纹、默认 7 天 TTL 和日期分片缓存 |
| `providers/transport.py` | 可注入 Python HTTP JSON 传输和 secret-safe 错误分类 |
| `providers/go_transport.py` | 捆绑 Go HTTP worker 的 JSONL 适配、进程生命周期与 Python fallback 边界 |
| `providers/ioc_info.py` | IOC Info 批量查询、空结果定向重试、缓存适配与历史 CLI 实现 |
| `providers/k01_compromise.py` | K01 批量分类、请求 profile 缓存隔离和严格 tags 规范化 |
| `providers/fdark.py` | F-Dark 五类 IOC 查询变体、原始响应缓存和统一样本语义 |
| `providers/whois.py` | 当前 WHOIS 查询、日期事实规范化及 stale 审计回退 |
| `providers/pdns.py` | 完整 pDNS 活动记录、Unix 时间规范化及 freshness 降级 |
| `providers/icp.py` | 默认 ICP 查询、host 去重、typed 当前状态、cache-first 和限速并发 |
| `providers/factory.py` | 环境变量凭据、本地非密钥配置、Provider 选择及 cache/run 审计组装 |
| `progress.py` | TTY 感知、线程安全的逐接口实时进度渲染器（非 TTY 节流降级） |
| `profile.py` | domain/IP/runtime 画像 |
| `evidence.py` | A-F 证据提取 |
| `dga.py` | DGA facts 与专用有序裁判 |
| `adjudicator.py` | 五类普通路由裁判、ICP 人工门和灰作用范围 |
| `routing.py` | 可靠 DGA-only 分类和分类失败降级 |
| `pipeline.py` | 发现/生命周期两阶段请求规划、provider 聚合、分路、facts/dossier 构建和结构化诊断 |
| `diff.py` | 确定性 verdict 迁移、成员变化和重点变化组报告 |
| `rules.py` | 规则配置 |
| `config.py` | 阈值配置 |
| `export.py` | JSONL、CSV、Excel |
| `cli.py` | 编排、诊断、CLI |

当前公开兼容 API：

- `run_pipeline_with_diagnostics(input_path, config)`：旧快照结构化结果。
- `run_pipeline(input_path, config)`：旧快照 verdict 列表包装器。
- `run_unified_pipeline(bundle, providers, config, context, progress=None)`：统一 provider/路由边界；可选 `progress` 回调在每个 provider 采集完成时收到一行进度文本，回调异常不影响采集结果。
- `compare_verdicts(before, after)`：确定性迁移和成员差异报告。

### 6.1 在线 Provider 配置

- 默认顺序：`k01_compromise,ioc_info,fdark,whois,pdns,icp`；缺少任一来源凭据只禁用该来源。
- 请求规划：先用 K01/IOC Info/F-Dark 做分类与样本发现；domain 类验证当前 ICP，DGA 路由追加 WHOIS/pDNS，standard 路由仅在历史 URL/钓鱼灰分支需要时追加 WHOIS，IP 类跳过三类生命周期接口。
- CLI：`--provider-config` 指向本地非密钥 JSON，`--cache-dir` 保存可复用原始响应缓存（默认 `.\provider-cache`），`--run-dir/raw` 保存本次运行审计副本，`--offline` 只读本地数据/cache，`--refresh` 绕过 cache；`--offline` 与 `--refresh` 互斥。
- CLI 可见性：统一模式启动打印 provider 清单（disabled 标注并在 stderr 给出原因，sidecar 单独标注）、绝对缓存目录、缓存模式/TTL/分片数和 Go/Python HTTP worker；采集期间逐接口实时进度条 `[provider] done/total 耗时` 输出到 stderr（终端时 ANSI 原地重绘，非终端节流降级），provider 完成打印原 `provider 'x': completed in ...` 永久行；结束打印结果缓存 hit/miss 及 miss 原因、逐 provider 状态计数、被拒绝输入行计数与总耗时；diagnostics `provider_metrics` 含 `duration_seconds`。
- CLI 迁移对比：`--diff-baseline` 接受上次 result JSONL，运行前 fail-fast 校验（存在性、JSON、`ioc`/`conclusion` 字段），研判后经 `compare_verdicts` 输出确定性迁移报告到 `--diff-output` 或默认 `<输出名>_diff.json`；旧快照兼容模式同样适用，`--diff-output` 必须与 `--diff-baseline` 同用。
- 凭据环境变量：`K01_COMPROMISE_API_KEY`、`IOC_INFO_API_KEY`、`FDP_ACCESS`/`FDP_SECRET`；WHOIS 可用独立 `WHOIS_ACCESS`/`WHOIS_SECRET`，pDNS 可用独立 `PDNS_ACCESS`/`PDNS_SECRET`，未设置独立值时回退到 FDP 凭据。
- endpoint 环境变量：`K01_COMPROMISE_URL`、`IOC_INFO_URL`、`FDARK_URL`、`WHOIS_URL`、`PDNS_URL`。
- ICP 凭据环境变量：`ICP_UC`、`ICP_KEY`；endpoint 为可选 `ICP_URL`。K01、IOC Info、F-Dark、WHOIS、pDNS 默认 TTL 7 天；ICP 默认 TTL 30 天、workers 2、rate 2/s。本地配置可为单个 provider 设置 `ttl_seconds`、`ttl_hours` 或 `ttl_days`，三者只能选一。
- Cache 物理格式：每个来源独立写入 `.cache_<provider>/cache_YYYY-MM-DD.jsonl`，跨分片读取最新 query key，并兼容旧 `<provider>.jsonl`；读取时按文件签名惰性建立内存索引，写入时增量更新，外部追加或新增分片后自动重载。
- 研判结果缓存：默认启用并保留 7 天，写入 `.cache_adjudication_results/cache_YYYY-MM-DD.jsonl`；只有 IOC/快照/规则/provider 公开配置指纹一致时复用，`--refresh` 绕过，命中数、miss 原因与错误进入 diagnostics。中断运行已经写入的 provider 原始响应仍可复用，但不缓存未完成的最终研判行。
- 在线 HTTP 执行：运行包内置 `ioc_rejudge/bin/provider_http.exe`，六个在线 provider 使用共享 Go worker 复用连接并遵守各自 `workers`/`rate_per_second`；Python 继续负责响应解析、缓存、离线回放、Observation、diagnostics 和裁判，worker 缺失时回退 Python transport。
- 本地配置拒绝 secret/token/password/authorization 类字段；在线缺少某来源凭据时只将该来源标为 disabled，不中止其他来源。
- 离线回放不需要凭据，但必须保留与首次运行一致的 provider 选择、非密钥查询配置和持久 `--cache-dir`；离线传输 fail-closed，不允许网络回退。
- 跨 provider 并发由 `Config.provider_workers` 限制，默认 5；最终 Observation、诊断和 verdict 仍按输入 IOC 与 provider 配置顺序稳定归并。

## 7. 当前已知缺陷

1. 真实 ICP endpoint、认证和生产响应尚未用用户凭据验收；自动测试持续使用 mock/cache，禁止读取 `token_icp.txt`。
2. 脱敏全量快照使用带下划线的占位域名，其中 9,487 条会被严格 DNS 输入校验拒绝；任务 12 另以内部 pipeline 审计覆盖全部记录，不放宽生产校验。
3. ICP workers/rate 本地配置当前只校验为正数，尚未定义产品级硬上限；真实生产值需由接口所有者批准。

修复时先用测试复现，不在旧逻辑上继续叠加例外。

## 8. 项目结构

```text
ioc_rejudge_cli_1.4.1/
|-- ioc_rejudge/                 # 当前业务包
|-- rules/                       # 默认规则 JSON
|-- tests/                       # 测试
|-- ioc_info/                    # 脱敏快照，非发布源代码
|-- outputs/                     # 研判产物，非发布源代码
|-- 其他接口/                    # F-Dark、WHOIS、pDNS、HTTP 参考实现/文档
|-- docs/
|   |-- ARCHITECTURE.md
|   |-- DEVELOPMENT.md
|   |-- HISTORY.md
|   `-- superpowers/             # 已批准规格和实施计划
|-- README.md
|-- CHANGELOG.md
|-- CLAUDE.md
|-- VERSION
|-- pack.py
|-- push.py
`-- upgrade.py
```

## 9. 工作原则

- 非微小改动先说明目标、范围、风险和验证方法。
- 需求不清或会改变业务结论时，先确认后编码。
- 先写规格，再写实施计划，再实现。
- 优先小步迭代；实现与审查/验证分开。
- 遵循现有模块边界，不做无关重构。
- 只有用户明确授权发布时才可通过 `push.py` 按 allow-list 初始化、提交、打标签和推送；禁止 `git add .`、整目录提交或 force push。
- 不执行破坏性文件操作。

## 10. 编码约束

- 代码和代码注释使用英文。
- 注释说明意图、约束和边界，不记录开发过程。
- 优先使用稳定符号名和模块职责定位。
- 不为未确认需求提前抽象。
- 使用结构化解析器处理 JSON、URL、时间和表格。
- 不在生产代码中匹配 R 编号或脱敏 IOC 值。
- 不在代码、commit message 或发布说明中出现协作工具名称。
- 不使用 `/init`。

## 11. 测试与验收

### 当前真实基线

```powershell
python -m pytest tests -q
```

当前结果：`708 passed, 1 skipped`。skip 为 Windows 不适用的 POSIX 脚本执行探针；真实 Windows `provider_http.exe` 已由本地 HTTP 端到端验收覆盖。另含 GitHub Release 下载更新、本地凭证文件来源隔离、控制台可见性、逐 provider 进度耗时、`--diff-baseline` 迁移对比、Excel 评审列、电子表格公式注入、脏 `level` 批处理隔离、DGA 默认 UTC 时间、逐接口日期缓存、完整研判结果缓存、缓存索引性能、生命周期请求规划、最新 comment/context、过期误报出口与发布 allow-list/忽略规则安全专项。

任务 22 在线端到端验收：`tests/test_live_acceptance.py` 与 live pipeline 联合为 `13 passed`。九个合成场景全程使用注入 transport，并对 `requests.Session.get/post` 设置 fail-fast 网络哨兵；online mock 填充五源 cache/raw 后移除全部凭据，offline replay 的 verdict、原因、来源、顺序及 Observation 稳定字段与 online 完全一致。递归扫描 JSONL、CSV、Excel 及解压后的 XML/rels、diagnostics、cache、raw 和 log，sentinel 凭据零匹配。

任务 12 离线验收：裸 IOC sidecar smoke 输出 `误报/dga/false_positive` 且必要 provider 完整；旧快照 smoke 输出 1 条存活有效。脱敏全量 10,856 行包含 3 个重复顶层 IOC，按 `original_ioc` 对齐为 10,853 个唯一输入，legacy 与统一 pipeline 结论变化为 0；黑转白、白转黑、转灰、转复核均为 0。

### 变更准入

- Bug：复现 -> 修复 -> 相关测试 -> 全量测试。
- 修改 normalize/evidence/adjudicator：必须运行人工校准和全量差异。
- 修改 export：必须验证 JSONL、CSV、Excel 和 sheet 统计。
- 修改 provider：必须测试 success/no_data/error/disabled、缓存、离线和凭据泄漏。
- 无法完成全量验证时，明确报告旧故障、新故障和未覆盖风险。
- 不允许删除断言、静默跳过或忽略收集错误来宣布完成。

详细命令见 `docs/DEVELOPMENT.md`。

## 12. 人工校准

当前 11 条人工样本的自动目标：

| 样本 | 目标 |
|---|---|
| R001-R004 | 黑 |
| R005 | DGA 白 |
| R006-R007 | 黑 |
| R013 | 当前 ICP 确认不存在 + 运营恶意上下文，黑 |
| R016 | 灰并保留 URL |
| R018 | DGA 白 |
| R023 | 结构化公开 APT，黑 |

规则改动不能只通过 11 条样本。必须生成全量 before/after 转移，检查所有黑转白、白转黑和大规模变化组。

## 13. 数据与安全

- 示例使用 `.invalid` 和私网地址。
- 不把真实 IOC、原始响应、缓存、客户数据或凭据写入源码和文档。
- token 只进入环境变量或本地忽略文件。
- diagnostics、日志和导出不得包含请求头或 secrets。
- provider 原始响应必须可审计，但不进入发布源文件。
- 修改脱敏逻辑时必须做敏感值残留扫描。

## 14. 文档规则

- README 只描述当前可用命令；规划能力必须标记“未实现”。
- 架构文档记录稳定边界，不记录临时调试过程。
- CHANGELOG 只记录用户可见行为和兼容性变化。
- HISTORY 保存旧里程碑，不作为当前事实来源。
- 有意义的代码、架构、测试或工作流变更完成后更新本文件进度。
- 文档与源码冲突时，以可运行代码和可复现测试为当前事实，并修正文档。

## 15. 历史实施计划

1. `docs/superpowers/plans/2026-07-23-multi-source-core.md`
2. `docs/superpowers/plans/2026-07-23-live-providers.md`

两份计划均已实施完成，仅用于追溯决策。新的在线 HTTP 工作必须先取得正式外部契约并另立规格；ICP 当前契约已冻结但真实 endpoint 仍待授权验收。

## 16. 进度记录

| 日期 | 范围 | 完成内容与验证摘要 |
|---|---|---|
| 2026-08-10 | 2.2.6 发布准备 | 六个在线 provider 接入状态确定后计数的实时进度，TTY 原地重绘、非 TTY 节流且重复终态去重；捆绑 Go HTTP worker 按 provider 原配置并发/限速，Python 保留解析、缓存和裁判语义及 fallback；修复直接脚本启动和逐 IOC 全量重扫缓存分片的性能退化，CLI 显示缓存路径/模式/TTL/miss 原因并在 Ctrl+C 后说明复用边界；修复 `push.py --check` 误推送；真实 Windows EXE 本地 HTTP 验收通过，Python 全量 `708 passed, 1 skipped`，Go、语法、102 文件 pack check 与 diff check 通过 |
| 2026-08-05 | 2.2.5 发布 | `comment/context` 只取同一 IOC 最新 ioc_info 记录；“黑产/扩展/扩线”保留强恶意证据，但在 WHOIS 过期、无近期活动、ICP+官网闭环、显式资产变化、无威胁残留五条件同时成立时允许误报；“恶意”降为普通强恶意上下文；统一 pipeline 对强备注追加 WHOIS 规划，缓存契约升级为 4；源树与独立发布包均为 `670 passed`，10,856 条脱敏快照相对 v2.2.4 有 505 条黑转待复核、黑白互转 0；发布提交 `461b1bb6989ad399e1f1b0854c15505cbf89115a` 与附注标签 `v2.2.5` 已推送；发布包 `ioc_rejudge_v2.2.5_20260805-094736.zip` 含 96 个发布文件、禁入项 0、SHA-256 `022ecd02a74233e5254d9da0d0a96e7fffd2b305b1657eb980d3b9296cef6105`，GitHub Release 与 ZIP 资产已发布，无 force push |
| 2026-08-04 | 2.2.4 发布 | 新增 `authoritative_context_indicators` 默认关键词“黑产/扩展/扩线”，命中后强制标准路由并跳过 ICP/DGA 白证据，直接输出 block；源树与独立发布包均为 `656 passed`，10,856 条脱敏快照迁移仅有 253 条待复核转黑、黑白互转 0；发布提交 `19f58ef13a07c38d2f922b86160bf9f6f19229a8` 与附注标签 `v2.2.4` 已推送；发布包 `ioc_rejudge_v2.2.4_20260804-161114.zip` 含 96 个发布文件、禁入项 0、SHA-256 `a4e64b68a727095fa570e0e2692a8d8ece39ff212358f3332fb6208032985791`，GitHub Release 与 ZIP 资产已发布，无 force push |
| 2026-06 | v1.4.1 | 建立离线快照解析、IOC 归一化、A-F 证据、画像、裁判、导出、诊断和发布脚本；历史详情见 `docs/HISTORY.md` |
| 2026-07-22 | 人工校准 | 完成首批 7 条和第二批 4 条人工研判，识别 DGA、时序、ICP、URL 作用范围和公开 APT 边界 |
| 2026-07-23 | 设计 | 确认多源聚合、DGA 专用规则、非 DGA ICP 人工门和灰状态；完成规格与两份实施计划 |
| 2026-07-23 | 文档 | 重建 README、协作上下文、架构、开发指南、历史和更新日志；仅文档变更，业务代码未修改；验证 6 个文件存在、相对链接 0 损坏、占位符 0、代码围栏成对 |
| 2026-07-23 | 开发提示词 | 将核心与在线实施计划拆成 22 份有依赖、可单独验证的开发提示词；validator 通过，最大任务 102 行、链接/启动词各 22、占位符 0；业务代码未修改 |
| 2026-07-23 | 任务 1 | 恢复 IOC Info 兼容脚本、脱敏工具和仓库内集成 fixture；专项 15 passed，全量 172 passed，敏感值模式扫描无匹配 |
| 2026-07-23 | 任务 2 | 新增 IocTarget、Observation、provider/freshness/route/disposition 类型，扩展灰结论、Evidence 来源和 Verdict 兼容字段；专项 9 passed，全量 178 passed |
| 2026-07-24 | 任务 3-4 | 完成统一输入解析、结构校验、provider 协议和 sidecar 状态语义；返修后全量 240 passed |
| 2026-07-24 | 任务 5 | 当前状态改为仅取最新记录，保留 RecordSnapshot 与历史 ICP，增加脏类型保护；全量 249 passed |
| 2026-07-24 | 任务 6 | 统一恶意样本语义、英文词边界、公开 APT 结构证据和 URL 作用范围，二次返修后专项 135 passed、全量 297 passed |
| 2026-07-24 | 任务 7 提示词 | 根据前四轮独立验收强化 DGA 优先级矩阵、时间等号边界、脏布尔/时间反例和真实 RED 门；提示词包 validator 通过 |
| 2026-07-24 | 任务 7 | 完成 DGA 专用有序裁判并通过第三次返修独立验收；专项 50 passed、全量 338 passed、语法编译通过；当时混合 aware/naive 的不可比较项按保守语义跳过，该行为已由 2.1.0 H1 的统一 UTC 比较取代 |
| 2026-07-24 | 任务 8 提示词 | 基于任务 7 验收强化非 DGA ICP 最高优先级、灰条件逐项反例、脏 WHOIS/ICP、DGA 隔离、真实 RED 与 disposition/scope_actions 契约；提示词包 validator 通过 |
| 2026-07-24 | 任务 8 | 完成非 DGA ICP 最高优先级人工门、完整灰条件、DGA 隔离及 route/disposition/scope_actions 契约；联合专项 139 passed、全量 383 passed、语法检查和五分支真实探针通过 |
| 2026-07-24 | 任务 9 | 完成精确 DGA-only 路由、provider 异常隔离、统一 pipeline、裸 IOC/sidecar CLI 和旧快照包装器兼容；专项 24 passed、全量 401 passed、CLI help 与三模块语法检查通过 |
| 2026-07-24 | 任务 10 | 扩展 route/disposition/scope/provider 导出，JSONL 保留结构、CSV/Excel 稳定 JSON，Excel 分为统计/总/判黑/灰/误报/待复核且待复核不再计黑；联合专项 24 passed、全量 402 passed |
| 2026-07-24 | 任务 11 | 将 11 类人工原因固化为合成 `.invalid` 证据回归，新增确定性 verdict diff；修复结构化公开 APT 被威胁残留误降复核的通用优先级；专项 19 passed、全量 421 passed、敏感模式扫描无匹配 |
| 2026-07-24 | 任务 12 | 完成核心离线验收：全量 421 passed；裸 IOC DGA 与 legacy snapshot smoke 通过；全数据按 original_ioc 对齐 10,853 个唯一输入且结论迁移为 0；4 个临时输出已清理，fixture/新增源码无凭据匹配 |
| 2026-07-24 | 任务 13 | 新增 secret-safe ProviderSettings 和 provider 级 append-only JsonlProviderCache；覆盖稳定 query key、TTL 等号、坏行恢复、200 路跨实例线程追加和落盘脱敏；专项 19 passed、全量 440 passed |
| 2026-07-24 | 任务 14 | 新增可注入 RequestsTransport，将 timeout/connection/http/json_decode 精确分类并清洗 URL 凭据/query/header/body；transport 11 passed、共享基础设施 30 passed、全量 451 passed |
| 2026-07-24 | 任务 15 | 将 IOC Info 请求、dict/list 规范化、定向空结果重试和历史 main 迁入统一 provider；根脚本改为薄重导出；专项 21 passed、CLI 联合 31 passed、全量 463 passed |
| 2026-07-24 | 任务 16 | 新增 K01 compromises 批量 provider；保留五类 IOC 原始请求形态，按三个 ignore flag 隔离缓存，严格规范化 tags 并仅允许 DGA-only 进入专用路由；专项 21 passed、全量 473 passed、语法编译通过 |
| 2026-07-24 | 任务 17 | 迁入 F-Dark 已审阅 IOC 查询变体，默认仅请求快速主变体；复用统一恶意样本语义并支持完整 query cache/offline/refresh；专项 11 passed、样本语义联合 102 passed、全量 484 passed |
| 2026-07-24 | 任务 18 | 新增 domain/URL/domain:port WHOIS provider，区分获取时间、注册日期和缓存 freshness，失败时仅附 stale 审计；修复统一 facts 将查询时间误作到期时间；WHOIS+DGA 47 passed、全量 495 passed |
| 2026-07-24 | 任务 19 | 新增 domain 类 pDNS provider，逐条保留完整解析记录和 raw cache，坏 Unix 时间不回退当前时间，stale 不参与 DGA 白；pDNS+DGA 47 passed、全量 506 passed |
| 2026-07-24 | 任务 20 | 新增五源 Provider 工厂与在线 CLI 参数；密钥仅取环境变量，本地 JSON 只覆盖非密钥项，缺凭据独立 disabled；cache 与 run/raw 分离并支持无凭据 offline replay；联合 31 passed、全量 527 passed、哨兵扫描零匹配 |
| 2026-07-24 | 任务 21 | 使用单个有界线程池并发不同 Provider，按配置/输入顺序确定性归并并隔离 future 异常；新增逐 IOC freshness 契约，必要样本 stale/unknown 不计完整；并发专项连续五轮各 12 passed、全量 534 passed |
| 2026-07-24 | 任务 22 | 完成九场景全 mock 在线验收、移除凭据后的 offline exact replay、五源 raw 审计与 IP:port applicability；联合专项 13 passed、全量 535 passed；无真实网络，JSONL/CSV/Excel XML/diagnostics/cache/raw/log 的 sentinel 凭据扫描零匹配 |
| 2026-07-25 | 2.0.0 发布准备 | legacy 坏 URL 改为按行隔离并写入 diagnostics；新增运行/开发依赖清单和纯文件系统 allow-list 打包器，发布包带 `RELEASE.json` 且排除数据、输出、缓存与内部实施材料；README、架构、开发指南和更新日志同步为当前能力；全量 538 passed，`pack.py --check` 通过 |
| 2026-07-26 | 开发提示词 | 将显式 ICP 与运营证据计划审计并拆成 8 份串行、每份不超过 5 个可修改文件的开发提示词；修正 offline replay 无凭据与在线凭据门的计划冲突，记录未定义速率上限风险；生成前实测全量 538 passed、`pack.py --check` 通过，提示词包 validator 通过 |
| 2026-07-26 | 总控开发提示词 | 任务 1-3 已完成并独立复验至全量 555 passed；新增 139 行剩余任务总控入口，先复验既有基线，再连续执行任务 4-8 的开发、返修、独立验收与最终文档闭环；bundle validator 通过、占位符 0、安全护栏和最终验证命令齐全 |
| 2026-07-26 | 任务 4-8 总控闭环 | 完成 current ICP、显式 opt-in ICP provider/factory/CLI、R003/R013 校准与在线离线 exact replay；全量 588 passed，focused 78 passed，默认/缺凭据/offline miss zero-call，真实 requests fail-fast、sentinel 扫描、CLI help 与 pack check 通过；真实 endpoint 仍待授权凭据验收 |
| 2026-07-26 | ICP 独立验收返修 | 修复 provider 聚合 error 仍消费残留 ICP Observation、响应回显凭据落盘/进入 Observation 和字段优先级错误；新增标准/DGA 状态门、cache/run raw 脱敏、确定性限速与 2-worker 峰值回归，全量 596 passed；匿名迁移为白转黑 1、转复核 1，其余关键变化 0；真实 endpoint 与 workers/rate 产品硬上限仍待外部确认 |
| 2026-07-26 | 控制台可见性与迁移对比 | 统一模式新增启动 provider 清单与 disabled 原因、逐 provider 完成进度与耗时（`duration_seconds` 进 diagnostics）、结束逐源状态计数、被拒绝输入行计数与总耗时；新增 `--diff-baseline`/`--diff-output` 确定性迁移报告，baseline 运行前 fail-fast 并兼容旧快照模式；Excel 评审 sheet 新增判定原因（紧随结论）、评审建议与缺失必要来源列；14 项专项先失败后实现，全量 610 passed 零回归 |
| 2026-07-27 | H2/H3 高危修复 | CSV/Excel 自由文本统一中和公式前缀且 JSONL 保真；脏 `level` 统一规约并补齐 legacy/统一 pipeline 逐 IOC 容错；专项 22 passed、全量 617 passed |
| 2026-07-27 | H1 高危修复 | DGA aware/naive 时间统一为 UTC 比较，默认生产路径近期 pDNS 恢复判白且近期恶意样本恢复存活标签；联合专项 79 passed、全量 618 passed；脱敏全量代理 10,853 个唯一 IOC 变化 0、白转黑 0，定向默认路径验证旧失活有效转误报 |
| 2026-07-27 | 2.1.0 发布 | 最终全量 620 passed、发布暂存树独立 620 passed、`pack.py --check` 91 个文件；生成 `ioc_rejudge_v2.1.0_20260727-094833.zip` 并审计禁入条目 0；保留 GitHub 既有 v1.2.0 历史，`master` 快进至 `fa8c270`，已推送附注标签 `v2.1.0`，无 force push |
| 2026-07-27 | 2.1.1 本地凭证文件 | 新增 `--credentials-file` 固定字段 JSON 来源，指定后不回退环境变量；发布包带空白示例并排除 `credentials.local.json`；专项 36 passed、全量 625 passed、发布清单 92 个文件 |
| 2026-07-27 | 2.1.2 联网更新 | 解压版更新器改用 GitHub Releases API 下载并校验最新 ZIP，不再对非 Git 工作树执行 pull；更新器专项 5 passed、全量 630 passed |
| 2026-07-28 | 分接口缓存与请求规划 | 六源默认启用；K01/IOC Info/F-Dark/WHOIS/pDNS 默认缓存 7 天、ICP 30 天并支持逐接口配置；缓存改为 provider 独立日期分片且兼容旧格式；pipeline 先发现再按 domain/DGA/灰分支规则请求 ICP/WHOIS/pDNS；统一模式默认使用 `provider-cache`，发布包加入配置示例；全量 634 passed、语法编译、pack check 和示例解析通过 |
| 2026-07-28 | 研判结果缓存 | 新增 `.cache_adjudication_results/cache_YYYY-MM-DD.jsonl`，默认缓存规范化 IOC 与完整结果 7 天；以快照/规则/provider 公开配置及凭据身份摘要防止误用旧结论，支持 partial hit、离线复用、refresh 绕过、错误结果重试和坏行恢复；控制台/diagnostics 显示 hit/miss；全量 641 passed，实际 CLI 双跑第二次 hit=1/miss=0 且无 provider 采集 |
| 2026-07-28 | 2.2.0 发布 | 源树、发布包独立树及远端临时克隆均为 641 passed；发布包 `ioc_rejudge_v2.2.0_20260728-121130.zip` 含 96 个发布文件与 `RELEASE.json`，禁入项 0；发布提交 `aca70478ca086487a18f2ec8b225c7a18b4c64db` 已快进推送，附注标签 `v2.2.0` 已推送且无 force push；GitHub Release 已发布并上传同名 ZIP 资产 |
| 2026-07-28 | 更新器确认门 | `upgrade.py` 联网流程改为先查 GitHub Release 是否有新版，发现新版后再询问是否下载安装；拆分 `_check_latest_release` 与 `_download_latest_release`；更新器专项 7 passed、全量 643 passed |
| 2026-07-28 | 2.2.1 发布 | 更新器确认门改动；提交 53ad8b2 已快进推送 master 并推送标签 v2.2.1，无 force push；GitHub Release v2.2.1 已发布并上传同名 ZIP 资产 |
| 2026-07-29 | 2.2.2 发布 | 普通 operator/context 改为同记录 level 准入，低等级 domain 的具体恶意 URL 输出灰并保留 path，高等级在强业务闭环+显式资产变化+无残留时保留误报出口；完整结果缓存契约升级；源树与独立发布包均为 650 passed；发布提交 `6dfb85431e2ba9ddc38d7371dab54815c0c9a7c8` 已快进推送并创建附注标签 `v2.2.2`；发布包 `ioc_rejudge_v2.2.2_20260729-165700.zip` 含 96 个发布文件、禁入项 0，GitHub Release 与 ZIP 资产已发布，无 force push |
| 2026-07-30 | 2.2.3 发布 | K01 批量响应在写入 per-IOC cache key 前按目标节点隔离，保留响应包络和无网络离线回放契约；K01 专项 11 passed、provider/pipeline/online-offline 联合专项 161 passed，源树与独立发布包均为 651 passed；发布提交 `bf723ab82e0323ef2ec9488e73635ee95ab18e28` 和附注标签 `v2.2.3` 已快进推送；发布包 `ioc_rejudge_v2.2.3_20260730-001216.zip` 含 96 个发布文件、禁入项 0，GitHub Release 与 ZIP 资产已发布，无 force push |
