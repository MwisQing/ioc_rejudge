# 更新日志

## 未发布

## 2.2.8 - 2026-08-11

- 修复：完整研判结果缓存现在感知 provider 原始缓存分片状态；删除或清空某个接口缓存后不再错误复用旧 verdict，而是以 `fingerprint_mismatch` 重新采集。
- 修复：provider 采集完成后使用最新原始缓存状态写入完整结果指纹，避免首次写入后下一次运行产生不必要的缓存 miss。
- 变更：ICP 默认并发和限速由 `2 workers / 2 requests per second` 提升为 `8/8`；仍可通过 `providers.icp.workers` 和 `providers.icp.rate_per_second` 覆盖，接口出现限流时建议降为 `4/4`。
- 验证：结果缓存、ICP 和 provider 工厂专项 `60 passed`；全量测试、发布包独立测试及发布审计见本版本发布记录。

## 2.2.7 - 2026-08-10

- 修复：K01 compromises 不再把全部 IOC 放进单个批量请求，默认按 100 条分批；某批返回 `10002` 等业务错误时只影响该批，其他批次继续查询并复用已写入的 provider cache。
- 变更：`provider-config.json` 支持 `providers.k01_compromise.batch_size`；K01 业务错误 diagnostics 现在包含接口 `msg`，并对可能回显的凭据做清洗。
- 验证：K01/provider/live/offline 联合专项 `190 passed, 1 skipped`，全量 `713 passed, 1 skipped`。

## 2.2.6 - 2026-08-10

- 新增：在线统一研判时在控制台逐接口显示实时进度条，格式为 `[provider] done/total 耗时`；stderr 为终端时用 ANSI 原地重绘，重定向或管道时降级为节流行输出避免刷屏，重复终态自动去重。
- 新增：发布运行包内置 Go HTTP 批处理 worker，六个在线 provider 在不改变 Python 解析、缓存、Observation、诊断和裁判语义的前提下复用连接并按各自 `workers`/`rate_per_second` 并发请求；worker 缺失时保留 Python transport 回退。
- 修复：provider 缓存与完整研判结果缓存由逐 IOC 重复扫描全部 JSONL 分片改为按文件签名惰性建立索引并在写入时增量更新，批量重跑及首次缓存写入不再出现接近二次方的读取退化。
- 修复：`python ioc_rejudge\cli.py ...` 可从项目根目录直接运行；`python -m ioc_rejudge.cli ...` 保持兼容。
- 变更：CLI 启动显示绝对缓存目录、reuse/refresh/offline 模式、结果缓存 TTL、已有分片数和 Go/Python HTTP worker；结束始终显示结果缓存 hit/miss 与 missing/stale/fingerprint_mismatch/refresh 原因。Ctrl+C 以 130 退出并说明已落盘 provider 缓存可复用、未完成研判结果不缓存。
- 修复：`push.py --check` 现在严格只读，只校验 Git 仓库、origin、分支和本地状态，不再执行分支或标签推送。
- 验证：真实 Windows `provider_http.exe` 通过本地 HTTP 并发、限速、GET/POST、121 请求管道、HTTP/JSON/超时和凭据不泄漏验收；Python 全量 `708 passed, 1 skipped`，Go `go test ./...`、语法编译、`pack.py --check`（102 个发布文件）和 `git diff --check` 通过。

## 2.2.5 - 2026-08-05

- 修复：同一 IOC 多条 ioc_info 记录的 `comment/context` 只取按 `updatetime`、`inserttime`、`disposaltime` 和原始顺序确定的最新记录；最新备注为空时不回填历史备注。
- 变更：最新备注中的“黑产、扩展、扩线”作为强恶意证据，但不再永久锁黑；仅在 WHOIS 已过期、无近期活动、当前 ICP+官网闭环、显式资产变化和无威胁残留同时成立时允许判误报。“恶意”进入普通强恶意上下文，不作为无条件直接判黑关键词。研判结果缓存契约升级，避免复用旧裁判结论。
- 验证：全量测试 `670 passed`；10,856 条脱敏快照相对 v2.2.4 有 505 条黑结论转为待复核（494 条存活有效、11 条失活有效），黑转白、白转黑、转灰和成员变化均为 0；严格过期误报出口与缺少 WHOIS 反例由合成回归覆盖。

## 2.2.4 - 2026-08-04

- 新增：规则配置支持 `authoritative_context_indicators`，默认识别 comment/context 中的“黑产”“扩展”“扩线”；命中后跳过 DGA 白证据和普通 ICP 门，直接输出 `block` 黑结论，并在原因中记录命中词。
- 验证：关键词、路由、统一 pipeline 与人工校准专项通过；全量测试 `656 passed`；脱敏快照 before/after 共 10,856 条，新增规则只产生 `待复核→存活有效/失活有效`，黑白互转为 0。

## 2.2.3 - 2026-07-30

- 修复：K01 批量查询不再将包含整批 IOC 的完整 `data` 重复写入每个 per-IOC cache key；每个 `.cache_k01_compromise` 条目只保留当前 IOC 节点。
- 兼容：缓存仍保留 K01 `status`、`msg` 等响应包络，新缓存可按原 provider 解析路径完成无网络离线回放。
- 验证：K01 回归先复现了整批响应串入每个 key 的旧行为，修复后 K01 专项 `11 passed`，provider/pipeline/online-offline 联合专项 `161 passed`，源树全量 `651 passed`。

## 2.2.2 - 2026-07-29

- 修复：普通运营来源和上下文恶意词不再绕过 `historical_malicious_level` 直接把低等级 domain 判黑；多记录聚合时由承载恶意上下文的记录自身完成等级准入，禁止借用其他记录的高 level。
- 变更：低等级 domain 若仍有关联的具体恶意 URL 且无合格恶意样本，输出 `灰`，domain 不继续拦截且不加入白名单，并通过 `scope_actions` 保留带 path 的 URL。
- 变更：达到恶意等级只进入黑证据裁判；普通 operator 上下文在强正常业务闭环、显式结构化资产变化且无威胁残留时允许判为 `误报`，clue-group 无条件 block 语义保持不变。
- 修复：完整研判结果缓存指纹升级裁判契约，规则实现更新后不再复用旧 verdict；Provider 原始响应缓存仍可离线复判。
- 验证：证据/裁判/缓存专项 `163 passed`、人工校准 `12 passed`；全量 `650 passed`，语法编译通过；缓存样本迁移为 1 条 `存活有效→灰`、1 条 `存活有效→存活有效`，无黑白互转。

## 2.2.1 - 2026-07-28

- 变更：`upgrade.py` 联网更新流程改为先查询 GitHub Release 发现是否有新版，确认存在新版本后再询问用户是否下载并安装；不再在不知道是否有新版时即要求用户决定是否联网检查。
- 重构：拆分 `_check_latest_release`（只查版本不下载）与 `_download_latest_release`（确认新版后下载安装），`main` 的 GitHub 分支按检查→确认→下载→安装顺序串联。
- 验证：更新器专项 7 passed（新增 `_check_latest_release` 版本比较、当前版本跳过与非法 tag 三项），全量 643 passed。

## 2.2.0 - 2026-07-28

- 新增：六个 live provider 均进入默认来源；domain 类目标执行当前 ICP 验证，DGA 路由再追加 WHOIS/pDNS，普通路由仅在历史 URL/钓鱼灰分支需要时追加 WHOIS，IP 类跳过三类生命周期接口。
- 变更：K01、IOC Info、F-Dark、WHOIS、pDNS 默认缓存 7 天，ICP 默认 30 天；每个 provider 均可通过本地配置单独覆盖 TTL。
- 变更：缓存改为 `.cache_<provider>/cache_YYYY-MM-DD.jsonl` 的逐接口日期分片，并兼容读取旧 `<provider>.jsonl`；统一模式未指定 `--cache-dir` 时默认使用 `.\provider-cache`。
- 新增：发布包包含 `provider-config.example.json`，列出六个接口的默认缓存天数及 ICP 并发/限速配置。
- 新增：规范化 IOC 的完整研判结果默认缓存 7 天，使用独立日期分片；输入快照、规则、provider 选择或公开查询配置变化时自动重新研判，命中时跳过 provider 请求。
- 变更：`provider-config.json` 顶层 `result_cache` 可设置 `enabled` 和单一 TTL；`--refresh` 同时绕过 provider 与研判结果缓存，diagnostics/控制台显示结果缓存 hit/miss。
- 验证：全量 `641 passed`，实际 CLI 双跑第二次 `hit=1 miss=0` 且无 provider 采集；`python -m compileall -q ioc_rejudge tests`、`python pack.py --check` 和示例配置解析通过。

## 2.1.2 - 2026-07-27

- 变更：解压版项目的 `upgrade.py` 联网更新改为查询 GitHub Releases API、下载最新 `ioc_rejudge` ZIP 并复用安全合并安装，不再对 Release 解压目录执行 `git pull`。
- 校验：联网包在安装前验证 tag、ZIP 内 `VERSION` 和安全成员路径；当前版本不低于最新 Release 时直接报告已是最新。
- 验证：GitHub Release 选择、API 查询、流式下载、当前版本跳过和版本不一致清理专项 `5 passed`；全量 `630 passed`。

## 2.1.1 - 2026-07-27

- 新增：`--credentials-file` 支持从项目目录的独立 JSON 文件读取固定白名单凭据；指定后不回退系统或进程环境变量。
- 新增：发布包包含空白 `credentials.example.json`；实际 `credentials.local.json` 已加入 `.gitignore` 并保持在发布 allow-list 之外。
- 保持：`--provider-config` 继续只承载 endpoint、TTL、超时等非密钥配置，原环境变量凭据方式继续兼容。
- 验证：凭证文件结构、未知字段、类型、来源隔离、CLI 参数、发布排除和全量回归 `625 passed`。

## 2.1.0 - 2026-07-27

- 新增：ICP provider 作为显式 opt-in live source，支持按 host 去重、secret-safe cache、限速并发和 positive/negative `icp_registration` Observation。
- 新增：默认五源保持不变；`ICP_UC`、`ICP_KEY` 和可选 `ICP_URL` 仅在显式选择 ICP 时生效，offline 可无凭据回放 cache。
- 变更：fresh negative 当前 ICP 会完成当前检查并保留历史 ICP；clue-group 证据无条件 standard block，R013 校准为当前 ICP 确认不存在且运营恶意上下文判黑。
- 修复：provider 聚合状态为 error/disabled 时不再消费残留的 ICP success Observation，标准路由和 DGA 均保持保守语义。
- 修复：ICP 响应按字段优先级短路解析，写入 cache/run raw 前递归清洗服务端可能回显的当前凭据值。
- 验证：全量 `596 passed`，补充确定性限速和内部并发峰值测试；mock online/offline exact replay、zero-call、真实网络 fail-fast、sentinel 扫描和 `pack.py --check` 通过。真实 endpoint 生产验收及 workers/rate 产品硬上限仍待外部确认。
- 新增：`--diff-baseline`/`--diff-output` 输出与上次 result JSONL 的确定性结论迁移报告（黑白互转、转灰、转复核与成员变化），baseline 校验失败在研判前 fail-fast；旧快照兼容模式同样适用。
- 新增：统一模式控制台可见性——启动打印 provider 清单与 disabled 原因，逐 provider 完成进度与耗时输出到 stderr，结束打印逐 provider 状态计数、被拒绝输入行计数与总耗时；diagnostics `provider_metrics` 新增 `duration_seconds`。
- 新增：Excel 评审 sheet 增加 `判定原因`（紧随结论列）、`评审建议` 与 `缺失必要来源` 列，待复核评审无需交叉查 JSONL。
- 验证：全量 `610 passed`（新增 13 项控制台可见性、进度耗时与迁移对比专项，1 项 Excel 评审列专项），既有基线零回归。
- 修复：CSV 与 Excel 导出会中和以 `=`、`+`、`-`、`@`、Tab 或 CR 开头的自由文本，阻止电子表格公式注入；JSONL 继续保留原始值。
- 修复：顶层或嵌套 `level` 为 `null`、非数值字符串等脏值时统一按无有效等级处理，并将统一 pipeline 的序列化纳入逐 IOC 容错，单条坏数据不再击穿整批。
- 验证：公式注入与脏 `level` 专项 `22 passed`，全量 `617 passed`。
- 修复：DGA 时间比较统一将 aware datetime 转为 UTC 后去除时区，naive datetime 保持原值；生产默认时间改用 UTC，近期 pDNS 与恶意样本不再因 aware/naive 混用被静默忽略。
- 验证：DGA、统一 pipeline、九场景 mock、人工校准与迁移专项 `79 passed`，最终全量 `620 passed`（含 2 项发布 allow-list/忽略规则安全测试）；10,853 个唯一 IOC 的脱敏全量代理审计变化 0、白转黑 0，定向默认路径确认近期 aware pDNS 从旧 `失活有效` 修正为 `误报`。

## 2.0.0 - 2026-07-25

### 文档

- 重建根目录 README 和项目协作上下文。
- 新增当前/目标架构说明、开发验证指南和历史归档。
- 修正旧文档中与当前磁盘不一致的测试与文件状态。
- 将 README、架构和开发指南更新为已完成的 `2.0.0` 当前能力，不再把多源聚合写成未来计划。

### 已完成的核心基础

- 新增 Observation、provider 状态、route/disposition 和 `灰` 模型契约。
- 新增裸 IOC/旧快照统一输入解析与本地 JSONL sidecar provider，并接入统一 CLI pipeline。
- 新增记录级时序快照和当前/历史状态隔离。
- 新增独立 DGA facts 与专用裁判；恶意样本优先于白信号，样本查询不完整时进入待复核。
- 新增普通路由 ICP 人工门与运营证据优先级：未解决 ICP 进入待复核，clue-group 可直接判黑。
- 新增普通 domain 灰裁判；仅完整历史 URL 闭环可降灰，并通过 `scope_actions` 保留具体 URL。
- 新增统一分路 pipeline 和裸 IOC CLI；支持重复 `--ioc`、`--offline`、`--refresh` 与本地 `--provider-data NAME=PATH`，并保留旧快照 API/命令。
- DGA 仅在成功分类 tags 精确为 `dga` 时进入专用裁判；分类失败时保留强恶意闭环，白/灰候选降级为待复核。
- JSONL、CSV 和 Excel 已输出 route/disposition/scope/provider 扩展契约；Excel 增加独立灰与待复核 sheet，待复核不再计入判黑。
- 新增 11 类脱敏人工证据校准和确定性 verdict 差异报告，可筛选黑白互转、转灰、转复核以及新增/删除 IOC。
- 完成核心离线验收：裸 IOC DGA sidecar 回放与旧快照命令均通过，旧公开 API 保持兼容。
- 新增在线 provider 共用的 secret-safe settings 与 append-only JSONL TTL 缓存；坏行不阻断其他缓存，敏感映射值写盘前脱敏。
- 新增可注入 HTTP JSON 传输层，统一区分超时、连接、HTTP 和 JSON 解码错误，错误信息不包含认证请求细节。
- IOC Info 已迁入统一 provider，支持批量查询、按空 IOC 定向重试、offline/refresh 缓存语义；历史根脚本入口继续可用。
- 新增 K01 compromises 批量 provider；五类 IOC 保留原始请求形态，三个 ignore profile 独立缓存，只有规范化 tags 精确为 DGA-only 才能进入 DGA 专用路由。
- 新增 F-Dark provider；忠实迁移五类 IOC 查询变体，常规路径仅使用快速主变体，并复用核心恶意样本判定生成关联样本 Observation。
- 新增 WHOIS provider；仅查询 domain 类 host，完整保留注册日期和状态字段，严格区分获取时间、缓存新鲜度与域名到期事实，在线失败只附 stale 审计数据。
- 新增 pDNS provider；domain 类目标逐条保留完整解析活动，规范化 Unix 首末时间，坏时间保持不可比较且 stale 数据不参与 DGA 白信号。
- 裸 IOC CLI 已接通五个默认在线 Provider 和显式 opt-in ICP，支持本地非密钥配置、独立 cache/run 目录、refresh 与 offline replay；缺失凭据只禁用对应来源。
- Provider 凭据仅从明确环境变量读取；本地 JSON 禁止 secret 字段，诊断与 raw cache 不序列化认证值。
- 不同 Provider 通过单个有界线程池并发收集，最终仍按输入 IOC 与配置 Provider 顺序稳定输出；单个来源异常不会终止批次。
- DGA 自动白要求 IOC Info 与 F-Dark 均完成且结果新鲜；陈旧空缓存不再被视为“已证明无关联样本”。
- 完成含 ICP 正负事实的九个合成业务场景全 mock 在线验收；online cache 填充后可在移除全部凭据的情况下 exact offline replay，结论、原因、来源和顺序保持一致。
- 五个在线 Provider 的原始响应同时写入持久 cache 与当前 `run_dir/raw` 审计；JSONL、CSV、Excel XML、diagnostics、cache、raw 和日志的 sentinel 凭据扫描零匹配，验收过程无真实网络请求。
- 新增 `requirements.txt` 和 `requirements-dev.txt`，明确运行与测试依赖。
- 重建非 Git `pack.py`：严格读取 `VERSION`，使用显式 allow-list，支持 `--check`/`--output-dir`，并在 zip 中生成 `RELEASE.json` 成员清单；打包过程不改版本、不执行 Git 或网络操作。
- 发布包纳入业务代码、规则、测试、用户文档和兼容脚本，排除 IOC 数据、outputs、cache/run、内部提示词与实施材料。

### 修复

- 当前 ICP、WHOIS、HTTP 等状态只取最新记录，不再跨时间回填或拼字段。
- 统一关联恶意样本语义，排除 `not-a-virus`、低 level 和显式零 confidence。
- 英文恶意词改为 token-aware 边界，避免 `rat`/`c2` 子串误命中。
- `relate_url` 不再自动扩大为 domain 强证据；只保留结构、端口和作用范围均有效的 HTTP(S) URL。
- 新增公开 APT 的结构化组合证据，不依赖 IOC 值或人工来源特例。
- DGA 恶意样本时间改为逐项比较；混合时区时间不会因单个不可比较值丢失其他近期活动，也不会在全部不可比较时崩溃或放白。
- WHOIS 到期事实不再混入响应获取时间，已过期域名不会因“刚查询”被误判为当前未过期。
- 完整结构化公开 APT 组合不再被自身 APT 元数据误判为冲突残留；无正常业务证据时稳定保留为黑情报。
- 旧快照中的端口越界或其他无法归一化 URL 改为按行隔离：写入 diagnostics、继续处理后续 IOC，且不会降级成 domain 研判。

### 已知问题

- 真实 ICP endpoint、认证和生产响应仍需在授权环境中验收；自动测试不发真实请求，也不读取 `token_icp.txt`。
- 严格裸 IOC 校验会拒绝脱敏数据中的下划线占位域名；不会为测试占位符放宽生产 DNS 规则。

## 1.4.1

- 支持离线 JSONL 快照重判。
- 支持 domain、URL、domain:port、IP 和 IP:port 归一化。
- 提取 A-F 证据、画像观察和威胁残留。
- 输出 JSONL、CSV、Excel 和 diagnostics。
- 提供规则 JSON 覆盖、打包、推送和升级脚本。
