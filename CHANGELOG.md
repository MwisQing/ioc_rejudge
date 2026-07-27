# 更新日志

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
