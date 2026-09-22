# 架构说明

本文描述 IOC Rejudge CLI `2.7.0` 的当前实现。历史设计和实施计划保留在 `docs/superpowers/`，但不再作为当前能力清单。

## 1. 总体数据流

```text
legacy JSONL snapshot / bare IOC file / repeated --ioc
                         |
                         v
              parse, validate, normalize
                         |
             +-----------+-----------+
             |                       |
      legacy snapshot           unified input
       compatibility                  |
             |                 provider factory
             |          + live providers + sidecars
             |                       |
             |              bounded collection
             |                       |
             |             ordered Observations
             |                       |
             +-----------+-----------+
                         |
                  route selection
                 /               \
              DGA              standard
                 \               /
                  unified Verdict
                         |
             JSONL / CSV / six-sheet Excel
                     + diagnostics
```

离线路线入口另有一条适配链：`roadmap_cli.py` 和 UI workbench 只调用既有本地快照 pipeline 或受控文件操作，持久化 task、results、diagnostics 和人工 review overlay；provider 参数在离线后端中明确拒绝，不伪造联网成功。

系统保留两条入口，但共享核心归一化、证据与裁判语义：

- 兼容入口：未指定统一模式参数的 `.jsonl` 走 `run_pipeline_with_diagnostics()`。
- 统一入口：裸 IOC、`--ioc`、sidecar、live provider、cache 或 offline replay 走 `run_unified_pipeline()`。

## 2. 核心模型

### 2.1 IocTarget

`IocTarget` 保存原始值、规范化值、类型、host 和端口。支持：

- `domain`
- `url`
- `domain_port`
- `ip`
- `ip_port`

URL 保留 scheme、port 和 path，不自动降级成根 domain。输入边界统一验证 DNS label、IPv4 八位组和 `1-65535` 端口。

### 2.2 Observation

provider 只负责把外部或本地数据转换为 Observation，不直接输出最终黑白结论。主要字段：

```text
ioc, scope, provider, kind, status,
fetched_at, observed_at, freshness,
strength, payload, raw_ref
```

时间含义严格分离：

- `fetched_at`：响应获取或 cache 记录时间。
- `observed_at`：业务数据自身的观察时间。
- 样本 `last_seen`、pDNS 活动时间等才可能成为存活事实。
- 请求时间、`updatetime` 和 cache 写入时间不自动证明 IOC 活跃。
- 比较前统一转为 naive UTC；无时区输入保留既有墙上时间，带 offset 的 ISO-8601 输入换算为 UTC。无效值逐项跳过，不能满足 `recent`/`fresh`；未来值也不能满足这两个条件。

### 2.3 Verdict

统一 Verdict 同时表达结论和处置：

| 结论 | `disposition` | 语义 |
|---|---|---|
| `存活有效` | `block` | 当前恶意闭环且有近期活动 |
| `失活有效` | `block` | 历史恶意闭环成立，仍保留拦截 |
| `灰` | `gray` | 当前范围不继续拦截，也不加入白名单 |
| `误报` | `false_positive` | 恶意判断不成立 |
| `待复核` | `review` | 必要证据缺失、冲突或来源失败 |

`scope_actions` 和 `retained_urls` 表达作用范围，例如 domain 降灰但保留具体恶意 URL。

## 3. 模块边界

| 模块 | 职责 |
|---|---|
| `inputs.py` | 裸 IOC/快照识别、编码处理、结构校验、去重和错误记录 |
| `parser.py` | 兼容 JSONL 快照、ISO/legacy 时间解析、UTC 归一化和统一 freshness/recent 比较 |
| `normalize.py` | IOC 规范化（`parse_ioc_value` 保留 URL scheme 的统一身份；`normalize_ioc` 为历史 scheme-less 契约）、记录时序排序和 dossier 聚合（merge 使用 scheme-aware 身份） |
| `models.py` | Evidence、RecordSnapshot、IocDossier、Verdict |
| `observations.py` | IocTarget、Observation、provider/freshness/route/disposition 类型 |
| `profile.py` | domain、IP、HTTP 和运行时画像 |
| `business_identity.py` | 画像与证据共用的可信业务字段和网站主体关系校验 |
| `review_queue.py` | 待复核结果队列与人工标签的本地 JSONL 辅助读写；CLI 只追加人工 overlay，不覆盖系统结论 |
| `roadmap_cli.py` | 离线 job/review/explain/history/health/cache/table import/export-bundle 命令适配 |
| `workbench_backend.py` | 本地离线快照 workbench 任务、诊断、结果、复核和导出持久化 |
| `input_adapters.py` | CSV/XLSX IOC 导入、物理行号、defang/公式风险与重复报告 |
| `export_bundle.py` | JSONL/CSV/XLSX/diagnostics/diff bundle 原子导出与冲突预检 |
| `cache_admin.py` | provider/result cache 统计与整 shard dry-run/apply 清理 |
| `evidence.py` | A-F 证据、样本语义、APT 组合和 URL 作用范围 |
| `routing.py` | 可靠 DGA-only 分类与分类失败降级 |
| `dga.py` | DGA facts 和有序硬规则裁判 |
| `adjudicator.py` | 普通 IOC 五类结论、ICP 人工门和灰规则 |
| `pipeline.py` | provider 并发、Observation 归并、facts/dossier 构建和分路 |
| `files.py` | 路径解析/相等、可写性预检（含已存在目标的 sibling 探测）、单一 atomic 写入原语 `atomic_write_via`（仅 sibling temp + `os.replace`） |
| `export.py` | JSONL（按行流式）、CSV、六表 Excel |
| `diff.py` | Verdict 转移和成员变化报告 |
| `config.py` / `rules.py` | 阈值和规则配置 |
| `cli.py` | 参数解析、两条入口编排、输出和 diagnostics |
| `share.py` / `share_text.py` | 本地口令保护的 AES-SIV token bundle、v0.7 形态自由文本扫描、流式严格扫描和 token restore |
| `ui.py` + `ui.html` | 本地 share 助手：回环 HTTP 服务与单文件页面，可折叠 JSON 查看、IOC Info lookup 和「脱敏并复制」 |

## 4. Provider 架构

`providers/base.py` 定义 `Provider` 协议、不可变 `ProviderContext` 和 `ProviderResult`。每个请求 IOC 必须得到明确状态：

- `success`
- `no_data`
- `error`
- `disabled`

`error` 和 `disabled` 绝不等价于“已查询且无数据”。必要来源失败会阻止自动白或灰，但普通强恶意闭环仍可保留黑结论。

当前 provider：

| Provider | 作用 | 网络状态 |
|---|---|---|
| `k01_compromise` | 可靠 DGA-only 分类 | live |
| `ioc_info` | IOC 详情、关联记录和证据 | live |
| `fdark` | 关联恶意样本与活动时间 | live |
| `whois` | 当前注册和到期事实 | live |
| `pdns` | 完整解析活动记录 | live |
| `icp` | 按 host 去重的当前备案 positive/negative Observation | live |
| `SidecarProvider` | 任意预取 Observation，包括 ICP | local |

factory 默认构造六源；缺少 ICP 凭据时只将 ICP 标记为 `disabled`。自动验收只使用 mock/cache，真实 endpoint 风险单独保留。

ICP 响应按 `resultObject.website_icp_num`、`resultObject.icp`、`rows[0].website_icp_num`、`rows[0].icp` 逐级短路规范化；已获得有效高优先级值后，不再让无关的低优先级坏字段推翻结果。成功空结果输出 `kind=icp_registration`、`status=success`、`payload={"current": false, "registration": ""}`；这是真实的 typed negative fact，不是 `no_data`。正结果只输出非空字符串备案号。`resultCode=3003` 或 `身份校验失败` 是认证/业务失败，输出 `error`，不得写成 typed negative，也不得覆盖 IOC Info 备案字段。

### 4.1 工厂与配置

`providers/factory.py` 负责：

- 保持默认 provider 顺序。
- 从非密钥配置或环境变量读取 endpoint，从显式本地凭证文件或兼容环境变量读取凭据。
- 从本地 JSON 读取非密钥配置。
- 对缺凭据来源单独标记 `disabled`。
- 构造 live 或 fail-closed offline transport。
- 分离持久 cache 与当前 run 审计目录。

非密钥 provider 配置拒绝 secret/token/password/authorization 类字段。`enabled` 与布尔查询选项要求真正的 JSON boolean；数值选项（含 `max_attempts`、允许为 0 的 `retry_delay`）在 `load_local_config` 阶段统一校验，即使该 provider 本轮未选中。独立凭证文件只接受固定认证字段，指定后不回退环境变量；ProviderSettings 的表示形式和异常信息不会暴露认证值。

ICP 默认限制为 8 workers 和 8 requests/second。配置层目前只校验二者为正数，尚未定义产品级硬上限；接口出现限流、超时或业务错误时可通过本地配置降为 4/4，生产配置必须遵守接口所有者批准的上限。

### 4.2 HTTP 传输

`providers/transport.py` 提供可注入 JSON 传输，统一分类：

- timeout
- connection
- HTTP error
- JSON decode error
- offline

生产路径默认把 JSON HTTP 交给捆绑的 Go worker；Python 仍负责解析、缓存和裁判。worker 按块拉起，一块失败不得中断后续块。测试可注入 Python transport 完全阻断真实网络。根目录 `iocProducer_api_ioc_info.py` 是旧调用方兼容薄入口，不属于统一 provider 的传输边界。

### 4.3 Cache 与审计

`JsonlProviderCache` 使用稳定 query key、provider 独立目录和按日 append-only JSONL：

- 默认缓存目录为 `.\provider-cache`；每个接口写入 `.cache_<provider>/cache_YYYY-MM-DD.jsonl`，不共用永久单文件。
- K01、IOC Info、F-Dark、WHOIS、pDNS 默认 TTL 7 天，ICP 默认 30 天；本地配置可逐接口覆盖。
- K01 批量查询默认按 100 个 IOC 分批，批大小可由非密钥 provider 配置覆盖；批次级 transport/业务错误只标记该批，其他批次继续处理。
- 读取跨日期分片选择同一 query key 的最新响应，并兼容旧 `<provider>.jsonl`。
- 内存索引只保存 key、分片路径、字节偏移和 `fetched_at`，不驻留 `raw`；`get` 按偏移读一行。
- K01 批量请求在为 per-IOC query key 写入缓存时保留响应包络，但 `data` 只保留当前 IOC 节点；离线回放与在线解析使用同一响应契约。
- 坏 cache 行不会阻断其他有效行。
- stale 结果可用于审计，但不能伪装成新鲜白证据。
- cache freshness 使用包含边界的 `0 <= now - fetched_at <= ttl`；精确 TTL 仍算 fresh，未来或无效 `fetched_at` 按 stale/miss 处理，aware/naive 输入可安全混用。
- ICP cache key 只含 endpoint/host；写入 cache 和 `run_dir/raw` 前按当前 `uc`/`key` 值递归脱敏，避免服务端回显值进入 raw 或错误文本。
- `--refresh` 绕过 cache。
- `--offline` 只能读取 sidecar/cache，不允许网络回退。
- 在线响应同时写入持久 cache 和 `run_dir/raw` 审计副本。

### 4.4 请求规划

live pipeline 分两阶段收集，避免每个 IOC 无条件请求全部接口：

1. K01、IOC Info、F-Dark 完成分类、情报详情和关联样本发现。
2. domain 类目标总是验证当前 ICP；DGA 路由追加 WHOIS/pDNS；standard 路由只有历史 URL/钓鱼证据可能形成灰分支时追加 WHOIS；IP 类跳过三类生命周期接口。

Sidecar 和自定义非 live provider 继续按原 provider 协议执行，不被 live 请求规划器改写。未请求的 provider/IOC 组合显式记录为 `disabled`，与查询完成后的 `no_data` 区分。

### 4.5 研判结果缓存

`AdjudicationResultCache` 位于 provider 缓存根目录的 `.cache_adjudication_results/cache_YYYY-MM-DD.jsonl`，默认 TTL 7 天。每行保存规范化 IOC、配置指纹、研判时间、可选 `valid_until` 时间边界和完整 verdict 输出。

当前裁判缓存契约为 `12`。契约 10 起：目标身份保留 URL scheme（`case.invalid` / `http://…` / `https://…` 为三个独立目标）；指纹对每个目标关联其依赖的 provider 原始缓存记录摘要（fetched_at + raw + params，含 absence），而不是全局分片存在位；sidecar 内容哈希按 `(path, mtime_ns, size)` 在单次 run 内复用。契约 11 起：`valid_until` 取全部已评估实质活动事件的最早 inclusive 上界（快照/IOC Info 的 hash·flint·access·dtree，pDNS 窗口，WHOIS 日期；未来事件在激活时刻前 1µs 截止），并纳入依赖 provider 原始缓存的 `fetched_at+TTL`（含 NO_DATA 完整性）。契约 12 起：`fetched_at+TTL` 边界扩展到 sidecar 行（含显式 fresh 的 NO_DATA 完整性），未来 fetched_at 在激活时刻（前 1µs）截止复用，配置指纹纳入 sidecar TTL。同一天内越过边界时以 `temporal_expired` miss 并重算，无时间敏感证据的 30 秒内重复运行仍可 hit。旧契约行不会被误用；历史 provider 原始缓存文件不迁移。

配置指纹覆盖 scheme-aware IOC 身份、输入快照记录、规则/阈值、provider 顺序、公开 settings、查询选项、sidecar 内容摘要与 TTL、凭据身份摘要和**按目标**的 provider 原始依赖摘要；凭据原文不序列化、不落盘。只有新鲜、指纹完全相同且未越过 `valid_until` 的结果才会命中，命中目标在 provider 收集前被移出 pending 集合。同一目标原始响应追加或真正消失会造成该目标 `fingerprint_mismatch`，不牵连无关 IOC；生产 provider 原始缓存没有删除 API。部分命中时只为 miss 目标执行 provider pipeline，最终按输入顺序归并。provider `error` 或必要来源缺失的结果不落盘。`--refresh` 强制全部 miss；坏行只进入 `result_cache_errors`，不阻断其他有效结果。

## 5. 并发与确定性

Go HTTP worker 按块提交任务（默认 `max(workers * 2, 8)`，低内存档更小）。一块的进程崩溃或输出损坏时，只把该块未完成 job 记为 transport `error`，后续块继续；`collect()` 仍返回 `ProviderResult`，不会把整路 IOC 打成 pipeline 级失败。

CLI 按物理内存封顶 HTTP workers、`Config.provider_workers` 和每进程 job 数；约 4 GiB 为 2/2/4，约 8 GiB 为 4/3/8，更大内存不封顶。`IOC_REJUDGE_MEMORY_PROFILE=full` 关闭封顶。Provider 缓存索引只保留 key 与文件偏移，`raw` 在 `get` 时按行读取。

pipeline 在每个收集阶段使用有界线程池并发不同 provider。并发只影响采集时延，不改变业务顺序：

- IOC 按输入首次出现顺序输出。
- provider 按配置顺序归并。
- 同一 IOC 内 Observation 保留 provider 原始顺序。
- 单个 future 异常转换为该 provider 的 `error`，不会终止整批任务。
- 同一组有效 Observation 在 online 和 offline replay 中产生相同 Verdict。

## 6. 时序聚合

旧快照中的多条记录先按记录时间和原始 index 稳定排序。当前状态只来自唯一最新记录：

- WHOIS、HTTP、ICP、官网、标题和解析 IP 不跨记录回填。
- WHOIS 字典不跨记录拼字段。
- 旧 ICP 保存在 `historical_icp_values`，只用于冲突审计，不冒充当前 ICP。
- provider merge 完成后，统一聚合 `icp/icp_record/icp_registration` 类型且 freshness 为 `fresh` 的 Observation；单条状态与该 IOC 的 provider 聚合状态均须为 success，`current` 须为布尔值，positive 须含非空备案值。仅 positive 时确定性选择备案值并完成检查；仅 negative 时清空当前备案并完成检查；两者并存时设置 `current_icp_conflict`、保留原字段并标记检查未完成。错误、禁用、未知 freshness 和 stale 不能提供当前事实，输入顺序不决定冲突结果。标准路由与 DGA 使用同一聚合边界，历史 IOC Info 备案不提供 DGA 当前 ICP 白信号。
- RecordSnapshot 保留原始 index、时间、来源和 raw 记录。
- hash、family、source 等历史恶意集合仍可跨记录聚合。

## 7. 路由和裁判

### 7.1 DGA 路由

只有成功且规范化 tags 精确为 DGA-only 的可靠分类进入 DGA 路由。域名形状、熵或旧 `dga_score` 不足以自动路由。

DGA 规则按固定顺序执行：

1. 关联恶意样本优先，按可比较的样本时间区分存活/失活。
2. 当前 ICP 正负冲突时进入待复核，不能由生命周期白信号覆盖；若第 1 条已保留黑结论，也标记必须复核。
3. 样本查询不完整或不新鲜时进入待复核。
4. 无恶意样本且当前 ICP 存在时判误报。
5. 无恶意样本且 WHOIS 未过期时判误报。
6. 无恶意样本且 pDNS 在配置窗口内时判误报。
7. 查询完整且无白证据时保留失活有效。

`not-a-virus`、低 level 和显式零 confidence 不算关联恶意样本。混合 aware/naive 时间逐项按 UTC 比较，单个不可比较时间只跳过自身；未来样本或 pDNS 时间不能伪造近期活动。

### 7.2 普通路由

- clue-group evidence 无条件 standard block。普通 operator source + 明确恶意 context 必须由达到 `historical_malicious_level` 的同一条记录承载，不能借用其他记录的高 level；当前/历史 ICP 未解决时进入待复核。
- 低于恶意等级门槛的 domain 不形成普通 A/C 黑证据；若存在达到 `relate_url_malicious_level` 的具体 URL 且无合格恶意样本，则 domain 降灰并优先保留带 path 的 URL。
- 高等级只提供黑证据准入，不锁死结论；强业务闭环、显式结构化资产变化与无威胁残留同时成立时允许输出误报。
- 当前 ICP 正负冲突先于白、灰出口处理；直接恶意样本强 A、权威上下文关键词或 clue-group 可保留黑结论并标记必须复核，其余冲突进入待复核。
- C 级历史闭环不能只靠 DNS/HTTP/sample 等中性文本或强来源加聚合字段；样本须来自同一条达到等级门槛且关联目标的记录，并通过统一恶意样本检查。恶意准入数值必须有限且可转换。
- `business_identity.trusted_business_identity()` 同时约束画像与 E 证据：配置字段全部非空，至少一个网站字段锚定目标 host；仅允许 host 相同或差一个 `www.` 前缀，不推断任意子域组织关系。备案号可辅助但不能独立锚定，其他原始业务值可保留为弱证据。
- WHOIS 未过期或近期 pDNS 不独立判白。
- 英文恶意 indicator 使用字母数字词法边界；中文保持包含匹配。
- 公开 APT 只在结构化条件闭环时形成历史恶意证据：记录主体的规范化 IOC 和类型必须匹配目标，阈值字段须为有限数值，引用须为 host/端口有效且无 userinfo 的 HTTP(S) URL。结构化记录承担 IOC 关联，外部报告 host 无需等于 IOC，正文无需重复 IOC；不声称联网核验正文。
- `relate_url` 仅对结构、host 和端口均有效的 HTTP(S) URL 建立精确作用范围；URL 目标的直接 A 证据与 retained 必须与目标 scheme-aware 身份完全一致（http/https 不串证），域名目标可按 host 保留 URL 但不得由 relate_url 建立 A。
- 灰包括既有的历史 URL/失活域名分支，以及低等级但具体恶意 URL 仍需保留的正常服务滥用分支；弱白证据本身不能单独触发灰。

### 7.3 时间比较边界

`parser.py` 提供 `normalize_datetime`、`latest_datetime`、`is_recent`、`is_fresh` 和 `is_unexpired`，供 normalize、profile、evidence、adjudicator、pipeline、provider cache 和 result cache 共享。近期/新鲜判断均拒绝未来值、无效值和负窗口，精确窗口端点保留。

## 8. 输出与诊断

JSONL 保留嵌套数据；CSV/Excel 对对象和数组做稳定 JSON 序列化。Excel 固定为：

```text
统计, 总, 判黑, 灰, 误报, 待复核
```

diagnostics 记录解析失败、嵌套 `data` 拒绝的无界计数（`nested_data_error_count`，样例仍有界）、无效 IOC、provider 状态/异常、必要来源缺失和跳过计数。兼容快照中的单条坏 URL、非对象 JSON 行以及嵌套非对象 `data` 条目会被隔离，后续合法 IOC 继续处理；快照非法 IOC 标注物理文件行号。CLI 在 provider 采集前解析全部输出路径并做冲突/可写性预检（已存在输出也探测 sibling 临时文件可写）；结果与 diagnostics/diff 仅经 sibling temp + `os.replace` 写入，锁文件失败保留原字节。`-j`/`-c` 也会自动落盘 diagnostics；可选 `--strict` 把输入拒绝、嵌套/解析错误与传输/处理失败映射为非 0 退出，业务待复核不计入失败。JSONL 按行流式写入；JSONL/CSV 契约包含 `classification_unknown` 布尔导出。

## 9. 安全边界

- 凭据只来自环境变量，不进入本地 provider 配置。
- 错误、日志、diagnostics、导出、cache 和 raw 审计不得包含认证值。
- 发布 allow-list 排除 `ioc_info/`、`outputs/`、cache/run、release 和内部实施材料。
- 原始响应为了审计可以落在用户指定的 cache/run 目录，但不是发布源文件。
- 测试使用注入 transport 和网络哨兵验证零真实请求。
- 不读取 `token_icp.txt`；ICP 生产 endpoint 尚未用用户凭据验收，当前证据来自 synthetic/mock 和本地 cache replay。
- `python -m ioc_rejudge share` 是独立的云端协作边界：key 文件使用 scrypt 派生密钥包裹，key 原文不进入 bundle、manifest、日志或 HTTP 请求；IOC/人员/路径等使用确定性 AES-SIV token，credential-like 字段和 JWT 只输出 `[REDACTED]`。自由文本另覆盖 defang、云主机名、hex+exe、标注人名、`请联系`、bang 路径和 Base64 JSON，不使用明文对照表。
- share bundle 采用 JSONL 流式读写和原子替换；manifest 保存输出 hash、bundle_id、key_id、行数和扫描统计，并使用本地 key 对全部字段做完整性认证，不保存原文 hash、原文或口令。
- share bundle 不是生产 pipeline 输入；原始 manifest 留在本地，云端改写结果的每行必须回传顶层 `bundle_id`。restore 使用相同 key 验证 manifest、bundle 归属和 token；未知/非规范 token、错误 key、manifest 被替换或还原后 key 冲突均 fail-closed。
- share 的隐私边界不是全字段加密：确定性 token 有意暴露类型、相等关系、JSON 结构及大致长度，未命中规则的普通文本和时间保持可读。不同案件需要隔离关联时必须使用不同 key；自由文本身份线索需通过 names file 和发送前人工审阅补充，残留扫描不能证明任意自然语言均已匿名化。
- `python -m ioc_rejudge ui` 只监听 `127.0.0.1` 且不可配置为其他地址；页面与 API 请求均需携带进程级会话令牌并通过 Host/Origin 校验（防 DNS rebinding 与跨站请求），非 200 响应关闭连接避免 keep-alive 错位。服务拒绝地址复用，端口被占用时回退随机端口，杜绝两个 UI 进程共享同一端口。
- UI 成功解锁后把口令原子写入 key 同目录的 `passphrase` 文件（POSIX `0o600`，Windows 尽力设置），下次启动自动解锁；`/api/lock` 同时清内存和该文件。页面响应 `Cache-Control: no-store`，口令不得进入日志、HTML 或 status 的其它字段。
- bundle 目录按 `bundle_id` 存储并保留最近 20 个，restore 按 bundle_id 直定位、sha256 兜底匹配本地 manifest。UI 不执行研判 pipeline、不提供关闭严格模式的入口。
- `POST /api/lookup` 只构造 `ioc_info` provider，默认 `refresh=False`、TTL 7 天，与研判 CLI 共用 `--cache-dir`（默认 `.\provider-cache`）。进程内复用该 provider 及缓存索引；有凭据时 cache miss 才联网（连接 5 秒、读取 15 秒，不重试、不拉 Go worker），live 失败可回退陈旧缓存。无凭据时改为 offline 只读缓存，全部 miss 则 4xx 且不得联网。lookup 不要求 key 已解锁，且不占用 create/restore 的状态锁；create/restore 仍要求解锁。

## 10. 兼容性与限制

- `run_pipeline_with_diagnostics()` 和 `run_pipeline()` 保留旧快照调用方式。
- `run_unified_pipeline()` 是 provider/路由统一边界。
- `compare_verdicts()` 提供确定性结论转移审计。
- `compare_verdicts()` 用于匿名快照迁移报告中的黑白互转、转灰/复核和成员变化；迁移验收再根据 synthetic/mock Observation 单独列出 ICP positive/negative/unresolved 分组。
- 严格 DNS 校验拒绝带下划线的脱敏占位域名；这是输入数据限制，不放宽生产规则。
- `pack.py` 始终使用纯文件系统 allow-list，不创建 commit 或 tag；仅在用户明确授权发布时，`push.py` 才可按独立 allow-list 初始化 Git、创建版本标签并推送。
