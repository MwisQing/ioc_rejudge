# 架构说明

本文描述 IOC Rejudge CLI `2.1.0` 的当前实现。历史设计和实施计划保留在 `docs/superpowers/`，但不再作为当前能力清单。

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
| `parser.py` | 兼容 JSONL 快照和时间解析 |
| `normalize.py` | IOC 规范化、记录时序排序和 dossier 聚合 |
| `models.py` | Evidence、RecordSnapshot、IocDossier、Verdict |
| `observations.py` | IocTarget、Observation、provider/freshness/route/disposition 类型 |
| `profile.py` | domain、IP、HTTP 和运行时画像 |
| `evidence.py` | A-F 证据、样本语义、APT 组合和 URL 作用范围 |
| `routing.py` | 可靠 DGA-only 分类与分类失败降级 |
| `dga.py` | DGA facts 和有序硬规则裁判 |
| `adjudicator.py` | 普通 IOC 五类结论、ICP 人工门和灰规则 |
| `pipeline.py` | provider 并发、Observation 归并、facts/dossier 构建和分路 |
| `export.py` | JSONL、CSV、六表 Excel |
| `diff.py` | Verdict 转移和成员变化报告 |
| `config.py` / `rules.py` | 阈值和规则配置 |
| `cli.py` | 参数解析、两条入口编排、输出和 diagnostics |

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
| `icp` | 按 host 去重的当前备案 positive/negative Observation | live, explicit opt-in |
| `SidecarProvider` | 任意预取 Observation，包括 ICP | local |

factory 将默认列表与支持列表分离：默认仍为五源，ICP 只有 `--providers ...,icp` 显式选择时才构造。自动验收只使用 mock/cache，真实 endpoint 风险单独保留。

ICP 响应按 `resultObject.website_icp_num`、`resultObject.icp`、`rows[0].website_icp_num`、`rows[0].icp` 逐级短路规范化；已获得有效高优先级值后，不再让无关的低优先级坏字段推翻结果。成功空结果输出 `kind=icp_registration`、`status=success`、`payload={"current": false, "registration": ""}`；这是真实的 typed negative fact，不是 `no_data`。正结果只输出非空字符串备案号。

### 4.1 工厂与配置

`providers/factory.py` 负责：

- 保持默认 provider 顺序。
- 从环境变量读取 endpoint 和凭据。
- 从本地 JSON 读取非密钥配置。
- 对缺凭据来源单独标记 `disabled`。
- 构造 live 或 fail-closed offline transport。
- 分离持久 cache 与当前 run 审计目录。

本地配置拒绝 secret/token/password/authorization 类字段，ProviderSettings 的表示形式和异常信息不会暴露认证值。

ICP 默认限制为 2 workers 和 2 requests/second。配置层目前只校验二者为正数，尚未定义产品级硬上限；生产配置必须遵守接口所有者批准的上限。

### 4.2 HTTP 传输

`providers/transport.py` 提供可注入 JSON 传输，统一分类：

- timeout
- connection
- HTTP error
- JSON decode error
- offline

生产 provider 依赖注入的 transport，测试可完全阻断真实网络。根目录 `iocProducer_api_ioc_info.py` 是旧调用方兼容薄入口，不属于统一 provider 的传输边界。

### 4.3 Cache 与审计

`JsonlProviderCache` 使用稳定 query key 和 append-only JSONL：

- TTL 按 provider 和 query profile 判断。
- 坏 cache 行不会阻断其他有效行。
- stale 结果可用于审计，但不能伪装成新鲜白证据。
- ICP cache key 只含 endpoint/host；写入 cache 和 `run_dir/raw` 前按当前 `uc`/`key` 值递归脱敏，避免服务端回显值进入 raw 或错误文本。
- `--refresh` 绕过 cache。
- `--offline` 只能读取 sidecar/cache，不允许网络回退。
- 在线响应同时写入持久 cache 和 `run_dir/raw` 审计副本。

## 5. 并发与确定性

pipeline 使用单个有界线程池并发不同 provider。并发只影响采集时延，不改变业务顺序：

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
- provider merge 完成后，只有单条 Observation 和该 IOC 的 provider 聚合状态都为 success，且 Observation 非 stale，才应用到 `current_icp_check_complete` 与当前备案字段；negative 会清空当前备案并完成检查，聚合 error/disabled 或 stale 不覆盖当前状态。该门同时约束标准路由和 DGA 当前 ICP 白信号。
- RecordSnapshot 保留原始 index、时间、来源和 raw 记录。
- hash、family、source 等历史恶意集合仍可跨记录聚合。

## 7. 路由和裁判

### 7.1 DGA 路由

只有成功且规范化 tags 精确为 DGA-only 的可靠分类进入 DGA 路由。域名形状、熵或旧 `dga_score` 不足以自动路由。

DGA 规则按固定顺序执行：

1. 关联恶意样本优先，按可比较的样本时间区分存活/失活。
2. 样本查询不完整或不新鲜时进入待复核。
3. 无恶意样本且当前 ICP 存在时判误报。
4. 无恶意样本且 WHOIS 未过期时判误报。
5. 无恶意样本且 pDNS 在配置窗口内时判误报。
6. 查询完整且无白证据时保留失活有效。

`not-a-virus`、低 level 和显式零 confidence 不算关联恶意样本。混合 aware/naive 时间逐项比较，单个不可比较时间只跳过自身。

### 7.2 普通路由

- clue-group evidence 无条件 standard block；operator source + 明确恶意 context 仅在当前 ICP 冲突已解决时 block。未解决的当前/历史 ICP 对非 DGA domain 进入待复核。
- WHOIS 未过期或近期 pDNS 不独立判白。
- 英文恶意 indicator 使用字母数字词法边界；中文保持包含匹配。
- 公开 APT 只在结构化条件闭环时形成历史恶意证据。
- `relate_url` 仅对结构、host 和端口均有效的 HTTP(S) URL 建立精确作用范围。
- 灰要求完整历史 URL 闭环和对应正常化条件，不能由弱白证据单独触发。

## 8. 输出与诊断

JSONL 保留嵌套数据；CSV/Excel 对对象和数组做稳定 JSON 序列化。Excel 固定为：

```text
统计, 总, 判黑, 灰, 误报, 待复核
```

diagnostics 记录解析失败、无效 IOC、provider 状态/异常、必要来源缺失和跳过计数。兼容快照中的单条坏 URL 会被隔离并留下样例，后续合法 IOC 继续处理。

## 9. 安全边界

- 凭据只来自环境变量，不进入本地 provider 配置。
- 错误、日志、diagnostics、导出、cache 和 raw 审计不得包含认证值。
- 发布 allow-list 排除 `ioc_info/`、`outputs/`、cache/run、release 和内部实施材料。
- 原始响应为了审计可以落在用户指定的 cache/run 目录，但不是发布源文件。
- 测试使用注入 transport 和网络哨兵验证零真实请求。
- 不读取 `token_icp.txt`；ICP 生产 endpoint 尚未用用户凭据验收，当前证据来自 synthetic/mock 和本地 cache replay。

## 10. 兼容性与限制

- `run_pipeline_with_diagnostics()` 和 `run_pipeline()` 保留旧快照调用方式。
- `run_unified_pipeline()` 是 provider/路由统一边界。
- `compare_verdicts()` 提供确定性结论转移审计。
- `compare_verdicts()` 用于匿名快照迁移报告中的黑白互转、转灰/复核和成员变化；迁移验收再根据 synthetic/mock Observation 单独列出 ICP positive/negative/unresolved 分组。
- 严格 DNS 校验拒绝带下划线的脱敏占位域名；这是输入数据限制，不放宽生产规则。
- `pack.py` 始终使用纯文件系统 allow-list，不创建 commit 或 tag；仅在用户明确授权发布时，`push.py` 才可按独立 allow-list 初始化 Git、创建版本标签并推送。
