# IOC Rejudge CLI

IOC Rejudge CLI 是一个可审计的 IOC 多源研判工具。`2.2.5` 同时支持旧 IOC Info JSONL 快照和裸 IOC 输入，可聚合本地或在线 provider，按 DGA/普通 IOC 分路，并输出结构化结论、证据来源和诊断信息。

## 当前状态

| 项目 | 当前值 |
|---|---|
| 版本 | `2.2.8` |
| Python | 已用 Python 3.12 验证 |
| 输入 | 旧 JSONL 快照、裸 IOC 文件、重复 `--ioc` |
| IOC 类型 | domain、URL、domain:port、IP、IP:port |
| 结论 | `存活有效`、`失活有效`、`灰`、`误报`、`待复核` |
| live provider | K01、IOC Info、F-Dark、WHOIS、pDNS、ICP；按 IOC 类型和研判需要分流 |
| 本地 provider | 任意 JSONL sidecar；可用于 ICP Observation 回放 |
| 当前测试 | `670 passed` |

ICP provider 已按固定响应契约实现并通过 mock/cache 验收；真实 endpoint、认证和生产响应仍需在具备授权凭据的环境中单独确认。

## 安装

建议使用独立虚拟环境：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

开发和测试环境：

```powershell
python -m pip install -r requirements-dev.txt
```

查看所有参数：

```powershell
python -m ioc_rejudge --help
```

## 快速开始

### 旧快照兼容模式

没有提供统一模式参数时，`.jsonl` 输入保持旧快照行为：

```powershell
python -m ioc_rejudge -i .\snapshot.jsonl -j .\result.jsonl --diagnostics .\diagnostics.json
```

CSV 输出：

```powershell
python -m ioc_rejudge -i .\snapshot.jsonl -c .\result.csv --diagnostics .\diagnostics.json
```

如果不指定 `-j` 或 `-c`，默认生成 `<输入名>_result.xlsx` 和 `<输入名>_diagnostics.json`。坏行或端口越界的 URL 会按行跳过并记录到 diagnostics，不会中断整批任务，也不会降级成 domain 继续研判。

### 裸 IOC 离线研判

直接输入一个或多个 IOC：

```powershell
python -m ioc_rejudge `
  --ioc example.invalid `
  --ioc https://example.invalid/path `
  --offline `
  -j .\result.jsonl `
  --diagnostics .\diagnostics.json
```

没有 sidecar 或可用 cache 时，缺少事实的裸 IOC 会进入 `待复核`，不会被臆测为黑或白。

裸 IOC 文件是一行一个值，支持空行和以 `#` 开头的注释：

```text
example.invalid
example.invalid:443
https://example.invalid/login
192.0.2.10:8443
```

使用裸 IOC 文件时，显式加 `--offline`、`--providers` 或其他统一模式参数：

```powershell
python -m ioc_rejudge -i .\iocs.txt --offline -c .\result.csv
```

### 本地 sidecar

`--provider-data NAME=PATH` 可重复使用：

```powershell
python -m ioc_rejudge `
  --ioc example.invalid `
  --offline `
  --provider-data icp=.\icp.jsonl `
  --provider-data local_intel=.\intel.jsonl `
  -j .\result.jsonl
```

sidecar 每行是一个 Observation，至少包含 `ioc`、`kind`、`status`、`fetched_at`、`observed_at` 和 `payload`：

```json
{"ioc":"example.invalid","kind":"ioc_info_record","status":"success","scope":"domain","fetched_at":"2026-07-25T10:00:00","observed_at":"2026-07-25T10:00:00","payload":{"key":"example.invalid"}}
```

可选字段为 `scope`、`strength` 和 `raw_ref`。文件缺失、坏 JSON 或未知状态会明确记为 provider `error`，不会伪装成 `no_data`。

## 在线 Provider

默认顺序为：

```text
k01_compromise,ioc_info,fdark,whois,pdns,icp
```

可显式选择和排序：

```powershell
python -m ioc_rejudge `
  --ioc example.invalid `
  --providers k01_compromise,ioc_info,fdark,whois,pdns,icp `
  --credentials-file .\credentials.local.json `
  --provider-config .\provider-config.json `
  --cache-dir .\provider-cache `
  --run-dir .\runs\run-001 `
  -j .\result.jsonl
```

推荐将凭据保存在项目根目录的 `credentials.local.json`。先复制发布包内的空白示例，再填写实际值：

```powershell
Copy-Item .\credentials.example.json .\credentials.local.json
notepad .\credentials.local.json
```

运行时显式传入：

```powershell
python -m ioc_rejudge `
  --ioc example.invalid `
  --providers k01_compromise,ioc_info,fdark,whois,pdns,icp `
  --credentials-file .\credentials.local.json `
  --cache-dir .\provider-cache `
  --run-dir .\runs\run-001 `
  -j .\result.jsonl
```

凭据字段如下；endpoint 仍可使用环境变量或 `--provider-config` 中的非密钥 `url`：

| Provider | 凭据环境变量 | endpoint 环境变量 |
|---|---|---|
| K01 | `K01_COMPROMISE_API_KEY` | `K01_COMPROMISE_URL` |
| IOC Info | `IOC_INFO_API_KEY` | `IOC_INFO_URL` |
| F-Dark | `FDP_ACCESS`、`FDP_SECRET` | `FDARK_URL` |
| WHOIS | `WHOIS_ACCESS`、`WHOIS_SECRET`；缺省回退 FDP 凭据 | `WHOIS_URL` |
| pDNS | `PDNS_ACCESS`、`PDNS_SECRET`；缺省回退 FDP 凭据 | `PDNS_URL` |
| ICP | `ICP_UC`、`ICP_KEY` | `ICP_URL`（可选） |

`--credentials-file` 只接受表中的固定凭据字段；未知字段、非字符串值和坏 JSON 会在请求前报错。指定该参数后，本次运行只从这个文件读取凭据，不回退读取进程或系统环境变量。`credentials.local.json` 已加入 `.gitignore`，并被发布 allow-list 排除。

`--provider-config` 只允许非密钥设置，例如 endpoint、启用状态、超时、查询参数和 TTL。包含 secret、token、password 或 authorization 类字段的配置会被拒绝。缺少某个 provider 的凭据只会把该 provider 标记为 `disabled`，不会中止其他来源。未使用 `--credentials-file` 时，原有环境变量凭据方式继续兼容。可直接复制发布包内的缓存配置示例：

```powershell
Copy-Item .\provider-config.example.json .\provider-config.json
notepad .\provider-config.json
```

K01、IOC Info、F-Dark、WHOIS、pDNS 默认缓存 7 天，ICP 默认缓存 30 天；每个 provider 都可在配置文件中使用 `ttl_days`、`ttl_hours` 或 `ttl_seconds` 单独覆盖，三者只能设置一个。K01 批量接口默认按 100 个 IOC 分批请求，可通过 `providers.k01_compromise.batch_size` 调整；某一批的业务错误只影响该批，成功批次仍会写入逐 IOC provider cache。未传 `--cache-dir` 时，统一模式默认使用 `.\provider-cache`。

每个接口使用独立目录和日期分片：`.cache_<provider>/cache_YYYY-MM-DD.jsonl`。读取时会跨日期分片选择同一 query key 的最新记录，并兼容旧版根目录 `<provider>.jsonl`；因此缓存不会继续无限堆在一个文件里。

完整研判结果也默认缓存 7 天，写入 `.cache_adjudication_results/cache_YYYY-MM-DD.jsonl`。缓存行同时保存规范化 IOC、输入/规则/provider 配置指纹、provider 原始缓存状态、研判时间和完整输出对象；重复研判同一规范化 IOC 时，只有快照内容、规则阈值、provider 选择、影响查询的公开配置及原始缓存状态均一致才会复用，命中后直接跳过 provider 请求。删除或清空某个 provider 原始缓存后，相关完整结果会因 `fingerprint_mismatch` 重新采集。可在 `provider-config.json` 顶层配置：

```json
"result_cache": {
  "enabled": true,
  "ttl_days": 7
}
```

结果缓存 TTL 也支持 `ttl_hours` 或 `ttl_seconds`。过期、坏行或指纹不一致时重新研判；provider `error` 或必要来源缺失的未完成结果不写入缓存，下一次继续重试；`--refresh` 会同时绕过 provider 缓存和研判结果缓存。离线运行可以复用兼容的研判结果缓存。

请求规划先调用 K01、IOC Info、F-Dark 完成分类与恶意样本发现，再按规则调用生命周期接口：domain/URL/domain:port 进行当前 ICP 验证；只有 DGA 路由再请求 WHOIS 和 pDNS，普通路由仅在历史 URL/钓鱼证据可能进入过期域名灰分支时请求 WHOIS；IP/IP:port 跳过 ICP、WHOIS 和 pDNS。

ICP 查询按 host 去重，凭据来自显式凭证文件或兼容环境变量，不读取 `token_icp.txt`。缺凭据在线运行和无缓存 offline miss 都产生零 live ICP 请求。响应写入 cache 或 `run_dir/raw` 前会按当前 ICP 凭据值再次脱敏，避免服务端回显认证值。

ICP 默认使用 8 workers 和 8 requests/second。本地 provider 配置可以调整这两个正数；如果接口返回限流、超时或业务错误，可降为 4/4。当前尚未定义或强制产品级硬上限，生产使用时仍应保持在接口所有者批准的范围内。

`--refresh` 绕过已有 provider cache 和研判结果 cache；它与 `--offline` 互斥。

### 离线回放

在线运行把可复用响应写入 `--cache-dir`（未指定时为 `.\provider-cache`），把本次原始响应审计副本写入 `--run-dir/raw`。之后可移除凭据并回放：

```powershell
python -m ioc_rejudge `
  --ioc example.invalid `
  --providers k01_compromise,ioc_info,fdark,whois,pdns,icp `
  --provider-config .\provider-config.json `
  --cache-dir .\provider-cache `
  --offline `
  -j .\replay.jsonl
```

回放必须使用与在线运行一致的 provider 选择、非密钥查询配置和 cache。离线传输为 fail-closed，不会悄悄访问网络。
ICP 的 fresh 成功空结果是 typed negative Observation（`current=false`），不是 `no_data`；offline 可无凭据读取 fresh/stale cache，stale 仅供审计。只有 Observation 和对应 provider 聚合状态都为 success 时，当前 ICP 才能完成检查；聚合 error/disabled 始终保守处理。

### 运行可见性

统一模式启动时打印本次 provider 清单：disabled 项标注 `[disabled]` 并在 stderr 给出原因（如缺少凭据），本地 sidecar 标注 `(sidecar)`。每个 provider 完成采集时在 stderr 输出一行进度与耗时；结束时打印研判结果缓存 `hit/miss`、逐 provider 状态计数（success/no_data/error/disabled/cache_hit 与耗时）和总耗时。diagnostics 包含 `result_cache_hit`、`result_cache_miss`、`result_cache_errors` 与 `provider_metrics.duration_seconds`。

### 结论迁移对比

`--diff-baseline` 接受上一次运行的 result JSONL，在本次研判完成后输出确定性迁移报告：

```powershell
python -m ioc_rejudge `
  --ioc example.invalid `
  --offline `
  --diff-baseline .\last_result.jsonl `
  -j .\result.jsonl
```

报告默认写入 `<输出名>_diff.json`，可用 `--diff-output` 指定其他路径；内容包含 `transitions`、`changed`、`black_to_white`、`white_to_black`、`to_gray`、`to_review` 与成员变化（`only_before`/`only_after`），控制台同步打印各组计数。baseline 文件缺失、坏 JSON 或缺少 `ioc`/`conclusion` 字段会在研判开始前直接报错，不会浪费一次完整运行。该参数同样适用于旧快照兼容模式。

## 研判语义

系统不使用证据打分或平均。强弱证据按明确优先级组合：

- `updatetime` 是情报记录时间，不是活跃证据。
- `level` 先决定普通情报能否进入黑证据裁判，默认门槛为 40；达到门槛仍不等于最终必黑，也不直接证明当前存活。
- `失活有效` 仍是黑情报，处置为 `block`。
- provider `error`、`disabled` 与 `no_data` 严格区分。
- 同一 IOC 先聚合 Observation，再统一裁判。

DGA 只有在可靠 K01 分类精确为 DGA-only 时进入专用路由：

1. 有关联恶意样本时不能判白，并按样本活动时间区分存活/失活。
2. 必要样本查询未完整或不新鲜时进入 `待复核`。
3. 无关联恶意样本时，当前 ICP、WHOIS 未过期或近 30 天 pDNS 任一成立即可判 `误报`。
4. 白证据均不成立且查询完整时保留为 `失活有效`。

普通 IOC 规则包括：

- 非 DGA domain 的 clue-group 证据无条件 standard block；其他 operator malicious context 必须由达到恶意等级门槛的同一条记录承载，且仅在当前 ICP 冲突已解决时 block。
- 低于恶意等级门槛的 domain 不因 `manual`、强来源或上下文恶意词自动升黑；若仍有达到 URL 门槛的具体恶意 URL，则 domain 输出 `灰` 并保留 path 级 URL。
- 达到 40/50/60/70 等级只表示进入黑证据裁判；当强正常业务闭环、明确结构化资产变化和无威胁残留同时成立时，仍可判 `误报`。
- WHOIS 未过期或近期 pDNS 不足以单独把普通 IOC 判白。
- `relate_url` 只证明有效 HTTP(S) URL 作用范围，不自动扩大为 domain 强证据。
- `灰` 表示当前范围不继续拦截但也不加入白名单，可通过 `retained_urls` 保留具体 URL。

## 输出

JSONL 保留嵌套结构；CSV 和 Excel 对列表/对象使用稳定 JSON 序列化。主要字段包括：

- `conclusion`、`reason`、`route`、`disposition`
- `scope_actions`、`retained_urls`
- `provider_statuses`、`evidence_origins`
- `missing_required_providers`、`classification_unknown`

Excel 固定包含六个 sheet：

- `统计`
- `总`
- `判黑`
- `灰`
- `误报`
- `待复核`

`待复核` 不计入 `判黑`。

评审 sheet 在结论列后紧跟 `判定原因` 和 `评审建议`（必看/抽检/不看），末尾包含 `缺失必要来源`；`待复核` 行无需交叉查 JSONL 即可看到裁判依据和缺失来源。

## 数据与安全

- 不要把真实 IOC、客户数据、cache、raw response、run 目录或凭据加入发布包。
- 示例和测试使用 `.invalid`、文档网段或合成值。
- diagnostics、日志、导出和 provider 错误不应包含认证头或 secret。
- ICP 真实 endpoint 未纳入本地自动验收；验收使用注入 transport、cache 和合成值，禁止把凭据写入文档或读取 `token_icp.txt`。
- 严格 DNS 校验拒绝下划线、空 label、非法连字符和越界 IPv4；脱敏数据若使用下划线占位域名，需要先修正占位格式，生产校验不会为 fixture 放宽。

## 验证与发布

运行全量测试：

```powershell
python -m pytest tests -q
```

检查发布清单但不创建文件：

```powershell
python pack.py --check
```

创建确定性 allow-list 发布包：

```powershell
python pack.py --output-dir .\release
```

打包器读取 `VERSION`，生成带 `RELEASE.json` 清单的 zip；它不初始化 Git、不提交、不打 tag、不改版本号，也不访问网络。发布包排除 `ioc_info/`、`outputs/`、cache、run、`release/`、开发提示词和内部实施文档。

## 文档

- [架构说明](docs/ARCHITECTURE.md)
- [开发与验证](docs/DEVELOPMENT.md)
- [历史记录](docs/HISTORY.md)
- [更新日志](CHANGELOG.md)
- [协作上下文](CLAUDE.md)
