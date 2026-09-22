# IOC Rejudge CLI

IOC Rejudge CLI 是一个可审计的 IOC 多源研判工具。`2.8.0` 同时支持旧 IOC Info JSONL 快照和裸 IOC 输入，可聚合本地或在线 provider，按 DGA/普通 IOC 分路，并输出结构化结论、证据来源和诊断信息。新增的离线路线命令、CSV/XLSX 适配、结果 bundle 导出和本地 workbench 让批处理与人工复核可以在无网络环境完成。

## 当前状态

| 项目 | 当前值 |
|---|---|
| 版本 | `2.8.0` |
| Python | 已用 Python 3.12 验证 |
| 输入 | 旧 JSONL 快照、裸 IOC 文件、重复 `--ioc` |
| IOC 类型 | domain、URL、domain:port、IP、IP:port |
| 结论 | `存活有效`、`失活有效`、`灰`、`误报`、`待复核` |
| live provider | K01、IOC Info、F-Dark、WHOIS、pDNS、ICP；按 IOC 类型和研判需要分流 |
| 本地 provider | 任意 JSONL sidecar；可用于 ICP Observation 回放 |
| 当前测试 | `1153 passed, 1 skipped`（2026-09-22） |

ICP provider 已按固定响应契约实现并通过 mock/cache 验收；真实 endpoint、认证和生产响应仍需在具备授权凭据的环境中单独确认。

## 本地安全分享

当需要让云端 AI 查看本地研判证据时，使用独立的 `share` 子命令创建安全上下文包。它不会把密钥上传，也不会修改本地裁判输入：IOC、URL、IPv4/IPv6、hash、人员、路径和准标识符会被替换为同一 key 下可关联的 AES-SIV token；凭据字段、URL userinfo、敏感 query 值和内嵌凭据会永久变成 `[REDACTED]`。口令默认交互式输入，也可以通过 `IOC_SHARE_PASSPHRASE` 提供给自动化进程。

创建 bundle（首次运行生成本地 key 文件）：

```powershell
python -m ioc_rejudge share create `
  -i .\snapshot.jsonl `
  -o .\share.jsonl `
  --key-file .\share-key.json `
  --generate-key `
  --names-file .\names.txt
```

创建完成会同时生成 `share.jsonl.manifest.json`。只上传 `share.jsonl`；key 和原始 manifest 都留在本机。把 manifest 中的 `bundle_id` 告知云端 AI，并要求它在返回 JSONL 的每个对象顶层原样加入该字段。常见结构化人员字段会自动 token 化；自由文本中的姓名应逐行写入 `names.txt` 并通过 `--names-file` 提供。严格模式默认开启，如果脱敏后仍发现 URL、域名、IP、hash、UUID、路径、人员字段或 credential-like 值，命令会失败并删除不合格输出。

发送前可单独扫描：

```powershell
python -m ioc_rejudge share scan -i .\share.jsonl
```

云端返回保留 token 和顶层 `bundle_id` 的 JSONL 后，在本地使用原始 manifest 验证并还原：

```powershell
python -m ioc_rejudge share restore `
  -i .\cloud-review.jsonl `
  -o .\cloud-review-restored.jsonl `
  --key-file .\share-key.json `
  --manifest .\share.jsonl.manifest.json
```

还原前会用本地 key 验证 manifest 认证码、输出 hash、`bundle_id` 和 key_id；未知或被篡改的 token、被替换的 manifest、还原后重复 key 默认 fail-closed。凭据类字段不设计为可恢复值。还原后的结果才可以与本地原始 IOC 或人工审阅库合并，不能把 token bundle 直接当作生产研判输入。

## 本地 share 助手 UI

`share` 命令行参数较多，高频单条/小批量场景可以用本地单页助手代替。在保存研判产物和 share key 的机器上运行：

```powershell
python -m ioc_rejudge ui
```

浏览器会自动打开带会话令牌的本地页面（默认端口 8731，被占用时自动换随机端口）。可用 `--port`、`--key-file`、`--bundle-dir`、`--cache-dir`、`--credentials-file`、`--no-browser` 调整。默认缓存目录与研判 CLI 相同（`.\provider-cache`）。当前目录存在 `credentials.local.json` 时会自动用来查 IOC Info，否则读本终端环境变量；也可显式 `--credentials-file`。页面操作对应完整流程：

1. 首次使用输入非空口令并勾选“生成新 key”（默认 `~\.ioc-share\key.json`）。成功后口令保存在 key 同目录的 `passphrase` 文件，下次启动自动解锁；点“清除口令”会同时清内存和该文件。
2. “查询 IOC Info”：粘贴每行一个 IOC，或填本机文件路径。默认走 7 天缓存，没有缓存再请求接口；接口失败时可以用本机更旧的缓存。无凭据时只读缓存。查询结果是明文，页面可展开/合拢查看，不要直接发给云端。若页面提示查询超时，到启动 UI 的窗口按 Ctrl+C 停掉再启动，不要只刷新网页。
3. 点“脱敏并复制”：生成一行一个脱敏 JSON 并写入剪贴板（本机仍保存 bundle，便于以后还原）。“复制明文（未脱敏，勿发给云端）”只留给本机核对。
4. 把剪贴板里的脱敏 JSON 发给云端 AI；如需对方改完再还原，让返回行带上页面上的 `bundle_id`，且不要改 `ss1:` token。
5. “还原 AI 返回”：粘贴云端返回的 JSONL，自动匹配本地 bundle 并还原。已有研判 JSONL 时仍可用“生成脱敏包”面板。

另有“残留扫描”面板可对任意 JSONL 做外发前检查。安全边界：服务只监听 `127.0.0.1`，所有请求需会话令牌并通过 Host/Origin 校验；记住的口令只在本机 key 目录，页面 `no-store`，不把口令或凭据回显到页面；bundle 保存在 `~\.ioc-share\bundles`，manifest 自动匹配无需手工管理。历史展示上限 `--history-limit N`（默认 20）只是列表展示上限，超过上限不会删除旧 bundle 的 manifest 与还原/云端回复产物；同 id 重建采用“先完整备份、再提交”的事务，保留已有还原文件，更早任务仍可按 `bundle_id` 自动还原。磁盘会随历史增长，需要清理时请人工管理 bundle 目录（UI 不提供删除）。UI 不执行研判、不提供关闭严格模式的入口；除“查询 IOC Info”只访问 IOC Info 外，create/restore/scan 不发起网络请求。

确定性 token 会有意保留值类型、相等关系和 JSON 结构，同一 key 在不同 bundle 中也可被云端关联；普通文本和时间只有命中规则后才会替换。若不同案件不应被交叉关联，应为每个案件或信任边界生成独立 key。残留扫描是发送前的强制防线，但不能证明任意自然语言都不含身份线索；上传前仍需维护人员字段和 `names.txt`。

## 离线工作台与运维命令

路线能力提供机器可读 JSON 的离线入口，适合批处理、审阅和本地工作台联调：

```powershell
python -m ioc_rejudge job start --input .\snapshot.jsonl --job-dir .\jobs --offline
python -m ioc_rejudge review list --input .\results.jsonl --queue .\reviews.jsonl
python -m ioc_rejudge explain --input .\results.jsonl --ioc example.invalid
python -m ioc_rejudge history list --history-dir .\runs
python -m ioc_rejudge health --providers ioc_info,whois --offline
python -m ioc_rejudge cache inspect --cache-dir .\provider-cache
python -m ioc_rejudge cache cleanup --cache-dir .\provider-cache --before 2026-01-01
python -m ioc_rejudge import-table --input .\report.csv --column indicator --output .\input.jsonl
python -m ioc_rejudge export-bundle --input .\results.jsonl --output-dir .\bundle
```

也可以使用 `roadmap` 包装入口。`import-table` 支持 CSV/XLSX 的物理行号、defang 恢复、公式风险拦截和重复报告；`export-bundle` 会预检路径冲突并原子写出 JSONL、CSV、XLSX 及可选 diagnostics/diff。`cache cleanup` 默认只生成计划，只有加 `--apply` 才删除完整旧 shard。UI 默认使用本地离线 workbench：页面可以拖放或选择 legacy JSONL 导入 staging，以后台模式启动任务并自动轮询状态，在安全边界内取消尚未开始的任务，查看 diagnostics 和安全运行摘要，按 disposition/关键字/Provider 异常分页筛选，点击结果查看解释，提交人工 overlay，用 baseline task 做 diff，并选择 JSONL/CSV/XLSX/diagnostics/diff/bundle 下载。明文查询和还原结果复制、覆盖 key 前会二次确认；页面不读取真实凭据，也不发起网络请求。摘要和浏览器响应不暴露本地路径或凭据；跨运行历史和生产 provider 诊断仍以 CLI 为准。

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

如果不指定 `-j` 或 `-c`，默认生成 `<输入名>_result.xlsx` 和 `<输入名>_diagnostics.json`。指定 `-j` 或 `-c` 时也会自动写诊断文件到主输出旁的 `<主输出名>_diagnostics.json`（仍可用 `--diagnostics` 覆盖路径）。坏行、非对象 JSON 行、嵌套非对象 `data` 条目或端口越界的 URL 会按行隔离并记入 diagnostics，不会中断整批任务，也不会降级成 domain 继续研判。裸 IOC 文件里的非法值报错使用物理行号（注释和空行不重新编号）；`--ioc` 内联值使用 `inline IOC N` 定位。

输出路径在请求任何 provider 之前做冲突与可写性预检：结果 JSONL/CSV/Excel、diagnostics、diff 不得覆盖输入、diff 基线、rules、provider-config、credentials 或 sidecar 文件，输出之间也不能互相撞路径；嵌套输出目录会自动创建。写入使用临时文件再替换，失败时尽量保留上一份有效输出；Excel 被占用时给出可操作提示。

默认退出码在仍有可用结果时保持 0（部分输入被拒绝也兼容旧行为）。自动化可用 `--strict`：仍会写出可用结果和 diagnostics，但在存在拒绝输入、provider 错误、处理错误或缺失必要来源时以非 0 退出；普通业务「待复核」结论本身不算失败。

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

`--provider-config` 只允许非密钥设置，例如 endpoint、启用状态、超时、查询参数和 TTL。包含 secret、token、password 或 authorization 类字段的配置会被拒绝。`enabled` 以及 K01 的 `ignore_port`/`ignore_url`/`ignore_top`、F-Dark 的 `include_slow_variants`/`include_url_param` 必须是 JSON 布尔值，字符串 `"false"` 或 `0`/`1` 会被拒绝；`max_attempts`、`retry_delay` 等数值同样做类型与有限性校验（`retry_delay` 允许 0）。错误信息指出 provider/选项名，不回显凭据。缺少某个 provider 的凭据只会把该 provider 标记为 `disabled`，不会中止其他来源。未使用 `--credentials-file` 时，原有环境变量凭据方式继续兼容。可直接复制发布包内的缓存配置示例：

```powershell
Copy-Item .\provider-config.example.json .\provider-config.json
notepad .\provider-config.json
```

K01、IOC Info、F-Dark、WHOIS、pDNS 默认缓存 7 天，ICP 默认缓存 30 天；每个 provider 都可在配置文件中使用 `ttl_days`、`ttl_hours` 或 `ttl_seconds` 单独覆盖，三者只能设置一个。K01 批量接口默认按 100 个 IOC 分批请求，可通过 `providers.k01_compromise.batch_size` 调整；某一批的业务错误只影响该批，成功批次仍会写入逐 IOC provider cache。未传 `--cache-dir` 时，统一模式默认使用 `.\provider-cache`。

每个接口使用独立目录和日期分片：`.cache_<provider>/cache_YYYY-MM-DD.jsonl`。读取时会跨日期分片选择同一 query key 的最新记录，并兼容旧版根目录 `<provider>.jsonl`；因此缓存不会继续无限堆在一个文件里。

完整研判结果也默认缓存 7 天，写入 `.cache_adjudication_results/cache_YYYY-MM-DD.jsonl`。缓存行同时保存规范化 IOC（URL 保留 scheme，故裸域名与 http/https 互不合并）、输入/规则/provider 配置指纹、**该目标依赖的** provider 原始响应摘要、可选 `valid_until`（全部实质活动输入、pDNS/WHOIS 边界、未来事件激活前 1µs、依赖 provider 的 `fetched_at+TTL`）、研判时间和完整输出对象；重复研判同一规范化 IOC 时，只有快照、规则、provider 选择、公开查询配置及该目标原始依赖均一致，且评估时刻未越过 `valid_until`，才会复用。同一目标的原始响应更新或删除会使该目标 `fingerprint_mismatch`；无关 IOC 不受影响。同一天内越过时间敏感边界时以 `temporal_expired` 重算。可在 `provider-config.json` 顶层配置：

```json
"result_cache": {
  "enabled": true,
  "ttl_days": 7
}
```

结果缓存 TTL 也支持 `ttl_hours` 或 `ttl_seconds`。过期、坏行或指纹不一致时重新研判；provider `error` 或必要来源缺失的未完成结果不写入缓存，下一次继续重试；`--refresh` 会同时绕过 provider 缓存和研判结果缓存。离线运行可以复用兼容的研判结果缓存。

研判结果缓存契约升级会自动使旧结论失效并重新计算；provider 原始响应缓存文件不做迁移，仍按各自缓存策略复用（原始响应只用于重新取证，不携带旧结论）。provider 原始缓存是 append-only JSONL，生产代码没有删除 API；某条响应真正消失（例如手工清理临时分片）时，依赖该响应的已完成结果会因缺席摘要而失效重算。

请求规划先调用 K01、IOC Info、F-Dark 完成分类与恶意样本发现，再按规则调用生命周期接口：domain/URL/domain:port 进行当前 ICP 验证；只有 DGA 路由再请求 WHOIS 和 pDNS，普通路由仅在历史 URL/钓鱼证据可能进入过期域名灰分支时请求 WHOIS；IP/IP:port 跳过 ICP、WHOIS 和 pDNS。

ICP 查询按 host 去重，凭据来自显式凭证文件或兼容环境变量，不读取 `token_icp.txt`。缺凭据在线运行和无缓存 offline miss 都产生零 live ICP 请求。响应写入 cache 或 `run_dir/raw` 前会按当前 ICP 凭据值再次脱敏，避免服务端回显认证值。

所有在线 provider 的响应在消费与持久化边界统一按「配置的凭据值 + 敏感字段名」脱敏：即使服务端把认证值回显到普通字段（`message`、`details` 等），原始缓存、`run_dir/raw`、观测载荷和错误文案也不会保留凭据原文；请求认证仍使用内存中的真实凭据。

ICP 默认使用 8 workers 和 8 requests/second。本地 provider 配置可以调整这两个正数；如果接口返回限流、超时或业务错误，可降为 4/4。当前尚未定义或强制产品级硬上限，生产使用时仍应保持在接口所有者批准的范围内。

统一模式会检测本机物理内存，避免几千条 IOC 把 4 GiB 机器打进换页。约 4 GiB 及以下自动把 HTTP workers、跨 provider 并发和每个 Go 查询进程的任务数封顶；约 8 GiB 使用中间档；更大内存保持原默认（K01 等 10 workers，ICP 8）。Go HTTP worker 按块拉起进程，一块崩溃只影响该块，不会把整路接口打成 `error`。启动时打印 `Memory:` 行。可用环境变量 `IOC_REJUDGE_MEMORY_PROFILE=full` 关闭封顶，或 `=low` 强制按 4 GiB 档运行。

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
ICP 的 fresh 成功空结果是 typed negative Observation（`current=false`），不是 `no_data`；offline 可无凭据读取 fresh/stale cache，stale 仅供审计。当前 ICP 只采纳类型明确、fresh、Observation 与对应 provider 聚合状态均为 success 的事实，`current` 必须为布尔值，positive 还需非空备案值。历史 IOC Info 备案不替代当前检查；同时收到有效正负事实时保留冲突并进入复核，结论不随返回顺序改变。已有直接恶意样本等强证据仍可保留黑结论，并提示必须复核。

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

报告默认写入 `<输出名>_diff.json`，可用 `--diff-output` 指定其他路径；内容包含 `operations`（本次实际对比的 verdict 行数）、`transitions`、`changed`、`black_to_white`、`white_to_black`、`to_gray`、`to_review`、同结论下的 `operational_changes`（disposition、scope_actions、retained_urls、review_suggestion、missing_required_providers、classification_unknown 的 before/after 值；无序集合仅顺序或重复项变化不计为变更）与成员变化（`only_before`/`only_after`），控制台同步打印 `operations=N changed=…` 等各组计数。baseline 文件缺失、坏 JSON 或缺少 `ioc`/`conclusion` 字段会在研判开始前直接报错，不会浪费一次完整运行。该参数同样适用于旧快照兼容模式。

## 研判语义

系统不使用证据打分或平均。强弱证据按明确优先级组合：

- `updatetime` 是情报记录时间，不是活跃证据。
- 时间比较统一经过 `parser.py` 的 UTC 归一化：无时区时间保留既有墙上时间，带 offset 的 ISO-8601 时间先换算为 UTC；无效时间逐项忽略，不会让整批比较失败。
- `is_recent` 和 `is_fresh` 都使用包含边界的 `0 <= now - value <= window`；未来时间、缺失时间和无效时间不能满足近期或新鲜条件。`fetched_at` 只决定缓存新鲜度，`observed_at`/样本时间才可能参与业务活跃判断。
- `level` 先决定普通情报能否进入黑证据裁判，默认门槛为 40；达到门槛仍不等于最终必黑，也不直接证明当前存活。
- `失活有效` 仍是黑情报，处置为 `block`。
- provider `error`、`disabled` 与 `no_data` 严格区分。
- 同一 IOC 先聚合 Observation，再统一裁判。

DGA 只有在可靠 K01 分类精确为 DGA-only 时进入专用路由：

1. 有关联恶意样本时不能判白，并按样本活动时间区分存活/失活。
2. 当前 ICP 正负事实冲突时进入 `待复核`，WHOIS/pDNS 白信号不能覆盖该冲突。
3. 必要样本查询未完整或不新鲜时进入 `待复核`。
4. 无关联恶意样本且无当前 ICP 冲突时，当前 ICP、WHOIS 未过期或近 30 天 pDNS 任一成立即可判 `误报`。
5. 白证据均不成立且查询完整时保留为 `失活有效`。

普通 IOC 规则包括：

- 非 DGA domain 的 clue-group 证据无条件 standard block；其他 operator malicious context 必须由达到恶意等级门槛的同一条记录承载，且仅在当前 ICP 冲突已解决时 block。
- 低于恶意等级门槛的 domain 不因 `manual`、强来源或上下文恶意词自动升黑；若仍有达到 URL 门槛的具体恶意 URL，则 domain 输出 `灰` 并保留 path 级 URL。该门槛看最新记录的 level，不取历史最大值；同一套证据下 URL 类型 IOC 仍可判黑。
- 「仿冒网站」「仿冒下载」、`family=phishingsite` 以及公开钓鱼源（openphish / phishtank / maltrail）与「黑产/扩展/扩线」一样直接判黑。`钓鱼站点` 或仅 `family=phish` 不会因此自动变黑或变白。
- 达到 40/50/60/70 等级只表示进入黑证据裁判；当强正常业务闭环、明确结构化资产变化和无威胁残留同时成立时，仍可判 `误报`。
- DNS 查询、HTTP 连接、sample 等中性描述不再单独建立历史恶意闭环；C 级样本闭环必须由达到等级门槛且关联当前 IOC 的同一条记录提供合格恶意样本。
- 可信商业身份要求配置中的字段齐全，并有网站 host 与目标一致（允许仅相差 `www.`）；无关官网、单独备案号或标题不能形成强业务身份闭环。
- 公开 APT 证据要求结构化记录主体匹配当前 IOC、报告链接有效；外部报告域名无需等于 IOC，这不等于已联网验证报告正文。
- 非有限威胁数值（如 NaN、Infinity）和无法转换的极大数值不参与等级或样本准入判断。
- WHOIS 未过期或近期 pDNS 不足以单独把普通 IOC 判白。
- `relate_url` 只证明有效 HTTP(S) URL 作用范围，不自动扩大为 domain 强证据。
- `灰` 表示当前范围不继续拦截但也不加入白名单，可通过 `retained_urls` 保留具体 URL。

## 输出

JSONL 保留嵌套结构；CSV 和 Excel 对列表/对象使用稳定 JSON 序列化。主要字段包括：

- `conclusion`、`reason`、`route`、`disposition`
- `scope_actions`、`retained_urls`
- `provider_statuses`、`evidence_origins`
- `missing_required_providers`
- `classification_unknown`（JSONL 为布尔；CSV 为 `true`/`false` 文本；旧兼容行缺省为 `false`）

Excel 固定包含六个 sheet：

- `统计`
- `总`
- `判黑`
- `灰`
- `误报`
- `待复核`

`待复核` 不计入 `判黑`。

评审 sheet 在结论列后紧跟 `判定原因` 和 `评审建议`（必看/抽检/不看），末尾包含 `缺失必要来源`；`待复核` 行无需交叉查 JSONL 即可看到裁判依据和缺失来源。

### 复核队列

内置复核队列（`review_queue.py`）按「需要人工处理」建模，并由 `python -m ioc_rejudge review list|label|reopen` 暴露本地 JSONL 闭环。默认队列（`pending_only=True`）包含：`disposition=review` 的行、结论为「待复核」的行，以及 `review_suggestion=必看` 的行（含仍为 block 的黑结论）；普通 `block + 无需复核` 不进入默认队列；`pending_only=False` 返回全部带 IOC 的行。人工 label/reopen 以 overlay 追加，只保存意见，不覆盖系统结论；队列入队不等于判黑 Excel 表——总表/判黑表本就包含必看黑结论。

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
