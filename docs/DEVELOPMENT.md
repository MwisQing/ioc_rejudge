# 开发与验证

本文是 IOC Rejudge CLI `2.1.0` 的开发准入说明。发布脚本只可在用户明确授权后初始化、提交、打 tag 或推送。

## 1. 开发前阅读

1. 根目录 `CLAUDE.md`
2. 根目录 `README.md`
3. `docs/ARCHITECTURE.md`
4. 与任务直接相关的源码和测试
5. 仅在需要追溯设计时阅读 `docs/superpowers/` 中的规格和计划

规格与计划记录实施背景，运行代码和可复现测试才是当前事实。

## 2. 环境

- 当前版本：`2.1.0`
- 已验证 Python：3.12
- 运行依赖：`openpyxl`、`requests`
- 开发依赖：pytest

安装：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
```

基础检查：

```powershell
python --version
python -m ioc_rejudge --help
python -c "import openpyxl, pytest, requests; print('dependencies ok')"
```

## 3. 当前基线

截至 2026-07-27：

```powershell
python -m pytest tests -q
```

结果：

```text
620 passed
```

其中包括：

- 旧快照兼容、裸 IOC 输入和 CLI 行为。
- 时序聚合、证据边界、DGA/普通路由和人工校准。
- 五个默认 live provider、显式 opt-in ICP、sidecar、cache、transport、factory 和并发 pipeline。
- online mock 到无凭据 offline exact replay。
- JSONL、CSV、六表 Excel、diagnostics 和凭据残留扫描。
- ICP positive/negative、fresh/stale/offline/refresh、host 去重、聚合错误门、缺凭据 zero-call、确定性限速和内部并发上限。
- 非 Git 发布 allow-list、`RELEASE.json` 和排除规则。
- 控制台 provider 启停/进度/状态可见性、逐 provider 耗时诊断和 `--diff-baseline` 迁移对比。
- Excel 评审 sheet 判定原因/评审建议/缺失必要来源列。

## 4. 变更流程

功能或 bugfix 必须遵循：

1. 用最小失败测试表达所需行为。
2. 运行该测试并确认失败原因与问题一致。
3. 实现最小修复，不混入无关重构。
4. 运行相关模块测试。
5. 运行全量测试。
6. 根据风险补充 CLI、导出、离线回放或凭据扫描。
7. 更新 `CLAUDE.md` 进度；用户可见变化同步 `CHANGELOG.md` 和 README。

不得通过删除断言、降低测试强度、静默跳过或忽略收集错误宣布完成。不能运行某项验证时，必须说明原因和残余风险。

## 5. 测试矩阵

### 输入与兼容入口

```powershell
python -m pytest tests/test_inputs.py tests/test_parser.py tests/test_normalize.py tests/test_cli.py tests/test_integration.py -q
```

### 证据和裁判

```powershell
python -m pytest tests/test_evidence.py tests/test_boundary.py tests/test_dga.py tests/test_routing.py tests/test_adjudicator.py tests/test_profile_adjudication.py -q
```

### Provider 基础设施

```powershell
python -m pytest tests/test_sidecar_provider.py tests/providers -q
```

### Pipeline、校准和最终验收

```powershell
python -m pytest tests/test_live_pipeline.py tests/test_manual_calibration.py tests/test_live_acceptance.py -q
```

### 输出和发布

```powershell
python -m pytest tests/test_export.py tests/test_release_tools.py -q
python pack.py --check
```

修改共享模型或跨模块契约时，专项测试不能替代全量测试。

## 6. 高风险模块

| 模块 | 主要风险 | 最少附加验证 |
|---|---|---|
| `normalize.py` | 当前/历史状态混淆，同 IOC 合并变化 | normalize、profile、裁判、全量差异 |
| `evidence.py` | 黑白证据边界和 URL scope 变化 | evidence、boundary、人工校准、全量 |
| `dga.py` / `routing.py` | DGA 错路由或弱证据放白 | DGA、routing、pipeline、九场景 |
| `adjudicator.py` | 最终结论或 disposition 变化 | adjudicator、manual calibration、diff |
| `pipeline.py` | provider 失败传播、顺序和 freshness | live pipeline、online/offline acceptance |
| `export.py` | 人工工作表兼容和敏感字段泄漏 | JSONL/CSV/Excel、打开读取、XML 扫描 |
| provider | 外部 schema、认证、缓存和离线边界 | 契约测试、错误矩阵、cache、泄漏扫描 |
| `pack.py` | 用户数据、缓存或内部材料进入发布包 | release tests、manifest audit、解压全测 |

## 7. Provider 开发

### 7.1 协议

Provider 必须：

- 实现 `name`、`supports(target)` 和 `collect(targets, context)`。
- 为每个请求 target 返回明确 ProviderStatus。
- 输出 Observation，不直接构造最终结论。
- 保留可审计 `raw_ref`，同时不泄漏认证数据。
- 保持输入顺序或提供足够键让 pipeline 确定性归并。

### 7.2 必测状态

- success
- no_data
- disabled
- timeout / connection / HTTP / malformed JSON error
- 部分 target 成功、部分失败
- cache fresh / stale / miss / refresh
- `--offline` 零网络且 cache 缺失时 fail-closed
- 日志、异常、diagnostics、cache 和 raw 文件零凭据残留
- provider 聚合状态为 error/disabled 时，即使残留 success Observation 也不能完成当前事实
- mock 响应在普通字段中回显凭据时，cache 与 `run_dir/raw` 仍必须零残留

### 7.3 配置和凭据

- endpoint 与认证值只从明确环境变量读取。
- 本地 provider JSON 只承载非密钥配置。
- 不把完整 request headers/body/query 写入异常。
- 新 provider 若需要在线 ICP/HTTP 一类新契约，先取得正式 endpoint、认证和响应样例，不猜字段。
- 当前 ICP 契约已由 mock/cache 固化；真实 endpoint 仍需授权环境验收，不读取 `token_icp.txt`。
- ICP 的 workers/rate 配置当前只校验为正数，尚无已批准的硬上限；在产品上限确定前，生产值必须由接口所有者批准。

### 7.4 时间和 freshness

- 保留接口事实时间，不用请求时间替代。
- `fetched_at` 与 `observed_at` 不可混用。
- stale 数据仅供审计，不能满足自动白所需的新鲜事实。
- 对脏时间和 aware/naive 混合逐条防御，不能因一个坏值丢掉其他有效事实。

## 8. 业务规则约束

- 不引入证据打分、权重或平均。
- 不让弱状态证据推翻直接恶意样本。
- 不让 `updatetime` 或 `level` 直接代表活跃。
- 不在生产代码匹配人工样本 R 编号、脱敏 IOC 或具体研判结论。
- 人工研判原因用于提炼通用规则和新增正反例。
- DGA 自动白必须先确认恶意样本查询完整且无关联样本。
- 非 DGA ICP 保持人工门，不复用 DGA 白规则。
- URL 证据不自动扩张为 domain 证据。

当前 11 类人工校准目标：

| 样本 | 自动目标 |
|---|---|
| R001-R004 | 黑 |
| R005 | DGA 白 |
| R006-R007 | 黑 |
| R013 | 当前 ICP 确认不存在 + 运营恶意上下文，黑 |
| R016 | 灰并保留 URL |
| R018 | DGA 白 |
| R023 | 结构化公开 APT，黑 |

规则改动必须结合 `compare_verdicts()` 检查黑转白、白转黑、转灰、转复核和大规模成员变化，不能只看 11 条样本通过。

迁移审计使用匿名 before/after verdict 与 synthetic/mock Observation 调用 `compare_verdicts()`，报告固定分组：黑白互转、转灰、转复核、only-before/only-after，以及 ICP positive、negative、unresolved 成员；禁止真实 ICP 请求。

2026-07-26 ICP 返修使用合成 `.invalid` 成员复核聚合错误边界：黑转白 0、白转黑 1、转灰 0、转复核 1、only-before/only-after 均为 0。`stable-clue.invalid` 属于 clue matches；历史 ICP 分组为 positive=`stable-positive.invalid`、negative=`stable-negative.invalid`、unresolved=`aggregate-error-standard.invalid,aggregate-error-dga.invalid`。结论迁移由 `compare_verdicts()` 生成，ICP 分组来自同次 synthetic Observation 清单，全程不构造 live provider。

## 9. 输入和错误隔离

- 使用结构化 JSON、URL 和时间解析器，不用字符串猜 schema。
- DNS label、IPv4 和端口校验复用 `inputs.py` 的统一边界。
- URL 必须保留完整 scope，不把解析失败值降级成 host。
- 批处理中的单条坏 IOC 应写入 diagnostics 并继续后续记录。
- 文件整体不可读、配置不合法或没有任何有效 IOC 时可以明确失败。

## 10. 输出验证

JSONL 应保留对象/列表类型；CSV 和 Excel 使用稳定 JSON 字符串。Excel 必须同时存在：

```text
统计, 总, 判黑, 灰, 误报, 待复核
```

修改导出后至少检查：

- 每个 sheet 的成员集合和统计一致。
- 待复核不进入判黑。
- `scope_actions`、`retained_urls`、provider 状态和证据来源不丢失。
- 控制字符不会破坏 Excel XML。
- 用 openpyxl 重新打开生成文件。
- 对 zip 内 XML/rels 以及 JSONL、CSV、diagnostics 做凭据扫描。

## 11. 文档维护

- `README.md`：只描述当前可运行能力、命令和限制。
- `CLAUDE.md`：协作规则、当前事实和连续进度。
- `docs/ARCHITECTURE.md`：稳定模块边界、数据流和失败语义。
- `docs/HISTORY.md`：历史里程碑，不作为当前事实来源。
- `CHANGELOG.md`：版本级用户可见变化和已知限制。
- `docs/superpowers/specs/`、`plans/`：历史决策和实施依据，不进入发布包。

文档中的测试数字必须来自刚运行的命令。规划能力必须明确标记未实现；已经落地的能力不得继续写成未来计划。

## 12. 发布流程

当前项目使用纯文件系统 allow-list 打包，不依赖 Git。

### 12.1 发布前

```powershell
Get-Content VERSION
python -m pytest tests -q
python -m ioc_rejudge --help
python pack.py --check
```

确认 README、CHANGELOG、CLAUDE、架构和开发指南版本一致，且 `requirements.txt` / `requirements-dev.txt` 存在。

### 12.2 创建发布包

```powershell
python pack.py --output-dir .\release
```

打包器：

- 读取严格 `X.Y.Z` 的 `VERSION`。
- 只包含显式 `_INCLUDE_PATHS`。
- 生成 `RELEASE.json`，列出版本和全部成员。
- 排除用户数据、outputs、cache/run、release、pycache、zip、开发提示词和内部 spec/plan。
- 不修改版本号，不执行 Git 或网络操作。

### 12.3 发布包验收

对新 zip 必须：

1. 校验 zip 成员无绝对路径和 `..`。
2. 校验 `RELEASE.json.version` 与 `VERSION` 一致。
3. 校验 manifest `included_paths` 与实际成员精确一致。
4. 确认禁止目录和当前环境凭据值没有进入任何成员。
5. 解压到新的临时目录。
6. 在解压目录运行 `python -m pytest tests -q`。
7. 在解压目录运行 `python -m ioc_rejudge --help` 和 `python pack.py --check`。

源目录测试通过不等于发布包可用；解压后的独立验证是发布完成条件。
