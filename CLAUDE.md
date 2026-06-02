# APT IOC 快照重判工具

## 项目背景

对客户 APT 告警 IOC 做批量重判。输入 JSON 快照，不依赖外部查询。输出四类结论：存活有效、失活有效、误报、待复核。

## 使用方式

```bash
python -m ioc_rejudge -i <快照.jsonl> [-j result.jsonl] [-c result.csv] [--rules rules.json] [--diagnostics diag.json]
# 不指定 -c/-j 时默认生成 Excel（summary + results 双 sheet、自动列宽、表头筛选、固定表头、审阅排序）
# --rules: 可选 JSON 规则配置文件，不指定时使用内置默认值
# --diagnostics: 可选诊断 JSON 输出路径，Excel 模式下自动生成
# 输入格式：逐行 JSONL，每行 {"ioc": "...", "data": [...]}
```

## 协作规则

- 本文件分为默认规则与按需模式两层。
- 默认规则始终生效。
- 按需模式仅在用户明确要求，或任务明显需要且已获用户确认时启用；未启用前，不默认进入重流程。
- 涉及项目/系统设计、文档体系设计或高风险改动时，应在开始时让用户选择是否启用相关按需模式。

## 默认规则

### 工作原则

- 非微小改动先说明方法。
- 需求有歧义、风险高或影响大时，先澄清并获批，再开始写代码。
- 坚持 Spec Coding，避免 Vibe Coding；Plan 只写方案、范围、风险和验收标准，不写实现代码。
- 优先小步迭代；实现与审查分离。
- 完成后可执行 /simplify；必要时使用 /loop。

### 编码约束

- 代码中只使用英文。
- 注释说明意图、约束和边界，不记录开发过程式说明。
- 优先用概念、模块、职责和符号名定位代码；不要只依赖易漂移的行号，必要时可补充文件路径。
- Spec 不依赖行号定位代码。
- 不为未被请求的未来需求提前抽象、泛化或暴露配置。

### 质量与验证

- 项目早期只保留最小必要质量标准：可运行、可验证、可回滚。
- 关键路径、高风险改动和外部接口必须可验证。
- 修复 bug 时，先复现，再修复，再验证。
- 任何"已完成""已修复""已通过"的结论，都必须附验证方式、命令或结果摘要。
- 若当前无法验证，必须明确说明原因、风险和未覆盖范围。
- 修复 bug 或完成功能后，必须运行全量回归测试，所有用例通过才算完成。

### 拆分与沉淀

- 将任务拆成低耦合、可独立验证的子任务；必要时使用 /batch。
- 重复出现且边界稳定的流程，应沉淀为 Skill、脚本或检查清单。
- 公共规则优先沉淀为文档、测试或自动化，而不是只停留在对话里。

### 协作与纠错

- 被纠正时，先验证问题是否适用于当前代码库，再调整做法。
- 外部建议先核对是否适用，再决定是否采纳。
- 对重复性问题，沉淀为明确规则、测试或自动检查。

### 禁止事项

- 永远不要使用 /init，除非项目明确要求。
- CLAUDE.md 必须按项目实际需求编写，不套用空泛模板。
- 不要在代码注释、commit message 或 PR body 中使用描述开发进度的词，如 FIXED、Step、Week、Section、Phase、AC-x。
- 不要在代码注释、commit message 或 PR body 中出现 AI 工具名称，如 Codex、Claude、Grok、Gemini 等。
- 不要把外部实现细节、外部文档或外部技能树直接提升为当前项目的硬约束。

## 按需模式

### 架构与演进模式

- 适用：用户要求项目或系统设计满足分层、稳定接口、可演进，或明确要求按架构流程推进。
- 优先做分层设计；不同层次保持职责分离，只通过明确、稳定的接口交互。
- 不要让上层依赖下层实现细节，也不要建立非必要的跨层耦合；若必须依赖，应收敛为单向、最小依赖。
- 每个层次内优先做 primitive 设计；primitive 应是独立、可替换、可组合、可验证的最小功能单元。
- 若项目采用多 Agent 协作，应按层次设计专用 agent 与 skill，使其职责、输入、输出和边界清晰。
- 架构演进必须逐步验证；每一步新增特性或重构，都要确认不破坏已有接口、行为和关键路径。

### 严格验证模式

- 适用：改动高风险、回归代价高，或用户要求每一步都经过验证。
- 将工作拆成可独立验证的小步；每一步完成后先验证，再继续下一步。
- 新增特性、重构或修复都要确认不破坏已有功能、接口和关键路径。
- 若当前无法完成必要验证，应暂停继续扩展，并明确说明阻塞、风险和未覆盖范围。

## 调用链

```
cli.py
  → parser.read_jsonl_snapshot()    # 逐行读 JSONL，返回 [{"ioc": ..., "data": [...]}]
  → normalize.merge_records()       # 同 IOC 多记录合并（支持 url/ip_port/domain_port）
  → evidence.extract_evidence()     # 提取 A-F 级证据（附加 strength/tags，使用规则配置）
  → adjudicator.adjudicate()        # 判定结论（基于 evidence metadata 判定强 A/强 E）
  → export.export_jsonl/csv/excel()  # 导出（Excel: summary + results 双 sheet）
  → export_diagnostics()            # 诊断 JSON 导出
```

## API 清单

### rules.py — 规则配置
- `RuleConfig` — dataclass，字段：`strong_sources`, `weak_sources`, `malicious_indicators`, `context_comment_malicious_indicators`, `context_comment_historical_indicators`, `normalization_indicators`, `review_indicators`, `trusted_business_fields`
- `load_rules(filepath: str | None = None) -> RuleConfig` — 加载 JSON 规则文件，None 时返回内置默认值；缺失键自动补全；校验类型和字段名

### parser.py — 快照解析
- `parse_time(value: str | None) -> datetime | None` — 多格式时间解析
- `read_jsonl_snapshot(filepath: str) -> list[dict]` — 逐行读 JSONL，返回 [{"ioc": ..., "data": [...]}]，支持 UTF-8/GBK，容错前缀文本
- `safe_get(record: dict, *keys: str, default=None)` — 嵌套字典安全取值

### normalize.py — IOC 归一化与合并
- `normalize_ioc(value: str, port: str = "0") -> tuple[str, str, list[str]]` — 归一化 IOC（ip/ip_port/domain/domain_port/url）
- `group_by_ioc(records: list[dict]) -> dict[str, list[dict]]` — 按 IOC 分组
- `merge_records(records: list[dict]) -> IocDossier` — 合并同 IOC 全部记录为 Dossier

### evidence.py — 证据提取（A-F 级）
- `extract_evidence(dossier: IocDossier, config: Config) -> IocDossier` — 主入口，调用 _extract_a 到 _extract_f
- `_ioc_aware_match(ioc: str, text: str) -> bool` — IOC 感知文本匹配（域名边界、IP 数字边界、URL 解析、子域名支持）
- `_is_strong_a(dossier: IocDossier) -> bool` — 强 A 判定（基于 evidence metadata: strength=strong）
- `_is_strong_e(dossier: IocDossier) -> bool` — 强 E 判定（基于 evidence metadata: strength=strong）
- 内部函数：`_extract_a/b/c/d/e/f(dossier, config)` — 各级证据提取，附加 strength/tags

### adjudicator.py — 裁判树
- `adjudicate(dossier: IocDossier) -> Verdict` — 主入口，A-F 证据 → 结论
- `_build_hit_evidence(dossier: IocDossier) -> str` — 拼接命中证据摘要
- 内部函数：`_make_verdict()`, `_make_conflict_verdict()`, `_build_forbidden()`, `_build_reason()`

### models.py — 数据结构
- `Conclusion(str, Enum)` — 存活有效/失活有效/误报/待复核
- `EvidenceLevel(str, Enum)` — A/B/C/D/E/F
- `EvidenceStrength(str, Enum)` — strong/normal/weak
- `Evidence` — level + field + detail + strength + tags
- `IocDossier` — IOC 全量信息（证据、时间、来源、hash 等）
- `Verdict` — 裁判输出（结论、恶意性质、活跃状态、置信度等）

### config.py — 配置
- `Config` — dataclass，字段：`activity_window_days(365)`, `hash_malicious_level(40)`, `relate_url_malicious_level(40)`, `historical_malicious_level(40)`, `high_level_no_a_threshold(70)`, `rules(RuleConfig)`
- `load_config(...) -> Config` — CLI 参数覆盖默认值，支持 `rules_path` 参数加载 JSON 规则

### export.py — 导出
- `export_jsonl(verdicts: list[dict], filepath: str)` — 导出 JSONL
- `export_csv(verdicts: list[dict], filepath: str)` — 导出 CSV
- `export_excel(verdicts: list[dict], filepath: str, diagnostics: dict | None = None)` — 导出 Excel（summary + results 双 sheet、审阅排序、结论着色、自动列宽、表头筛选、冻结首行）
- `_display_width(text: str) -> int` — 估算显示宽度（CJK 字符算 2 列宽）
- `_sort_key(v: dict) -> tuple` — 审阅排序键（必看→抽检→不看，待复核→存活有效→失活有效→误报）

### cli.py — 入口
- `run_pipeline(input_path: str, config: Config) -> list[dict]` — 完整流水线（兼容包装）
- `run_pipeline_with_diagnostics(input_path: str, config: Config) -> PipelineResult` — 带诊断的完整流水线
- `Diagnostics` — dataclass，诊断数据（parse_error_count, missing_data_count, empty_data_count, skipped_total 等）
- `PipelineResult` — dataclass，verdicts + diagnostics
- `export_diagnostics(diag: Diagnostics, filepath: str)` — 导出诊断 JSON
- `main()` — argparse CLI（支持 -i/-j/-c/--rules/--diagnostics + 阈值参数）

## 当前进度

| 功能 | 状态 | 说明 |
|------|------|------|
| 核心流水线 | ✅ 完成 | parser→normalize→evidence→adjudicator→export 全通 |
| A-F 证据提取 | ✅ 完成 | 6 级证据全部实现，附加 strength/tags 元数据 |
| 裁判树 | ✅ 完成 | A+E 冲突检测、强弱区分，基于 evidence metadata 判定 |
| CLI 入口 | ✅ 完成 | 支持 -i/-j/-c/--rules/--diagnostics + 阈值参数；不指定输出时默认 Excel |
| `__main__.py` | ✅ 完成 | `python -m ioc_rejudge` 可用 |
| Excel 导出 | ✅ 完成 | summary + results 双 sheet、审阅排序（必看→抽检→不看）、结论着色、自动列宽（CJK 感知）、表头筛选、冻结首行 |
| 规则配置 | ✅ 完成 | `rules.py` + `rules/default_rules.json`；`--rules` 加载 JSON 配置；缺失键自动补全；类型校验 |
| 证据强度模型 | ✅ 完成 | `EvidenceStrength(str, Enum)` strong/normal/weak；附加到 Evidence 对象 |
| IOC 感知匹配 | ✅ 完成 | 域名边界匹配（evil.com ≠ not-evil.com、evil.com.cn）、IP 数字边界、URL 解析、子域名支持 |
| URL/端口归一化 | ✅ 完成 | `normalize_ioc` 支持 url/ip_port/domain_port 类型；URL 和 domain 分开裁判 |
| 证据详情字段 | ✅ 完成 | 输出包含 evidence_a~f_detail（格式：`field [strength,tags]: detail`） |
| 诊断导出 | ✅ 完成 | `Diagnostics` dataclass + `export_diagnostics` JSON 导出；Excel 模式自动生成诊断文件 |
| 测试 | ✅ 96/96 通过 | pytest 全量通过（含 29 条边界测试） |
| 证据修复 | ✅ 完成 | _extract_a 删除 cutoff 死参数 |
| 裁判修复 | ✅ 完成 | _make_conflict_verdict 统一调用 _build_forbidden |
| 测试修复 | ✅ 完成 | test_5 断言精确匹配 |
| CLI 修复 | ✅ 完成 | 直接 .value 替代 hasattr 检查 |
| iocProducer_api_ioc_info.py | ✅ 完成 | API `data` 字典解出、逐行写缓存和结果 JSONL、请求成功/失败状态展示 |
| JSONL 输入支持 | ✅ 完成 | `read_jsonl_snapshot` 逐行读 JSONL，替换旧 `read_json_snapshot`；58/58 测试通过 |
| 静默失败修复 | ✅ 完成 | 正则回退 crash 修复、解析失败计数、空 data 行警告、GBK 编码测试、空 IOC 检测 |
| 验收测试 | ✅ 通过 | 17/17 场景通过，96/96 单元测试通过 |
| pack/push/upgrade VERSION 联动 | ✅ 完成 | pack: VERSION 加入 _INCLUDE_PATHS，zip 名含版本号，支持 bump；push: 自动 git init + 初始提交（解压场景），自动推送 tags；upgrade: 更新前比较版本，降级/同版本需确认 |

## 铁律（不可违反）

- 不打分、不平均、不让弱证据推翻强证据
- `updatetime` 不是存活证据
- `level` 是威胁等级，不是存活状态
- 误报 = 恶意关联不成立，不是"现在不活了"
- 失活 = 历史恶意已老化，不是"原情报错误"
- 同 IOC 必须先合并再裁判

## 测试

```bash
python -m pytest tests/ -v
```

96 个测试全通过是准入门槛。修改 adjudicator 或 evidence 后必须跑测试。
