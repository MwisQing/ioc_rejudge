# 项目历史

本文归档旧版 `CLAUDE.md` 中的主要里程碑。历史状态反映当时环境，不自动代表当前磁盘仍可复现。当前事实以根目录 `README.md`、`CLAUDE.md` 和实际测试结果为准。

## 1. 核心流水线

- 建立 `parser -> normalize -> evidence -> adjudicator -> export` 离线快照重判链路。
- 支持 JSONL、UTF-8/GBK 和前缀文本容错。
- 建立 A-F 六级证据、证据强度和裁判树。
- 增加 URL、domain:port、IP:port 归一化。
- 增加 JSONL、CSV、Excel 和 diagnostics 输出。

## 2. 证据与画像

- 建立 domain、IP、运行时三层画像。
- 增加 WHOIS、HTTP、证书、页面标题、解析和反查域名观察。
- 增加威胁残留保护门，避免弱正常信号直接洗白。
- 区分情报过期与失活有效。
- 将 parking 降为弱状态，不独立制造误报。
- 收紧部分强 A 触发词，但当前仍存在裸子串边界问题。

## 3. 导出与诊断

- Excel 增加统计、总表、判黑和误报 sheet。
- 增加审阅排序、颜色、筛选、冻结表头和 CJK 列宽。
- 增加非法控制字符过滤。
- 增加解析错误、缺失数据和跳过行诊断。

## 4. 工程与发布

- 建立 `pack.py`、`push.py` 和 `upgrade.py`。
- `pack.py` 移除 Git 依赖，通过 VERSION 生成 zip。
- `push.py` 支持在无 `.git` 的解压目录初始化仓库。
- `upgrade.py` 支持本地 zip 和版本比较。

## 5. 脱敏与外部接口

- 曾设计并测试 IOC 缓存脱敏脚本。
- 整理 F-Dark、WHOIS、pDNS 和 HTTP 接口脚本/文档。
- IOC Info 查询脚本在邻近 K01 项目中仍有可用版本，但当前项目根目录缺少测试所需文件。

## 6. 人工校准

- 首批 7 条人工研判：黑 6、白 1。
- 第二批 4 条用于探索新证据边界。
- 业务澄清后确定：人工原因用于改写通用规则，不作为高优先级人工来源。
- 确定 DGA 专用白规则、非 DGA ICP 人工门、灰状态和 domain/URL 分域目标。

## 7. 2026-07-23 多源改造设计

- 确认从快照裁判升级为裸 IOC 多源聚合。
- 完成多源架构规格。
- 完成核心/离线和在线 provider 两份实施计划。
- 尚未修改业务代码。

相关文档：

- `docs/superpowers/specs/2026-07-23-multi-source-ioc-adjudication-design.md`
- `docs/superpowers/plans/2026-07-23-multi-source-core.md`
- `docs/superpowers/plans/2026-07-23-live-providers.md`
