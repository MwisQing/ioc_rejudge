# 更新日志

## 未发布

暂无。

## 2.8.0 - 2026-09-22

- 新增：本地 workbench 页面接通导入 staging、后台任务启动/自动轮询/状态刷新、取消边界、分页筛选、快捷 disposition、解释详情、当前页复核导航、人工 review overlay、diagnostics、baseline diff 和 JSONL/CSV/XLSX 下载；不可用后端、活动任务和失败状态不会伪造成功。
- 新增：workbench 支持拖放单个 JSONL、运行摘要、diagnostics/diff/bundle 受控导出、结果字段摘要和 Provider 异常/缺失快捷筛选；导出范围会显示当前筛选条件与预计行数。
- 安全：查询明文、还原结果复制和覆盖已有 key 前增加二次确认；摘要与浏览器响应不暴露本地路径、凭据或 token。
- 验证：workbench/UI 专项 `44 passed`，全量 Python 测试 `1153 passed, 1 skipped`，真实 Chromium 桌面/390px 回归通过，`compileall`、Node 页面脚本语法和 `git diff --check` 通过。
- 新增：离线 workbench 支持显式后台模式，任务状态原子持久化并区分 queued/running/succeeded/failed/cancelled；服务重启会把未完成任务收口为 failed，取消只作用于尚未开始的任务。
- 修复：筛选结果的 `result_id` 始终对应原始结果行，避免点击筛选后的第二条结果打开第一条解释；浏览器任务响应不再暴露本地结果/diagnostics 路径。
- 文档：更新高频用户前端优化说明、README 和协作上下文，明确 P1 已实施与本轮 P2 范围及剩余非目标。
- 体验：增加研判工作台、脱敏协作、运维状态的顶部锚点导航，减少长页面滚动。
- 体验：窄屏结果表改为带字段标签的卡片，结果按 24 行/帧增量挂载并可取消过时渲染；补充真实浏览器回归，覆盖导入、后台任务、结果加载和明文复制确认。

## 2.7.0 - 2026-09-22

- 新增：离线路线命令入口，支持 `job` 生命周期、`review` 人工标签/重开、`explain` 解释、`history` 查询、`health --offline` 配置检查、`cache inspect/cleanup`、`import-table` 和 `export-bundle`；成功输出机器可读 JSON，缓存清理默认 dry-run，provider 参数在本地后端中 fail-closed。
- 新增：本地 workbench 后端接入 UI。导入的 legacy snapshot 在本机离线执行并持久化 task 状态、results、diagnostics、人工 review overlay 和 JSONL/CSV/XLSX 导出；不调用真实 provider 网络，也不覆盖系统结论。
- 新增：CSV/XLSX IOC 导入适配与结果 bundle 导出。支持引号换行、物理行号、defang 恢复、公式风险拦截、重复报告、输出冲突预检和原子写入；cache admin 可分别统计 provider/result cache，并按完整日期 shard 安全清理。
- 修复：`cache_type=all` 清理时按 shard 所属目录使用正确的 provider/result 行结构校验，避免结果缓存被误判为坏行而漏清理。
- 修复：配置的 API 凭据值即使被上游在普通 JSON 字段（`message`、`details` 等）回显，也不会进入原始缓存、run 审计副本、观测载荷或错误文案。共享脱敏助手 `providers/redaction.py` 提供值级替换与 secret-safe 错误渲染；六个在线 provider（K01、IOC Info、F-Dark、WHOIS、pDNS、ICP）在响应消费与缓存写入边界统一接入，`JsonlProviderCache.put` 新增 keyword-only `secret_values=()`：缓存 key 仍按原始 IOC/params 计算，落盘 params/raw、run 审计副本和返回的 entry 字段同时执行敏感字段名与配置值脱敏；`get` 仍用原始 params 查询。并发写入使用不同合成哨兵验证落盘字节。
- 修复：普通路由合并快照与 WHOIS Observation 时，新鲜的 provider WHOIS 记录按 fetch 时间覆盖快照里较旧的到期日，输入顺序不影响结果；覆盖不发明情报时间，快照 `updatetime` 仍是 intel 记录时间。F-Dark 适配器保留样本 hash 类型（MD5/SHA1/SHA256）、confidence/family/level、真实样本观察时间（lseen/fseen）与 provenance；缺失、无效或未来样本时间，低 level、零 confidence 与 `not-a-virus` 不会成为当前恶意活动。
- 修复：DGA 路由只接受可靠、fresh、目标匹配的 `dga_classification`；error/stale/unknown/错目标事实保持保守。sidecar freshness 一律由 `fetched_at` + 来源 TTL + 评估时刻推导，显式 fresh 的 NO_DATA 行可作为完整性事实；未来/过期 fetched_at 有明确边界。
- 修复：完整结果缓存的 `valid_until` 纳入依赖 sidecar 行的 `fetched_at+TTL`（含显式 fresh NO_DATA）与未来 fetched_at 激活边界（激活时刻前 1µs 截止）；配置指纹纳入 sidecar TTL。缓存契约升级为 `12`，旧结论自动重算；历史 provider 缓存文件不做迁移。
- 修复：统一目标身份保留 URL scheme。`case.invalid`、`http://case.invalid`、`https://case.invalid` 为三个独立研判目标（与输入顺序无关）；http/https 同 path 不合并；host 大小写与尾点仍去重。快照匹配、sidecar、dossier merge、relate_url 直接证据、retained_urls、结果缓存与导出共用同一 scheme-aware 身份；HTTP 目标不会因 HTTPS `relate_url` 建立 A 证据。`normalize_ioc()` 仍返回历史 scheme-less 形态供记录分组与 provider 原始缓存 IOC 字段兼容。
- 修复：完整结果缓存支持同一天内的时间敏感失效。缓存行可带 `valid_until`：覆盖全部实质活动输入（快照 hash/flint/access/dtree 与 IOC Info 样本，非 latest-only）、pDNS 窗口、WHOIS 日期、未来事件在激活时刻前 1µs 截止，以及依赖 provider 原始缓存 `fetched_at+TTL`（含 NO_DATA 完整性事实）。越过边界时 `temporal_expired` 重算且与无缓存结论一致；无时间敏感证据时 30 秒内重复运行仍 hit。
- 修复：完整结果指纹改为按目标关联 provider 原始响应摘要（内容/fetch 时间/params/absence，含 FDark 多变体与 host 作用域查询），同一目标 raw 更新或真正消失只使该目标 miss；无关 IOC 保持 hit。生产 provider 原始缓存没有删除 API，历史缓存文件也不迁移；真正缺席（如临时分片被移除）通过依赖摘要使相关结果失效。sidecar 内容哈希按 path+mtime+size 在单次 run 内只读一次。
- 修复：必看黑结论（block + review_suggestion=必看）进入默认复核队列；普通无需复核的 block 仍排除。队列入队不等于判黑 Excel 表：总表/判黑表本就包含必看黑结论。
- 修复：同结论下处置范围/保留 URL/复核义务变化出现在 diff 的 `operational_changes`（`disposition`/`scope_actions`/`retained_urls`/`review_suggestion`/`missing_required_providers`/`classification_unknown`，无序集合仅顺序或重复变化不计），避免只看 `changed=[]` 漏掉运维变更；CLI diff 摘要新增 `operations=N`（本次实际对比的 verdict 行数）。
- 修复：Share UI 超过历史展示上限（`max_bundles`，UI CLI `--history-limit N`）时不再删除旧 bundle 的 manifest 与还原产物；同 id 重建保留 restored/cloud 文件并采用先备份后提交的事务。列表仅返回最近 N 条，更早任务仍可按 bundle_id 还原；磁盘增长需人工清理。
- 修复：JSONL 输入隔离非对象行（`[]`/`null`/数字/字符串）与嵌套非对象 `data` 条目；嵌套拒绝有无界 `nested_data_error_count`（样例仍有界），legacy/unified diagnostics 与 `--strict` 均计入，同时继续导出合法条目；快照非法 IOC 位置使用物理文件行号。
- 修复：输出路径在 provider 采集前做冲突与可写性预检（已存在输出也探测同目录 sibling 临时文件），禁止覆盖输入/基线/规则/配置/凭据/sidecar，并拒绝输出路径互撞；JSONL/CSV/Excel/diagnostics/diff 仅经 sibling 临时文件 + `os.replace` 写入，`PermissionError`/写失败时保留原字节，不做截断或复制回落。
- 变更：始终写出 diagnostics（`-j`/`-c` 时默认写到主输出旁的 `*_diagnostics.json`）；JSONL 按行流式写入 atomic sibling temp；JSONL/CSV 导出 `classification_unknown`（JSONL 布尔，CSV `true`/`false`，旧行默认 `false`）；新增可选 `--strict`，在拒绝输入、嵌套/解析错误、provider/处理错误或缺失必要来源时非 0 退出，业务待复核本身不算失败。
- 修复：本地 `upgrade.py` 选择 release zip 时严格匹配 `pack.py` 包名语法 `ioc_rejudge_vX.Y.Z_YYYYMMDD-HHMMSS.zip` 并校验真实日历时间戳；按语义版本再按时间戳排序，拒绝负版本/残缺版本/畸形时间戳。
- 修复：provider 配置中 `enabled` 与布尔查询选项必须是 JSON boolean，拒绝字符串 `"false"` 与 `0`/`1` 静默转真；`max_attempts`/`retry_delay`/TTL 等数值拒绝 NaN/Inf 与 timedelta 溢出，错误以字段级 ValueError 返回而非 OverflowError 回溯；CLI 活动窗口与等级阈值拒绝非法/非有限/过大 day 窗口。
- 修复：ICP 接口返回 `resultCode=3003` 或 `身份校验失败` 时记为 `error`，不再当成「已查询且无备案」的成功负结果。这类失败不会清空 IOC Info 上的备案号，也不会单独证明当前无备案。研判结果缓存契约升级为 `9`。既有失败缓存仍可复用为 error，默认不因此全量重打 ICP；要拿到真实当前备案需凭证有效后 `--refresh` 或清除 `.cache_icp`。
- 变更：普通路由把「仿冒网站」「仿冒下载」、`family=phishingsite` 以及公开钓鱼源（openphish / phishtank / maltrail / high-confidence-osint，含接口常见拼写 `hign-confidence-osint`）与「黑产/扩展/扩线」同级直接判黑。`钓鱼站点` 和 `family=phish` 不因此打黑或打白。域名 IOC 的 URL 作用范围灰出口改看最新记录等级，不再被历史更高 level 挡住；URL IOC 仍可因匹配的 `relate_url` 判黑。
- 修复：share 严格扫描不再把包名或 `*.so` 被 token 化后剩下的 `/lib/` 当成 Unix 路径。助手「脱敏并复制」不会因此失败；`/home/.../file` 这类带文件名的路径仍会脱敏。
- 修复：Go HTTP worker 按块拉起进程。一块崩溃、非 JSON 输出或非零退出时，只把该块未返回的请求记为 `error`，后续块继续；不再把整路 K01/IOC Info 打成 `failed after` 并全员待复核。
- 变更：统一模式按本机物理内存封顶并发。约 4 GiB 使用 HTTP workers 2、跨 provider 并发 2、每进程 4 个 HTTP 任务；约 8 GiB 为 4/3/8；更大内存保持原默认。启动打印 `Memory:`。`IOC_REJUDGE_MEMORY_PROFILE=full` 关闭封顶，`low` 强制低内存档。
- 变更：provider 原始缓存内存索引不再驻留整份 `raw` 响应，只保留文件偏移；物理 JSONL 格式不变。
- 验证：Python 全量测试 `1140 passed, 1 skipped`；Go 测试通过；`python pack.py --check` 检查 144 个发布文件；`python -m compileall -q ioc_rejudge` 通过。发布包内容、manifest、禁入项和 SHA-256 在打包后复核。

## 2.6.0 - 2026-09-10

- 修复：统一时间边界。legacy/ISO-8601 时间在比较前归一化为 UTC，aware/naive 可安全混用；`recent`/`fresh` 精确端点包含，未来、无效和负 Unix 时间不能满足近期或缓存新鲜条件；一次 pipeline 使用同一评估时刻完成证据、裁判和结果序列化。
- 修复：DNS 查询、HTTP 连接和 sample 等中性描述不再单独形成历史恶意闭环；C 级样本证据必须由同一条等级合格且关联目标的记录提供，待复核原因对应实际缺失的证据。
- 修复：当前 ICP 只采纳成功且 fresh 的类型化事实，历史备案不再充当 DGA 当前白信号；有效正负事实并存时保留冲突，结果不再由返回顺序决定。冲突阻止自动误报、灰出口，明确的强恶意仍可保留黑并要求复核。
- 修复：画像与证据共用网站主体关系校验，无关官网、单独备案号或标题不再形成强业务身份；公开 APT 校验结构化记录主体及报告 URL，保留合法外部报告引用。
- 修复：NaN、Infinity 和溢出数值不能绕过等级、恶意样本或 APT 阈值检查；研判结果缓存契约升级为 `7`，旧结论自动重新计算，原始 provider 缓存仍可复用。
- 修复：`python -m ioc_rejudge ui` 在当前目录存在 `credentials.local.json` 时自动用于 IOC Info 查询，不再只读启动终端的环境变量。缺少凭据时页面给出可见提示，查询按钮显示「查询中…」。
- 修复：助手「查询 IOC Info」改为单次 Python HTTP（连接 5 秒、读取 15 秒），不再走研判用的 10 次空结果重试和每次拉起 Go worker。同一进程复用缓存索引，接口失败时可用超过 7 天的本机旧缓存；查询不再锁住整页。浏览器 45 秒仍无响应时提示到启动窗口结束进程，不要只刷新网页。
- 修复：「清除口令」在未解锁、也没有本机记住口令时以前看起来像没反应；现在会清空输入框、给出明确提示，并返回是否清除了已保存口令。
- 验证：时间边界、正确性回归、人工校准和 UI 专项通过；全量测试与 `pack.py --check` 结果见本版本发布记录。14 个合成场景迁移为黑转白 0、白转黑 1、转复核 7。原始全量脱敏快照不在当前工作树，实际数据的全量迁移尚未验收。

## 2.5.0 - 2026-09-02

- 变更：`python -m ioc_rejudge ui` 新 key 口令改为非空即可，不再要求至少 12 个字符；成功解锁后把口令保存在 key 同目录的 `passphrase` 文件，下次启动自动解锁。“清除口令”同时删除该文件。
- 新增：页面“查询 IOC Info”面板和 `POST /api/lookup`。可粘贴裸 IOC 或填写本机文件；只查询 `ioc_info`，默认 7 天缓存优先，miss 再走接口。新增 `--cache-dir`（默认 `.\provider-cache`）和 `--credentials-file`。查询不要求先解锁；无凭据时只读缓存，全部 miss 则报错且不联网。
- 新增：查询/脱敏/还原结果支持展开和合拢查看；查询后的主操作是“脱敏并复制”（一行一个 compact JSONL 进剪贴板）。复制明文按钮标明未脱敏、勿发给云端。
- 安全：share 自由文本补齐 v0.7 漏检形态（defang、JWT、云主机名、hex+exe、`Update By`/`请联系`、bang 路径、粘连域名、截断/下划线 IPv4、Base64 JSON），仍使用 AES-SIV token；JWT 永久 `[REDACTED]`。不引入对照表或假值体系。
- 安全：记住的口令只在本机 key 目录，不进入页面、日志或 status 明文回显；CLI `share` 路径不读写该文件。lookup 允许本机按既有 provider 栈访问 IOC Info，不把凭据写入查询结果。
- 验证：share+UI 专项 `39 passed`，全量 `751 passed, 1 skipped`，`pack.py --check` 107 个发布文件。

## 2.4.0 - 2026-09-01

- 新增：`python -m ioc_rejudge ui` 本地 share 助手单页工具，把“研判产物脱敏 -> 复制给云端 AI -> 粘贴 AI 返回 -> 还原”压缩为页面上的两次点击；默认端口 8731，占用时自动回退随机端口，支持 `--port`/`--key-file`/`--bundle-dir`/`--no-browser`。
- 新增：share bundle 本地存储管理——`~/.ioc-share/bundles` 按 `bundle_id` 保存最近 20 个 bundle，restore 自动按行内 `bundle_id` 直定位、sha256 兜底匹配本地 manifest，不再需要手工指定 manifest 路径。
- 安全：UI 服务只监听 `127.0.0.1` 且拒绝地址复用（防 Windows 双进程共享端口）；页面与全部 `/api/*` 端点要求进程级会话令牌并通过 Host/Origin（含端口）校验；key 口令仅驻留服务进程内存，页面 `no-store`，可一键清除。
- 安全：`share.ensure_key` 公开函数补齐 key 生成/解锁/覆盖校验入口；share 既有脱敏、manifest 认证和严格残留扫描语义不变，UI 不提供关闭严格模式的入口。
- 修复：未授权或未找到的请求在返回 403/404 前排空请求体，避免 Windows 在未读缓冲上关闭套接字时发送 RST，导致客户端读不到拒绝响应。
- 兼容：`ui.py`/`ui.html` 使用标准库 `http.server` 与零外部资源单文件页面，无新增运行依赖；页面剪贴板不可用时自动回退全选 + Ctrl+C。
- 验证：UI 专项 `15 passed`（真实回环服务覆盖安全门、key 生命周期、create/restore/scan 回环、manifest 双路匹配、严格失败清理、保留上限和端口回退），全量 `742 passed, 1 skipped`，`pack.py --check` 106 个发布文件。

## 2.3.0 - 2026-08-24

- 新增：`python -m ioc_rejudge share create|restore|scan`，支持本地口令保护的 AES-SIV 可关联 token、流式 JSONL、带 key 认证的 manifest 和严格残留扫描。
- 安全：credential-like 字段、URL 凭据和内嵌凭据在 share bundle 中永久 `[REDACTED]`，key 与原始 manifest 不进入云端；错误 key、篡改/非规范 token、manifest 认证失败或 bundle 归属不匹配时 fail-closed。
- 修复：研判结果缓存 fingerprint 纳入 UTC 评估日期，避免跨活动窗口或日期边界复用旧结论；旧缓存契约自动失效。
- 修复：`--seed` 现在能让 legacy anonymizer 的 domain、IP、hash 和 email 替身真正稳定复现。

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
