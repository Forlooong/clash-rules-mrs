# Mihomo MRS：日常可用优先的 v2 分流

v2 是独立候选通道：**关闭广告拦截，国内直连、其余代理，个人例外优先**。仅保留一个“节点选择”组，不加入 DIRECT 自动回退。沿用系统代理，不启用 TUN。v1 仍可读取和回滚；候选发布与服务器实际启用是不同状态。

## v2 的来源与顺序

主要分类使用 MetaCubeX 的 `geolocation-cn`、private、CN IP，以及 Google、YouTube、Telegram、Netflix、GitHub、OpenAI。Loyalsoldier 和 ACL4SSR 的整个固定生产分支继续审计，但不自动取并集。没有广告匹配、上游进程直连、整表 UnBan、通用代理表或 ASN 出口规则。

顺序固定为：回环 → 个人 DIRECT → 个人代理 → 私网 → 明确海外服务 → Telegram IP → 国内域名 → 国内 IP → MATCH 节点选择。国内 IP 规则允许主动解析；私网和 Telegram IP 使用 `no-resolve`。个人规则文件保持原接口，Binance、Bybit Global 与 Bybit 的根域名和子域名直连。

`geolocation-cn` 也不是安全白名单。`scripts/shared-platform-roots.json` 明确剔除已识别的共享云/CDN 整根规则，记录来源与原因，保留具体业务子域。没有按 `cloud`/`cdn` 字符串批量删域名。国内 IP 兜底仍可令其国内地址直连；不声称已识别互联网上全部共享平台。

## v2 的 DNS 与消费接口

`runtime/snapshot.py` 只装配规则与 MRS；最终订阅编译必须再调用 `runtime/dns.py::assemble_dns`，并以 `sort_keys=False` 输出 YAML。实际集成目标是 `sing-box/sbmanager`，其内置模块与这里同步。

- 国内域名：国内 DoH，经 DIRECT；节点域名与解析器引导：独立的 IP 地址 DoH，经 DIRECT。
- 未分类、明确海外、个人境外直连域名：Cloudflare/Google DoH，经“节点选择”。`direct-nameserver` 同样使用代理 DoH，开启 `direct-nameserver-follow-policy`。
- 不设置国内 fallback。代理 DNS 断线且无有效缓存时，查询失败，不自动换成国内 DNS。
- DNS policy 按个人、私网、服务、国内顺序在最终编译重建。正则/关键词使用内联 classical provider；域名和 IP 仍为 MRS，不多下载 YAML。
- 迁移旧自动 DNS 策略，保留可证明不冲突的自定义加密代理解析；冲突拒绝激活。进程、端口、个人 IP 规则无法完整表达 DNS 意图，构建报告记录边界。

这约束 Mihomo 接管的连接。系统代理不会接管所有应用，浏览器自带 DNS、绕过代理的进程及局域网 system 解析不在全设备保证内。Binance 业务直连与可信 DNS 可以验证，但可信地址仍被 TLS 重置时，规则不能保证恢复网页。

清单 `schema_version=2, policy_version=balanced-v2`；入口 `release/candidate-v2.json`（预览 `candidates/candidate-v2.json`），不覆盖 v1 的 `candidate.json`。迁移用 `sb rules update --channel v2`；状态、候选通道、规则构建、DNS、模板及完整订阅通过同一事务切换，`sb rollback <transaction-id>` 同时恢复。仅更新 MRS URL 不能完成迁移。

自定义 DNS 通过随内联元数据交付的域名索引检查与自动策略的交集，不能仅因解析器写了 `#节点选择` 就放行。无法证明不相交的通配符、后缀与复杂正则组合会保留旧配置并报告；精确域名更容易验证。

## v2 全量审计与发布门槛

固定三个生产分支提交，下载完整归档，重建 Git blob/tree SHA 核对目录完整性。逐条读取规范文本，包括 ASN 和其他客户端格式；为不支持的语法明确记录排除理由，未知语法阻止发布。逐个比较文本、YAML、rule 和 MRS 的可表达投影；IP 比较覆盖区间，域名区分精确、后缀、仅子域与正则。MRS 解码器用固定核心编译/反编译夹具交叉核对。复杂正则/进程/端口交集无法证明时标为未穷尽，实际配置回归补充。

客户端只取 MRS、内联谓词及小型元数据（总上限 8 MiB）。完整清单、逐条原文、风险、排除、投影报告和对应源码通过独立 `audit-<build-id>.tar.gz` Release 附件交付；运行清单绑定审计 manifest 的 SHA-256。缺文件、未知语法、投影不一致、必需集合为空或核心行为回归失败均阻止候选发布。

构建最后生成 `artifact-manifest.json`，绑定全部审计报告与源码归档的大小和哈希；发布前逐项复核。`routing-changes.json.gz` 对同次上游输入的 v1 重建基线与 v2 比较完整规则链、域名锚点/子域边界和 IP 覆盖，明确标出进程、IP、复杂正则带来的不确定性。这是迁移策略报告，不冒充当前线上状态或所有网站的实际连接测试。审计失败时 CI 仍上传诊断附件，候选入口保持旧版本。

### 修复上游派生 MRS，不豁免错误

原始审计保存在 `audit/original`。已确认的 ACL 生成器错误把 `DOMAIN-SUFFIX,` 等前缀当成了域名字符；修复从该提交真正用于生成此文件的 classical 文本重新提取可表达的域名规则，逐个编译和核对。只含关键词或正则的分类，其域名投影是空集合，原 classical 谓词必须保留；不能填入占位域名，也不能将零字节文件视为有效 MRS。

经典 `DOMAIN`/`DOMAIN-SUFFIX` 中的星号是字面字符，不能转换成 domain provider 的通配符；这些谓词同样完整保留在 classical 记录中。空集合使用无终结节点的 MRS 编码，并在固定 Mihomo v1.19.32 中逐项验证 provider 实际加载、规则数为零和不误匹配。该版本的命令行转换器主动拒绝零规则集合，因此报告明确记录这项限制，空集合不宣称通过了命令行反编译。

`audit/repairs` 保存真实重建文件与原始哈希、来源文本哈希、新哈希及核心验证证据。再次审计时仍重建原始 Git 树以确认目录完整性，另外标记实际验证的修复文件；最终 `audit/manifest.json` 的通过状态只表示修复后的全部有效文件已通过，不会改写原始失败报告。未知故障、文本损坏或修复后仍不一致继续阻止构建。没有按哈希忽略错误的隔离放行表。

依赖 Python 3.12、PyYAML 6.0.2、zstandard 0.24.0、Mihomo v1.19.32：

```sh
python -m unittest discover -s tests -v
python scripts/four_sources.py --build-id rules-local-v1
python scripts/build_balanced.py --sources out/sources.json --build-id rules-local-v2 --prepare-only
python scripts/audit_sources.py --sources balanced-out/sources.json --mihomo mihomo --output audit/original
```

原始审计失败时，先阅读 `audit/original/errors.json`。只有修复器明确支持的故障可重建；修复失败不能跳过：

```sh
python scripts/repair_sources.py --audit audit/original --sources balanced-out/sources.json --mihomo mihomo --output audit/repairs
python scripts/audit_sources.py --sources balanced-out/sources.json --mihomo mihomo --output audit --repairs audit/repairs
python scripts/build_balanced.py --sources balanced-out/sources.json --build-id rules-local-v2 --audit audit
python scripts/test_core.py --snapshot-dir balanced-out
python scripts/test_dns_core.py --mihomo mihomo
```

Windows 为涉及核心的命令传 `--mihomo <完整路径>`。规则回归使用完整产物，追踪出口连接本机 mock；另有真实核心 DNS 冷启动、父域/子域优先级、可信解析后的业务直连、主动 IP 解析及代理断线测试。消费端还验证遗漏 DNS 装配、排序持久化、哈希损坏、旧模板迁移及整体事务回滚。旧通道数量阈值、不可覆盖标签和发布后哈希核验继续保留。

下文记录 **v1 兼容通道**；其广告和旧分流顺序不属于 v2。

每日北京时间 **07:00**（UTC 23:00）同步 Loyalsoldier、ACL4SSR、MetaCubeX 和本仓库个人规则；提交个人规则、脚本或工作流也触发构建。每轮固定上游提交后从文本编译，使用 Mihomo v1.19.32。定时任务可能延迟，不保证每天有内容变化。

## 来源范围

| 来源 | 范围与处理 |
|---|---|
| Loyalsoldier/clash-rules | 原 13 个基础 MRS；applications 进程规则内嵌 |
| ACL4SSR/ACL4SSR | LocalAreaNetwork、UnBan、BanAD、ChinaDomain、ProxyGFWlist；排除最后一个表的全部 IP |
| MetaCubeX/meta-rules-dat | meta 分支；private、category-ads-all、geolocation-!cn、google、telegram、netflix、github、openai、youtube；cn 使用 geo-lite；IP 仅 private、cn、telegram |
| personal/direct.yaml、proxy.yaml | 全部个人规则；当前 Binance/Bybit 后缀直连，代理表为空 |

MetaCubeX 从 classical 文本读取，保留 domain-only 导出无法承载的正则。没有引入 Netflix IP、共享 CDN、云平台或 ASN 大范围表，也没有增加策略组。

## 新快照与旧兼容入口

新版用不可覆盖的 rules-<run-id>-<attempt> 标签发布，标签指向产物提交。新版全部 **rule-provider 文件为 MRS**。关键词、正则、进程和带选项的个人规则保存在 inline-rules.json，由订阅生成器随每日快照更新并内嵌到最终 YAML；JSON 不是 Mihomo rule-provider。

- build-manifest.json：构建/来源提交、核心版本、Fake-IP 池、provider 路径、文件大小与 SHA-256。
- inline-rules.json：个人直连/代理、本地、广告、applications、服务代理、通用代理、直连八个固定区段。
- sources.json、build-report.json、conflict-report.json、cidr-report.json：来源、重复覆盖、冲突与规范化。
- licenses：原始来源说明、CC BY-SA 4.0 文本及修改声明；见 [NOTICE](NOTICE.md)。
- 融合产物采用 GPLv3，并保留 ACL 原始授权；source-archive.tar.gz 保留可重编的原文、转换源码及全部许可。解压后在 builder 目录安装依赖及指定版本 Mihomo，使用 --offline 重编。
- GitHub Release：完整快照附件，远程文件与附件全部校验后才发布候选索引。

测试分支只更新 **candidates/candidate.json**；主分支验收后更新 **release/candidate.json**。旧 release/loyalsoldier/*.mrs、applications.yaml、个人 YAML、manifest.json、clash-snippet.yaml 保留基础语义和原格式，不混入新融合结果。

## 使用与更新

新版 provider 固定到同一个真实标签，例如：

    https://raw.githubusercontent.com/Forlooong/clash-rules-mrs/<build-id>/loyalsoldier/direct.mrs

常用服务为 services/services-proxy.mrs，ACL 补充在 acl4ssr，个人规则在 personal。实际 URL、格式与 behavior 由清单生成。

**完整订阅至少每 24 小时更新一次**，才能取得新快照。provider 的 interval=43200 只读取当前固定版本，不能自行切换构建。仅保存固定 MRS 地址而不更新完整订阅，将一直使用原版本。

顺序：必要本地引导 → 个人 DIRECT/代理 → private/lancidr → UnBan DIRECT → 广告 REJECT → applications/Apple → Google/常用服务/Telegram IP → 通用代理 → 直连 → gfw/greatfire/tld → cncidr → MATCH。只有一个手动“节点选择”组。

自动 IP 源排除 198.18.0.0/16；198.18.0.0/15 保留剩余 198.19.0.0/16。个人显式冲突报错。跨策略不破坏性删除；关键词、正则、进程和 IP 的复杂交集由回归补充，报告不宣称穷尽语义分析。

## 构建与测试

依赖 Python 3.12、PyYAML 6.0.2 与 Mihomo v1.19.32：

    python3 -m unittest discover -s tests -v
    python3 scripts/four_sources.py --build-id rules-local
    python3 scripts/test_core.py

构建实际编译全部 MRS，并以 Mihomo 加载完整配置。test_core 启动隔离核心，所有追踪出口连接本机 mock，采集 Rule/Payload/Chains；覆盖精确/后缀、个人例外、UnBan、广告、常用服务、Meta 正则及普通云主机负例，不访问真实节点或公共测试网站。

Windows 可传 --mihomo 指定官方 Windows 二进制。--offline 仅用于重编已经固定提交且验证原文哈希的缓存输入；CI 每轮重新读取上游。

首次四来源构建建立基线。后续来源/产物数量变化超过 20% 或文件超过旧版两倍时阻断发布；workflow_dispatch 的 allow_count_change 可为已复核的数量变动做单次放行。核心回归与哈希校验不能通过该开关绕过。

## 历史 v1 生成器适配与灰度

本节的 `/opt/proxy-stack` 命令仅适用于旧生成器，不是当前部署步骤。当前使用的 `sing-box/sbmanager` 通过上文 `sb rules update --channel v2` 与事务回滚管理规则和 DNS；本次本地修复与验证不会触发服务器迁移或发布。

runtime/snapshot.py 不含节点或令牌。deployment 中的 systemd service/timer 每 15 分钟验证候选，网络下载不在订阅请求内执行。临时目录整批通过才更新 staged.json；无 active.json 时仍使用旧模式。

1. 备份正式 subscription.py 与有效缓存，禁止提交公开仓库。
2. scripts/adapt_generator.py INPUT OUTPUT 对源码结构校验后生成适配版；生产结构改变则拒绝自动修改。安装 snapshot.py 到生成器同目录。
3. 正式定时器读 release 候选；灰度使用 candidates 候选和受保护测试入口。
4. Windows 使用独立自建测试配置，不改当前其他订阅。Android/iPhone 核实客户端版本及 MRS 支持后逐端验收。
5. 客户端验收通过后才 activate，默认不自动激活第一版。

服务器命令：

    python3 snapshot.py refresh --state /opt/proxy-stack/subgen/snapshot-state
    python3 snapshot.py refresh --state /opt/proxy-stack/subgen/snapshot-state --candidate-url https://raw.githubusercontent.com/Forlooong/clash-rules-mrs/candidates/candidate.json
    python3 snapshot.py verify --state /opt/proxy-stack/subgen/snapshot-state
    python3 snapshot.py activate --state /opt/proxy-stack/subgen/snapshot-state --build-id <verified-build>
    python3 snapshot.py disable --state /opt/proxy-stack/subgen/snapshot-state

activate 创建 activation.enabled；此后验证成功才自动切换。disable 暂停后续自动激活，保留当前版本。回滚时 disable，再指定旧 build-id activate 并再次 disable，客户端刷新完整订阅。缓存至少保留 30 天、最近五版及 active/staged；远端标签和 Release 不自动删除。

保持唯一节点组、节点参数、永久地址和流量统计。规则装配器不再顺带修改 TUN、嗅探或 DNS；这些设置由完整订阅模板与编译阶段负责。

构建通过不等于多端上线完成。真实 DNS 循环、代理出口、Netflix 播放和移动端兼容需记录实测；Cloudflare DNS ISP 本身不是泄漏证据。公开仓库永远不包含节点密钥、订阅令牌或私有生产配置。
