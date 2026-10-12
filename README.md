# 四来源 Mihomo MRS 规则

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

## 正式生成器适配与灰度

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

保持唯一节点组、节点参数、永久地址和流量统计。新版 TUN 仅关闭，嗅探跳过 CGNAT，删除相同解析器的冗余节点 policy；不添加 UnBan 全表 DNS policy，不修改 REALITY。

构建通过不等于多端上线完成。真实 DNS 循环、代理出口、Netflix 播放和移动端兼容需记录实测；Cloudflare DNS ISP 本身不是泄漏证据。公开仓库永远不包含节点密钥、订阅令牌或私有生产配置。
