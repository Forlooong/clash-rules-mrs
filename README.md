# Clash / Mihomo 分流规则

面向日常使用的 Mihomo 规则项目：**国内直连、其余代理、个人例外优先，默认关闭广告拦截**。域名和 IP 规则编译为 MRS，由配套的 [sing-box 订阅生成器](https://github.com/Forlooong/sing-box) 生成可导入客户端的完整配置。

本文说明当前 **v2** 方案。使用系统代理接入，默认关闭 TUN；代理流量统一交给一个手动“节点选择”组。

## 设计层级

与配套生成器组合后的完整配置分为六层：

| 层级 | 配置段 | 职责 |
| :--- | :--- | :--- |
| 节点层 | `proxies` | 由订阅生成器导出已启用、兼容 Mihomo 的节点配置 |
| 内核层 | 通用配置、`profile`、`tun` | 本地端口、并发、选择记忆；默认规则模式、关闭 TUN |
| 解析层 | `dns` | Fake-IP、国内外 DoH 分流、节点域名的独立解析 |
| 策略层 | `proxy-groups` | 唯一的“节点选择”组，手动选择代理出口 |
| 规则源 | `rule-providers` | 加载 MRS；DNS 所需的辅助匹配以内嵌 classical 规则提供 |
| 执行层 | `rules` | 从上到下匹配，决定直连或使用代理节点 |

节点由生成器管理，本仓库负责规则构建和规则、DNS 的装配。正则等不能无损转换为 MRS 的条件会保留在最终配置中。

## 默认链路

```text
应用请求 → 本机 Mihomo → rules 从上到下匹配
                         ├─ DIRECT → 直连目标服务
                         └─ 节点选择 → 当前选中的节点 → 目标服务
```

“节点选择”使用 `select`，默认模板开启选择记忆。在客户端切换这个组即可更换代理线路；所有命中代理规则的流量共用当前节点。未命中前面规则的请求，最终由 `MATCH` 交给这个组。

组内只包含实际节点，不加入 DIRECT 自动回退。代理节点不可用时，需要切换到另一个可用节点。

## 分流规则

规则按以下优先级排列，**首次命中即决定出口**：

| 顺序 | 匹配内容 | 出口 |
| :--- | :--- | :--- |
| 1 | 必要回环：`localhost`、`127.0.0.0/8`、`::1/128` | DIRECT |
| 2 | 个人直连规则 | DIRECT |
| 3 | 个人代理规则 | 节点选择 |
| 4 | 私网与局域网 | DIRECT |
| 5 | Google、YouTube、Telegram、Netflix、GitHub、OpenAI | 节点选择 |
| 6 | Telegram IP | 节点选择 |
| 7 | 国内域名 | DIRECT |
| 8 | 国内 IP | DIRECT |
| 9 | `MATCH`：其余请求 | 节点选择 |

国内域名以 MetaCubeX 的 `geolocation-cn` 为主。已识别的共享云/CDN 整根后缀会被[过滤](scripts/shared-platform-roots.json)，保留明确的业务子域；国内 IP 兜底仍然生效。国内 IP 规则允许主动解析，私网和 Telegram IP 规则使用 `no-resolve`。

默认规则不加载广告表、上游整表进程直连或整表 UnBan。日常遇到个别站点需要调整时，优先使用个人规则。

## DNS 如何分流

**业务连接走哪里，与域名向谁查询，是两个独立决定。** 默认使用 Fake-IP，实际解析按以下策略进行：

| 查询对象 | 解析方式 | DNS 查询出口 |
| :--- | :--- | :--- |
| 个人规则中的域名，包括直连例外 | Cloudflare / Google DoH | 节点选择 |
| 明确海外服务、未分类域名 | Cloudflare / Google DoH | 节点选择 |
| 其余已知国内域名 | 国内 DoH | DIRECT |
| `localhost`、普通私网与局域网名称 | 系统解析 | 跟随系统设置 |
| 代理节点域名、解析器引导 | 独立的国内 DoH | DIRECT |

例如，个人规则中的币安采用以下路径：

```text
解析 binance.com → 节点选择 → Cloudflare / Google DoH
访问 binance.com → DIRECT → 目标服务器
```

`direct-nameserver` 同样使用代理 DoH，并通过 `direct-nameserver-follow-policy` 让国内域名遵循国内解析策略。代理不可用且没有有效 DNS 缓存时，相关解析会失败，不会自动退回国内 DNS。

系统代理的覆盖范围取决于应用是否接入 Mihomo；浏览器独立 DNS、绕过代理的应用等需要另行配置，不能据此承诺全设备零泄漏。直连站点即使解析正确，也可能在 TCP 或 TLS 阶段失败，添加直连规则不等于保证网页可用。

## 使用与更新

### 客户端

1. 使用支持 MRS 的 Mihomo 客户端，导入生成器提供的 **Clash / Mihomo YAML 完整订阅**。本项目以 Mihomo `v1.19.32` 构建和验证。
2. 在客户端选择“规则”模式，启用系统代理，保持 TUN 关闭。系统代理开关由客户端管理。
3. 在“节点选择”中选一个可用节点。
4. 开启完整订阅的自动更新，建议每 12 小时刷新一次。

已有订阅继续使用原地址。`candidate-v2.json` 是供生成器读取的版本索引，不能作为客户端订阅导入。

### 配套生成器

已升级到支持 v2 的 `sing-box/sbmanager` 的服务器，可用以下命令启用 v2 并查看状态：

```sh
sb rules update --channel v2
sb rules status
```

此后 `sb rules update` 沿用当前通道。更新分为三个环节：

| 环节 | 更新方式 |
| :--- | :--- |
| 仓库构建 | 计划每天北京时间 07:00 同步上游；提交个人规则也会触发构建，任务可能延迟 |
| 服务器订阅 | 定时任务约每 15 分钟检查候选，通过校验后更新完整订阅 |
| 客户端 | 刷新完整订阅，取得新的规则版本和 DNS 配置 |

每份订阅中的 MRS URL 固定到同一个发布版本。provider 的 12 小时刷新只更新该固定地址；**获取新版本需要刷新完整订阅**。服务器更新失败时继续使用原配置，回滚方法见[维护指南](docs/maintenance.md#服务器更新与回滚)。

## 添加个人规则

| 文件 | 用途 |
| :--- | :--- |
| [personal/direct.yaml](personal/direct.yaml) | 强制业务直连 |
| [personal/proxy.yaml](personal/proxy.yaml) | 强制使用“节点选择” |

只填写匹配条件，出口由文件决定。下面是向直连文件追加规则的格式示例，修改时保留已有条目：

```yaml
payload:
  - DOMAIN-SUFFIX,example.com
  - DOMAIN,api.example.net
```

`DOMAIN-SUFFIX` 匹配根域名及所有子域名，`DOMAIN` 只匹配指定域名。不要填写 `https://`、URL 路径，或在末尾再加 `DIRECT`、`节点选择`。代理文件使用相同格式；没有条目时保留现有的空字符串占位。

当前个人直连包含 `binance.com`、`bybit-global.com`、`bybit.com`。这些后缀覆盖它们的子域名，不代表覆盖平台使用的所有第三方服务。

**个人直连整段先于个人代理。** 如果把 `example.com` 放进直连后缀规则，再把 `api.example.com` 放进代理规则，子域仍会直连。避免两份文件中的范围重叠；文件内条目的书写顺序也不等同于最终跨规则类型的匹配顺序。

提交修改后，等待构建和服务器更新完成，再刷新客户端完整订阅。只编辑本地文件或客户端缓存中的 MRS，不会更新仓库发布的规则。

## 规则来源

| 来源 | 本项目的用法 |
| :--- | :--- |
| [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) | 主要分类来源：国内域名、私网、CN IP 和明确海外服务 |
| [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) | 全量审计与分类参考，v2 不整表合并 |
| [ACL4SSR/ACL4SSR](https://github.com/ACL4SSR/ACL4SSR) | 全量审计与规则组织参考，v2 不整表合并 |
| 本仓库个人规则 | 表达个人直连、代理例外，优先于上游分类 |

每次构建固定上游提交，检查规则内容与派生格式，修复已识别的 MRS 生成错误后重新验证。构建、发布和订阅生成器通过 SHA-256 校验对应产物；完整审计与源码作为独立 Release 附件提供。

需要进一步了解时，可查看[构建、集成与维护](docs/maintenance.md)、[v1 兼容与历史生成器](docs/legacy-v1.md)、[发布版本](https://github.com/Forlooong/clash-rules-mrs/releases)及[来源与许可声明](NOTICE.md)。
