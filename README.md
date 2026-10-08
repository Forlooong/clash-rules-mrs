# Forlooong Clash/Mihomo MRS 规则仓库

基于 [CRThu/clash-rules-mrs](https://github.com/CRThu/clash-rules-mrs) 的 Fork，继续转换 [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules)，同时在本仓库维护个人规则。请勿将包含节点密钥或订阅 Token 的完整 Clash YAML 提交到本公开仓库。

## 编辑私人规则

- [`personal/direct.yaml`](personal/direct.yaml)：强制直连。
- [`personal/proxy.yaml`](personal/proxy.yaml)：强制代理。

规则格式仍为 Mihomo classical YAML，例如：

```yaml
payload:
  - DOMAIN,login.example.com
  - DOMAIN-SUFFIX,example.org
  - IP-CIDR,203.0.113.0/24,no-resolve
```

个人规则从 [Forlooong/personal-clash-rules](https://github.com/Forlooong/personal-clash-rules) 初次迁移；此后应在新 Fork 编辑，不再自动读取旧仓库。当前两份源文件只含 `payload: ['']` 空占位符，**没有实际私人规则，因此不会发布空的私人 MRS**。

## 构建产物

- 13 个 Loyalsoldier MRS：`release/loyalsoldier/{reject,icloud,apple,google,proxy,direct,private,gfw,greatfire,tld-not-cn,telegramcidr,cncidr,lancidr}.mrs`；其中前 10 个为 `domain`，后 3 个为 `ipcidr`。
- 原版 `applications.txt` 是 classical 格式，发布为 `release/loyalsoldier/applications.yaml`，不能强行转为 MRS。
- 有对应规则才生成 `release/personal/personal-direct-domain.mrs`、`personal-direct-ipcidr.mrs`、`personal-proxy-domain.mrs`、`personal-proxy-ipcidr.mrs`。
- `no-resolve`、关键词、正则、进程、端口及其他不可无损转换的私人规则，保留为 `release/personal/personal-{direct,proxy}-classical.yaml`，不会静默丢弃。
- 构建还输出 `release/manifest.json`、`release/clash-snippet.yaml` 和 `release/personal/build-report.json`。

## 自动构建

[Sync and Build MRS Rulesets](https://github.com/Forlooong/clash-rules-mrs/actions/workflows/sync.yml) 每日 UTC 23:00（北京时间次日 07:00）计划运行；修改私人规则、构建脚本、测试或工作流时自动触发，也可以使用 Run workflow。GitHub 计划任务可能延迟。

Fork 默认可能停用 Actions：打开仓库 Actions 页面，确认并启用此工作流；若发布失败，检查 Actions 的 `GITHUB_TOKEN` 仓库 `contents: write` 权限及工作流日志。构建流程在测试通过后才更新 `release` 分支。

## Clash Mi/Mihomo 使用

首次 Actions 构建**成功发布后**，可获取实际生成的 [规则集配置片段](https://raw.githubusercontent.com/Forlooong/clash-rules-mrs/release/clash-snippet.yaml)。它只包括 rule-providers 和个人规则，不能当作完整订阅覆盖节点、DNS 与 proxy-groups。私人 direct 规则应在私人 proxy 和通用分流规则之前；现有策略组名称为 `节点选择`。

典型 Loyalsoldier 文件（仅当 release 分支完成发布才有效）：

```yaml
rule-providers:
  direct:
    type: http
    behavior: domain
    format: mrs
    url: https://raw.githubusercontent.com/Forlooong/clash-rules-mrs/release/loyalsoldier/direct.mrs
    path: ./ruleset/forlooong/loyalsoldier/direct.mrs
    interval: 43200
    proxy: 节点选择
```

`interval: 43200` 控制客户端每 12 小时检查规则更新，与 GitHub Actions 的每日构建以及完整 Clash 订阅刷新相互独立。MRS 通常降低规则解析开销，但不能保证彻底消除 iOS VPN 断开。GitHub Raw 与第三方 CDN 可能有不同缓存和网络可达性。

## 开发测试

使用 Python 3.12、PyYAML 6.0.2，以及 Mihomo v1.19.32。执行 `python3 -m unittest discover -s tests -v`，再执行 `bash scripts/build.sh` 构建；CI 还以 `mihomo -t` 校验生成的本地 file rule-providers。

如果合并上游 Fork 更新，需检查上游是否改动 `.github/workflows/sync.yml` 和 `scripts/build.sh`，不要覆盖私人转换功能。原项目与规则贡献者版权归各自作者。
