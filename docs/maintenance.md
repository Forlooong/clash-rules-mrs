# 构建、集成与维护

[返回项目说明](../README.md)

本文面向维护规则构建、订阅生成器和服务器更新流程的使用者。客户端导入订阅、选择节点和添加个人域名规则见项目首页。

## 订阅生成器集成

v2 通过 `schema_version=2`、`policy_version=balanced-v2` 标识。正式入口为 [release/candidate-v2.json](https://raw.githubusercontent.com/Forlooong/clash-rules-mrs/release/candidate-v2.json)，预览入口为 [candidates/candidate-v2.json](https://raw.githubusercontent.com/Forlooong/clash-rules-mrs/candidates/candidate-v2.json)。索引指向不可覆盖的 `rules-<run-id>-<attempt>-v2` 标签及清单 SHA-256。

生成器读取 `build-manifest.json` 和 `inline-rules.json`，校验该版本的全部运行文件，再生成完整订阅。客户端获取最终 YAML 和其中引用的 MRS；完整审计附件另行保存，不随订阅下载。

规则与 DNS 必须分别装配：

1. 调用 [runtime/snapshot.py](../runtime/snapshot.py) 中的 `assemble` 生成 `rules` 和 MRS provider。
2. 调用 [runtime/dns.py](../runtime/dns.py) 中的 `assemble_dns` 生成 DNS 策略与内嵌 classical provider。
3. 以 `sort_keys=False` 输出 YAML，保留 DNS 匹配顺序，并验证最终完整配置。

当前集成方为 [sing-box/sbmanager](https://github.com/Forlooong/sing-box)，其中的内置模块需要与本仓库同步。规则装配器本身不修改节点、TUN 或嗅探设置。

DNS 编译会识别旧版自动策略，并保留可证明不冲突的自定义项。自定义域名与自动策略的交集依据当前版本的域名索引检查；无法证明兼容的通配符、后缀或复杂正则会阻止激活，旧配置继续使用。进程、端口和个人 IP 规则只能决定业务路由，不能完整表达 DNS 意图。

## 服务器更新与回滚

以下命令适用于已安装的 `sing-box/sbmanager`：

```sh
sb rules status
sb rules update --channel v2
sb check
```

首次选择 v2 时，通道、规则版本、DNS、模板和完整订阅通过同一事务切换。以后执行 `sb rules update` 沿用当前通道；定时任务也沿用该通道。版本下载或验证失败时保留原配置。

每次成功变更返回 `transaction` ID。需要恢复历史状态时，先暂停自动更新，并等待正在运行的 `sb-rules.service` 结束，再检查和回滚对应事务：

```sh
systemctl stop sb-rules.timer
sb transaction list
sb transaction rollback <transaction-id>
sb check
```

使用要撤销的那次操作返回的准确 ID。存在较新的普通变更事务时，须按事务依赖倒序处理。`sb rules update --channel v1` 是切换到 v1 的当前候选版本，不等同于恢复迁移前的历史状态。

规则事务不会替管理员恢复手动暂停的 timer。确认配置健康、候选版本也适合继续更新后，执行 `systemctl start sb-rules.timer`；若只是回滚到同一通道的旧版本，应先修复候选，否则自动更新可能再次启用刚撤销的构建。

## 全量审计与发布门槛

固定三个生产分支提交，下载完整归档，重建 Git blob/tree SHA 核对目录完整性。逐条读取规范文本，包括 ASN 和其他客户端格式；为不支持的语法明确记录排除理由，未知语法阻止发布。逐个比较文本、YAML、rule 和 MRS 的可表达投影；IP 比较覆盖区间，域名区分精确、后缀、仅子域与正则。MRS 解码器用固定核心编译/反编译夹具交叉核对。复杂正则/进程/端口交集无法证明时标为未穷尽，实际配置回归补充。

生成器消费的运行产物包括 MRS、内联谓词及小型元数据，总上限为 8 MiB；客户端读取生成后的完整订阅和其中引用的 MRS。完整清单、逐条原文、风险、排除、投影报告和对应源码通过独立 `audit-<build-id>.tar.gz` Release 附件交付；运行清单绑定审计 manifest 的 SHA-256。缺文件、未知语法、投影不一致、必需集合为空或核心行为回归失败均阻止候选发布。

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

## 兼容入口与许可

v1 的 `candidate.json`、旧版基础 MRS 和个人 YAML 接口继续保留。历史生成器的接入方式见 [v1 兼容说明](legacy-v1.md)。

来源归属、许可与修改声明见 [NOTICE.md](../NOTICE.md) 和 [LICENSE](../LICENSE)。v2 对应的原文、构建源码及许可材料位于独立审计附件中；`build-manifest.json` 绑定该附件内审计清单的哈希。
