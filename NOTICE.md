# Rule source attribution and modifications

Public rule data is derived from:

- Loyalsoldier/clash-rules (release branch), including its upstream attribution.
- ACL4SSR/ACL4SSR (master branch), CC BY-SA 4.0.
- MetaCubeX/meta-rules-dat (meta branch), with source attribution in master README.
- Forlooong/clash-rules-mrs personal/direct.yaml and personal/proxy.yaml.

ACL4SSR-derived rule data, including the merged domain/IP collections, is
distributed under CC BY-SA 4.0 with attribution and modification notices.
This does not relicense unrelated upstream materials or the entire repository.
Upstream READMEs and the CC BY-SA legal text accompany every snapshot.
MetaCubeX aggregates other sources; their attribution and applicable terms
remain in its README. Build manifests record immutable source commits.

Changes: parsing, normalization, equivalent same-policy deduplication,
Fake-IP range subtraction, selected-source merging, MRS recompilation,
classical predicate extraction into inline-rules.json. ProxyGFWlist IP
rules are intentionally excluded. Credentials are never part of rule data.
