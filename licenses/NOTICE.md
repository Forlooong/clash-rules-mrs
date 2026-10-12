# Source attribution, licenses and modifications

Public rule inputs:

- Loyalsoldier/clash-rules, release branch; GPLv3 repository.
- ACL4SSR/ACL4SSR, master branch; CC BY-SA 4.0.
- MetaCubeX/meta-rules-dat, meta branch; GPLv3 repository.
- Forlooong/clash-rules-mrs personal/direct.yaml and personal/proxy.yaml.

Combined adapted collections and the new build/runtime code are distributed
under GPLv3. ACL-only collections (unban-domain and direct-ipcidr) retain
CC BY-SA 4.0. Original ACL material retains attribution, CC terms and
modification notices. CC BY-SA 4.0 permits one-way compatibility with GPLv3
for adaptations: https://creativecommons.org/compatible-licenses/
GPL material is not relabeled as CC BY-SA.

Snapshots retain both GPL license texts, original READMEs and the CC legal
text. MetaCubeX's dependency attributions remain in its README. Source and
notice commits are recorded independently. source-archive.tar.gz preserves
corresponding text inputs, builder/runtime source and notices even if an
upstream release branch is rewritten.

Changes: normalization, equivalent same-policy deduplication, Fake-IP
subtraction, selected-source merging, MRS recompilation and classical
predicate extraction into inline-rules.json. ProxyGFWlist IPs are excluded.
Credentials and private subscriptions are never part of published source.
