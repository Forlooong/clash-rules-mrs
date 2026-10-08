#!/usr/bin/env bash
set -euo pipefail
BASE_URL="$(printenv BASE_URL || true)"
if [ -z "$BASE_URL" ]; then BASE_URL="https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release"; fi
mkdir -p raw/loyalsoldier out/loyalsoldier
download() {
  curl -fsSL --retry 3 "$BASE_URL/$1.txt" -o "raw/loyalsoldier/$1.txt"
  test -s "raw/loyalsoldier/$1.txt"
}
for name in reject icloud apple google proxy direct private gfw greatfire tld-not-cn; do
  download "$name"
  mihomo convert-ruleset domain yaml "raw/loyalsoldier/$name.txt" "out/loyalsoldier/$name.mrs"
  test -s "out/loyalsoldier/$name.mrs"
done
for name in telegramcidr cncidr lancidr; do
  download "$name"
  mihomo convert-ruleset ipcidr yaml "raw/loyalsoldier/$name.txt" "out/loyalsoldier/$name.mrs"
  test -s "out/loyalsoldier/$name.mrs"
done
download applications
cp raw/loyalsoldier/applications.txt out/loyalsoldier/applications.yaml
python3 scripts/build-personal.py
python3 scripts/generate-config.py
