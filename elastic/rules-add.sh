#!/bin/bash
# Write detection rules (JSON array on stdin) to rules/<rule_id>.json with homelab defaults; push with rules-sync.sh.
set -eu
cd /boot/config/compose/elastic
jq -c '.[] | {enabled: true, actions: [], version: 1, author: ["homelab"], license: "internal", interval: "5m", from: "now-6m"} + .' \
| while IFS= read -r r; do
    id=$(jq -r .rule_id <<<"$r"); jq . <<<"$r" > "rules/$id.json"; echo "rules/$id.json"
  done
