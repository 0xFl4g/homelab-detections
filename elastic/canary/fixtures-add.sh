#!/bin/bash
# Merge canary fixtures (JSON array on stdin) into fixtures.json. Same key (name, else rule_id) replaces.
set -eu
F=/boot/config/compose/elastic/canary/fixtures.json
new=$(cat)
jq --argjson n "$new" '[.[] | (.name // .rule_id) as $k | select(($n | map(.name // .rule_id) | index($k)) | not)] + $n' "$F" > "$F.tmp"
mv "$F.tmp" "$F"
jq length "$F"
