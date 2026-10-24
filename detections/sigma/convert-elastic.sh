#!/bin/bash
# Convert lab Sigma rules to Elastic detection-rule JSON (array on stdout) for rules-add.sh on Unraid.
# Requires: uv tool install sigma-cli --with pysigma-backend-elasticsearch
# Usage: ./convert-elastic.sh [dir]   (default rules/lab; one rule per .yml, rule_id from the file stem)
set -euo pipefail
cd "$(dirname "$0")"
D=${1:-rules/lab}
# Collect first: one failing file must fail the batch with nothing on stdout (a partial array would be pushed).
out=$(for f in "$D"/*.yml; do
  [ -e "$f" ] || continue
  if grep -qE '^[[:space:]]*product:[[:space:]]*windows' "$f"; then p=(-p ecs_windows)
  elif grep -qE '^[[:space:]]*product:[[:space:]]*linux' "$f"; then p=(-p pipelines/ecs_linux.yml)
  else p=(--without-pipeline); fi
  cat=$(sed -nE 's/^[[:space:]]*category:[[:space:]]*([a-z_]+).*/\1/p' "$f" | head -1)
  sigma convert -t eql "${p[@]}" -f siem_rule_ndjson "$f" |
    jq -c --arg id "homelab-lab-$(basename "$f" .yml)" --arg cat "$cat" '
      . + {rule_id: $id, index: ["logs-*-lab"]}
      | .tags = ((.tags // []) + ["homelab", "lab"] | map(select(test("autoblock|notify"; "i") | not)) | unique)
      | if $cat == "process_creation" and (.query | startswith("any where "))
        then .query = "process where event.type == \"start\" and (" + (.query | ltrimstr("any where ")) + ")" else . end
      | del(.id, .from, .interval, .meta, .license)' || exit 1   # timing + licence from rules-add.sh (5m / now-6m overlap); set -e is off inside $()
done)
jq -s . <<<"$out"
