#!/bin/bash
# Push every rules/*.json to Kibana (create or overwrite). Exit 1 on any error.
set -eu
cd /boot/config/compose/elastic
set -a; . ./.env; set +a
jq -c . rules/*.json > /tmp/rules.ndjson
docker cp /tmp/rules.ndjson kibana:/tmp/rules.ndjson && rm /tmp/rules.ndjson
# credentials via stdin, never argv (docker exec command lines are logged)
out=$(printf '%s\n' "elastic:$ELASTIC_PASSWORD" | docker exec -i kibana sh -c 'IFS= read -r U; exec curl -s -u "$U" -H "kbn-xsrf: true" \
  -X POST "http://localhost:5601/api/detection_engine/rules/_import?overwrite=true" -F file=@/tmp/rules.ndjson')
docker exec -u 0 kibana rm -f /tmp/rules.ndjson
echo "$out" | jq -c '{success, success_count, errors: [.errors[]? | {rule_id, msg: .error.message}]}'
[ "$(echo "$out" | jq -r .success)" = "true" ]
