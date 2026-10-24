#!/bin/bash
# Daily detection canary: inject TEST-NET-1 events per fixture, then
#  - "expect" absent/"alert": the rule must alert for that fixture's IP (polled up to 15 min)
#  - "expect":"none": the rule must NOT alert for that IP (checked after >= 11 min, two rule cycles)
set -u
# Crash reporting to Sentry: a non-zero exit BEFORE the last line is a script failure. Fixture
# failures exit at the end ([ $fail = 0 ]) and stay with Grafana, so they are not reported here.
canary_done=0
trap 'rc=$?; if [ $rc != 0 ] && [ $canary_done = 0 ]; then bash /mnt/cache/appdata/sentry/sentry-report.sh /mnt/cache/appdata/sentry/secrets/homelab-scripts.dsn "elastic-canary exited $rc before finishing" elastic-canary; fi' EXIT
D=/boot/config/compose/elastic
OUT=${CANARY_OUT:-/mnt/cache/appdata/node-exporter/textfile/elastic-canary.prom}
FX=${CANARY_FIXTURES:-$D/canary/fixtures.json}
set -a; . $D/.env; set +a
# es -X METHOD https://localhost:9200/PATH [-d BODY] -> esq.sh (credentials/body via stdin, never argv)
es() { local m=$2 u=${3#https://localhost:9200} b=${5-}; bash $D/esq.sh "$m" "$u" "$b"; }
alerts_for() {  # rule_id ip -> count of alerts since START (IP fields, threshold terms, or host marker canary-<ip>)
  es -X POST "https://localhost:9200/.alerts-security.alerts-default/_count" -d "{\"query\":{\"bool\":{\"filter\":[
    {\"term\":{\"kibana.alert.rule.rule_id\":\"$1\"}},
    {\"range\":{\"@timestamp\":{\"gte\":\"$START\"}}},
    {\"query_string\":{\"query\":\"source.ip:\\\"$2\\\" OR destination.ip:\\\"$2\\\" OR kibana.alert.threshold_result.terms.value:(\\\"$2\\\" OR \\\"canary-$2\\\") OR host.name:\\\"canary-$2\\\"\"}}]}}}" | jq -r '.count // 0'
}
START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
# Per-run locally-administered MAC for new_terms fixtures (a fixed value would only alert once per history window).
s=$(date +%s); RUNMAC=$(printf '02:ca:%02x:%02x:%02x:%02x' $(( s >> 24 & 255 )) $(( s >> 16 & 255 )) $(( s >> 8 & 255 )) $(( s & 255 )))
n=$(jq length $FX)
declare -A IPOF RULEOF EXPECT
for i in $(seq 0 $((n-1))); do
  f=$(jq -c ".[$i]" $FX)
  rid=$(jq -r .rule_id <<<"$f"); key=$(jq -r '.name // .rule_id' <<<"$f")
  stream=$(jq -r .stream <<<"$f"); cnt=$(jq -r .count <<<"$f")
  ip=$(jq -r '.fixed_ip // empty' <<<"$f"); [ -z "$ip" ] && ip="192.0.2.$(( 10 + i ))"   # unique per fixture, TEST-NET-1
  IPOF[$key]=$ip; RULEOF[$key]=$rid; EXPECT[$key]=$(jq -r '.expect // "alert"' <<<"$f")
  pl=$(jq -r '.pipeline // empty' <<<"$f")
  for k in $(seq 1 "$cnt"); do
    while IFS= read -r tpl; do
      now=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
      doc=$(jq -c --arg ip "$ip" --arg mac "$RUNMAC" --arg ts "$now" --arg sts "$(date '+%b %e %H:%M:%S')" --arg iso "$(date +%Y-%m-%dT%H:%M:%S.000000%z)" '
        tostring | gsub("__IP__";$ip) | gsub("__MAC__";$mac) | gsub("__SYSLOGTS__";$sts) | gsub("__ISOTS__";$iso) | fromjson
        | . + {"@timestamp":$ts, "tags":((.tags // []) + ["canary"])}' <<<"$tpl")
      es -X POST "https://localhost:9200/$stream/_doc?op_type=create${pl:+&pipeline=$pl}" -d "$doc" >/dev/null
    done < <(jq -c 'if .docs then .docs[] else .doc end' <<<"$f")
  done
done
INJECTED=$(date +%s)
declare -A OK
deadline=$(( INJECTED + 900 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  pending=0
  for key in "${!IPOF[@]}"; do
    [ "${EXPECT[$key]}" = none ] && continue
    [ "${OK[$key]:-0}" = 1 ] && continue
    if [ "$(alerts_for "${RULEOF[$key]}" "${IPOF[$key]}")" -gt 0 ]; then OK[$key]=1; else pending=1; fi
  done
  [ $pending = 0 ] && break
  sleep 30
done
wait_until=$(( INJECTED + 660 )); now=$(date +%s); [ "$now" -lt "$wait_until" ] && sleep $(( wait_until - now ))
for key in "${!IPOF[@]}"; do
  [ "${EXPECT[$key]}" = none ] || continue
  [ "$(alerts_for "${RULEOF[$key]}" "${IPOF[$key]}")" = 0 ] && OK[$key]=1
done
pass=0; fail=0; lines=""
for key in "${!IPOF[@]}"; do
  if [ "${OK[$key]:-0}" = 1 ]; then pass=$((pass+1)); v=1; else fail=$((fail+1)); v=0; logger -t elastic-canary "FAIL $key (${RULEOF[$key]}, expect=${EXPECT[$key]}) ip=${IPOF[$key]}"; fi
  lines+="elastic_canary_detection{rule=\"$key\"} $v"$'\n'
done
{
  echo "# HELP elastic_canary_pass_total Elastic detection fixtures that behaved as expected (alert / no alert)"
  echo "# TYPE elastic_canary_pass_total gauge"; echo "elastic_canary_pass_total $pass"
  echo "# TYPE elastic_canary_fail_total gauge"; echo "elastic_canary_fail_total $fail"
  echo "# TYPE elastic_canary_last_run_timestamp_seconds gauge"; echo "elastic_canary_last_run_timestamp_seconds $(date +%s)"
  echo "# TYPE elastic_canary_detection gauge"; printf "%s" "$lines"
} > $OUT.tmp && mv $OUT.tmp $OUT
logger -t elastic-canary "pass=$pass fail=$fail"
# Close every open canary alert (this run's and stragglers) so fixtures stay out of entity risk scores and
# open-alert counts. Markers: tag canary, host canary-<ip>, or a TEST-NET-1 address (threshold alerts lose the tag).
bash $D/kbq.sh POST /api/detection_engine/signals/status '{"status":"closed","query":{"bool":{"filter":[{"term":{"kibana.alert.workflow_status":"open"}}],"should":[{"term":{"tags":"canary"}},{"prefix":{"host.name":"canary-"}},{"term":{"source.ip":"192.0.2.0/24"}},{"term":{"destination.ip":"192.0.2.0/24"}}],"minimum_should_match":1}}}' \
  | jq -r '"closed canary alerts: \(.updated // .)"' | logger -t elastic-canary
# Entity store v2 has no document filter, so canary-<ip> hosts become host entities. Extraction is incremental
# (each run starts at the previous one's end) and has seen this run's docs by now, so deleted entities stay gone.
del=0
for id in $(es -X POST "https://localhost:9200/.entities.v2.latest.security_default-*/_search?size=500&filter_path=hits.hits._source.entity.id" -d '{"_source":["entity.id"],"query":{"prefix":{"entity.id":"host:canary-"}}}' | jq -r '.hits.hits[]?._source.entity.id'); do
  bash $D/kbq.sh DELETE /api/security/entity_store/entities/ "{\"entityId\":\"$id\"}" >/dev/null && del=$((del+1))
done
logger -t elastic-canary "deleted canary host entities: $del"
# Daily entity-history indices are created with 1 replica (managed template, no @custom hook); single node -> 0.
es -X PUT "https://localhost:9200/.entities.v2.history.security_default.*/_settings?expand_wildcards=all" -d '{"index":{"number_of_replicas":0}}' >/dev/null
canary_done=1
[ $fail = 0 ]
