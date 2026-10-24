#!/bin/bash
# Simulate logs-pfsense.log@custom against test-dns-pipeline.json; print PASS/FAIL per case.
cd /boot/config/compose/elastic
r=$(bash esq.sh POST "/_ingest/pipeline/logs-pfsense.log@custom/_simulate" @/boot/config/compose/elastic/pipelines/test-dns-pipeline.json)
c() { v=$(jq -r --arg i "$1" ".docs[] | select(.doc._id==\$i) | .doc._source | $2" <<<"$r"); [ "$v" = "$3" ] && echo "PASS $1 $2" || echo "FAIL $1 $2 = $v (want $3)"; }
c servfail '.dns.response_code' SERVFAIL;   c servfail '.labels.dns_answered_locally // "none"' none
c dnsbl '.dns.response_code' NOERROR;       c dnsbl '.labels.dns_answered_locally' true
c cached '.labels.dns_answered_locally // "none"' none
c base32 '.labels.dns_base32' true;         c base32 '.labels.dns_base64 // "none"' none;  c base32 '.labels.dns_long_label // "none"' none
c base64 '.labels.dns_base64' true;         c base64 '.labels.dns_base32 // "none"' none
c long '.labels.dns_long_label' true;       c long '.labels.dns_base64 // "none"' none
c cymru '.labels.dns_long_label // "none"' none
c filterlog_untouched '.labels // "none"' none;  c filterlog_untouched '.error // "none"' none
