# Sigma detection library — sol.example.com

Portable detection rules in [Sigma 2.x](https://github.com/SigmaHQ/sigma) format.
These mirror the **flat-match subset** of the homelab's Wazuh ruleset
(`/var/ossec/etc/rules/local_rules.xml`) — single-event, single-field signature
detections that round-trip cleanly between Sigma and any backend (Wazuh, Splunk,
Elastic, Loki, OpenSearch, QRadar, Sentinel).

## Why dual-format

Wazuh is the runtime engine for production. Sigma is the portable form, written
once and convertible to any SIEM the next employer happens to use. **Roughly 30
of the homelab's 80 custom rules** are flat-match and round-trip cleanly. The
other 50 use Wazuh-specific features (`<if_sid>` chains, `<frequency>` aggregations,
`<prematch>` decoder gating) that Sigma can't express — those stay native and
aren't represented here.

This is the **honest** approach: don't pretend the lossy auto-converter works,
do hand-write the portable subset, document the tradeoff.

## Layout

- `rules/` — one Sigma rule per file, named by ATT&CK technique
- `lint.sh` — runs `sigma check` against every rule
- `convert-opensearch.sh` — converts to OpenSearch Lucene queries (works against
  the `wazuh-alerts-*` indices via Grafana datasource or Wazuh dashboard)
- `convert-loki.sh` — converts to Loki LogQL (works against the existing Loki)

## Running locally

```sh
uv tool install --with pysigma-backend-opensearch --with pysigma-backend-loki sigma-cli
./lint.sh
./convert-opensearch.sh > opensearch-queries.txt
```

## Coverage map

| Sigma rule | Mirrors Wazuh rule | MITRE |
|---|---|---|
| `crowdsec_ti_hit_srcip.yml` | 100040 / 100250 | T1071 |
| `abusech_ti_hit_srcip.yml` | 100045 / 100251 | T1071 |
| `netflow_outbound_c2.yml` | 100048 / 100056 | T1071 |
| `cryptomining_beacon_port.yml` | 100049 | T1496 |
| `suricata_active_exploit.yml` | 100001 | T1190 |
| `dns_oversized_txt.yml` | 100306 | T1071.004, T1572 |
| `dns_dga_servfail_burst.yml` | 100305 | T1568.002 |
| `dns_anonymity_tld.yml` | 100307 | T1090.003 |
| `web_brute_force_lan_external.yml` | 100126 | T1110 |
| `opencanary_lan_probe.yml` | 100702 | T1046 |
| `yara_malware_match.yml` | 100801 | T1059, T1204.002 |
| `zeek_self_signed_cert.yml` | 100604 | T1573.002 |

## Status

This is a **parallel export**, not the runtime ruleset. Updates should be
synchronised manually when adding new flat-match detections to `local_rules.xml`.
The test loop is: write Wazuh rule → if flat-match, mirror to Sigma → run
`./lint.sh` to validate → optionally `./convert-opensearch.sh` to confirm the
generated query matches what Wazuh would alert on.

## Lab rules → Elastic (2026-10-16)

`rules/lab/` holds detections written from the detection lab (spec
`docs/superpowers/specs/2026-10-16-detection-lab-design.md`). Unlike the parallel
export above, these ARE the source: `./convert-elastic.sh` emits Elastic rule JSON
(`rule_id homelab-lab-<file stem>`, tags `homelab`+`lab`, index `logs-*-lab`, any
`autoblock`/`notify` tag stripped) and the result is pushed with

    rules=$(./convert-elastic.sh) && ssh unraid 'cd /boot/config/compose/elastic && bash rules-add.sh && bash rules-sync.sh' <<<"$rules"

(The `&&` matters: a failed conversion exits non-zero with nothing on stdout, and must not reach Unraid.)
Process-creation rules are narrowed to `process where event.type == "start"`, so one execution raises one alert.

Windows rules use the `ecs_windows` pipeline, Linux rules the vendored `pipelines/ecs_linux.yml`; others convert without one. Rules
Sigma cannot express (sequences, thresholds) stay native EQL in `rules/` on Unraid,
with the Sigma file kept here for portability. Self-test: `./test-convert-elastic.sh`.
