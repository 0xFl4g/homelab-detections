# Sigma detection library — sol.example.com

Portable detection rules in [Sigma 2.x](https://github.com/SigmaHQ/sigma) format. The production engine is
Elastic Security (rules-as-code on Unraid, `elastic/rules/` in the public export). Sigma is the portable form:
written once and convertible to whatever SIEM is in front of me.

## Two kinds of rule here

- **`rules/lab/`: the source.** Written from the detection lab and converted to Elastic with
  `./convert-elastic.sh` (below). What runs in Elastic is generated from these files.
- **`rules/*.yml`: portable copies.** Hand-written in 2026-05, when Wazuh was the SIEM, for the flat-match
  subset of the custom ruleset: single-event, single-field signatures that round-trip cleanly between
  backends. Rules that need sequences, thresholds or correlation stay native and aren't represented. Wazuh
  was replaced by Elastic on 2026-09-29; where the detection was ported, the Elastic rule is listed below.

Not pretending a lossy auto-converter works: hand-write the portable subset and document the tradeoff.

## Layout

- `rules/` — one Sigma rule per file; `rules/lab/` converts to Elastic
- `pipelines/ecs_linux.yml` — field mapping for Linux lab rules
- `lint.sh` — `sigma check` plus `sigma analyze` over `rules/`
- `convert-elastic.sh`, `test-convert-elastic.sh` — Sigma → Elastic rule JSON and its self-test
- `convert-opensearch.sh`, `convert-loki.sh` — legacy converters from the Wazuh/Loki era (both backends are
  retired; kept as portability examples)

## Running locally

```sh
uv tool install sigma-cli --with pysigma-backend-elasticsearch
sigma check --fail-on-issues rules/
./test-convert-elastic.sh
```

## Coverage map (portable copies)

| Sigma rule | Original Wazuh rule | Elastic rule today | MITRE |
|---|---|---|---|
| `crowdsec_ti_hit_srcip.yml` | 100040 / 100250 | `homelab-100250` | T1071 |
| `abusech_ti_hit_srcip.yml` | 100045 / 100251 | `homelab-100251` | T1071 |
| `netflow_outbound_c2.yml` | 100048 / 100056 | `homelab-100048` | T1071 |
| `cryptomining_beacon_port.yml` | 100049 | `homelab-100049` | T1496 |
| `suricata_active_exploit.yml` | 100001 | `homelab-100001` | T1190 |
| `dns_oversized_txt.yml` | 100306 | `homelab-100306` | T1071.004, T1572 |
| `dns_dga_servfail_burst.yml` | 100305 | `homelab-100305` | T1568.002 |
| `dns_anonymity_tld.yml` | 100307 | `homelab-100307` | T1090.003 |
| `web_brute_force_lan_external.yml` | 100126 | `homelab-100126` | T1110 |
| `opencanary_lan_probe.yml` | 100702 | `homelab-100702` | T1046 |
| `yara_malware_match.yml` | 100801 | `homelab-100801` | T1059, T1204.002 |
| `zeek_self_signed_cert.yml` | 100604 | — (Zeek removed 2026-10-01) | T1573.002 |

## Lab rules → Elastic (2026-10-16)

`rules/lab/` holds detections written from the detection lab (spec
`a private design doc`). Unlike the parallel
export above, these ARE the source: `./convert-elastic.sh` emits Elastic rule JSON
(`rule_id homelab-lab-<file stem>`, tags `homelab`+`lab`, index `logs-*-lab`, any
`autoblock`/`notify` tag stripped) and the result is pushed with

    rules=$(./convert-elastic.sh) && ssh unraid 'cd /boot/config/compose/elastic && bash rules-add.sh && bash rules-sync.sh' <<<"$rules"

(The `&&` matters: a failed conversion exits non-zero with nothing on stdout, and must not reach Unraid.)
Process-creation rules are narrowed to `process where event.type == "start"`, so one execution raises one alert.

Windows rules use the `ecs_windows` pipeline, Linux rules the vendored `pipelines/ecs_linux.yml`; others convert without one. Rules
Sigma cannot express (sequences, thresholds) stay native EQL in `rules/` on Unraid,
with the Sigma file kept here for portability. Self-test: `./test-convert-elastic.sh`.
