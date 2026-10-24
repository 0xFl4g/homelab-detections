# homelab-detections

Detection-as-code from the security monitoring I run on my homelab. An OPNsense firewall (Suricata IDS,
CrowdSec, Unbound DNS, NetFlow), an Unraid server running most services in Docker, a PiKVM and a Synology
NAS send their telemetry to a single-node Elastic Security stack. Everything here is live: these rules
alert on that network every day, and a canary proves each one still fires.

## What's here

| Path | What it is |
|---|---|
| `elastic/rules/` | Elastic detection rules (KQL, EQL sequences, thresholds), deployed with `elastic/rules-sync.sh` |
| `elastic/canary/` | Canary harness: injects synthetic events into the live stack daily and checks every rule fires, plus `expect: none` fixtures that must stay silent |
| `elastic/pipelines/` | Ingest pipelines the rules depend on |
| `detections/sigma/` | Sigma rules with lint and convert scripts and self-tests. `rules/lab/` closes gaps found by running Atomic Red Team in an isolated lab VLAN |
| `detections/native/` | Elastic-native rules for lab gaps Sigma can't express (auditd watches) |
| `detections/attack-map.json` | Source of truth for ATT&CK tags; `scripts/attack.py` validates it against MITRE's STIX data and generates each rule's `threat` field |
| `sigma/` | Earlier Sigma rules from before the move to Elastic |
| `runbooks/` | Response runbooks for the alerts that page me |

## How it's tested

- **CI on every push:** Sigma lint and conversion self-test, rule JSON validation (unique ids, required fields),
  ATT&CK ids checked against the current MITRE release, and a leak scan.
- **Daily canary in production:** synthetic events for each covered rule are written to the real indices; the run
  fails if a rule doesn't alert or a negative fixture does.

## Notes

- Many rules began as ports of Wazuh rules when I moved the SIEM to Elastic in September 2026; their descriptions
  keep the original Wazuh id.
- This tree is exported from a private infrastructure repo by a script that scrubs identifiers and refuses to
  publish if gitleaks finds anything. Internal RFC 1918 addresses are left as they are.
- Issues are welcome. Pull requests can't be merged directly because the tree is regenerated on each export.
- Licence: scripts MIT (`LICENSE`), rule content DRL 1.1 (`LICENSE-DRL`).

**86 Elastic rules · 24 Sigma rules · 119 canary checks covering 86 rules · 3 runbooks · MITRE ATT&CK v20.0**

## ATT&CK coverage

| Tactic | Technique | Elastic rules | Sigma rules |
|---|---|---|---|
| Reconnaissance | T1595 Active Scanning | [100126](elastic/rules/homelab-100126.json) | — |
| Initial Access | T1078 Valid Accounts | — | [opencanary_lan_probe](detections/sigma/rules/opencanary_lan_probe.yml) |
| Initial Access | T1133 External Remote Services | [100102](elastic/rules/homelab-100102.json) | — |
| Initial Access | T1190 Exploit Public-Facing Application | [100001](elastic/rules/homelab-100001.json) | [suricata_active_exploit](detections/sigma/rules/suricata_active_exploit.yml), [web_brute_force_lan_external](detections/sigma/rules/web_brute_force_lan_external.yml) |
| Initial Access | T1200 Hardware Additions | [100322](elastic/rules/homelab-100322.json), [100323](elastic/rules/homelab-100323.json), [100324](elastic/rules/homelab-100324.json), [net-new-device](elastic/rules/homelab-net-new-device.json) | — |
| Execution | T1059 Command and Scripting Interpreter | — | [yara_malware_match](detections/sigma/rules/yara_malware_match.yml) |
| Execution | T1204.002 Malicious File | [100801](elastic/rules/homelab-100801.json) | [yara_malware_match](detections/sigma/rules/yara_malware_match.yml) |
| Execution | T1610 Deploy Container | [100004](elastic/rules/homelab-100004.json) | — |
| Persistence | T1053.003 Cron | [100101](elastic/rules/homelab-100101.json) | — |
| Persistence | T1098 Account Manipulation | [100020](elastic/rules/homelab-100020.json), [100085](elastic/rules/homelab-100085.json), [pikvm-credentials](elastic/rules/homelab-pikvm-credentials.json) | — |
| Persistence | T1098.004 SSH Authorized Keys | [100023](elastic/rules/homelab-100023.json), [100043-rev](elastic/rules/homelab-100043-rev.json), [100043](elastic/rules/homelab-100043.json), [lab-t1098-004-authkeys](elastic/rules/homelab-lab-t1098-004-authkeys.json) | — |
| Persistence | T1136.001 Local Account | [100020](elastic/rules/homelab-100020.json), [100042-rev](elastic/rules/homelab-100042-rev.json), [100042](elastic/rules/homelab-100042.json) | — |
| Persistence | T1543.002 Systemd Service | [100022](elastic/rules/homelab-100022.json), [100043-rev](elastic/rules/homelab-100043-rev.json), [100043](elastic/rules/homelab-100043.json) | — |
| Persistence | T1543.005 Container Service | [100025](elastic/rules/homelab-100025.json) | — |
| Persistence | T1547.006 Kernel Modules and Extensions | [100401](elastic/rules/homelab-100401.json) | — |
| Persistence | T1556.003 Pluggable Authentication Modules | [lab-authconfig-tamper](elastic/rules/homelab-lab-authconfig-tamper.json) | — |
| Privilege Escalation | T1548.001 Setuid and Setgid | [100400](elastic/rules/homelab-100400.json) | — |
| Privilege Escalation | T1548.003 Sudo and Sudo Caching | [100021](elastic/rules/homelab-100021.json), [100042-rev](elastic/rules/homelab-100042-rev.json), [100042](elastic/rules/homelab-100042.json), [lab-authconfig-tamper](elastic/rules/homelab-lab-authconfig-tamper.json) | — |
| Privilege Escalation | T1611 Escape to Host | [100004](elastic/rules/homelab-100004.json) | — |
| Stealth | T1014 Rootkit | [100401](elastic/rules/homelab-100401.json) | — |
| Stealth | T1036.003 Rename Legitimate Utilities | [lab-t1036_003_masquerade_tmp](elastic/rules/homelab-lab-t1036_003_masquerade_tmp.json) | [t1036_003_masquerade_tmp](detections/sigma/rules/lab/t1036_003_masquerade_tmp.yml) |
| Stealth | T1070.003 Clear Command History | [100024](elastic/rules/homelab-100024.json) | — |
| Stealth | T1070.004 File Deletion | [553](elastic/rules/homelab-553.json) | — |
| Stealth | T1564.001 Hidden Files and Directories | [100026](elastic/rules/homelab-100026.json), [lab-hidden-file-tmp](elastic/rules/homelab-lab-hidden-file-tmp.json) | — |
| Defense Impairment | T1553.004 Install Root Certificate | [lab-t1553_004_rogue_ca](elastic/rules/homelab-lab-t1553_004_rogue_ca.json) | — |
| Defense Impairment | T1685 Disable or Modify Tools | [lab-t1562_impair_defenses](elastic/rules/homelab-lab-t1562_impair_defenses.json) | [t1562_impair_defenses](detections/sigma/rules/lab/t1562_impair_defenses.yml), [wazuh-agent-silent-disconnect](sigma/wazuh-agent-silent-disconnect.yml) |
| Defense Impairment | T1685.004 Disable or Modify Linux Audit System Log | [lab-t1562_impair_defenses](elastic/rules/homelab-lab-t1562_impair_defenses.json) | [t1562_impair_defenses](detections/sigma/rules/lab/t1562_impair_defenses.yml) |
| Defense Impairment | T1685.006 Clear Linux or Mac System Logs | [100107](elastic/rules/homelab-100107.json) | — |
| Defense Impairment | T1686 Disable or Modify System Firewall | [100005-unaudited](elastic/rules/homelab-100005-unaudited.json), [100005](elastic/rules/homelab-100005.json), [100106](elastic/rules/homelab-100106.json), [lab-t1562_impair_defenses](elastic/rules/homelab-lab-t1562_impair_defenses.json) | [t1562_impair_defenses](detections/sigma/rules/lab/t1562_impair_defenses.yml) |
| Credential Access | T1003.008 /etc/passwd and /etc/shadow | [lab-t1003_008_shadow_read](elastic/rules/homelab-lab-t1003_008_shadow_read.json) | [t1003_008_shadow_read](detections/sigma/rules/lab/t1003_008_shadow_read.yml) |
| Credential Access | T1040 Network Sniffing | [lab-t1040_packet_capture](elastic/rules/homelab-lab-t1040_packet_capture.json) | [t1040_packet_capture](detections/sigma/rules/lab/t1040_packet_capture.yml) |
| Credential Access | T1110 Brute Force | [100327](elastic/rules/homelab-100327.json), [ti-auth-src](elastic/rules/homelab-ti-auth-src.json) | [web_brute_force_lan_external](detections/sigma/rules/web_brute_force_lan_external.yml) |
| Credential Access | T1110.001 Password Guessing | [100041](elastic/rules/homelab-100041.json), [100082](elastic/rules/homelab-100082.json), [100132](elastic/rules/homelab-100132.json), [100201](elastic/rules/homelab-100201.json), [100211](elastic/rules/homelab-100211.json), [100221](elastic/rules/homelab-100221.json), [100231](elastic/rules/homelab-100231.json), [100328](elastic/rules/homelab-100328.json), [5404](elastic/rules/homelab-5404.json) | — |
| Credential Access | T1552.001 Credentials In Files | [lab-t1552_001_credential_file_search](elastic/rules/homelab-lab-t1552_001_credential_file_search.json) | [t1552_001_credential_file_search](detections/sigma/rules/lab/t1552_001_credential_file_search.yml) |
| Credential Access | T1552.003 Shell History | [lab-t1552_003_shell_history_access](elastic/rules/homelab-lab-t1552_003_shell_history_access.json) | [t1552_003_shell_history_access](detections/sigma/rules/lab/t1552_003_shell_history_access.yml) |
| Credential Access | T1552.004 Private Keys | [lab-t1552_004_private_key_search](elastic/rules/homelab-lab-t1552_004_private_key_search.json) | [t1552_004_private_key_search](detections/sigma/rules/lab/t1552_004_private_key_search.yml) |
| Discovery | T1046 Network Service Discovery | [100702](elastic/rules/homelab-100702.json), [lab-t1046_network_scan](elastic/rules/homelab-lab-t1046_network_scan.json) | [t1046_network_scan](detections/sigma/rules/lab/t1046_network_scan.yml), [opencanary_lan_probe](detections/sigma/rules/opencanary_lan_probe.yml) |
| Lateral Movement | T1021.004 SSH | [100102](elastic/rules/homelab-100102.json) | — |
| Command and Control | T1071 Application Layer Protocol | [100047](elastic/rules/homelab-100047.json), [100048](elastic/rules/homelab-100048.json), [100250](elastic/rules/homelab-100250.json), [100251](elastic/rules/homelab-100251.json), [ti-suricata-dst](elastic/rules/homelab-ti-suricata-dst.json), [ti-suricata-sni](elastic/rules/homelab-ti-suricata-sni.json), [ti-suricata-src](elastic/rules/homelab-ti-suricata-src.json) | [abusech_ti_hit_srcip](detections/sigma/rules/abusech_ti_hit_srcip.yml), [crowdsec_ti_hit_srcip](detections/sigma/rules/crowdsec_ti_hit_srcip.yml), [netflow_outbound_c2](detections/sigma/rules/netflow_outbound_c2.yml) |
| Command and Control | T1071.004 DNS | [100304](elastic/rules/homelab-100304.json), [100306](elastic/rules/homelab-100306.json), [100311](elastic/rules/homelab-100311.json), [100312](elastic/rules/homelab-100312.json), [100313](elastic/rules/homelab-100313.json) | [dns_oversized_txt](detections/sigma/rules/dns_oversized_txt.yml) |
| Command and Control | T1090.003 Multi-hop Proxy | [100307](elastic/rules/homelab-100307.json) | [dns_anonymity_tld](detections/sigma/rules/dns_anonymity_tld.yml) |
| Command and Control | T1132.001 Standard Encoding | [100312](elastic/rules/homelab-100312.json), [100313](elastic/rules/homelab-100313.json) | — |
| Command and Control | T1568.001 Fast Flux DNS | — | [dns_anonymity_tld](detections/sigma/rules/dns_anonymity_tld.yml) |
| Command and Control | T1568.002 Domain Generation Algorithms | [100305](elastic/rules/homelab-100305.json) | [dns_dga_servfail_burst](detections/sigma/rules/dns_dga_servfail_burst.yml) |
| Command and Control | T1571 Non-Standard Port | [100901](elastic/rules/homelab-100901.json) | — |
| Command and Control | T1572 Protocol Tunneling | — | [dns_oversized_txt](detections/sigma/rules/dns_oversized_txt.yml) |
| Command and Control | T1573.002 Asymmetric Cryptography | — | [zeek_self_signed_cert](detections/sigma/rules/zeek_self_signed_cert.yml) |
| Exfiltration | T1041 Exfiltration Over C2 Channel | — | [netflow_outbound_c2](detections/sigma/rules/netflow_outbound_c2.yml) |
| Exfiltration | T1048 Exfiltration Over Alternative Protocol | [100306](elastic/rules/homelab-100306.json), [100312](elastic/rules/homelab-100312.json), [100313](elastic/rules/homelab-100313.json) | — |
| Exfiltration | T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol | — | [dns_oversized_txt](detections/sigma/rules/dns_oversized_txt.yml) |
| Impact | T1485 Data Destruction | [100105](elastic/rules/homelab-100105.json) | — |
| Impact | T1486 Data Encrypted for Impact | [100100](elastic/rules/homelab-100100.json) | — |
| Impact | T1489 Service Stop | [100505](elastic/rules/homelab-100505.json), [100509](elastic/rules/homelab-100509.json) | — |
| Impact | T1490 Inhibit System Recovery | [100104](elastic/rules/homelab-100104.json) | — |
| Impact | T1496 Resource Hijacking | — | [cryptomining_beacon_port](detections/sigma/rules/cryptomining_beacon_port.yml) |
| Impact | T1496.001 Compute Hijacking | [100049-dns](elastic/rules/homelab-100049-dns.json), [100049](elastic/rules/homelab-100049.json), [100103](elastic/rules/homelab-100103.json) | — |
| Impact | T1529 System Shutdown/Reboot | [100321](elastic/rules/homelab-100321.json) | — |

## Unmapped by design

These rules watch availability, hygiene or indicator matches rather than one technique.

- `homelab-100057`: IOC match (abuse.ch hash); not tied to one technique
- `homelab-100059`: IOC match (abuse.ch domain); not tied to one technique
- `homelab-100136`: admin-panel access audit; visibility, not a technique
- `homelab-100303`: DNS REFUSED volume; hygiene signal
- `homelab-100507`: container restart loop; availability, not adversary behaviour
- `homelab-100910`: container crash loop; availability
- `homelab-5108`: kernel OOM kill; availability
- `homelab-5138`: SATA/disk error; hardware
