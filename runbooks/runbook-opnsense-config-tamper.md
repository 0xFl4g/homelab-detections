---
type: concept
title: "OPNsense config.xml tampering"
created: 2026-05-13
updated: 2026-10-02
status: developing
tags: [concept, runbook]
---

# OPNsense config.xml tampering

> Written in 2026-05 when Wazuh was the SIEM (removed 2026-09-29; Elastic since). Wazuh rule IDs and `wazuh-*` commands below are historical: re-point them at the Elastic rule when this runbook is next used.

**Sigma rule:** `8d4f2c1e-3b5a-4f7e-9c8d-2e1a5b6f7d8c` (opnsense-config-tamper-offhours)
**Wazuh rule:** 100005 (Wazuh manager local_rules.xml)
**Severity:** critical (off-hours) / medium (admin hours)
**Avg time to triage:** 10 min

## What fired

`/conf/config.xml` on OPNsense was modified. Wazuh saw the file change (size/mtime/hashes all differ). The file is the **complete router configuration** — firewall rules, NAT, VPN, certs, users, plugins. Any change is potentially security-relevant.

## Triage (5 min — decide if it's noise)

- [ ] **Are you the one editing?** If yes and you remember the change → close as benign admin activity.
- [ ] **Is the change during admin hours (07:00-23:00 local)?**
  Off-hours changes are FAR more suspicious. The Sigma rule above escalates only those.
- [ ] **Was os-git-backup triggered around the same time?**
  ```bash
  ssh opnsense 'tail -20 /conf/backup/git/.git/logs/HEAD 2>/dev/null'
  ```
  If a commit appeared right after the change, the change went through the WebUI (which triggers the git-push syshook).

**All three indicate routine admin activity** → close, no action.
**ANY off-hours change OR no git-push correlation** → investigate.

## Investigation (15-30 min)

1. **What changed?** Compare to backup. Most recent backups are at `~/VSCode/homelab/backups/opnsense/`.
   ```bash
   # Pull current config
   scp opnsense:/conf/config.xml /tmp/config.new.xml
   # Find most recent backup
   tar xzf ~/VSCode/homelab/backups/opnsense/$(ls -t ~/VSCode/homelab/backups/opnsense/*.tar.gz | head -1) -C /tmp/wazuh-cmp/
   diff /tmp/wazuh-cmp/*/config.xml /tmp/config.new.xml | head -60
   ```

2. **Who made the change?** Check OPNsense WebUI audit log:
   ```bash
   ssh opnsense 'sh -c "tail -100 /var/log/audit/audit.log"'
   ```
   Look for `user_login`, `user_logout`, `config change` events near the timestamp.

3. **What category of change?**
   - **Firewall rules** (`<filter><rule>`) → most concerning. Verify legitimacy.
   - **NAT rules** (`<nat>`) → second-most concerning. Port forward changes can expose internal services.
   - **Users** (`<system><user>`) → new user account = compromise indicator.
   - **Certificates / API keys** → rare but possible legitimate rotation.
   - **DNS / Unbound overrides** → low risk usually, but check for hijack of internal domains.

4. **If suspicious WebUI auth involved**, check source IP of the session:
   ```bash
   ssh opnsense 'sh -c "grep \"$(date '+%Y-%m-%dT%H')\" /var/log/lighttpd/access.log | grep -E \"POST|PUT|DELETE\""'
   ```

## Response

- **Routine admin** → close, optionally annotate with the change context for future review.
- **Off-hours but verified by trusted admin** → close with note in incident log.
- **Suspicious / unverified:**
  1. **Snapshot current config** before reverting: `scp opnsense:/conf/config.xml ~/forensics/opnsense-suspect-$(date +%s).xml`
  2. **Compare diff** carefully; if you find an injected firewall rule, NAT, or user, document it
  3. **Restore prior config** via WebUI: System → Configuration → History → revert to last-known-good
  4. **Rotate secrets** that might have been viewed: API keys, certificates, WG keys
  5. **Investigate root cause:** how did the attacker get WebUI/SSH access? Check fail2ban logs, audit log, recent firewall rule changes.

## Close-out

- [ ] Change is either benign-acknowledged or reverted-and-investigated
- [ ] If new pattern of false-positive (e.g., a new automated process editing config), suppress in Wazuh rule
- [ ] If real incident, file follow-up tickets for cause investigation + secret rotation

