---
type: concept
title: "Container OOM cascade"
created: 2026-05-13
updated: 2026-10-02
status: developing
tags: [concept, runbook]
---

# Container OOM cascade

> Written in 2026-05 when Wazuh was the SIEM (removed 2026-09-29; Elastic since). Wazuh rule IDs and `wazuh-*` commands below are historical: re-point them at the Elastic rule when this runbook is next used.

**Sigma rule:** `2f3b5d6e-8c1a-4e2f-9d7b-3c8e5f9a1b2c` (container-oom-cascade)
**Wazuh rule:** 5108 (System running out of memory) — fires on kernel OOM line in syslog
**Severity:** high
**Avg time to triage:** 10 min

## What fired

Linux kernel OOM-killer killed a process. Wazuh rule 5108 fires on the kernel log line. **The killed process is often NOT the cause of memory pressure** — the OOM-killer picks the process with the highest `oom_score`, which can be a well-behaved service that happened to be large. The actual leaker is one or more containers without `mem_limit`.

## Triage (5 min)

- [ ] **Which process got killed?** Read the alert's `full_log` field. Note process name + UID + total-vm + anon-rss.
- [ ] **Was the killed process a critical service?**
  Critical: prometheus, wazuh-*, authentik-*, traefik, opensearch, *-postgres, *-postgresql, immich-*
  Routine: chromium / headless-shell / msedge (browser-based containers) — these get OOM-killed regularly when unlimited
- [ ] **How many OOM events in the last hour?**
  ```bash
  ssh unraid 'dmesg | grep -c "Out of memory: Killed"'
  ```
  Single event = could be one runaway. Multiple events = cascading pressure across containers.

**Critical service killed** → proceed urgently to investigation.
**Browser-based container in unlimited state killed** → add mem_limit, close.

## Investigation (15 min)

1. **List containers WITHOUT mem_limit** (the prime suspects):
   ```bash
   ssh unraid 'docker ps --format "{{.Names}}" | while read c; do
       m=$(docker inspect "$c" --format "{{.HostConfig.Memory}}")
       [ "$m" = "0" ] && echo "$c"
   done'
   ```

2. **Of those, which are using the most RAM right now?**
   ```bash
   ssh unraid 'docker stats --no-stream --format "{{.Name}} {{.MemUsage}}" | sort -k2 -h -r | head -15'
   ```

3. **Has any unlimited container been OOM-killed itself recently?** (look for `OOMKilled: true`)
   ```bash
   ssh unraid 'docker ps -a --format "{{.Names}}" | while read c; do
       o=$(docker inspect "$c" --format "{{.State.OOMKilled}}")
       [ "$o" = "true" ] && echo "$c — OOMKilled at $(docker inspect $c --format "{{.State.FinishedAt}}")"
   done'
   ```

4. **Cross-reference time of OOM event** (from the alert) with the FinishedAt of OOMKilled containers from step 3. The leaker is the one that died at or just after the OOM moment.

5. **Check the host's overall memory pressure trend** in Grafana:
   - Node Exporter dashboard → memory available / committed
   - cAdvisor dashboard → top containers by working_set

## Response

- **If a known-leaky container is identified** (typically Chromium/Edge-based scrapers, headless browsers):
  ```yaml
  # In its compose file:
  mem_limit: 3g  # or 4g — sized 1.5-2x typical RSS
  ```
  Apply with `docker-compose up -d <service>`. Verify limit:
  ```bash
  docker inspect <container> --format '{{.HostConfig.Memory}}'
  ```

- **If a critical service was killed as cascade victim** (e.g., Prometheus killed at 11.7 GB RSS while hathor-headless-shell was the real leaker — observed 2026-05-11):
  - Restart the critical service if not already restarted by `restart: unless-stopped`
  - Verify data integrity (Prometheus WAL recovery, Postgres autovacuum state, etc.)
  - **Then** apply the mem_limit fix to the actual leaker

- **If multiple OOM events in <1h**, the system is in cascading pressure:
  - Identify all unlimited containers and apply emergency mem_limits (best guess sizing now, refine later)
  - Consider whether host RAM is sized adequately for the workload

## Close-out

- [ ] All leaky containers have appropriate `mem_limit`
- [ ] Critical service that was killed is back up and verified healthy
- [ ] unraid-compose-stacks updated if new mem_limit constraints added
- [ ] If a recurring leak pattern, add to an internal note

