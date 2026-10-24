---
type: concept
title: "Authentik brute-force burst"
created: 2026-05-14
updated: 2026-10-02
status: developing
tags: [concept, runbook]
---

# Authentik brute-force burst

> Written in 2026-05 when Wazuh was the SIEM (removed 2026-09-29; Elastic since). Wazuh rule IDs and `wazuh-*` commands below are historical: re-point them at the Elastic rule when this runbook is next used.

**Sigma rule:** `5a7c9b1d-4e2f-3a8d-6c5b-9f1a2e3d4c5b` (`sigma/authentik-bruteforce.yml`)
**Wazuh rule:** TBD (assign on first conversion)
**Severity:** high
**Avg time to triage:** 10 min

## What fired

5+ Authentik login failures from the same `client_ip` within a 5-minute window. Authentik covers both the 4-tier forward-auth (cookie at `sol.example.com` / `example.com`) and native OIDC services (Grafana, Immich, Forgejo, FreshRSS, Audiobookshelf, Jellyfin).

Maps to MITRE ATT&CK: T1110.001 (Password Guessing), T1110.003 (Password Spraying).

## Triage (5 min — decide if it's noise)

- [ ] **Whose IP?** Cross-check `client_ip` against:
  - Known operator IPs (Mac, NetBird overlay 100.x.y.z, WG_OPNSENSE 10.25.20.x)
  - Internal LAN (10.20.20.0/24) → likely a service account or a phone with stale creds
  - External: `curl -s https://ipinfo.io/<ip>/json` and check ASN + country
- [ ] **Same user or many users?** Query Authentik Events for `client_ip == <ip>` last 1h. Same user 5× = mistyped password. 5 different users = spray.
- [ ] **Did they eventually succeed?** Look for `login` (success) event from same `client_ip` after the failure burst. Success → potential breach. No success → blocked attempt.

**Pure-noise signatures:**
- Same user, 5+ failures, then success from same IP → user got their password right eventually. Close.
- Service account with old password hammering hourly → fix the service, suppress source IP for 24h.

**Real-attack signatures:**
- Many usernames from one IP, no success → spray. Investigate.
- One username, many sources → distributed credential stuffing. Investigate.
- One username, one source, no success, IP in suspicious ASN/country → targeted brute force. Investigate.

## Investigation (15-30 min)

1. **Pull the full event sequence** for the source IP:
   - Authentik UI: Admin → Events → filter `client_ip == <ip>` last 24h
   - Or query Loki: `{job="authentik"} |~ "<ip>"` last 24h
2. **Check whether any session was created**: look for `event_action=login` (success) or `event_action=authorize_application` after the failures.
3. **Cross-reference Wazuh**: search alerts.json for the same IP — concurrent SSH brute force from same source?
   ```bash
   ssh unraid 'docker exec wazuh-manager grep "<ip>" /var/ossec/logs/alerts/alerts.json | tail -20'
   ```
4. **Is the IP in CrowdSec already?** `ssh opnsense 'cscli decisions list -i <ip>'` — should be blocked at the firewall if so. If not, why didn't CrowdSec catch this?
5. **MFA status**: did the target user have MFA enabled? If yes, password failures are lower-severity (MFA blocks even if password leaked). Check user record in Authentik UI.

## Response

| Finding | Action |
|---|---|
| Noise (user mistyped, eventually succeeded) | Close. Optionally suppress `client_ip == <user-known-ip>` for 24h. |
| Spray, no success, external IP | Manually block via OPNsense: `ssh opnsense 'pfctl -t crowdsec_blocklists -T add <ip>'`. File the IP in CrowdSec via `cscli decisions add -i <ip> -d 7d -R authentik-bruteforce`. Tune CrowdSec scenario if it didn't auto-block. |
| Spray, success on one account | **Treat as breach.** Force password reset on that user. Invalidate all Authentik sessions: Admin → Users → user → Sessions → Revoke All. Check audit log for what they did post-login. |
| Internal IP, recurring | Service account misconfig. Identify the service via `nmap -Pn <ip>` or `arp -an | grep <ip>` on OPNsense, fix or rotate credential. |
| Distributed (many sources, one user) | Targeted attack. Enable MFA on that user if not already. Consider geoblocking. |

**Preserve forensics before remediation** if the burst looks novel: `ssh unraid 'docker exec authentik-server pg_dump -t authentik_events_event ... '` snapshot of the event window.

## Close-out

- [ ] Source IP triaged (blocked, suppressed, or marked benign)
- [ ] Affected user(s) notified or password-reset if breach
- [ ] CrowdSec scenario tuned if it should have caught this but didn't
- [ ] Wazuh rule that triggered this runbook noted with assigned ID
- [ ] If novel pattern: file as a new sigma rule + paired runbook

## References

- Sigma: `sigma/authentik-bruteforce.yml`
- Memory: domain-and-tls — Authentik 4-tier forward-auth architecture
- OPNsense: CrowdSec is the primary firewall-side bouncer; Wazuh active-response is a secondary layer
- MITRE: [T1110.001](https://attack.mitre.org/techniques/T1110/001/), [T1110.003](https://attack.mitre.org/techniques/T1110/003/)
