# Attacking my own lab: what Atomic Red Team found in my Linux detections

**Dates:** 2026-10-16 to 10-18 · **Type:** detection coverage test · **Status:** 12 rules added; destructive tests and Windows still to do

## Summary

I ran every Linux test in Atomic Red Team that could run unattended against an isolated lab VM, and checked
which ones my Elastic Security setup detected. In the clean measurement, **45% of tests raised no alert at
all**, and only a quarter were caught by a rule for the right technique. The biggest single cause wasn't a
missing rule but missing telemetry: on Linux, Elastic Defend never reports a file being modified in place,
so a whole class of persistence and tampering was invisible. I added 12 rules (8 Sigma, 4 native), each
verified by re-running its test and covered by the daily canary.

## The lab

- **Isolated network:** its own VLAN on the firewall. The lab VM can reach the Elastic Fleet server,
  Elasticsearch and the internet, nothing else on the LAN. Attempts to reach the LAN are blocked and logged.
- **One target:** `lab-ubu01`, built fresh from the Ubuntu 26.04 cloud image, with a clean snapshot to revert
  to.
- **Telemetry:** Elastic Defend, journald and auditd. Elastic's prebuilt rules for those sources turned on:
  448 for Defend, 39 for auditd.
- **Safety:** my auto-block responder ignores alerts from lab hosts and the lab subnet, and lab rules never
  carry the tags that page me or trigger blocking. Otherwise attacking the lab would get the lab blocked.

## Method

- **Scope:** every Linux-supported atomic, 434 tests across 121 techniques. 29 were blocklisted because they
  end the session (reboots, ransomware simulations, log destruction) and 6 need manual steps, leaving 399.
- **Runner:** a batch script on the VM ran each test with its prerequisites and cleanup, recorded a UTC time
  window, and checked that sudo, SSH and the Elastic agent were still healthy before moving on.
- **Attribution:** an alert counted for a test if its original event time fell inside the test's window. It
  counted as **on-technique** only if the alert's ATT&CK ID matched the test's. One rule that fired on the
  runner's own `sudo` wrapper was excluded as harness noise.

## Results

Batch 1 is the clean measurement: **216 tests.**

| Outcome | Tests | Share |
|---|---|---|
| Caught by a rule for the right technique | 54 | 25% |
| Raised some alert (any rule) | 118 | 55% |
| No alert at all | 98 | 45% |

The biggest clusters of misses: unsecured credentials (T1552, 21 tests), disabling security tools and
firewall changes (T1685 and T1686, 16), obfuscation (T1027, 8), archiving collected data (T1560, 7) and
packet capture (T1040, 7).

**Why I don't quote the second batch.** After reverting the VM, a second batch ran 111 more tests. It
reported no misses at all, which is too good to be true. When I rechecked the numbers for this write-up, 42
of its "detections" matched only the firewall-flush and firewall-rule rules. The runner flushes the host
firewall after every test (a fix for an earlier problem), so those alerts were detecting my test harness,
not the technique. Combining the batches would have claimed 69% any-alert coverage; without that noise it's
about 57%. The clean batch is the number I trust.

## Root cause: Linux file events have no "modified"

Testing persistence through SSH keys (T1098.004) showed the main gap. Elastic Defend on Linux emits file
`creation`, `deletion` and `rename` events, never modification: of 3,016 recent file events, zero were
modifications. The prebuilt rule for SSH authorized-keys activity keys on `change or creation`, so it only
fires when the file is new, not when an attacker appends a key to an existing one, which is the common case.

The same rule held across three techniques. **Detection depends on how the file is written, not which file
it is:**

| Technique | Write method | Defend event | Detected |
|---|---|---|---|
| T1098.004 `echo > authorized_keys` | in-place truncate-write | none | no, needed auditd |
| T1053.003 `echo > /etc/cron.d/x` | new file | creation | yes |
| T1548.003 `sed -i /etc/sudoers` | temp file + rename | rename | yes |

A second, smaller cause: the test runner executes each test from a temporary script, so the process command
line is just `sh /tmp/...` and command-line rules have nothing to match. An attacker can do the same.

## The 12 rules

| Rule | ATT&CK | Built on |
|---|---|---|
| Packet capture tools | T1040 | Sigma → EQL, process events |
| Private key search | T1552.004 | Sigma → EQL, process events |
| Credential file search | T1552.001 | Sigma → EQL, process events |
| Shell history access | T1552.003 | Sigma → EQL, process events |
| Shadow file read | T1003.008 | Sigma → EQL, process events |
| Impair defenses (audit, logging, SELinux, firewall) | T1685, T1685.004, T1686 | Sigma → EQL, process events |
| Network scanning tools | T1046 | Sigma → EQL, process events |
| System-process name run from a temp path | T1036.003 | Sigma → EQL, process events |
| SSH authorized_keys write | T1098.004 | native EQL, auditd watch |
| sudoers/PAM tampering | T1548.003, T1556.003 | native EQL, auditd watch |
| Root CA added to the trust store | T1553.004 | native EQL, Defend file + process events |
| Hidden file in a world-writable path | T1564.001 | native EQL, Defend file events |

Each was verified by re-running its atomic and seeing it fire. Each also has a fixture in the daily canary,
which injects synthetic events into the live SIEM and checks that every rule still alerts.

**Accepted gaps, on purpose:** benign discovery commands (listing services, hosts, locale), obfuscation and
archiving tools that are everywhere in normal use, and techniques for products I don't run.

## Still to do

- **72 tests not run:** the destructive set (service stops, `magic-sysrq`, and similar), which need running by
  hand with a snapshot revert after each. One of them, a sysrq "terminate all processes", slipped past my
  name filter and killed the runner and SSH mid-batch.
- **Windows:** the same exercise against Windows VMs.

## Lessons

- **Test the telemetry, not just the rules.** The largest gap was an event type that never arrives.
  No rule can fix that; an auditd watch can.
- **Your harness is part of what you measure.** A firewall flush I added for stability generated 42 fake
  detections. Check results that look too good.
- **Isolate the test loop.** In a `while read` batch loop, tests that read stdin consumed the loop's own
  input and were silently skipped: the first batch got through only 217 of 399 (and most likely produced the
  one junk result row I removed). Destructive tests also hit the harness: one shredded the results file,
  another emptied `authorized_keys`.
- **Revert, don't repair.** After a test breaks the VM, go back to the clean snapshot instead of fixing it by
  hand. Repairs leave state that skews the next result.
