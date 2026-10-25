# No swap, two OOM kills, and choosing what the kernel kills

**Dates:** 2026-10-11 and 2026-10-22 · **Severity:** medium (one service down a day, one restarted) · **Status:** mitigated

## Summary

My main server has 62.5 GiB of RAM and no swap. When memory runs out, the Linux OOM killer picks a process and
kills it, and by default it picks the biggest. Twice in two weeks that was something I cared about: first a
production VM, which stayed down for about a day, then Elasticsearch, the core of my SIEM. Between the two I
had started telling the kernel what to kill first, and the second event shows that working: the VM was
spared. It also shows that I had knowingly cut my memory headroom too thin, so I gave some back.

## Impact

- **10-11:** the VM running a production web-app backend was killed and stayed down until I started it by
  hand the next evening, about 27 hours later. Its Postgres recovered cleanly; no data loss. The osquery
  agent on the host stopped the same day, which tripped a "stream stale" alert.
- **10-22:** Elasticsearch (7.0 GiB resident) and two machine-learning `autodetect` processes were killed.
  Elasticsearch's restart policy brought it back 17 seconds later. Some indices came back without their
  replica shards assigned, leaving the cluster yellow until I fixed their replica settings. The VM was not
  touched.

## Timeline (UTC)

| When | Event |
|---|---|
| 10-11 15:03 | During a long-running machine-learning batch job, the host runs out of memory; the kernel kills the VM's QEMU process |
| 10-12 evening | VM started by hand (autostart was off); Postgres does a clean crash recovery. osquery restarted after its stale-stream alert |
| 10-19 | A guard script starts protecting the VM (below). Same day, self-hosted Sentry goes live in full mode; its design notes record that this leaves about 7 GiB of headroom with no swap and call it "a standing risk" |
| 10-22 06:03:41 | Global OOM: the kernel kills Elasticsearch's Java process (7.0 GiB) and two ML jobs. The VM is spared |
| 10-22 06:03:58 | Elasticsearch running again |
| 10-23 | Sentry moved to its errors-only mode, which frees about 6 GiB; replica settings fixed; a bug in the guard's process match fixed |

## Root cause

**No swap means no slack.** On this host, an unlimited container that grows, or a one-off heavy batch job,
goes straight to the OOM killer. The kernel scores processes mostly by memory use, so the
largest long-running things are the usual victims: a VM with a fixed 12 GB allocation, or a Java heap.

**10-11:** a long machine-learning batch job pushed the host over. The VM was the biggest target.

**10-22:** the immediate trigger isn't recorded, but the conditions were: three days earlier I had added a
monitoring platform that uses about 15 GiB in its full mode, knowingly leaving around 7 GiB free. That was
enough for normal days and not enough for a bad minute.

## What changed

- **The kernel now has a preference.** A small script sets the VM's QEMU process to `oom_score_adj -500`, so
  under memory pressure the kernel kills a container first. libvirt resets the value every time the VM
  starts, so the script runs every 5 minutes instead of once. On 10-22 the VM survived.
- **The guard's own check was fixed.** An ad-hoc check on 10-22 matched itself instead of the QEMU process
  (a classic `ps | grep` trap). The match is now anchored to the QEMU binary, with a test.
- **Headroom given back.** Sentry runs in errors-only mode by default and switches to full mode only when I
  need performance traces. That freed about 6 GiB.
- **Replica settings that survive restarts.** The indices that came back yellow get zero replicas from the
  setup script and from a daily job, so a restart of this single-node cluster doesn't leave them unassigned.
- **Already in place and still the rule:** heavy containers get memory limits of 1.5 to 3 times their
  measured resident size, so a runaway hits its own limit before it hits the host.

## Still open

- Postgres inside the VM should get its own `oom_score_adj`, so that under memory pressure in the VM a
  stateless container dies, never the database.
- How I noticed the 10-22 event isn't recorded, and the alert rule for kernel OOM kills wasn't checked
  against either date. Confirming that the OOM alert fires is the next small task.

## Lessons

- **If you don't choose the OOM victim, the kernel will.** `oom_score_adj` is cheap, and on a host without
  swap it's the difference between losing a cache and losing a database.
- **Write down the risk you accept, with the number.** The design notes said "about 7 GiB of headroom, a
  standing risk". When the risk landed three days later, that line made the response obvious.
- **Restart policies hide kills.** Elasticsearch was back in 17 seconds. Without the kernel log and the
  replica fallout, it would have looked like nothing happened. An OOM should always alert, even when it
  heals itself.
- **Values that something else resets need to be enforced, not set.** A one-time `oom_score_adj` would have
  been gone after the VM's next start.
