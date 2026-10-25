# The update job that could never finish: a read-only device left writable for 20 days

**Date found:** 2026-10-24 · **Severity:** medium (hardening silently off) · **Status:** resolved

## Summary

My PiKVM, the out-of-band console for the main server, runs with a read-only root filesystem: it protects the
SD card from corruption on power loss and makes tampering harder. A weekly job switched the root to read-write,
upgraded packages, then tried to switch it back. That last step failed every week there was something to
upgrade, so the device had been sitting read-write since 2026-10-04. A routine health check found it on
10-24. The fix was a reboot and a decision: updates on this device are now attended, not automatic.

## Impact

- **Root filesystem writable for 20 days** (from 2026-10-04 03:04 UTC to 10-24) on a device whose design
  assumes it isn't: higher risk of SD-card corruption on power loss, and one layer of tamper resistance gone.
- **An update was half applied.** Tailscale's package had been upgraded but the old daemon kept running
  until a restart.
- **Nothing alerted.** The job logged its failure to the journal every week, and nobody reads the journal.
- No data loss was found.

## Timeline (UTC)

| When | Event |
|---|---|
| 2026-09-27 | The weekly job fails on a package conflict (a separate, already-known problem, fixed on 10-01 with the vendor's updater) |
| 10-01 | Reboot after that fix: root back to read-only |
| 10-04 03:04 | Weekly job: packages upgrade, then `mount -o remount,ro /` fails with "mount point is busy". **Root stays writable from here** |
| 10-11 03:27 | Same failure |
| 10-18 03:21 | Same failure |
| 10-24 13:38 | Health check flags the failed unit; the cause is found within minutes |
| 10-24 13:44 | Timer disabled, package snapshot taken, reboot. Root read-only again, all services verified |

The journal (kept since 09-25) shows no successful run of the job at all.

## How it was found

A routine read-only sweep of the hosts listed failed systemd units. `pacman-update.service` was one, and its
last lines were:

```
+ mount -o remount,ro /
mount: /: mount point is busy.
pacman-update.service: Main process exited, code=exited, status=32/n/a
```

`findmnt -no OPTIONS /` confirmed the root was `rw`. The run history showed the same failure three weeks
running.

## Root cause

The job was one line: `rw && pacman -Syu --noconfirm && pacman -Sc --noconfirm && ro`.

When `pacman` replaces a shared library, programs that are already running keep the old file open. It no
longer has a name (it shows as `(deleted)` in `/proc/<pid>/maps`), but it still occupies space on the
filesystem. Linux refuses to remount a filesystem read-only while such unlinked files are open, because
it couldn't free them afterwards. On this device the list included systemd, udevd, D-Bus, avahi, the RNG
daemon and two KVM services, holding the old `libcrypto`, `libz` and Python 3.14.

So the job could only ever finish in a week with nothing to upgrade. Only a reboot (or restarting every
affected process) releases the old files. The design was broken from the start; it simply hadn't been tested
against a week with updates.

## What changed

- **No unattended updates on this device.** Two alternatives were on the table: update and reboot
  automatically, or update without rebooting. The first means an unattended reboot of the one console I need
  when something else is broken, possibly while I'm not on site. The second leaves the root writable until someone
  reboots, which is exactly this incident. Updates are now run by hand with the vendor's updater
  (`pikvm-update`), followed by a reboot and a checklist.
- **The checklist covers the end state, not just the commands:** root is `ro`, the KVM services, Tailscale and
  log forwarding are running, no failed units, and the Tailscale settings that keep this device a subnet
  router without accepting routes are unchanged.
- **Written down with the reason,** so the timer doesn't get re-enabled by someone who thinks it was disabled
  by mistake.

The first manual update the same day turned up a second surprise: the vendor's updater hung at its last step
(`tailscale up`) with Tailscale already running and correctly configured. Because the script runs with
`set -e`, killing the hung command would also skip its final config check, so I ran that check (`kvmd -m`)
by hand before rebooting. That's documented too.

## Lessons

- **A job that changes security state must verify the end state and alert when it isn't reached.** This one
  logged "failed" every week; a log that nobody reads isn't monitoring. A check that alerts when the root stays
  writable outside a maintenance session is the obvious next step.
- **Read-only roots and package managers don't mix without a reboot.** Any "remount ro after updating" step
  should expect to fail after a library upgrade.
- **Decide update policy per device.** The best answer for a server isn't the best answer for the device you
  use to rescue the server.
- **Test the unhappy week.** The job only worked when there was nothing to do.
