# Three ways in: making remote access to the homelab survive one router failing

**Date:** 2026-09-26 · **Type:** design note (after two outages) · **Status:** in place; failover not yet tested

## Why

I reach the lab's LAN from outside through a Tailscale subnet router: one machine on the LAN advertises the
LAN's address range to my tailnet, and my laptop routes through it. With a single router, one failed service
means no remote access, and I'm often not on site.

The out-of-band console (a PiKVM) had already taught me how easy it is to cut that access. Twice, enabling
`--accept-routes` on it took it offline: it sits on the LAN whose route it then accepted, and the overlapping
routes cut it off. The rule that came out of that is simple and permanent:
the PiKVM never accepts routes and never advertises itself as an exit node. (I didn't record dates or
durations for those two outages, so this note is about what I built afterwards.)

## Design

Three machines on the LAN advertise the same range, and all three routes are approved:

| Router | Role |
|---|---|
| OPNsense (the firewall) | Holds the WAN address itself, so it needs no NAT rule |
| Unraid (the main server) | Second router |
| PiKVM (the out-of-band console) | Third router; advertises only, never accepts routes |

Tailscale picks one of the approved routers and fails over automatically when it stops responding. There's no
priority setting, so any of the three being active is normal. When the Unraid route was approved, Tailscale
moved traffic to it immediately.

## Making it fast: direct connections behind NAT

A subnet router that only reaches the tailnet through a relay works, but slowly. Getting direct connections for
the two routers behind the firewall's NAT took three pieces:

1. **Hybrid outbound NAT on OPNsense,** so I could add manual rules alongside the automatic ones.
2. **Static-port rules** for Unraid and the PiKVM, so the source port Tailscale uses inside is the port the
   outside world sees. Without that, the NAT rewrites the port and peers can't predict it.
3. **A distinct port per router.** Two static-port mappings of the same port collide on the WAN address, so
   each router runs Tailscale on its own fixed port.

Verified on 2026-09-26: all three routers showed `direct` connections from my laptop at about 70 ms.

One false alarm worth knowing: `tailscale netcheck` keeps reporting `MappingVariesByDestIP: true` even with
this in place, because it probes from a random port rather than the configured one. `tailscale status` and
`tailscale ping` (look for `direct`) are the checks that mean something.

## The bug that showed up the same day

With everything advertised and approved, SSH from outside still timed out. My laptop's network map arrived
without the LAN route at all. The cause was the tailnet's access policy: it allowed my devices and a few
other ranges, but not the LAN range. Tailscale won't send a client a route the policy doesn't let it use,
so the approval did nothing. Adding the range to the policy fixed it.

The lesson: **a subnet route needs three things, not two.** Advertised, approved, and allowed by the access
policy.

## Limits I accept

- **It covers a failed router service, not a failed firewall.** OPNsense is also the WAN gateway; if it's
  down, the other two can't reach the tailnet either. Surviving that would need a second internet path.
- **The PiKVM is weak hardware** (ARM, 1.7 GB RAM). If Tailscale happens to route through it, it's slower.
  I accepted that in exchange for a third path.
- **Failover hasn't been tested yet.** I know it fails over in principle (it switched when a route was
  approved), but I haven't measured failover time or failback. That test needs someone on site in case it
  goes wrong, which is the whole point of having it.

## Lessons

- **Redundancy for remote access has to be designed around what you can't fix remotely.** The firewall is
  the single point of failure here, and I've written that down instead of pretending otherwise.
- **Keep the console boring.** The device you use to rescue everything else gets the most conservative
  configuration: no accepted routes, no exit node, no surprises.
- **Check the policy layer.** Most "the route is there but nothing works" problems are an ACL, not a route.
