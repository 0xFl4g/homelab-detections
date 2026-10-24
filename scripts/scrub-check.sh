#!/bin/bash
# Generic leak scan for this public tree: fails on public IPv4/IPv6 addresses, Tailscale/CGNAT addresses
# and email addresses. Private, documentation and placeholder addresses pass.
# Usage: scripts/scrub-check.sh [dir]   (default: repo root)
set -euo pipefail
python3 - "${1:-.}" <<'PY'
import ipaddress, os, re, sys
root = sys.argv[1]
ALLOW = {"100.64.0.0", "100.64.0.10", "1.2.3.4"}  # CGNAT base/placeholder, conventional dummy IP
CGNAT = ipaddress.ip_network("100.64.0.0/10")
ip_rx = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?!\d|\.\d)")
ip6_rx = re.compile(r"(?<![\w:])((?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4})(?![\w:])", re.I)
mail_rx = re.compile(r"\b[\w.%+-]+@[\w-]+(?:\.[\w-]+)*\.[a-z]{2,}\b", re.I)
hits = []
for d, dirs, files in os.walk(root):
    dirs[:] = [x for x in dirs if x != ".git"]
    for n in files:
        p = os.path.join(d, n)
        try:
            text = open(p, encoding="utf-8").read()
        except UnicodeDecodeError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for m in ip_rx.findall(line):
                try:
                    ip = ipaddress.ip_address(m)
                except ValueError:
                    continue
                if m in ALLOW:
                    continue
                if ip in CGNAT or ip.is_global:
                    hits.append(f"{p}:{i}: address {m}")
            for m in ip6_rx.findall(line):
                try:
                    if ipaddress.ip_address(m).is_global:
                        hits.append(f"{p}:{i}: address {m}")
                except ValueError:
                    pass
            for m in mail_rx.findall(line):
                hits.append(f"{p}:{i}: email {m}")
print("\n".join(hits) or "scrub-check: clean")
sys.exit(1 if hits else 0)
PY
