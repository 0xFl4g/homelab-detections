#!/usr/bin/env python3
"""Check elastic/rules/*.json: valid JSON, unique rule_id, required fields, and `threat` equal to what
detections/attack-map.json generates (scripts/attack.py), with every map id valid in the ATT&CK bundle.

check-rules.py <tree> <enterprise-attack.json>
"""
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import attack  # noqa: E402

REQUIRED = ("rule_id", "name", "query", "type", "severity", "risk_score", "threat")


def main(tree, stix):
    idx = attack.load(stix)
    with open(f"{tree}/detections/attack-map.json") as f:
        amap = json.load(f)
    errs = attack.validate(amap, idx)
    seen = {}
    for p in sorted(glob.glob(f"{tree}/elastic/rules/*.json")):
        try:
            with open(p) as f:
                r = json.load(f)
        except ValueError as e:
            errs.append(f"{p}: invalid JSON ({e})")
            continue
        missing = [k for k in REQUIRED if k not in r]
        if missing:
            errs.append(f"{p}: missing {', '.join(missing)}")
            continue
        rid = r["rule_id"]
        if rid in seen:
            errs.append(f"{p}: duplicate rule_id {rid} (also {seen[rid]})")
        seen[rid] = p
        if rid not in amap:
            errs.append(f"{p}: {rid} has no entry in attack-map.json")
        elif json.dumps(r["threat"], sort_keys=True) != json.dumps(attack.threat(amap[rid], idx), sort_keys=True):
            errs.append(f"{p}: threat differs from attack-map.json")
    print("\n".join(errs) or f"check-rules: {len(seen)} rules ok")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
