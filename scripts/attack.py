#!/usr/bin/env python3
"""Validate detections/attack-map.json against MITRE ATT&CK STIX and build Elastic `threat` arrays.

attack.py validate <map.json> <enterprise-attack.json>
attack.py threat <map.json> <enterprise-attack.json> <rule_id>
"""
import json
import sys

BASE = "https://attack.mitre.org"


def load(stix_path):
    """Index the bundle: tactics by id, techniques by id (name, tactic ids, dead flag)."""
    with open(stix_path) as f:
        objs = json.load(f)["objects"]
    tactics, short = {}, {}
    for o in objs:
        if o["type"] == "x-mitre-tactic":
            tid = o["external_references"][0]["external_id"]
            tactics[tid] = o["name"]
            short[o["x_mitre_shortname"]] = tid
    techs, sid = {}, {}
    for o in objs:
        if o["type"] != "attack-pattern":
            continue
        eid = next((r["external_id"] for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if not eid:
            continue
        sid[o.get("id")] = eid
        techs[eid] = {
            "name": o["name"],
            "tactics": {short[k["phase_name"]] for k in o.get("kill_chain_phases", []) if k["phase_name"] in short},
            "dead": bool(o.get("revoked") or o.get("x_mitre_deprecated")),
        }
    revoked_by = {sid[o["source_ref"]]: sid[o["target_ref"]] for o in objs
                  if o["type"] == "relationship" and o.get("relationship_type") == "revoked-by"
                  and o["source_ref"] in sid and o["target_ref"] in sid}
    return {"tactics": tactics, "techs": techs, "revoked_by": revoked_by}


def validate(amap, idx):
    errs = []
    for rid, entries in amap.items():
        if rid.startswith("_note_"):
            continue
        for e in entries:
            ta, te, sub = e.get("tactic"), e.get("technique"), e.get("subtechnique")
            if ta not in idx["tactics"]:
                errs.append(f"{rid}: unknown tactic {ta}")
            t = idx["techs"].get(te)
            if not t or t["dead"]:
                errs.append(f"{rid}: unknown or revoked technique {te}")
            elif ta not in t["tactics"]:
                errs.append(f"{rid}: {te} is not under {ta}")
            if sub:
                s = idx["techs"].get(sub)
                if not s or s["dead"] or not sub.startswith(f"{te}."):
                    errs.append(f"{rid}: bad subtechnique {sub} for {te}")
                elif ta not in s["tactics"]:
                    errs.append(f"{rid}: {sub} is not under {ta}")
    return errs


def threat(entries, idx):
    """Elastic threat array: one item per tactic, techniques merged, subtechniques merged."""
    out = {}
    for e in entries:
        ta, te, sub = e["tactic"], e["technique"], e.get("subtechnique")
        tac = out.setdefault(ta, {"framework": "MITRE ATT&CK",
                                  "tactic": {"id": ta, "name": idx["tactics"][ta], "reference": f"{BASE}/tactics/{ta}/"},
                                  "technique": []})
        tech = next((t for t in tac["technique"] if t["id"] == te), None)
        if tech is None:
            tech = {"id": te, "name": idx["techs"][te]["name"], "reference": f"{BASE}/techniques/{te}/"}
            tac["technique"].append(tech)
        if sub and sub not in [s["id"] for s in tech.get("subtechnique", [])]:
            tech.setdefault("subtechnique", []).append(
                {"id": sub, "name": idx["techs"][sub]["name"], "reference": f"{BASE}/techniques/{sub.replace('.', '/')}/"})
    return list(out.values())


def main(argv):
    cmd, map_path, stix_path = argv[1], argv[2], argv[3]
    with open(map_path) as f:
        amap = json.load(f)
    idx = load(stix_path)
    if cmd == "validate":
        errs = validate(amap, idx)
        print("\n".join(errs) or f"ok ({sum(1 for k in amap if not k.startswith('_note_'))} rules)")
        return 1 if errs else 0
    if cmd == "threat":
        print(json.dumps(threat(amap[argv[4]], idx)))
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
