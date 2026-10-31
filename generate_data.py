#!/usr/bin/env python3
"""Deterministic generator for tiered enterprise networks (DMZ -> app -> data -> vault)."""
import csv
import json
import os
import random
import sys

TIER_NAMES = ["dmz", "app", "data", "vault"]
TIER_SHARE = [0.15, 0.35, 0.35, 0.15]
TIER_CRIT = [(1, 5), (5, 20), (20, 60), (60, 150)]
TIER_COST = [(1, 3), (2, 6), (3, 9), (4, 12)]


def make_records(n, seed, entries=2):
    """Return (node_rows, edge_rows) for a random tiered network of n hosts."""
    rng = random.Random(seed)
    sizes = [max(1, round(n * s)) for s in TIER_SHARE]
    sizes[1] += n - sum(sizes)
    tiers, nodes = [], []
    k = 0
    for t, size in enumerate(sizes):
        members = []
        for _ in range(size):
            k += 1
            lo, hi = TIER_CRIT[t]
            clo, chi = TIER_COST[t]
            nid = "H%03d" % k
            members.append(nid)
            nodes.append({"id": nid, "name": "%s-%d" % (TIER_NAMES[t], len(members)),
                          "criticality": rng.randint(lo, hi), "isolation_cost": rng.randint(clo, chi),
                          "is_entry": 0, "status": "active"})
        tiers.append(members)
    for nid in rng.sample(tiers[0], min(entries, len(tiers[0]))):
        row = next(r for r in nodes if r["id"] == nid)
        row["is_entry"] = 1
        row["isolation_cost"] = 40      # taking an internet-facing gateway offline is very expensive
    edges = set()
    for t in range(3):
        for u in tiers[t]:
            for v in rng.sample(tiers[t + 1], min(len(tiers[t + 1]), rng.randint(1, 3))):
                edges.add((u, v))
    for t in range(4):                      # lateral movement inside a tier
        for u in tiers[t]:
            if rng.random() < 0.25 and len(tiers[t]) > 1:
                v = rng.choice([x for x in tiers[t] if x != u])
                edges.add((u, v))
    edge_rows = [{"src": s, "dst": d} for s, d in sorted(edges)]
    return nodes, edge_rows


def write_csv(path, rows, fields):
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    data = os.path.join(here, "data")
    os.makedirs(data, exist_ok=True)
    fields = ["id", "name", "criticality", "isolation_cost", "is_entry", "status"]
    budgets = {}
    for label, n, seed, entries, frac in [("medium", 40, 7, 2, 0.0), ("large", 300, 11, 3, 0.0)]:
        nodes, edges = make_records(n, seed, entries)
        write_csv(os.path.join(data, label + "_nodes.csv"), nodes, fields)
        write_csv(os.path.join(data, label + "_edges.csv"), edges, ["src", "dst"])
    budgets.update({"small": 4, "medium": 15, "large": 60})
    with open(os.path.join(data, "budgets.json"), "w") as fh:
        json.dump(budgets, fh, indent=2)
    print("wrote datasets; suggested budgets:", budgets)


if __name__ == "__main__":
    sys.exit(main())
