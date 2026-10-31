#!/usr/bin/env python3
"""Controlled-size comparison: Branch and Bound vs Greedy vs Brute force.

Experiment A (exactness + cost): n = 8..24, brute force feasible.  Every B&B loss
               is checked against the exhaustive optimum.
Experiment B (scaling): n = 40..300, brute force infeasible; B&B vs Greedy only.
Each timing is the median of REPEATS runs.  Results go to results/*.csv (+ .png).
"""
import csv
import os
import statistics
import sys

from generate_data import make_records
from simulator import Network, run_algorithm

REPEATS = 3
HERE = os.path.dirname(os.path.abspath(__file__))


def build(n, seed):
    nodes, edges = make_records(n, seed, entries=1 if n < 14 else 2)
    return Network.from_records(nodes, edges)


def budget_for(net, frac):
    return max(1, round(frac * sum(c for i, c in enumerate(net.cost) if not (net.entry_mask >> i) & 1)))


def timed(net, budget, algo, **kw):
    runs = [run_algorithm(net, budget, algo, **kw) for _ in range(REPEATS)]
    r = runs[0]
    r.pop("_eng", None)
    r["runtime_s"] = statistics.median(x["runtime_s"] for x in runs)
    return r


def experiment_a(rows):
    print("Experiment A: exactness check and cost (budget = 25%% of non-entry isolation cost)")
    print("%4s %7s | %9s %9s %9s | %10s %10s %10s | %8s %8s" % (
        "n", "budget", "loss_bf", "loss_bnb", "loss_gr", "t_bf(s)", "t_bnb(s)", "t_gr(s)", "bf_subs", "bnb_nodes"))
    for n in (8, 10, 12, 14, 16, 18, 20, 22, 24):
        for seed in (1, 2, 3):
            net = build(n, seed)
            b = budget_for(net, 0.25)
            bf = timed(net, b, "brute", time_limit=120)
            bb = timed(net, b, "bnb")
            gr = timed(net, b, "greedy")
            if bf["complete"]:
                assert abs(bf["loss"] - bb["loss"]) < 1e-9, ("B&B mismatch", n, seed, bf["loss"], bb["loss"])
            rows.append(dict(experiment="A", n=n, seed=seed, budget=b, loss_brute=bf["loss"], loss_bnb=bb["loss"],
                             loss_greedy=gr["loss"], t_brute=bf["runtime_s"], t_bnb=bb["runtime_s"],
                             t_greedy=gr["runtime_s"], brute_subsets=bf["stats"]["subsets"],
                             bnb_nodes=bb["stats"]["nodes"], bnb_pruned=bb["stats"]["pruned"],
                             greedy_gap_pct=100.0 * (gr["loss"] - bb["loss"]) / bb["loss"] if bb["loss"] else 0.0))
            print("%4d %7s | %9s %9s %9s | %10.4f %10.4f %10.4f | %8d %8d" % (
                n, b, bf["loss"], bb["loss"], gr["loss"], bf["runtime_s"], bb["runtime_s"], gr["runtime_s"],
                bf["stats"]["subsets"], bb["stats"]["nodes"]))


def experiment_b(rows):
    print("\nExperiment B: scaling (brute force infeasible); B&B time limit 30 s")
    print("%4s %7s | %9s %9s %8s | %10s %10s | %9s %s" % (
        "n", "budget", "loss_bnb", "loss_gr", "gr_gap%", "t_bnb(s)", "t_gr(s)", "bnb_nodes", "status"))
    for n in (40, 80, 120, 200, 300):
        net = build(n, 5)
        b = budget_for(net, 0.04)
        bb = timed(net, b, "bnb", time_limit=30)
        gr = timed(net, b, "greedy")
        gap = 100.0 * (gr["loss"] - bb["loss"]) / bb["loss"] if bb["loss"] else 0.0
        rows.append(dict(experiment="B", n=n, seed=5, budget=b, loss_bnb=bb["loss"], loss_greedy=gr["loss"],
                         t_bnb=bb["runtime_s"], t_greedy=gr["runtime_s"], bnb_nodes=bb["stats"]["nodes"],
                         bnb_pruned=bb["stats"]["pruned"], greedy_gap_pct=gap, status=bb["status"]))
        print("%4d %7s | %9s %9s %8.1f | %10.4f %10.4f | %9d %s" % (
            n, b, bb["loss"], gr["loss"], gap, bb["runtime_s"], gr["runtime_s"], bb["stats"]["nodes"], bb["status"]))


def save(rows):
    os.makedirs(os.path.join(HERE, "results"), exist_ok=True)
    fields = sorted({k for r in rows for k in r})
    with open(os.path.join(HERE, "results", "benchmark.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed - skipped plot (CSV saved)")
        return
    a = [r for r in rows if r["experiment"] == "A"]
    ns = sorted({r["n"] for r in a})

    def med(key):
        return [statistics.median(r[key] for r in a if r["n"] == n) for n in ns]

    fig, ax = plt.subplots(1, 2, figsize=(11, 4))
    ax[0].semilogy(ns, med("t_brute"), "o-", label="Brute force")
    ax[0].semilogy(ns, med("t_bnb"), "s-", label="Branch and Bound")
    ax[0].semilogy(ns, med("t_greedy"), "^-", label="Greedy")
    ax[0].set_xlabel("hosts (n)"); ax[0].set_ylabel("median runtime (s, log)"); ax[0].legend()
    ax[0].set_title("Runtime vs network size")
    ax[1].semilogy(ns, med("brute_subsets"), "o-", label="Brute force: subsets evaluated")
    ax[1].semilogy(ns, med("bnb_nodes"), "s-", label="B&B: nodes explored")
    ax[1].set_xlabel("hosts (n)"); ax[1].set_ylabel("operations (log)"); ax[1].legend()
    ax[1].set_title("Search effort")
    fig.tight_layout()
    fig.savefig(os.path.join(HERE, "results", "benchmark.png"), dpi=130)
    print("saved results/benchmark.csv and results/benchmark.png")


if __name__ == "__main__":
    rows = []
    experiment_a(rows)
    experiment_b(rows)
    save(rows)
