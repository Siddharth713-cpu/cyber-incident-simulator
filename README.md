# Cyber Incident Propagation Simulator (Branch and Bound)

DAA PBL - Project Challenge 13. Given a network, the attacker's entry points and a limited
isolation budget, the tool decides **which hosts to quarantine** so that the worst-case damage of a
breach is minimal, and explains the decision in plain language.

## 1. User, objective, constraints

| Item | Definition |
|---|---|
| User | A SOC / incident-response lead who must contain a breach with limited time and staff. |
| Input | `nodes.csv` (`id,criticality,isolation_cost,is_entry,status[,name]`), `edges.csv` (`src,dst`), `--budget B`. |
| Decision | A set `I` of hosts to isolate (disconnect). |
| Objective | Minimise `loss(I)` = total criticality of hosts the attacker can reach from the entry points when hosts in `I` are removed (worst case: the attacker moves along every edge). |
| Hard constraint | `sum(isolation_cost[u] for u in I) <= B`. |
| Assumptions | Directed edge `u->v` = attacker on `u` can move to `v`; worst-case (deterministic) spread; isolating a host also removes it as a stepping stone; entry hosts may be isolated (usually very expensive); `offline` hosts are already disconnected and cost nothing. |
| Consequence of a bad plan | Higher criticality compromised. If no plan reaches a requested `--target-loss`, the tool says *INFEASIBLE within this budget* and reports the best achievable loss. |

The problem is a budgeted node-removal (critical-node) problem and is NP-hard, which is why a smart
exact search (Branch and Bound) is useful.

## 2. Algorithm (Branch and Bound)

**State:** `(I, F, left)`: `I` isolated hosts, `F` hosts decided *not* to isolate, `left` remaining budget.
**Decision variable:** `x_u in {0,1}` - isolate host `u`.
**Selection rule:** among candidates (infected, not in `F`, affordable) branch on the one with the
largest `value(D(u)) / cost(u)`, where `D(u)` = hosts reachable from `u` (what isolating `u` could save).
First child: isolate `u`; second child: forbid `u`.
**Bound (minimisation, lower bound on loss of any plan in the subtree):**
`LB = loss(I) - min( loss(I) - value(S), fractionalKnapsack(items=(value(D(u)), cost(u)), capacity=left) )`
where `S` = hosts reachable from an entry using only hosts in `F` (they can never be saved).
**Pruning:** if `LB >= best_loss` the subtree is cut. **Stop:** no affordable candidate, or LB prune, or
(optional) node/time limit. **Output reconstruction:** best `I` found, then redundant isolations are removed.
A greedy plan is used as the initial incumbent (can be disabled with `--no-warm-start`).

```
BNB(I, F, left):
    R <- infected(I);  loss <- value(R)
    if loss < best: best <- loss; bestPlan <- I
    C <- { u in R \ F : cost[u] <= left }
    if C is empty: return
    S <- reach(entries ∩ F, only through F)
    UB_saving <- min(loss - value(S), fractionalKnapsack({(value(D(u)), cost[u]) : u in C}, left))
    if loss - UB_saving >= best: return              # prune
    u* <- argmax_{u in C} value(D(u)) / cost[u]
    BNB(I ∪ {u*}, F, left - cost[u*])                # isolate u*
    BNB(I, F ∪ {u*}, left)                           # never isolate u*
```

### Correctness argument (why the bound is valid, so the result is optimal)
1. Let `X = I' \ I` be the hosts isolated deeper in the subtree. Any host `w` saved by `X` (infected now,
   not infected afterwards) is either in `X`, or every attacker path to `w` crosses some `x in X`; in both
   cases `w` is reachable from some `x in X`, i.e. `w in D(x)`.
2. Every `x in X` is infected now, not in `F`, and affordable, hence it is one of the candidate items.
3. So `saving(X) <= sum_{x in X} value(D(x))` with `sum cost(x) <= left`, which is at most the optimum of
   the fractional knapsack relaxation. Hosts in `S` are never saved (all their path hosts are in `F`).
4. Therefore `loss(I') >= LB`; pruning when `LB >= best` never discards a strictly better plan
   (invariant: the incumbent is the best plan among all explored subtrees plus all pruned ones).
5. The two children partition the subtree (u* isolated / not isolated), and recursion ends because every
   level either consumes budget or adds a host to `F`, so the search is exhaustive up to pruning => optimal.
This is also checked empirically: B&B equals the exhaustive optimum in 250 random tests + 27 benchmark
instances (see `tests/`, `results/`).

### Complexity
* Per node: `candidates x (V+E)` for the `D(u)` searches (+ sort) => `O(V (V+E))`.
* Worst case number of nodes `O(2^V)` (NP-hard problem); the bound makes it much smaller in practice
  (see table). Memory `O(V)` recursion depth plus `O(V)` bitmask state (hosts are Python big-int bitmasks).
* Greedy baseline: `O(k * V * (V+E))`, `k` = hosts chosen. Brute force: `O(2^V (V+E))`.
* Measured deviations: B&B nodes are far below `2^V`, but the effort is not smooth in `n` - it depends on
  the budget and structure (e.g. n=300 took 51,961 nodes / ~10 s while n=200 took 559 nodes).

## 3. Baselines
* **Greedy**: repeatedly isolate the host with the best *actual* saving/cost ratio. Fast but can be trapped
  (small instance: loss 81 vs optimal 51; benchmark: up to ~200x worse than optimal on some instances).
* **Brute force**: all affordable subsets of reachable hosts, scored with an *independent* set-based checker
  (`evaluate_plan`), which also verifies every plan reported by the other algorithms.

## 4. Datasets (`data/`)
| Scale | Files | Size | Budget | Notes |
|---|---|---|---|---|
| Small (hand-verifiable) | `small_*.csv` | 8 hosts | 4 | Worked example below |
| Medium | `medium_*.csv` | 40 hosts | 15 | Greedy 272 vs optimal 208 |
| Large stress | `large_*.csv` | 300 hosts | 60 | Optimal in ~10 s; brute force cannot finish |
| Dirty | `dirty_*.csv` | 11 rows | 4 | Duplicates, missing/invalid values, unknown edge endpoints |

Regenerate the synthetic ones with `python3 generate_data.py` (seeded, deterministic).

**Treatment of bad data:** missing id / duplicate id (first kept) / missing, non-numeric or negative
criticality / cost <= 0 / invalid `status` or `is_entry` => the row is *rejected and reported*; missing
`is_entry` => 0 and missing `status` => active (warning); edges with unknown hosts rejected; self-loops and
duplicate edges dropped (warning). Empty file => empty network (loss 0). Wrong columns => `INPUT ERROR`, exit code 2.

### Hand-verified small instance
`E` (entry) -> `X, Y, Z`; `X->X1`; `Y->Y1`; `Z->Z1`; `Y->W`; `Z->W`. Budget 4. Affordable plans only:
`{}` loss 131; `{X}` 81; `{Y}` 101; `{Z}` 101; `{Y,Z}` **51** (isolating both parents also saves `W`).
Optimum = isolate Y and Z (51). Greedy picks X first (ratio 16.7 > 15) and ends at 81.
The program reproduces exactly these numbers (`results/demo_small.txt`).

## 5. Run it
```bash
python3 simulator.py --nodes data/small_nodes.csv --edges data/small_edges.csv --budget 4 --algo all --trace 10
python3 simulator.py --nodes data/medium_nodes.csv --edges data/medium_edges.csv --budget 15 --algo all
python3 simulator.py --nodes data/large_nodes.csv  --edges data/large_edges.csv  --budget 60 --time-limit 30
python3 simulator.py --nodes data/dirty_nodes.csv  --edges data/dirty_edges.csv  --budget 4        # validation report
python3 simulator.py ... --target-loss 40      # feasibility check      | --json  machine-readable output
python3 -m unittest discover -s tests -v       # 21 tests
python3 benchmark.py                           # -> results/benchmark.csv / .png
```
Environment: Python 3.8+ (tested on 3.13), standard library only; `matplotlib` optional for the plot.

## 6. Results (from `results/benchmark_output.txt`)
* Experiment A (n = 8..24, 27 instances): B&B loss == brute-force optimum in all 27; at n=24 B&B explored
  293-2,213 nodes vs 4,860-26,100 subsets for brute force (about 10-14x faster in time, and the gap widens with n).
* Greedy was optimal in 10 of 27 instances but up to ~213x worse in others.
* Experiment B (n = 40..300): B&B proved optimality up to n=300; greedy gap up to 60% on the n=40 case.
* Plot: `results/benchmark.png`.

## 7. Edge cases / tests (`tests/test_simulator.py`)
Empty network, no entry point, zero budget, budget below every cost, ties, cycles + self-loops, extreme
values (1e12), offline host, isolating the entry point, shared downstream host (non-additive savings),
redundant isolation removed, infeasible target; invalid input (missing column / file / bad rows / CLI exit
code 2 / negative budget); 250-instance randomized cross-check vs brute force; 300-host stress test.

## 8. Limitations and when another algorithm is better
* Worst-case spread model (no probabilities, no time dimension) - a probabilistic or temporal model would
  need Monte-Carlo simulation or DP over time.
* Exponential worst case: for very large/dense networks use the `--time-limit` anytime mode (reports gap to the
  root bound) or an ILP / Lagrangian method; greedy remains the fastest option when optimality is not needed.
* Isolation is all-or-nothing and costs are additive; partial controls (patching, rate limiting) not modelled.

## 9. Team contribution statement

Team of five. Everyone took part in the design discussion, the mentor checkpoints and the final demo.

| Member | Main contribution |
|---|---|
| Siddharth Goyal | Problem modelling; Branch and Bound algorithm, lower bound and correctness argument; integration of `simulator.py`; team coordination |
| Aareen Mishra | Datasets: hand-verified small instance, medium and large generator (`generate_data.py`); data-cleaning rules and the dirty-data test file |
| Vaibhav Srivastava | Baselines (greedy and brute force) and the benchmark experiments, tables and plot (`benchmark.py`, `results/`) |
| Sanyom Thareja | Test suite: edge cases, invalid-input tests, 250-instance randomized cross-check and the 300-host stress test (`tests/`) |
| Daksh Chaudhary | README and written report, plain-English explanation output, demo script and video |

Learning outcomes: how a valid lower bound makes Branch and Bound prune safely, why greedy can be
trapped when savings are not additive, how to verify an algorithm against an independent checker, and how to
measure and explain the gap between theory (`2^V`) and observed behaviour.
