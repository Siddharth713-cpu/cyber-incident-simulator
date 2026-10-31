#!/usr/bin/env python3
"""Cyber Incident Propagation Simulator - Branch and Bound containment planner.

Problem (see README.md for the full model):
  Hosts form a directed network (an edge u->v means "an attacker on u can move
  to v").  Some hosts are attacker entry points.  Every host has a criticality
  (value lost if compromised) and an isolation cost (effort to quarantine it).
  With a limited isolation budget, choose hosts to isolate so that the total
  criticality of compromised hosts (worst case: the attacker reaches everything
  reachable) is minimal.

Algorithms:
  * Branch and Bound (required paradigm) - exact, with a valid lower bound
  * Greedy (baseline 1)                  - best saving/cost ratio, repeatedly
  * Brute force (baseline 2)             - exhaustive over affordable subsets,
                                           evaluated with an independent checker
"""
import argparse
import csv
import json
import math
import os
import sys
import time

EPS = 1e-9
TRUE_WORDS = {"1", "true", "yes", "y", "t"}
FALSE_WORDS = {"0", "false", "no", "n", "f"}
NODE_COLUMNS = ["id", "criticality", "isolation_cost", "is_entry", "status"]
EDGE_COLUMNS = ["src", "dst"]


class ValidationError(Exception):
    """Raised when the input cannot be used at all (bad schema, bad budget)."""


# --------------------------------------------------------------------------
# Input handling
# --------------------------------------------------------------------------
def _num(value, field):
    if value is None or str(value).strip() == "":
        raise ValueError("missing %s" % field)
    try:
        v = float(str(value).strip())
    except ValueError:
        raise ValueError("non-numeric %s: %r" % (field, value))
    if math.isnan(v) or math.isinf(v):
        raise ValueError("%s is not finite: %r" % (field, value))
    return int(v) if v.is_integer() else v


class Network:
    """Validated network.  Node i has successors bitmask adj[i]."""

    def __init__(self):
        self.ids = []
        self.names = []
        self.crit = []
        self.cost = []
        self.entry_mask = 0
        self.offline_mask = 0
        self.adj = []
        self.edges = []          # (src_idx, dst_idx) kept for the independent checker
        self.rejected = []       # (where, reason)
        self.warnings = []
        self.index = {}

    @property
    def n(self):
        return len(self.ids)

    @property
    def full_mask(self):
        return (1 << self.n) - 1

    @classmethod
    def from_records(cls, node_rows, edge_rows=()):
        net = cls()
        for lineno, row in enumerate(node_rows, start=2):
            where = "nodes row %d" % lineno
            nid = str(row.get("id") if row.get("id") is not None else "").strip()
            if not nid:
                net.rejected.append((where, "missing id"))
                continue
            if nid in net.index:
                net.rejected.append((where, "duplicate id %r (first occurrence kept)" % nid))
                continue
            try:
                crit = _num(row.get("criticality"), "criticality")
                cost = _num(row.get("isolation_cost"), "isolation_cost")
            except ValueError as exc:
                net.rejected.append((where, "%s (id %s)" % (exc, nid)))
                continue
            if crit < 0:
                net.rejected.append((where, "negative criticality (id %s)" % nid))
                continue
            if cost <= 0:
                net.rejected.append((where, "isolation_cost must be > 0 (id %s)" % nid))
                continue
            raw_entry = str(row.get("is_entry") if row.get("is_entry") is not None else "").strip().lower()
            if raw_entry in TRUE_WORDS:
                is_entry = True
            elif raw_entry in FALSE_WORDS:
                is_entry = False
            elif raw_entry == "":
                is_entry = False
                net.warnings.append("%s: is_entry missing for %s, assumed 0" % (where, nid))
            else:
                net.rejected.append((where, "invalid is_entry %r (id %s)" % (raw_entry, nid)))
                continue
            raw_status = str(row.get("status") if row.get("status") is not None else "").strip().lower()
            if raw_status == "":
                raw_status = "active"
                net.warnings.append("%s: status missing for %s, assumed active" % (where, nid))
            if raw_status not in ("active", "offline"):
                net.rejected.append((where, "invalid status %r (id %s)" % (raw_status, nid)))
                continue
            i = len(net.ids)
            net.index[nid] = i
            net.ids.append(nid)
            name = row.get("name")
            net.names.append(str(name).strip() if name not in (None, "") else nid)
            net.crit.append(crit)
            net.cost.append(cost)
            if is_entry:
                net.entry_mask |= 1 << i
            if raw_status == "offline":
                net.offline_mask |= 1 << i
        net.adj = [0] * net.n
        seen = set()
        for lineno, row in enumerate(edge_rows, start=2):
            where = "edges row %d" % lineno
            s = str(row.get("src") if row.get("src") is not None else "").strip()
            d = str(row.get("dst") if row.get("dst") is not None else "").strip()
            if s not in net.index or d not in net.index:
                net.rejected.append((where, "unknown node in edge %r -> %r" % (s, d)))
                continue
            if s == d:
                net.warnings.append("%s: self-loop on %s dropped" % (where, s))
                continue
            key = (net.index[s], net.index[d])
            if key in seen:
                net.warnings.append("%s: duplicate edge %s -> %s dropped" % (where, s, d))
                continue
            seen.add(key)
            net.edges.append(key)
            net.adj[key[0]] |= 1 << key[1]
        return net


def _read_csv(path, required):
    if not os.path.exists(path):
        raise ValidationError("file not found: %s" % path)
    with open(path, newline="", encoding="utf-8-sig") as fh:
        text = fh.read()
    if text.strip() == "":
        return [], True
    reader = csv.DictReader(text.splitlines())
    header = [h.strip() for h in (reader.fieldnames or [])]
    missing = [c for c in required if c not in header]
    if missing:
        raise ValidationError("%s: missing required column(s): %s" % (path, ", ".join(missing)))
    rows = []
    for row in reader:
        rows.append({(k or "").strip(): (v.strip() if isinstance(v, str) else v) for k, v in row.items()})
    return rows, False


def load_network(nodes_path, edges_path=None):
    node_rows, empty = _read_csv(nodes_path, NODE_COLUMNS)
    edge_rows = []
    if edges_path:
        edge_rows, _ = _read_csv(edges_path, EDGE_COLUMNS)
    net = Network.from_records(node_rows, edge_rows)
    if empty:
        net.warnings.append("%s is empty: network has no hosts" % nodes_path)
    return net


# --------------------------------------------------------------------------
# Independent checker (plain sets, no bitmasks) - used to verify every result
# --------------------------------------------------------------------------
def evaluate_plan(net, plan_idx):
    """Return (loss, infected_idx_set, plan_cost) for isolating hosts plan_idx."""
    blocked = set(plan_idx) | {i for i in range(net.n) if (net.offline_mask >> i) & 1}
    succ = {i: [] for i in range(net.n)}
    for s, d in net.edges:
        succ[s].append(d)
    stack = [i for i in range(net.n) if (net.entry_mask >> i) & 1 and i not in blocked]
    seen = set(stack)
    while stack:
        u = stack.pop()
        for v in succ[u]:
            if v not in blocked and v not in seen:
                seen.add(v)
                stack.append(v)
    loss = sum(net.crit[i] for i in seen)
    cost = sum(net.cost[i] for i in set(plan_idx))
    return loss, seen, cost


def bits(mask):
    while mask:
        low = mask & -mask
        yield low.bit_length() - 1
        mask ^= low


# --------------------------------------------------------------------------
# Solvers
# --------------------------------------------------------------------------
class Stats:
    def __init__(self):
        self.nodes = 0           # B&B nodes explored
        self.pruned = 0          # nodes cut by the bound
        self.leaves = 0
        self.bound_evals = 0
        self.reach_calls = 0     # elementary graph-search operations
        self.subsets = 0         # brute force subsets evaluated
        self.incumbent_updates = 0
        self.max_depth = 0

    def as_dict(self):
        return dict(self.__dict__)


class Engine:
    def __init__(self, net, budget):
        self.net = net
        self.budget = budget
        self.base_allowed = net.full_mask & ~net.offline_mask
        self.entry = net.entry_mask & self.base_allowed
        self.tables = self._build_tables(net.crit)
        self.stats = Stats()

    @staticmethod
    def _build_tables(vals):
        tables = []
        for base in range(0, len(vals), 8):
            chunk = vals[base:base + 8]
            t = [0] * 256
            for b in range(1, 256):
                low = b & -b
                i = low.bit_length() - 1
                t[b] = t[b ^ low] + (chunk[i] if i < len(chunk) else 0)
            tables.append(t)
        return tables

    def val(self, mask):
        s = 0
        k = 0
        while mask:
            s += self.tables[k][mask & 255]
            mask >>= 8
            k += 1
        return s

    def reach(self, start, allowed):
        """Hosts reachable from `start` moving only through `allowed` hosts."""
        self.stats.reach_calls += 1
        adj = self.net.adj
        seen = start & allowed
        frontier = seen
        while frontier:
            nxt = 0
            m = frontier
            while m:
                low = m & -m
                nxt |= adj[low.bit_length() - 1]
                m ^= low
            nxt &= allowed & ~seen
            seen |= nxt
            frontier = nxt
        return seen

    def infected(self, isolated):
        allowed = self.base_allowed & ~isolated
        return self.reach(self.entry & allowed, allowed)

    def plan_cost(self, mask):
        return sum(self.net.cost[i] for i in bits(mask))

    # ---- Greedy baseline -------------------------------------------------
    def greedy(self):
        isolated = 0
        left = self.budget
        while True:
            allowed = self.base_allowed & ~isolated
            R = self.reach(self.entry & allowed, allowed)
            loss = self.val(R)
            best = None
            for u in bits(R):
                c = self.net.cost[u]
                if c > left:
                    continue
                a2 = allowed & ~(1 << u)
                saving = loss - self.val(self.reach(self.entry & a2, a2))
                if saving > EPS:
                    key = (saving / c, -u)
                    if best is None or key > best[0]:
                        best = (key, u)
            if best is None:
                return isolated
            isolated |= 1 << best[1]
            left -= self.net.cost[best[1]]

    # ---- Branch and Bound ------------------------------------------------
    def bnb(self, warm_start=True, node_limit=None, time_limit=None, trace=0):
        net = self.net
        st = self.stats
        self._t0 = time.perf_counter()
        self._node_limit = node_limit
        self._time_limit = time_limit
        self._trace_left = trace
        self.trace_lines = []
        self.limit_hit = False
        self.root_lb = None

        self.best_mask = 0
        self.best_loss = self.val(self.infected(0))
        if warm_start:
            g = self.greedy()
            gl = self.val(self.infected(g))
            if gl < self.best_loss - EPS:
                self.best_mask, self.best_loss = g, gl
        self._search(0, 0, self.budget, 0)
        self._polish()
        return self.best_mask

    def _log(self, depth, isolated, loss, lb, action):
        if self._trace_left <= 0:
            return
        self._trace_left -= 1
        names = ",".join(self.net.ids[i] for i in bits(isolated)) or "-"
        lb_txt = "n/a" if lb is None else ("%.4g" % lb)
        self.trace_lines.append(
            "node %-4d depth=%-2d isolated={%s} loss=%.4g LB=%s best=%.4g -> %s"
            % (self.stats.nodes, depth, names, loss, lb_txt, self.best_loss, action))

    def _out_of_budget(self):
        if self._node_limit is not None and self.stats.nodes >= self._node_limit:
            return True
        if self._time_limit is not None and time.perf_counter() - self._t0 > self._time_limit:
            return True
        return False

    def _search(self, isolated, forbidden, left, depth):
        if self.limit_hit:
            return
        if self._out_of_budget():
            self.limit_hit = True
            return
        net, st = self.net, self.stats
        st.nodes += 1
        st.max_depth = max(st.max_depth, depth)

        allowed = self.base_allowed & ~isolated
        R = self.reach(self.entry & allowed, allowed)
        loss = self.val(R)
        if loss < self.best_loss - EPS:
            self.best_loss, self.best_mask = loss, isolated
            st.incumbent_updates += 1

        items = []
        for u in bits(R & ~forbidden):
            c = net.cost[u]
            if c <= left:
                D = self.reach(1 << u, allowed)
                items.append((self.val(D) / c, u, self.val(D), c))
        if not items:
            st.leaves += 1
            if depth == 0:
                self.root_lb = loss
            self._log(depth, isolated, loss, loss, "leaf (no affordable candidate)")
            return

        # Lower bound on the loss of ANY plan in this subtree:
        #  saved hosts must lie downstream of an isolated host (D(u)), and
        #  hosts reachable from an entry through never-isolated hosts stay infected.
        st.bound_evals += 1
        sure = self.reach(self.entry & forbidden & allowed, allowed & forbidden)
        cap = loss - self.val(sure)
        items.sort(key=lambda t: (-t[0], t[1]))
        remaining, ub = left, 0
        for ratio, u, profit, c in items:
            if c <= remaining:
                ub += profit
                remaining -= c
            else:
                ub += profit * remaining / c
                break
        lb = loss - min(cap, ub)
        if depth == 0:
            self.root_lb = lb
        if lb >= self.best_loss - EPS:
            st.pruned += 1
            self._log(depth, isolated, loss, lb, "PRUNED (LB >= best)")
            return

        _, u, _, c = items[0]
        self._log(depth, isolated, loss, lb,
                  "branch on %s (ratio %.4g): isolate first, then forbid" % (net.ids[u], items[0][0]))
        self._search(isolated | (1 << u), forbidden, left - c, depth + 1)
        self._search(isolated, forbidden | (1 << u), left, depth + 1)

    def _polish(self):
        """Drop isolations that do not change the loss (keeps plans minimal)."""
        mask = self.best_mask
        target = self.val(self.infected(mask))
        for u in sorted(bits(mask), key=lambda i: (-self.net.cost[i], i)):
            trial = mask & ~(1 << u)
            if self.val(self.infected(trial)) <= target + EPS:
                mask = trial
        self.best_mask = mask
        self.best_loss = self.val(self.infected(mask))

    # ---- Brute force baseline (uses the independent checker) -------------
    def brute(self, time_limit=None):
        net = self.net
        t0 = time.perf_counter()
        _, reachable, _ = evaluate_plan(net, [])
        rel = sorted(reachable)             # isolating unreachable hosts never helps
        best = [None, None, None]           # loss, cost, plan
        self.limit_hit = False

        def rec(i, chosen, cost):
            if self.limit_hit:
                return
            if time_limit is not None and time.perf_counter() - t0 > time_limit:
                self.limit_hit = True
                return
            if i == len(rel):
                self.stats.subsets += 1
                loss, _, c = evaluate_plan(net, chosen)
                if best[0] is None or loss < best[0] - EPS or (abs(loss - best[0]) <= EPS and c < best[1]):
                    best[0], best[1], best[2] = loss, c, list(chosen)
                return
            rec(i + 1, chosen, cost)
            u = rel[i]
            if cost + net.cost[u] <= self.budget:
                chosen.append(u)
                rec(i + 1, chosen, cost + net.cost[u])
                chosen.pop()

        sys.setrecursionlimit(max(10000, 4 * len(rel) + 100))
        rec(0, [], 0)
        plan = best[2] or []
        mask = 0
        for u in plan:
            mask |= 1 << u
        return mask


# --------------------------------------------------------------------------
# Running + reporting
# --------------------------------------------------------------------------
def run_algorithm(net, budget, algo, **opts):
    eng = Engine(net, budget)
    sys.setrecursionlimit(max(10000, net.n * 4 + 100))
    t0 = time.perf_counter()
    if algo == "bnb":
        mask = eng.bnb(warm_start=opts.get("warm_start", True),
                       node_limit=opts.get("node_limit"),
                       time_limit=opts.get("time_limit"),
                       trace=opts.get("trace", 0))
    elif algo == "greedy":
        mask = eng.greedy()
    elif algo == "brute":
        mask = eng.brute(time_limit=opts.get("time_limit"))
    else:
        raise ValueError("unknown algorithm %r" % algo)
    runtime = time.perf_counter() - t0

    plan = sorted(bits(mask))
    loss, infected, cost = evaluate_plan(net, plan)          # independent verification
    internal_loss = eng.val(eng.infected(mask))
    base_loss = evaluate_plan(net, [])[0]
    complete = not getattr(eng, "limit_hit", False)
    lb = getattr(eng, "root_lb", None)
    res = {
        "algorithm": algo,
        "plan": [net.ids[i] for i in plan],
        "plan_cost": cost,
        "budget": budget,
        "budget_violation": max(0, cost - budget),
        "loss": loss,
        "loss_without_action": base_loss,
        "infected": sorted(net.ids[i] for i in infected),
        "verified": abs(loss - internal_loss) <= 1e-6 * max(1, abs(loss)),
        "runtime_s": runtime,
        "complete": complete,
        "stats": eng.stats.as_dict(),
        "root_lower_bound": lb,
    }
    if algo == "bnb":
        res["status"] = "OPTIMAL (proved)" if complete else "BEST FOUND (limit reached, not proved)"
        if lb is not None and loss > 0:
            res["gap_to_bound"] = max(0.0, (loss - lb) / loss) if not complete else 0.0
        else:
            res["gap_to_bound"] = 0.0
        res["trace"] = eng.trace_lines
    elif algo == "brute":
        res["status"] = "OPTIMAL (exhaustive)" if complete else "INCOMPLETE (time limit)"
    else:
        res["status"] = "HEURISTIC (no optimality guarantee)"
    res["_eng"] = eng
    return res


def explain(net, res, target_loss=None):
    """Plain-English explanation for a non-specialist."""
    eng = res.pop("_eng", None)
    names = {net.ids[i]: i for i in range(net.n)}
    total = sum(net.crit[i] for i in range(net.n) if not (net.offline_mask >> i) & 1)
    entries = [net.ids[i] for i in bits(net.entry_mask & ~net.offline_mask)]
    lines = []
    if not entries:
        lines.append("No attacker entry point is defined (or all are offline), so nothing can be compromised.")
        return lines
    base, after = res["loss_without_action"], res["loss"]
    lines.append("Attack starts at: %s." % ", ".join(entries))
    lines.append("With no action, the attacker can reach %d host(s) worth %s of %s total criticality."
                 % (len(evaluate_plan(net, [])[1]), _fmt(base), _fmt(total)))
    if not res["plan"]:
        if res["budget"] <= 0:
            lines.append("The budget is 0, so nothing can be isolated.")
        elif base <= 0:
            lines.append("There is nothing to protect.")
        else:
            lines.append("No affordable isolation reduces the damage, so the plan is empty.")
    else:
        lines.append("Recommended: isolate %s (cost %s of budget %s)."
                     % (", ".join(res["plan"]), _fmt(res["plan_cost"]), _fmt(res["budget"])))
        plan_idx = [names[x] for x in res["plan"]]
        for x in res["plan"]:
            rest = [i for i in plan_idx if net.ids[i] != x]
            marginal = evaluate_plan(net, rest)[0] - after
            lines.append("  - %s: removing it from the plan would add %s of loss." % (x, _fmt(marginal)))
        pct = 100.0 * (base - after) / base if base > 0 else 0.0
        lines.append("Worst-case loss falls from %s to %s (%.0f%% reduction)." % (_fmt(base), _fmt(after), pct))
    if res["infected"]:
        top = sorted(res["infected"], key=lambda x: -net.crit[names[x]])[:5]
        lines.append("Still exposed (highest value first): %s." % ", ".join(
            "%s (%s)" % (x, _fmt(net.crit[names[x]])) for x in top))
    lines.append("Result quality: %s." % res["status"])
    if target_loss is not None:
        if after <= target_loss + EPS:
            lines.append("Target loss <= %s: ACHIEVED." % _fmt(target_loss))
        elif res["complete"] and res["algorithm"] in ("bnb", "brute"):
            lines.append("Target loss <= %s: INFEASIBLE within this budget (the best possible is %s). "
                         "Increase the budget or relax the target." % (_fmt(target_loss), _fmt(after)))
        else:
            lines.append("Target loss <= %s: not reached by this (non-proven) plan." % _fmt(target_loss))
    return lines


def _fmt(x):
    if isinstance(x, float) and not x.is_integer():
        return "%.4g" % x
    return "%d" % x if float(x).is_integer() else str(x)


def print_validation(net, out=sys.stdout):
    out.write("Input: %d host(s) accepted, %d edge(s), %d entry point(s), %d offline.\n" % (
        net.n, len(net.edges), bin(net.entry_mask).count("1"), bin(net.offline_mask).count("1")))
    for where, why in net.rejected:
        out.write("  REJECTED %s: %s\n" % (where, why))
    for w in net.warnings:
        out.write("  note: %s\n" % w)


def print_table(results, out=sys.stdout):
    out.write("\n%-8s %-12s %10s %10s %12s %12s %s\n" % (
        "algo", "loss", "cost", "runtime_s", "explored", "pruned", "status"))
    for r in results:
        st = r["stats"]
        explored = st["nodes"] if r["algorithm"] == "bnb" else (
            st["subsets"] if r["algorithm"] == "brute" else st["reach_calls"])
        out.write("%-8s %-12s %10s %10.4f %12d %12d %s\n" % (
            r["algorithm"], _fmt(r["loss"]), _fmt(r["plan_cost"]), r["runtime_s"],
            explored, st["pruned"], r["status"]))


def main(argv=None):
    p = argparse.ArgumentParser(description="Cyber Incident Propagation Simulator (Branch and Bound)")
    p.add_argument("--nodes", required=True, help="nodes CSV: id,criticality,isolation_cost,is_entry,status[,name]")
    p.add_argument("--edges", help="edges CSV: src,dst")
    p.add_argument("--budget", type=float, required=True, help="total isolation budget")
    p.add_argument("--algo", choices=["bnb", "greedy", "brute", "all"], default="bnb")
    p.add_argument("--trace", type=int, default=0, help="print the first N branch-and-bound steps")
    p.add_argument("--target-loss", type=float, help="acceptable worst-case loss; reports feasibility")
    p.add_argument("--node-limit", type=int, help="stop B&B after this many nodes")
    p.add_argument("--time-limit", type=float, help="stop B&B / brute force after this many seconds")
    p.add_argument("--no-warm-start", action="store_true", help="do not seed B&B with the greedy plan")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    args = p.parse_args(argv)

    try:
        if args.budget < 0 or math.isnan(args.budget):
            raise ValidationError("budget must be >= 0")
        net = load_network(args.nodes, args.edges)
    except ValidationError as exc:
        sys.stderr.write("INPUT ERROR: %s\n" % exc)
        return 2

    budget = int(args.budget) if float(args.budget).is_integer() else args.budget
    algos = ["bnb", "greedy", "brute"] if args.algo == "all" else [args.algo]
    results = []
    for a in algos:
        results.append(run_algorithm(net, budget, a, node_limit=args.node_limit,
                                     time_limit=args.time_limit, trace=args.trace,
                                     warm_start=not args.no_warm_start))

    if args.json:
        for r in results:
            r.pop("_eng", None)
        json.dump({"validation": {"rejected": net.rejected, "warnings": net.warnings},
                   "results": results}, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    print_validation(net)
    for r in results:
        if r["algorithm"] == "bnb" and r.get("trace"):
            print("\nBranch-and-bound trace (first %d nodes):" % len(r["trace"]))
            for line in r["trace"]:
                print("  " + line)
    main_res = results[0]
    print("\n=== Explanation (%s) ===" % main_res["algorithm"])
    for line in explain(net, main_res, args.target_loss):
        print(line)
    for r in results[1:]:
        r.pop("_eng", None)
    print_table(results)
    if args.algo == "all":
        opt = min(r["loss"] for r in results if r["complete"])
        for r in results:
            gap = 100.0 * (r["loss"] - opt) / opt if opt > 0 else 0.0
            print("  %s gap from best-known optimum: %.1f%%" % (r["algorithm"], gap))
    return 0


if __name__ == "__main__":
    sys.exit(main())
