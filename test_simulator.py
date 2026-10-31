"""Run:  python3 -m unittest discover -s tests -v"""
import os
import random
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from generate_data import make_records                      # noqa: E402
from simulator import (Network, ValidationError, evaluate_plan, load_network,   # noqa: E402
                       run_algorithm)


def net_of(nodes, edges=()):
    """nodes: (id, crit, cost, entry[, status]) tuples; edges: (src, dst)."""
    rows = []
    for t in nodes:
        rows.append({"id": t[0], "criticality": t[1], "isolation_cost": t[2], "is_entry": t[3],
                     "status": t[4] if len(t) > 4 else "active"})
    return Network.from_records(rows, [{"src": s, "dst": d} for s, d in edges])


def solve(net, budget, algo="bnb", **kw):
    r = run_algorithm(net, budget, algo, **kw)
    r.pop("_eng", None)
    return r


class SmallInstance(unittest.TestCase):
    def test_hand_verified_optimum_and_greedy_trap(self):
        net = load_network(os.path.join(ROOT, "data/small_nodes.csv"), os.path.join(ROOT, "data/small_edges.csv"))
        self.assertEqual(solve(net, 4)["loss"], 51)                 # isolate Y and Z
        self.assertEqual(sorted(solve(net, 4)["plan"]), ["Y", "Z"])
        self.assertEqual(solve(net, 4, "greedy")["loss"], 81)       # greedy picks X
        self.assertEqual(solve(net, 4, "brute")["loss"], 51)


class EdgeCases(unittest.TestCase):
    def test_1_empty_network(self):
        net = Network.from_records([], [])
        r = solve(net, 5)
        self.assertEqual((r["loss"], r["plan"]), (0, []))

    def test_2_no_entry_point(self):
        net = net_of([("A", 5, 1, 0), ("B", 7, 1, 0)], [("A", "B")])
        self.assertEqual(solve(net, 3)["loss"], 0)

    def test_3_zero_budget(self):
        net = net_of([("E", 1, 9, 1), ("A", 5, 1, 0)], [("E", "A")])
        r = solve(net, 0)
        self.assertEqual((r["loss"], r["plan"]), (6, []))

    def test_4_budget_below_every_cost_is_infeasible_to_improve(self):
        net = net_of([("E", 1, 9, 1), ("A", 5, 4, 0)], [("E", "A")])
        r = solve(net, 3)
        self.assertEqual(r["loss"], 6)
        self.assertEqual(r["budget_violation"], 0)

    def test_5_ties_are_deterministic(self):
        net = net_of([("E", 1, 99, 1), ("A", 10, 2, 0), ("B", 10, 2, 0)], [("E", "A"), ("E", "B")])
        a, b = solve(net, 2), solve(net, 2)
        self.assertEqual(a["plan"], b["plan"])
        self.assertEqual(a["loss"], 11)

    def test_6_cycles_and_self_loops(self):
        net = net_of([("E", 1, 99, 1), ("A", 3, 1, 0), ("B", 4, 1, 0)],
                     [("E", "A"), ("A", "B"), ("B", "A"), ("A", "A")])
        self.assertEqual(solve(net, 1)["loss"], 1)
        self.assertEqual(solve(net, 1, "brute")["loss"], 1)

    def test_7_extreme_values(self):
        big = 10 ** 12
        net = net_of([("E", 1, 10 ** 9, 1), ("A", big, 1, 0), ("B", big, 1, 0)], [("E", "A"), ("E", "B")])
        self.assertEqual(solve(net, 1)["loss"], big + 1)

    def test_8_offline_host_blocks_spread(self):
        net = net_of([("E", 1, 99, 1), ("A", 50, 1, 0, "offline"), ("B", 9, 1, 0)], [("E", "A"), ("A", "B")])
        self.assertEqual(solve(net, 0)["loss"], 1)

    def test_9_entry_point_can_be_isolated(self):
        net = net_of([("E", 100, 2, 1), ("A", 50, 5, 0)], [("E", "A")])
        r = solve(net, 2)
        self.assertEqual((r["plan"], r["loss"]), (["E"], 0))

    def test_10_shared_downstream_needs_both_parents(self):
        net = net_of([("E", 1, 99, 1), ("P", 1, 1, 0), ("Q", 1, 1, 0), ("S", 100, 99, 0)],
                     [("E", "P"), ("E", "Q"), ("P", "S"), ("Q", "S")])
        self.assertEqual(solve(net, 1)["loss"], 102)
        self.assertEqual(solve(net, 2)["loss"], 1)

    def test_11_unnecessary_isolation_is_removed(self):
        net = net_of([("E", 1, 99, 1), ("A", 0, 1, 0), ("B", 5, 1, 0)], [("E", "A"), ("E", "B")])
        self.assertEqual(solve(net, 2)["plan"], ["B"])

    def test_12_target_infeasible_message(self):
        from simulator import explain
        net = net_of([("E", 1, 99, 1), ("A", 5, 4, 0)], [("E", "A")])
        r = run_algorithm(net, 1, "bnb")
        text = " ".join(explain(net, r, target_loss=0))
        self.assertIn("INFEASIBLE", text)


class InvalidInput(unittest.TestCase):
    def _write(self, d, name, text):
        p = os.path.join(d, name)
        with open(p, "w") as fh:
            fh.write(text)
        return p

    def test_missing_column_raises(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, "n.csv", "id,criticality\nA,1\n")
            with self.assertRaises(ValidationError):
                load_network(p)

    def test_missing_file_raises(self):
        with self.assertRaises(ValidationError):
            load_network("/no/such/file.csv")

    def test_bad_records_are_rejected_not_crashing(self):
        net = Network.from_records([
            {"id": "A", "criticality": "x", "isolation_cost": 1, "is_entry": 1, "status": "active"},
            {"id": "B", "criticality": -1, "isolation_cost": 1, "is_entry": 0, "status": "active"},
            {"id": "C", "criticality": 1, "isolation_cost": 0, "is_entry": 0, "status": "active"},
            {"id": "D", "criticality": 1, "isolation_cost": 1, "is_entry": 0, "status": "weird"},
            {"id": "D", "criticality": 1, "isolation_cost": 1, "is_entry": 0, "status": "active"},
            {"id": "D", "criticality": 1, "isolation_cost": 1, "is_entry": 0, "status": "active"}])
        self.assertEqual(net.ids, ["D"])
        self.assertEqual(len(net.rejected), 5)

    def test_cli_exit_code_2_on_invalid_input(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, "n.csv", "wrong,header\n1,2\n")
            r = subprocess.run([sys.executable, os.path.join(ROOT, "simulator.py"), "--nodes", p, "--budget", "3"],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 2)
            self.assertIn("INPUT ERROR", r.stderr)

    def test_cli_negative_budget_rejected(self):
        r = subprocess.run([sys.executable, os.path.join(ROOT, "simulator.py"), "--nodes",
                            os.path.join(ROOT, "data/small_nodes.csv"), "--budget", "-1"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)


class Correctness(unittest.TestCase):
    def test_bnb_equals_brute_force_on_random_instances(self):
        rng = random.Random(2024)
        for trial in range(250):
            n = rng.randint(4, 13)
            nodes, edges = make_records(max(n, 4), rng.randint(0, 10 ** 6), entries=rng.randint(1, 2))
            for r in nodes:                                  # shuffle costs/values to widen coverage
                if not r["is_entry"]:
                    r["isolation_cost"] = rng.randint(1, 6)
                    r["criticality"] = rng.randint(0, 30)
            net = Network.from_records(nodes, edges)
            budget = rng.randint(0, 14)
            bb, bf = solve(net, budget), solve(net, budget, "brute")
            self.assertAlmostEqual(bb["loss"], bf["loss"], msg="trial %d" % trial)
            self.assertLessEqual(bb["plan_cost"], budget)
            self.assertTrue(bb["verified"])
            self.assertLessEqual(bb["loss"], solve(net, budget, "greedy")["loss"] + 1e-9)

    def test_plan_never_exceeds_budget_and_matches_checker(self):
        nodes, edges = make_records(60, 3)
        net = Network.from_records(nodes, edges)
        r = solve(net, 25)
        idx = [net.index[x] for x in r["plan"]]
        loss, _, cost = evaluate_plan(net, idx)
        self.assertEqual((loss, cost), (r["loss"], r["plan_cost"]))
        self.assertLessEqual(cost, 25)


class Stress(unittest.TestCase):
    def test_large_network_finishes_with_limit_and_valid_plan(self):
        nodes, edges = make_records(300, 11, entries=3)
        net = Network.from_records(nodes, edges)
        r = solve(net, 60, time_limit=5)
        self.assertLessEqual(r["plan_cost"], 60)
        self.assertLessEqual(r["loss"], solve(net, 60, "greedy")["loss"])
        self.assertLess(r["runtime_s"], 15)


if __name__ == "__main__":
    unittest.main()
