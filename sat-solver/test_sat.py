#!/usr/bin/env python3
"""test_sat.py - validation for the from-scratch CDCL solver.

1. Hand-built SAT/UNSAT cases with known answers.
2. Random 3-SAT fuzzing cross-validated against Glucose3 (python-sat):
   same sat/unsat verdict on every instance, and any model we return must
   satisfy the formula.
3. Phase-transition sweep: clause/variable ratio vs sat fraction and conflicts.
"""
import random
import sys
import time

from sat import Solver, parse_dimacs, check_model

PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok  {name}")
    else:
        FAIL += 1
        print(f" FAIL {name}")


# ------------------------------------------------------------------ 1. hand tests
def hand_tests():
    print("== hand tests ==")
    # trivially sat
    m = Solver(2, [[1, 2], [-1]]).solve()
    check("simple sat", m is not None and check_model(2, [[1, 2], [-1]], m))
    # unit conflict
    check("unit conflict unsat", Solver(1, [[1], [-1]]).solve() is None)
    # empty clause
    check("empty clause unsat", Solver(2, [[1, 2], []]).solve() is None)
    # pigeonhole php(3,2): 3 pigeons, 2 holes -> UNSAT
    php = []
    for i in range(3):
        php.append([i * 2 + 1, i * 2 + 2])
    for i in range(3):
        for j in range(i + 1, 3):
            php.append([-(i * 2 + 1), -(j * 2 + 1)])
            php.append([-(i * 2 + 2), -(j * 2 + 2)])
    check("pigeonhole(3,2) unsat", Solver(6, php).solve() is None)
    # pigeonhole php(2,2) -> SAT
    php2 = [[1, 2], [3, 4], [-1, -3], [-2, -4]]
    m = Solver(4, php2).solve()
    check("pigeonhole(2,2) sat", m is not None and check_model(4, php2, m))
    # xor chain
    x = [[1, 2, 3], [1, -2], [-1, 2], [-3, 4], [3, 4]]
    m = Solver(4, x).solve()
    check("xor-ish sat", m is not None and check_model(4, x, m))
    # tautology removal
    m = Solver(2, [[1, -1, 2], [1]]).solve()
    check("tautology drop", m is not None and check_model(2, [[1, -1, 2], [1]], m))
    # learned clause path: force a real conflict analysis (not level-0)
    # (a v b) & (~a v b) & (a v ~b) & (~a v ~b)  -> UNSAT, needs decisions
    hard = [[1, 2], [-1, 2], [1, -2], [-1, -2]]
    s = Solver(2, hard)
    m = s.solve()
    check("2x2 full unsat", m is None and s.n_conflicts > 0)
    # DIMACS round trip
    dimacs = "c comment\np cnf 2 2\n1 2 0\n-1 0\n"
    n, cl = parse_dimacs(dimacs)
    check("dimacs parse", n == 2 and cl == [[1, 2], [-1]])


def rand_3sat(n, m, rng):
    clauses = []
    for _ in range(m):
        vs = rng.sample(range(1, n + 1), 3)
        clauses.append([v if rng.random() < 0.5 else -v for v in vs])
    return clauses


# ------------------------------------------------------------------ 2. cross-validation
def cross_validate(trials=300):
    print("== cross-validation vs Glucose3 ==")
    from pysat.solvers import Glucose3
    rng = random.Random(20261008)
    mism = 0
    t0 = time.time()
    for t in range(trials):
        n = rng.randint(10, 45)
        m = rng.randint(n, int(5.5 * n))
        clauses = rand_3sat(n, m, rng)
        mine = Solver(n, clauses).solve()
        g = Glucose3()
        for c in clauses:
            g.add_clause(c)
        g_sat = g.solve()
        g.delete()
        if (mine is None) != (not g_sat):
            mism += 1
            print(f"  MISMATCH trial {t}: n={n} m={m} mine={mine is not None} glucose={g_sat}")
        elif mine is not None and not check_model(n, clauses, mine):
            mism += 1
            print(f"  BAD MODEL trial {t}")
    dt = time.time() - t0
    check(f"cross-val {trials} random 3-SAT vs glucose (0 mismatches)", mism == 0)
    print(f"  ({dt:.1f}s total for both solvers)")


def learned_clause_soundness():
    """Every learned clause must be entailed by the original formula:
    orig /\ ~L must be UNSAT (checked by Glucose). This is the regression
    test for the first-UIP bug (stale `seen` set) found 2026-10-08."""
    print("== learned-clause soundness ==")
    import sat as satmod
    from pysat.solvers import Glucose3
    orig_analyze = satmod.Solver.analyze_conflict
    bad = []

    def checked(self, conflict_cid):
        learned, uip, bj = orig_analyze(self, conflict_cid)
        g = Glucose3()
        for c in checked.orig:
            g.add_clause(c)
        for l in learned:
            g.add_clause([-l])
        if g.solve():
            bad.append(list(learned))
        g.delete()
        return learned, uip, bj

    satmod.Solver.analyze_conflict = checked
    try:
        rng = random.Random(999)
        for t in range(15):
            n = rng.randint(20, 50)
            clauses = rand_3sat(n, int(4.26 * n), rng)  # hardest region
            checked.orig = clauses
            Solver(n, clauses).solve()
    finally:
        satmod.Solver.analyze_conflict = orig_analyze
    check(f"learned-clause soundness (0 unsound of all learned)", len(bad) == 0)
    if bad:
        print("  example unsound:", bad[0])


def stress():
    print("== stress ==")
    from pysat.solvers import Glucose3
    # bigger random instances
    rng = random.Random(31337)
    ok = True
    t0 = time.time()
    for t in range(10):
        n = 120
        clauses = rand_3sat(n, int(4.26 * n), rng)
        mine = Solver(n, clauses).solve()
        g = Glucose3()
        for c in clauses:
            g.add_clause(c)
        gs = g.solve()
        g.delete()
        if (mine is None) != (not gs) or (mine is not None and not check_model(n, clauses, mine)):
            ok = False
            print(f"  mismatch at n=120 trial {t}")
    print(f"  10x n=120 3-SAT in {time.time()-t0:.1f}s")
    check("stress n=120 matches glucose", ok)
    # pigeonhole scaling (CDCL should crush these)
    t0 = time.time()
    php = []
    P, H = 8, 7
    for i in range(P):
        php.append([i * H + h + 1 for h in range(H)])
    for h in range(H):
        for i in range(P):
            for j in range(i + 1, P):
                php.append([-(i * H + h + 1), -(j * H + h + 1)])
    s = Solver(P * H, php)
    check("pigeonhole(8,7) unsat", s.solve() is None)
    print(f"  pigeonhole(8,7): {s.n_conflicts} conflicts in {time.time()-t0:.2f}s")


# ------------------------------------------------------------------ 3. phase transition
def phase_transition():
    print("== phase transition (random 3-SAT, n=30, 25 seeds/ratio) ==")
    from pysat.solvers import Glucose3
    rng = random.Random(77)
    print("  ratio  sat%   avg_conflicts  avg_decisions")
    for ratio in [2.0, 2.5, 3.0, 3.5, 4.0, 4.26, 4.5, 5.0, 6.0]:
        sat_n = 0
        tc = td = 0
        n = 30
        m = int(ratio * n)
        for _ in range(25):
            clauses = rand_3sat(n, m, rng)
            s = Solver(n, clauses)
            model = s.solve()
            g = Glucose3()
            for c in clauses:
                g.add_clause(c)
            gs = g.solve()
            g.delete()
            assert (model is None) == (not gs), "verdict mismatch in sweep"
            if model is not None:
                sat_n += 1
            tc += s.n_conflicts
            td += s.n_decisions
        print(f"  {ratio:5.2f}  {sat_n/25:4.0%}   {tc/25:9.1f}  {td/25:9.1f}")


if __name__ == "__main__":
    hand_tests()
    cross_validate(300)
    learned_clause_soundness()
    stress()
    phase_transition()
    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)
