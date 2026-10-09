#!/usr/bin/env python3
"""schedule.py - plan Kyle's tree-work week as a SAT problem.

Jobs compete for a 5-day week (Mon-Fri) and for exclusive equipment
(chipper, bucket truck, stump grinder). Encoded from scratch into CNF and
solved with the hand-built CDCL solver: each job picks exactly one start
day, jobs needing the same machine may not overlap, and precedence
constraints are honored.
"""
import sys
import time

sys.path.insert(0, "..")
from sat import Solver, check_model

DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri"]

# (name, duration_days, resources, precedences)
JOBS = [
    ("Oak removal (huge)",  2, {"chipper", "bucket"}, []),
    ("Pine trim (3 trees)", 1, {"bucket"}, []),
    ("Storm cleanup",       1, {"chipper"}, []),
    ("Stump grinding x4",   1, {"grinder"}, [0]),   # after the oak is down
    ("Brush clearing",      2, {"chipper"}, [2]),   # after storm cleanup
    ("Dead pine takedown",  1, {"bucket"}, []),
]


def encode():
    var = {}
    n = 0

    def V(j, s):
        return var[(j, s)]

    clauses = []
    for j, (name, dur, res, prec) in enumerate(JOBS):
        starts = [s for s in range(5) if s + dur <= 5]
        for s in starts:
            n += 1
            var[(j, s)] = n
        # exactly one start day
        clauses.append([V(j, s) for s in starts])
        for i in range(len(starts)):
            for k in range(i + 1, len(starts)):
                clauses.append([-V(j, starts[i]), -V(j, starts[k])])
    # precedence: job j starts only after each predecessor finishes
    for j, (name, dur, res, prec) in enumerate(JOBS):
        for p in prec:
            pdur = JOBS[p][1]
            pstarts = [s for s in range(5) if s + pdur <= 5]
            jstarts = [s for s in range(5) if s + dur <= 5]
            for sp in pstarts:
                ok = [sj for sj in jstarts if sj >= sp + pdur]
                clauses.append([-V(p, sp)] + [V(j, sj) for sj in ok])
    # resource exclusivity: overlapping jobs may not share a machine
    for j1 in range(len(JOBS)):
        for j2 in range(j1 + 1, len(JOBS)):
            shared = JOBS[j1][2] & JOBS[j2][2]
            if not shared:
                continue
            d1, d2 = JOBS[j1][1], JOBS[j2][1]
            for s1 in range(5 - d1 + 1):
                for s2 in range(5 - d2 + 1):
                    if max(s1, s2) < min(s1 + d1, s2 + d2):  # overlap
                        clauses.append([-V(j1, s1), -V(j2, s2)])
    return n, clauses, var


def main():
    nvars, clauses, var = encode()
    t0 = time.time()
    s = Solver(nvars, clauses)
    model = s.solve()
    dt = time.time() - t0
    print(f"scheduler: {nvars} vars, {len(clauses)} clauses, "
          f"{s.n_decisions} decisions, {s.n_conflicts} conflicts, {dt:.3f}s")
    if model is None:
        print("UNSAT: no feasible week with these jobs/resources.")
        return
    assert check_model(nvars, clauses, model)
    plan = {}
    for j, (name, dur, res, prec) in enumerate(JOBS):
        for st in range(5 - dur + 1):
            if model[var[(j, st)]]:
                plan[j] = st
    print(f"\n{'Job':24s} {'Days':12s} Equipment")
    print("-" * 60)
    for j, (name, dur, res, prec) in enumerate(JOBS):
        st = plan[j]
        days = ",".join(DAYS[st + k] for k in range(dur))
        print(f"{name:24s} {days:12s} {', '.join(sorted(res))}")
    # resource usage grid
    print("\nEquipment usage:")
    grid = {r: ["--"] * 5 for r in ("chipper", "bucket", "grinder")}
    for j, (name, dur, res, prec) in enumerate(JOBS):
        for k in range(dur):
            for r in res:
                assert grid[r][plan[j] + k] == "--", f"double-booked {r}"
                grid[r][plan[j] + k] = f"J{j}"
    for r in ("chipper", "bucket", "grinder"):
        print(f"  {r:8s} " + " ".join(f"{DAYS[d]}:{grid[r][d]}" for d in range(5)))
    # precedence check
    for j, (name, dur, res, prec) in enumerate(JOBS):
        for p in prec:
            assert plan[p] + JOBS[p][1] <= plan[j], "precedence violated"
    print("\nverified: no double-booked equipment, all precedence honored")


if __name__ == "__main__":
    main()
