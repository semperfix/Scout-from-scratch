# SAT Solver — CDCL from Scratch

A complete Conflict-Driven Clause Learning SAT solver in ~330 lines of
stdlib-only Python (`sat.py`). DIMACS CNF parser with simplification,
DPLL search with **two-watched-literal** unit propagation, **CDCL** (first-UIP
conflict analysis over the implication graph, non-chronological backjumping,
clause learning), and a **VSIDS-lite** branching heuristic with phase saving.

Validated against Glucose3 on 300 random 3-SAT instances with **0 mismatches**,
every learned clause regression-proven entailed, pigeonhole(8,7) UNSAT in
0.94 s, and the 3-SAT phase transition (hardness peaking at clause/var ratio
≈ 4.26) reproduced empirically.

## Dependencies

Stdlib only. No pip packages.

## How to run

```
python3 test_sat.py            # 13 validation checks (13/13)
python3 apps/nqueens.py        # 8-queens in 0.00 s (apps/ run from the sat-solver root)
python3 apps/sudoku.py         # AI Escargot (hardest known puzzle) — ~1 min
python3 apps/schedule.py       # tree-work week scheduler: 6 jobs, 5 days, exclusive equipment
```

The apps set `sys.path` relative to `apps/`, so run them from the `sat-solver/`
root (e.g. `PYTHONPATH=. python3 apps/nqueens.py` also works).

## Usage example

```python
from sat import solve_cnf, check_model

# pigeonhole(3,2): 3 pigeons, 2 holes — UNSAT
nvars, clauses = 6, []
for p in range(3):
    clauses.append([p*2+1, p*2+2])              # each pigeon in some hole
for h in range(2):
    for p1 in range(3):
        for p2 in range(p1+1, 3):
            clauses.append([-(p1*2+h+1), -(p2*2+h+1)])  # no hole has two pigeons

model = solve_cnf(nvars, clauses)   # None  ->  UNSAT
assert model is None
```

The reusable template for new problems is `apps/schedule.py`: exactly-one
choice variables + pairwise mutex clauses + precedence implications, then
`check_model` to machine-verify the answer.

## Key learnings

- **In CDCL, the `seen` set is the *cut*, not history.** The first version
  learned unsound clauses because the UIP scan picked a stale variable instead
  of the true first UIP — resolved variables must be discarded from `seen`,
  mirroring MiniSat's `analyze()`. (Caught by a fuzzer + Glucose
  cross-validation, not by staring at the code.)
- **Two-watched literals are the reason modern solvers touch only a fraction
  of clauses per assignment** — unit propagation cost, not branching, is what
  makes SAT practical.
- **A leader/scheduler pattern generalizes:** "find an assignment satisfying
  all these rules" covers scheduling jobs/crews/equipment, puzzles, and
  configuration. Encode to CNF, solve, verify — the solver doesn't care what
  the variables mean.
- **Cross-validation beats unit tests for solvers.** Hand cases prove you
  implemented what you meant; 300 random instances against Glucose prove you
  didn't learn something wrong. The learned-clause entailment check (orig ∧ ¬L
  UNSAT) catches soundness bugs that satisfiability checks miss.

## Files

- `sat.py` — the CDCL solver + DIMACS parser + `solve_cnf`/`check_model`
- `test_sat.py` — 13 validation checks (13/13)
- `apps/nqueens.py` — N-queens encoding
- `apps/sudoku.py` — Sudoku encoding (AI Escargot)
- `apps/schedule.py` — tree-work week scheduler (the reusable template)
- `NOTES.md` — the full skill writeup
