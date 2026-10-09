# Skill #36: SAT solving (CDCL) from scratch — `~/workspace/learning/sat/`

**What it is:** a complete Conflict-Driven Clause Learning SAT solver written
from scratch in ~330 lines of stdlib-only Python (`sat.py`), plus a
validation suite and three applied encodings.

**Implemented by hand:**
- DIMACS CNF parser with tautology/duplicate simplification
- DPLL search with **two-watched-literal** unit propagation (the reason
  modern solvers touch only a fraction of clauses per assignment)
- **CDCL**: first-UIP conflict analysis by resolution over the implication
  graph, non-chronological backjumping, clause learning
- **VSIDS-lite** branching heuristic (activity bumping + decay) with phase saving

**Validation (13/13 checks, `test_sat.py`):**
- Hand cases: pigeonhole(3,2) UNSAT, xor chains, tautology dropping
- **300 random 3-SAT instances cross-validated against Glucose3: 0 mismatches**
  (same sat/unsat verdict every time; every returned model verified)
- **Learned-clause soundness regression test**: every clause the solver ever
  learns is proven entailed (orig ∧ ¬L UNSAT via Glucose) — 0 unsound
- Stress: 10× n=120 3-SAT match Glucose; pigeonhole(8,7) UNSAT in 0.94s
- **Phase-transition experiment reproduced**: hardness peaks exactly at
  clause/var ratio ≈ 4.26 (easy-hard-easy pattern, sat% 100→0)

**Real bug caught by the fuzzer (worth knowing):** the first version learned
clauses that were *not entailed* — the UIP scan picked "most recent trail
variable in `seen`" without clearing resolved variables from `seen`, so it
selected a stale variable instead of the true first UIP. Fixed by mirroring
MiniSat's analyze(): discard each resolved variable from `seen` and stop when
the cut holds exactly one current-level variable. Lesson: in CDCL, the `seen`
set is the *cut*, not history — resolved variables must leave it.

**Applications (`apps/`):**
- `nqueens.py` — 8-queens in 0.00s, 12-queens in 0.02s, boards verified
- `sudoku.py` — AI Escargot (one of the hardest known puzzles): solved and
  verified (97,885 decisions, 45,659 conflicts, 56s — slow vs Glucose, but
  complete and correct)
- `schedule.py` — **tree-work week scheduler for Kyle**: 6 jobs, 5 days,
  exclusive chipper/bucket/grinder + precedence constraints → valid week
  printed and machine-verified (no double-booked equipment)

**When to reach for it:** any constraint problem — scheduling jobs/crews/
equipment, puzzles, configuration, "find an assignment satisfying all these
rules". Encode to CNF, solve, verify. The scheduler pattern in
`apps/schedule.py` is the reusable template (exactly-one choice variables +
pairwise mutex + precedence implications).
