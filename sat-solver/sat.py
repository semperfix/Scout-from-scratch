#!/usr/bin/env python3
"""sat.py - CDCL SAT solver written from scratch (stdlib only).

Implements, by hand:
  - DIMACS CNF parser (with tautology/dup simplification)
  - DPLL search with two-watched-literal unit propagation
  - Conflict-Driven Clause Learning (CDCL) with first-UIP conflict analysis
  - Non-chronological backjumping
  - VSIDS-lite branching heuristic with phase saving

No SAT libraries used in the solver itself. python-sat (Glucose) is used only
in test_sat.py as an independent oracle for cross-validation.
"""

from collections import defaultdict


class Solver:
    def __init__(self, nvars, clauses):
        self.nvars = nvars
        self.clauses = []              # list of list[int]
        self.watches = defaultdict(set)  # literal -> set of clause ids
        self.assign_map = {}           # var -> bool
        self.levels = {}               # var -> decision level
        self.phase = {}                # var -> last assigned polarity
        self.trail = []                # (lit, level, reason_cid)
        self.queue = []                # falsified literals awaiting propagation
        self.decision_level = 0
        # VSIDS-lite
        self.activity = {v: 0.0 for v in range(1, nvars + 1)}
        self.var_inc = 1.0
        # stats
        self.n_decisions = 0
        self.n_conflicts = 0
        self.n_propagations = 0
        self.n_learned = 0
        # preprocess input clauses
        units = []
        for cl in clauses:
            s = set(cl)
            if any(-l in s for l in s):
                continue  # tautology
            c = list(s)
            if not c:
                self._immediate_unsat = True
                return
            self.add_clause(c)
            if len(c) == 1:
                units.append(c[0])
        self._immediate_unsat = False
        # initial unit assignments at level 0
        for lit in units:
            v = abs(lit)
            if v in self.assign_map:
                if self.assign_map[v] != (lit > 0):
                    self._immediate_unsat = True
                    return
                continue
            self._assign(lit, reason=None)

    # ------------------------------------------------------------------ core
    def add_clause(self, clause):
        cid = len(self.clauses)
        self.clauses.append(list(clause))
        self.watches[clause[0]].add(cid)
        if len(clause) > 1:
            self.watches[clause[1]].add(cid)
        return cid

    def _value(self, lit):
        a = self.assign_map.get(abs(lit))
        if a is None:
            return None
        return a == (lit > 0)

    def _assign(self, lit, reason):
        v = abs(lit)
        val = lit > 0
        self.assign_map[v] = val
        self.levels[v] = self.decision_level
        self.phase[v] = val
        self.trail.append((lit, self.decision_level, reason))
        self.queue.append(-lit)  # the falsified literal needs propagation

    def unit_propagate(self):
        """Two-watched-literal propagation. Returns conflicting clause id or None."""
        while self.queue:
            f = self.queue.pop()
            watchers = list(self.watches[f])
            for cid in watchers:
                c = self.clauses[cid]
                if len(c) < 2:
                    # unit clause watching its only literal; falsified => conflict
                    if self._value(c[0]) is False:
                        self.queue.clear()
                        return cid
                    continue
                # ensure c[1] is the falsified literal
                if c[0] == f:
                    c[0], c[1] = c[1], c[0]
                if self._value(c[0]) is True:
                    continue  # clause already satisfied
                # find a replacement watch among the rest
                moved = False
                for i in range(2, len(c)):
                    if self._value(c[i]) is not False:
                        self.watches[f].discard(cid)
                        self.watches[c[i]].add(cid)
                        c[1], c[i] = c[i], c[1]
                        moved = True
                        self.n_propagations += 1
                        break
                if not moved:
                    v0 = self._value(c[0])
                    if v0 is False:
                        self.queue.clear()
                        return cid  # conflict
                    self._assign(c[0], reason=cid)  # unit clause: force c[0]
        return None

    # ------------------------------------------------------- conflict analysis
    def analyze_conflict(self, conflict_cid):
        """First-UIP resolution. Returns (learned_clause, uip_lit, backjump_level).

        Mirrors MiniSat's analyze(): each resolved variable is removed from
        `seen`, and the loop runs until the cut holds exactly one
        current-level variable -- that variable IS the first UIP. (Picking
        "the most recent trail variable still in seen" without clearing
        resolved variables selects a stale variable and learns a clause
        that is not entailed -- the classic form of this bug.)
        """
        cur = self.decision_level
        seen = set()
        learned = []
        counter = 0
        for lit in self.clauses[conflict_cid]:
            v = abs(lit)
            if v in seen:
                continue
            seen.add(v)
            lv = self.levels[v]
            if lv == cur:
                counter += 1
            elif lv > 0:
                learned.append(lit)
        idx = len(self.trail) - 1
        uip_lit = None
        while True:
            # most recent trail literal at cur level still in the cut
            while True:
                tlit, tlevel, treason = self.trail[idx]
                idx -= 1
                tv = abs(tlit)
                if tv in seen and self.levels[tv] == cur:
                    break
            seen.discard(tv)
            counter -= 1
            if counter == 0:
                uip_lit = -tlit  # last variable left in the cut: the UIP
                break
            # counter > 0 here, so tlit cannot be a decision: a decision is
            # always the oldest literal of its level, and the most recent
            # in-cut literal would then be the decision only if it were the
            # sole current-level variable left (counter == 0).
            assert treason is not None, "decision var in resolution chain"
            for r in self.clauses[treason]:
                rv = abs(r)
                if rv == tv or rv in seen:
                    continue
                seen.add(rv)
                rlv = self.levels[rv]
                if rlv == cur:
                    counter += 1
                elif rlv > 0:
                    learned.append(r)
        assert uip_lit is not None
        learned.append(uip_lit)
        # dedupe, keep uip first
        dedup = [uip_lit] + [l for l in learned[:-1] if l != uip_lit]
        seen2 = set()
        learned = [l for l in dedup if not (l in seen2 or seen2.add(l))]
        backjump = 0
        for l in learned[1:]:
            backjump = max(backjump, self.levels[abs(l)])
        return learned, uip_lit, backjump

    def backjump(self, level):
        while self.trail and self.trail[-1][1] > level:
            lit, _, _ = self.trail.pop()
            v = abs(lit)
            del self.assign_map[v]
            del self.levels[v]
        self.decision_level = level
        self.queue.clear()

    def pick_branch_var(self):
        best, best_act = None, -1.0
        for v in range(1, self.nvars + 1):
            if v not in self.assign_map and self.activity[v] > best_act:
                best, best_act = v, self.activity[v]
        return best

    # ------------------------------------------------------------------ solve
    def solve(self):
        if self._immediate_unsat:
            return None
        conflict = self.unit_propagate()
        if conflict is not None:
            return None
        while True:
            var = self.pick_branch_var()
            if var is None:
                return {v: self.assign_map[v] for v in range(1, self.nvars + 1)}
            self.decision_level += 1
            self.n_decisions += 1
            lit = var if self.phase.get(var, True) else -var
            self._assign(lit, reason=None)
            while True:
                conflict = self.unit_propagate()
                if conflict is None:
                    break
                self.n_conflicts += 1
                if self.decision_level == 0:
                    return None
                learned, uip, bj = self.analyze_conflict(conflict)
                for l in learned:
                    self.activity[abs(l)] += self.var_inc
                self.var_inc *= 1.0 / 0.95  # VSIDS decay
                self.backjump(bj)
                cid = self.add_clause(learned)
                self.n_learned += 1
                self._assign(uip, reason=cid)


# ------------------------------------------------------------------ DIMACS io
def parse_dimacs(text):
    nvars = 0
    clauses = []
    cur = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('c'):
            continue
        if line.startswith('p'):
            parts = line.split()
            nvars = int(parts[2])
            continue
        for tok in line.split():
            lit = int(tok)
            if lit == 0:
                clauses.append(cur)
                cur = []
            else:
                cur.append(lit)
    if cur:
        clauses.append(cur)
    return nvars, clauses


def to_dimacs(nvars, clauses):
    out = [f"p cnf {nvars} {len(clauses)}"]
    for c in clauses:
        out.append(" ".join(map(str, c)) + " 0")
    return "\n".join(out) + "\n"


def solve_cnf(nvars, clauses):
    return Solver(nvars, clauses).solve()


def check_model(nvars, clauses, model):
    if model is None:
        return False
    for c in clauses:
        ok = False
        for lit in c:
            v = abs(lit)
            if model.get(v) == (lit > 0):
                ok = True
                break
        if not ok:
            return False
    return True
