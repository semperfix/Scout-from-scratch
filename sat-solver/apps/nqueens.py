#!/usr/bin/env python3
"""nqueens.py - solve N-Queens by reduction to SAT, using the from-scratch solver."""
import sys
import time

sys.path.insert(0, "..")
from sat import Solver, check_model


def encode(n):
    def var(r, c):
        return r * n + c + 1

    clauses = []
    # each row has at least one queen
    for r in range(n):
        clauses.append([var(r, c) for c in range(n)])
    # at most one queen per row / column / diagonal (pairwise)
    def at_most_one(cells):
        for i in range(len(cells)):
            for j in range(i + 1, len(cells)):
                clauses.append([-cells[i], -cells[j]])

    for r in range(n):
        at_most_one([var(r, c) for c in range(n)])
    for c in range(n):
        at_most_one([var(r, c) for r in range(n)])
    for d in range(-n + 1, n):
        at_most_one([var(r, r - d) for r in range(n) if 0 <= r - d < n])
    for k in range(2 * n - 1):
        at_most_one([var(r, k - r) for r in range(n) if 0 <= k - r < n])
    return n * n, clauses, var


def solve_nqueens(n):
    nvars, clauses, var = encode(n)
    t0 = time.time()
    s = Solver(nvars, clauses)
    model = s.solve()
    dt = time.time() - t0
    assert model is not None and check_model(nvars, clauses, model)
    board = [["." for _ in range(n)] for _ in range(n)]
    for r in range(n):
        for c in range(n):
            if model[var(r, c)]:
                board[r][c] = "Q"
    print(f"{n}-queens: {nvars} vars, {len(clauses)} clauses, "
          f"{s.n_decisions} decisions, {s.n_conflicts} conflicts, {dt:.2f}s")
    for row in board:
        print(" ".join(row))
    # verify
    queens = [(r, c) for r in range(n) for c in range(n) if board[r][c] == "Q"]
    assert len(queens) == n
    for i, (r1, c1) in enumerate(queens):
        for r2, c2 in queens[i + 1:]:
            assert r1 != r2 and c1 != c2 and abs(r1 - r2) != abs(c1 - c2)
    print("board verified: no two queens attack")


if __name__ == "__main__":
    solve_nqueens(int(sys.argv[1]) if len(sys.argv) > 1 else 8)
