#!/usr/bin/env python3
"""sudoku.py - solve Sudoku by reduction to SAT, using the from-scratch solver."""
import sys
import time

sys.path.insert(0, "..")
from sat import Solver, check_model

# A genuinely hard puzzle (AI Escargot, rated one of the hardest known)
ESCARGOT = [
    "100007090",
    "030020008",
    "009600500",
    "005300900",
    "010080002",
    "600004000",
    "300000010",
    "040000007",
    "007000300",
]


def encode(grid):
    def var(r, c, d):
        return (r * 9 + c) * 9 + d + 1  # d = 0..8 for digits 1..9

    clauses = []
    # each cell holds exactly one digit
    for r in range(9):
        for c in range(9):
            cells = [var(r, c, d) for d in range(9)]
            clauses.append(cells[:])
            for i in range(9):
                for j in range(i + 1, 9):
                    clauses.append([-cells[i], -cells[j]])
    # each row/col/box contains each digit at least once
    # (at-most-once follows from the cell constraints)
    for d in range(9):
        for r in range(9):
            clauses.append([var(r, c, d) for c in range(9)])
        for c in range(9):
            clauses.append([var(r, c, d) for r in range(9)])
        for br in range(3):
            for bc in range(3):
                clauses.append([var(br * 3 + dr, bc * 3 + dc, d)
                                for dr in range(3) for dc in range(3)])
    # givens
    for r in range(9):
        for c in range(9):
            d = int(grid[r][c])
            if d:
                clauses.append([var(r, c, d - 1)])
    return 729, clauses, var


def solve_sudoku(grid):
    nvars, clauses, var = encode(grid)
    t0 = time.time()
    s = Solver(nvars, clauses)
    model = s.solve()
    dt = time.time() - t0
    assert model is not None and check_model(nvars, clauses, model)
    out = [[0] * 9 for _ in range(9)]
    for r in range(9):
        for c in range(9):
            for d in range(9):
                if model[var(r, c, d)]:
                    out[r][c] = d + 1
    print(f"sudoku: {nvars} vars, {len(clauses)} clauses, "
          f"{s.n_decisions} decisions, {s.n_conflicts} conflicts, {dt:.2f}s")
    for r in range(9):
        row = ""
        for c in range(9):
            row += str(out[r][c]) + (" " if (c + 1) % 3 else "  ")
        print(row.rstrip())
        if r in (2, 5):
            print()
    # verify
    for r in range(9):
        assert sorted(out[r]) == list(range(1, 10))
        assert sorted(out[i][r] for i in range(9)) == list(range(1, 10))
    for br in range(3):
        for bc in range(3):
            box = [out[br * 3 + dr][bc * 3 + dc] for dr in range(3) for dc in range(3)]
            assert sorted(box) == list(range(1, 10))
    for r in range(9):
        for c in range(9):
            if grid[r][c] != "0":
                assert out[r][c] == int(grid[r][c])
    print("solution verified: rows, columns, boxes, givens all consistent")


if __name__ == "__main__":
    solve_sudoku(ESCARGOT)
