# Spreadsheet Engine — Learnings

## What I built
`sheets.py`: a complete spreadsheet formula engine, zero dependencies (~1,650 lines):
hand-written lexer → recursive-descent parser → AST evaluator, a Workbook with
multi-sheet support, dependency-graph topological evaluation (Kahn's algorithm)
with cycle detection, Excel-compatible type coercion and error propagation,
60+ functions, drag-fill relative-reference copy, CSV import/export, a grid
renderer, and a REPL.

## Earned insights (things I got wrong first)

1. **Excel's `=-2^2` is 4, not -4.** Unary minus binds tighter than `^` — a
   famous quirk I had to encode deliberately (`power := unary ('^' power)?`
   with `unary` above `power` in the grammar). Getting "Excel-compatible"
   means implementing the quirks, not the math-textbook grammar. I wrote a
   test asserting 4.0 so the quirk is pinned, not accidental.

2. **`=""=0` is TRUE in Excel.** Empty text equals numeric zero in comparisons
   (but `"a"=0` is FALSE). My first type-rank implementation returned FALSE
   and a test caught it. The fix: normalize `""` → `0.0` when the other side
   is a number, in both equality and ordering. Comparison semantics are a
   patchwork of special cases, not one clean rule.

3. **Aggregators have two different rulebooks.** Inside a range, SUM ignores
   text/booleans/blanks; as direct arguments, booleans count as 1/0 but text
   is `#VALUE!`. `SUM(TRUE,1)` = 2 but `SUM` over a range containing TRUE
   skips it. I implemented this by keeping range-expansion inside the
   aggregator instead of a shared flatten helper — the shared helper erased
   exactly the distinction that mattered.

4. **Laziness is load-bearing, not an optimization.** `IF(FALSE,1,1/0)` must
   be 2, so IF/IFERROR take unevaluated ASTs. AND/OR I made strict (errors
   propagate even past FALSE) — a judgment call; Excel evaluates all AND/OR
   args. The test suite pins whichever semantics I chose.

5. **Cycle detection falls out of Kahn's algorithm for free.** Cells never
   reaching in-degree zero are in cycles *or downstream of cycles*. Marking
   them `#CYCLE!` in the memo before evaluating the topological order means
   dependents propagate the error naturally through normal error propagation
   — no special-case code needed.

6. **Drag-fill copy is a lexer problem, not a string problem.** Shifting
   `A1`→`A2` with regex would also rewrite the `A1` inside `"A1"` string
   literals. Tokenizing first and rebuilding from token spans keeps literals
   untouched and makes `$`-absolute handling exact. Off-grid shifts become
   `#REF!`, matching Excel.

7. **CSV bit me the way it bites everyone:** the comma inside
   `=ROUND(E9*0.5,2)` split the field mid-formula. Quote formula fields
   containing commas. (Also: my first demo had row numbers off by one because
   of a blank row — the renderer was the test that caught it. Visualization
   as debugging, same lesson as the geo-routing SVGs.)

8. **Range-in-scalar-context is a deliberate gap.** Real Excel spills
   (`=A1:A3` fills three cells); mine returns `#VALUE!`. Dynamic arrays are a
   whole second engine. Named, not hidden.

## Validation
`test_sheets.py`: 108/108 checks — precedence incl. the `-2^2` quirk,
coercion edge cases, all 7 error values and their propagation, aggregator
range-vs-direct rules, IF laziness, ROUND half-away-from-zero, MOD's
sign-of-divisor, 1-indexed text functions, VLOOKUP exact/#N/A/#REF!,
SUMIF/COUNTIF/AVERAGEIF with wildcards, PMT pinned to the known 30-yr $200k
@ 5% payment ($1,073.64), cycle detection incl. self-reference and downstream
propagation, diamond/chain dependency shapes, cross-sheet and quoted-sheet
refs, drag-fill shifts, and CSV roundtrips (values and formulas).

## Real artifacts
- `demos/tree-estimate.csv` — a tree-job estimate: line items, 7% materials
  tax, 50% deposit, balance. Renders correctly.
- `demos/abe-ledger.csv` — Abe wages ledger: chained running-balance
  formulas (450 → 420 → 320 → 470), SUM totals, and an outstanding-balance
  cross-check that agrees with the chain (470 = E5).

## The tool for
"Turn this pile of numbers into a sheet I can recompute" — job estimates,
wage ledgers, loan math (PMT), any tabular calculation Kyle wants without
opening Excel. `python3 sheets.py render file.csv`, `calc -o out.csv`, or the
`repl`.
