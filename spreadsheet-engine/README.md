# Spreadsheet Formula Engine

A complete spreadsheet formula engine with zero dependencies (~1,650 lines): hand-written lexer → recursive-descent parser → AST evaluator, a Workbook with multi-sheet support, dependency-graph topological evaluation (Kahn's algorithm) with cycle detection, Excel-compatible type coercion and error propagation, 60+ functions, drag-fill relative-reference copy, CSV import/export, a grid renderer, and a REPL. Evaluates real workbooks — job estimates, wage ledgers, loan math (PMT) — without Excel. 108/108 checks in the test suite, including Excel's famous quirks.

## Dependencies

Python 3 standard library only. No third-party packages (verified: `sheets.py` and `test_sheets.py` import only `argparse`, `csv`, `math`, `os`, `re`, `sys`, `tempfile`).

## How to run

Entry point: `sheets.py`

```
python3 sheets.py calc   workbook.csv              # evaluate formulas
python3 sheets.py calc   workbook.csv -o out.csv   # write computed values to CSV
python3 sheets.py calc   workbook.csv --render     # evaluate and print the grid
python3 sheets.py render workbook.csv              # pretty-print the grid
python3 sheets.py repl                             # interactive prompt
python3 test_sheets.py                             # 108-check test suite
```

## Usage example

```
$ python3 sheets.py calc --render demos/tree-estimate.csv
                                       A     B    C         D          E                    F
  1 Tree Job Estimate - Rhoton Tree Work                                                     ...
  3              Oak removal, front yard     6   85       120        630 includes stump grind
  8                             Subtotal                          1292.5
  9             Tax (7%, materials only)                            23.8
 10                                Total                          1316.3
 11                        Deposit (50%)                          658.15
 12                          Balance due                          658.15
```

All formulas (`=D3+E3`, `=SUM(...)`, `=E9*0.5`...) recompute live in the CSV — edit the inputs, re-run `calc`.

## Key learnings (from LEARNINGS.md)

- "Excel-compatible" means implementing the quirks, not the math-textbook grammar: `=-2^2` is **4** in Excel (unary minus binds tighter than `^`), and `=""=0` is TRUE (empty text equals numeric zero in comparisons, but `"a"=0` is FALSE). Both are pinned by tests so the quirks stay deliberate, not accidental.
- Aggregators have two different rulebooks: inside a range, `SUM` ignores text/booleans/blanks; as direct arguments, booleans count as 1/0 but text is `#VALUE!`. The range-vs-direct distinction lives in the aggregator's own range-expansion — a shared flatten helper erased exactly the distinction that mattered.
- Cycle detection falls out of Kahn's algorithm for free: cells never reaching in-degree zero are in cycles *or downstream of cycles*. Marking them `#CYCLE!` before evaluating means dependents propagate the error through normal error propagation — no special-case code.
- Drag-fill copy is a lexer problem, not a string problem: shifting `A1`→`A2` with regex would also rewrite the `A1` inside `"A1"` string literals. Tokenizing first and rebuilding from token spans keeps literals untouched and makes `$`-absolute handling exact.

## Files

- `sheets.py` — the engine: lexer, parser, AST evaluator, Workbook, CLI (`calc`/`render`/`repl`)
- `test_sheets.py` — 108 checks: precedence quirks, coercion, all 7 error values, aggregators, IF laziness, VLOOKUP, cycle detection, drag-fill, CSV roundtrips
- `demos/tree-estimate.csv` — tree-job estimate: line items, 7% materials tax, 50% deposit, balance
- `demos/abe-ledger.csv` — wages ledger: chained running-balance formulas (450 → 420 → 320 → 470) with an outstanding-balance cross-check that agrees
- `LEARNINGS.md` — full expedition notes
