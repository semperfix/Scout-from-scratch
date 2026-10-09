# Regex Engine From Scratch (Thompson NFA)

A complete regular-expression engine with zero use of the `re` module: recursive-descent parser → Thompson NFA (fragment patching) → Pike-VM-style lockstep simulation. `refox.py` is the grep/extract/sub CLI on top. 72 deterministic checks plus a differential fuzzer (`diff_test.py`) that throws 4,000 random patterns at it with stdlib `re` as the oracle — 99.7% agreement, with the residual gaps documented as CPython's most obscure backtracking corners. Worst case is roughly quadratic in input length (fine for triage, not for megabyte inputs).

## Dependencies

Python 3 standard library only. No third-party packages (verified: `regex.py`, `refox.py`, `test_regex.py`, `diff_test.py` import only `os`, `random`, `signal`, `sys`, and each other — `re` is used only inside the *test oracle*, never by the engine).

## How to run

Entry point: `refox.py`

```
python3 refox.py find <pattern> <file> [--count]   # grep-like search
python3 refox.py extract <preset> <file>           # preset: phones | amounts | dates
python3 refox.py sub <pattern> <repl> <file>       # substitution
python3 test_regex.py                              # 72 deterministic checks
python3 diff_test.py                               # differential fuzzer vs stdlib re (oracle)
```

## Usage example

```
$ python3 refox.py find 'cas[hH]' demo/abe-thread.txt
15:22: cash

$ python3 refox.py extract amounts demo/abe-thread.txt
$420
$450
```

## Key learnings (from LEARNINGS.md)

- Backtracking order is emulated without backtracking: every epsilon fork appends `'0'` (first choice) or `'1'` (second choice) to a priority string, all complete matches are collected, and the lexicographically smallest priority wins. Greedy `*` puts the loop on `'0'`, lazy `*?` puts the exit on `'0'` — reproducing PCRE-ish leftmost-first semantics including which *path* wins, which is what capture groups report.
- Thompson's construction is almost mechanical; the *semantics* (which match wins, what groups capture) is where all the subtlety lives. Differential fuzzing against `re` found 3 genuine semantic bugs that 72 hand-written tests missed — the fuzzer is the test suite that matters. Example: CPython's empty-iteration rule for `(a?)*` was fixed by a compile-time rewrite `X*` → `(?: Xs X? | )` rather than per-thread loop state.
- Epsilon-dedup (generation stamps) is load-bearing for termination but interacts with every semantic extension: any mutable per-closure state breaks its "same state + same pos = same future" assumption, so the fix is always to keep the NFA pure and push the cleverness into the compiler.
- `re`'s edge semantics are arbitrary-but-real: `findall` reports `''` for non-participating groups while `match.group()` reports `None`; `(a?)*` records the final empty iteration, then stops. Matching them is what "compatible" means, not elegance.

## Files

- `refox.py` — CLI: `find` / `extract` (phones, amounts, dates presets) / `sub`
- `regex.py` — the engine: parser → Thompson NFA → priority-based simulation
- `test_regex.py` — 72 deterministic checks
- `diff_test.py` — differential fuzzer against stdlib `re` (4,000 random patterns)
- `demo/abe-thread.txt` — real message-thread fixture for searching
- `LEARNINGS.md` — full expedition notes (priority model, 6 fuzzer-caught bugs, residual gaps)
