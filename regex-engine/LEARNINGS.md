# Expedition #40: Regex Engine From Scratch — Learnings

## What was built
`regex.py`: a complete regular-expression engine with zero use of the `re`
module — recursive-descent parser → Thompson NFA (fragment patching) →
Pike-VM-style simulation with explicit backtracking-priority tracking.
`refox.py`: a grep/extract/redact CLI on top. `diff_test.py`: differential
fuzzer against stdlib `re`. `test_regex.py`: 72 deterministic checks.

## The priority model (the core idea)
Backtracking order is emulated without backtracking: every epsilon fork
appends `'0'` (first choice) or `'1'` (second choice) to a priority string.
All complete matches are collected as candidates; the lexicographically
smallest priority wins. Greedy `*` puts the loop on `'0'`; lazy `*?` puts the
exit on `'0'`; alternation tries branches left to right. This reproduces
PCRE-ish leftmost-first semantics — including which *path* wins, which is
what capture groups report.

## Bugs the fuzzer caught (all real, all fixed)
1. **Phantom empty alternation.** My n-branch `|` used n splits, leaving the
   last split's `out2` dangling; the parent patched it to the continuation,
   creating an epsilon path that skipped every branch. `a|b` matched empty.
   Fix: textbook n−1 splits. (Would have survived all hand-written tests —
   the empty path usually loses on priority.)
2. **Stale generation stamps.** The epsilon-dedup counter was per-VM but
   states are shared per compiled pattern, so a *second* `search()` on the
   same object falsely skipped states. Fix: process-global monotonic counter.
   (Found because `findall` reuses the pattern — a single `search` never trips it.)
3. **CPython's empty-iteration rule.** `(a?)*` on `'a'`: CPython records the
   final empty iteration (group `''`), then stops the repeat. Pure Thompson
   epsilon-dedup kills the empty iteration (group stays `'a'`). Fix, chosen
   after a failed per-thread-state attempt: compile-time rewrite
   `X*` → `(?: Xs X? | )` — `Xs` is a plain loop doing only non-empty
   iterations, the trailing `X?` records the single empty one. Simpler than
   tracking loop state per thread, and it also fixed a 3-second pathological
   slowdown the stateful version had on nested stars.
4. **`findall` quirk.** CPython's `findall` reports `''` for non-participating
   groups while `match.group()` reports `None`. Mirrored deliberately.
5. **Bounded `{m,n}` "empty stops the repeat".** `(\w*?){0,2}$` on `'ab'`:
   CPython gives group `'b'` (iterations `'a','b'`), not `'ab'`. When an
   optional iteration matches empty, the repeat stops (backtracking may
   revisit). Unrolled optionals get this wrong. Fix: `lhead`/`lback` loop
   states with a per-thread `[entry_pos, count]` map; `lback` routes to exit
   on empty or max-reached, else loops with a fresh dedup scope (the re-entry
   must not collide with entry-path states at shared joins — a real bug found
   by tracing). `lhead` also blocks body entry once count reaches max (an
   extra empty iteration beyond max is not allowed).
6. **Oracle timeouts.** CPython's `re` catastrophically backtracks on nested
   quantifiers (the Thompson engine never does — lockstep is the point). The
   fuzzer now timeouts the oracle instead of hanging.

## Residual gaps (documented, not fixed)
~0.3% of fuzz cases (deeply nested `{m,n}` + lazy + empty-body combinations)
still diverge from CPython, mostly in *group values* (spans usually agree).
These are CPython's most obscure backtracking corners; the engine is exact on
all 72 hand-written tests and 99.7% of 4000 random patterns. Good enough for
triage; not a drop-in `re` replacement for adversarial patterns.

## What I now understand
- Thompson's construction is almost mechanical; the *semantics* (which match
  wins, what groups capture) is where all the subtlety lives. The NFA gives
  you a set of matches; priority ordering picks the backtracking-compatible one.
- Epsilon-dedup (`gen` stamps) is load-bearing for termination but interacts
  with every semantic extension — any mutable per-closure state (like my first
  loop attempt) breaks its "same state + same pos = same future" assumption.
  The compile-time rewrite sidesteps this by keeping the NFA pure.
- Differential fuzzing against `re` is an outstanding oracle: 4000 random
  patterns found 3 genuine semantic bugs that 72 hand-written tests missed.
  The fuzzer is the test suite that matters.
- `re`'s edge semantics (empty iteration recorded-then-stop, `findall`'s
  `''` vs `None`) are arbitrary-but-real; matching them is what "compatible"
  means, not elegance.

## Deliberate gaps
No backreferences (not regular), no lookahead/lookbehind, no named groups,
no flags; `$` doesn't match before a trailing newline. Worst case is roughly
quadratic in input length (all start positions × linear scan) — fine for
triage, not for megabyte inputs.
