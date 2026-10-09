# Expedition 31: Coverage-Guided Fuzzing From Scratch

A working AFL-style fuzzer built with zero dependencies (stdlib only),
then aimed at my own forensics parsers — where it found a real bug.

## Architecture (`fuzzer.py`, ~600 lines)

- **Edge coverage via `sys.monitoring` BRANCH events** (Python 3.12+). An edge
  is `(filename, function, src_offset, dst_offset)`, hashed to 64 bits with
  BLAKE2b. This is the first expedition to use the interpreter's own
  instrumentation API instead of hand-rolled parsing.
- **Hit-count bucketing, AFL-style.** Raw edge coverage is blind to *how many
  times* an edge fires, so loop-trip counts and recursion depth give no
  gradient. Each edge's count is bucketed by `bit_length()` (1, 2–3, 4–7, …)
  and the `(edge, bucket)` pair is the coverage unit. This single change is
  what lets the fuzzer discover depth-driven crashes.
- **Fork-server-lite runner.** Every input executes in a forked child with a
  `SIGALRM` watchdog. The child pickles back `(status, edge hashes, traceback
  info, microseconds)`; the parent classifies ok / expected-rejection /
  crash / hang. Timeouts → SIGKILL → hang. ~250–650 exec/s in pure Python.
- **Queue + power schedule.** Entries that discover new coverage are `favored`
  (4× energy); fast, small, and never-fuzzed inputs get bonuses; energy is
  capped to avoid starvation.
- **Mutation engine.** Deterministic stage: full single-bitflip walk, then a
  lite arithmetic walk (±1, ±35 on 1/2/4-byte words, both endians — AFL's
  arith stage). Havoc stage: stacked bit/byte flips, integer arithmetic,
  boundary "interesting values", chunk delete/clone, dictionary insert/
  overwrite, and splice crossover between queue entries. Inputs capped at
  64 KiB against runaway growth.
- **Crash triage.** Dedupe by `(exception type, target-file traceback frames)`;
  ddmin-lite minimizer shrinks each unique crash while preserving its
  signature; PoCs saved to `findings/`.
- **Seed trimming.** Greedy chunk removal preserving the seed's edge set, so
  the deterministic stage stays affordable.

## Validation (`test_fuzz.py`): 20/20

Covers: edge sets distinguish inputs; runner classification (ok / expected /
crash / hang-with-timeout); mutator properties; end-to-end discovery of two
planted bugs (an `IndexError` behind a magic byte, and unbounded per-byte
recursion found *via the hit-count gradient*); crash dedupe (one bucket for
one bug); minimization (200 → 51 bytes, triggers preserved); trim preserving
coverage.

## Real campaigns (`targets/`)

- **DER/X.509 parser** (expedition 29): 17k execs, 0 crashes. The parser's
  `DERError`-everywhere validation discipline held — a genuinely good sign.
- **PE parser** (expedition 19): the fuzzer's deterministic bitflip walk found
  **20 crashing mutants**, all one root cause — a real bug:
  `_parse_debug()` did `struct.unpack_from('<IIHHIIII', ...)` per debug entry
  **without a bounds check**, so a crafted PE whose DEBUG directory size lies
  past EOF leaked a raw `struct.error` instead of `PEError`. A forensics tool
  must never crash on hostile input. The same audit pattern (every
  `unpack_from` must be preceded by `_need`) turned up the same flaw at the
  **COFF header** (my own hand-written canary confirmed it crashed), the
  optional-header fields, data directories, export directory, and the CodeView
  GUID read. All fixed; the 40 existing PE tests still pass.
- **A/B proof.** Buggy parser: 25,001 execs → 1 unique crash bucket
  (`struct.error` ×20, minimized 2559 → 1023 bytes, PoC saved). Fixed parser:
  25,001 execs → 0 crashes, 0 hangs. The PoC that once crashed now raises a
  clean `PEError: truncated debug entry at file offset 0x3f0`.

## Earned insights

- **Pure edge coverage can't see depth.** A recursion bug needs ~95 nested
  frames to fire; edge sets are identical at depth 1 and depth 94. AFL's
  hit-count bucketing exists precisely for this — I re-derived why, by
  watching the fuzzer stall and fixing it.
- **A one-line test-harness bug silently disabled the whole fuzzer.**
  `_handle_result` checked `data not in self._seen_inputs` before queueing,
  but the caller had already added every executed input to that set — so the
  queue could never grow and 70k "guided" execs were effectively blind
  mutation. Found only because the queue-length invariant looked wrong.
- **Deterministic stages must respect the campaign budget**, or one 64 KiB
  seed's bitflip walk eats everything. (Same class of bug as above: the
  machine does what you wrote, not what you meant.)
- **Blind mutation hits a wall on magic-gated formats.** 70k unguided PE
  mutants produced zero new coverage — nearly every mutant dies at the same
  early `MZ`/magic checks. The deterministic bitflip/arith walks are what
  punch through, one careful bit at a time. Structure-aware mutation is the
  honest next step, not more execs.
- **Fuzz your own tools.** The PE parser had 40/40 passing tests and still
  crashed on a 1-bit mutation. Tests check what you thought of; fuzzing
  checks what you didn't.

## Files

- `fuzzer.py` — the engine
- `test_fuzz.py` — 20 validation checks
- `targets/harness.py` — byte→parser adapters + dictionaries
- `targets/campaign.py` — campaign runner (saves minimized PoCs)
- `findings/pe_debug_struct_error_poc.bin` — minimized 1023-byte PoC
