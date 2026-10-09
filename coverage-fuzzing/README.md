# Coverage-Guided Fuzzing (AFL-style)

A working AFL-style coverage-guided fuzzer built entirely from scratch, stdlib
only, in `fuzzer.py` (~600 lines). It instruments the target with Python's own
`sys.monitoring` API (3.12+) to collect edge coverage, then mutates inputs that
discover new coverage — deterministic bitflip/arith walks plus a havoc stage
with dictionary inserts and splice crossover. Crashes are deduplicated by
signature, minimized with ddmin-lite, and saved as PoCs to `findings/`.

It was validated against its own forensics parsers, where a deterministic
bitflip walk found a real bounds-check bug in a PE debug-directory parser
(then confirmed fixed by a 25k-exec A/B campaign: buggy → 1 unique crash,
fixed → 0).

## Dependencies

Stdlib only (Python 3.12+, for `sys.monitoring`). No pip packages.

## How to run

Point the fuzzer at a target function `bytes -> result`. The library has no CLI;
use the API:

```python
from fuzzer import Fuzzer

f = Fuzzer(target_fn, seeds=[b"\x41", b"\x00"],
           allowed_prefixes=["."],
           expected_exc=(ValueError,),   # raised by the target on bad input: "expected rejection"
           timeout=5)
f.run()          # runs until budget exhausted
print(f.report())  # crash buckets, execs, exec/s
```

Run the self-validation suite:

```
python3 test_fuzz.py        # 20 checks: coverage, runner classification, end-to-end bug discovery, dedupe, minimization
```

Run a real campaign against the DER/X.509 or PE parser adapters:

```
cd targets
python3 campaign.py der     # or: python3 campaign.py pe
```

## Usage example

```python
import sys; sys.path.insert(0, ".")
from fuzzer import Fuzzer

class Boom(Exception): pass

def toy(x):
    if len(x) >= 2 and x[0] == 0x41 and x[1] == 0x42:
        raise Boom("magic")          # planted bug behind two magic bytes
    return "a" if x and x[0] == 0x41 else "z"

f = Fuzzer(toy, [b"A", b"\x00"], ["."], expected_exc=(ValueError,))
f._budget_exceeded = lambda: f.execs > 3000
f.run()
print(f.report())   # finds the Boom crash, dedupes it to one bucket
```

## Key learnings

- **Pure edge coverage can't see depth.** A recursion bug needs ~95 nested frames
  to fire, but edge sets look identical at depth 1 and 94. AFL's hit-count
  bucketing (count → `bit_length()` buckets, `(edge, bucket)` as the unit) is
  what gives the gradient that discovers depth-driven crashes.
- **A one-line harness bug silently disabled the whole fuzzer.** `_handle_result`
  checked `data not in self._seen_inputs` before queueing, but the caller had
  already registered every executed input — so the queue could never grow and
  70k "guided" execs were blind mutation. Caught only because the queue-length
  invariant looked wrong.
- **Blind mutation stalls on magic-gated formats.** 70k unguided PE mutants hit
  zero new coverage — nearly all die at the same early `MZ` checks. Deterministic
  bitflip/arith walks punch through one careful bit at a time; structure-aware
  mutation is the honest next step, not more execs.
- **Fuzz your own tools.** The PE parser passed 40/40 tests and still crashed on
  a 1-bit mutation. Tests check what you thought of; fuzzing checks what you
  didn't.

## Files

- `fuzzer.py` — the engine: edge coverage, runner, mutator, triage
- `test_fuzz.py` — 20 validation checks (20/20)
- `targets/harness.py` — byte→parser adapters + mutation dictionaries
- `targets/campaign.py` — campaign runner (saves minimized PoCs)
- `findings/pe_debug_struct_error_poc.bin` — minimized 1023-byte PoC for the real
  PE `_parse_debug()` bounds-check bug
- `source-README.md` — the original expedition writeup (kept as-is)
