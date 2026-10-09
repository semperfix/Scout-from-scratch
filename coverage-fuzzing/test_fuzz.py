#!/usr/bin/env python3
"""Validation checks for the fuzzer engine itself."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fuzzer import Fuzzer, Mutator, run_one
import random

HERE = os.path.dirname(os.path.abspath(__file__))
checks = []
def check(name, cond, extra=""):
    checks.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + (f" [{extra}]" if extra else ""))

class ToyError(Exception): pass

# --- 1. branch coverage distinguishes inputs on a toy target ---
def toy(x):
    if x[0] == 0x41: return "a"
    elif x[0] == 0x42: return "b"
    return "z"
f = Fuzzer(toy, [b"\x41", b"\x00"], [HERE], expected_exc=(ToyError,))
r1 = f._exec(b"\x41"); r2 = f._exec(b"\x42")
e1, e2 = set(r1["edges"]), set(r2["edges"])
check("coverage: different inputs hit different edges", e1 != e2 and e1 and e2,
      f"{len(e1)}/{len(e2)} edges")
check("coverage: non-empty edge set on real code", len(e1 | e2) >= 1,
      f"{len(e1 | e2)} edges")

# --- 2. runner classification: ok / expected / crash / hang ---
def raiser(data):
    if data[:1] == b"X": raise ToyError("rejected")
    if data[:1] == b"Y": raise IndexError("bug")
    if data[:1] == b"Z":
        while True: pass
    return len(data)
f2 = Fuzzer(raiser, [b"q"], [HERE], expected_exc=(ToyError,), timeout=2)
check("runner: ok", f2._exec(b"q")["status"] == "ok")
check("runner: expected-rejection", f2._exec(b"X")["status"] == "expected")
rc = f2._exec(b"Y")
check("runner: crash w/ traceback frames", rc["status"] == "crash" and rc["tb"][0] == "IndexError", str(rc["tb"][0]))
t0 = __import__("time").time()
rh = f2._exec(b"Z")
check("runner: hang detected near timeout", rh["status"] == "hang" and __import__("time").time() - t0 < 6, f"{__import__('time').time()-t0:.1f}s")

# --- 3. mutator properties ---
m = Mutator(random.Random(1), dictionary=[b"PE\x00\x00", b"MZ"])
d = b"hello world, this is a test buffer"
walk = list(m.det_bitflip_walk(b"AB"))
check("det walk yields len*8 mutants", len(walk) == 16 and len({bytes(w) for w in walk}) == 16)
h = m.havoc(d)
check("havoc changes bytes", h != d)
check("havoc caps length", len(m.havoc(b"A" * 70000)) <= 65536)
s = m._splice(b"AAAA", b"BBBB")
check("splice mixes parents", set(s) <= {65, 66} and len(s) > 0)
check("interesting values hit boundary set", any(v in m._interesting(bytes(8)) for v in [0, 255]))

# --- 4. end-to-end: planted bugs in a toy parser ---
# Bug 2 is unbounded per-byte recursion (the classic nested-structure CVE
# shape: parser recurses once per input byte, no depth cap). Any input grown
# past ~57 bytes crashes it; the hit-count gradient must guide the growth.
import sys as _sys
def buggy_parse(data):
    _sys.setrecursionlimit(60)
    try:
        return _buggy_parse(data)
    finally:
        _sys.setrecursionlimit(1000)

def _buggy_parse(data):
    # bug 1: IndexError when 0xFF appears at position 2 (unchecked index)
    if len(data) >= 3 and data[2] == 0xFF:
        table = [1, 2]
        return table[data[0]]          # IndexError for data[0] > 1
    # bug 2: one stack frame per input byte, no depth limit
    def walk(i):
        if i < len(data):
            return data[i] + walk(i + 1)
        return 0
    if len(data) > 10:
        return walk(0)
    if not data:
        raise ToyError("empty")
    return data[0]

fz = Fuzzer(buggy_parse, [b"abc", b"(x)"], [HERE],
            expected_exc=(ToyError,), dictionary=[b"(", b"(("],
            timeout=3, seed=42)
fz.run(max_execs=4000, max_secs=90, log_every=4000)
sigs = {s[0] for s in fz.crashes}
check("e2e: planted IndexError found", "IndexError" in sigs, str(sorted(sigs)))
check("e2e: planted RecursionError found", "RecursionError" in sigs, str(sorted(sigs)))
check("e2e: coverage grew beyond seed", len(fz.global_edges) > 10, f"{len(fz.global_edges)} edges")

# --- 5. dedupe: same root cause, different inputs -> one bucket ---
def samebug(data):
    lst = [1]
    return lst[data[0] % 5 + 1]   # IndexError via two different trigger bytes
fz2 = Fuzzer(samebug, [b"\x00"], [HERE], expected_exc=(ToyError,), seed=7)
fz2.run(max_execs=1500, max_secs=45, log_every=1500)
check("dedupe: one bucket for one bug", len(fz2.crashes) == 1, f"{len(fz2.crashes)} buckets")

# --- 6. minimizer shrinks a crashing input ---
def crashpad(data):
    if len(data) > 50 and data[10] == 0x7F and data[40] == 0x7F:
        raise IndexError("pad-bug")
    raise ToyError("nope")
fz3 = Fuzzer(crashpad, [b"\x00" * 200], [HERE], expected_exc=(ToyError,), seed=3)
# hand it a known crashing input (deterministic stage will flip bits to find it too)
big = bytearray(200); big[10] = 0x7F; big[40] = 0x7F
r = fz3._exec(bytes(big))
sig = fz3._sig(r["tb"])
mini = fz3.minimize(bytes(big), sig)
check("minimizer: still crashes", fz3._exec(mini)["status"] == "crash")
check("minimizer: strictly smaller", len(mini) < 200, f"{len(mini)} bytes")
check("minimizer: keeps both trigger bytes", mini.count(0x7F) >= 2)

# --- 7. trim preserves coverage ---
def branchy(data):
    if len(data) > 4 and data[0] == 0xAA and data[4] == 0xBB:
        return "deep"
    return "shallow"
fz4 = Fuzzer(branchy, [b"\xaaPAD\xbb" + b"Z" * 100], [HERE], expected_exc=(ToyError,), seed=9)
e = fz4.queue[0]
r0 = fz4._exec(e.data); before = set(r0["edges"])
fz4._note_coverage_input(e.data, r0["edges"])  # seed the global edge set
newlen = fz4._trim(e)
r1 = fz4._exec(e.data); after = set(r1["edges"])
check("trim: shrinks", newlen < 105, f"{newlen}")
check("trim: coverage preserved", before.issubset(after))

print(f"\n{sum(1 for _, c in checks if c)}/{len(checks)} checks passed")
sys.exit(0 if all(c for _, c in checks) else 1)
