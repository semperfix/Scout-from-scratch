# WebAssembly MVP Interpreter — Three-Stage Engine from Scratch

A real WebAssembly MVP engine in ~1,260 lines of dependency-free Python:
`wasm.py` is a three-stage pipeline — **decode** (binary format → Module dict;
all 12 section ids, signed/unsigned LEB128, block types, init exprs, limits;
malformed input raises `WasmError`, never silent garbage), **validate**
(spec-style type checking with value-type + control-frame stacks including
unreachable-polymorphism, in the same pass that patches every branch to an
absolute target pc), and **execute** (pc-driven stack machine with explicit
call and label stacks). Integer ops (i32/i64), linear memory (all loads/stores,
`memory.size`/`memory.grow`), tables + `call_indirect` with signature checks,
globals, host-function imports, start functions, and data/elem segments, with
spec traps (`WasmTrap`): divide-by-zero, `INT_MIN/-1`, out-of-bounds memory,
`unreachable`, null/signature-mismatched indirect calls. `emit.py` is a mini
assembler that shares the opcode table with the interpreter so the two can't
drift; `demo.py` runs a sandboxed-plugin scenario (untrusted module gets only
granted host functions; a hostile OOB read traps cleanly; fib(20)=6765 through
the interpreter).

**Validation: `test_wasm.py` 260/260** — units (fib/fact/br_table/indirect/
host-imports/globals-persistence/start/data-segments), 10 validation-rejection
tests, 5 trap kinds, differential tests against Node/V8, plus a 200-module
random-program fuzzer — with 300 more across 2 extra seeds, **500/500 random
programs agree** with V8 on values *and* traps. V8 caught real bugs during
development (opcode table layout, elem/data segment shape, `memory.size`/`grow`
reserved byte, SLEB canonicalization); all fixed and locked in by tests.

## Dependencies

- **Stdlib only** for `wasm.py`, `emit.py`, and `demo.py` — no pip packages.
- The **differential/fuzzer tests** in `test_wasm.py` additionally require
  **Node.js**: `wasmrun.mjs` drives V8's real `WebAssembly` engine as the
  oracle via `subprocess`. If `node` isn't on PATH, those tests are the only
  part that fails.

## How to run

```
python3 demo.py            # sandboxed plugin: granted, hostile, fib(20)
python3 test_wasm.py       # 260 checks; differential+fuzzer need node

# drive the node oracle directly (expects a module + request JSON):
node wasmrun.mjs module.wasm request.json
```

`request.json` shape: `{"calls": [{"name": "main", "args": [["i32", 5],
["i64", "123"]]}]}` — prints `{"results": [...], "logged": [...]}`.

## Usage example

```python
import sys
sys.path.insert(0, ".")
import wasm, emit
from emit import *

# assemble a module by hand, run it through the interpreter
m = Module()
t = m.typedef(['i32'], ['i32'])
m.memory(1, 1)
body = (local_get(0) + local_get(0) + intop('i32.add') + end())
m.def_func(t, [], body)
m.export('run', 'func', 0)
inst = wasm.load(m.build(), {})

print(inst.invoke('run', [21]))   # -> [42]

# memory is bounded: reading 1 GiB out of a 1-page memory traps, it doesn't segfault
m2 = Module()
t2 = m2.typedef([], ['i32'])
m2.memory(1, 1)
m2.def_func(t2, [], i32_const(2**30) + memop('i32.load') + end())
m2.export('run', 'func', 0)
inst2 = wasm.load(m2.build(), {})
try:
    inst2.invoke('run')
except wasm.WasmTrap as e:
    print("trapped cleanly:", e)   # -> out of bounds memory access
```

## Limitations

- **MVP only.** Deliberate gaps, named in the source: no f32/f64, no SIMD, no
  bulk-memory, no multi-value, no threads, no GC. f32/f64 blocks occupy
  opcodes `0x5b–0x66` — the interpreter will reject modules containing them.
- **It's an interpreter, not a JIT.** Correct but slow — real recursion like
  fib(20) is the sweet spot; heavy numeric loops will be orders of magnitude
  slower than V8.
- **Differential and fuzzer tests require Node.js** (`wasmrun.mjs` needs V8's
  `WebAssembly`). Pure-Python unit tests don't.
- The fuzzer emits random *valid* programs — it only proves what it actually
  emits (an early opcode-table bug survived 200 fuzz modules because the
  corpus never materialized the real opcodes). Targeted probes, not just fuzz
  volume, are what keep the table honest.
- Validation is spec-style but the engine isn't a byte-for-byte spec clone;
  error messages are `WasmError`/`WasmTrap` strings, not spec-formatted.
