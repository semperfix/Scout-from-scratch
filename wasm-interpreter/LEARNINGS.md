# Learning expedition #44 — WebAssembly MVP interpreter from scratch

## What was built

`~/workspace/learning/44-wasm/`:
- **`wasm.py`** (~1,260 lines, zero deps) — a real three-stage engine:
  1. **decode**: binary format → Module dict. All 12 section ids, LEB128 (signed/unsigned), block types, init exprs, limits. Malformed input → `WasmError`, never silent garbage.
  2. **validate**: spec-style type checking — value-type stack + control-frame stack with **unreachable-polymorphism** (after `unreachable`/`br`/`return`, popped types are "unknown", not errors), in the same pass that **patches every branch to an absolute target pc**.
  3. **execute**: pc-driven stack machine with explicit call stack and label stack. i32/i64 integer ops, linear memory (all loads/stores, `memory.size/grow`), tables + `call_indirect` with signature checks, globals, host-function imports, start functions, data/elem segments. Spec traps (`WasmTrap`): div-by-zero, `INT_MIN/-1`, OOB memory, `unreachable`, null/signature-mismatched indirect calls.
- **`emit.py`** — mini assembler (shares the opcode table with the interpreter so the two can't drift).
- **`test_wasm.py`** — 260 checks: unit tests, 10 validation-rejection tests, differential vs Node/V8, and a 200-module random-program fuzzer vs V8 (plus 300 more across 2 extra seeds: **500/500 agree**).
- **`wasmrun.mjs`** — Node harness driving V8's real `WebAssembly` engine as the oracle.
- **`demo.py`** — sandboxed-plugin demo: untrusted module gets only granted host functions; hostile OOB read traps cleanly; fib(20)=6765 through the interpreter.

Deliberate gaps, named: f32/f64, SIMD, bulk-memory, multi-value, threads, GC.

## Earned insights (all paid for in debugging, most caught by V8)

1. **The oracle is the spec you can't memorize.** My recalled opcode table had `i32.clz=0x5b` — V8 said "f32.eq". I had dropped the entire float-comparison block (`0x5b–0x66`) from memory, shifting clz/ctz/popcnt to the wrong slots. Empirical probe confirmed the real layout: `0x67/0x68/0x69`. Never trust a memorized constant table; probe it.
2. **MVP elem/data kind-0 segments have no index field.** I "remembered" `flag, tableidx, offset` — V8 rejected it: table/memory 0 is *implied*; the explicit index only exists in the bulk-memory proposal. Same class of error as #1: memory of the spec ≠ the spec.
3. **`memory.size`/`memory.grow` carry a reserved `0x00` byte.** Without consuming it, the decoder reads the next opcode as a memory index ("memory index 65 exceeds..."). Reserved bytes are load-bearing.
4. **Signed LEB128 must be canonical.** `i32.const 0x80000000` encoded as unsigned-style `80 80 80 80 08` → V8: "extra bits in varint". Consts must be masked into the type's signed range *before* SLEB encoding.
5. **Branch-to-function-label is exactly `return`.** My pc-driven design would have popped the func label and jumped past the final `end` into nowhere; compiling `br`-to-func as `return` at validation time deletes the whole problem class.
6. **Validation and branch resolution want to be one pass.** Both walk the identical control structure; doing them together means the label arities/heights the validator proves are the ones the patcher uses — they can't disagree.
7. **The `if`-without-`else` false-branch must land ON the `end` op, not past it** — the `end` op is what pops the label. Landing past it leaks a label entry. (Caught by re-reading, not by test — the kind of bug a fuzzer rarely trips because it needs the exact shape.)
8. **Fuzz agreement can be vacuous.** 200 modules passed while my `clz` opcode was wrong — the 0x5b bytes in the corpus were LEB immediates, and `unop` draws rarely materialized as real opcodes. A differential fuzzer only proves what it actually emits; the targeted opcode probe is what caught it.

## Validation

- `test_wasm.py`: **260/260** (units incl. fib/fact/br_table/indirect/host-imports/globals-persistence/start/data-segments, 10 validation rejections, 5 trap kinds).
- Differential vs V8: every unit module + **500 random programs across 3 seeds agree** with Node's engine on values *and* traps.
- Real bugs found by V8, fixed: opcode table (clz/ctz/popcnt), elem/data segment shape, memory.size/grow reserved byte, SLEB canonicalization.

## New capability

Execute untrusted WebAssembly modules in a true sandbox: the module's universe is its linear memory + granted host functions + nothing else — no syscalls exist in the instruction set. The tool for running, inspecting, and forensically analyzing wasm blobs (browser extensions ship them, malware droppers ship them, plugins ship them): decode it, validate it, watch exactly what it does, catch every escape attempt as a clean trap.
