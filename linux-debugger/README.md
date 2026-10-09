# Linux Debugger (ptrace)

`foxdbg` is a from-scratch Linux x86-64 debugger built on `ptrace`, with zero dependencies beyond the stdlib. It spawns a process under `PTRACE_TRACEME` or attaches to a live pid, then offers the classic debugger toolkit: software breakpoints (int3 patching with original-byte save/restore), single-stepping, continue-to-breakpoint, full register dumps (`user_regs_struct`) with targeted register set, arbitrary memory read/write via PEEK/POKE, backtraces by walking the rbp frame-pointer chain, a tiny x86-64 disassembler for readable `step` display, and a scripted REPL (`break/b`, `continue/c`, `step/s`, `regs`, `x`, `bt`, `dis`, `quit`). `target.c` / `target2.c` are small C programs (rebuilt below) that the test suite debugs.

## Dependencies

Python 3 standard library only (`ctypes`, `os`, `signal`, `struct`, `sys` — verified). **Linux x86-64 only** (hard dependency on ptrace request numbers, the `user_regs_struct` layout, and the `u_debugreg` offset). C test targets need `gcc` to rebuild.

## How to run

Entry point: `foxdbg.py` (as a library, plus a scripted REPL)

```
gcc target.c -o target      # rebuild the C test targets (binaries not shipped)
gcc target2.c -o target2
python3 test_foxdbg.py      # exercises breakpoints/regs/memory/step against the targets
```

Scripted REPL example (from inside the debugger session):

```
(b) break *main+10     # software breakpoint
(b) continue           # run to breakpoint
(b) regs               # register dump
(b) x rip 8            # examine 8 words at rip
(b) step               # single-step with disassembly display
(b) bt                 # backtrace via rbp chain
(b) quit
```

## Usage example

```python
from foxdbg import Debugger, mem_read, dis_one

dbg = Debugger("path/to/target")      # spawn under PTRACE_TRACEME
dbg.attach_break(main_addr)           # int3 patch, original byte saved
dbg.continue_()                       # run until the breakpoint hits
print(dbg.regs()["rip"])              # full user_regs_struct dump
print(dis_one(dbg, dbg.regs()["rip"]))  # disassemble the current instruction
raw = mem_read(dbg.pid, stack_addr, 64)
```

## Key learnings

- Breakpoints are just memory writes: `int3` (0xCC) is patched over the target instruction's first byte and the original byte is saved; when the trap fires, the debugger restores the byte, backs `rip` up by one, and re-arms the breakpoint after stepping. Single-step + re-arm is the whole dance.
- A backtrace needs no symbol tables when code uses frame pointers: walk `rbp` → `[rbp]` = previous rbp, `[rbp+8]` = return address, repeat until rbp is 0. The debugger only breaks when `-fno-omit-frame-pointer` code is involved.
- ptrace talks in words, not bytes: PEEK/POKE move whole 8-byte words, so byte-granularity memory reads need shift-and-mask on word-aligned reads; the request numbers and `struct user` debug-register offset (848 on x86-64) are ABI constants, not portable values.
- `PTRACE_GETREGS` returns the full `user_regs_struct` — a 27-field ctypes structure laid out register-for-register. Getting the field order wrong corrupts every register name silently; the disassembler + a known `rip` is the ground truth to validate against.

## Files

- `foxdbg.py` — the debugger: ptrace bindings, breakpoints, regs, memory R/W, backtrace, disassembler, REPL
- `test_foxdbg.py` — test suite driving the debugger against the C targets
- `target.c`, `target2.c` — small C debug targets (source only; build with `gcc -o target target.c` / `gcc -o target2 target2.c`)
