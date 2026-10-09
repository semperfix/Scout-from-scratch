# FoxScript — learnings

## 1. Python's augmented assignment evaluates the target before the RHS

The nastiest bug of the expedition. The VM had:

```python
self._frame().ip -= self._read_u16()
```

`obj.attr -= f()` compiles to roughly `t = obj; old = t.attr; t.attr = old - f()`.
The RHS `_read_u16()` advances `ip` by 2 (reading the operand bytes), but the
store writes back `old_ip - offset`, **silently discarding the 2-byte advance**.
Every LOOP and JUMP landed 2 bytes early and re-executed garbage — a while loop
re-ran `DEFINE_GLOBAL`, which popped the script closure off the stack and
stored it as a variable, producing a baffling "operands must be two numbers"
two statements later.

It was extra confusing because `JUMP_IF_FALSE`/`JUMP_IF_TRUE` were immune: they
used a temp (`offset = self._read_u16()` then `self._frame().ip += offset`),
where the load happens after the reads. And adding debug prints to LOOP
"fixed" the bug, because the rewrite used the two-step form — a textbook
Heisenbug. Rule earned: **never put a side-effecting call on the RHS of an
augmented attribute assignment.**

## 2. On RETURN, discard the callee's window — not the caller's

First attempt truncated the stack to the *caller's* base on return, wiping the
caller's own locals and pending operands (fib computed `fib(n-1)` then read
the *result* back as `n`). The correct picture: the callee's window starts at
the callee value itself, sitting *above* the caller's region. Return = pop the
result, `del stack[callee_base:]`, push the result where the callee was. The
caller's slots below are untouched, which is exactly why the callee's frame can
overlap the caller's operand stack in the first place.

## 3. Upvalues are a compile-time structure, not a runtime one

`_resolve_upvalue` walks the *compiler* chain (marking locals captured as it
goes) and collects `(is_local, index)` on the child Compiler — but the
`CLOSURE` instruction and the disassembler read them off the `Function`
object, whose list was always empty. Closures silently captured nothing
(`GET_UPVALUE` → IndexError). Fix: copy `child.upvalues` onto the function
when finalizing it. The general lesson: when two structures must agree across
a phase boundary (compile-time collection vs runtime use), assert the handoff
exists rather than assuming it.

## 4. Jump patching wants a strict emit/patch discipline

`emit_jump` returns the offset of the first operand byte; `patch_jump` writes
`target - (offset + 2)` big-endian. The `+2` is the whole contract — get it
wrong and every loop/if silently misbehaves. Disassembling early (the `--dis`
flag) paid for itself immediately: the fib bug was visible as correct
bytecode, which correctly redirected suspicion from the compiler to the VM.

## 5. `and`/`or` are value-producing; JUMP_IF_FALSE must not pop

For `a && b` to evaluate to `a` when `a` is falsy (not just `false`), the
conditional jump has to *leave* the condition on the stack. So the VM's
conditional jumps never pop, and `if`/`while` emit an explicit POP after the
jump. One instruction, two callers, different stack discipline — documented at
the opcode, not hoped for.

## 6. Fewer opcodes via desugaring (twice)

`<=` compiles to `GREATER` + `NOT`; `for` never reaches the compiler at all —
the parser rewrites it to `{ init; while (cond) { body; incr; } }`. Both keep
the VM small (35 opcodes) at the cost of slightly larger bytecode. A language
is mostly decisions about what *not* to implement.

## 7. `print` as a builtin function beats `print` as a statement

No special syntax, no special compilation — `print(x)` is just a CALL of a
variadic native. It composes (`print(f(x))`), and the REPL gets it for free.

## 8. Latent gotcha noted: `list.index` and `True == 1.0`

Constant dedup via `chunk.constants.index(value)` aliases `True` with `1.0`
in Python. It didn't bite (no boolean constants pooled alongside 1.0 in the
tests), but a production constant pool needs type-tagged equality.

## 9. Tests caught the design bugs; the bug that bit hardest was in the harness language, not the language

45 tests, all green — but the worst bug (item 1) was a Python semantics trap
in the VM *implementation*, invisible to language-level tests until loops ran.
Same moral as expedition #31: test the contract ("jump lands exactly on the
target instruction"), not just the outcomes.
