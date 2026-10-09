# FoxScript — a programming language from scratch

FoxScript is a complete little scripting language built with zero dependencies: a hand-written lexer, a recursive-descent parser, a bytecode compiler, and a stack-based VM, in about 1,500 lines of Python. It supports closures with real upvalues, first-class functions, arrays, maps, short-circuit logic, and clean runtime errors with line numbers. Ship it a `.fox` file and it lexes, parses, compiles, and runs it end to end.

## Dependencies

Python 3 standard library only. No third-party packages (verified: `lexer.py`, `parser.py`, `compiler.py`, `vm.py`, `natives.py`, `fox.py` import only `sys`, `time`, and each other).

## How to run

Entry point: `fox.py`

```
python3 fox.py demo/paycheck.fox        # Abe wages ledger
python3 fox.py demo/tree_estimate.fox   # tree-job estimator
python3 fox.py                         # REPL (globals persist between lines)
python3 fox.py --dis prog.fox          # disassemble bytecode instead of running
python3 tests/run_tests.py              # 45-test suite (language + error cases)
```

## Usage example

The language itself:

```js
// closures capture
fn counter() {
  let c = 0;
  return fn() { c = c + 1; return c; };
}
let a = counter();
print(a());  // 1
print(a());  // 2

let crew = ["kyle", "tony"];
crew = push(crew, "amanda");
let job = {"trees": 6, "hazard": 2};
print(job["trees"]);

for (let i = 0; i < 3; i = i + 1) { print(i); }  // desugared to while in the parser
```

And running it:

```
$ python3 fox.py demo/paycheck.fox
=== Boss Man Abe: wages owed ===
gross claimed:       $450
top rail piece:     -$30
net owed:            $420
cash app proof:      none received
stories so far:      3 (sent it / bad reception / app stuck)
```

Types: numbers (float), strings, booleans, nil, arrays, maps, functions. Only `false` and `nil` are falsy. Builtins: `print len push pop keys has str num type assert range clock`. Non-goals: no classes, modules, `break`/`continue`, string interpolation, or tail-call optimization.

## Key learnings (from LEARNINGS.md)

- Python's augmented assignment evaluates the target before the RHS — `frame.ip -= self._read_u16()` silently discarded the 2-byte operand advance and made every loop jump 2 bytes early (a Heisenbug that "fixed" itself when debug prints changed the code shape). Never put a side-effecting call on the RHS of an augmented attribute assignment.
- Upvalues are a compile-time structure, not a runtime one: the child `Compiler` collects `(is_local, index)` pairs, but the runtime `Function` object reads them off itself — so they must be explicitly copied onto the `Function` at finalization, or closures silently capture nothing.
- Desugar aggressively to keep the VM small: `<=` compiles to `GREATER` + `NOT`, and `for` never reaches the compiler at all (the parser rewrites it to `{ init; while (cond) { body; incr; } }`). A language is mostly decisions about what *not* to implement.
- Disassembling early pays for itself: the fib bug was visible as correct bytecode, which correctly redirected suspicion from the compiler to the VM. Test the contract ("jump lands exactly on the target instruction"), not just outcomes.

## Files

- `fox.py` — CLI driver: run files, REPL, `--dis` disassembler
- `lexer.py` — tokenizer (escapes, `//` comments, newline suppression inside brackets)
- `parser.py` — recursive-descent parser → AST (desugars `for` to `while`)
- `compiler.py` — AST → bytecode (scopes → stack slots, free vars → upvalues, jump patching)
- `vm.py` — stack VM: call frames, value stack, open-upvalue list, 35 opcodes
- `natives.py` — builtin functions
- `demo/` — `paycheck.fox`, `tree_estimate.fox` (real-world demo scripts)
- `tests/` — `run_tests.py` harness + 50 `.fox` test programs (features + 14 error cases)
- `LEARNINGS.md` — full expedition notes
