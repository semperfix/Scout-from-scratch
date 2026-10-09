#!/usr/bin/env python3
"""FoxScript driver: run files, start a REPL, or disassemble bytecode.

Usage:
    python3 fox.py prog.fox      run a script
    python3 fox.py               start the REPL (globals persist)
    python3 fox.py --dis prog.fox   dump bytecode chunks
"""

import sys

from lexer import Lexer, LexError
from parser import Parser, ParseError
from compiler import compile_program, CompileError, OP_NAMES
from vm import VM, FoxError


def compile_source(source):
    tokens = Lexer(source).tokenize()
    program = Parser(tokens).parse()
    return compile_program(program)


def run_source(source, vm, filename="<stdin>"):
    try:
        fn = compile_source(source)
    except (LexError, ParseError, CompileError) as e:
        sys.stderr.write("%s: %s\n" % (filename, e))
        return 65  # EX_DATAERR, like clox
    except RecursionError:
        # hostile or absurd nesting depth: fail clean, never traceback
        sys.stderr.write("%s: expression too deeply nested\n" % filename)
        return 65
    try:
        vm.interpret(fn)
    except FoxError as e:
        sys.stderr.write("Runtime error: %s\n" % e)
        return 70
    return 0


def disassemble(fn, out=None):
    out = out or sys.stdout

    def show(f, depth):
        ch = f.chunk
        out.write("%s== %s (arity %d) ==\n" % ("  " * depth,
                                              f.name or "<anon>", f.arity))
        i = 0
        code = ch.code
        while i < len(code):
            op = code[i]
            name = OP_NAMES.get(op, "?%d" % op)
            line = ch.lines[i]
            ops = ""
            i += 1
            # no-operand ops: NIL TRUE FALSE POP EQUAL GREATER LESS
            # ADD SUBTRACT MULTIPLY DIVIDE MOD POWER NEGATE NOT
            # CLOSE_UPVALUE RETURN GET_INDEX SET_INDEX
            if op in (1, 2, 3, 4, 12, 13, 14, 15, 16, 17, 18, 19, 20,
                      21, 22, 29, 30, 33, 34):
                pass
            elif op in (23, 24, 25, 26):  # jumps: u16
                ops = "%d" % ((code[i] << 8) | code[i + 1])
                i += 2
            elif op == 0:  # CONSTANT
                idx = code[i]
                ops = "%d (%r)" % (idx, _const_repr(ch.constants[idx]))
                i += 1
            elif op == 28:  # CLOSURE
                idx = code[i]
                fnc = ch.constants[idx]
                ops = "%d (%r) upvalues=%s" % (
                    idx, _const_repr(fnc), fnc.upvalues)
                i += 1 + 2 * len(fnc.upvalues)
            else:  # single u8 operand
                ops = "%d" % code[i]
                if op in (9, 10, 11):
                    ops += " (%r)" % ch.constants[code[i]]
                i += 1
            out.write("  %04d  line %-4d %-14s %s\n" % (i, line, name, ops))
        for c in ch.constants:
            if hasattr(c, "chunk"):
                show(c, depth + 1)

    def _const_repr(c):
        return c

    show(fn, 0)


def repl():
    vm = VM()
    print("FoxScript REPL -- Ctrl-D to quit")
    while True:
        try:
            line = input("fox> ")
        except EOFError:
            print()
            break
        if not line.strip():
            continue
        run_source(line, vm, filename="<repl>")


def main(argv):
    if len(argv) == 1:
        repl()
        return 0
    if argv[1] == "--dis" and len(argv) == 3:
        with open(argv[2]) as f:
            src = f.read()
        try:
            fn = compile_source(src)
        except (LexError, ParseError, CompileError) as e:
            sys.stderr.write("%s: %s\n" % (argv[2], e))
            return 65
        disassemble(fn)
        return 0
    if len(argv) == 2:
        with open(argv[1]) as f:
            src = f.read()
        return run_source(src, VM(), filename=argv[1])
    sys.stderr.write("usage: fox.py [prog.fox | --dis prog.fox]\n")
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv))
