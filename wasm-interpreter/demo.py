#!/usr/bin/env python3
"""demo.py -- what the wasm interpreter is FOR: sandboxed plugins.

A wasm module is untrusted code. The only things it can touch are what the
host explicitly grants: imported functions, its own linear memory, nothing
else. No filesystem, no network, no syscalls -- those don't exist in the
instruction set. This demo runs an "untrusted plugin" three ways:
  1. normal: it logs and computes through host-granted functions
  2. hostile: it tries to read outside its memory -> clean WasmTrap
  3. fib: real recursion through the interpreter
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wasm
from wasm import WasmTrap
import emit
from emit import *


def plugin_module():
    """Untrusted plugin: imports env.log(i32) and env.store(i32,i32)->i32,
    exports run() -> i32. Computes (6*7)+log, stores via host."""
    m = Module()
    tlog = m.typedef(['i32'], [])
    tstore = m.typedef(['i32', 'i32'], ['i32'])
    trun = m.typedef([], ['i32'])
    m.import_func('env', 'log', tlog)      # funcidx 0
    m.import_func('env', 'store', tstore)  # funcidx 1
    body = (i32_const(6 * 7) + call(0)          # log(42)
            + i32_const(6 * 7)                    # [42]
            + i32_const(1) + i32_const(99) + call(1)  # [42, store_result]
            + intop('i32.add')                     # [43]
            + end())
    m.def_func(trun, [], body)
    m.export('run', 'func', 2)
    return m.build()


def hostile_module():
    """Tries to read 1GB past its memory. The spec says: trap."""
    m = Module()
    t = m.typedef([], ['i32'])
    m.memory(1, 1)
    m.def_func(t, [], i32_const(2**30) + memop('i32.load') + end())
    m.export('run', 'func', 0)
    return m.build()


def fib_module():
    m = Module()
    t = m.typedef(['i32'], ['i32'])
    body = (local_get(0) + i32_const(2) + intop('i32.lt_s')
            + if_(['i32']) + local_get(0) + else_()
            + local_get(0) + i32_const(1) + intop('i32.sub') + call(0)
            + local_get(0) + i32_const(2) + intop('i32.sub') + call(0)
            + intop('i32.add') + end() + end())
    m.def_func(t, [], body)
    m.export('fib', 'func', 0)
    return m.build()


def main():
    print('== 1. sandboxed plugin ==')
    log, store = [], {}

    def host_log(x):
        log.append(x)

    def host_store(k, v):
        store[k] = v
        return len(store)

    inst = wasm.load(plugin_module(),
                     {('env', 'log'): host_log, ('env', 'store'): host_store})
    print('run() ->', inst.invoke('run'))
    print('plugin could only do what we granted: log =', log,
          'store =', store)

    print('== 2. hostile plugin ==')
    inst = wasm.load(hostile_module())
    try:
        inst.invoke('run')
        print('NO TRAP -- sandbox broken!')
    except WasmTrap as e:
        print('trapped cleanly:', e)

    print('== 3. fib(20) through the interpreter ==')
    inst = wasm.load(fib_module())
    print('fib(20) =', inst.invoke('fib', [20])[0])


if __name__ == '__main__':
    main()
