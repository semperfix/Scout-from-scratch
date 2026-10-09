#!/usr/bin/env python3
"""test_wasm.py -- unit tests + differential tests vs Node/V8 + fuzzer."""
import json
import os
import random
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wasm
from wasm import WasmError, WasmTrap
import emit
from emit import *

PASS = 0
FAIL = 0
FAILURES = []


def check(name, cond, detail=''):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        FAILURES.append(name)
        print('FAIL: %s %s' % (name, detail))


def expect_trap(name, fn):
    try:
        fn()
    except WasmTrap:
        check(name, True)
        return
    except Exception as e:
        check(name, False, 'wrong exception: %r' % e)
        return
    check(name, False, 'no trap raised')


def expect_verror(name, fn):
    try:
        fn()
    except WasmTrap:
        check(name, False, 'trap instead of validation error')
    except WasmError:
        check(name, True)
    except Exception as e:
        check(name, False, 'wrong exception: %r' % e)
    else:
        check(name, False, 'no error raised')


# --------------------------------------------------------------------------
# differential harness vs node
# --------------------------------------------------------------------------

HERE = os.path.dirname(os.path.abspath(__file__))


def run_node(wasm_bytes, calls):
    wp = rp = None
    try:
        with tempfile.NamedTemporaryFile(suffix='.wasm',
                                         delete=False) as f:
            f.write(wasm_bytes)
            wp = f.name
        with tempfile.NamedTemporaryFile(suffix='.json', mode='w',
                                         delete=False) as f:
            json.dump({'calls': calls}, f)
            rp = f.name
        p = subprocess.run(['node', os.path.join(HERE, 'wasmrun.mjs'),
                            wp, rp], capture_output=True, text=True,
                           timeout=30)
        return json.loads(p.stdout)
    finally:
        for q in (wp, rp):
            if q:
                try:
                    os.unlink(q)
                except OSError:
                    pass


def norm_mine(results, types):
    out = []
    for v, t in zip(results, types):
        out.append(str(int(v)))
    return out


def norm_node(r):
    v = r['value']
    if isinstance(v, dict) and 'i64' in v:
        return v['i64']
    return str(int(v))


def diff_check(name, wasm_bytes, calls, imports=None, argtypes=None):
    """Run calls on both engines; results (or traps) must agree."""
    imports = imports or {}
    node = run_node(wasm_bytes, calls)
    if 'link_error' in node:
        expect_verror(name + ' [node link error -> mine rejects]',
                      lambda: wasm.load(wasm_bytes, imports))
        return
    try:
        inst = wasm.load(wasm_bytes, imports)
    except WasmError as e:
        check(name, False, 'mine rejected but node linked: %s' % e)
        return
    for call, nres in zip(calls, node['results']):
        cname = call['name']
        args = [a[1] if a[0] == 'i32' else int(a[1]) for a in call['args']]
        try:
            mres = inst.invoke(cname, args)
            mok, mtrap = True, False
        except WasmTrap:
            mok, mtrap = False, True
        if nres.get('ok'):
            types = (argtypes or {}).get(cname, [])
            check(name + '/' + cname,
                  mok and norm_mine(mres, types) == [norm_node(nres)],
                  'mine=%r node=%r' % (mres if mok else 'TRAP',
                                        nres['value']))
        else:
            check(name + '/' + cname + ' trap',
                  mtrap and nres.get('trap'),
                  'mine_trap=%s node=%r' % (mtrap, nres))


def ncalls(name, args, restype):
    """Build node call specs + expected result types."""
    return [{'name': name,
             'args': [['i32', a] if not isinstance(a, tuple) else [a[0], str(a[1])]
                      for a in args]}], {name: [restype]}


def dc(name, wasm_bytes, cname, args, restype, imports=None):
    """diff_check with the ncalls tuple wired to the right parameters."""
    calls, rt = ncalls(cname, args, restype)
    diff_check(name, wasm_bytes, calls, imports=imports, argtypes=rt)


def dcn(name, wasm_bytes, speclist, imports=None):
    """diff_check for several (cname, args, restype) calls at once."""
    calls, rt = [], {}
    for cname, args, restype in speclist:
        c, r = ncalls(cname, args, restype)
        calls += c
        rt.update(r)
    diff_check(name, wasm_bytes, calls, imports=imports, argtypes=rt)


# --------------------------------------------------------------------------
# unit test modules
# --------------------------------------------------------------------------

def mod_arith():
    m = Module()
    t = m.typedef([], ['i32'])
    body = (i32_const(40) + i32_const(2) + intop('i32.add')
            + i32_const(3) + intop('i32.mul')
            + i32_const(10) + intop('i32.sub') + end())
    m.def_func(t, [], body)
    m.export('main', 'func', 0)
    return m.build()


def mod_locals():
    m = Module()
    t = m.typedef(['i32'], ['i32'])
    # a*a + 2*a + 1 ; extra local for tmp
    body = (local_get(0) + local_get(0) + intop('i32.mul') + local_set(1)
            + local_get(0) + i32_const(2) + intop('i32.mul')
            + local_get(1) + intop('i32.add')
            + i32_const(1) + intop('i32.add') + end())
    m.def_func(t, ['i32'], body)
    m.export('main', 'func', 0)
    return m.build()


def mod_fact():
    m = Module()
    t = m.typedef(['i32'], ['i32'])
    body = (local_get(0) + local_set(1)
            + i32_const(1) + local_set(2)
            + block()
            + loop()
            + local_get(1) + intop('i32.eqz') + br_if(1)
            + local_get(2) + local_get(1) + intop('i32.mul') + local_set(2)
            + local_get(1) + i32_const(1) + intop('i32.sub') + local_set(1)
            + br(0)
            + end() + end()
            + local_get(2) + end())
    m.def_func(t, ['i32', 'i32'], body)
    m.export('main', 'func', 0)
    return m.build()


def mod_fib():
    m = Module()
    t = m.typedef(['i32'], ['i32'])
    # fib is funcidx 0 (no imports)
    body = (local_get(0) + i32_const(2) + intop('i32.lt_s')
            + if_(['i32'])
            + local_get(0)
            + else_()
            + local_get(0) + i32_const(1) + intop('i32.sub') + call(0)
            + local_get(0) + i32_const(2) + intop('i32.sub') + call(0)
            + intop('i32.add')
            + end() + end())
    m.def_func(t, [], body)
    m.export('main', 'func', 0)
    return m.build()


def mod_max():
    m = Module()
    t = m.typedef(['i32', 'i32'], ['i32'])
    body = (local_get(0) + local_get(1) + intop('i32.gt_s')
            + if_(['i32']) + local_get(0) + else_() + local_get(1)
            + end() + end())
    m.def_func(t, [], body)
    m.export('main', 'func', 0)
    return m.build()


def mod_brtable():
    m = Module()
    t = m.typedef(['i32'], ['i32'])
    body = (block(['i32'])            # $out
            + block() + block() + block() + block()   # $c3 $c2 $c1 $c0
            + local_get(0) + br_table([0, 1, 2, 3], 3)
            + end()
            + i32_const(10) + br(3)
            + end()
            + i32_const(20) + br(2)
            + end()
            + i32_const(30) + br(1)
            + end()
            + i32_const(40)
            + end() + end())
    m.def_func(t, [], body)
    m.export('main', 'func', 0)
    return m.build()


def mod_memory():
    m = Module()
    t = m.typedef([], ['i32'])
    m.memory(1, 2)
    m.data(i32_const(1000) + end(), b'Hi')
    body = (i32_const(100) + i32_const(0x12345678) + memop('i32.store')
            + i32_const(100) + memop('i32.load')
            + i32_const(200) + i32_const(0xAB) + memop('i32.store8')
            + i32_const(200) + memop('i32.load8_u')
            + intop('i32.add')
            + i32_const(1000) + memop('i32.load8_u')
            + intop('i32.add')
            + end())
    m.def_func(t, [], body)
    m.export('main', 'func', 0)
    return m.build()


def mod_memgrow():
    m = Module()
    t = m.typedef([], ['i32'])
    m.memory(1, 3)
    body = (memory_size()
            + i32_const(1) + memory_grow() + intop('i32.add')
            + memory_size() + intop('i32.add')
            + i32_const(100) + memory_grow()   # fails: max 3, have 2
            + intop('i32.add')
            + end())
    m.def_func(t, [], body)
    m.export('main', 'func', 0)
    return m.build()


def mod_traps_which(which):
    m = Module()
    t = m.typedef([], ['i32'])
    m.memory(1, 1)
    if which == 'div0':
        body = i32_const(1) + i32_const(0) + intop('i32.div_s') + end()
    elif which == 'overflow':
        body = i32_const(-2**31) + i32_const(-1) + intop('i32.div_s') + end()
    elif which == 'oob':
        body = i32_const(70000) + memop('i32.load') + end()
    elif which == 'unreachable':
        body = unreachable() + end()
    elif which == 'rem0':
        body = i64_const(5) + i64_const(0) + intop('i64.rem_u') + drop() + i32_const(0) + end()
    else:
        raise ValueError(which)
    m.def_func(t, [], body)
    m.export('main', 'func', 0)
    return m.build()


def mod_indirect():
    m = Module()
    t2 = m.typedef(['i32', 'i32'], ['i32'])
    tcall = m.typedef(['i32', 'i32', 'i32'], ['i32'])
    add = m.def_func(t2, [], local_get(0) + local_get(1)
                     + intop('i32.add') + end())
    sub = m.def_func(t2, [], local_get(0) + local_get(1)
                     + intop('i32.sub') + end())
    assert (add, sub) == (0, 1)
    m.table(2)
    m.elem(i32_const(0) + end(), [0, 1])
    body = (local_get(1) + local_get(2) + local_get(0)
            + call_indirect(t2) + end())
    m.def_func(tcall, [], body)
    m.export('main', 'func', 2)
    return m.build()


def mod_hostlog():
    m = Module()
    tlog = m.typedef(['i32'], [])
    t = m.typedef([], ['i32'])
    m.import_func('env', 'log', tlog)
    body = (i32_const(42) + call(0) + i32_const(43) + call(0)
            + i32_const(7) + end())
    m.def_func(t, [], body)
    m.export('main', 'func', 1)
    return m.build()


def mod_globals():
    m = Module()
    t = m.typedef([], ['i32'])
    tg = m.typedef(['i32'], [])
    m.global_('i32', 1, i32_const(7) + end())
    get = m.def_func(t, [], global_get(0) + i32_const(1)
                     + intop('i32.add') + end())
    sett = m.def_func(tg, [], local_get(0) + global_set(0) + end())
    m.export('get', 'func', get)
    m.export('set', 'func', sett)
    return m.build()


def mod_start():
    m = Module()
    t = m.typedef([], ['i32'])
    ts = m.typedef([], [])
    m.global_('i32', 1, i32_const(0) + end())
    s = m.def_func(ts, [], i32_const(99) + global_set(0) + end())
    g = m.def_func(t, [], global_get(0) + end())
    m.start = s
    m.export('main', 'func', g)
    return m.build()


def mod_i64():
    m = Module()
    t = m.typedef(['i64'], ['i64'])
    body = (local_get(0) + i64_const(2**40) + intop('i64.add')
            + i64_const(3) + intop('i64.mul')
            + intop('i32.wrap_i64') + intop('i64.extend_i32_s')
            + end())
    m.def_func(t, [], body)
    m.export('main', 'func', 0)
    return m.build()


def mod_cmp():
    m = Module()
    t = m.typedef([], ['i32'])
    # lt_s(-1,1)=1, lt_u(-1,1)=0, eq(5,5)=1, ne=0, ge_s... sum = 1+0+1+1
    body = (i32_const(-1) + i32_const(1) + intop('i32.lt_s')
            + i32_const(-1) + i32_const(1) + intop('i32.lt_u')
            + intop('i32.add')
            + i32_const(5) + i32_const(5) + intop('i32.eq')
            + intop('i32.add')
            + i32_const(7) + i32_const(7) + intop('i32.ne')
            + intop('i32.add')
            + end())
    m.def_func(t, [], body)
    m.export('main', 'func', 0)
    return m.build()


def mod_bitops():
    m = Module()
    t = m.typedef([], ['i32'])
    body = (i32_const(1) + i32_const(33) + intop('i32.shl')      # k masked: 2
            + i32_const(0xF0) + i32_const(4) + intop('i32.rotr')  # 0x0F
            + intop('i32.add')                                    # 17
            + i32_const(0x80000000) + intop('i32.clz')            # 0
            + intop('i32.add')
            + i32_const(12) + intop('i32.popcnt')                 # 2
            + intop('i32.add')
            + i32_const(16) + intop('i32.ctz')                    # 4
            + intop('i32.add')
            + end())
    m.def_func(t, [], body)
    m.export('main', 'func', 0)
    return m.build()


def run_units():
    # arithmetic
    b = mod_arith()
    check('arith mine', wasm.load(b).invoke('main') == [116])
    dc('arith', b, 'main', [], 'i32')

    # locals
    b = mod_locals()
    check('locals mine', wasm.load(b).invoke('main', [5]) == [36])
    dc('locals', b, 'main', [5], 'i32')

    # factorial loop
    b = mod_fact()
    check('fact mine', wasm.load(b).invoke('main', [5]) == [120])
    check('fact0 mine', wasm.load(b).invoke('main', [0]) == [1])
    dc('fact', b, 'main', [6], 'i32')

    # fib recursion
    b = mod_fib()
    check('fib mine', wasm.load(b).invoke('main', [10]) == [55])
    dc('fib', b, 'main', [12], 'i32')

    # max via if/else
    b = mod_max()
    inst = wasm.load(b)
    check('max mine', inst.invoke('main', [3, 9]) == [9]
          and inst.invoke('main', [9, 3]) == [9])
    dc('max', b, 'main', [3, 9], 'i32')

    # br_table
    b = mod_brtable()
    inst = wasm.load(b)
    check('brtable mine',
          [inst.invoke('main', [i])[0] for i in range(6)]
          == [10, 20, 30, 40, 40, 40])
    dcn('brtable', b, [('main', [i], 'i32') for i in range(6)])

    # memory
    b = mod_memory()
    want = (0x12345678 + 0xAB + 72) % 2**32
    got = wasm.load(b).invoke('main')
    check('memory mine', got == [want], 'got %r want %r' % (got, want))
    dc('memory', b, 'main', [], 'i32')

    # memory.grow
    b = mod_memgrow()
    check('memgrow mine', wasm.load(b).invoke('main') == [1 + 1 + 2 - 1])
    dc('memgrow', b, 'main', [], 'i32')

    # traps
    for which in ('div0', 'overflow', 'oob', 'unreachable', 'rem0'):
        b = mod_traps_which(which)
        expect_trap('trap/%s mine' % which,
                    lambda b=b: wasm.load(b).invoke('main'))
        dc('trap/' + which, b, 'main', [], 'i32')

    # call_indirect (+ null + sig mismatch traps)
    b = mod_indirect()
    inst = wasm.load(b)
    check('indirect mine',
          inst.invoke('main', [0, 10, 3]) == [13]
          and inst.invoke('main', [1, 10, 3]) == [7])
    expect_trap('indirect null mine',
                lambda: inst.invoke('main', [5, 10, 3]))
    dcn('indirect', b, [('main', [0, 10, 3], 'i32'),
                        ('main', [1, 10, 3], 'i32'),
                        ('main', [5, 10, 3], 'i32')])

    # host import
    b = mod_hostlog()
    logged = []
    inst = wasm.load(b, {('env', 'log'): logged.append})
    check('hostlog mine',
          inst.invoke('main') == [7] and logged == [42, 43],
          'logged=%r' % logged)
    node = run_node(b, [{'name': 'main', 'args': []}])
    check('hostlog node logged', node.get('logged') == [42, 43],
          repr(node))

    # globals persist across invokes
    b = mod_globals()
    inst = wasm.load(b)
    check('globals mine',
          inst.invoke('get') == [8]
          and inst.invoke('set', [41]) == []
          and inst.invoke('get') == [42])

    # start function
    b = mod_start()
    check('start mine', wasm.load(b).invoke('main') == [99])

    # i64 + wrap/extend
    b = mod_i64()
    v = 5
    want = (((v + 2**40) * 3) & 0xFFFFFFFF)
    want = want - 2**32 if want >= 2**31 else want
    check('i64 mine', wasm.load(b).invoke('main', [v]) == [want],
          'want %d' % want)
    dc('i64', b, 'main', [('i64', v)], 'i64')

    # comparisons signed vs unsigned
    b = mod_cmp()
    check('cmp mine', wasm.load(b).invoke('main') == [2])
    dc('cmp', b, 'main', [], 'i32')

    # bit ops
    b = mod_bitops()
    check('bitops mine', wasm.load(b).invoke('main') == [17 + 0 + 2 + 4])
    dc('bitops', b, 'main', [], 'i32')


def run_validation_tests():
    # bad magic / version
    expect_verror('bad magic', lambda: wasm.decode_module(b'NOPE' + b'\x00' * 8))
    expect_verror('bad version',
                  lambda: wasm.decode_module(wasm.MAGIC + b'\x02\x00\x00\x00'))

    # unknown opcode
    m = Module()
    t = m.typedef([], [])
    m.def_func(t, [], b'\xff' + end())
    expect_verror('unknown opcode',
                  lambda: wasm.load(m.build()))

    # type mismatch: i32.add with a single operand
    m = Module()
    t = m.typedef([], ['i32'])
    m.def_func(t, [], i32_const(1) + intop('i32.add') + end())
    m.export('main', 'func', 0)
    expect_verror('type mismatch add',
                  lambda: wasm.load(m.build()))

    # stack underflow at end (block promises i32, delivers nothing)
    m = Module()
    t = m.typedef([], [])
    m.def_func(t, [], block(['i32']) + end() + end())
    expect_verror('block arity mismatch',
                  lambda: wasm.load(m.build()))

    # if without else returning a value
    m = Module()
    t = m.typedef([], [])
    m.def_func(t, [], i32_const(1) + if_(['i32']) + drop() + end() + end())
    expect_verror('if-no-else with results',
                  lambda: wasm.load(m.build()))

    # br to nonexistent depth
    m = Module()
    t = m.typedef([], [])
    m.def_func(t, [], br(5) + end())
    expect_verror('bad br depth', lambda: wasm.load(m.build()))

    # set immutable global
    m = Module()
    t = m.typedef([], [])
    m.global_('i32', 0, i32_const(1) + end())
    m.def_func(t, [], i32_const(2) + global_set(0) + end())
    expect_verror('set immutable global',
                  lambda: wasm.load(m.build()))

    # unreachable code after br is OK (polymorphism), still validates
    m = Module()
    t = m.typedef([], ['i32'])
    body = block(['i32']) + i32_const(9) + br(0) + i32_const(1) \
        + i32_const(2) + intop('i32.add') + end() + end()
    m.def_func(t, [], body)
    m.export('main', 'func', 0)
    b = m.build()
    check('unreachable-after-br validates',
          wasm.load(b).invoke('main') == [9])
    dc('unreachable-after-br', b, 'main', [], 'i32')

    # br_table arity mismatch
    m = Module()
    t = m.typedef([], [])
    body = (block(['i32']) + block() + i32_const(0)
            + br_table([0, 1], 0) + end() + end() + end())
    m.def_func(t, [], body)
    expect_verror('br_table arity mismatch',
                  lambda: wasm.load(m.build()))

    # misaligned memory op
    m = Module()
    t = m.typedef([], [])
    m.memory(1, 1)
    m.def_func(t, [], i32_const(0) + memop('i32.load', align=3) + drop()
               + end())
    expect_verror('misaligned load', lambda: wasm.load(m.build()))


# --------------------------------------------------------------------------
# fuzzer: random valid programs, differential vs node
# --------------------------------------------------------------------------

BINOPS = ['add', 'sub', 'mul', 'and', 'or', 'xor', 'div_u', 'rem_u',
          'div_s', 'rem_s', 'shl', 'shr_u', 'shr_s']
UNOPS = ['eqz', 'clz', 'ctz', 'popcnt']
CMPS = ['eq', 'ne', 'lt_s', 'lt_u', 'gt_s', 'gt_u', 'le_u', 'ge_s']
CONSTS = [0, 1, 2, 3, 5, 7, 10, 100, 1000, -1, -2, -100,
          2**31 - 1, -2**31, 2**16, 2**30]


def gen_expr(rng, depth, nloc):
    """Random expression evaluating to one i32. Always type-valid."""
    if depth <= 0:
        c = rng.choice(['const', 'local'])
    else:
        c = rng.choice(['const', 'local', 'binop', 'unop', 'cmp',
                        'select', 'if', 'call', 'countdown', 'memround',
                        'binop', 'const', 'cmp'])
    if c == 'const':
        return i32_const(rng.choice(CONSTS))
    if c == 'local' and nloc > 0:
        return local_get(rng.randrange(nloc))
    if c == 'local':
        return i32_const(rng.choice(CONSTS))
    if c == 'unop':
        return gen_expr(rng, depth - 1, nloc) + intop('i32.' + rng.choice(UNOPS))
    if c == 'cmp':
        a = gen_expr(rng, depth - 1, nloc)
        b = gen_expr(rng, depth - 1, nloc)
        return a + b + intop('i32.' + rng.choice(CMPS))
    if c == 'select':
        cc = gen_expr(rng, depth - 1, nloc)
        v1 = gen_expr(rng, depth - 1, nloc)
        v2 = gen_expr(rng, depth - 1, nloc)
        return v1 + v2 + cc + select()  # stack: v1, v2, cond(top)
    if c == 'if':
        cc = gen_expr(rng, depth - 1, nloc)
        t = gen_expr(rng, depth - 1, nloc)
        e = gen_expr(rng, depth - 1, nloc)
        return cc + if_(['i32']) + t + else_() + e + end()
    if c == 'call':
        a = gen_expr(rng, depth - 1, nloc)
        b = gen_expr(rng, depth - 1, nloc)
        return a + b + call(1)  # helper is funcidx 1
    if c == 'countdown':
        # [bound] -> sum(1..bound): uses scratch locals nloc-2, nloc-1.
        # bound is masked to 0..63: negative would loop forever in BOTH
        # engines, and large bounds would take forever.
        k, acc = nloc - 2, nloc - 1
        bound = gen_expr(rng, depth - 1, nloc)
        return (bound + i32_const(63) + intop('i32.and') + local_tee(k)
                + i32_const(0) + local_set(acc)
                + block() + loop()
                + local_get(k) + intop('i32.eqz') + br_if(1)
                + local_get(acc) + local_get(k) + intop('i32.add')
                + local_set(acc)
                + local_get(k) + i32_const(1) + intop('i32.sub')
                + local_set(k)
                + br(0) + end() + end()
                + drop() + local_get(acc))
    if c == 'memround':
        addr = rng.choice([0, 4, 100, 1024, 4096])
        v = gen_expr(rng, depth - 1, nloc)
        return (i32_const(addr) + v + memop('i32.store')
                + i32_const(addr) + memop('i32.load'))
    # binop
    op = rng.choice(BINOPS)
    a = gen_expr(rng, depth - 1, nloc)
    b = gen_expr(rng, depth - 1, nloc)
    if op in ('div_u', 'rem_u', 'div_s', 'rem_s') and rng.random() < 0.8:
        b = b + i32_const(1) + intop('i32.or')  # mostly nonzero divisor
    return a + b + intop('i32.' + op)


def fuzz_module(rng):
    m = Module()
    t0 = m.typedef(['i32'], ['i32'])
    t1 = m.typedef(['i32', 'i32'], ['i32'])
    # main FIRST so it is funcidx 0; helper is funcidx 1 (gen_expr emits
    # call(1) for the helper)
    nloc = 1 + 3  # param + 3 scratch
    m.def_func(t0, ['i32', 'i32', 'i32'], gen_expr(rng, 4, nloc))
    # helper: h(a,b) = a*b + a - b
    m.def_func(t1, [],
               local_get(0) + local_get(1) + intop('i32.mul')
               + local_get(0) + intop('i32.add')
               + local_get(1) + intop('i32.sub') + end())
    m.memory(1, 1)
    m.export('main', 'func', 0)
    return m.build()


def run_fuzz(n=200, seed=1234):
    rng = random.Random(seed)
    agree = 0
    for i in range(n):
        wb = fuzz_module(rng)
        arg = rng.choice([0, 1, 5, 42, -1, -100, 2**31 - 1, -2**31])
        calls, rt = ncalls('main', [arg], 'i32')
        before = len(FAILURES)
        diff_check('fuzz/%d' % i, wb, calls, argtypes=rt)
        if len(FAILURES) == before:
            agree += 1
        else:
            # dump the failing module for forensics
            with open('/tmp/fuzzfail_%d.wasm' % i, 'wb') as f:
                f.write(wb)
            print('  failing module saved to /tmp/fuzzfail_%d.wasm (arg %d)'
                  % (i, arg))
            if len(FAILURES) - before > 0 and i > 5:
                pass
    check('fuzz agreement %d/%d' % (agree, n), agree == n)


if __name__ == '__main__':
    run_units()
    run_validation_tests()
    run_fuzz()
    print('\n%d passed, %d failed' % (PASS, FAIL))
    if FAILURES:
        print('failures: %s' % FAILURES[:20])
    sys.exit(1 if FAIL else 0)
