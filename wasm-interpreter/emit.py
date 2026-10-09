#!/usr/bin/env python3
"""emit.py -- tiny assembler for building wasm test modules by hand."""
import wasm

VT = {'i32': b'\x7f', 'i64': b'\x7e'}


def uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7f
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def sleb(n):
    out = bytearray()
    while True:
        b = n & 0x7f
        n >>= 7
        sign = b & 0x40
        if (n == 0 and not sign) or (n == -1 and sign):
            out.append(b)
            return bytes(out)
        out.append(b | 0x80)


def vec(items):
    return uleb(len(items)) + b''.join(items)


def name(s):
    b = s.encode('utf-8')
    return uleb(len(b)) + b


def _op(code, *imms):
    return bytes([code]) + b''.join(imms)


# build opcode helpers from wasm.OP_INFO so the two can never drift
_OPCODES = {v[0]: k for k, v in wasm.OP_INFO.items()}


def _simple(nm):
    code = _OPCODES[nm]
    return lambda: _op(code)


unreachable = _simple('unreachable')
nop = _simple('nop')
else_ = _simple('else')
end = _simple('end')
ret = _simple('return')
drop = _simple('drop')
select = _simple('select')
memory_size = lambda: b'\x3f\x00'
memory_grow = lambda: b'\x40\x00'


def _with_u(nm):
    code = _OPCODES[nm]
    return lambda i: _op(code, uleb(i))


br = _with_u('br')
br_if = _with_u('br_if')
call = _with_u('call')
local_get = _with_u('local.get')
local_set = _with_u('local.set')
local_tee = _with_u('local.tee')
global_get = _with_u('global.get')
global_set = _with_u('global.set')


def call_indirect(t):
    return _op(_OPCODES['call_indirect'], uleb(t), uleb(0))


def br_table(labels, dflt):
    return _op(_OPCODES['br_table'],
               vec([uleb(l) for l in labels]), uleb(dflt))


def i32_const(n):
    # canonical signed-32 encoding: mask into range first, or V8 rejects
    # "extra bits in varint"
    n &= 0xFFFFFFFF
    if n >= 0x80000000:
        n -= 0x100000000
    return _op(_OPCODES['i32.const'], sleb(n))


def i64_const(n):
    n &= 0xFFFFFFFFFFFFFFFF
    if n >= 0x8000000000000000:
        n -= 0x10000000000000000
    return _op(_OPCODES['i64.const'], sleb(n))


def _memop(nm, offset=0, align=None):
    code = _OPCODES[nm]
    width = wasm.MEMOP[nm][0]
    if align is None:
        align = {1: 0, 2: 1, 4: 2, 8: 3}[width]
    return _op(code, uleb(align), uleb(offset))


def memop(nm, offset=0, align=None):
    return _memop(nm, offset, align)


def block(results=()):
    return _blocklike('block', results)


def loop(results=()):
    return _blocklike('loop', results)


def if_(results=()):
    return _blocklike('if', results)


def _blocklike(nm, results):
    code = _OPCODES[nm]
    if not results:
        bt = b'\x40'
    elif len(results) == 1:
        bt = VT[results[0]]
    else:
        raise ValueError('multi-value blocks not supported')
    return _op(code, bt)


def intop(nm):
    return _simple(nm)()


class Module:
    """Assemble a module; funcidx counts imports first (like the spec)."""

    def __init__(self):
        self.types = []
        self.imports = []      # (mod, name, typeidx)
        self.func_types = []
        self.tables = []       # (min, max)
        self.mems = []         # (min, max)
        self.globs = []        # (valtype, mut, init_expr_bytes)
        self.exports = []      # (name, kind, idx)
        self.start = None
        self.elems = []        # (offset_expr, [funcidx])
        self.codes = []        # (locals_bytes, body_bytes)
        self.datas = []        # (offset_expr, bytes)

    # -- types --
    def typedef(self, params, results):
        self.types.append((params, results))
        return len(self.types) - 1

    # -- functions --
    def import_func(self, mod, name, typeidx):
        self.imports.append((mod, name, typeidx))
        return len(self.imports) - 1

    def def_func(self, typeidx, locals_, body):
        """locals_: list of valtype names. Returns overall funcidx."""
        self.func_types.append(typeidx)
        loc = b''
        if locals_:
            # group consecutive same types
            groups = []
            for t in locals_:
                if groups and groups[-1][1] == t:
                    groups[-1][0] += 1
                else:
                    groups.append([1, t])
            loc = uleb(len(groups)) + b''.join(
                uleb(c) + VT[t] for c, t in groups)
        else:
            loc = uleb(0)
        self.codes.append((loc, body))
        return len(self.imports) + len(self.func_types) - 1

    # -- others --
    def table(self, min_, max_=None):
        self.tables.append((min_, max_))

    def memory(self, min_, max_=None):
        self.mems.append((min_, max_))

    def global_(self, vt, mut, init):
        self.globs.append((vt, mut, init))

    def export(self, nm, kind, idx):
        self.exports.append((nm, kind, idx))

    def elem(self, offset_expr, funcidxs):
        self.elems.append((offset_expr, funcidxs))

    def data(self, offset_expr, bs):
        self.datas.append((offset_expr, bs))

    # -- build --
    def build(self):
        secs = []

        def limits(lo, hi):
            if hi is None:
                return uleb(0) + uleb(lo)
            return uleb(1) + uleb(lo) + uleb(hi)

        if self.types:
            items = []
            for params, results in self.types:
                items.append(b'\x60' + vec([VT[p] for p in params])
                             + vec([VT[r] for r in results]))
            secs.append((1, vec(items)))
        if self.imports:
            items = [name(m) + name(f) + b'\x00' + uleb(t)
                     for m, f, t in self.imports]
            secs.append((2, vec(items)))
        if self.func_types:
            secs.append((3, vec([uleb(t) for t in self.func_types])))
        if self.tables:
            secs.append((4, vec([b'\x70' + limits(lo, hi)
                                 for lo, hi in self.tables])))
        if self.mems:
            secs.append((5, vec([limits(lo, hi) for lo, hi in self.mems])))
        if self.globs:
            items = [VT[vt] + bytes([mut]) + init
                     for vt, mut, init in self.globs]
            secs.append((6, vec(items)))
        if self.exports:
            kinds = {'func': 0, 'table': 1, 'mem': 2, 'global': 3}
            items = [name(n) + bytes([kinds[k]]) + uleb(i)
                     for n, k, i in self.exports]
            secs.append((7, vec(items)))
        if self.start is not None:
            secs.append((8, uleb(self.start)))
        if self.elems:
            # MVP kind 0: flag, offset expr, funcidx vec (table 0 implied)
            items = [uleb(0) + off + vec([uleb(f) for f in fs])
                     for off, fs in self.elems]
            secs.append((9, vec(items)))
        if self.codes:
            items = []
            for loc, body in self.codes:
                content = loc + body
                items.append(uleb(len(content)) + content)
            secs.append((10, vec(items)))
        if self.datas:
            # MVP kind 0: flag, offset expr, bytes (memory 0 implied)
            items = [uleb(0) + off + vec([bytes([b]) for b in bs])
                     for off, bs in self.datas]
            secs.append((11, vec(items)))

        out = bytearray(wasm.MAGIC + wasm.VERSION)
        for sid, body in secs:
            out += uleb(sid) + uleb(len(body)) + body
        return bytes(out)
