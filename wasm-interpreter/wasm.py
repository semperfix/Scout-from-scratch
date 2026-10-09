#!/usr/bin/env python3
"""wasm.py -- WebAssembly MVP (integer subset) from scratch.

Zero dependencies. Three stages, like a real engine:
  1. decode   -- binary format -> Module dict (all 12 section ids)
  2. validate -- spec-style type checking with unreachable-polymorphism
  3. execute  -- stack-machine interpreter with branch-target patching

Deliberate scope: i32/i64 integer ops, linear memory, tables, globals,
function imports/exports, call_indirect, start functions, data/elem segments.
NOT implemented: f32/f64, SIMD, bulk-memory ops, multi-value blocks,
threads, GC, tail calls. Those raise clean WasmErrors, never silent garbage.

Traps (div-by-zero, OOB memory, unreachable, bad indirect call, ...) raise
WasmTrap, mirroring the spec's "execution gets stuck" semantics.
"""

MAGIC = b'\x00asm'
VERSION = b'\x01\x00\x00\x00'
PAGE = 65536
MAX_PAGES = 65536

I32 = 'i32'
I64 = 'i64'
VALTYPE = {0x7f: I32, 0x7e: I64}

M32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF


class WasmError(Exception):
    """Decode/validation/link error -- the module is rejected."""


class WasmTrap(WasmError):
    """Runtime trap -- execution aborted per spec semantics."""


# --------------------------------------------------------------------------
# LEB128
# --------------------------------------------------------------------------

def read_uleb(data, pos):
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise WasmError('unexpected end of section in leb128')
        b = data[pos]
        pos += 1
        result |= (b & 0x7f) << shift
        if not b & 0x80:
            return result, pos
        shift += 7
        if shift > 100:
            raise WasmError('leb128 too long')


def read_sleb(data, pos):
    result = 0
    shift = 0
    b = 0
    while True:
        if pos >= len(data):
            raise WasmError('unexpected end of section in leb128')
        b = data[pos]
        pos += 1
        result |= (b & 0x7f) << shift
        shift += 7
        if not b & 0x80:
            break
        if shift > 100:
            raise WasmError('leb128 too long')
    if b & 0x40:
        result -= 1 << shift
    return result, pos


def read_name(data, pos):
    n, pos = read_uleb(data, pos)
    if pos + n > len(data):
        raise WasmError('name overruns section')
    try:
        s = data[pos:pos + n].decode('utf-8')
    except UnicodeDecodeError:
        raise WasmError('name is not valid utf-8')
    return s, pos + n


# --------------------------------------------------------------------------
# integer helpers (spec: arithmetic is mod 2^N, comparisons read signedness)
# --------------------------------------------------------------------------

def u32(v):
    return v & M32


def s32(v):
    v &= M32
    return v - 0x100000000 if v >= 0x80000000 else v


def u64(v):
    return v & M64


def s64(v):
    v &= M64
    return v - 0x10000000000000000 if v >= 0x8000000000000000 else v


def trunc_div(a, b):
    """Truncated division (toward zero) without float precision loss."""
    q = abs(a) // abs(b)
    return -q if (a < 0) != (b < 0) else q


def clz(v, bits):
    v &= (1 << bits) - 1
    return bits if v == 0 else bits - v.bit_length()


def ctz(v, bits):
    v &= (1 << bits) - 1
    if v == 0:
        return bits
    return ((v & -v).bit_length() - 1)


def popcnt(v, bits):
    return bin(v & ((1 << bits) - 1)).count('1')


def rotl(v, k, bits):
    k &= bits - 1
    v &= (1 << bits) - 1
    return ((v << k) | (v >> (bits - k))) & ((1 << bits) - 1)


def rotr(v, k, bits):
    k &= bits - 1
    v &= (1 << bits) - 1
    return ((v >> k) | (v << (bits - k))) & ((1 << bits) - 1)


# --------------------------------------------------------------------------
# opcode table: opcode -> (name, immediate-kind)
# immediate kinds: '' none | 'u' u32 | 'uu' u32,u32 | 's' s32 | 'S' s64
#                  'bt' blocktype | 'btbl' br_table | 'm' memarg
#                  'z' reserved zero byte (memory.size/grow memidx)
# --------------------------------------------------------------------------

OP_INFO = {
    0x00: ('unreachable', ''), 0x01: ('nop', ''),
    0x02: ('block', 'bt'), 0x03: ('loop', 'bt'), 0x04: ('if', 'bt'),
    0x05: ('else', ''), 0x0b: ('end', ''),
    0x0c: ('br', 'u'), 0x0d: ('br_if', 'u'), 0x0e: ('br_table', 'btbl'),
    0x0f: ('return', ''),
    0x10: ('call', 'u'), 0x11: ('call_indirect', 'uu'),
    0x1a: ('drop', ''), 0x1b: ('select', ''),
    0x20: ('local.get', 'u'), 0x21: ('local.set', 'u'), 0x22: ('local.tee', 'u'),
    0x23: ('global.get', 'u'), 0x24: ('global.set', 'u'),
    0x28: ('i32.load', 'm'), 0x29: ('i64.load', 'm'),
    0x2c: ('i32.load8_s', 'm'), 0x2d: ('i32.load8_u', 'm'),
    0x2e: ('i32.load16_s', 'm'), 0x2f: ('i32.load16_u', 'm'),
    0x30: ('i64.load8_s', 'm'), 0x31: ('i64.load8_u', 'm'),
    0x32: ('i64.load16_s', 'm'), 0x33: ('i64.load16_u', 'm'),
    0x34: ('i64.load32_s', 'm'), 0x35: ('i64.load32_u', 'm'),
    0x36: ('i32.store', 'm'), 0x37: ('i64.store', 'm'),
    0x3a: ('i32.store8', 'm'), 0x3b: ('i32.store16', 'm'),
    0x3c: ('i64.store8', 'm'), 0x3d: ('i64.store16', 'm'), 0x3e: ('i64.store32', 'm'),
    0x3f: ('memory.size', 'z'), 0x40: ('memory.grow', 'z'),
    0x41: ('i32.const', 's'), 0x42: ('i64.const', 'S'),
    0x45: ('i32.eqz', ''), 0x46: ('i32.eq', ''), 0x47: ('i32.ne', ''),
    0x48: ('i32.lt_s', ''), 0x49: ('i32.lt_u', ''),
    0x4a: ('i32.gt_s', ''), 0x4b: ('i32.gt_u', ''),
    0x4c: ('i32.le_s', ''), 0x4d: ('i32.le_u', ''),
    0x4e: ('i32.ge_s', ''), 0x4f: ('i32.ge_u', ''),
    0x50: ('i64.eqz', ''), 0x51: ('i64.eq', ''), 0x52: ('i64.ne', ''),
    0x53: ('i64.lt_s', ''), 0x54: ('i64.lt_u', ''),
    0x55: ('i64.gt_s', ''), 0x56: ('i64.gt_u', ''),
    0x57: ('i64.le_s', ''), 0x58: ('i64.le_u', ''),
    0x59: ('i64.ge_s', ''), 0x5a: ('i64.ge_u', ''),
    0x5b: ('f32.eq', ''), 0x5c: ('f32.ne', ''), 0x5d: ('f32.lt', ''),
    0x5e: ('f32.le', ''), 0x5f: ('f32.gt', ''), 0x60: ('f32.ge', ''),
    0x61: ('f64.eq', ''), 0x62: ('f64.ne', ''), 0x63: ('f64.lt', ''),
    0x64: ('f64.le', ''), 0x65: ('f64.gt', ''), 0x66: ('f64.ge', ''),
    0x67: ('i32.clz', ''), 0x68: ('i32.ctz', ''), 0x69: ('i32.popcnt', ''),
    0x6a: ('i32.add', ''), 0x6b: ('i32.sub', ''), 0x6c: ('i32.mul', ''),
    0x6d: ('i32.div_s', ''), 0x6e: ('i32.div_u', ''),
    0x6f: ('i32.rem_s', ''), 0x70: ('i32.rem_u', ''),
    0x71: ('i32.and', ''), 0x72: ('i32.or', ''), 0x73: ('i32.xor', ''),
    0x74: ('i32.shl', ''), 0x75: ('i32.shr_s', ''), 0x76: ('i32.shr_u', ''),
    0x77: ('i32.rotl', ''), 0x78: ('i32.rotr', ''),
    0x79: ('i64.clz', ''), 0x7a: ('i64.ctz', ''), 0x7b: ('i64.popcnt', ''),
    0x7c: ('i64.add', ''), 0x7d: ('i64.sub', ''), 0x7e: ('i64.mul', ''),
    0x7f: ('i64.div_s', ''), 0x80: ('i64.div_u', ''),
    0x81: ('i64.rem_s', ''), 0x82: ('i64.rem_u', ''),
    0x83: ('i64.and', ''), 0x84: ('i64.or', ''), 0x85: ('i64.xor', ''),
    0x86: ('i64.shl', ''), 0x87: ('i64.shr_s', ''), 0x88: ('i64.shr_u', ''),
    0x89: ('i64.rotl', ''), 0x8a: ('i64.rotr', ''),
    0xa7: ('i32.wrap_i64', ''),
    0xac: ('i64.extend_i32_s', ''), 0xad: ('i64.extend_i32_u', ''),
    0xc0: ('i32.extend8_s', ''), 0xc1: ('i32.extend16_s', ''),
    0xc2: ('i64.extend8_s', ''), 0xc3: ('i64.extend16_s', ''),
    0xc4: ('i64.extend32_s', ''),
}

# memory op metadata: name -> (width_bytes, signed, result_type | None for store)
MEMOP = {
    'i32.load': (4, True, I32), 'i64.load': (8, True, I64),
    'i32.load8_s': (1, True, I32), 'i32.load8_u': (1, False, I32),
    'i32.load16_s': (2, True, I32), 'i32.load16_u': (2, False, I32),
    'i64.load8_s': (1, True, I64), 'i64.load8_u': (1, False, I64),
    'i64.load16_s': (2, True, I64), 'i64.load16_u': (2, False, I64),
    'i64.load32_s': (4, True, I64), 'i64.load32_u': (4, False, I64),
    'i32.store': (4, I32), 'i64.store': (8, I64),
    'i32.store8': (1, I32), 'i32.store16': (2, I32),
    'i64.store8': (1, I64), 'i64.store16': (2, I64), 'i64.store32': (4, I64),
}

# --------------------------------------------------------------------------
# stage 1: decode
# --------------------------------------------------------------------------

def decode_blocktype(data, pos, types):
    """-> ((params, results), pos). MVP: params must be empty."""
    b = data[pos]
    if b == 0x40:
        return ([], []), pos + 1
    if b in VALTYPE:
        return ([], [VALTYPE[b]]), pos + 1
    idx, pos = read_sleb(data, pos)
    if idx < 0 or idx >= len(types):
        raise WasmError('bad block type index %d' % idx)
    params, results = types[idx]
    if params:
        raise WasmError('multi-value block params not supported in MVP')
    return ((params, results), pos)


def decode_instr(data, pos, types):
    """Decode one instruction. -> ((name, imms...), pos)."""
    if pos >= len(data):
        raise WasmError('unexpected end of expression')
    opcode = data[pos]
    pos += 1
    info = OP_INFO.get(opcode)
    if info is None:
        raise WasmError('unknown opcode 0x%02x' % opcode)
    name, kind = info
    if kind == '':
        return (name,), pos
    if kind == 'u':
        v, pos = read_uleb(data, pos)
        return (name, v), pos
    if kind == 'uu':
        a, pos = read_uleb(data, pos)
        b, pos = read_uleb(data, pos)
        return (name, a, b), pos
    if kind == 's':
        v, pos = read_sleb(data, pos)
        return (name, v), pos
    if kind == 'S':
        v, pos = read_sleb(data, pos)
        return (name, v), pos
    if kind == 'bt':
        bt, pos = decode_blocktype(data, pos, types)
        return (name, bt), pos
    if kind == 'btbl':
        n, pos = read_uleb(data, pos)
        labels = []
        for _ in range(n):
            l, pos = read_uleb(data, pos)
            labels.append(l)
        dflt, pos = read_uleb(data, pos)
        return (name, labels, dflt), pos
    if kind == 'm':
        align, pos = read_uleb(data, pos)
        offset, pos = read_uleb(data, pos)
        return (name, align, offset), pos
    if kind == 'z':
        v, pos = read_uleb(data, pos)
        if v != 0:
            raise WasmError('nonzero reserved memory index')
        return (name,), pos
    raise WasmError('bad immediate kind')  # unreachable


def decode_expr(data, pos, types):
    """Decode an expression up to the `end` that closes depth 0."""
    instrs = []
    depth = 0
    while True:
        if pos >= len(data):
            raise WasmError('unterminated expression')
        (name, *imms), pos = decode_instr(data, pos, types)
        if name in ('block', 'loop', 'if'):
            depth += 1
        elif name == 'end':
            if depth == 0:
                instrs.append(('end',))
                return instrs, pos
            depth -= 1
        elif name == 'else':
            if depth == 0:
                raise WasmError('else outside if')
        instrs.append((name, *imms))


def decode_limits(data, pos):
    flags, pos = read_uleb(data, pos)
    if flags & ~0x1:
        raise WasmError('unsupported limits flags %d' % flags)
    lo, pos = read_uleb(data, pos)
    hi = None
    if flags & 0x1:
        hi, pos = read_uleb(data, pos)
    return (lo, hi), pos


def decode_vec(data, pos, fn):
    n, pos = read_uleb(data, pos)
    items = []
    for _ in range(n):
        item, pos = fn(data, pos)
        items.append(item)
    return items, pos


def decode_type(data, pos):
    if data[pos] != 0x60:
        raise WasmError('bad functype tag 0x%02x' % data[pos])
    pos += 1
    params = []
    n, pos = read_uleb(data, pos)
    for _ in range(n):
        t = VALTYPE.get(data[pos])
        if t is None:
            raise WasmError('unsupported valtype 0x%02x' % data[pos])
        params.append(t)
        pos += 1
    results = []
    n, pos = read_uleb(data, pos)
    for _ in range(n):
        t = VALTYPE.get(data[pos])
        if t is None:
            raise WasmError('unsupported valtype 0x%02x' % data[pos])
        results.append(t)
        pos += 1
    return (params, results), pos


def decode_module(data):
    """Parse the binary format into a Module dict. Raises WasmError."""
    if data[0:4] != MAGIC:
        raise WasmError('bad magic: %r' % data[0:4])
    if data[4:8] != VERSION:
        raise WasmError('unsupported version: %r' % data[4:8])
    mod = {'types': [], 'imports': [], 'func_types': [], 'tables': [],
           'memories': [], 'globals': [], 'exports': [], 'start': None,
           'elems': [], 'codes': [], 'datas': []}
    pos = 8
    while pos < len(data):
        sec_id, pos = read_uleb(data, pos)
        sec_size, pos = read_uleb(data, pos)
        end = pos + sec_size
        if end > len(data):
            raise WasmError('section %d overruns file' % sec_id)
        body = data[pos:end]
        bpos = 0
        if sec_id == 0:
            pass  # custom section: ignored
        elif sec_id == 1:
            mod['types'], bpos = decode_vec(
                body, 0, lambda d, p: decode_type(d, p))
        elif sec_id == 2:
            def dec_import(d, p):
                m, p = read_name(d, p)
                f, p = read_name(d, p)
                kind = d[p]
                p += 1
                if kind == 0:
                    t, p = read_uleb(d, p)
                    return ({'module': m, 'name': f, 'kind': 'func',
                             'type': t}, p)
                raise WasmError('only function imports supported in MVP')
            mod['imports'], bpos = decode_vec(body, 0, dec_import)
        elif sec_id == 3:
            mod['func_types'], bpos = decode_vec(
                body, 0, lambda d, p: read_uleb(d, p))
        elif sec_id == 4:
            def dec_table(d, p):
                et = d[p]
                p += 1
                if et != 0x70:
                    raise WasmError('only funcref tables supported')
                lim, p = decode_limits(d, p)
                return ({'limits': lim}, p)
            mod['tables'], bpos = decode_vec(body, 0, dec_table)
        elif sec_id == 5:
            def dec_mem(d, p):
                lim, p = decode_limits(d, p)
                return ({'limits': lim}, p)
            mod['memories'], bpos = decode_vec(body, 0, dec_mem)
        elif sec_id == 6:
            def dec_global(d, p):
                t = VALTYPE.get(d[p])
                if t is None:
                    raise WasmError('unsupported global valtype')
                p += 1
                mut = d[p]
                p += 1
                if mut not in (0, 1):
                    raise WasmError('bad global mutability')
                init, p = decode_expr(d, p, mod['types'])
                return ({'type': t, 'mut': mut, 'init': init}, p)
            mod['globals'], bpos = decode_vec(body, 0, dec_global)
        elif sec_id == 7:
            def dec_export(d, p):
                name, p = read_name(d, p)
                kind = d[p]
                p += 1
                idx, p = read_uleb(d, p)
                kinds = {0: 'func', 1: 'table', 2: 'mem', 3: 'global'}
                if kind not in kinds:
                    raise WasmError('bad export kind')
                return ({'name': name, 'kind': kinds[kind], 'index': idx}, p)
            mod['exports'], bpos = decode_vec(body, 0, dec_export)
        elif sec_id == 8:
            mod['start'], bpos = read_uleb(body, 0)
        elif sec_id == 9:
            def dec_elem(d, p):
                flag, p = read_uleb(d, p)
                if flag != 0:
                    raise WasmError('only active elem segment kind 0 supported')
                # MVP kind 0: table 0 is implied, no tableidx field
                off, p = decode_expr(d, p, mod['types'])
                idxs, p = decode_vec(d, p, lambda dd, pp: read_uleb(dd, pp))
                return ({'offset': off, 'funcs': idxs}, p)
            mod['elems'], bpos = decode_vec(body, 0, dec_elem)
        elif sec_id == 10:
            def dec_code(d, p):
                size, p = read_uleb(d, p)
                cend = p + size
                locals_ = []
                n, p = read_uleb(d, p)
                for _ in range(n):
                    cnt, p = read_uleb(d, p)
                    t = VALTYPE.get(d[p])
                    if t is None:
                        raise WasmError('unsupported local valtype')
                    p += 1
                    locals_.extend([t] * cnt)
                expr, p = decode_expr(d, p, mod['types'])
                if p != cend:
                    raise WasmError('code body size mismatch')
                return ({'locals': locals_, 'raw': expr}, p)
            mod['codes'], bpos = decode_vec(body, 0, dec_code)
        elif sec_id == 11:
            def dec_data(d, p):
                flag, p = read_uleb(d, p)
                if flag != 0:
                    raise WasmError('only active data segment kind 0 supported')
                # MVP kind 0: memory 0 is implied, no memidx field
                off, p = decode_expr(d, p, mod['types'])
                n, p = read_uleb(d, p)
                if p + n > len(d):
                    raise WasmError('data overruns section')
                return ({'offset': off, 'bytes': d[p:p + n]}, p + n)
            mod['datas'], bpos = decode_vec(body, 0, dec_data)
        else:
            raise WasmError('unknown section id %d' % sec_id)
        if bpos != len(body):
            raise WasmError('section %d has trailing bytes' % sec_id)
        pos = end
    return mod

# --------------------------------------------------------------------------
# stage 2: validate + resolve branch targets (single combined pass)
#
# Produces resolved instruction tuples where every br/br_if/br_table/if/else
# carries absolute target pcs. Validation follows the spec algorithm:
# value-type stack + control-frame stack with unreachable-polymorphism
# (after unreachable/br/return, popped values are "unknown", not errors).
# --------------------------------------------------------------------------

_UNSET = object()


def _int_sig(name):
    """(pops, pushes) for integer ops like 'i32.add'."""
    width, op = name.split('.')
    if op in ('clz', 'ctz', 'popcnt', 'eqz'):
        return ([width], [I32] if op == 'eqz' else [width])
    if op in ('eq', 'ne', 'lt_s', 'lt_u', 'gt_s', 'gt_u', 'le_s', 'le_u',
              'ge_s', 'ge_u'):
        return ([width, width], [I32])
    if op in ('add', 'sub', 'mul', 'div_s', 'div_u', 'rem_s', 'rem_u', 'and',
              'or', 'xor', 'shl', 'shr_s', 'shr_u', 'rotl', 'rotr'):
        return ([width, width], [width])
    if name == 'i32.wrap_i64':
        return ([I64], [I32])
    if name in ('i64.extend_i32_s', 'i64.extend_i32_u'):
        return ([I32], [I64])
    if name in ('i32.extend8_s', 'i32.extend16_s'):
        return ([I32], [I32])
    if name in ('i64.extend8_s', 'i64.extend16_s', 'i64.extend32_s'):
        return ([I64], [I64])
    return None


def compile_function(mod, type_idx, code):
    """Validate a function body and resolve branch targets.

    Returns dict(code=[resolved instrs], locals=[types], params, results).
    Raises WasmError on any validation failure.
    """
    params, results = mod['types'][type_idx]
    local_types = list(params) + list(code['locals'])
    n_funcs = len(mod['imports']) + len(mod['func_types'])
    n_globals = len(mod['globals'])  # MVP: no imported globals
    has_mem = len(mod['memories']) > 0

    out = []          # resolved instructions
    fixups = []       # (out_pos, frame, is_loop) for branch targets
    vs = []           # value-type stack (types or None == unknown)
    frames = []       # control frames (validation + resolution state)

    def push_frame(kind, label, end, is_if=False, start=None):
        frames.append({'kind': kind, 'label': label, 'end': end,
                       'height': len(vs), 'unreachable': False,
                       'is_if': is_if, 'else_seen': False,
                       'start': start, 'end_idx': None, 'else_idx': None})

    def push_val(t):
        vs.append(t)

    def pop_val(expect=_UNSET):
        fr = frames[-1]
        if len(vs) == fr['height']:
            if fr['unreachable']:
                return None  # unknown type: the polymorphism rule
            raise WasmError('type error: stack underflow')
        t = vs.pop()
        if expect is not _UNSET and expect is not None \
                and t is not None and t != expect:
            raise WasmError('type error: expected %s, got %s' % (expect, t))
        return t

    def pop_vals(ts):
        for t in reversed(ts):
            pop_val(t)

    def push_vals(ts):
        vs.extend(ts)

    def mark_unreachable():
        fr = frames[-1]
        fr['unreachable'] = True
        del vs[fr['height']:]

    def check_height(fr):
        # at a label end, the stack must hold exactly height + end values
        if not fr['unreachable'] and len(vs) != fr['height'] + len(fr['end']):
            raise WasmError('type error: stack height mismatch at end')

    def close_frame():
        # validate against the frame BEFORE popping it: pop_val reads
        # frames[-1] for the unreachable-polymorphism rule
        fr = frames[-1]
        check_height(fr)
        if fr['kind'] == 'if' and not fr['else_seen'] and fr['end']:
            raise WasmError('type error: if without else must return []')
        pop_vals(fr['end'])
        del vs[fr['height']:]
        push_vals(fr['end'])
        frames.pop()
        fr['end_idx'] = len(out)
        out.append(('end',))
        return fr

    def emit_branch(name, depth, cond):
        # cond: True for br_if (peeks), False for br
        if depth + 1 > len(frames):
            raise WasmError('type error: bad branch depth %d' % depth)
        target = frames[-1 - depth]
        is_loop = target['kind'] == 'loop'
        # br to the implicit function label is exactly `return`
        is_return = target['kind'] == 'func'
        if cond:
            pop_val(I32)
            pop_vals(target['label'])
            push_vals(target['label'])
        else:
            pop_vals(target['label'])
            mark_unreachable()
        out.append([name, None, depth + 1, len(target['label']),
                    is_loop, target['height'], is_return])
        fixups.append((len(out) - 1, target, is_loop))

    push_frame('func', results, results, start=0)

    for (name, *imms) in code['raw']:
        if name == 'unreachable':
            mark_unreachable()
            out.append(('unreachable',))
        elif name == 'nop':
            out.append(('nop',))
        elif name == 'drop':
            pop_val()
            out.append(('drop',))
        elif name == 'select':
            pop_val(I32)
            t2 = pop_val()
            t1 = pop_val()
            if t1 is not None and t2 is not None and t1 != t2:
                raise WasmError('type error: select operand mismatch')
            push_val(t1 if t1 is not None else t2)
            out.append(('select',))
        elif name in ('block', 'loop'):
            (bparams, bresults) = imms[0]
            pop_vals(bparams)
            idx = len(out)
            push_frame(name,
                       bparams if name == 'loop' else bresults, bresults,
                       start=idx + 1)
            arity = len(frames[-1]['label'])
            if name == 'loop':
                out.append(['loop', idx + 1, None, arity])
            else:
                out.append(['block', None, arity])
            frames[-1]['out_idx'] = idx
        elif name == 'if':
            (bparams, bresults) = imms[0]
            pop_val(I32)
            pop_vals(bparams)
            idx = len(out)
            push_frame('if', bresults, bresults, is_if=True, start=idx + 1)
            out.append(['if', None, None, len(bresults)])
            frames[-1]['out_idx'] = idx
        elif name == 'else':
            fr = frames[-1]
            if not fr['is_if'] or fr['else_seen']:
                raise WasmError('else without matching if')
            check_height(fr)
            pop_vals(fr['end'])
            del vs[fr['height']:]
            fr['else_seen'] = True
            fr['unreachable'] = False
            fr['else_idx'] = len(out)
            out.append(['else', None])
        elif name == 'end':
            fr = close_frame()
            idx = fr.get('out_idx')
            if idx is not None:
                if fr['kind'] == 'block':
                    out[idx][1] = fr['end_idx']
                elif fr['kind'] == 'loop':
                    out[idx][2] = fr['end_idx']
                elif fr['kind'] == 'if':
                    out[idx][1] = fr['else_idx']
                    out[idx][2] = fr['end_idx']
            if fr['is_if'] and fr['else_idx'] is not None:
                out[fr['else_idx']][1] = fr['end_idx']
        elif name == 'br':
            emit_branch('br', imms[0], cond=False)
        elif name == 'br_if':
            emit_branch('br_if', imms[0], cond=True)
        elif name == 'br_table':
            labels, dflt = imms
            pop_val(I32)
            depths = labels + [dflt]
            for d in depths:
                if d + 1 > len(frames):
                    raise WasmError('type error: bad br_table depth')
            sigs = [frames[-1 - d]['label'] for d in depths]
            if any(s != sigs[0] for s in sigs):
                raise WasmError('type error: br_table label arity mismatch')
            pop_vals(sigs[0])
            mark_unreachable()
            entries = []
            for d in depths:
                t = frames[-1 - d]
                is_loop = t['kind'] == 'loop'
                entries.append([None, d + 1, len(t['label']), is_loop,
                                t['height'], t['kind'] == 'func'])
                fixups.append(('table', len(out), len(entries) - 1, t,
                               is_loop))
            out.append(['br_table', entries])
        elif name == 'return':
            pop_vals(results)
            mark_unreachable()
            out.append(('return', len(results)))
        elif name == 'call':
            fidx = imms[0]
            if fidx >= n_funcs:
                raise WasmError('bad call function index %d' % fidx)
            if fidx < len(mod['imports']):
                p, r = mod['types'][mod['imports'][fidx]['type']]
            else:
                p, r = mod['types'][mod['func_types'][fidx - len(mod['imports'])]]
            pop_vals(p)
            push_vals(r)
            out.append(('call', fidx))
        elif name == 'call_indirect':
            type_idx2, table_idx = imms
            if table_idx != 0 or table_idx >= len(mod['tables']):
                raise WasmError('bad call_indirect table %d' % table_idx)
            if type_idx2 >= len(mod['types']):
                raise WasmError('bad call_indirect type %d' % type_idx2)
            pop_val(I32)
            p, r = mod['types'][type_idx2]
            pop_vals(p)
            push_vals(r)
            out.append(('call_indirect', type_idx2))
        elif name in ('local.get', 'local.tee'):
            i = imms[0]
            if i >= len(local_types):
                raise WasmError('bad local index %d' % i)
            if name == 'local.tee':
                t = pop_val(local_types[i])
                push_val(t)
            else:
                push_val(local_types[i])
            out.append((name, i))
        elif name == 'local.set':
            i = imms[0]
            if i >= len(local_types):
                raise WasmError('bad local index %d' % i)
            pop_val(local_types[i])
            out.append((name, i))
        elif name == 'global.get':
            i = imms[0]
            if i >= n_globals:
                raise WasmError('bad global index %d' % i)
            push_val(mod['globals'][i]['type'])
            out.append((name, i))
        elif name == 'global.set':
            i = imms[0]
            if i >= n_globals:
                raise WasmError('bad global index %d' % i)
            if mod['globals'][i]['mut'] != 1:
                raise WasmError('set of immutable global')
            pop_val(mod['globals'][i]['type'])
            out.append((name, i))
        elif name in MEMOP:
            if not has_mem:
                raise WasmError('memory op with no memory defined')
            align, offset = imms
            meta = MEMOP[name]
            if (1 << align) > meta[0]:
                raise WasmError('misaligned memory op: align 2^%d > %d bytes'
                                % (align, meta[0]))
            if name.endswith('load') or '.load' in name:
                width, signed, rt = meta
                pop_val(I32)
                push_val(rt)
                out.append(('load', width, signed, rt, offset))
            else:
                width, vt = meta
                pop_val(vt)
                pop_val(I32)
                out.append(('store', width, vt, offset))
        elif name in ('memory.size', 'memory.grow'):
            if not has_mem:
                raise WasmError('memory op with no memory defined')
            if name == 'memory.grow':
                pop_val(I32)
            push_val(I32)
            out.append((name,))
        elif name in ('i32.const', 'i64.const'):
            push_val(I32 if name == 'i32.const' else I64)
            out.append((name, imms[0]))
        else:
            sig = _int_sig(name)
            if sig is None:
                raise WasmError('unsupported op in MVP: %s' % name)
            pops, pushes = sig
            pop_vals(pops)
            push_vals(pushes)
            out.append((name,))

    if frames:
        raise WasmError('unbalanced control frames')
    # the final ('end',) already closed the implicit func frame above

    # patch branch targets: loop -> body start; block/if -> just past `end`
    resolved = [tuple(o) if isinstance(o, list) else o for o in out]
    for fx in fixups:
        if fx[0] == 'table':
            _, out_pos, entry_idx, target, is_loop = fx
            op = list(resolved[out_pos])
            entries = [list(e) for e in op[1]]
            entries[entry_idx][0] = target['start'] if is_loop \
                else target['end_idx'] + 1
            op[1] = [tuple(e) for e in entries]
            resolved[out_pos] = tuple(op)
        else:
            out_pos, target, is_loop = fx
            op = list(resolved[out_pos])
            op[1] = target['start'] if is_loop else target['end_idx'] + 1
            resolved[out_pos] = tuple(op)

    return {'code': resolved, 'locals': local_types, 'params': params,
            'results': results}

# --------------------------------------------------------------------------
# stage 3: execute -- stack-machine interpreter over resolved instructions
# --------------------------------------------------------------------------

class _Frame:
    __slots__ = ('code', 'locals', 'vs', 'labels', 'pc')

    def __init__(self, code, locals_):
        self.code = code
        self.locals = locals_
        self.vs = []
        self.labels = []
        self.pc = 0


def _idiv(op, a, b, bits):
    mask = (1 << bits) - 1
    top = 1 << (bits - 1)
    if op in ('div_s', 'rem_s'):
        a = a & mask
        b = b & mask
        a = a - (1 << bits) if a >= top else a
        b = b - (1 << bits) if b >= top else b
    else:
        a &= mask
        b &= mask
    if b == 0:
        raise WasmTrap('integer divide by zero')
    if op == 'div_s':
        if a == -top and b == -1:
            raise WasmTrap('integer overflow')
        return trunc_div(a, b) & mask
    if op == 'div_u':
        return (a // b) & mask
    if op == 'rem_s':
        if a == -top and b == -1:
            return 0
        r = abs(a) % abs(b)
        return (-r if a < 0 else r) & mask
    return (a % b) & mask  # rem_u


def _icmp(op, a, b, bits):
    mask = (1 << bits) - 1
    top = 1 << (bits - 1)
    if op.endswith('_s'):
        a = a & mask
        b = b & mask
        a = a - (1 << bits) if a >= top else a
        b = b - (1 << bits) if b >= top else b
    else:
        a &= mask
        b &= mask
    return {'eq': a == b, 'ne': a != b,
            'lt_s': a < b, 'lt_u': a < b,
            'gt_s': a > b, 'gt_u': a > b,
            'le_s': a <= b, 'le_u': a <= b,
            'ge_s': a >= b, 'ge_u': a >= b}[op]


class Instance:
    """An instantiated module: link imports, run start, call exports."""

    def __init__(self, mod, imports=None):
        imports = imports or {}
        self.types = mod['types']
        self.funcs = []

        # --- link function imports (index space comes first) ---
        for imp in mod['imports']:
            key = (imp['module'], imp['name'])
            if key not in imports:
                raise WasmError('missing import %s.%s' % key)
            params, results = self.types[imp['type']]
            self.funcs.append({'kind': 'host', 'fn': imports[key],
                               'params': params, 'results': results})

        # --- compile defined functions ---
        if len(mod['func_types']) != len(mod['codes']):
            raise WasmError('function/code section length mismatch')
        for ti, code in zip(mod['func_types'], mod['codes']):
            if ti >= len(self.types):
                raise WasmError('bad function type index %d' % ti)
            comp = compile_function(mod, ti, code)
            params, results = self.types[ti]
            self.funcs.append({'kind': 'wasm', 'code': comp['code'],
                               'params': params, 'results': results,
                               'n_extra': len(comp['locals']) - len(params)})

        # --- table (MVP: single funcref table) ---
        if len(mod['tables']) > 1:
            raise WasmError('multiple tables not supported in MVP')
        self.table = []
        if mod['tables']:
            lo, hi = mod['tables'][0]['limits']
            self.table = [None] * lo

        # --- memory (MVP: single memory) ---
        if len(mod['memories']) > 1:
            raise WasmError('multiple memories not supported in MVP')
        self.memory = bytearray()
        self.mem_max = MAX_PAGES
        if mod['memories']:
            lo, hi = mod['memories'][0]['limits']
            if lo > MAX_PAGES:
                raise WasmError('memory minimum too large')
            self.memory = bytearray(lo * PAGE)
            self.mem_max = hi if hi is not None else MAX_PAGES

        # --- globals ---
        self.globals = []
        for g in mod['globals']:
            v = self._eval_init(g['init'], g['type'])
            self.globals.append([g['type'], g['mut'], v])

        # --- elem segments ---
        for e in mod['elems']:
            off = self._eval_init(e['offset'], I32)
            if off < 0 or off + len(e['funcs']) > len(self.table):
                raise WasmTrap('elem segment does not fit table')
            for i, fi in enumerate(e['funcs']):
                if fi >= len(self.funcs):
                    raise WasmError('bad elem function index %d' % fi)
                self.table[off + i] = fi

        # --- data segments ---
        for d in mod['datas']:
            off = self._eval_init(d['offset'], I32)
            bs = d['bytes']
            if off < 0 or off + len(bs) > len(self.memory):
                raise WasmTrap('data segment does not fit memory')
            self.memory[off:off + len(bs)] = bs

        self.exports = {ex['name']: ex for ex in mod['exports']}

        if mod['start'] is not None:
            if mod['start'] >= len(self.funcs):
                raise WasmError('bad start function index')
            self._execute(mod['start'], [])

    # -- instantiation helpers ------------------------------------------------
    def _eval_init(self, expr, expect):
        if len(expr) != 2 or expr[0][0] not in (
                'i32.const', 'i64.const', 'global.get') or expr[1] != ('end',):
            raise WasmError('unsupported init expression')
        name = expr[0][0]
        if name == 'i32.const' and expect == I32:
            return u32(expr[0][1])
        if name == 'i64.const' and expect == I64:
            return u64(expr[0][1])
        if name == 'global.get':
            i = expr[0][1]
            if i >= len(self.globals):
                raise WasmError('bad global.get in init expr')
            t, _, v = self.globals[i]
            if t != expect:
                raise WasmError('global.get type mismatch in init expr')
            return v
        raise WasmError('init expr type mismatch')

    def _host_call(self, f2, args):
        res = f2['fn'](*args)
        r = f2['results']
        if not r:
            return []
        vals = list(res) if isinstance(res, (list, tuple)) else [res]
        if len(vals) != len(r):
            raise WasmTrap('host function returned wrong arity')
        return [u32(v) if t == I32 else u64(v)
                for t, v in zip(r, vals)]

    # -- public API ------------------------------------------------------------
    def invoke(self, name, args=()):
        """Call an exported function. Returns list of signed ints."""
        ex = self.exports.get(name)
        if ex is None or ex['kind'] != 'func':
            raise WasmError('no exported function %r' % (name,))
        f = self.funcs[ex['index']]
        if len(args) != len(f['params']):
            raise WasmError('arity mismatch invoking %s' % name)
        masked = [u32(a) if t == I32 else u64(int(a))
                  for t, a in zip(f['params'], args)]
        res = self._execute(ex['index'], masked)
        return [s32(v) if t == I32 else s64(v)
                for t, v in zip(f['results'], res)]

    # -- the interpreter --------------------------------------------------------
    def _execute(self, fidx, args):
        f = self.funcs[fidx]
        if f['kind'] == 'host':
            return self._host_call(f, args)
        fr = _Frame(f['code'],
                    list(args) + [0] * f['n_extra'])
        fr.labels.append({'kind': 'func', 'arity': len(f['results']),
                          'height': 0, 'start': 0, 'end_idx': None})
        stack = [fr]

        def do_branch(fr, target, npop, arity, keep, height, is_return):
            """Returns True when the current frame finished."""
            vs = fr.vs
            vals = vs[len(vs) - arity:] if arity else []
            del vs[height:]
            if is_return:
                stack.pop()
                if stack:
                    stack[-1].vs.extend(vals)
                return True, vals
            vs.extend(vals)
            if not keep:
                del fr.labels[-npop:]
            fr.pc = target
            return False, None

        def do_call(fr, f2):
            n = len(f2['params'])
            vs = fr.vs
            args = vs[len(vs) - n:] if n else []
            del vs[len(vs) - n:]
            if f2['kind'] == 'host':
                vs.extend(self._host_call(f2, args))
                fr.pc += 1
                return
            fr.pc += 1
            nfr = _Frame(f2['code'], list(args) + [0] * f2['n_extra'])
            nfr.labels.append({'kind': 'func', 'arity': len(f2['results']),
                               'height': 0, 'start': 0, 'end_idx': None})
            stack.append(nfr)

        while True:
            fr = stack[-1]
            op = fr.code[fr.pc]
            name = op[0]
            vs = fr.vs

            if name == 'nop':
                fr.pc += 1
            elif name == 'unreachable':
                raise WasmTrap('unreachable executed')
            elif name == 'drop':
                vs.pop()
                fr.pc += 1
            elif name == 'select':
                c = vs.pop()
                v2 = vs.pop()
                v1 = vs.pop()
                vs.append(v1 if c != 0 else v2)
                fr.pc += 1
            elif name == 'block':
                _, end_idx, arity = op
                fr.labels.append({'kind': 'block', 'arity': arity,
                                  'height': len(vs), 'start': 0,
                                  'end_idx': end_idx})
                fr.pc += 1
            elif name == 'loop':
                _, start, end_idx, arity = op
                fr.labels.append({'kind': 'loop', 'arity': arity,
                                  'height': len(vs), 'start': start,
                                  'end_idx': end_idx})
                fr.pc += 1
            elif name == 'if':
                _, else_idx, end_idx, arity = op
                c = vs.pop()
                fr.labels.append({'kind': 'if', 'arity': arity,
                                  'height': len(vs), 'start': 0,
                                  'end_idx': end_idx})
                if c == 0:
                    # no else: land ON the end op so it pops the label
                    fr.pc = else_idx + 1 if else_idx is not None else end_idx
                else:
                    fr.pc += 1
            elif name == 'else':
                fr.pc = op[1]  # land on `end`, which pops the label
            elif name == 'end':
                lab = fr.labels.pop()
                if lab['kind'] == 'func':
                    arity = lab['arity']
                    vals = vs[len(vs) - arity:] if arity else []
                    stack.pop()
                    if not stack:
                        return vals
                    stack[-1].vs.extend(vals)
                else:
                    fr.pc += 1
            elif name == 'br':
                _, target, npop, arity, keep, height, is_ret = op
                done, vals = do_branch(fr, target, npop, arity, keep,
                                       height, is_ret)
                if done and not stack:
                    return vals
            elif name == 'br_if':
                _, target, npop, arity, keep, height, is_ret = op
                c = vs.pop()
                if c != 0:
                    done, vals = do_branch(fr, target, npop, arity, keep,
                                           height, is_ret)
                    if done and not stack:
                        return vals
                else:
                    fr.pc += 1
            elif name == 'br_table':
                entries = op[1]
                i = vs.pop()
                e = entries[i] if 0 <= i < len(entries) - 1 else entries[-1]
                target, npop, arity, keep, height, is_ret = e
                done, vals = do_branch(fr, target, npop, arity, keep,
                                       height, is_ret)
                if done and not stack:
                    return vals
            elif name == 'return':
                arity = op[1]
                vals = vs[len(vs) - arity:] if arity else []
                stack.pop()
                if not stack:
                    return vals
                stack[-1].vs.extend(vals)
            elif name == 'call':
                do_call(fr, self.funcs[op[1]])
            elif name == 'call_indirect':
                tidx = op[1]
                i = vs.pop()
                if i < 0 or i >= len(self.table) or self.table[i] is None:
                    raise WasmTrap('call_indirect: null function reference')
                f2 = self.funcs[self.table[i]]
                ep, er = self.types[tidx]
                if f2['params'] != ep or f2['results'] != er:
                    raise WasmTrap('call_indirect: signature mismatch')
                do_call(fr, f2)
            elif name == 'local.get':
                vs.append(fr.locals[op[1]])
                fr.pc += 1
            elif name == 'local.set':
                fr.locals[op[1]] = vs.pop()
                fr.pc += 1
            elif name == 'local.tee':
                fr.locals[op[1]] = vs[-1]
                fr.pc += 1
            elif name == 'global.get':
                vs.append(self.globals[op[1]][2])
                fr.pc += 1
            elif name == 'global.set':
                t = self.globals[op[1]][0]
                self.globals[op[1]][2] = u32(vs.pop()) if t == I32 \
                    else u64(vs.pop())
                fr.pc += 1
            elif name == 'i32.const':
                vs.append(u32(op[1]))
                fr.pc += 1
            elif name == 'i64.const':
                vs.append(u64(op[1]))
                fr.pc += 1
            elif name == 'load':
                _, w, signed, rt, off = op
                base = vs.pop()
                ea = (base & M32) + off
                if ea + w > len(self.memory):
                    raise WasmTrap('out of bounds memory access')
                raw = int.from_bytes(self.memory[ea:ea + w], 'little')
                if signed and raw >= (1 << (w * 8 - 1)):
                    raw -= 1 << (w * 8)
                vs.append(raw)
                fr.pc += 1
            elif name == 'store':
                _, w, vt, off = op
                val = vs.pop()
                base = vs.pop()
                ea = (base & M32) + off
                if ea + w > len(self.memory):
                    raise WasmTrap('out of bounds memory access')
                self.memory[ea:ea + w] = (
                    val & ((1 << (w * 8)) - 1)).to_bytes(w, 'little')
                fr.pc += 1
            elif name == 'memory.size':
                vs.append(len(self.memory) // PAGE)
                fr.pc += 1
            elif name == 'memory.grow':
                n = vs.pop()
                cur = len(self.memory) // PAGE
                if n < 0 or cur + n > self.mem_max:
                    vs.append(M32)  # -1 as i32
                else:
                    self.memory.extend(b'\x00' * (n * PAGE))
                    vs.append(cur)
                fr.pc += 1
            else:
                self._exec_int(fr, name)
                fr.pc += 1

    def _exec_int(self, fr, name):
        """Integer arithmetic/comparison/conversion ops."""
        vs = fr.vs
        width, o = name.split('.')
        bits = 32 if width == 'i32' else 64
        mask = M32 if bits == 32 else M64
        top = 1 << (bits - 1)

        def S(v):
            v &= mask
            return v - (1 << bits) if v >= top else v

        if o in ('add', 'sub', 'mul', 'and', 'or', 'xor'):
            b = vs.pop()
            a = vs.pop()
            r = {'add': a + b, 'sub': a - b, 'mul': a * b,
                 'and': a & b, 'or': a | b, 'xor': a ^ b}[o]
            vs.append(r & mask)
        elif o in ('div_s', 'div_u', 'rem_s', 'rem_u'):
            b = vs.pop()
            a = vs.pop()
            vs.append(_idiv(o, a, b, bits))
        elif o in ('shl', 'shr_s', 'shr_u', 'rotl', 'rotr'):
            b = vs.pop()
            a = vs.pop() & mask
            k = b & (bits - 1)
            if o == 'shl':
                vs.append((a << k) & mask)
            elif o == 'shr_s':
                vs.append((S(a) >> k) & mask)
            elif o == 'shr_u':
                vs.append(a >> k)
            elif o == 'rotl':
                vs.append(rotl(a, k, bits))
            else:
                vs.append(rotr(a, k, bits))
        elif o in ('clz', 'ctz', 'popcnt'):
            a = vs.pop()
            vs.append({'clz': clz(a, bits), 'ctz': ctz(a, bits),
                       'popcnt': popcnt(a, bits)}[o])
        elif o == 'eqz':
            vs.append(1 if (vs.pop() & mask) == 0 else 0)
        elif o in ('eq', 'ne', 'lt_s', 'lt_u', 'gt_s', 'gt_u',
                   'le_s', 'le_u', 'ge_s', 'ge_u'):
            b = vs.pop()
            a = vs.pop()
            vs.append(1 if _icmp(o, a, b, bits) else 0)
        elif o == 'wrap_i64':
            vs.append(vs.pop() & M32)
        elif o == 'extend_i32_s':
            vs.append(S(vs.pop() & M32) & M64)
        elif o == 'extend_i32_u':
            vs.append(vs.pop() & M32)
        elif o in ('extend8_s', 'extend16_s', 'extend32_s'):
            n = {'extend8_s': 8, 'extend16_s': 16, 'extend32_s': 32}[o]
            a = vs.pop() & ((1 << n) - 1)
            if a >= (1 << (n - 1)):
                a -= 1 << n
            vs.append(a & mask)
        else:
            raise WasmError('unimplemented int op: %s' % name)


def load(data, imports=None):
    """Decode + instantiate a module. Returns an Instance."""
    return Instance(decode_module(data), imports)
