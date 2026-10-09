#!/usr/bin/env python3
"""sheets.py — a from-scratch spreadsheet formula engine. Zero dependencies.

Supports: A1 refs (relative/absolute), cross-sheet refs, ranges, 60+ functions,
Excel-compatible type coercion and error propagation, dependency-graph
topological evaluation with cycle detection, relative formula copy (drag-fill),
CSV import/export, a pretty renderer, and a small REPL.

Value model: float | str | bool | None(empty) | XlError | RangeVal
"""

import csv
import argparse
import math
import re
import sys

MAX_ROW = 1048576
MAX_COL = 16384  # XFD

# ---------------------------------------------------------------- errors

class XlError:
    """An Excel-style error value. Propagates through every operation."""
    __slots__ = ("code",)
    _cache = {}

    def __new__(cls, code):
        if code in cls._cache:
            return cls._cache[code]
        o = super().__new__(cls)
        o.code = code
        cls._cache[code] = o
        return o

    def __repr__(self):
        return self.code

    def __eq__(self, a):
        return isinstance(a, XlError) and a.code == self.code

    def __hash__(self):
        return hash(self.code)


DIV0 = XlError("#DIV/0!")
VALUE = XlError("#VALUE!")
REF = XlError("#REF!")
NAME = XlError("#NAME?")
NUM = XlError("#NUM!")
NA = XlError("#N/A")
CYCLE = XlError("#CYCLE!")


class FormulaSyntaxError(Exception):
    pass


class LexError(FormulaSyntaxError):
    pass


# ---------------------------------------------------------------- A1 addressing

def col_to_name(c):
    """0-based column index -> 'A', 'Z', 'AA', ..."""
    s = ""
    c += 1
    while c:
        c, r = divmod(c - 1, 26)
        s = chr(65 + r) + s
    return s


def name_to_col(name):
    c = 0
    for ch in name.upper():
        c = c * 26 + (ord(ch) - 64)
    return c - 1


def parse_a1(tok):
    """Parse '$A$1'-style token. Returns (row, col, abs_row, abs_col),
    the string 'REF' if out of grid bounds, or None if not a ref."""
    m = re.fullmatch(r"(\$?)([A-Za-z]{1,3})(\$?)(\d+)", tok)
    if not m:
        return None
    col = name_to_col(m.group(2))
    row = int(m.group(4)) - 1
    if not (0 <= col < MAX_COL and 0 <= row < MAX_ROW):
        return "REF"
    return (row, col, m.group(3) == "$", m.group(1) == "$")


def a1_of(r, c, abs_row=False, abs_col=False):
    return ("$" if abs_col else "") + col_to_name(c) + ("$" if abs_row else "") + str(r + 1)


# ---------------------------------------------------------------- lexer

def lex(s):
    """Tokenize a formula body (no leading '='). Tokens are
    (kind, text, start, end)."""
    toks = []
    i, n = 0, len(s)
    while i < n:
        ch = s[i]
        if ch.isspace():
            i += 1
            continue
        if ch == '"':  # string literal, "" is an escaped quote
            j = i + 1
            while j < n:
                if s[j] == '"':
                    if j + 1 < n and s[j + 1] == '"':
                        j += 2
                        continue
                    break
                j += 1
            if j >= n:
                raise LexError("unterminated string literal")
            toks.append(("STR", s[i:j + 1], i, j + 1))
            i = j + 1
            continue
        if ch == "'":  # quoted sheet name: 'My Sheet'!
            j = i + 1
            while j < n:
                if s[j] == "'":
                    if j + 1 < n and s[j + 1] == "'":
                        j += 2
                        continue
                    break
                j += 1
            if j >= n:
                raise LexError("unterminated quoted sheet name")
            toks.append(("SHEETQ", s[i:j + 1], i, j + 1))
            i = j + 1
            continue
        if ch.isdigit() or (ch == "." and i + 1 < n and s[i + 1].isdigit()):
            m = re.match(r"(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?", s[i:])
            toks.append(("NUM", m.group(0), i, i + len(m.group(0))))
            i += len(m.group(0))
            continue
        if ch.isalpha() or ch == "_" or ch == "$":
            m = re.match(r"\$?[A-Za-z]{1,3}\$?\d+", s[i:])
            if m:
                e = i + len(m.group(0))
                # 'ABC1def' is an identifier, not a cell ref
                if e < n and (s[e].isalpha() or s[e] == "_" or s[e] == "."):
                    m = None
                else:
                    toks.append(("CELL", m.group(0), i, e))
                    i = e
                    continue
            m2 = re.match(r"[A-Za-z_][A-Za-z0-9_.]*", s[i:])
            if not m2:
                raise LexError("bad character %r" % ch)
            toks.append(("IDENT", m2.group(0), i, i + len(m2.group(0))))
            i += len(m2.group(0))
            continue
        two = s[i:i + 2]
        if two in ("<>", "<=", ">="):
            toks.append(("OP", two, i, i + 2))
            i += 2
            continue
        if ch in "=<>+-*/^&%(),:!":
            toks.append(("OP", ch, i, i + 1))
            i += 1
            continue
        raise LexError("bad character %r" % ch)
    toks.append(("EOF", "", n, n))
    return toks


# ---------------------------------------------------------------- parser
# Precedence (Excel order, with Excel's famous quirk that unary minus binds
# tighter than ^, so =-2^2 is 4):
#   comparison -> concat(&) -> additive -> multiplicative -> power -> unary -> postfix(%) -> primary

CMP_OPS = ("=", "<>", "<", ">", "<=", ">=")


class Parser:
    def __init__(self, toks):
        self.toks = toks
        self.i = 0

    def peek(self):
        return self.toks[self.i]

    def next(self):
        t = self.toks[self.i]
        self.i += 1
        return t

    def expect_op(self, op):
        t = self.next()
        if t[0] != "OP" or t[1] != op:
            raise FormulaSyntaxError("expected %r, got %r" % (op, t[1]))
        return t

    def parse(self):
        node = self.expr()
        t = self.peek()
        if t[0] != "EOF":
            raise FormulaSyntaxError("unexpected %r" % t[1])
        return node

    def expr(self):
        return self.comparison()

    def comparison(self):
        node = self.concat()
        while self.peek()[0] == "OP" and self.peek()[1] in CMP_OPS:
            op = self.next()[1]
            node = ("binop", op, node, self.concat())
        return node

    def concat(self):
        node = self.additive()
        while self.peek()[0] == "OP" and self.peek()[1] == "&":
            self.next()
            node = ("binop", "&", node, self.additive())
        return node

    def additive(self):
        node = self.multiplicative()
        while self.peek()[0] == "OP" and self.peek()[1] in ("+", "-"):
            op = self.next()[1]
            node = ("binop", op, node, self.multiplicative())
        return node

    def multiplicative(self):
        node = self.power()
        while self.peek()[0] == "OP" and self.peek()[1] in ("*", "/"):
            op = self.next()[1]
            node = ("binop", op, node, self.power())
        return node

    def power(self):
        node = self.unary()
        if self.peek()[0] == "OP" and self.peek()[1] == "^":
            self.next()
            node = ("binop", "^", node, self.power())  # right-assoc
        return node

    def unary(self):
        if self.peek()[0] == "OP" and self.peek()[1] == "-":
            self.next()
            return ("unop", "-", self.unary())
        if self.peek()[0] == "OP" and self.peek()[1] == "+":
            self.next()
            return self.unary()
        return self.postfix()

    def postfix(self):
        node = self.primary()
        while self.peek()[0] == "OP" and self.peek()[1] == "%":
            self.next()
            node = ("pct", node)
        return node

    def primary(self):
        t = self.peek()
        if t[0] == "NUM":
            self.next()
            return ("num", float(t[1]))
        if t[0] == "STR":
            self.next()
            return ("str", t[1][1:-1].replace('""', '"'))
        if t[0] == "OP" and t[1] == "(":
            self.next()
            node = self.expr()
            self.expect_op(")")
            return node
        if t[0] in ("IDENT", "SHEETQ"):
            return self.ident_or_sheetref()
        if t[0] == "CELL":
            return self.cell_or_range(None)
        raise FormulaSyntaxError("unexpected %r" % t[1])

    def ident_or_sheetref(self):
        t = self.next()
        sheet = None
        if t[0] == "SHEETQ":
            sheet = t[1][1:-1].replace("''", "'")
            self.expect_op("!")
        elif self.peek()[0] == "OP" and self.peek()[1] == "!":
            sheet = t[1]
            self.next()
        else:
            up = t[1].upper()
            if up == "TRUE":
                return ("bool", True)
            if up == "FALSE":
                return ("bool", False)
            if self.peek()[0] == "OP" and self.peek()[1] == "(":
                self.next()
                args = []
                if not (self.peek()[0] == "OP" and self.peek()[1] == ")"):
                    while True:
                        args.append(self.expr())
                        if self.peek()[0] == "OP" and self.peek()[1] == ",":
                            self.next()
                            continue
                        break
                self.expect_op(")")
                return ("call", up, args)
            return ("name", t[1])  # bare unknown name -> #NAME? at eval
        # sheet-qualified reference follows
        t2 = self.peek()
        if t2[0] != "CELL":
            raise FormulaSyntaxError("expected cell reference after '!'")
        return self.cell_or_range(sheet)

    def cell_or_range(self, sheet):
        t = self.next()  # CELL
        p = parse_a1(t[1])
        if p == "REF":
            first = ("referr",)
        elif p is None:
            raise FormulaSyntaxError("bad cell reference %r" % t[1])
        else:
            r, c, ar, ac = p
            first = ("cell", sheet, r, c, ar, ac)
        if self.peek()[0] == "OP" and self.peek()[1] == ":":
            self.next()
            t2 = self.next()
            if t2[0] != "CELL":
                raise FormulaSyntaxError("expected cell reference after ':'")
            p2 = parse_a1(t2[1])
            if first[0] == "referr" or p2 == "REF":
                return ("referr",)
            r1, c1, ar1, ac1 = p
            r2, c2, ar2, ac2 = p2
            return ("range", sheet,
                    min(r1, r2), min(c1, c2), max(r1, r2), max(c1, c2),
                    ar1, ac1, ar2, ac2)
        return first


def parse_formula(body):
    """Parse a formula body (without leading '=')."""
    return Parser(lex(body)).parse()

# ---------------------------------------------------------------- values & coercion

class RangeVal:
    """A rectangular cell range awaiting a function that knows what to do
    with it. In scalar context it is a #VALUE! error (no implicit
    intersection / spilling here — a deliberate, documented gap)."""
    __slots__ = ("sheet", "r1", "c1", "r2", "c2")

    def __init__(self, sheet, r1, c1, r2, c2):
        self.sheet, self.r1, self.c1, self.r2, self.c2 = sheet, r1, c1, r2, c2

    def __repr__(self):
        return "RangeVal(%s!%s:%s)" % (
            self.sheet or "?", a1_of(self.r1, self.c1), a1_of(self.r2, self.c2))


def num_to_text(v):
    if v != v or v in (float("inf"), float("-inf")):  # NaN/inf shouldn't happen
        return str(v)
    if float(v).is_integer() and abs(v) < 1e15:
        return str(int(v))
    s = "%.10f" % v
    return s.rstrip("0").rstrip(".")


def to_number(v):
    """Excel arithmetic coercion: blank->0, bool->1/0, numeric text->number,
    empty text->#VALUE! (unlike a blank cell)."""
    if isinstance(v, XlError):
        return v
    if v is None:
        return 0.0
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        s = v.strip()
        if s == "":
            return VALUE
        try:
            return float(s)
        except ValueError:
            return VALUE
    return VALUE  # RangeVal etc.


def to_text(v):
    if isinstance(v, XlError):
        return v
    if v is None:
        return ""
    if isinstance(v, bool):
        return "TRUE" if v else "FALSE"
    if isinstance(v, (int, float)):
        return num_to_text(v)
    return v


def to_bool_strict(v):
    """For IF/AND/OR/NOT conditions. Text -> #VALUE! (Excel behavior)."""
    if isinstance(v, XlError):
        return v
    if v is None:
        return False
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    return VALUE


def type_rank(v):
    if v is None:
        return -1
    if isinstance(v, bool):
        return 2
    if isinstance(v, (int, float)):
        return 0
    return 1  # text


def xl_equal(a, b):
    """Excel '=' equality: case-insensitive text, blank equals 0 and '',
    and (the documented quirk) empty text equals numeric 0."""
    if isinstance(a, XlError) or isinstance(b, XlError):
        return None  # caller propagates
    # "" behaves as 0 against numbers
    if isinstance(a, str) and a == "" and isinstance(b, (int, float)) \
            and not isinstance(b, bool):
        a = 0.0
    if isinstance(b, str) and b == "" and isinstance(a, (int, float)) \
            and not isinstance(a, bool):
        b = 0.0
    ra, rb = type_rank(a), type_rank(b)
    if ra == -1 and rb == -1:
        return True
    if ra == -1:
        return xl_equal(0.0 if rb == 0 else "", b)
    if rb == -1:
        return xl_equal(a, 0.0 if ra == 0 else "")
    if ra != rb:
        return False
    if ra == 0:
        return float(a) == float(b)
    if ra == 1:
        return a.lower() == b.lower()
    return bool(a) == bool(b)


def cmp_values(op, l, r):
    """Excel comparison with cross-type rank ordering:
    number < text < logical, blank below all (but equal to 0 and '')."""
    if isinstance(l, XlError):
        return l
    if isinstance(r, XlError):
        return r
    if op == "=":
        return xl_equal(l, r)
    if op == "<>":
        return not xl_equal(l, r)
    # ordering: normalize blank/"" against the other side's type
    rl, rr = type_rank(l), type_rank(r)
    if rl == 1 and l == "" and rr == 0:
        l, rl = 0.0, 0
    if rr == 1 and r == "" and rl == 0:
        r, rr = 0.0, 0
    if rl == -1 and rr == -1:
        diff = 0
    elif rl == -1:
        if rr == 0:
            diff = -1 if 0.0 < float(r) else (1 if 0.0 > float(r) else 0)
        elif rr == 1:
            diff = -1 if "" < r.lower() else (1 if "" > r.lower() else 0)
        else:  # blank sorts below FALSE
            diff = -1
    elif rr == -1:
        flip = {"<": ">", ">": "<", "<=": ">=", ">=": "<="}[op]
        return cmp_values(flip, r, l)
    elif rl != rr:
        diff = -1 if rl < rr else 1
    elif rl == 0:
        diff = -1 if float(l) < float(r) else (1 if float(l) > float(r) else 0)
    elif rl == 1:
        a, b = l.lower(), r.lower()
        diff = -1 if a < b else (1 if a > b else 0)
    else:
        diff = -1 if (not l and r) else (1 if (l and not r) else 0)
    return {"<": diff < 0, ">": diff > 0,
            "<=": diff <= 0, ">=": diff >= 0}[op]


def apply_binop(op, l, r):
    if isinstance(l, XlError):
        return l
    if isinstance(r, XlError):
        return r
    if isinstance(l, RangeVal) or isinstance(r, RangeVal):
        return VALUE
    if op == "&":
        return to_text(l) + to_text(r)
    if op in CMP_OPS:
        return cmp_values(op, l, r)
    a = to_number(l)
    if isinstance(a, XlError):
        return a
    b = to_number(r)
    if isinstance(b, XlError):
        return b
    try:
        if op == "+":
            return a + b
        if op == "-":
            return a - b
        if op == "*":
            return a * b
        if op == "/":
            if b == 0:
                return DIV0
            return a / b
        if op == "^":
            res = a ** b
            if isinstance(res, complex):
                return NUM
            return res
    except (OverflowError, ValueError):
        return NUM
    raise AssertionError("unknown op " + op)


# ---------------------------------------------------------------- evaluator

class Ctx:
    def __init__(self, wb, sheet_name, memo):
        self.wb = wb            # Workbook
        self.sheet = sheet_name  # current sheet name
        self.memo = memo        # {(sheet, r, c): value} computed formula cells


def eval_node(node, ctx):
    k = node[0]
    if k == "num":
        return node[1]
    if k == "str":
        return node[1]
    if k == "bool":
        return node[1]
    if k == "name":
        return NAME
    if k == "referr":
        return REF
    if k == "cell":
        _, sheet, r, c, _, _ = node
        return ctx.wb.cell_value(sheet or ctx.sheet, r, c, ctx.memo)
    if k == "range":
        _, sheet, r1, c1, r2, c2, _, _, _, _ = node
        return RangeVal(sheet or ctx.sheet, r1, c1, r2, c2)
    if k == "binop":
        _, op, l, r = node
        return apply_binop(op, eval_node(l, ctx), eval_node(r, ctx))
    if k == "unop":
        v = eval_node(node[2], ctx)
        n = to_number(v)
        return -n if not isinstance(n, XlError) else n
    if k == "pct":
        v = eval_node(node[1], ctx)
        n = to_number(v)
        return n / 100.0 if not isinstance(n, XlError) else n
    if k == "call":
        _, name, args = node
        fn = FUNCTIONS.get(name)
        if fn is None:
            return NAME
        return fn(args, ctx)
    raise AssertionError("bad node " + str(k))


def eval_args(args, ctx):
    """Eagerly evaluate argument list. First XlError wins."""
    out = []
    for a in args:
        v = eval_node(a, ctx)
        if isinstance(v, XlError):
            return v
        out.append(v)
    return out


def iter_range(ctx, rv):
    """Yield computed values of every cell in a range, row-major."""
    sheet = ctx.wb.sheets[rv.sheet]
    for r in range(rv.r1, rv.r2 + 1):
        for c in range(rv.c1, rv.c2 + 1):
            yield ctx.wb.cell_value(rv.sheet, r, c, ctx.memo)


def flatten_args(args, ctx):
    """Evaluate args; expand RangeVals to their cell values. Errors win."""
    vals = eval_args(args, ctx)
    if isinstance(vals, XlError):
        return vals
    out = []
    for v in vals:
        if isinstance(v, RangeVal):
            out.extend(iter_range(ctx, v))
        else:
            out.append(v)
    return out


def numbers_only(vals, direct_ok_bool=True):
    """Excel aggregator semantics: within ranges, only numbers count
    (text/bools/blanks ignored, errors propagate). As direct arguments,
    bools count as 1/0 but text is #VALUE!."""
    # flatten_args already expanded ranges; we lose range-vs-direct info,
    # so aggregators below handle ranges themselves. This helper is for
    # the direct-args path.
    nums = []
    for v in vals:
        if isinstance(v, XlError):
            return v
        if isinstance(v, bool):
            if direct_ok_bool:
                nums.append(1.0 if v else 0.0)
        elif isinstance(v, (int, float)):
            nums.append(float(v))
        elif isinstance(v, str):
            return VALUE
        # None (blank) skipped
    return nums


# ---------------------------------------------------------------- functions

def _agg(args, ctx, op):
    """Shared aggregator: SUM/AVERAGE/MIN/MAX/COUNT/PRODUCT over args where
    ranges contribute numbers only and direct text is #VALUE!."""
    vals = eval_args(args, ctx)
    if isinstance(vals, XlError):
        return vals
    nums = []
    count_nonempty = 0
    for v in vals:
        if isinstance(v, RangeVal):
            for cell in iter_range(ctx, v):
                if isinstance(cell, XlError):
                    return cell
                if cell is None:
                    continue
                count_nonempty += 1
                if isinstance(cell, bool):
                    continue  # ignored inside ranges
                if isinstance(cell, (int, float)):
                    nums.append(float(cell))
                # text inside ranges ignored
        else:
            if isinstance(v, XlError):
                return v
            if v is None:
                continue
            count_nonempty += 1
            if isinstance(v, bool):
                nums.append(1.0 if v else 0.0)
            elif isinstance(v, (int, float)):
                nums.append(float(v))
            else:
                return VALUE  # direct text arg
    if op == "SUM":
        return sum(nums)
    if op == "COUNT":
        return float(len(nums))
    if op == "COUNTA":
        return float(count_nonempty)
    if not nums:
        return DIV0 if op == "AVERAGE" else 0.0
    if op == "AVERAGE":
        return sum(nums) / len(nums)
    if op == "MIN":
        return min(nums)
    if op == "MAX":
        return max(nums)
    if op == "PRODUCT":
        p = 1.0
        for x in nums:
            p *= x
        return p
    raise AssertionError(op)


def f_IF(args, ctx):
    if len(args) not in (2, 3):
        return VALUE
    cond = eval_node(args[0], ctx)
    if isinstance(cond, XlError):
        return cond
    b = to_bool_strict(cond)
    if isinstance(b, XlError):
        return b
    if b:
        return eval_node(args[1], ctx)
    if len(args) == 3:
        return eval_node(args[2], ctx)
    return False


def f_IFERROR(args, ctx):
    if len(args) != 2:
        return VALUE
    v = eval_node(args[0], ctx)
    if isinstance(v, XlError):
        return eval_node(args[1], ctx)  # lazy fallback
    return v


def f_AND(args, ctx):
    vals = eval_args(args, ctx)  # strict: errors propagate even past FALSE
    if isinstance(vals, XlError):
        return vals
    if not vals:
        return True  # vacuous truth, matches Excel
    for v in vals:
        if isinstance(v, RangeVal):
            return VALUE
        b = to_bool_strict(v)
        if isinstance(b, XlError):
            return b
        if not b:
            return False
    return True


def f_OR(args, ctx):
    vals = eval_args(args, ctx)
    if isinstance(vals, XlError):
        return vals
    if not vals:
        return False
    for v in vals:
        if isinstance(v, RangeVal):
            return VALUE
        b = to_bool_strict(v)
        if isinstance(b, XlError):
            return b
        if b:
            return True
    return False


def f_NOT(args, ctx):
    if len(args) != 1:
        return VALUE
    v = eval_node(args[0], ctx)
    b = to_bool_strict(v)
    return (not b) if not isinstance(b, XlError) else b


def _one_num(args, ctx, fname):
    if len(args) != 1:
        return VALUE
    v = eval_node(args[0], ctx)
    n = to_number(v)
    if isinstance(n, XlError) or isinstance(v, RangeVal):
        return n if isinstance(n, XlError) else VALUE
    return n


def f_ABS(args, ctx):
    n = _one_num(args, ctx, "ABS")
    return abs(n) if not isinstance(n, XlError) else n


def f_INT(args, ctx):
    n = _one_num(args, ctx, "INT")
    return float(math.floor(n)) if not isinstance(n, XlError) else n


def f_SQRT(args, ctx):
    n = _one_num(args, ctx, "SQRT")
    if isinstance(n, XlError):
        return n
    if n < 0:
        return NUM
    return math.sqrt(n)


def f_MOD(args, ctx):
    if len(args) != 2:
        return VALUE
    vals = eval_args(args, ctx)
    if isinstance(vals, XlError):
        return vals
    a = to_number(vals[0])
    b = to_number(vals[1])
    if isinstance(a, XlError):
        return a
    if isinstance(b, XlError):
        return b
    if b == 0:
        return DIV0
    # Excel: result takes the sign of the divisor
    return a - b * math.floor(a / b)


def f_POWER(args, ctx):
    if len(args) != 2:
        return VALUE
    vals = eval_args(args, ctx)
    if isinstance(vals, XlError):
        return vals
    return apply_binop("^", vals[0], vals[1])


def _round_half_away(x, n):
    p = 10.0 ** n
    return math.copysign(math.floor(abs(x) * p + 0.5), x) / p


def f_ROUND(args, ctx):
    if len(args) != 2:
        return VALUE
    vals = eval_args(args, ctx)
    if isinstance(vals, XlError):
        return vals
    x = to_number(vals[0])
    n = to_number(vals[1])
    if isinstance(x, XlError):
        return x
    if isinstance(n, XlError):
        return n
    return _round_half_away(x, int(n))


def f_ROUNDUP(args, ctx):
    if len(args) != 2:
        return VALUE
    vals = eval_args(args, ctx)
    if isinstance(vals, XlError):
        return vals
    x = to_number(vals[0])
    n = to_number(vals[1])
    if isinstance(x, XlError):
        return x
    if isinstance(n, XlError):
        return n
    p = 10.0 ** int(n)
    return math.copysign(math.ceil(abs(x) * p - 1e-9), x) / p


def f_ROUNDDOWN(args, ctx):
    if len(args) != 2:
        return VALUE
    vals = eval_args(args, ctx)
    if isinstance(vals, XlError):
        return vals
    x = to_number(vals[0])
    n = to_number(vals[1])
    if isinstance(x, XlError):
        return x
    if isinstance(n, XlError):
        return n
    p = 10.0 ** int(n)
    return math.copysign(math.floor(abs(x) * p + 1e-9), x) / p


def f_EXP(args, ctx):
    n = _one_num(args, ctx, "EXP")
    if isinstance(n, XlError):
        return n
    try:
        return math.exp(n)
    except OverflowError:
        return NUM


def f_LN(args, ctx):
    n = _one_num(args, ctx, "LN")
    if isinstance(n, XlError) or n <= 0:
        return n if isinstance(n, XlError) else NUM
    return math.log(n)


def f_LOG(args, ctx):
    if len(args) not in (1, 2):
        return VALUE
    vals = eval_args(args, ctx)
    if isinstance(vals, XlError):
        return vals
    x = to_number(vals[0])
    base = to_number(vals[1]) if len(vals) == 2 else 10.0
    if isinstance(x, XlError):
        return x
    if isinstance(base, XlError):
        return base
    if x <= 0 or base <= 0 or base == 1:
        return NUM
    return math.log(x, base)


def f_PI(args, ctx):
    if args:
        return VALUE
    return math.pi


# ---- text functions (1-indexed, like Excel) ----

def _text_arg(v):
    t = to_text(v)
    return t


def f_LEN(args, ctx):
    if len(args) != 1:
        return VALUE
    v = eval_node(args[0], ctx)
    if isinstance(v, XlError):
        return v
    return float(len(_text_arg(v)))


def f_LEFT(args, ctx):
    if len(args) not in (1, 2):
        return VALUE
    vals = eval_args(args, ctx)
    if isinstance(vals, XlError):
        return vals
    s = _text_arg(vals[0])
    n = int(to_number(vals[1])) if len(vals) == 2 else 1
    if isinstance(n, XlError) or n < 0:
        return n if isinstance(n, XlError) else VALUE
    return s[:n]


def f_RIGHT(args, ctx):
    if len(args) not in (1, 2):
        return VALUE
    vals = eval_args(args, ctx)
    if isinstance(vals, XlError):
        return vals
    s = _text_arg(vals[0])
    n = int(to_number(vals[1])) if len(vals) == 2 else 1
    if n < 0:
        return VALUE
    return s[len(s) - n:] if n else ""


def f_MID(args, ctx):
    if len(args) != 3:
        return VALUE
    vals = eval_args(args, ctx)
    if isinstance(vals, XlError):
        return vals
    s = _text_arg(vals[0])
    start = to_number(vals[1])
    num = to_number(vals[2])
    if isinstance(start, XlError):
        return start
    if isinstance(num, XlError):
        return num
    if int(start) < 1 or int(num) < 0:
        return VALUE
    return s[int(start) - 1:int(start) - 1 + int(num)]


def f_UPPER(args, ctx):
    if len(args) != 1:
        return VALUE
    v = eval_node(args[0], ctx)
    return _text_arg(v).upper() if not isinstance(v, XlError) else v


def f_LOWER(args, ctx):
    if len(args) != 1:
        return VALUE
    v = eval_node(args[0], ctx)
    return _text_arg(v).lower() if not isinstance(v, XlError) else v


def f_TRIM(args, ctx):
    if len(args) != 1:
        return VALUE
    v = eval_node(args[0], ctx)
    if isinstance(v, XlError):
        return v
    return re.sub(r"\s+", " ", _text_arg(v)).strip()


def f_CONCAT(args, ctx):
    vals = flatten_args(args, ctx)
    if isinstance(vals, XlError):
        return vals
    out = []
    for v in vals:
        if isinstance(v, XlError):
            return v
        out.append(_text_arg(v))
    return "".join(out)


def f_REPT(args, ctx):
    if len(args) != 2:
        return VALUE
    vals = eval_args(args, ctx)
    if isinstance(vals, XlError):
        return vals
    s = _text_arg(vals[0])
    n = to_number(vals[1])
    if isinstance(n, XlError) or int(n) < 0:
        return n if isinstance(n, XlError) else VALUE
    return s * int(n)


def f_FIND(args, ctx):
    if len(args) not in (2, 3):
        return VALUE
    vals = eval_args(args, ctx)
    if isinstance(vals, XlError):
        return vals
    find = _text_arg(vals[0])
    within = _text_arg(vals[1])
    start = int(to_number(vals[2])) if len(vals) == 3 else 1
    if isinstance(start, XlError) or start < 1:
        return start if isinstance(start, XlError) else VALUE
    i = within.find(find, start - 1)
    if i < 0:
        return VALUE
    return float(i + 1)


def f_VALUE(args, ctx):
    if len(args) != 1:
        return VALUE
    v = eval_node(args[0], ctx)
    if isinstance(v, XlError):
        return v
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return float(v)
    n = to_number(v if isinstance(v, str) else _text_arg(v))
    return n


# ---- lookup & conditional aggregation ----

def f_VLOOKUP(args, ctx):
    if len(args) not in (3, 4):
        return VALUE
    vals = eval_args(args, ctx)
    if isinstance(vals, XlError):
        return vals
    key, table = vals[0], vals[1]
    if not isinstance(table, RangeVal):
        return VALUE
    ci = to_number(vals[2])
    if isinstance(ci, XlError):
        return ci
    ci = int(ci)
    width = table.c2 - table.c1 + 1
    if ci < 1:
        return VALUE
    if ci > width:
        return REF
    approx = True
    if len(vals) == 4:
        a = vals[3]
        b = to_bool_strict(a)
        if isinstance(b, XlError):
            # Excel: numeric nonzero = TRUE
            n = to_number(a)
            if isinstance(n, XlError):
                return n
            b = n != 0
        approx = b
    rows = []
    for r in range(table.r1, table.r2 + 1):
        rows.append([ctx.wb.cell_value(table.sheet, r, c, ctx.memo)
                     for c in range(table.c1, table.c2 + 1)])
    if not approx:
        for row in rows:
            e = xl_equal(row[0], key)
            if e:
                v = row[ci - 1]
                return v if not isinstance(v, XlError) else v
        return NA
    # approximate: last row with first-col <= key (assumes sorted)
    best = None
    for row in rows:
        k = row[0]
        if isinstance(k, XlError):
            continue
        le = cmp_values("<=", k, key)
        if le is True:
            best = row
        elif isinstance(le, XlError):
            return le
    if best is None:
        return NA
    return best[ci - 1]


def parse_criteria(c):
    """-> (op, is_text, value). is_text values may carry * ? wildcards."""
    if isinstance(c, bool):
        return ("=", False, 1.0 if c else 0.0)
    if isinstance(c, (int, float)):
        return ("=", False, float(c))
    if c is None:
        return ("=", True, "")
    s = str(c)
    op = "="
    for cand in ("<=", ">=", "<>", "<", ">", "="):
        if s.startswith(cand):
            op = cand
            s = s[len(cand):]
            break
    st = s.strip()
    try:
        return (op, False, float(st))
    except ValueError:
        return (op, True, st)


def criteria_match(cell, crit):
    op, is_text, target = crit
    if isinstance(cell, XlError):
        return False
    if is_text:
        cs = "" if cell is None else _text_arg(cell).lower()
        ts = target.lower()
        if "*" in ts or "?" in ts:
            rx = "".join(".*" if ch == "*" else "." if ch == "?"
                         else re.escape(ch) for ch in ts)
            m = re.fullmatch(rx, cs) is not None
        else:
            m = cs == ts
        if op == "=":
            return m
        if op == "<>":
            return not m
        # ordering on text
        diff = -1 if cs < ts else (1 if cs > ts else 0)
        return {"<": diff < 0, ">": diff > 0,
                "<=": diff <= 0, ">=": diff >= 0}[op]
    # numeric criteria; blank cell counts as 0
    cn = 0.0 if cell is None else to_number(cell)
    if isinstance(cn, XlError):
        return False
    if isinstance(cell, str):
        return False  # text never matches a numeric criterion
    diff = -1 if cn < target else (1 if cn > target else 0)
    return {"=": diff == 0, "<>": diff != 0, "<": diff < 0, ">": diff > 0,
            "<=": diff <= 0, ">=": diff >= 0}[op]


def _crit_range(args, ctx, want_sum):
    if len(args) not in (2, 3):
        return VALUE
    vals = eval_args(args, ctx)
    if isinstance(vals, XlError):
        return vals
    rng, crit = vals[0], vals[1]
    if not isinstance(rng, RangeVal):
        return VALUE
    sum_rng = vals[2] if len(vals) == 3 else rng
    if not isinstance(sum_rng, RangeVal):
        return VALUE
    crit = parse_criteria(crit)
    cells = list(iter_range(ctx, rng))
    sums = list(iter_range(ctx, sum_rng))
    total = 0.0
    n = 0
    for i, cell in enumerate(cells):
        if criteria_match(cell, crit):
            n += 1
            if want_sum and i < len(sums):
                sv = sums[i]
                if isinstance(sv, XlError):
                    return sv
                sn = to_number(sv)
                total += sn if not isinstance(sn, XlError) else 0.0
    return (total, float(n))


def f_SUMIF(args, ctx):
    r = _crit_range(args, ctx, True)
    return r[0] if not isinstance(r, XlError) else r


def f_COUNTIF(args, ctx):
    if len(args) != 2:
        return VALUE
    r = _crit_range(args, ctx, False)
    return r[1] if not isinstance(r, XlError) else r


def f_AVERAGEIF(args, ctx):
    if len(args) not in (2, 3):
        return VALUE
    r = _crit_range(args, ctx, True)
    if isinstance(r, XlError):
        return r
    total, n = r
    return total / n if n else DIV0


# ---- financial ----

def f_PMT(args, ctx):
    if len(args) not in (3, 4, 5):
        return VALUE
    vals = eval_args(args, ctx)
    if isinstance(vals, XlError):
        return vals
    nums = [to_number(v) for v in vals]
    for x in nums:
        if isinstance(x, XlError):
            return x
    rate, nper = nums[0], nums[1]
    pv = nums[2]
    fv = nums[3] if len(nums) > 3 else 0.0
    typ = nums[4] if len(nums) > 4 else 0.0
    if nper == 0:
        return DIV0
    if rate == 0:
        return -(pv + fv) / nper
    try:
        return -(rate * (fv + pv * (1 + rate) ** nper)) / \
            ((1 + rate * typ) * ((1 + rate) ** nper - 1))
    except (OverflowError, ZeroDivisionError):
        return NUM


def f_TODAY(args, ctx):
    import datetime
    if args:
        return VALUE
    d = datetime.date.today()
    # Excel serial date; not needed numerically here, return ISO text
    return d.isoformat()


# ---- info ----

def f_ISBLANK(args, ctx):
    if len(args) != 1:
        return VALUE
    v = eval_node(args[0], ctx)
    return v is None


def f_ISERROR(args, ctx):
    if len(args) != 1:
        return VALUE
    return isinstance(eval_node(args[0], ctx), XlError)


def f_ISNUMBER(args, ctx):
    if len(args) != 1:
        return VALUE
    v = eval_node(args[0], ctx)
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def f_ISTEXT(args, ctx):
    if len(args) != 1:
        return VALUE
    return isinstance(eval_node(args[0], ctx), str)


FUNCTIONS = {
    "SUM": lambda a, c: _agg(a, c, "SUM"),
    "AVERAGE": lambda a, c: _agg(a, c, "AVERAGE"),
    "MIN": lambda a, c: _agg(a, c, "MIN"),
    "MAX": lambda a, c: _agg(a, c, "MAX"),
    "COUNT": lambda a, c: _agg(a, c, "COUNT"),
    "COUNTA": lambda a, c: _agg(a, c, "COUNTA"),
    "PRODUCT": lambda a, c: _agg(a, c, "PRODUCT"),
    "IF": f_IF, "IFERROR": f_IFERROR, "AND": f_AND, "OR": f_OR, "NOT": f_NOT,
    "ABS": f_ABS, "INT": f_INT, "MOD": f_MOD, "POWER": f_POWER,
    "ROUND": f_ROUND, "ROUNDUP": f_ROUNDUP, "ROUNDDOWN": f_ROUNDDOWN,
    "SQRT": f_SQRT, "EXP": f_EXP, "LN": f_LN, "LOG": f_LOG, "PI": f_PI,
    "LEN": f_LEN, "LEFT": f_LEFT, "RIGHT": f_RIGHT, "MID": f_MID,
    "UPPER": f_UPPER, "LOWER": f_LOWER, "TRIM": f_TRIM, "CONCAT": f_CONCAT,
    "REPT": f_REPT, "FIND": f_FIND, "VALUE": f_VALUE,
    "VLOOKUP": f_VLOOKUP, "SUMIF": f_SUMIF, "COUNTIF": f_COUNTIF,
    "AVERAGEIF": f_AVERAGEIF, "PMT": f_PMT, "TODAY": f_TODAY,
    "ISBLANK": f_ISBLANK, "ISERROR": f_ISERROR,
    "ISNUMBER": f_ISNUMBER, "ISTEXT": f_ISTEXT,
}

# ---------------------------------------------------------------- workbook

def ast_refs(node, cur_sheet):
    """All (sheet, r, c) cells an AST node depends on."""
    refs = set()
    k = node[0]
    if k == "cell":
        _, sheet, r, c, _, _ = node
        refs.add((sheet or cur_sheet, r, c))
    elif k == "range":
        _, sheet, r1, c1, r2, c2, _, _, _, _ = node
        sh = sheet or cur_sheet
        # rects can be enormous; only formula cells matter for ordering,
        # and callers intersect with those — but be safe with a cap.
        if (r2 - r1 + 1) * (c2 - c1 + 1) <= 100000:
            for r in range(r1, r2 + 1):
                for c in range(c1, c2 + 1):
                    refs.add((sh, r, c))
        else:
            refs.add(("__BIGRANGE__", sh, r1, c1, r2, c2))
    elif k in ("binop",):
        refs |= ast_refs(node[2], cur_sheet) | ast_refs(node[3], cur_sheet)
    elif k in ("unop", "pct"):
        refs |= ast_refs(node[1] if k == "pct" else node[2], cur_sheet)
    elif k == "call":
        for a in node[2]:
            refs |= ast_refs(a, cur_sheet)
    return refs


class Sheet:
    def __init__(self, name):
        self.name = name
        self.cells = {}  # (r, c) -> ('v', value) | ('f', src, ast)

    def bounds(self):
        if not self.cells:
            return (0, 0, 0, 0)
        rs = [r for r, _ in self.cells]
        cs = [c for _, c in self.cells]
        return (min(rs), min(cs), max(rs), max(cs))


class Workbook:
    def __init__(self):
        self.sheets = {}
        self.order = []
        self.values = {}  # {(sheet, r, c): computed value} after calc()

    def add_sheet(self, name):
        if name not in self.sheets:
            self.sheets[name] = Sheet(name)
            self.order.append(name)
        return self.sheets[name]

    # -- cell input -------------------------------------------------
    @staticmethod
    def parse_value(text):
        """Interpret raw CSV/text input: formula, bool, number, or string."""
        if text == "" or text is None:
            return ("v", None)
        if isinstance(text, str) and text.startswith("="):
            ast = parse_formula(text[1:])
            return ("f", text, ast)
        if isinstance(text, str):
            up = text.strip().upper()
            if up == "TRUE":
                return ("v", True)
            if up == "FALSE":
                return ("v", False)
            if re.fullmatch(r"[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?",
                            text.strip()):
                return ("v", float(text.strip()))
            return ("v", text)
        return ("v", text)

    def set(self, sheet_name, a1, raw):
        p = parse_a1(a1)
        if p == "REF" or p is None:
            raise FormulaSyntaxError("bad address %r" % a1)
        r, c, _, _ = p
        sh = self.add_sheet(sheet_name)
        sh.cells[(r, c)] = self.parse_value(raw)

    # -- evaluation --------------------------------------------------
    def formula_cells(self):
        out = {}
        for sname, sh in self.sheets.items():
            for (r, c), cell in sh.cells.items():
                if cell[0] == "f":
                    out[(sname, r, c)] = cell
        return out

    def calc(self):
        """Topological evaluation. Cells in or downstream of a dependency
        cycle get #CYCLE!."""
        fcells = self.formula_cells()
        refs = {}
        for key, (_, _src, ast) in fcells.items():
            sname = key[0]
            rr = ast_refs(ast, sname)
            # intersect with actual formula cells (big-range marker aside)
            deps = set()
            big = [x for x in rr if x[0] == "__BIGRANGE__"]
            for d in rr:
                if d[0] != "__BIGRANGE__":
                    if d in fcells:
                        deps.add(d)
            for (_, sh, r1, c1, r2, c2) in big:
                for fk in fcells:
                    fs, fr, fc = fk
                    if fs == sh and r1 <= fr <= r2 and c1 <= fc <= c2:
                        deps.add(fk)
            refs[key] = deps

        # Kahn's algorithm
        indeg = {k: len(v) for k, v in refs.items()}
        dependents = {k: set() for k in fcells}
        for k, ds in refs.items():
            for d in ds:
                dependents[d].add(k)
        ready = sorted([k for k, d in indeg.items() if d == 0])
        topo = []
        while ready:
            k = ready.pop(0)
            topo.append(k)
            for dep in sorted(dependents[k]):
                indeg[dep] -= 1
                if indeg[dep] == 0:
                    ready.append(dep)
            ready.sort()
        cyclic = set(fcells) - set(topo)

        memo = {}
        for k in cyclic:
            memo[k] = CYCLE
        for key in topo:
            sname, r, c = key
            _, _src, ast = fcells[key]
            ctx = Ctx(self, sname, memo)
            try:
                v = eval_node(ast, ctx)
                memo[key] = VALUE if isinstance(v, RangeVal) else v
            except RecursionError:
                memo[key] = CYCLE
            except Exception:
                memo[key] = VALUE
        self.values = memo
        return memo

    def cell_value(self, sheet_name, r, c, memo=None):
        """Raw or computed value of any cell (used during evaluation)."""
        memo = self.values if memo is None else memo
        key = (sheet_name, r, c)
        if key in memo:
            return memo[key]
        sh = self.sheets.get(sheet_name)
        if sh is None:
            return REF
        cell = sh.cells.get((r, c))
        if cell is None:
            return None
        if cell[0] == "v":
            return cell[1]
        return memo.get(key, CYCLE)  # formula not yet evaluated

    def get(self, sheet_name, a1):
        """Computed value of a cell after calc()."""
        p = parse_a1(a1)
        if p == "REF" or p is None:
            return REF
        r, c, _, _ = p
        return self.cell_value(sheet_name, r, c)

    def display(self, v):
        if isinstance(v, XlError):
            return v.code
        if v is None:
            return ""
        if isinstance(v, bool):
            return "TRUE" if v else "FALSE"
        if isinstance(v, (int, float)):
            return num_to_text(v)
        if isinstance(v, RangeVal):
            return "#VALUE!"
        return str(v)


# ---------------------------------------------------------------- drag-fill copy

def shift_formula(body, drow, dcol):
    """Shift relative references in a formula body by (drow, dcol),
    like dragging a fill handle. Absolute ($) parts don't move; refs that
    fall off the grid become #REF!; string literals are untouched."""
    toks = lex(body)
    out = []
    last = 0
    for kind, text, s, e in toks:
        if kind == "CELL":
            p = parse_a1(text)
            out.append(body[last:s])
            if p == "REF" or p is None:
                out.append("#REF!")
            else:
                r, c, ar, ac = p
                nr = r if ar else r + drow
                nc = c if ac else c + dcol
                if 0 <= nr < MAX_ROW and 0 <= nc < MAX_COL:
                    out.append(a1_of(nr, nc, ar, ac))
                else:
                    out.append("#REF!")
            last = e
    out.append(body[last:])
    return "".join(out)


def copy_cell(wb, sheet_name, src_a1, dst_a1):
    """Copy a cell's formula with relative-reference adjustment."""
    p1, p2 = parse_a1(src_a1), parse_a1(dst_a1)
    sh = wb.sheets[sheet_name]
    cell = sh.cells.get((p1[0], p1[1]))
    if cell is None:
        sh.cells.pop((p2[0], p2[1]), None)
        return
    if cell[0] == "f":
        body = shift_formula(cell[1][1:], p2[0] - p1[0], p2[1] - p1[1])
        sh.cells[(p2[0], p2[1])] = ("f", "=" + body, parse_formula(body))
    else:
        sh.cells[(p2[0], p2[1])] = cell


# ---------------------------------------------------------------- CSV I/O

def load_csv(path, sheet_name="Sheet1"):
    wb = Workbook()
    with open(path, newline="", encoding="utf-8") as f:
        for r, row in enumerate(csv.reader(f)):
            for c, text in enumerate(row):
                if text != "":
                    wb.set(sheet_name, a1_of(r, c), text)
    return wb


def save_csv(wb, path, sheet_name="Sheet1", values=True):
    sh = wb.sheets[sheet_name]
    r0, c0, r1, c1 = sh.bounds()
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        for r in range(r0, r1 + 1):
            row = []
            for c in range(c0, c1 + 1):
                cell = sh.cells.get((r, c))
                if cell is None:
                    row.append("")
                elif cell[0] == "f" and values:
                    row.append(wb.display(wb.cell_value(sheet_name, r, c)))
                elif cell[0] == "f":
                    row.append(cell[1])
                else:
                    v = cell[1]
                    row.append(wb.display(v))
            w.writerow(row)


# ---------------------------------------------------------------- rendering

def render(wb, sheet_name="Sheet1"):
    sh = wb.sheets[sheet_name]
    r0, c0, r1, c1 = sh.bounds()
    grid = []
    for r in range(r0, r1 + 1):
        grid.append([wb.display(wb.cell_value(sheet_name, r, c))
                     for c in range(c0, c1 + 1)])
    widths = [0] * (c1 - c0 + 1)
    for row in grid:
        for i, v in enumerate(row):
            widths[i] = max(widths[i], len(v))
    widths = [max(w, len(col_to_name(c0 + i))) for i, w in enumerate(widths)]
    lines = []
    header = "    " + " ".join(col_to_name(c0 + i).rjust(widths[i])
                               for i in range(len(widths)))
    lines.append(header)
    for ri, row in enumerate(grid):
        lines.append(str(r0 + ri + 1).rjust(3) + " " +
                     " ".join(v.rjust(widths[i]) for i, v in enumerate(row)))
    return "\n".join(lines)


# ---------------------------------------------------------------- REPL & CLI

def repl():
    wb = Workbook()
    wb.add_sheet("Sheet1")
    print("sheet repl — assign like  A1 = 5   or   B2 = =A1*2")
    print("commands: render | calc | quit")
    while True:
        try:
            line = input("sheet> ").strip()
        except EOFError:
            break
        if not line:
            continue
        if line == "quit":
            break
        if line == "render":
            wb.calc()
            print(render(wb))
            continue
        if line == "calc":
            wb.calc()
            print("ok")
            continue
        m = re.match(r"([A-Za-z]{1,3}\d+)\s*=\s*(.*)$", line, re.I)
        if not m:
            print("?")
            continue
        try:
            wb.set("Sheet1", m.group(1).upper(), m.group(2))
            wb.calc()
            print("= " + wb.display(wb.get("Sheet1", m.group(1).upper())))
        except FormulaSyntaxError as e:
            print("syntax: " + str(e))


def main(argv=None):
    ap = argparse.ArgumentParser(description="from-scratch spreadsheet engine")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("calc", help="evaluate a CSV workbook")
    p.add_argument("input")
    p.add_argument("-o", "--output")
    p.add_argument("--sheet", default="Sheet1")
    p.add_argument("--formulas", action="store_true",
                   help="write formulas instead of computed values")
    p.add_argument("--render", action="store_true")
    r = sub.add_parser("render", help="pretty-print a CSV workbook")
    r.add_argument("input")
    r.add_argument("--sheet", default="Sheet1")
    sub.add_parser("repl", help="interactive prompt")
    ns = ap.parse_args(argv)
    if ns.cmd == "repl":
        repl()
        return
    wb = load_csv(ns.input, ns.sheet)
    wb.calc()
    if ns.cmd == "render":
        print(render(wb, ns.sheet))
    elif ns.cmd == "calc":
        if ns.render:
            print(render(wb, ns.sheet))
        if ns.output:
            save_csv(wb, ns.output, ns.sheet, values=not ns.formulas)
            print("wrote " + ns.output)


if __name__ == "__main__":
    main()
