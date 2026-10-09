#!/usr/bin/env python3
"""tinydb: a tiny SQL database engine built from scratch.

Zero dependencies. Implements:
  * pager + B+tree storage (leaf/interior pages, node splits, leaf linked list)
  * type-tagged record codec (NULL / INT / REAL / TEXT)
  * SQL tokenizer + recursive-descent parser
      CREATE TABLE, INSERT INTO ... VALUES, SELECT with
      JOIN / WHERE / GROUP BY / HAVING / ORDER BY / LIMIT / DISTINCT
  * query executor with SQLite-compatible comparison semantics

Stated non-goals: UPDATE / DELETE / DROP, secondary indexes, transactions/WAL,
overflow pages (one record must fit in one 4 KiB page), subqueries, UNION,
foreign keys, ALTER TABLE, built-in scalar functions.
"""

import json
import math
import os
import re
import struct
import sys
from bisect import bisect_left, bisect_right
from functools import cmp_to_key

PAGE_SIZE = 4096
MAGIC = b"TINYDB\x00\x01"          # 8 bytes
LEAF, INTERIOR = 0x01, 0x02
# A node counts as "full" (must be split before descending) when it is this
# close to the page edge AND holds more than one key. Single-key nodes are
# never split (a lone big record is allowed up to the page limit).
SPLIT_MARGIN = 256


class TinyDBError(Exception):
    pass


# ---------------------------------------------------------------------------
# varint + record codec
# ---------------------------------------------------------------------------

def encode_uvarint(n):
    if n < 0:
        raise TinyDBError("varint must be non-negative")
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def decode_uvarint(buf, pos):
    n = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise TinyDBError("truncated varint")
        b = buf[pos]
        pos += 1
        n |= (b & 0x7F) << shift
        if not (b & 0x80):
            return n, pos
        shift += 7
        if shift > 63:
            raise TinyDBError("varint too large")


T_NULL, T_INT, T_REAL, T_TEXT = 0, 1, 2, 3


def encode_record(values):
    """values: list of None/int/float/str -> bytes."""
    out = bytearray()
    out += encode_uvarint(len(values))
    for v in values:
        if v is None:
            out.append(T_NULL)
        elif isinstance(v, bool):
            out.append(T_INT)
            out += struct.pack("<q", int(v))
        elif isinstance(v, int):
            out.append(T_INT)
            try:
                out += struct.pack("<q", v)
            except struct.error:
                raise TinyDBError("integer out of int64 range")
        elif isinstance(v, float):
            out.append(T_REAL)
            out += struct.pack("<d", v)
        elif isinstance(v, str):
            b = v.encode("utf-8")
            out.append(T_TEXT)
            out += encode_uvarint(len(b))
            out += b
        else:
            raise TinyDBError("cannot store value of type %s" % type(v).__name__)
    return bytes(out)


def decode_record(buf):
    ncols, pos = decode_uvarint(buf, 0)
    vals = []
    for _ in range(ncols):
        if pos >= len(buf):
            raise TinyDBError("truncated record")
        tag = buf[pos]
        pos += 1
        if tag == T_NULL:
            vals.append(None)
        elif tag == T_INT:
            vals.append(struct.unpack("<q", buf[pos:pos + 8])[0])
            pos += 8
        elif tag == T_REAL:
            vals.append(struct.unpack("<d", buf[pos:pos + 8])[0])
            pos += 8
        elif tag == T_TEXT:
            ln, pos = decode_uvarint(buf, pos)
            vals.append(buf[pos:pos + ln].decode("utf-8"))
            pos += ln
        else:
            raise TinyDBError("bad value tag %d" % tag)
    return vals


# ---------------------------------------------------------------------------
# pager: page 1 = header + JSON catalog; pages are 1-based
# ---------------------------------------------------------------------------

class Pager:
    def __init__(self, path):
        fresh = not os.path.exists(path)
        self.f = open(path, "r+b" if not fresh else "w+b")
        # lite buffer pool: write-through page cache (single writer, so no
        # invalidation needed). Without it, deep-tree inserts are all disk IO.
        self._cache = {}
        if fresh:
            self.page_count = 1
            self._write_raw(1, b"\x00" * PAGE_SIZE)
            self.save_catalog({"tables": {}})
        else:
            hdr = self._read_raw(1)
            if hdr[:8] != MAGIC:
                raise TinyDBError("not a tinydb file (bad magic)")
            self.page_count = struct.unpack("<I", hdr[8:12])[0]

    def _read_raw(self, pgno):
        self.f.seek((pgno - 1) * PAGE_SIZE)
        data = self.f.read(PAGE_SIZE)
        if len(data) != PAGE_SIZE:
            raise TinyDBError("short read on page %d" % pgno)
        return data

    def _write_raw(self, pgno, data):
        assert len(data) == PAGE_SIZE
        self.f.seek((pgno - 1) * PAGE_SIZE)
        self.f.write(data)
        self.f.flush()

    def read_page(self, pgno):
        if not (1 <= pgno <= self.page_count):
            raise TinyDBError("page %d out of range" % pgno)
        if pgno not in self._cache:
            self._cache[pgno] = self._read_raw(pgno)
        return self._cache[pgno]

    def write_page(self, pgno, data):
        if not (1 <= pgno <= self.page_count):
            raise TinyDBError("page %d out of range" % pgno)
        self._cache[pgno] = data
        self._write_raw(pgno, data)

    def alloc_page(self):
        self.page_count += 1
        n = self.page_count
        blank = b"\x00" * PAGE_SIZE
        self._cache[n] = blank
        self._write_raw(n, blank)
        return n

    def load_catalog(self):
        hdr = self.read_page(1)
        clen = struct.unpack("<I", hdr[12:16])[0]
        raw = hdr[16:16 + clen]
        if len(raw) != clen:
            raise TinyDBError("catalog overruns page 1")
        return json.loads(raw.decode("utf-8"))

    def save_catalog(self, cat):
        raw = json.dumps(cat, separators=(",", ":")).encode("utf-8")
        if len(raw) > PAGE_SIZE - 16:
            raise TinyDBError("catalog too large for page 1")
        hdr = bytearray(PAGE_SIZE)
        hdr[:8] = MAGIC
        struct.pack_into("<I", hdr, 8, self.page_count)
        struct.pack_into("<I", hdr, 12, len(raw))
        hdr[16:16 + len(raw)] = raw
        self.write_page(1, bytes(hdr))

    def close(self):
        self.f.close()


# ---------------------------------------------------------------------------
# B+tree keyed by int64 rowid. Interior nodes use move-up separators;
# leaf separators are copies (right sibling keeps the key).
# ---------------------------------------------------------------------------

class _Node:
    __slots__ = ("leaf", "keys", "children", "payloads", "next_leaf")

    def __init__(self, leaf):
        self.leaf = leaf
        self.keys = []
        self.children = []    # interior only
        self.payloads = []    # leaf only
        self.next_leaf = 0    # leaf only


class BTree:
    def __init__(self, pager, root):
        self.pager = pager
        self.root = root

    # -- serialization ------------------------------------------------------
    def _read(self, pgno):
        raw = self.pager.read_page(pgno)
        t = raw[0]
        if t not in (LEAF, INTERIOR):
            raise TinyDBError("page %d is not a btree node" % pgno)
        n = struct.unpack("<H", raw[1:3])[0]
        node = _Node(t == LEAF)
        if node.leaf:
            node.next_leaf = struct.unpack("<I", raw[3:7])[0]
            pos = 7
            for _ in range(n):
                key = struct.unpack(">q", raw[pos:pos + 8])[0]
                pos += 8
                ln = struct.unpack("<I", raw[pos:pos + 4])[0]
                pos += 4
                node.keys.append(key)
                node.payloads.append(bytes(raw[pos:pos + ln]))
                pos += ln
        else:
            pos = 3
            for _ in range(n):
                key = struct.unpack(">q", raw[pos:pos + 8])[0]
                pos += 8
                child = struct.unpack("<I", raw[pos:pos + 4])[0]
                pos += 4
                node.keys.append(key)
                node.children.append(child)
            node.children.append(struct.unpack("<I", raw[pos:pos + 4])[0])
        return node

    def _write(self, pgno, node):
        out = bytearray()
        out.append(LEAF if node.leaf else INTERIOR)
        out += struct.pack("<H", len(node.keys))
        if node.leaf:
            out += struct.pack("<I", node.next_leaf)
            for k, p in zip(node.keys, node.payloads):
                out += struct.pack(">q", k)
                out += struct.pack("<I", len(p))
                out += p
        else:
            for k, c in zip(node.keys, node.children):
                out += struct.pack(">q", k)
                out += struct.pack("<I", c)
            out += struct.pack("<I", node.children[-1])
        if len(out) > PAGE_SIZE:
            raise TinyDBError("node overruns page")
        out += b"\x00" * (PAGE_SIZE - len(out))
        self.pager.write_page(pgno, bytes(out))

    def _is_full(self, node):
        if len(node.keys) <= 1:
            return False
        # serialize cheaply: fixed part + per-entry size
        if node.leaf:
            size = 7 + sum(12 + len(p) for p in node.payloads)
        else:
            size = 7 + 12 * len(node.keys)
        return size > PAGE_SIZE - SPLIT_MARGIN

    # -- insertion ----------------------------------------------------------
    def insert(self, key, payload):
        if len(payload) + 32 > PAGE_SIZE:
            raise TinyDBError("record too large for one page (no overflow pages)")
        root = self._read(self.root)
        if self._is_full(root):
            new_root_pg = self.pager.alloc_page()
            new_root = _Node(False)
            new_root.children = [self.root]
            self._write(new_root_pg, new_root)
            self._split_child(new_root_pg, 0)
            self.root = new_root_pg
        self._insert_nonfull(self.root, key, payload)

    def _split_child(self, parent_pg, i):
        """Split full child i of parent. Returns (separator_key, child_was_leaf)."""
        parent = self._read(parent_pg)
        cpg = parent.children[i]
        child = self._read(cpg)
        zpg = self.pager.alloc_page()
        right = _Node(child.leaf)
        mid = max(1, len(child.keys) // 2)
        if child.leaf:
            right.keys = child.keys[mid:]
            right.payloads = child.payloads[mid:]
            right.next_leaf = child.next_leaf
            child.keys = child.keys[:mid]
            child.payloads = child.payloads[:mid]
            child.next_leaf = zpg
            sep = right.keys[0]          # copy-up
            was_leaf = True
        else:
            sep = child.keys[mid]        # move-up
            right.keys = child.keys[mid + 1:]
            right.children = child.children[mid + 1:]
            child.keys = child.keys[:mid]
            child.children = child.children[:mid + 1]
            was_leaf = False
        self._write(cpg, child)
        self._write(zpg, right)
        parent.keys.insert(i, sep)
        parent.children.insert(i + 1, zpg)
        self._write(parent_pg, parent)
        return sep, was_leaf

    def _insert_nonfull(self, pgno, key, payload):
        node = self._read(pgno)
        if node.leaf:
            i = bisect_left(node.keys, key)
            if i < len(node.keys) and node.keys[i] == key:
                node.payloads[i] = payload      # upsert (rowids are unique anyway)
            else:
                node.keys.insert(i, key)
                node.payloads.insert(i, payload)
            self._write(pgno, node)
            return
        i = bisect_right(node.keys, key)
        child = self._read(node.children[i])
        if self._is_full(child):
            sep, was_leaf = self._split_child(pgno, i)
            node = self._read(pgno)             # parent changed
            # leaf splits copy the separator up: equal keys live on the right.
            # interior splits move it up: the key cannot equal sep (unique keys).
            if (was_leaf and key >= sep) or (not was_leaf and key > sep):
                i += 1
        self._insert_nonfull(node.children[i], key, payload)

    # -- lookup + scan ------------------------------------------------------
    def find(self, key):
        pgno = self.root
        while True:
            node = self._read(pgno)
            if node.leaf:
                i = bisect_left(node.keys, key)
                if i < len(node.keys) and node.keys[i] == key:
                    return node.payloads[i]
                return None
            pgno = node.children[bisect_right(node.keys, key)]

    def scan(self):
        """Yield (key, payload) in key order via the leaf linked list."""
        pgno = self.root
        while True:                             # descend to leftmost leaf
            node = self._read(pgno)
            if node.leaf:
                break
            pgno = node.children[0]
        while pgno:
            node = self._read(pgno)
            for k, p in zip(node.keys, node.payloads):
                yield k, p
            pgno = node.next_leaf

    def count(self):
        return sum(1 for _ in self.scan())


# ---------------------------------------------------------------------------
# SQL tokenizer + recursive-descent parser -> AST
# ---------------------------------------------------------------------------

KEYWORDS = {
    "select", "from", "where", "group", "by", "order", "having", "limit",
    "distinct", "as", "join", "inner", "on", "and", "or", "not", "null",
    "create", "table", "insert", "into", "values", "like", "is",
    "count", "sum", "avg", "min", "max", "integer", "real", "text",
    "true", "false", "asc", "desc",
}

_TOKEN_RE = re.compile(r"""
      (?P<ws>\s+)
    | (?P<comment>--[^\n]*)
    | (?P<string>'(?:[^']|'')*')
    | (?P<number>(?:\d+\.\d*|\.\d+|\d+)(?:[eE][+-]?\d+)?)
    | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
    | (?P<op><>|!=|<=|>=|=|<|>|\+|-|\*|/|%|,|;|\(|\)|\.)
""", re.VERBOSE)


class _Tok:
    __slots__ = ("kind", "text")

    def __init__(self, kind, text):
        self.kind = kind      # 'kw', 'ident', 'string', 'number', 'op', 'eof'
        self.text = text

    def __repr__(self):
        return "Tok(%s,%r)" % (self.kind, self.text)


def tokenize(sql):
    toks = []
    for m in _TOKEN_RE.finditer(sql):
        kind = m.lastgroup
        text = m.group()
        if kind in ("ws", "comment"):
            continue
        if kind == "ident" and text.lower() in KEYWORDS:
            toks.append(_Tok("kw", text.lower()))
        elif kind == "ident":
            toks.append(_Tok("ident", text))
        elif kind == "string":
            toks.append(_Tok("string", text[1:-1].replace("''", "'")))
        elif kind == "number":
            toks.append(_Tok("number", text))
        else:
            toks.append(_Tok("op", text))
    toks.append(_Tok("eof", ""))
    return toks


# -- AST nodes ---------------------------------------------------------------
class _Lit:
    __slots__ = ("value",)

    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "Lit(%r)" % (self.value,)


class _Col:
    __slots__ = ("table", "name")

    def __init__(self, table, name):
        self.table = table      # alias or None
        self.name = name

    def __repr__(self):
        return "Col(%s.%s)" % (self.table, self.name)


class _BinOp:
    __slots__ = ("op", "l", "r")

    def __init__(self, op, l, r):
        self.op = op
        self.l = l
        self.r = r


class _UnOp:
    __slots__ = ("op", "e")

    def __init__(self, op, e):
        self.op = op
        self.e = e


class _Agg:
    __slots__ = ("func", "arg", "star")

    def __init__(self, func, arg, star=False):
        self.func = func        # count/sum/avg/min/max
        self.arg = arg
        self.star = star


class _Like:
    __slots__ = ("e", "pat", "neg")

    def __init__(self, e, pat, neg):
        self.e = e
        self.pat = pat
        self.neg = neg


class _IsNull:
    __slots__ = ("e", "neg")

    def __init__(self, e, neg):
        self.e = e
        self.neg = neg


class _Star:
    __slots__ = ("table",)

    def __init__(self, table=None):
        self.table = table


class _Create:
    def __init__(self, name, columns):
        self.name = name
        self.columns = columns   # [(name, type)]


class _Insert:
    def __init__(self, table, columns, rows):
        self.table = table
        self.columns = columns   # [name] or None
        self.rows = rows         # [[expr]]


class _Select:
    def __init__(self, distinct, items, from_, joins, where,
                 group_by, having, order_by, limit):
        self.distinct = distinct
        self.items = items       # [(expr|_Star, alias)]
        self.from_ = from_       # [(table, alias)]
        self.joins = joins       # [(table, alias, on_expr)]
        self.where = where
        self.group_by = group_by
        self.having = having
        self.order_by = order_by  # [(expr, desc)]
        self.limit = limit


class _Parser:
    def __init__(self, toks):
        self.toks = toks
        self.pos = 0

    def peek(self):
        return self.toks[self.pos]

    def next(self):
        t = self.toks[self.pos]
        self.pos += 1
        return t

    def at_kw(self, *words):
        t = self.peek()
        return t.kind == "kw" and t.text in words

    def at_op(self, *ops):
        t = self.peek()
        return t.kind == "op" and t.text in ops

    def expect_kw(self, *words):
        t = self.next()
        if not (t.kind == "kw" and t.text in words):
            raise TinyDBError("expected %s, got %r" % ("/".join(words), t.text))
        return t

    def expect_op(self, *ops):
        t = self.next()
        if not (t.kind == "op" and t.text in ops):
            raise TinyDBError("expected %s, got %r" % ("/".join(ops), t.text))
        return t

    def expect_ident(self):
        t = self.next()
        if t.kind != "ident":
            raise TinyDBError("expected identifier, got %r" % t.text)
        return t.text.lower()

    # -- entry -------------------------------------------------------------
    def parse_statement(self):
        if self.at_kw("select"):
            return self.parse_select()
        if self.at_kw("create"):
            return self.parse_create()
        if self.at_kw("insert"):
            return self.parse_insert()
        raise TinyDBError("unsupported statement near %r" % self.peek().text)

    def parse_create(self):
        self.expect_kw("create")
        self.expect_kw("table")
        name = self.expect_ident()
        self.expect_op("(")
        cols = []
        while True:
            cname = self.expect_ident()
            ctype = self.expect_kw("integer", "real", "text").text
            cols.append((cname, ctype))
            if self.at_op(","):
                self.next()
                continue
            break
        self.expect_op(")")
        return _Create(name, cols)

    def parse_insert(self):
        self.expect_kw("insert")
        self.expect_kw("into")
        table = self.expect_ident()
        columns = None
        if self.at_op("("):
            # '(' directly after the table name is always a column list
            self.next()
            columns = [self.expect_ident()]
            while self.at_op(","):
                self.next()
                columns.append(self.expect_ident())
            self.expect_op(")")
        self.expect_kw("values")
        rows = []
        while True:
            self.expect_op("(")
            row = [self.parse_expr()]
            while self.at_op(","):
                self.next()
                row.append(self.parse_expr())
            self.expect_op(")")
            rows.append(row)
            if self.at_op(","):
                self.next()
                continue
            break
        return _Insert(table, columns, rows)

    # -- SELECT ------------------------------------------------------------
    def parse_select(self):
        self.expect_kw("select")
        distinct = False
        if self.at_kw("distinct"):
            self.next()
            distinct = True
        items = self.parse_select_list()
        from_ = []
        if self.at_kw("from"):
            self.next()
            from_.append(self.parse_table_ref())
        joins = []
        while self.at_kw("join", "inner"):
            if self.at_kw("inner"):
                self.next()
            self.expect_kw("join")
            t, a = self.parse_table_ref()
            self.expect_kw("on")
            joins.append((t, a, self.parse_expr()))
        where = self.parse_expr() if self.at_kw("where") and self.next() else None
        group_by = []
        if self.at_kw("group"):
            self.next()
            self.expect_kw("by")
            group_by = [self.parse_expr()]
            while self.at_op(","):
                self.next()
                group_by.append(self.parse_expr())
        having = self.parse_expr() if self.at_kw("having") and self.next() else None
        order_by = []
        if self.at_kw("order"):
            self.next()
            self.expect_kw("by")
            while True:
                e = self.parse_expr()
                desc = False
                if self.at_kw("desc", "asc"):
                    desc = self.next().text == "desc"
                order_by.append((e, desc))
                if self.at_op(","):
                    self.next()
                    continue
                break
        limit = None
        if self.at_kw("limit"):
            self.next()
            t = self.next()
            if t.kind != "number":
                raise TinyDBError("LIMIT needs a number")
            limit = int(float(t.text))
        return _Select(distinct, items, from_, joins, where,
                       group_by, having, order_by, limit)

    def parse_table_ref(self):
        table = self.expect_ident()
        alias = table
        if self.at_kw("as"):
            self.next()
            alias = self.expect_ident()
        elif self.peek().kind == "ident":
            alias = self.expect_ident()
        return table, alias

    def parse_select_list(self):
        items = []
        while True:
            if self.at_op("*"):
                self.next()
                items.append((_Star(), None))
            else:
                # table.* ?
                if (self.peek().kind == "ident" and
                        self.pos + 1 < len(self.toks) and
                        self.toks[self.pos + 1].kind == "op" and
                        self.toks[self.pos + 1].text == "." and
                        self.pos + 2 < len(self.toks) and
                        self.toks[self.pos + 2].kind == "op" and
                        self.toks[self.pos + 2].text == "*"):
                    tname = self.expect_ident()
                    self.expect_op(".")
                    self.expect_op("*")
                    items.append((_Star(tname), None))
                else:
                    e = self.parse_expr()
                    alias = None
                    if self.at_kw("as"):
                        self.next()
                        alias = self.expect_ident()
                    elif self.peek().kind == "ident":
                        # bare alias (but not a keyword; idents can't be keywords)
                        alias = self.expect_ident()
                    items.append((e, alias))
            if self.at_op(","):
                self.next()
                continue
            break
        return items

    # -- expressions (precedence climbing) ----------------------------------
    def parse_expr(self):
        return self.parse_or()

    def parse_or(self):
        e = self.parse_and()
        while self.at_kw("or"):
            self.next()
            e = _BinOp("or", e, self.parse_and())
        return e

    def parse_and(self):
        e = self.parse_not()
        while self.at_kw("and"):
            self.next()
            e = _BinOp("and", e, self.parse_not())
        return e

    def parse_not(self):
        if self.at_kw("not"):
            self.next()
            return _UnOp("not", self.parse_not())
        return self.parse_comparison()

    def parse_comparison(self):
        e = self.parse_add()
        while True:
            if self.at_op("=", "<>", "!=", "<", "<=", ">", ">="):
                op = self.next().text
                if op == "!=":
                    op = "<>"
                e = _BinOp(op, e, self.parse_add())
            elif self.at_kw("is"):
                self.next()
                neg = False
                if self.at_kw("not"):
                    self.next()
                    neg = True
                self.expect_kw("null")
                e = _IsNull(e, neg)
            elif self.at_kw("like") or (self.at_kw("not") and self._peek2_kw("like")):
                neg = False
                if self.at_kw("not"):
                    self.next()
                    neg = True
                self.expect_kw("like")
                e = _Like(e, self.parse_add(), neg)
            else:
                return e

    def _peek2_kw(self, word):
        return (self.pos + 1 < len(self.toks) and
                self.toks[self.pos + 1].kind == "kw" and
                self.toks[self.pos + 1].text == word)

    def parse_add(self):
        e = self.parse_mul()
        while self.at_op("+", "-"):
            op = self.next().text
            e = _BinOp(op, e, self.parse_mul())
        return e

    def parse_mul(self):
        e = self.parse_unary()
        while self.at_op("*", "/", "%"):
            op = self.next().text
            e = _BinOp(op, e, self.parse_unary())
        return e

    def parse_unary(self):
        if self.at_op("-", "+"):
            op = self.next().text
            return _UnOp(op, self.parse_unary())
        return self.parse_primary()

    def parse_primary(self):
        t = self.peek()
        if t.kind == "number":
            self.next()
            return _Lit(float(t.text) if ("." in t.text or "e" in t.text.lower())
                        else int(t.text))
        if t.kind == "string":
            self.next()
            return _Lit(t.text)
        if t.kind == "kw" and t.text in ("null", "true", "false"):
            self.next()
            return _Lit({"null": None, "true": 1, "false": 0}[t.text])
        if t.kind == "kw" and t.text in ("count", "sum", "avg", "min", "max"):
            return self.parse_agg()
        if t.kind == "op" and t.text == "(":
            self.next()
            e = self.parse_expr()
            self.expect_op(")")
            return e
        if t.kind == "ident":
            name = self.expect_ident()
            if self.at_op("."):
                self.next()
                col = self.expect_ident()
                return _Col(name, col)
            return _Col(None, name)
        raise TinyDBError("unexpected %r in expression" % t.text)

    def parse_agg(self):
        func = self.next().text
        self.expect_op("(")
        if self.at_op("*"):
            self.next()
            self.expect_op(")")
            if func != "count":
                raise TinyDBError("%s(*) not supported" % func)
            return _Agg(func, None, star=True)
        arg = self.parse_expr()
        self.expect_op(")")
        return _Agg(func, arg)


def parse(sql):
    toks = tokenize(sql)
    p = _Parser(toks)
    stmt = p.parse_statement()
    if p.peek().kind != "eof":
        raise TinyDBError("trailing tokens after statement: %r" % p.peek().text)
    return stmt


# ---------------------------------------------------------------------------
# expression evaluation — SQLite-compatible semantics
# ---------------------------------------------------------------------------

def _is_num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def sql_compare(a, b):
    """Three-way compare: NULL < numbers < text (SQLite ordering)."""
    if a is None and b is None:
        return 0
    if a is None:
        return -1
    if b is None:
        return 1
    an, bn = _is_num(a), _is_num(b)
    if an and bn:
        return (a > b) - (a < b)
    if isinstance(a, str) and isinstance(b, str):
        return (a > b) - (a < b)
    return -1 if an else 1   # numbers sort before text


def sql_eq(a, b):
    if a is None or b is None:
        return None
    if _is_num(a) and _is_num(b):
        return a == b
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    return False


def _kleen_and(a, b):
    if a is False or b is False:
        return False
    if a is None or b is None:
        return None
    return True


def _kleen_or(a, b):
    if a is True or b is True:
        return True
    if a is None or b is None:
        return None
    return False


def _kleen_not(a):
    return None if a is None else (not a)


def _is_true(v):
    return v is True


def _like_regex(pat):
    out = []
    for ch in pat:
        if ch == "%":
            out.append(".*")
        elif ch == "_":
            out.append(".")
        else:
            out.append(re.escape(ch))
    # SQLite LIKE is case-insensitive (ASCII); IGNORECASE is the close stdlib match
    return re.compile("".join(out) + r"\Z", re.DOTALL | re.IGNORECASE)


def _arith(op, a, b):
    if a is None or b is None:
        return None
    if not (_is_num(a) and _is_num(b)):
        raise TinyDBError("arithmetic on non-numeric values")
    if op == "+":
        return a + b
    if op == "-":
        return a - b
    if op == "*":
        return a * b
    if op == "/":
        if b == 0:
            return None
        return a / b
    if op == "%":
        if b == 0:
            return None
        r = math.fmod(a, b)
        # keep int when both operands were ints (matches SQLite for positives)
        if isinstance(a, int) and isinstance(b, int):
            r = int(r)
        return r
    raise TinyDBError("bad arithmetic op " + op)


def _resolve_col(table, name, row):
    if table is not None:
        key = (table, name)
        if key in row:
            return row[key]
        raise TinyDBError("no such column: %s.%s" % (table, name))
    # (None, name) keys come from the ORDER BY output namespace and shadow
    # real columns of the same name
    if (None, name) in row:
        return row[(None, name)]
    cands = [k for k in row if k[1] == name]
    if not cands:
        raise TinyDBError("no such column: %s" % name)
    if len(cands) > 1:
        raise TinyDBError("ambiguous column name: %s" % name)
    return row[cands[0]]


def eval_expr(e, row):
    """row: {(alias, colname): value}. Returns None/int/float/str/bool."""
    if isinstance(e, _Lit):
        return e.value
    if isinstance(e, _Col):
        return _resolve_col(e.table, e.name, row)
    if isinstance(e, _UnOp):
        v = eval_expr(e.e, row)
        if e.op == "not":
            return _kleen_not(v)
        if v is None:
            return None
        if e.op == "-":
            if not _is_num(v):
                raise TinyDBError("unary minus on non-numeric")
            return -v
        return v  # unary plus
    if isinstance(e, _BinOp):
        if e.op == "and":
            return _kleen_and(eval_expr(e.l, row), eval_expr(e.r, row))
        if e.op == "or":
            return _kleen_or(eval_expr(e.l, row), eval_expr(e.r, row))
        if e.op in ("+", "-", "*", "/", "%"):
            return _arith(e.op, eval_expr(e.l, row), eval_expr(e.r, row))
        if e.op == "=":
            return sql_eq(eval_expr(e.l, row), eval_expr(e.r, row))
        if e.op == "<>":
            r = sql_eq(eval_expr(e.l, row), eval_expr(e.r, row))
            return None if r is None else (not r)
        # ordering comparisons: NULL operand -> NULL
        a = eval_expr(e.l, row)
        b = eval_expr(e.r, row)
        if a is None or b is None:
            return None
        c = sql_compare(a, b)
        return {"<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0}[e.op]
    if isinstance(e, _Like):
        a = eval_expr(e.e, row)
        p = eval_expr(e.pat, row)
        if a is None or p is None:
            return None
        if not isinstance(a, str) or not isinstance(p, str):
            raise TinyDBError("LIKE needs text operands")
        m = _like_regex(p).match(a) is not None
        return (not m) if e.neg else m
    if isinstance(e, _IsNull):
        v = eval_expr(e.e, row)
        return (v is not None) if e.neg else (v is None)
    if isinstance(e, _Agg):
        raise TinyDBError("aggregate not allowed here")
    raise TinyDBError("cannot evaluate %r" % e)


def _has_agg(e):
    if isinstance(e, _Agg):
        return True
    if isinstance(e, (_BinOp,)):
        return _has_agg(e.l) or _has_agg(e.r)
    if isinstance(e, _UnOp):
        return _has_agg(e.e)
    if isinstance(e, _Like):
        return _has_agg(e.e) or _has_agg(e.pat)
    if isinstance(e, _IsNull):
        return _has_agg(e.e)
    return False


def _agg_value(agg, rows):
    f = agg.func
    if agg.star:
        return len(rows)
    vals = [eval_expr(agg.arg, r) for r in rows]
    vals = [v for v in vals if v is not None]
    if f == "count":
        return len(vals)
    if not vals:
        return None
    if f == "sum":
        s = vals[0]
        for v in vals[1:]:
            s = _arith("+", s, v)
        return s
    if f == "avg":
        s = vals[0]
        for v in vals[1:]:
            s = _arith("+", s, v)
        return s / len(vals)
    if f == "min":
        m = vals[0]
        for v in vals[1:]:
            if sql_compare(v, m) < 0:
                m = v
        return m
    if f == "max":
        m = vals[0]
        for v in vals[1:]:
            if sql_compare(v, m) > 0:
                m = v
        return m
    raise TinyDBError("bad aggregate " + f)


def _subst_agg(e, rows):
    """Replace aggregate nodes with their computed literal values."""
    if isinstance(e, _Agg):
        return _Lit(_agg_value(e, rows))
    if isinstance(e, _BinOp):
        return _BinOp(e.op, _subst_agg(e.l, rows), _subst_agg(e.r, rows))
    if isinstance(e, _UnOp):
        return _UnOp(e.op, _subst_agg(e.e, rows))
    if isinstance(e, _Like):
        return _Like(_subst_agg(e.e, rows), _subst_agg(e.pat, rows), e.neg)
    if isinstance(e, _IsNull):
        return _IsNull(_subst_agg(e.e, rows), e.neg)
    return e


def _expr_key(e):
    return repr(e)


def _default_name(e):
    if isinstance(e, _Col):
        return e.name
    if isinstance(e, _Agg):
        inner = "*" if e.star else _default_name(e.arg)
        return "%s(%s)" % (e.func, inner)
    if isinstance(e, _Lit):
        return repr(e.value)
    return "expr"


# ---------------------------------------------------------------------------
# tables + database facade
# ---------------------------------------------------------------------------

class _Table:
    def __init__(self, pager, name, columns, root, next_rowid):
        self.pager = pager
        self.name = name
        self.columns = columns          # [(name, type)]
        self.btree = BTree(pager, root)
        self.root = root
        self.next_rowid = next_rowid

    def col_index(self, name):
        for i, (cn, _) in enumerate(self.columns):
            if cn == name:
                return i
        raise TinyDBError("no such column: %s.%s" % (self.name, name))


class Database:
    def __init__(self, path):
        self.pager = Pager(path)
        self._load()

    def _load(self):
        cat = self.pager.load_catalog()
        self.tables = {}
        for name, meta in cat["tables"].items():
            self.tables[name] = _Table(
                self.pager, name, [tuple(c) for c in meta["columns"]],
                meta["root"], meta["next_rowid"])

    def _save(self):
        cat = {"tables": {}}
        for name, t in self.tables.items():
            if t.btree.root != t.root:
                t.root = t.btree.root
            cat["tables"][name] = {
                "columns": [list(c) for c in t.columns],
                "root": t.root,
                "next_rowid": t.next_rowid,
            }
        self.pager.save_catalog(cat)

    def close(self):
        self._save()
        self.pager.close()

    # -- DDL/DML -----------------------------------------------------------
    def create_table(self, name, columns):
        if name in self.tables:
            raise TinyDBError("table %s already exists" % name)
        seen = set()
        for cn, _ in columns:
            if cn in seen:
                raise TinyDBError("duplicate column name: %s" % cn)
            seen.add(cn)
        root = self.pager.alloc_page()
        self.pager.write_page(root, self._empty_leaf())
        self.tables[name] = _Table(self.pager, name, columns, root, 1)
        self._save()

    def _empty_leaf(self):
        out = bytearray()
        out.append(LEAF)
        out += struct.pack("<H", 0)
        out += struct.pack("<I", 0)   # next_leaf = none
        out += b"\x00" * (PAGE_SIZE - len(out))
        return bytes(out)

    def insert(self, table_name, columns, rows):
        t = self.tables.get(table_name)
        if t is None:
            raise TinyDBError("no such table: %s" % table_name)
        if columns is None:
            columns = [cn for cn, _ in t.columns]
        idx = [t.col_index(c) for c in columns]
        n = 0
        for row_exprs in rows:
            if len(row_exprs) != len(idx):
                raise TinyDBError("INSERT arity mismatch: %d values for %d columns"
                                  % (len(row_exprs), len(idx)))
            vals = [None] * len(t.columns)
            for j, e in zip(idx, row_exprs):
                vals[j] = eval_expr(e, {})
            t.btree.insert(t.next_rowid, encode_record(vals))
            t.next_rowid += 1
            n += 1
        self._save()
        return n

    # -- SELECT ------------------------------------------------------------
    def _table_rows(self, tname, alias):
        t = self.tables.get(tname)
        if t is None:
            raise TinyDBError("no such table: %s" % tname)
        out = []
        for rowid, payload in t.btree.scan():
            vals = decode_record(payload)
            row = {}
            for (cn, _), v in zip(t.columns, vals):
                row[(alias, cn)] = v
            row[(alias, "_rowid_")] = rowid
            out.append(row)
        return out, [(alias, cn) for cn, _ in t.columns]

    def select(self, sel):
        # FROM (cross join across entries) then JOINs
        rows = [{}]
        scope = []   # [(alias, [colnames])]
        for tname, alias in sel.from_:
            trows, tcols = self._table_rows(tname, alias)
            scope.append((alias, [c for _, c in tcols]))
            rows = [{**r, **tr} for r in rows for tr in trows]
        for tname, alias, on in sel.joins:
            trows, tcols = self._table_rows(tname, alias)
            scope.append((alias, [c for _, c in tcols]))
            joined = []
            for r in rows:
                for tr in trows:
                    m = {**r, **tr}
                    if _is_true(eval_expr(on, m)):
                        joined.append(m)
            rows = joined

        if sel.where is not None:
            rows = [r for r in rows if _is_true(eval_expr(sel.where, r))]

        # expand SELECT list (stars)
        items = []
        for e, alias in sel.items:
            if isinstance(e, _Star):
                if e.table is None:
                    for al, cols in scope:
                        for cn in cols:
                            items.append((_Col(al, cn), cn))
                else:
                    hit = [cols for al, cols in scope if al == e.table]
                    if not hit:
                        raise TinyDBError("no such table/alias in *: %s" % e.table)
                    for cn in hit[0]:
                        items.append((_Col(e.table, cn), cn))
            else:
                items.append((e, alias or _default_name(e)))

        grouped = bool(sel.group_by) or any(_has_agg(e) for e, _ in items) \
            or (sel.having is not None and _has_agg(sel.having))

        out_names = [a for _, a in items]
        out_rows = []

        # SQLite surfaces boolean results as 1/0, not true/false
        def outv(v):
            return int(v) if isinstance(v, bool) else v

        if grouped:
            groups = {}
            gorder = []
            for r in rows:
                key = tuple(eval_expr(g, r) for g in sel.group_by)
                if key not in groups:
                    groups[key] = []
                    gorder.append(key)
                groups[key].append(r)
            if not sel.group_by and not rows:
                groups[()] = []
                gorder = [()]
            for key in gorder:
                grows = groups[key]
                first = grows[0] if grows else {}
                keyenv = {}
                for g, v in zip(sel.group_by, key):
                    keyenv[_expr_key(g)] = v

                def gval(e):
                    e2 = _subst_agg(e, grows)
                    if isinstance(e2, _Col) and _expr_key(e) in keyenv:
                        return keyenv[_expr_key(e)]
                    return eval_expr(e2, first)

                if sel.having is not None and not _is_true(gval(sel.having)):
                    continue
                out_rows.append(tuple(outv(gval(e)) for e, _ in items))
        else:
            for r in rows:
                out_rows.append(tuple(outv(eval_expr(e, r)) for e, _ in items))

        if sel.distinct:
            seen = set()
            ded = []
            for row in out_rows:
                if row not in seen:
                    seen.add(row)
                    ded.append(row)
            out_rows = ded

        if sel.order_by:
            # ORDER BY namespace: output names shadow input columns
            pairs = list(zip(out_rows, rows)) if not grouped \
                else [(out, {}) for out in out_rows]
            for e, desc in reversed(sel.order_by):
                keyed = []
                for out, r in pairs:
                    ns = dict(zip(out_names, out))
                    v = eval_expr(e, _ns_row(ns, r))
                    keyed.append((self._skey(v), out, r))
                keyed.sort(key=lambda t: t[0], reverse=desc)
                pairs = [(o, r) for _, o, r in keyed]
            out_rows = [o for o, _ in pairs]

        if sel.limit is not None:
            out_rows = out_rows[:sel.limit]
        return out_names, out_rows

    @staticmethod
    def _skey(v):
        if v is None:
            return (0, 0, "")
        if _is_num(v):
            return (1, float(v), "")
        if isinstance(v, str):
            return (2, 0, v)
        return (2, 0, repr(v))

    # -- dispatch ----------------------------------------------------------
    def execute(self, sql):
        stmt = parse(sql)
        if isinstance(stmt, _Create):
            self.create_table(stmt.name, stmt.columns)
            return ["status"], [("table %s created" % stmt.name,)]
        if isinstance(stmt, _Insert):
            n = self.insert(stmt.table, stmt.columns, stmt.rows)
            return ["rows_inserted"], [(n,)]
        if isinstance(stmt, _Select):
            return self.select(stmt)
        raise TinyDBError("cannot execute %r" % stmt)


def _ns_row(ns, row):
    """Row-like dict: output names (keyed (None, name)) shadow input columns."""
    m = dict(row)
    for name, v in ns.items():
        m[(None, name)] = v
    return m


def main(argv):
    if len(argv) != 3:
        print("usage: tinydb.py <file.db> \"SQL\"", file=sys.stderr)
        return 2
    db = Database(argv[1])
    try:
        cols, rows = db.execute(argv[2])
    finally:
        db.close()
    print("\t".join(cols))
    for r in rows:
        print("\t".join("" if v is None else str(v) for v in r))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
