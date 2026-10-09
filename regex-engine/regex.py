#!/usr/bin/env python3
"""refox regex engine: regular expressions from scratch.

Three phases, zero use of the `re` module:
  1. Recursive-descent parser: pattern text -> AST.
  2. Thompson NFA construction: AST -> epsilon-NFA (fragment patching).
  3. Pike-VM-style simulation with explicit backtracking-priority tracking,
     so greedy/lazy quantifiers and alternation order match PCRE-ish
     leftmost-first semantics, including capture groups.

Supported syntax:
  literals, escapes, . \\d \\D \\w \\W \\s \\S \\b \\B \\n \\t \\r \\xHH,
  [abc] [a-z] [^...] (escapes and ranges inside), ^ $, * + ? {n} {n,} {n,m}
  and lazy *? +? ?? {n,m}?, (group) (?:group), alternation a|b.

Deliberate gaps (named, not hidden): no backreferences (not regular),
no lookahead/lookbehind, no named groups, no MULTILINE/DOTALL flags,
$ does not match before a trailing newline.
"""

import sys as _sys
# Epsilon-closure is recursive; pathological nested patterns can exceed the
# default 1000-frame limit. This is a triage tool, not a hardened library.
_sys.setrecursionlimit(10000)


class RegexError(Exception):
    pass


# ---------------------------------------------------------------------------
# 1. Parser: pattern -> AST (nested tuples)
# ---------------------------------------------------------------------------

_DIGITS = frozenset("0123456789")
_WORD = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
_SPACE = frozenset(" \t\n\r\f\v")
_SIMPLE_ESC = {"n": "\n", "t": "\t", "r": "\r", "f": "\f", "v": "\v",
               "a": "\a", "\\": "\\"}


class _Parser:
    def __init__(self, pattern):
        self.p = pattern
        self.i = 0
        self.ngroups = 0

    def peek(self):
        return self.p[self.i] if self.i < len(self.p) else ""

    def parse(self):
        node = self._alt()
        if self.i != len(self.p):
            raise RegexError("unexpected %r at index %d" % (self.peek(), self.i))
        return node

    def _alt(self):  # alt := seq ('|' seq)*
        branches = [self._seq()]
        while self.peek() == "|":
            self.i += 1
            branches.append(self._seq())
        return ("alt", branches) if len(branches) > 1 else branches[0]

    def _seq(self):  # seq := piece*  (stops at '|' or ')' or end)
        items = []
        while self.i < len(self.p) and self.peek() not in ")|":
            items.append(self._piece())
        return ("seq", items)

    def _piece(self):  # piece := atom quant?
        atom = self._atom()
        q = self._quant()
        if q is not None:
            lo, hi, greedy = q
            return ("rep", atom, lo, hi, greedy)
        return atom

    def _quant(self):
        c = self.peek()
        if c == "*":
            self.i += 1
            return (0, None, not self._lazy())
        if c == "+":
            self.i += 1
            return (1, None, not self._lazy())
        if c == "?":
            self.i += 1
            return (0, 1, not self._lazy())
        if c == "{":
            j = self.i + 1
            digits = ""
            while j < len(self.p) and self.p[j].isdigit():
                digits += self.p[j]
                j += 1
            if not digits:
                return None  # literal '{'
            lo = int(digits)
            hi = lo
            if j < len(self.p) and self.p[j] == ",":
                j += 1
                digits = ""
                while j < len(self.p) and self.p[j].isdigit():
                    digits += self.p[j]
                    j += 1
                hi = int(digits) if digits else None
            if j >= len(self.p) or self.p[j] != "}":
                return None  # malformed: literal '{'
            if hi is not None and hi < lo:
                raise RegexError("min repeat greater than max repeat")
            self.i = j + 1
            return (lo, hi, not self._lazy())
        return None

    def _lazy(self):
        if self.peek() == "?":
            self.i += 1
            return True
        return False

    def _atom(self):
        c = self.peek()
        if c == "(":
            return self._group()
        if c == "[":
            return self._class()
        if c == ".":
            self.i += 1
            return ("dot",)
        if c == "^":
            self.i += 1
            return ("assert", "start")
        if c == "$":
            self.i += 1
            return ("assert", "end")
        if c == "\\":
            return self._escape(in_class=False)
        if c in "*+?{|":
            raise RegexError("nothing to repeat / unexpected %r" % c)
        if c == "":
            raise RegexError("unexpected end of pattern")
        self.i += 1
        return ("lit", c)

    def _group(self):
        self.i += 1  # consume '('
        if self.p[self.i:self.i + 2] == "?:":
            self.i += 2
            node = self._alt()
            if self.peek() != ")":
                raise RegexError("unbalanced '('")
            self.i += 1
            return ("seq", [node]) if node[0] != "seq" else node
        self.ngroups += 1
        n = self.ngroups
        node = self._alt()
        if self.peek() != ")":
            raise RegexError("unbalanced '('")
        self.i += 1
        return ("grp", n, node)

    def _class(self):
        self.i += 1  # consume '['
        neg = False
        if self.peek() == "^":
            neg = True
            self.i += 1
        parts = []  # list of (frozenset, is_neg)
        if self.peek() == "]":  # leading ']' is literal
            parts.append((frozenset("]"), False))
            self.i += 1
        while True:
            c = self.peek()
            if c == "":
                raise RegexError("unbalanced '['")
            if c == "]":
                self.i += 1
                break
            if c == "\\":
                tset, tneg, single = self._class_escape()
            else:
                self.i += 1
                tset, tneg, single = frozenset(c), False, c
            # range?  X-Y  (only between two single literal chars)
            if (single is not None and not tneg and self.peek() == "-"
                    and self.i < len(self.p) and self.p[self.i + 1] != "]"):
                self.i += 1
                c2 = self.peek()
                if c2 == "\\":
                    s2, n2, single2 = self._class_escape()
                else:
                    self.i += 1
                    s2, n2, single2 = frozenset(c2), False, c2
                if single2 is not None and not n2:
                    a, b = single, single2
                    if ord(a) > ord(b):
                        raise RegexError("bad range %r-%r" % (a, b))
                    parts.append((frozenset(chr(o) for o in range(ord(a), ord(b) + 1)), False))
                    continue
                parts.append((tset, tneg))
                parts.append((frozenset("-"), False))
                parts.append((s2, n2))
            else:
                parts.append((tset, tneg))
        return ("cls", parts, neg)

    def _class_escape(self):
        """Inside [...]: returns (frozenset, is_neg, single_char_or_None)."""
        assert self.peek() == "\\"
        self.i += 1
        c = self.peek()
        if c == "":
            raise RegexError("pattern ends with backslash")
        self.i += 1
        if c == "d":
            return (_DIGITS, False, None)
        if c == "D":
            return (_DIGITS, True, None)
        if c == "w":
            return (_WORD, False, None)
        if c == "W":
            return (_WORD, True, None)
        if c == "s":
            return (_SPACE, False, None)
        if c == "S":
            return (_SPACE, True, None)
        if c == "b":
            return (frozenset("\x08"), False, "\x08")
        if c in _SIMPLE_ESC:
            ch = _SIMPLE_ESC[c]
            return (frozenset(ch), False, ch)
        if c == "x":
            ch = self._hex(2)
            return (frozenset(ch), False, ch)
        return (frozenset(c), False, c)

    def _escape(self, in_class):
        assert self.peek() == "\\"
        self.i += 1
        c = self.peek()
        if c == "":
            raise RegexError("pattern ends with backslash")
        self.i += 1
        if c == "d":
            return ("cls", [(_DIGITS, False)], False)
        if c == "D":
            return ("cls", [(_DIGITS, True)], False)
        if c == "w":
            return ("cls", [(_WORD, False)], False)
        if c == "W":
            return ("cls", [(_WORD, True)], False)
        if c == "s":
            return ("cls", [(_SPACE, False)], False)
        if c == "S":
            return ("cls", [(_SPACE, True)], False)
        if c == "b" and not in_class:
            return ("assert", "wb")
        if c == "B" and not in_class:
            return ("assert", "nwb")
        if c in _SIMPLE_ESC:
            return ("lit", _SIMPLE_ESC[c])
        if c == "x":
            return ("lit", self._hex(2))
        return ("lit", c)  # \., \*, \(, etc.

    def _hex(self, n):
        h = self.p[self.i:self.i + n]
        if len(h) != n or any(x not in "0123456789abcdefABCDEF" for x in h):
            raise RegexError("bad hex escape")
        self.i += n
        return chr(int(h, 16))


# ---------------------------------------------------------------------------
# 2. Thompson NFA construction: AST -> states
# ---------------------------------------------------------------------------

class _State:
    __slots__ = ("kind", "c", "parts", "neg", "out1", "out2",
                 "slot", "akind", "gen", "lhead", "lexit", "max_n",
                 "body_out1")

    def __init__(self, kind):
        self.kind = kind      # char|cls|dot|split|jmp|save|assert|match|
                              # lhead|lback
        self.c = None         # char
        self.parts = None     # cls: list of (frozenset, is_neg)
        self.neg = False      # cls: [^...]
        self.out1 = None
        self.out2 = None
        self.slot = -1        # save: capture slot
        self.akind = None     # assert: start|end|wb|nwb
        self.gen = 0          # epsilon-closure dedup stamp
        self.lhead = None     # lback: loop head state
        self.lexit = None     # lback: where to go when loop stops
        self.max_n = 0        # lhead: max optional iterations
        self.body_out1 = True  # lhead: True if out1 is the body (greedy)


class _Frag:
    __slots__ = ("start", "out")

    def __init__(self, start, out):
        self.start = start
        self.out = out  # list of (state, which) dangling patch points


def _patch(out, target):
    for st, which in out:
        if which == 1:
            st.out1 = target
        else:
            st.out2 = target


def _cat(f1, f2):
    _patch(f1.out, f2.start)
    return _Frag(f1.start, f2.out)


def _empty_frag():
    s = _State("jmp")
    return _Frag(s, [(s, 1)])


def _can_empty(node):
    """Static check: can this AST node match the empty string?"""
    t = node[0]
    if t in ("lit", "dot", "cls"):
        return False
    if t == "assert":
        return True
    if t == "seq":
        return all(_can_empty(x) for x in node[1])
    if t == "alt":
        return any(_can_empty(x) for x in node[1])
    if t == "grp":
        return _can_empty(node[2])
    if t == "rep":
        _, atom, lo, hi, _greedy = node
        return lo == 0 or _can_empty(atom)
    raise RegexError("cannot analyze node %r" % (t,))


def _plain_loop(body, greedy):
    head = _State("split")
    if greedy:
        head.out1 = body.start
        dangle = [(head, 2)]
    else:
        head.out2 = body.start
        dangle = [(head, 1)]
    _patch(body.out, head)
    return _Frag(head, dangle)


def _plain_opt(body, greedy):
    sp = _State("split")
    sk = _State("jmp")
    if greedy:
        sp.out1, sp.out2 = body.start, sk
    else:
        sp.out1, sp.out2 = sk, body.start
    _patch(body.out, sk)
    return _Frag(sp, [(sk, 1)])


def _compile(node):
    t = node[0]
    if t == "lit":
        s = _State("char")
        s.c = node[1]
        return _Frag(s, [(s, 1)])
    if t == "dot":
        s = _State("dot")
        return _Frag(s, [(s, 1)])
    if t == "cls":
        s = _State("cls")
        s.parts, s.neg = node[1], node[2]
        frag = _Frag(s, [(s, 1)])
        return frag
    if t == "assert":
        s = _State("assert")
        s.akind = node[1]
        return _Frag(s, [(s, 1)])
    if t == "seq":
        frags = [_compile(x) for x in node[1]]
        if not frags:
            return _empty_frag()
        acc = frags[0]
        for f in frags[1:]:
            acc = _cat(acc, f)
        return acc
    if t == "alt":
        # Right-nested splits: n branches need exactly n-1 splits. (A version
        # with n splits leaves the last split's out2 dangling; the parent
        # then patches it to the continuation, creating an epsilon path that
        # skips every branch -- a phantom empty match. Caught by fuzzing.)
        frags = [_compile(b) for b in node[1]]
        acc = frags[-1]
        for f in reversed(frags[:-1]):
            sp = _State("split")
            sp.out1 = f.start
            sp.out2 = acc.start
            acc = _Frag(sp, f.out + acc.out)
        return acc
    if t == "grp":
        n = node[1]
        s1 = _State("save")
        s1.slot = 2 * n
        f = _compile(node[2])
        s2 = _State("save")
        s2.slot = 2 * n + 1
        s1.out1 = f.start
        _patch(f.out, s2)
        return _Frag(s1, [(s2, 1)])
    if t == "rep":
        _, atom, lo, hi, greedy = node
        parts = [_compile(atom) for _ in range(lo)]
        if hi is None:  # unbounded loop
            if greedy and _can_empty(atom):
                # X* where X can match empty: rewrite as (?: Xs X? | ).
                # Xs is a plain Thompson loop (epsilon-dedup kills an empty
                # body, so it only does non-empty iterations); the trailing
                # X? records the single final empty iteration that CPython
                # performs before stopping the repeat. Without this, the
                # empty iteration is silently dropped and repeated groups
                # report None instead of ''. (Caught by differential fuzz.)
                star = _plain_loop(_compile(atom), greedy)
                opt = _plain_opt(_compile(atom), greedy)
                seq = _cat(star, opt)
                sp = _State("split")
                empty = _empty_frag()
                sp.out1 = seq.start
                sp.out2 = empty.start
                parts.append(_Frag(sp, seq.out + empty.out))
            else:
                parts.append(_plain_loop(_compile(atom), greedy))
        else:
            opt_n = hi - lo
            if opt_n > 0:
                if _can_empty(atom):
                    # Bounded optional loop with CPython's "empty stops the
                    # repeat" rule: if an iteration matches empty, stop (don't
                    # try more). Implemented via lhead/lback with a counter.
                    # (Unrolled optionals get the backtracking order wrong
                    # here — differential fuzzing proved it.)
                    body = _compile(atom)
                    head = _State("lhead")
                    head.max_n = opt_n
                    back = _State("lback")
                    back.lhead = head
                    nop = _State("jmp")
                    back.lexit = nop
                    if greedy:
                        head.out1 = body.start
                        head.out2 = nop
                        head.body_out1 = True
                    else:
                        head.out1 = nop
                        head.out2 = body.start
                        head.body_out1 = False
                    _patch(body.out, back)
                    parts.append(_Frag(head, [(nop, 1)]))
                else:
                    # Fast path: body can't be empty, so "empty stops" never
                    # triggers; plain unrolled optionals are exact.
                    for _ in range(opt_n):
                        parts.append(_plain_opt(_compile(atom), greedy))
        if not parts:
            return _empty_frag()
        acc = parts[0]
        for f in parts[1:]:
            acc = _cat(acc, f)
        return acc
    raise RegexError("cannot compile node %r" % (t,))


class _Program:
    def __init__(self, pattern):
        parser = _Parser(pattern)
        root = parser.parse()
        self.ngroups = parser.ngroups
        body = _compile(root)
        s0 = _State("save")
        s0.slot = 0
        s1 = _State("save")
        s1.slot = 1
        m = _State("match")
        s0.out1 = body.start
        _patch(body.out, s1)
        s1.out1 = m
        self.start = s0
        # anchored iff the pattern's first atom is ^
        self.anchored = (root[0] == "assert" and root[1] == "start") or (
            root[0] == "seq" and root[1] and root[1][0] == ("assert", "start"))


# ---------------------------------------------------------------------------
# 3. Pike VM simulation with backtracking-priority winner selection
# ---------------------------------------------------------------------------

def _isword(ch):
    return ch.isalnum() or ch == "_"


def _consume(st, ch):
    k = st.kind
    if k == "char":
        return st.c == ch
    if k == "cls":
        hit = any((ch in sset) != pneg for sset, pneg in st.parts)
        return (not hit) if st.neg else hit
    if k == "dot":
        return ch != "\n"
    return False


# Process-global generation counter for epsilon-closure dedup. It MUST NOT be
# per-VM: states are shared across every search on a compiled pattern, so a
# counter that restarts at 0 makes a later search falsely skip states stamped
# by an earlier one (real bug, caught by differential testing).
_GEN = 0


def _next_gen():
    global _GEN
    _GEN += 1
    return _GEN


class _VM:
    def __init__(self, prog):
        self.prog = prog
        self.endpos = 0

    # Epsilon closure, DFS in priority order. Threads that reach MATCH are
    # recorded as candidates (prio, end, captures); the caller picks min prio.
    #
    # Threads carry `lpos`: {id(lhead): [entry_pos, count]} for bounded
    # loops, implementing CPython's "empty iteration stops the repeat" rule.
    # lpos is copied on write (at lhead/lback), never mutated in place.
    def _add(self, lst, st, pos, caps, prio, lpos, s, cands, gen):
        if st is None or st.gen == gen:
            return
        st.gen = gen
        k = st.kind
        if k == "split":
            self._add(lst, st.out1, pos, caps, prio + "0", lpos, s, cands, gen)
            self._add(lst, st.out2, pos, caps, prio + "1", lpos, s, cands, gen)
        elif k == "lhead":
            lid = id(st)
            if lpos is None or lid not in lpos:
                nlpos = dict(lpos) if lpos else {}
                nlpos[lid] = [pos, 0]
                count = 0
            else:
                nlpos = lpos
                count = lpos[lid][1]
            if count >= st.max_n:
                # Max iterations reached: only take the exit branch.
                exit_out = st.out2 if st.body_out1 else st.out1
                self._add(lst, exit_out, pos, caps, prio + "1", nlpos,
                          s, cands, gen)
            else:
                self._add(lst, st.out1, pos, caps, prio + "0", nlpos,
                          s, cands, gen)
                self._add(lst, st.out2, pos, caps, prio + "1", nlpos,
                          s, cands, gen)
        elif k == "lback":
            lid = id(st.lhead)
            entry_pos, count = lpos[lid]
            if entry_pos == pos:
                # Body matched empty: stop the repeat (recorded).
                self._add(lst, st.lexit, pos, caps, prio, lpos, s, cands, gen)
            elif count >= st.lhead.max_n:
                # Max iterations reached: stop.
                self._add(lst, st.lexit, pos, caps, prio, lpos, s, cands, gen)
            else:
                # Loop again with fresh dedup scope (re-entry must not
                # collide with entry-path states at shared joins).
                nlpos = dict(lpos)
                nlpos[lid] = [pos, count + 1]
                self._add(lst, st.lhead, pos, caps, prio, nlpos,
                          s, cands, _next_gen())
        elif k == "jmp":
            self._add(lst, st.out1, pos, caps, prio, lpos, s, cands, gen)
        elif k == "save":
            nc = caps[:]
            nc[st.slot] = pos
            self._add(lst, st.out1, pos, nc, prio, lpos, s, cands, gen)
        elif k == "assert":
            if self._check(st.akind, s, pos):
                self._add(lst, st.out1, pos, caps, prio, lpos, s, cands, gen)
        elif k == "match":
            cands.append((prio, pos, caps))
        else:  # consuming state
            lst.append((st, caps, prio, lpos))

    def _check(self, akind, s, pos):
        if akind == "start":
            return pos == 0
        if akind == "end":
            return pos == self.endpos
        left = pos > 0 and _isword(s[pos - 1])
        right = pos < self.endpos and _isword(s[pos])
        return (left != right) if akind == "wb" else (left == right)

    def _step(self, clist, ch, npos, s, cands):
        nlist = []
        gen = _next_gen()
        for st, caps, prio, lpos in clist:
            if _consume(st, ch):
                self._add(nlist, st.out1, npos, caps, prio, lpos,
                          s, cands, gen)
        return nlist

    def _run_start(self, s, st0, endpos):
        """All (prio, end, caps) candidates for matches starting at st0."""
        self.endpos = endpos
        cands = []
        clist = []
        self._add(clist, self.prog.start, st0,
                  [-1] * (2 * (self.prog.ngroups + 1)), "", None, s, cands,
                  _next_gen())
        pos = st0
        while pos < endpos and clist:
            clist = self._step(clist, s[pos], pos + 1, s, cands)
            pos += 1
        return cands

    @staticmethod
    def _best(cands):
        if not cands:
            return None
        return min(cands, key=lambda c: c[0])  # lexicographic prio

# ---------------------------------------------------------------------------
# 4. Public API
# ---------------------------------------------------------------------------

class Match:
    def __init__(self, string, start, end, groups):
        self.string = string
        self._start = start
        self._end = end
        self._groups = groups  # list, index 0 = whole match

    def span(self, g=0):
        if g == 0:
            return (self._start, self._end)
        s = self._groups[2 * g]
        e = self._groups[2 * g + 1]
        return (s, e) if s != -1 else (-1, -1)

    def start(self, g=0):
        return self.span(g)[0]

    def end(self, g=0):
        return self.span(g)[1]

    def group(self, *gs):
        if len(gs) == 1:
            g = gs[0]
            if g == 0:
                return self.string[self._start:self._end]
            s, e = self.span(g)
            return self.string[s:e] if s != -1 else None
        return tuple(self.group(g) for g in gs)

    def groups(self):
        n = len(self._groups) // 2
        return tuple(self.group(g) for g in range(1, n))

    def __repr__(self):
        return "<refox.Match %r span=%r>" % (
            self.string[self._start:self._end], (self._start, self._end))


class Regex:
    def __init__(self, pattern):
        self.pattern = pattern
        self.prog = _Program(pattern)
        self.groups = self.prog.ngroups

    def _vm(self):
        return _VM(self.prog)

    def search(self, string, pos=0, endpos=None):
        endpos = len(string) if endpos is None else endpos
        vm = self._vm()
        for st0 in range(pos, endpos + 1):
            best = vm._best(vm._run_start(string, st0, endpos))
            if best is not None:
                _, end, caps = best
                return Match(string, st0, end, caps)
            if self.prog.anchored:
                break
        return None

    def match(self, string, pos=0, endpos=None):
        endpos = len(string) if endpos is None else endpos
        vm = self._vm()
        best = vm._best(vm._run_start(string, pos, endpos))
        if best is None:
            return None
        _, end, caps = best
        return Match(string, pos, end, caps)

    def fullmatch(self, string, pos=0, endpos=None):
        endpos = len(string) if endpos is None else endpos
        vm = self._vm()
        cands = [c for c in vm._run_start(string, pos, endpos)
                 if c[1] == endpos]
        best = vm._best(cands)
        if best is None:
            return None
        _, end, caps = best
        return Match(string, pos, end, caps)

    def findall(self, string, pos=0, endpos=None):
        out = []
        for m in self.finditer(string, pos, endpos):
            if self.groups == 0:
                out.append(m.group(0))
            elif self.groups == 1:
                # CPython quirk: findall reports '' (not None) for groups
                # that didn't participate; match.group() reports None.
                g = m.group(1)
                out.append("" if g is None else g)
            else:
                out.append(tuple("" if g is None else g
                                 for g in m.groups()))
        return out

    def _best_nonempty_at(self, s, a, endpos):
        """Best match starting at a with end > a (for finditer's empty-retry).
        Returns (end, caps) or None."""
        vm = self._vm()
        cands = [c for c in vm._run_start(s, a, endpos) if c[1] > a]
        best = vm._best(cands)
        if best is None:
            return None
        _, end, caps = best
        return (end, caps)

    def finditer(self, string, pos=0, endpos=None):
        endpos = len(string) if endpos is None else endpos
        p = pos
        while p <= endpos:
            m = self.search(string, p, endpos)
            if m is None:
                return
            a, b = m.span()
            if b > a:
                yield m
                p = b
                continue
            # Empty match at a: yield it, then CPython retries at a
            # disallowing empty, so a lazy quantifier can still match
            # non-empty here. If the retry fails, advance by one.
            yield m
            ne = self._best_nonempty_at(string, a, endpos)
            if ne is not None:
                end, caps = ne
                yield Match(string, a, end, caps)
                p = end
            else:
                p = a + 1

    def _expand(self, m, repl):
        res = []
        i = 0
        while i < len(repl):
            c = repl[i]
            if c == "\\" and i + 1 < len(repl):
                n = repl[i + 1]
                if n.isdigit():
                    g = m.group(int(n))
                    res.append("" if g is None else g)
                    i += 2
                    continue
                if n == "\\":
                    res.append("\\")
                    i += 2
                    continue
            res.append(c)
            i += 1
        return "".join(res)

    def sub(self, repl, string, count=0):
        out = []
        p = 0
        n = 0
        for m in self.finditer(string):
            if count and n >= count:
                break
            a, b = m.span()
            out.append(string[p:a])
            out.append(self._expand(m, repl))
            n += 1
            p = b
        out.append(string[p:])
        return "".join(out)

    def split(self, string, maxsplit=0):
        parts = []
        p = 0
        n = 0
        endpos = len(string)
        for m in self.finditer(string):
            if maxsplit and n >= maxsplit:
                break
            a, b = m.span()
            parts.append(string[p:a])
            for g in range(1, self.groups + 1):
                parts.append(m.group(g))
            p = b
            n += 1
        parts.append(string[p:])
        return parts


def compile(pattern):  # noqa: A001 - mirrors re.compile on purpose
    return Regex(pattern)
