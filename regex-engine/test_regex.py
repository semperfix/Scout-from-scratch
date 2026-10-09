#!/usr/bin/env python3
"""Deterministic known-answer tests for the refox engine."""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
import regex

PASS = 0
FAIL = 0


def check(name, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL %-40s got %r want %r" % (name, got, want))


def sp(pat, s, **kw):
    m = regex.compile(pat).search(s, **kw)
    return m.span() if m else None


# --- basic matching ---------------------------------------------------------
check("lit", sp(r"a", "a"), (0, 1))
check("lit-scan", sp(r"a", "ba"), (1, 2))
check("lit-miss", sp(r"a", "bbb"), None)
check("dot", sp(r"a.c", "axc"), (0, 3))
check("dot-not-nl", sp(r"a.c", "a\nc"), None)
check("escape-dot", sp(r"a\.c", "a.c"), (0, 3))
check("escape-star", sp(r"a\*", "a*"), (0, 2))

# --- anchors ----------------------------------------------------------------
check("caret", sp(r"^a", "ba"), None)
check("caret-ok", sp(r"^a", "ab"), (0, 1))
check("dollar", sp(r"a$", "ab"), None)
check("dollar-ok", sp(r"a$", "ba"), (1, 2))
check("both", sp(r"^a$", "a"), (0, 1))

# --- classes ----------------------------------------------------------------
check("class", sp(r"[abc]+", "abcaxyz"), (0, 4))
check("range", sp(r"[a-c]+", "abcxyz"), (0, 3))
check("neg", sp(r"[^a]+", "aab"), (2, 3))
check("neg2", sp(r"[^ab]", "c"), (0, 1))
check("digit", sp(r"\d+", "ab12"), (2, 4))
check("nondigit", sp(r"\D+", "12ab"), (2, 4))
check("word", sp(r"\w+", "hi!"), (0, 2))
check("space", sp(r"\s+", "a b"), (1, 2))
check("class-escape", sp(r"[\d]+", "a12"), (1, 3))
check("class-neg-escape", sp(r"[\D]+", "ab12"), (0, 2))
check("class-range-escape", sp(r"[\x41-\x43]+", "ABC"), (0, 3))
check("class-dash", sp(r"[a-]+", "a-a"), (0, 3))
check("class-rbracket", sp(r"[]a]+", "]a"), (0, 2))

# --- quantifiers -------------------------------------------------------------
check("star", sp(r"a*", "aaa"), (0, 3))
check("star-empty", sp(r"a*", "bbb"), (0, 0))
check("plus", sp(r"a+", "aaa"), (0, 3))
check("plus-miss", sp(r"a+", "bbb"), None)
check("opt", sp(r"a?", "a"), (0, 1))
check("lazy-star", sp(r"a*?", "aaa"), (0, 0))
check("lazy-plus", sp(r"a+?", "aaa"), (0, 1))
check("lazy-opt", sp(r"a??", "a"), (0, 0))
check("n", sp(r"a{2}", "aaa"), (0, 2))
check("n-m", sp(r"a{2,3}", "aaaa"), (0, 3))
check("n-m-lazy", sp(r"a{2,3}?", "aaaa"), (0, 2))
check("n-comma", sp(r"a{2,}", "aaaa"), (0, 4))

# --- groups ------------------------------------------------------------------
m = regex.compile(r"(\d+)-(\d+)").search("call 912-648-2048")
check("groups", m.groups(), ("912", "648"))
check("span1", m.span(1), (5, 8))
check("span2", m.span(2), (9, 12))
m = regex.compile(r"(a)(b)?").search("a")
check("opt-group-none", m.groups(), ("a", None))
m = regex.compile(r"(?:ab)+").search("abab")
check("noncap", (m.span(), m.groups()), ((0, 4), ()))
check("nested", regex.compile(r"((a)(b))").search("ab").groups(), ("ab", "a", "b"))
check("repeat-group-last", regex.compile(r"(\d)+").search("123").groups(), ("3",))
check("empty-iter-star", regex.compile(r"(a?)*").search("a").groups(), ("",))
check("empty-iter-plus", regex.compile(r"(a?)+").search("").groups(), ("",))
check("lazy-empty-iter", regex.compile(r"(a?)*?").search("").groups(), (None,))

# --- alternation ---------------------------------------------------------------
check("alt-first", sp(r"a|ab", "ab"), (0, 1))
check("alt-second", sp(r"ab|a", "ab"), (0, 2))
check("alt-scan", sp(r"a|b", " 2ab"), (2, 3))
check("alt-miss", sp(r"x|y", "ab"), None)
check("alt-empty-branch", sp(r"a|", "b"), (0, 0))

# --- word boundary ------------------------------------------------------------
check("wb", sp(r"\bcat\b", "a cat naps"), (2, 5))
check("wb-miss", sp(r"\bcat\b", "concats"), None)
check("nwb", sp(r"\Bcat\B", "concats"), (3, 6))

# --- API ----------------------------------------------------------------------
check("match", regex.compile(r"\d+").match("123ab").span(), (0, 3))
check("match-fail", regex.compile(r"\d+").match("ab123"), None)
check("fullmatch", regex.compile(r"\d+").fullmatch("123").span(), (0, 3))
check("fullmatch-fail", regex.compile(r"\d+").fullmatch("123a"), None)
check("findall", regex.compile(r"\d+").findall("a1b22c333"), ["1", "22", "333"])
check("findall-grp", regex.compile(r"(\d)(\d)?").findall("a1b22c3"),
      [("1", ""), ("2", "2"), ("3", "")])
check("sub", regex.compile(r"(\w+)@(\w+)").sub(r"\2=\1", "a@b c@d"), "b=a d=c")
check("sub-count", regex.compile(r"a").sub("X", "aaa", count=2), "XXa")
check("split", regex.compile(r"\s*,\s*").split("a, b ,c"), ["a", "b", "c"])
check("split-grp", regex.compile(r"(,)").split("a,b"), ["a", ",", "b"])
check("pos", sp(r"a", "ba", pos=1), (1, 2))

# --- errors --------------------------------------------------------------------
for bad in ["(", "[a", "a{2,1}", "\\", "*", "(?x)"]:
    try:
        regex.compile(bad)
        check("error-" + bad, "no-raise", "RegexError")
    except regex.RegexError:
        check("error-" + bad, "RegexError", "RegexError")

print("%d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
