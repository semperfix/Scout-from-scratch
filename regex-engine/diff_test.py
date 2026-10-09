#!/usr/bin/env python3
"""Differential test: refox vs stdlib `re` on random patterns and strings.

Compares search() span + groups and findall() output. Skips patterns that
either engine rejects. Fixed seed => reproducible.
"""
import random
import re
import sys
import signal

sys.path.insert(0, __import__("os").path.dirname(__file__))
import regex as refox


class _Timeout(Exception):
    pass


def _alarm_handler(signum, frame):
    raise _Timeout()


def re_search_timed(pat, s, secs=2):
    """re.search with a timeout. CPython's backtracker can catastrophically
    backtrack on nested quantifiers; the Thompson engine never does, so a
    timeout means the oracle (not the engine) gave up -> skip the case."""
    signal.signal(signal.SIGALRM, _alarm_handler)
    signal.alarm(secs)
    try:
        return re.search(pat, s)
    except _Timeout:
        return "TIMEOUT"
    finally:
        signal.alarm(0)


def re_findall_timed(pat, s, secs=2):
    signal.signal(signal.SIGALRM, _alarm_handler)
    signal.alarm(secs)
    try:
        return re.findall(pat, s)
    except _Timeout:
        return "TIMEOUT"
    finally:
        signal.alarm(0)

ATOMS = ["a", "b", "1", " ", ".", r"\d", r"\w", r"\s", "[ab]", "[a-c]",
         "[^ab]", r"[\dx]", "[a-z]", r"\x41", r"\.", r"\*"]
QUANTS = ["", "*", "+", "?", "{1,2}", "{2}", "{0,3}",
          "*?", "+?", "??", "{1,2}?"]
ALPHA = "ab12 \t"


def gen_piece(depth, rng):
    a = rng.choice(ATOMS)
    q = rng.choice(QUANTS)
    return a + q


def gen_seq(depth, rng):
    n = rng.randint(1, 4)
    parts = []
    for _ in range(n):
        r = rng.random()
        if r < 0.25 and depth < 3:
            sub = gen_alt(depth + 1, rng)
            parts.append("(%s)%s" % (sub, rng.choice(QUANTS[:7])))
        elif r < 0.35 and depth < 3:
            sub = gen_alt(depth + 1, rng)
            parts.append("(?:%s)%s" % (sub, rng.choice(QUANTS[:7])))
        else:
            parts.append(gen_piece(depth, rng))
    return "".join(parts)


def gen_alt(depth, rng):
    left = gen_seq(depth, rng)
    if rng.random() < 0.3 and depth < 3:
        return left + "|" + gen_seq(depth, rng)
    return left


def gen_pattern(rng):
    p = gen_alt(0, rng)
    if rng.random() < 0.15:
        p = "^" + p
    if rng.random() < 0.15:
        p = p + "$"
    return p


def norm_groups(g):
    return tuple(x if x is not None else None for x in g)


def one_case(pat, s):
    try:
        re.compile(pat)
    except re.error:
        return "skip-re"
    rm = re_search_timed(pat, s)
    if rm == "TIMEOUT":
        return "skip-timeout"
    try:
        rx = refox.compile(pat)
    except refox.RegexError:
        return "skip-refox"
    try:
        fm = rx.search(s)
    except Exception as e:  # noqa: BLE001 - any engine crash is a failure
        return "engine-crash: %r" % e
    if (rm is None) != (fm is None):
        return "match-disagree pat=%r s=%r re=%r fox=%r" % (pat, s, rm, fm)
    if rm is not None:
        if rm.span() != fm.span():
            return "span-disagree pat=%r s=%r re=%r fox=%r" % (
                pat, s, rm.span(), fm.span())
        if norm_groups(rm.groups()) != norm_groups(fm.groups()):
            return "groups-disagree pat=%r s=%r re=%r fox=%r" % (
                pat, s, rm.groups(), fm.groups())
        # findall agreement (refox mirrors re's str/tuple convention)
        rfa = re_findall_timed(pat, s)
        if rfa == "TIMEOUT":
            return "skip-timeout"
        ffa = rx.findall(s)
        # normalize: re returns list of str when 1 group
        if [x if isinstance(x, str) else tuple(x) for x in rfa] != ffa:
            return "findall-disagree pat=%r s=%r re=%r fox=%r" % (pat, s, rfa, ffa)
    return None
    return None


def main(n=4000, seed=20261008):
    rng = random.Random(seed)
    fails = 0
    skips = 0
    for i in range(n):
        pat = gen_pattern(rng)
        s = "".join(rng.choice(ALPHA) for _ in range(rng.randint(0, 10)))
        res = one_case(pat, s)
        if res is None:
            continue
        if res.startswith("skip"):
            skips += 1
            continue
        fails += 1
        print("FAIL:", res)
        if fails > 10:
            print("...stopping after 10 failures")
            break
    print("done: %d cases, %d failures, %d skips" % (n, fails, skips))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
