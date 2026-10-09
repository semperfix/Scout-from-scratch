#!/usr/bin/env python3
"""refox CLI: grep-like search and field extraction powered by the
from-scratch regex engine (regex.py). No `re` module used anywhere.

Usage:
  refox.py find <pattern> <file> [--count]
  refox.py extract <preset> <file>     (preset: phones | amounts | dates)
  refox.py sub <pattern> <repl> <file>
"""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
import regex

PRESETS = {
    # US-style phone numbers, incl. the 912 numbers in Kyle's orbit
    "phones": r"\b\d{3}[-. ]\d{3}[-. ]\d{4}\b",
    # dollar amounts like $450, $1,316.30
    "amounts": r"\$\d[\d,]*(?:\.\d{2})?",
    # dates like 2026-10-08 or 10/08/2026
    "dates": r"\b\d{4}-\d{2}-\d{2}\b|\b\d{1,2}/\d{1,2}/\d{2,4}\b",
}


def cmd_find(args):
    pat, path = args[0], args[1]
    count_only = "--count" in args
    rx = regex.compile(pat)
    n = 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for ln, line in enumerate(f, 1):
            for m in rx.finditer(line.rstrip("\n")):
                n += 1
                if not count_only:
                    print("%d:%d: %s" % (ln, m.start(), m.group(0)))
    if count_only:
        print(n)


def cmd_extract(args):
    preset, path = args[0], args[1]
    if preset not in PRESETS:
        sys.exit("unknown preset %r (choose: %s)"
                 % (preset, ", ".join(sorted(PRESETS))))
    rx = regex.compile(PRESETS[preset])
    seen = []
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    for m in rx.finditer(text):
        v = m.group(0)
        if v not in seen:
            seen.append(v)
    for v in seen:
        print(v)


def cmd_sub(args):
    pat, repl, path = args[0], args[1], args[2]
    rx = regex.compile(pat)
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    sys.stdout.write(rx.sub(repl, text))


def main(argv):
    if len(argv) < 2:
        sys.exit(__doc__)
    cmd = argv[1]
    try:
        if cmd == "find":
            cmd_find(argv[2:])
        elif cmd == "extract":
            cmd_extract(argv[2:])
        elif cmd == "sub":
            cmd_sub(argv[2:])
        else:
            sys.exit("unknown command %r" % cmd)
    except regex.RegexError as e:
        sys.exit("refox: bad pattern: %s" % e)
    except IndexError:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
