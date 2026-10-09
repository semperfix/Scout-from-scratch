#!/usr/bin/env python3
"""FoxScript test runner.

Each tests/*.fox file carries its expectations as trailing comments:
    // => <line>        expected stdout line, in order
    // !> <substr>      expected runtime error; stderr must contain substr
    // !!> <substr>     expected compile error; stderr must contain substr
"""

import os
import subprocess
import sys

DIR = os.path.dirname(os.path.abspath(__file__))
FOX = os.path.join(DIR, "..", "fox.py")


def parse_expect(path):
    out, err_kind, err_sub = [], None, None
    with open(path) as f:
        for line in f:
            s = line.strip()
            if s.startswith("// =>"):
                out.append(s[5:].strip())
            elif s.startswith("// !!>"):
                err_kind, err_sub = "compile", s[6:].strip()
            elif s.startswith("// !>"):
                err_kind, err_sub = "run", s[5:].strip()
    return out, err_kind, err_sub


def run_one(path):
    name = os.path.basename(path)
    want_out, err_kind, err_sub = parse_expect(path)
    try:
        p = subprocess.run([sys.executable, FOX, path],
                           capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return name, False, "TIMEOUT after 30s"
    got_out = p.stdout.splitlines()
    if err_kind is None:
        if p.returncode != 0:
            return name, False, "exit %d, stderr: %s" % (
                p.returncode, p.stderr.strip()[:200])
        if got_out != want_out:
            return name, False, "output mismatch:\n  want %r\n  got  %r" % (
                want_out, got_out)
        return name, True, ""
    want_code = 70 if err_kind == "run" else 65
    if p.returncode != want_code:
        return name, False, "expected exit %d, got %d (stderr: %s)" % (
            want_code, p.returncode, p.stderr.strip()[:200])
    if err_sub not in p.stderr:
        return name, False, "stderr missing %r (got: %s)" % (
            err_sub, p.stderr.strip()[:200])
    return name, True, ""


def main():
    files = sorted(f for f in os.listdir(DIR) if f.endswith(".fox"))
    passed, failed = 0, []
    for f in files:
        name, ok, msg = run_one(os.path.join(DIR, f))
        if ok:
            passed += 1
            print("PASS %s" % name)
        else:
            failed.append(name)
            print("FAIL %s: %s" % (name, msg))
    print("\n%d/%d passed" % (passed, len(files)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
