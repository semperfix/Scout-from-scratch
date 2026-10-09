#!/usr/bin/env python3
"""test_osint.py -- validate dorkgen.py (offline; asserts on structure)."""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from dorkgen import build_dorks, RUBRIC, CHECKLIST, worksheet

checks = []


def check(name, cond, detail=""):
    checks.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name +
          (" -- " + str(detail) if detail and not cond else ""))


def count_dorks(*a, **k):
    return sum(len(d) for _, d in build_dorks(*a, **k))


def main():
    n = count_dorks(name="Jordan Ellis")
    check("name-only yields 18+ dorks", n >= 18, n)
    n = count_dorks(name="Jordan Ellis", email="j@example.com",
                    phone="912-555-0147", username="jordanellis92",
                    location="Savannah, GA")
    check("full input yields 25+ dorks", n >= 25, n)

    cats = [c for c, _ in build_dorks(name="Jordan Ellis",
                                      email="j@example.com")]
    for want in ("IDENTITY", "SOCIAL", "RECORDS", "CONTACT PIVOTS",
                 "BREACH", "IMAGES"):
        check("category present: %s" % want,
              any(want in c for c in cats), cats)

    check("rubric has A-D grades",
          all("  %s " % g in RUBRIC or "\n  %s " % g in RUBRIC
              for g in "ABCD"), "")
    check("checklist has anchors",
          "DOB" in CHECKLIST and "Associates" in CHECKLIST)

    w = worksheet(argparse_ns())
    check("worksheet has rubric", "SOURCE-GRADING RUBRIC" in w)
    check("worksheet has checklist", "DISAMBIGUATION CHECKLIST" in w)
    check("worksheet has timeline table", "| Date | Event |" in w)
    check("worksheet has dork checkboxes", "- [ ] `" in w)

    p = subprocess.run([sys.executable, os.path.join(HERE, "dorkgen.py"),
                        "--name", "Jordan Ellis"], capture_output=True,
                       text=True)
    check("cli exits 0", p.returncode == 0, p.stderr[:200])
    check("cli output numbered", "[01]" in p.stdout and "dorks generated" in p.stdout)
    p = subprocess.run([sys.executable, os.path.join(HERE, "dorkgen.py"),
                        "--help"], capture_output=True, text=True)
    check("cli --help", p.returncode == 0 and "usage" in p.stdout.lower())

    failed = [n for n, ok in checks if not ok]
    print("\n%d/%d checks passed" % (len(checks) - len(failed), len(checks)))
    sys.exit(1 if failed else 0)


def argparse_ns():
    class N:
        name = email = phone = username = location = None
    return N()


if __name__ == "__main__":
    main()
