#!/usr/bin/env python3
"""statcheck -- test a claim against data, from scratch.

Usage:
  statcheck trend   <csv> --col VALUE [--date-col DATE]
      Is there a monotonic trend? Mann-Kendall + Sen's slope (robust to outliers).
  statcheck compare <csv> --col VALUE --group GROUP [--a A --b B]
      Do two groups differ? Welch t-test + permutation test + Cohen's d.
  statcheck corr    <csv> --x X --y Y
      Are X and Y related? Pearson r with bootstrap CI + Spearman.
  statcheck indep   <csv>  (CSV is a contingency table: first col = row labels)
      Are the categories independent? chi-square + Cramer's V.

All math is hand-rolled (stats.py); CSV reading uses the stdlib csv module.
"""
import csv
import math
import sys

import numpy as np

import stats as S


def read_csv(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    return rows


def col(rows, name):
    vals = []
    for r in rows:
        try:
            vals.append(float(r[name]))
        except (ValueError, TypeError, KeyError):
            pass
    return np.array(vals)


def cmd_trend(path, value_col, date_col=None):
    rows = read_csv(path)
    v = col(rows, value_col)
    if len(v) < 8:
        sys.exit(f"need >= 8 numeric values in --col {value_col}, got {len(v)}")
    mk = S.mannkendall(v)
    slope = S.sens_slope(v)
    print(f"n={len(v)}")
    print(f"Mann-Kendall: S={mk['S']}, Z={mk['Z']:.2f}, p={mk['p']:.4g} -> {mk['trend']}")
    print(f"Sen's slope: {slope:+.4g} per row-step")
    print("note: rows are treated as equally spaced in time; "
          "aggregate to annual means first if days are autocorrelated.")


def cmd_compare(path, value_col, group_col, a=None, b=None):
    rows = read_csv(path)
    groups = {}
    for r in rows:
        try:
            groups.setdefault(r[group_col], []).append(float(r[value_col]))
        except (ValueError, TypeError, KeyError):
            pass
    names = sorted(groups)
    if a is None or b is None:
        if len(names) != 2:
            sys.exit(f"need exactly 2 groups (or pass --a/--b); found: {names}")
        a, b = names[0], names[1]
    x, y = np.array(groups[a]), np.array(groups[b])
    t = S.ttest_ind(x, y)
    pmt = S.permutation_test(x, y, n_perm=5000, seed=0)
    d = S.cohens_d(x, y)
    mag = "negligible" if abs(d) < 0.2 else ("small" if abs(d) < 0.5 else ("medium" if abs(d) < 0.8 else "large"))
    print(f"{a}: n={len(x)}, mean={x.mean():.4g}   {b}: n={len(y)}, mean={y.mean():.4g}")
    print(f"Welch t={t['t']:.3f} (df={t['df']:.1f}), p={t['p']:.4g}")
    print(f"permutation p={pmt['p']:.4g}  (assumption-free cross-check)")
    print(f"Cohen's d={d:+.3f} ({mag} effect)")
    if t["p"] < 0.05 and abs(d) < 0.2:
        print("warning: 'significant' but negligible effect size -- "
              "statistical significance is not practical importance.")


def cmd_corr(path, x_col, y_col):
    rows = read_csv(path)
    pairs = []
    for r in rows:
        try:
            pairs.append((float(r[x_col]), float(r[y_col])))
        except (ValueError, TypeError, KeyError):
            pass
    x = np.array([p[0] for p in pairs])
    y = np.array([p[1] for p in pairs])
    if len(x) < 5:
        sys.exit(f"need >= 5 complete pairs, got {len(x)}")
    pr = S.pearsonr(x, y)
    ci = S.corr_bootstrap_ci(x, y, seed=0)
    sp = S.spearmanr(x, y)
    print(f"n={len(x)} pairs")
    print(f"Pearson r={pr['r']:+.3f}, p={pr['p']:.4g}, 95% boot CI [{ci['ci'][0]:+.3f}, {ci['ci'][1]:+.3f}]")
    print(f"Spearman rho={sp['r']:+.3f}, p={sp['p']:.4g}")
    if abs(pr["r"] - sp["r"]) > 0.25:
        print("note: Pearson and Spearman disagree a lot -- "
              "check for outliers or a non-linear relationship.")


def cmd_indep(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        rd = list(csv.reader(f))
    table = np.array([[float(c) for c in row[1:]] for row in rd[1:]])
    r = S.chi2_independence(table)
    mag = "negligible" if r["cramers_v"] < 0.1 else ("small" if r["cramers_v"] < 0.3
          else ("medium" if r["cramers_v"] < 0.5 else "large"))
    print(f"chi2={r['chi2']:.3f}, df={r['df']}, p={r['p']:.4g}")
    print(f"Cramer's V={r['cramers_v']:.3f} ({mag} association)")
    if (table < 5).any():
        print("warning: some cells < 5 -- chi-square approximation is shaky.")


def main(argv):
    if len(argv) < 3:
        sys.exit(__doc__)
    cmd, path = argv[1], argv[2]
    args = {}
    for tok in argv[3:]:
        if tok.startswith("--"):
            k, _, v = tok[2:].partition("=")
            args[k] = v or True
    if cmd == "trend":
        cmd_trend(path, args.get("col", "value"), args.get("date-col"))
    elif cmd == "compare":
        cmd_compare(path, args.get("col", "value"), args.get("group", "group"),
                    args.get("a"), args.get("b"))
    elif cmd == "corr":
        cmd_corr(path, args["x"], args["y"])
    elif cmd == "indep":
        cmd_indep(path)
    else:
        sys.exit(f"unknown command {cmd!r}\n" + __doc__)


if __name__ == "__main__":
    main(sys.argv)
