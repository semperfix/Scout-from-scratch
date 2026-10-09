# Statistical Inference Toolkit

A from-scratch statistics library plus a claim-testing CLI. `stats.py` implements normal/chi-square/t CDFs from hand-rolled special functions (regularized incomplete gamma via series/continued fraction, incomplete beta via continued fraction), then t-tests, chi-square tests, Pearson/Spearman, bootstrap CIs, permutation tests, Mann-Kendall + Sen's slope, multiple-testing corrections, OLS with full inference, and power analysis — all validated 45/45 against scipy. `statcheck.py` wraps the common tests in a one-liner CLI: trend, compare, corr, indep.

## Dependencies

**Not stdlib-only — this is the exception.** `stats.py` requires `numpy` (plus stdlib `math`). `claims.py` also uses `scipy.stats` (as an independent check, not as a dependency of the core math). `statcheck.py` itself only needs `stats.py` + `numpy`. Verified installed in this environment: numpy 1.26.4, scipy 1.11.4. (`pip install numpy scipy` otherwise.)

## How to run

Entry point: `statcheck.py` (options use `--name=value` syntax)

```
python3 statcheck.py trend   data.csv --col=value --date-col=date
#   Is there a monotonic trend? Mann-Kendall + Sen's slope (robust to outliers)

python3 statcheck.py compare data.csv --col=value --group=group --a=A --b=B
#   Do two groups differ? Welch t-test + permutation test + Cohen's d

python3 statcheck.py corr    data.csv --x=col1 --y=col2
#   Are X and Y related? Pearson r with bootstrap CI + Spearman

python3 statcheck.py indep   table.csv
#   Are the categories independent? chi-square + Cramer's V (CSV = contingency table)

python3 tests.py     # 45 checks against scipy
python3 claims.py    # four real claim-tests on the bundled ERA5 data
```

## Usage example

```
$ python3 statcheck.py trend temps.csv --col=value --date-col=date
n=10
Mann-Kendall: S=45, Z=3.94, p=8.303e-05 -> increasing
Sen's slope: +1.1 per row-step
note: rows are treated as equally spaced in time; aggregate to annual means first if days are autocorrelated.
```

## Key learnings (from LEARNINGS.md)

- A p-value is P(data | no effect), never P(no effect | data) — a permutation test literally counting "how often would shuffling alone produce a difference this big" agrees with Welch's t to 3 decimals. The t-test's Normality machinery is a shortcut; the shuffle is the meaning. Significance ≠ importance: the CLI prints effect size alongside p because d is the number you'd act on, not p.
- The aggregation choice *is* the analysis: Mann-Kendall on 10,958 autocorrelated daily temps screams significance, but on 30 annual means (n=30, ~independent) gives the honest answer: +0.72°F/decade, p=0.0022. Same data, two defensible answers — and 10-year windows show no trend at all (p=0.86).
- Bootstrapping a trend by shuffling the raw series destroys the time ordering, so every replicate is trendless noise — the fix is a residual bootstrap (fit the line, resample residuals). The CI must respect the data's structure.
- The continued-fraction incomplete beta has two limbs and you must pick: use the symmetry flip when x is large, or convergence stalls. Numerical code is full of quiet branch choices that textbooks compress into one line.

## Files

- `statcheck.py` — CLI: `trend` / `compare` / `corr` / `indep` (entry point)
- `stats.py` — the inference library: distributions, tests, resampling, OLS, power
- `tests.py` — 45 checks validating `stats.py` against scipy
- `claims.py` — four real claim-tests run against the bundled climate data
- `era5_bloomingdale.json` / `era5_bloomingdale_30y.json` — ERA5 reanalysis temps for Bloomingdale, GA (1-yr / 30-yr samples; real results: annual-mean daily highs warming +0.72°F/decade, 1995–2024)
- `LEARNINGS.md` — full expedition notes
