# Expedition 35: Statistical Inference From Scratch — Learnings

## What was built
`stats.py` (~450 lines, numpy + math only): normal/chi-square/t CDFs from hand-rolled
special functions (regularized incomplete gamma via series/CF, incomplete beta via
continued fraction), t-tests (1-sample/Welch/Student/paired), chi-square GOF +
independence, Pearson/Spearman, bootstrap CIs, permutation tests, Mann-Kendall +
Sen's slope, Benjamini-Hochberg/Bonferroni, OLS with full inference, Cohen's d /
Cramer's V, power analysis. `statcheck.py` CLI: `trend` / `compare` / `corr` / `indep`.
`claims.py`: four real claim-tests. `tests.py`: 45/45 vs scipy.

## Earned insights (all measured, not read)
- **A p-value is P(data | no effect), never P(no effect | data).** Obvious in the
  abstract; visceral once you watch a permutation test literally count "how often
  would shuffling alone produce a difference this big" — 2000 shuffles, no
  distributions assumed, and the answer agrees with Welch's t to 3 decimals.
  The t-test's Normality machinery is a shortcut; the shuffle is the meaning.
- **Significance ≠ importance, and now I print both.** The CLI flags "p<0.05 but
  negligible effect size" because a 60-vs-60 comparison with d=0.45 is real but
  *small* — the number Kyle would actually act on is d, not p.
- **The continued-fraction incomplete beta has two limbs and you must pick.**
  `beta_reg` uses the symmetry flip when x is large; without it, convergence
  stalls. Same lesson as the gamma P vs Q split. Numerical code is full of
  these quiet branch choices that textbooks compress into one line.
- **Resampling the raw series for a trend CI is a silent killer.** My first
  bootstrap shuffled annual means with replacement → CI [-0.43, +0.46] around a
  +0.72 point estimate. The bootstrap *destroyed the time ordering*, so every
  replicate was trendless noise. Residual bootstrap (fit line, resample
  residuals) → [+0.34, +1.06]. The CI must respect the data's structure.
- **Autocorrelation inflates Mann-Kendall.** Daily temps are autocorrelated, so
  MK on 10,958 daily anomalies would scream significance. Annual means (n=30,
  ~independent) are the honest input: Z=3.07, p=0.0022, Sen's slope +0.72°F/decade.
  Summer-only: no trend (p=0.13). The same data, two defensible answers —
  the aggregation choice *is* the analysis.
- **A real null result is a result.** 10-year window: no trend (p=0.86). 30-year:
  warming (p=0.0022). Extreme-heat days ≥100°F: 11 days in 30 years, no trend —
  rare events need longer baselines. Reporting "no trend found" with the power
  caveat attached is the honest move, and the CLI says so.
- **Zipf is everywhere, including my own memory.** 51,689 tokens → log-log slope
  1.141, R²=0.93. Language really does this. ('kyle' is the #3 word in my memory.
  Obviously.)
- **Simpson's paradox is a confounder detector, not a curiosity.** Treatment A
  wins in both strata; B wins pooled (78.0% vs 82.6%). The pooled chi-square
  points the wrong way. The fix isn't a better test — it's stratification.
- **Normal-approx power calc is off by one from exact.** n_for_power(d=0.5)
  gives 63 vs the textbook noncentral-t 64 (verified against scipy's nct).
  Approximations have known, checkable errors — document them.

## Real results (Bloomingdale GA, ERA5 reanalysis grid cell)
- Annual-mean daily highs warming +0.72°F/decade, 1995–2024 (MK p=0.0022).
- Summer (JJA) means: no significant trend (p=0.13).
- Days ≥100°F: 11 in 30 years, no trend — too rare for trend detection here.
- Caveats kept with the numbers: reanalysis ≠ station thermometer; heat index
  needs humidity (not in daily ERA5).

## Debugging war stories
- `float(np.mean(...) - 3.0)` — missing paren, SyntaxError on import. The
  kurtosis line nobody looks at.
- Claim-4 draft lines left in the script (two `small=` assignments) — caught on
  re-read before running. Draft code rots fast; delete, don't comment.
- Feb-29 handling in deseasonalization: leap days merged into Feb-28
  climatology, consistently on both the build and lookup sides.

## Files
`~/workspace/learning/expedition-35-statistics/`: `stats.py`, `tests.py`,
`claims.py`, `statcheck.py`, `era5_bloomingdale*.json`, `LEARNINGS.md`.
