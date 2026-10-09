"""claims.py -- put the from-scratch stats to work on real data.

Claim 1: "Bloomingdale GA is getting hotter" -- 10 yrs ERA5 daily tmax,
         deseasonalized + annual means, Mann-Kendall + Sen's slope.
Claim 2: "extreme heat days are increasing" -- days with tmax>=100F per year.
Claim 3: Zipf's law holds on the memory corpus (rank-frequency power law).
Claim 4: Simpson's paradox demo -- aggregation can flip a conclusion;
         stratification (chi-square per stratum) is the fix.

Run: python3 claims.py
"""
import json
import math
import re
from collections import Counter
from datetime import date

import numpy as np

import stats as S

print("=" * 70)
print("CLAIM 1: Bloomingdale, GA is getting hotter (ERA5, 1995-2024)")
print("=" * 70)
d = json.load(open("era5_bloomingdale_30y.json"))["daily"]
days = [date.fromisoformat(t) for t in d["time"]]
tmax = np.array(d["temperature_2m_max"], dtype=float)
print(f"n = {len(tmax)} daily highs, {days[0]} -> {days[-1]}")

# Deseasonalize: subtract day-of-year climatology (leap day merged into Feb 28)
doy = np.array([(dt.month, dt.day) for dt in days])
clim = {}
for m in range(1, 13):
    for dd in range(1, 32):
        sel = [(dt.month == m and dt.day == dd) or (m == 2 and dd == 28 and dt.month == 2 and dt.day == 29)
               for dt in days]
        if any(sel):
            clim[(m, dd)] = tmax[sel].mean()
anom = np.array([t - clim[(dt.month, min(dt.day, 28) if dt.month == 2 and dt.day == 29 else dt.day)]
                 for t, dt in zip(tmax, days)])
# annual means of anomalies (annual aggregation kills day-to-day autocorrelation,
# which would otherwise inflate Mann-Kendall significance)
years = np.array([dt.year for dt in days])
yrange = range(1995, 2025)
annual = np.array([anom[years == y].mean() for y in yrange])
mk = S.mannkendall(annual)
slope_per_yr = S.sens_slope(annual)
# bootstrap CI for the decadal slope: residual bootstrap (resampling the raw
# series would destroy the time ordering and center slopes on zero)
ny = len(annual)
t_idx = np.arange(ny, dtype=float)
lin = S.ols(t_idx, annual)
resid = annual - (lin["beta"][0] + lin["beta"][1] * t_idx)
fitted = lin["beta"][0] + lin["beta"][1] * t_idx
rng = np.random.default_rng(7)
bs = []
for _ in range(2000):
    rep = fitted + resid[rng.integers(0, ny, ny)]
    bs.append(S.sens_slope(rep) * 10)
lo, hi = np.percentile(bs, [2.5, 97.5])
print(f"annual-mean anomaly MK: S={mk['S']}, Z={mk['Z']:.2f}, p={mk['p']:.4f} -> {mk['trend']}")
print(f"Sen's slope: {slope_per_yr * 10:+.2f} F/decade  (95% boot CI [{lo:+.2f}, {hi:+.2f}])")
# summer-only (JJA) as a second look
summ = np.array([dt.month in (6, 7, 8) for dt in days])
sannual = np.array([anom[(years == y) & summ].mean() for y in yrange])
mks = S.mannkendall(sannual)
print(f"summer-mean anomaly MK: Z={mks['Z']:.2f}, p={mks['p']:.4f} -> {mks['trend']}, "
      f"Sen's slope {S.sens_slope(sannual) * 10:+.2f} F/decade")
print("caveat: ERA5 reanalysis grid cell, not a station thermometer; "
      "autocorrelation handled via annual means.")

print()
print("=" * 70)
print("CLAIM 2: extreme-heat days (tmax >= 100F) are increasing")
print("=" * 70)
hot = (tmax >= 100.0).astype(int)
hot_per_yr = np.array([hot[years == y].sum() for y in range(1995, 2025)])
print("per-year counts 1995-2024:", list(hot_per_yr))
mk2 = S.mannkendall(hot_per_yr)
print(f"MK on yearly counts: S={mk2['S']}, p={mk2['p']:.4f} -> {mk2['trend']}")
print("caveat: rare-event counts are noisy; heat *index* needs humidity, which ERA5-daily lacks.")

print()
print("=" * 70)
print("CLAIM 3: word frequencies in the memory corpus follow Zipf's law")
print("=" * 70)
import glob
words = []
for fp in glob.glob("/home/hatch/memory/**/*.md", recursive=True):
    words += re.findall(r"[a-z']+", open(fp, encoding="utf-8", errors="ignore").read().lower())
freq = Counter(w for w in words if len(w) > 2)
ranks = np.arange(1, len(freq) + 1)
counts = np.array(sorted(freq.values(), reverse=True), dtype=float)
fit = S.ols(np.log(ranks), np.log(counts))  # log f = a - b*log r
b = -fit["beta"][1]
print(f"corpus: {len(words)} tokens, {len(freq)} types")
print(f"log-log OLS: slope b = {b:.3f} (Zipf predicts ~1.0), R^2 = {fit['r2']:.4f}, "
      f"p = {fit['p'][1]:.2e}")
print("top 5:", freq.most_common(5))

print()
print("=" * 70)
print("CLAIM 4: Simpson's paradox -- aggregation can reverse the truth")
print("=" * 70)
# Classic kidney-stone-style table: treatment B looks better overall,
# but treatment A wins in BOTH strata. (Fictional numbers, real structure.)
# rows = recovered/not, cols = treatment A/B
# Charig et al. (1986) kidney-stone numbers:
small = np.array([[81, 234], [6, 36]])           # A: 81/87 recovered; B: 234/270
large = np.array([[192, 55], [71, 25]])           # A: 192/263;        B: 55/80
agg = small + large
for name, tab in (("small stones", small), ("large stones", large), ("AGGREGATED", agg)):
    r = S.chi2_independence(tab)
    ra = tab[0, 0] / tab[:, 0].sum()
    rb = tab[0, 1] / tab[:, 1].sum()
    winner = "A" if ra > rb else "B"
    print(f"{name:12s}: A recovers {ra:.1%}, B recovers {rb:.1%} -> {winner} wins "
          f"(chi2 p={r['p']:.2e}, V={r['cramers_v']:.2f})")
print("lesson: the pooled table points the wrong way (B wins) even though A wins in "
      "every stratum. Always stratify by the confounder "
      "(here: stone size -> treatment assignment).")
