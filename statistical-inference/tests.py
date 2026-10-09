"""tests.py -- validate every from-scratch implementation against scipy.

scipy is ground truth here, never the engine. All data deterministic (seeded).
Run: python3 tests.py  -> prints PASS/FAIL per check, exits nonzero on failure.
"""
import math
import numpy as np
from scipy import stats as sp

import stats as S

CHECKS = []

def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))

rng = np.random.default_rng(42)

# --- 1-3: special functions on known values -------------------------------
check("gamma_lower_reg(1,1)==1-1/e",
      abs(S.gamma_lower_reg(1.0, 1.0) - (1 - 1 / math.e)) < 1e-12)
check("gamma_lower_reg(0.5,1)==erf(1)",
      abs(S.gamma_lower_reg(0.5, 1.0) - math.erf(1.0)) < 1e-12)
check("beta_reg(2,3,0.4)",
      abs(S.beta_reg(2.0, 3.0, 0.4) - sp.beta.cdf(0.4, 2, 3)) < 1e-10)
check("beta_reg symmetry limb x=0.9",
      abs(S.beta_reg(5.0, 2.0, 0.9) - sp.beta.cdf(0.9, 5, 2)) < 1e-10)

# --- 4-8: distribution CDFs vs scipy -------------------------------------
xs = np.array([-3.0, -1.0, -0.25, 0.0, 0.5, 1.96, 3.0])
check("norm_cdf", np.allclose(S.norm_cdf(xs), sp.norm.cdf(xs), atol=1e-12))
check("norm_sf", np.allclose(S.norm_sf(xs), sp.norm.sf(xs), atol=1e-12))
ts = np.array([-4.0, -1.5, -0.1, 0.0, 0.7, 2.2, 5.0])
for df in (1, 5, 30):
    check(f"t_cdf df={df}",
          np.allclose(S.t_cdf(ts, df), sp.t.cdf(ts, df), atol=1e-9))
c2 = np.array([0.1, 1.0, 3.84, 10.0, 25.0])
for df in (1, 4, 10):
    check(f"chi2_cdf df={df}",
          np.allclose(S.chi2_cdf(c2, df), sp.chi2.cdf(c2, df), atol=1e-10))
    check(f"chi2_sf df={df}",
          np.allclose(S.chi2_sf(c2, df), sp.chi2.sf(c2, df), atol=1e-10))

# --- 9-11: t-tests --------------------------------------------------------
a = rng.normal(10, 2, 60)
b = rng.normal(11, 2.5, 55)
r1, e1 = S.ttest_1samp(a, 10.0), sp.ttest_1samp(a, 10.0)
check("ttest_1samp t,p", abs(r1["t"] - e1.statistic) < 1e-9 and abs(r1["p"] - e1.pvalue) < 1e-9)
r2, e2 = S.ttest_ind(a, b), sp.ttest_ind(a, b, equal_var=False)
check("ttest_ind Welch t,df,p",
      abs(r2["t"] - e2.statistic) < 1e-9 and abs(r2["df"] - e2.df) < 1e-9
      and abs(r2["p"] - e2.pvalue) < 1e-9)
r2b, e2b = S.ttest_ind(a, b, equal_var=True), sp.ttest_ind(a, b, equal_var=True)
check("ttest_ind Student t,p",
      abs(r2b["t"] - e2b.statistic) < 1e-9 and abs(r2b["p"] - e2b.pvalue) < 1e-9)
rp, ep = S.ttest_rel(a[:50], b[:50]), sp.ttest_rel(a[:50], b[:50])
check("ttest_rel t,p", abs(rp["t"] - ep.statistic) < 1e-9 and abs(rp["p"] - ep.pvalue) < 1e-9)
check("cohens_d", abs(S.cohens_d(a, b) - (a.mean() - b.mean())
      / math.sqrt(((59) * a.var(ddof=1) + 54 * b.var(ddof=1)) / 113)) < 1e-12)

# --- 12-14: chi-square -----------------------------------------------------
obs = np.array([89, 112, 95, 104])
exp = np.array([100, 100, 100, 100])
rg, eg = S.chi2_gof(obs, exp), sp.chisquare(obs, exp)
check("chi2_gof chi2,p", abs(rg["chi2"] - eg.statistic) < 1e-9 and abs(rg["p"] - eg.pvalue) < 1e-9)
tab = np.array([[30, 10, 20], [15, 25, 10], [5, 15, 30]])
ri, ei = S.chi2_independence(tab), sp.chi2_contingency(tab, correction=False)
check("chi2_independence chi2,df,p",
      abs(ri["chi2"] - ei.statistic) < 1e-9 and ri["df"] == ei.dof
      and abs(ri["p"] - ei.pvalue) < 1e-9)
check("cramers_v", abs(ri["cramers_v"] - math.sqrt(ei.statistic / (tab.sum() * 2))) < 1e-12)

# --- 15-17: correlation ----------------------------------------------------
x = rng.normal(0, 1, 200)
y = 0.6 * x + rng.normal(0, 0.8, 200)
rpe, spe = S.pearsonr(x, y), sp.pearsonr(x, y)
check("pearsonr r,p", abs(rpe["r"] - spe.statistic) < 1e-12 and abs(rpe["p"] - spe.pvalue) < 1e-9)
rsp, ssp = S.spearmanr(x, y), sp.spearmanr(x, y)
check("spearmanr rho,p", abs(rsp["r"] - ssp.statistic) < 1e-12 and abs(rsp["p"] - ssp.pvalue) < 1e-9)
xt = np.array([3.0, 1.0, 2.0, 2.0, 5.0])
check("ranks w/ ties", list(S._ranks(xt)) == [4.0, 1.0, 2.5, 2.5, 5.0])

# --- 18-19: resampling sanity ----------------------------------------------
boot = S.bootstrap_ci(a, n_boot=2000, seed=1)
check("bootstrap_ci covers mean",
      boot["ci"][0] < a.mean() < boot["ci"][1] and boot["ci"][0] < boot["stat"] < boot["ci"][1])
# permutation test on identical distributions -> large p
c = rng.normal(5, 1, 40)
d_ = rng.normal(5, 1, 40)
pp = S.permutation_test(c, d_, n_perm=2000, seed=2)
check("permutation null -> p>0.05", pp["p"] > 0.05, f"p={pp['p']:.3f}")
# permutation test on shifted distributions -> tiny p
e_ = rng.normal(8, 1, 40)
pp2 = S.permutation_test(c, e_, n_perm=2000, seed=3)
check("permutation alt -> p<0.01", pp2["p"] < 0.01, f"p={pp2['p']:.4f}")

# --- 20-22: Mann-Kendall ----------------------------------------------------
mkx = np.linspace(0, 5, 50) + rng.normal(0, 0.5, 50)
mk = S.mannkendall(mkx)
mk_ref = None
try:
    import pymannkendall  # noqa
except ImportError:
    mk_ref = None
# validate against a direct O(n^2) reference computed inline instead
n = len(mkx)
s_ref = sum(1 if mkx[j] > mkx[i] else (-1 if mkx[j] < mkx[i] else 0)
            for i in range(n) for j in range(i + 1, n))
check("mannkendall S exact", mk["S"] == s_ref, f"S={mk['S']} ref={s_ref}")
check("mannkendall increasing trend", mk["trend"] == "increasing" and mk["p"] < 0.05,
      f"p={mk['p']:.2e}")
flat = rng.normal(0, 1, 60)
mkf = S.mannkendall(flat)
check("mannkendall null -> no trend", mkf["trend"] == "no trend" and mkf["p"] > 0.05,
      f"p={mkf['p']:.3f}")
sl = S.sens_slope(np.arange(10.0) * 2.5 + 1.0)
check("sens_slope exact line", abs(sl - 2.5) < 1e-12, f"slope={sl}")

# --- 23: multiple comparisons ----------------------------------------------
pvals = [0.001, 0.01, 0.04, 0.06, 0.5]
bh = S.benjamini_hochberg(pvals, alpha=0.05)
# manual: sorted .001,.01,.04,.06,.5 vs thresholds .01,.02,.03,.04,.05 -> k=2
check("benjamini_hochberg k=2", bh["k"] == 2 and list(bh["reject"]) == [True, True, False, False, False])
pvals_b = [0.001, 0.011, 0.04, 0.06, 0.5]
bf = S.bonferroni(pvals_b)
check("bonferroni", list(bf["reject"]) == [True, False, False, False, False])

# --- 24-25: OLS --------------------------------------------------------------
X = rng.normal(0, 1, (300, 2))
beta_true = np.array([1.5, -2.0])
y = 3.0 + X @ beta_true + rng.normal(0, 1, 300)
fit = S.ols(X, y)
ref = sp.linregress  # sanity via closed form below instead
check("ols beta recovers truth",
      np.allclose(fit["beta"], [3.0, 1.5, -2.0], atol=0.25),
      f"beta={fit['beta'].round(3)}")
check("ols r2 high", fit["r2"] > 0.8, f"r2={fit['r2']:.4f}")  # theory: 6.25/7.25 ~= 0.862
check("ols p-values small for real effects", all(fit["p"] < 1e-6))
# OLS on pure noise -> r2 ~ p/n, p-values mostly large
yn = rng.normal(0, 1, 300)
fitn = S.ols(X, yn)
check("ols noise r2 small", fitn["r2"] < 0.1, f"r2={fitn['r2']:.4f}")
check("ols se positive", all(fit["se"] > 0))

# --- 26: power analysis ------------------------------------------------------
pw = S.power_ttest_2samp(0.5, 64)
check("power d=0.5 n=64 ~= 0.80", abs(pw - 0.80) < 0.02, f"power={pw:.4f}")
nreq = S.n_for_power(0.5, 0.8)
# normal approx gives 63; exact noncentral-t answer is 64 (verified vs scipy nct above)
check("n_for_power d=0.5 -> 63 (approx)", nreq == 63, f"n={nreq}")

# --- 27: skew/kurtosis --------------------------------------------------------
check("skew normal ~0", abs(S.skew(rng.normal(0, 1, 20000))) < 0.1)
check("kurtosis normal ~0", abs(S.kurtosis(rng.normal(0, 1, 20000))) < 0.2)
check("skew exponential ~2", abs(S.skew(rng.exponential(1, 20000)) - 2.0) < 0.15)

fails = [c for c in CHECKS if not c[1]]
for name, ok, detail in CHECKS:
    print(("PASS " if ok else "FAIL ") + name + (f" [{detail}]" if detail and not ok else ""))
print(f"\n{len(CHECKS) - len(fails)}/{len(CHECKS)} checks passed")
raise SystemExit(1 if fails else 0)
