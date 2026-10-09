"""stats.py -- statistics from scratch (numpy for arrays, math only for scalars).

Every distribution CDF and every test is implemented from first principles:
  - normal CDF via math.erf
  - chi-square CDF via the regularized lower incomplete gamma (series/CF)
  - Student-t CDF via the regularized incomplete beta (continued fraction)
  - Mann-Kendall trend test, bootstrap CIs, permutation tests,
    OLS regression with full inference, FDR correction, power analysis.

Validated against scipy in tests.py -- scipy is the ground truth, never the engine.
"""
import math
import numpy as np

# ---------------------------------------------------------------------------
# Special functions (from scratch)
# ---------------------------------------------------------------------------

def _gser(s, x):
    """Regularized lower incomplete gamma P(s,x) via series expansion (NR gser)."""
    if x <= 0:
        return 0.0
    gln = math.lgamma(s)
    ap = s
    total = 1.0 / s
    delta = total
    for _ in range(1000):
        ap += 1.0
        delta *= x / ap
        total += delta
        if abs(delta) < abs(total) * 1e-14:
            break
    return total * math.exp(-x + s * math.log(x) - gln)

def _gcf(s, x):
    """Regularized upper incomplete gamma Q(s,x) via continued fraction (NR gcf)."""
    gln = math.lgamma(s)
    b = x + 1.0 - s
    c = 1e300
    d = 1.0 / b
    h = d
    for i in range(1, 1000):
        a = -i * (i - s)
        b += 2.0
        d = a * d + b
        if abs(d) < 1e-300:
            d = 1e-300
        c = b + a / c
        if abs(c) < 1e-300:
            c = 1e-300
        d = 1.0 / d
        delta = c * d
        h *= delta
        if abs(delta - 1.0) < 1e-14:
            break
    return math.exp(-x + s * math.log(x) - gln) * h

def gamma_lower_reg(s, x):
    """P(s,x) = lower regularized incomplete gamma, s>0, x>=0."""
    if x < 0:
        raise ValueError("x must be >= 0")
    if x == 0:
        return 0.0
    if x < s + 1.0:
        return _gser(s, x)
    return 1.0 - _gcf(s, x)

def _betacf(a, b, x):
    """Continued fraction for incomplete beta (NR betacf)."""
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < 1e-300:
        d = 1e-300
    d = 1.0 / d
    h = d
    for m in range(1, 1000):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < 1e-300:
            d = 1e-300
        c = 1.0 + aa / c
        if abs(c) < 1e-300:
            c = 1e-300
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < 1e-300:
            d = 1e-300
        c = 1.0 + aa / c
        if abs(c) < 1e-300:
            c = 1e-300
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-14:
            break
    return h

def beta_reg(a, b, x):
    """I_x(a,b) = regularized incomplete beta, 0<=x<=1, a,b>0."""
    if x <= 0:
        return 0.0
    if x >= 1:
        return 1.0
    # symmetry: use the representation that converges faster
    bt = math.exp(math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
                  + a * math.log(x) + b * math.log(1.0 - x))
    if x < (a + 1.0) / (a + b + 2.0):
        return bt * _betacf(a, b, x) / a
    return 1.0 - bt * _betacf(b, a, 1.0 - x) / b

# ---------------------------------------------------------------------------
# Distribution CDFs / quantiles
# ---------------------------------------------------------------------------

def norm_cdf(x):
    x = np.asarray(x, dtype=float)
    return 0.5 * (1.0 + np.vectorize(math.erf)(x / math.sqrt(2.0)))

def norm_sf(x):
    return 1.0 - norm_cdf(x)

def chi2_cdf(x, df):
    x = np.asarray(x, dtype=float)
    v = np.vectorize(lambda t: gamma_lower_reg(df / 2.0, t / 2.0))(x)
    return np.where(x <= 0, 0.0, v)

def chi2_sf(x, df):
    return 1.0 - chi2_cdf(x, df)

def t_cdf(t, df):
    """Student-t CDF via the incomplete-beta identity."""
    t = np.asarray(t, dtype=float)
    x = df / (df + t * t)
    ib = np.vectorize(lambda q: beta_reg(df / 2.0, 0.5, q))(x)
    out = np.where(t >= 0, 1.0 - 0.5 * ib, 0.5 * ib)
    return out

def t_sf(t, df):
    return 1.0 - t_cdf(t, df)

# ---------------------------------------------------------------------------
# Descriptives
# ---------------------------------------------------------------------------

def mean(x):
    return float(np.mean(x))

def var(x, ddof=1):
    return float(np.var(x, ddof=ddof))

def std(x, ddof=1):
    return float(np.std(x, ddof=ddof))

def skew(x):
    x = np.asarray(x, dtype=float)
    m, s = x.mean(), x.std(ddof=1)
    return float(np.mean(((x - m) / s) ** 3))

def kurtosis(x):
    """Excess kurtosis (Fisher)."""
    x = np.asarray(x, dtype=float)
    m, s = x.mean(), x.std(ddof=1)
    return float(np.mean(((x - m) / s) ** 4)) - 3.0

# ---------------------------------------------------------------------------
# t-tests (from scratch)
# ---------------------------------------------------------------------------

def ttest_1samp(x, mu=0.0):
    x = np.asarray(x, dtype=float)
    n = len(x)
    m, s = x.mean(), x.std(ddof=1)
    t = (m - mu) / (s / math.sqrt(n))
    p = 2.0 * float(t_sf(abs(t), n - 1))
    return {"t": float(t), "df": n - 1, "p": p, "mean": float(m)}

def ttest_ind(a, b, equal_var=False):
    a = np.asarray(a, dtype=float)
    b = np.asarray(b, dtype=float)
    n1, n2 = len(a), len(b)
    m1, m2 = a.mean(), b.mean()
    if equal_var:
        s1, s2 = a.var(ddof=1), b.var(ddof=1)
        sp = ((n1 - 1) * s1 + (n2 - 1) * s2) / (n1 + n2 - 2)
        se = math.sqrt(sp * (1.0 / n1 + 1.0 / n2))
        df = n1 + n2 - 2
    else:  # Welch
        v1, v2 = a.var(ddof=1) / n1, b.var(ddof=1) / n2
        se = math.sqrt(v1 + v2)
        df = (v1 + v2) ** 2 / (v1 ** 2 / (n1 - 1) + v2 ** 2 / (n2 - 1))
    t = (m1 - m2) / se
    p = 2.0 * float(t_sf(abs(t), df))
    return {"t": float(t), "df": float(df), "p": p,
            "mean1": float(m1), "mean2": float(m2)}

def ttest_rel(a, b):
    return ttest_1samp(np.asarray(a, dtype=float) - np.asarray(b, dtype=float), 0.0)

def cohens_d(a, b):
    a = np.asarray(a, dtype=float)
    b = np.asarray(b, dtype=float)
    n1, n2 = len(a), len(b)
    sp = math.sqrt(((n1 - 1) * a.var(ddof=1) + (n2 - 1) * b.var(ddof=1)) / (n1 + n2 - 2))
    return float((a.mean() - b.mean()) / sp)

# ---------------------------------------------------------------------------
# Chi-square tests (from scratch)
# ---------------------------------------------------------------------------

def chi2_gof(observed, expected):
    o = np.asarray(observed, dtype=float)
    e = np.asarray(expected, dtype=float)
    chi2 = float(np.sum((o - e) ** 2 / e))
    df = len(o) - 1
    return {"chi2": chi2, "df": df, "p": float(chi2_sf(chi2, df))}

def chi2_independence(table):
    t = np.asarray(table, dtype=float)
    row = t.sum(axis=1, keepdims=True)
    col = t.sum(axis=0, keepdims=True)
    exp = row @ col / t.sum()
    chi2 = float(np.sum((t - exp) ** 2 / exp))
    df = (t.shape[0] - 1) * (t.shape[1] - 1)
    n = t.sum()
    k = min(t.shape)
    v = math.sqrt(chi2 / (n * (k - 1))) if k > 1 else 0.0
    return {"chi2": chi2, "df": df, "p": float(chi2_sf(chi2, df)),
            "cramers_v": v}

# ---------------------------------------------------------------------------
# Correlation (from scratch)
# ---------------------------------------------------------------------------

def pearsonr(x, y):
    x = np.asarray(x, dtype=float)
    y = np.asarray(y, dtype=float)
    n = len(x)
    xm, ym = x - x.mean(), y - y.mean()
    r = float(np.sum(xm * ym) / math.sqrt(np.sum(xm ** 2) * np.sum(ym ** 2)))
    r = max(-1.0, min(1.0, r))
    t = r * math.sqrt((n - 2) / (1 - r * r)) if abs(r) < 1 else math.inf
    p = 2.0 * float(t_sf(abs(t), n - 2)) if abs(r) < 1 else 0.0
    return {"r": r, "t": float(t), "df": n - 2, "p": p}

def _ranks(v):
    v = np.asarray(v, dtype=float)
    order = np.argsort(v, kind="mergesort")
    ranks = np.empty(len(v))
    i = 0
    while i < len(v):
        j = i
        while j + 1 < len(v) and v[order[j + 1]] == v[order[i]]:
            j += 1
        ranks[order[i:j + 1]] = (i + j) / 2.0 + 1.0
        i = j + 1
    return ranks

def spearmanr(x, y):
    return pearsonr(_ranks(x), _ranks(y))

def corr_bootstrap_ci(x, y, n_boot=2000, alpha=0.05, seed=0):
    x = np.asarray(x, dtype=float)
    y = np.asarray(y, dtype=float)
    rng = np.random.default_rng(seed)
    n = len(x)
    boots = np.empty(n_boot)
    for i in range(n_boot):
        idx = rng.integers(0, n, n)
        boots[i] = pearsonr(x[idx], y[idx])["r"]
    lo, hi = np.percentile(boots, [100 * alpha / 2, 100 * (1 - alpha / 2)])
    return {"r": pearsonr(x, y)["r"], "ci": (float(lo), float(hi))}

# ---------------------------------------------------------------------------
# Resampling: bootstrap CI, permutation test
# ---------------------------------------------------------------------------

def bootstrap_ci(x, stat=np.mean, n_boot=5000, alpha=0.05, seed=0):
    x = np.asarray(x, dtype=float)
    rng = np.random.default_rng(seed)
    n = len(x)
    boots = np.empty(n_boot)
    for i in range(n_boot):
        boots[i] = stat(x[rng.integers(0, n, n)])
    lo, hi = np.percentile(boots, [100 * alpha / 2, 100 * (1 - alpha / 2)])
    return {"stat": float(stat(x)), "ci": (float(lo), float(hi))}

def permutation_test(a, b, n_perm=10000, seed=0):
    """Two-sided permutation test on difference of means (from scratch)."""
    a = np.asarray(a, dtype=float)
    b = np.asarray(b, dtype=float)
    rng = np.random.default_rng(seed)
    obs = a.mean() - b.mean()
    pooled = np.concatenate([a, b])
    n1 = len(a)
    count = 0
    for _ in range(n_perm):
        rng.shuffle(pooled)
        d = pooled[:n1].mean() - pooled[n1:].mean()
        if abs(d) >= abs(obs):
            count += 1
    return {"diff": float(obs), "p": (count + 1) / (n_perm + 1)}

# ---------------------------------------------------------------------------
# Mann-Kendall trend test + Sen's slope (from scratch)
# ---------------------------------------------------------------------------

def mannkendall(x):
    """Two-sided Mann-Kendall. Returns S, var(S) w/ tie correction, Z, p, trend."""
    x = np.asarray(x, dtype=float)
    n = len(x)
    s = 0
    for i in range(n - 1):
        d = x[i + 1:] - x[i]
        s += int(np.sum(d > 0)) - int(np.sum(d < 0))
    # tie correction
    _, counts = np.unique(x, return_counts=True)
    tie = float(np.sum(counts * (counts - 1) * (2 * counts + 5)))
    var_s = (n * (n - 1) * (2 * n + 5) - tie) / 18.0
    if s > 0:
        z = (s - 1) / math.sqrt(var_s)
    elif s < 0:
        z = (s + 1) / math.sqrt(var_s)
    else:
        z = 0.0
    p = 2.0 * float(norm_sf(abs(z)))
    trend = "increasing" if (s > 0 and p < 0.05) else ("decreasing" if (s < 0 and p < 0.05) else "no trend")
    return {"S": int(s), "var_S": float(var_s), "Z": float(z), "p": p, "trend": trend}

def sens_slope(x):
    """Sen's slope estimator: median of all pairwise slopes."""
    x = np.asarray(x, dtype=float)
    n = len(x)
    slopes = []
    for i in range(n - 1):
        slopes.extend((x[i + 1:] - x[i]) / (np.arange(i + 1, n) - i))
    return float(np.median(slopes))

# ---------------------------------------------------------------------------
# Multiple comparisons
# ---------------------------------------------------------------------------

def benjamini_hochberg(pvals, alpha=0.05):
    p = np.asarray(pvals, dtype=float)
    m = len(p)
    order = np.argsort(p)
    ranked = p[order]
    thresh = (np.arange(1, m + 1) / m) * alpha
    below = np.where(ranked <= thresh)[0]
    k = int(below.max()) + 1 if len(below) else 0
    reject = np.zeros(m, dtype=bool)
    if k:
        reject[order[:k]] = True
    return {"reject": reject, "k": k}

def bonferroni(pvals, alpha=0.05):
    p = np.asarray(pvals, dtype=float)
    return {"reject": p <= alpha / len(p), "alpha_adj": alpha / len(p)}

# ---------------------------------------------------------------------------
# OLS regression with full inference (from scratch)
# ---------------------------------------------------------------------------

def ols(X, y, add_intercept=True):
    X = np.asarray(X, dtype=float)
    y = np.asarray(y, dtype=float)
    if X.ndim == 1:
        X = X[:, None]
    n = len(y)
    if add_intercept:
        X = np.column_stack([np.ones(n), X])
    p = X.shape[1]
    XtX = X.T @ X
    XtX_inv = np.linalg.inv(XtX)
    beta = XtX_inv @ X.T @ y
    resid = y - X @ beta
    df = n - p
    s2 = float(resid @ resid / df)
    se = np.sqrt(np.diag(XtX_inv) * s2)
    tvals = beta / se
    pvals = np.array([2.0 * float(t_sf(abs(t), df)) for t in tvals])
    ss_tot = float(((y - y.mean()) ** 2).sum())
    r2 = 1.0 - float(resid @ resid) / ss_tot
    r2adj = 1.0 - (1 - r2) * (n - 1) / df
    return {"beta": beta, "se": se, "t": tvals, "p": pvals,
            "r2": r2, "r2adj": r2adj, "df": df, "sigma2": s2}

# ---------------------------------------------------------------------------
# Power analysis (normal approximation, from scratch)
# ---------------------------------------------------------------------------

def power_ttest_2samp(d, n, alpha=0.05):
    """Power of two-sample t-test, equal n per group, effect size d (Cohen)."""
    from math import erf
    z_alpha = math.sqrt(2) * _erfinv(1 - alpha)  # two-sided critical
    ncp = d * math.sqrt(n / 2.0)
    Phi = lambda z: 0.5 * (1.0 + erf(z / math.sqrt(2.0)))
    return float(Phi(-z_alpha + ncp) + Phi(-z_alpha - ncp))

def _erfinv(y):
    # Winitzki approximation, good to ~1e-3 -- fine for power calcs
    a = 0.147
    sgn = 1.0 if y >= 0 else -1.0
    y = abs(y)
    t = math.log(1 - y * y)
    u = 2 / (math.pi * a) + t / 2
    return sgn * math.sqrt(math.sqrt(u * u - t / a) - u)

def n_for_power(d, power=0.8, alpha=0.05):
    """Sample size per group for two-sample t-test to hit target power."""
    n = 2
    while power_ttest_2samp(d, n, alpha) < power and n < 10_000_000:
        n = int(n * 1.2) + 1
    lo, hi = 2, n
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if power_ttest_2samp(d, mid, alpha) >= power:
            hi = mid
        else:
            lo = mid
    return hi
