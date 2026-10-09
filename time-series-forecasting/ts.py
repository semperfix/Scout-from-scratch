"""ts.py -- from-scratch time-series statistics toolkit (numpy only).

Covers: ACF, PACF via Levinson-Durbin recursion, least-squares AR(p) fitting
with AIC/BIC order selection, multi-step forecasts with prediction intervals
derived from MA(infinity) psi-weights, classical additive decomposition
(centered moving-average trend), additive Holt-Winters with a grid-searched
(alpha, beta, gamma), walk-forward backtesting (RMSE), and MAD-based anomaly
flagging.

Conventions: input series are 1-D numpy arrays. All forecasts carry a 95%
Gaussian prediction interval unless stated otherwise.
"""

import numpy as np


# --------------------------------------------------------------------------
# Autocorrelation
# --------------------------------------------------------------------------

def acf(x, max_lag):
    """Autocorrelation function at lags 0..max_lag (biased normalization)."""
    x = np.asarray(x, dtype=float)
    n = len(x)
    xc = x - x.mean()
    denom = np.dot(xc, xc)
    out = np.empty(max_lag + 1)
    for k in range(max_lag + 1):
        out[k] = np.dot(xc[: n - k], xc[k:]) / denom if denom > 0 else 0.0
    return out


def pacf_levinson(x, max_lag):
    """Partial autocorrelation via the Levinson-Durbin recursion.

    pacf[k] is the last coefficient of an AR(k) fit -- the direct correlation
    between x[t] and x[t-k] after removing the influence of the in-between
    lags. Returns array indexed by lag 0..max_lag (index 0 unused, = 1.0).
    """
    x = np.asarray(x, dtype=float)
    r = acf(x, max_lag)
    pacf = np.zeros(max_lag + 1)
    pacf[0] = 1.0
    if r[0] == 0:
        return pacf
    # Normalize to autocorrelation form.
    r = r / r[0]
    phi = np.zeros(max_lag + 1)   # current AR coefficients (1-indexed)
    err = 1.0
    for k in range(1, max_lag + 1):
        # Reflection (partial correlation) coefficient.
        acc = r[k]
        for j in range(1, k):
            acc -= phi[j] * r[k - j]
        lam = acc / err
        # Update AR coefficients: phi_new[j] = phi[j] - lam*phi[k-j].
        new_phi = phi.copy()
        for j in range(1, k):
            new_phi[j] = phi[j] - lam * phi[k - j]
        new_phi[k] = lam
        err *= (1.0 - lam * lam)
        phi = new_phi
        pacf[k] = lam
        if err <= 0:
            break
    return pacf


# --------------------------------------------------------------------------
# AR(p) least-squares fitting + order selection
# --------------------------------------------------------------------------

def ar_fit(y, p, include_intercept=True):
    """Least-squares AR(p) fit. Returns dict with coef, intercept, sigma2, nobs."""
    y = np.asarray(y, dtype=float)
    n = len(y)
    if p < 1 or n <= p:
        raise ValueError("need more observations than lags")
    # Design matrix of lagged values: row t holds y[t-1..t-p].
    X = np.column_stack([y[p - k: n - k] for k in range(1, p + 1)])
    yt = y[p:]
    if include_intercept:
        X = np.column_stack([np.ones(len(yt)), X])
    beta, *_ = np.linalg.lstsq(X, yt, rcond=None)
    resid = yt - X @ beta
    sigma2 = float(np.dot(resid, resid) / (len(yt) - X.shape[1]))
    if include_intercept:
        return {"coef": beta[1:], "intercept": float(beta[0]),
                "sigma2": sigma2, "nobs": len(yt), "p": p}
    return {"coef": beta, "intercept": 0.0, "sigma2": sigma2,
            "nobs": len(yt), "p": p}


def aic_bic(y, p, criterion="aic"):
    """AIC or BIC for an AR(p) fit (Gaussian log-likelihood, nobs = effective n)."""
    fit = ar_fit(y, p)
    n, k = fit["nobs"], p + 2  # p coefs + intercept + sigma2
    ll = -0.5 * n * (np.log(2 * np.pi * fit["sigma2"]) + 1.0)
    if criterion == "aic":
        return 2 * k - 2 * ll
    if criterion == "bic":
        return k * np.log(n) - 2 * ll
    raise ValueError("criterion must be 'aic' or 'bic'")


def select_ar_order(y, max_p=20, criterion="aic"):
    """Pick the AR order minimizing AIC (default) or BIC over 1..max_p."""
    scores = [(p, aic_bic(y, p, criterion)) for p in range(1, max_p + 1)]
    best = min(scores, key=lambda t: t[1])
    return {"order": best[0], "score": best[1], "scores": scores}


# --------------------------------------------------------------------------
# Forecasts with prediction intervals (MA(inf) psi-weights)
# --------------------------------------------------------------------------

def psi_weights(coef, n_terms):
    """MA(infinity) representation of an AR: x_t = mu + sum psi_j e_{t-j}.

    psi_0 = 1, psi_k = sum_{i=1..min(k,p)} phi_i * psi_{k-i}.
    """
    coef = np.asarray(coef, dtype=float)
    p = len(coef)
    psi = np.zeros(n_terms)
    psi[0] = 1.0
    for k in range(1, n_terms):
        s = 0.0
        for i in range(1, min(k, p) + 1):
            s += coef[i - 1] * psi[k - i]
        psi[k] = s
    return psi


def ar_forecast(y, fit, h, alpha=0.05):
    """Multi-step forecast from an AR fit.

    Returns dict: mean (h,), lower (h,), upper (h,) -- a (1-alpha) prediction
    interval whose variance at horizon j is sigma2 * sum_{i<j} psi_i^2.
    z = 1.96 for the default 95% interval (Gaussian innovations).
    """
    y = np.asarray(y, dtype=float)
    coef = np.asarray(fit["coef"], dtype=float)
    p = len(coef)
    mu = fit["intercept"]
    z = 1.96 if abs(alpha - 0.05) < 1e-9 else float(
        __import__("statistics").NormalDist().inv_cdf(1 - alpha / 2))
    psi = psi_weights(coef, h)
    hist = list(y[-p:])  # oldest..newest of the last p observations
    means, lowers, uppers = [], [], []
    cumvar = 0.0
    for j in range(h):
        f = mu + sum(coef[i] * hist[-(i + 1)] for i in range(p))
        cumvar += psi[j] ** 2
        sd = np.sqrt(fit["sigma2"] * cumvar)
        means.append(f)
        lowers.append(f - z * sd)
        uppers.append(f + z * sd)
        hist.append(f)
        hist.pop(0)
    return {"mean": np.array(means), "lower": np.array(lowers),
            "upper": np.array(uppers), "horizon": h}


# --------------------------------------------------------------------------
# Classical additive decomposition
# --------------------------------------------------------------------------

def centered_ma(x, m):
    """Centered moving average of odd window m (edges become NaN)."""
    x = np.asarray(x, dtype=float)
    if m % 2 == 0:
        raise ValueError("centered MA needs an odd window")
    half = m // 2
    trend = np.full_like(x, np.nan)
    w = np.ones(m) / m
    trend[half: len(x) - half] = np.convolve(x, w, mode="valid")
    return trend


def classical_decompose(x, period):
    """Additive decomposition x = trend + seasonal + resid.

    Trend via centered MA of the seasonal period (period made odd if needed).
    Seasonal indices are the per-position means of the detrended series.
    Returns dict with trend, seasonal (full-length), resid, seasonal_index.
    """
    x = np.asarray(x, dtype=float)
    m = period if period % 2 == 1 else period + 1
    trend = centered_ma(x, m)
    detrended = x - trend
    idx = np.full(period, np.nan)
    for s in range(period):
        vals = detrended[s::period]
        vals = vals[~np.isnan(vals)]
        idx[s] = vals.mean() if len(vals) else 0.0
    idx -= idx.mean()  # seasonal components sum to ~0 over a full cycle
    seasonal = np.tile(idx, int(np.ceil(len(x) / period)))[: len(x)]
    resid = x - trend - seasonal
    return {"trend": trend, "seasonal": seasonal, "resid": resid,
            "seasonal_index": idx}


# --------------------------------------------------------------------------
# Holt-Winters (additive) with grid search
# --------------------------------------------------------------------------

def holt_winters_additive(x, m, alpha, beta, gamma, h=0):
    """Additive Holt-Winters. Returns dict with fitted (in-sample one-step)
    values and, if h>0, a forecast dict like ar_forecast's (no intervals)."""
    x = np.asarray(x, dtype=float)
    n = len(x)
    # Initialize: level = mean of first season, trend = mean step over it,
    # seasonals = deviations from level in the first season.
    level = x[:m].mean()
    trend = (x[m: 2 * m].mean() - x[:m].mean()) / m if n >= 2 * m else 0.0
    seas = x[:m] - level
    fitted = np.empty(n)
    for t in range(n):
        s_idx = t % m
        prev_level = level
        fitted[t] = level + trend + seas[s_idx]
        level = alpha * (x[t] - seas[s_idx]) + (1 - alpha) * (level + trend)
        trend = beta * (level - prev_level) + (1 - beta) * trend
        seas[s_idx] = gamma * (x[t] - level) + (1 - gamma) * seas[s_idx]
    out = {"fitted": fitted, "level": level, "trend": trend, "seas": seas.copy()}
    if h > 0:
        fc = np.array([level + k * trend + seas[(n + k - 1) % m]
                       for k in range(1, h + 1)])
        out["forecast"] = fc
    return out


def holt_winters_grid(x, m, h=0, alphas=None, betas=None, gammas=None):
    """Grid-search (alpha, beta, gamma) minimizing in-sample one-step SSE."""
    alphas = alphas if alphas is not None else [0.1, 0.3, 0.5, 0.7, 0.9]
    betas = betas if betas is not None else [0.05, 0.1, 0.3, 0.5]
    gammas = gammas if gammas is not None else [0.1, 0.3, 0.5, 0.7]
    best, best_params = None, None
    for a in alphas:
        for b in betas:
            for g in gammas:
                r = holt_winters_additive(x, m, a, b, g)
                resid = x - r["fitted"]
                sse = float(np.dot(resid, resid))
                if best is None or sse < best:
                    best, best_params = sse, (a, b, g)
    out = {"params": best_params, "sse": best}
    out.update(holt_winters_additive(x, m, *best_params, h=h))
    return out


# --------------------------------------------------------------------------
# Walk-forward backtesting
# --------------------------------------------------------------------------

def walk_forward_backtest(y, fit_fn, forecast_fn, horizon, origins):
    """Walk-forward backtest.

    fit_fn(train) -> model; forecast_fn(model, train) -> array of `horizon`
    forecasts. `origins` are end indices of each training window.
    Returns dict with per-origin errors and overall RMSE/MAE.
    """
    y = np.asarray(y, dtype=float)
    errs = []
    for end in origins:
        train, actual = y[:end], y[end: end + horizon]
        if len(actual) < horizon:
            continue
        model = fit_fn(train)
        fc = np.asarray(forecast_fn(model, train))[:horizon]
        errs.append(actual - fc)
    errs = np.array(errs)
    return {"errors": errs,
            "rmse": float(np.sqrt(np.mean(errs ** 2))),
            "mae": float(np.mean(np.abs(errs))),
            "n_origins": len(errs)}


# --------------------------------------------------------------------------
# MAD-based anomaly flags
# --------------------------------------------------------------------------

def mad_anomalies(x, threshold=3.5):
    """Flag anomalies via the modified z-score: 0.6745*(x-median)/MAD.

    Returns dict with boolean flags and the scores. Robust to the very
    outliers it is trying to find (unlike mean/std z-scores).
    """
    x = np.asarray(x, dtype=float)
    med = np.median(x)
    mad = np.median(np.abs(x - med))
    if mad == 0:
        return {"flags": np.zeros(len(x), dtype=bool),
                "scores": np.zeros(len(x)), "median": med, "mad": mad}
    scores = 0.6745 * (x - med) / mad
    return {"flags": np.abs(scores) > threshold, "scores": scores,
            "median": med, "mad": mad}
