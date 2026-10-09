#!/usr/bin/env python3
"""heatcheck.py -- heat-safety outlook CLI.

Spot check:
    python3 heatcheck.py TEMP_F RH_PCT      # e.g. python3 heatcheck.py 96 65

7-day forecast demo (synthetic daily-max heat-index series):
    python3 heatcheck.py --forecast

The forecast demo builds a synthetic 400-day heat-index series (annual wave +
weekly pattern + AR(2) weather noise), fits an AIC-selected AR model, runs a
walk-forward backtest, flags anomalies, and prints a 7-day outlook with NWS
danger bands and work guidance.
"""

import argparse
import sys

import numpy as np

import heat
import ts


def spot_check(temp_f, rh_pct):
    hi = heat.heat_index(temp_f, rh_pct)
    band, desc = heat.danger_band(hi)
    print(f"temp {temp_f:.0f}F, RH {rh_pct:.0f}%")
    print(f"heat index: {hi:.0f}F")
    print(f"band: {band} -- {desc}")
    print(f"guidance: {heat.work_guidance(hi)}")


def synthetic_hi_series(n=400, seed=7):
    """Synthetic daily-max heat-index series: annual wave + weekly ripple +
    AR(2) weather noise, seeded for determinism."""
    rng = np.random.default_rng(seed)
    t = np.arange(n)
    seasonal = 18 * np.sin(2 * np.pi * t / 365.0 - 1.2) + 4 * np.sin(2 * np.pi * t / 7.0)
    e = rng.standard_normal(n)
    noise = np.zeros(n)
    for i in range(2, n):
        noise[i] = 0.65 * noise[i - 1] - 0.25 * noise[i - 2] + 1.6 * e[i]
    return 88 + seasonal + noise


def forecast_demo(horizon=7):
    y = synthetic_hi_series()
    print(f"series: {len(y)} synthetic daily-max heat-index days\n")

    # Model selection + fit. BIC, not AIC: on 400 points AIC keeps adding
    # lags that fit noise (a real overfitting trap -- see README).
    sel = ts.select_ar_order(y, max_p=20, criterion="bic")
    p = sel["order"]
    fit = ts.ar_fit(y, p)
    print(f"AR order by BIC: {p}  (BIC={sel['score']:.1f})")
    print("coefficients:", " ".join(f"{c:+.3f}" for c in fit["coef"]))
    print(f"residual sigma: {np.sqrt(fit['sigma2']):.2f}F\n")

    # Walk-forward backtest: monthly origins, 7-day horizon.
    origins = list(range(len(y) - 365, len(y) - horizon, 30))

    def fit_fn(tr):
        o = ts.select_ar_order(tr, max_p=14)["order"]
        return (o, ts.ar_fit(tr, o))

    def fc_fn(model, tr):
        o, f = model
        return ts.ar_forecast(tr, f, horizon)["mean"]

    bt = ts.walk_forward_backtest(y, fit_fn, fc_fn, horizon, origins)
    print(f"backtest: {bt['n_origins']} monthly origins, {horizon}-day horizon")
    print(f"  RMSE {bt['rmse']:.2f}F   MAE {bt['mae']:.2f}F\n")

    # Anomaly flags on the last 60 days.
    anom = ts.mad_anomalies(y[-60:])
    n_flag = int(anom["flags"].sum())
    print(f"anomaly scan (last 60 days): {n_flag} flagged day(s)")

    # 7-day outlook with prediction intervals + NWS bands.
    fc = ts.ar_forecast(y, fit, horizon)
    print(f"\n7-day heat-index outlook (95% prediction interval):")
    print(f"{'day':<5}{'HI':>7}{'low':>7}{'high':>7}  band            guidance")
    for j in range(horizon):
        hi = fc["mean"][j]
        band, _ = heat.danger_band(hi)
        print(f"+{j+1:<4}{hi:7.1f}{fc['lower'][j]:7.1f}{fc['upper'][j]:7.1f}  "
              f"{band:<15} {heat.work_guidance(hi)}")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Heat-safety outlook: spot heat-index check or 7-day "
                    "AR-forecast demo with NWS danger bands.")
    ap.add_argument("temp_f", nargs="?", type=float,
                    help="air temperature in degF (spot-check mode)")
    ap.add_argument("rh_pct", nargs="?", type=float,
                    help="relative humidity %% (spot-check mode)")
    ap.add_argument("--forecast", action="store_true",
                    help="run the 7-day forecast demo on a synthetic series")
    args = ap.parse_args(argv)

    if args.forecast:
        forecast_demo()
        return 0
    if args.temp_f is not None and args.rh_pct is not None:
        spot_check(args.temp_f, args.rh_pct)
        return 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
