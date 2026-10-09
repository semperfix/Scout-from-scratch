# Time-Series Analysis & Forecasting From Scratch

Numpy-only statistics toolkit: ACF, PACF via Levinson-Durbin recursion,
least-squares AR(p) fitting with AIC/BIC order selection, multi-step forecasts
with prediction intervals derived from MA(∞) psi-weights, classical additive
decomposition (centered moving-average trend), grid-searched additive
Holt-Winters, the NWS Rothfusz heat-index regression, walk-forward
backtesting (RMSE/MAE), and MAD-based anomaly flags. The `heatcheck` CLI gives
a 7-day heat-safety outlook with NWS danger bands and outdoor-work guidance.

## Dependencies

- **Python 3** (3.10+ recommended)
- **numpy** (`pip install numpy`) — needed for everything (`ts.py`,
  `heat.py`, `heatcheck.py`). This one is genuinely numerical: matrix
  least-squares, convolutions, and the Levinson-Durbin recursion.

## How to run

**Spot heat-index check** (entry point `heatcheck.py`):

```bash
python3 heatcheck.py 96 65        # 96°F air temp, 65% relative humidity
```

**7-day forecast demo** (synthetic daily-max heat-index series):

```bash
python3 heatcheck.py --forecast
```

**Use the toolkit as a library:**

```python
import numpy as np
import ts, heat

y = np.loadtxt("daily_max_hi.csv")

sel = ts.select_ar_order(y, max_p=20, criterion="bic")
fit = ts.ar_fit(y, sel["order"])
fc  = ts.ar_forecast(y, fit, h=7)          # mean / lower / upper (95% PI)

# Walk-forward backtest over monthly origins at 7-day horizon:
bt = ts.walk_forward_backtest(
    y,
    fit_fn=lambda tr: ts.ar_fit(tr, ts.select_ar_order(tr, max_p=14)["order"]),
    forecast_fn=lambda m, tr: ts.ar_forecast(tr, m, 7)["mean"],
    horizon=7, origins=range(len(y) - 365, len(y) - 7, 30))
print(bt["rmse"], bt["mae"])

# Classical decomposition, Holt-Winters, anomalies:
d  = ts.classical_decompose(y, period=7)
hw = ts.holt_winters_grid(y, m=7, h=7)
flags = ts.mad_anomalies(y)["flags"]

print(heat.heat_index(96, 65))             # 121.0
print(heat.danger_band(121.0))             # ('DANGER', ...)
```

## Example

```bash
$ python3 heatcheck.py 96 65
temp 96F, RH 65%
heat index: 121F
band: DANGER -- heat cramps/exhaustion likely; heat stroke possible
guidance: Dangerous. If you must work: start at first light, quit by early
afternoon, shade every 30-45 min, ice water on hand. Any dizziness/nausea =
stop immediately.

$ python3 heatcheck.py --forecast
series: 400 synthetic daily-max heat-index days

AR order by BIC: 17  (BIC=1602.0)
coefficients: +0.900 -0.319 +0.084 +0.010 +0.078 ...
residual sigma: 1.69F

backtest: 12 monthly origins, 7-day horizon
  RMSE 8.28F   MAE 4.30F

anomaly scan (last 60 days): 0 flagged day(s)

7-day heat-index outlook (95% prediction interval):
day       HI    low   high  band            guidance
+1      78.5   75.2   81.8  LOW             Normal day. ...
...
```

## Key learnings

- **AIC overfits AR order; BIC is the honest selector here.** On 2,000 points
  of clean AR(2) data, AIC picked order 8 (in-sample σ keeps falling while
  held-out error rises). BIC nailed order 2. Always confirm order selection
  on held-out origins — a lesson that cost a full backtest run on the original
  expedition (RMSE rose 7.86→8.80 chasing AIC lags).
- **Prediction intervals come from the MA(∞) representation, not from the
  residual σ alone.** Variance at horizon *h* is σ²·Σψ²; with stationary AR
  roots the ψ-weights decay, so intervals widen and then flatten — exactly
  what the smoke test asserts.
- **A "centered" moving average that is actually trailing injects bias.**
  Shifting the window by (m−1)/2 on a trending series adds (m−1)/2 × slope
  of phantom trend. `centered_ma` requires an odd window and NaNs the edges
  so the decomposition can't silently lie.
- **The Levinson-Durbin recursion is PACF, not an AR fit.** Each reflection
  coefficient λₖ *is* the partial autocorrelation at lag k — no matrix
  inversion needed. On the AR(2) fixture, PACF cuts off cleanly after lag 2.
- **The NWS regression needs its two adjustments to match the chart.**
  96°F/65% gives 121°F only with the full Rothfusz equation; below 80°F the
  NWS falls back to the simple Steadman formula, and the low-RH (<13%) /
  high-RH (>85%) adjustments matter at the edges.

## Files

| File | What it does |
|---|---|
| `heatcheck.py` | **Entry point**: spot heat-index check or `--forecast` 7-day outlook demo |
| `ts.py` | ACF, PACF via Levinson-Durbin, AR(p) least-squares + AIC/BIC, AR forecasts with psi-weight prediction intervals, classical additive decomposition, Holt-Winters grid search, walk-forward backtest, MAD anomalies |
| `heat.py` | NWS Rothfusz heat-index regression (+ RH adjustments, <80°F fallback), NWS danger bands, outdoor-work guidance strings |

## Limitations

- AR models are linear and stationary-only: no differencing/ARIMA, no
  regime changes, no exogenous regressors. The forecast demo's synthetic
  series has a strong annual wave that an AR soaks up with many lags —
  a seasonal model (or Holt-Winters with m=365 and tiny smoothing params)
  is the honest tool for real annual data.
- Prediction intervals assume Gaussian innovations; real heat-index errors
  are skewed on extreme days.
- Holt-Winters grid search is coarse (a few α/β/γ values) and additive-only;
  with fewer than ~3 seasonal cycles it memorizes noise.
- Heat index is defined for shade, light-wind conditions; sun and exertion
  push the real feel higher.
