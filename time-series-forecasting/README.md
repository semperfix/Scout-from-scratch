# Time-Series Analysis & Forecasting From Scratch

> **Status: writeup only — code is being rebuilt.** The original working code
> from this expedition lived in a temporary directory that no longer exists.
> What's below is an accurate description of what was built and learned; the
> implementation will be re-created and published here.

## What this skill covers

Numpy-only statistics toolkit: ACF, PACF via Levinson-Durbin, least-squares AR(p) with AIC/BIC order selection, multi-step forecasts with prediction intervals from MA(∞) psi-weights, classical additive decomposition (centered-MA trend), grid-searched Holt-Winters, NWS Rothfusz heat index, walk-forward backtesting, MAD-based anomaly flags. Applied to a real 1,011-day Bloomingdale GA heat-index series (hourly T/RH → daily-max HI): honest 5-model backtest over 12 monthly origins at 7-day horizon — AR(14) won at RMSE 7.86°F. Earned insights: a trailing MA mislabeled "centered" injects exactly (m−1)/2×slope of bias; AIC keeps adding lags while held-out error rises (in-sample σ fell, RMSE rose 7.86→8.80 — always confirm on held-out origins); Holt-Winters with 365 seasons and <3 cycles memorizes noise unless smoothing params are tiny (22.48→9.36 RMSE); the anomaly model confidently hallucinated a cold front the NWP physics forecast says doesn't exist — extrapolation invents regime changes. The `heatcheck` CLI gives a 7-day heat-safety outlook with NWS bands and tree-work guidance, plus spot checks (`python3 heatcheck.py 96 65` → 121°F DANGER). Validated 22/22 synthetic checks. The tool for "how hot will the work days be, and how much should I trust that number" — pairs with the ML skill's evaluation discipline.

## Planned tool

A from-scratch, zero-dependency implementation with a command-line entry point,
following the same pattern as the other tools in this repo: hand-rolled parsing,
validation against real-world data and reference implementations, and a triage
or analysis CLI.

## Source material

See `SKILLS.md` (skill #26) in the repo root for the full expedition notes.
