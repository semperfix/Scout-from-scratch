"""heat.py -- NWS Rothfusz heat-index calculation and danger bands.

Implements the National Weather Service heat-index regression (Rothfusz 1990,
as used on weather.gov): the full multiple-regression equation with the two
low/high-humidity adjustments, falling back to the simple Steadman formula
when the result is below 80 degF. Also maps the result to the four NWS danger
bands and gives plain-English work guidance.
"""


def heat_index(temp_f, rh_pct):
    """Heat index in degF from air temperature (degF) and relative humidity (%).

    Uses the Rothfusz regression; applies the NWS low-humidity and
    high-humidity adjustments; uses the simple formula below 80 degF.
    """
    t, r = float(temp_f), float(rh_pct)
    # Simple (Steadman) formula first -- the NWS uses this when HI < 80.
    simple = 0.5 * (t + 61.0 + ((t - 68.0) * 1.2) + (r * 0.094))
    hi = (-42.379 + 2.04901523 * t + 10.14333127 * r
          - 0.22475541 * t * r - 0.00683783 * t * t
          - 0.05481717 * r * r + 0.00122874 * t * t * r
          + 0.00085282 * t * r * r - 0.00000199 * t * t * r * r)
    if hi < 80:
        return (simple + t) / 2.0
    # Low-humidity adjustment: RH < 13% and 80 <= T <= 112.
    if r < 13 and 80 <= t <= 112:
        import math
        hi -= ((13 - r) / 4.0) * math.sqrt((17 - abs(t - 95.0)) / 17.0)
    # High-humidity adjustment: RH > 85% and 80 <= T <= 87.
    elif r > 85 and 80 <= t <= 87:
        hi += ((r - 85) / 10.0) * ((87 - t) / 5.0)
    return hi


def danger_band(hi):
    """NWS heat danger band for a heat-index value (degF).

    Returns (band_name, description) with the four standard bands.
    """
    hi = float(hi)
    if hi < 80:
        return ("LOW", "below heat-advisory concern")
    if hi < 91:
        return ("CAUTION", "fatigue possible with prolonged exposure/activity")
    if hi < 104:
        return ("EXTREME CAUTION", "heat stroke, cramps, or exhaustion possible")
    if hi < 126:
        return ("DANGER", "heat cramps/exhaustion likely; heat stroke possible")
    return ("EXTREME DANGER", "heat stroke highly likely")


# Work guidance keyed to the danger band, aimed at outdoor physical labor
# (e.g. tree work in the Georgia heat).
WORK_GUIDANCE = {
    "LOW": ("Normal day. Drink water, keep an eye on the sky -- "
            "heat index under 80F."),
    "CAUTION": ("Pace yourself. Water every 20-30 min, take shade breaks. "
                "Watch for early fatigue."),
    "EXTREME CAUTION": ("Serious heat. Water + electrolytes, mandatory shade "
                        "breaks every hour, buddy-check for cramps/dizziness. "
                        "Front-load the hard work before noon."),
    "DANGER": ("Dangerous. If you must work: start at first light, quit by "
               "early afternoon, shade every 30-45 min, ice water on hand. "
               "Any dizziness/nausea = stop immediately."),
    "EXTREME DANGER": ("Do not do physical outdoor work. Heat stroke is "
                       "likely, not just possible. Reschedule the job."),
}


def work_guidance(hi):
    """Plain-English work guidance string for a heat-index value."""
    band, _ = danger_band(hi)
    return WORK_GUIDANCE[band]


def apparent_series(temps_f, rhs_pct):
    """Heat-index series from parallel temp/RH arrays."""
    return [heat_index(t, r) for t, r in zip(temps_f, rhs_pct)]
