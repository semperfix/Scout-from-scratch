"""LSB steganalysis from scratch: chi-square PoV attack + RS analysis.

1. Chi-square (Westfeld & Pfitzmann): sequential LSB embedding equalizes the
   frequencies inside each Pair of Values (2k, 2k+1). The test measures how
   close observed pair counts are to the equalized expectation; p ~ 1 means
   "embedded". Scanning growing prefixes reveals WHERE a sequential payload ends.
2. RS analysis (Fridrich, Goljan, Du): groups of adjacent pixels are flipped
   with masks M / -M and classified Regular/Singular/Unusable by a noise
   discrimination function. Embedding rate p falls out of a quadratic whose
   coefficients are the four R-S differences (measured on image and LSB-flipped
   "negative"). Works against spread embedding too.
"""
import math

# ---------- chi-square machinery: regularized lower gamma P(s, x) ----------

def _gamma_p_series(s, x):
    gln = math.lgamma(s)
    ap = s
    total = 1.0 / s
    delta = total
    n = 1
    while True:
        ap += 1
        delta *= x / ap
        total += delta
        n += 1
        if abs(delta) < abs(total) * 1e-12 or n > 1000:
            break
    return total * math.exp(-x + s * math.log(x) - gln)


def _gamma_p_cf(s, x):
    # continued fraction for Q(s,x) = 1 - P(s,x), good for x >= s+1
    gln = math.lgamma(s)
    eps, tiny = 1e-12, 1e-300
    b = x + 1.0 - s
    c = 1.0 / tiny
    d = 1.0 / b if abs(b) > tiny else 1.0 / tiny
    h = d
    i = 1
    while True:
        an = -i * (i - s)
        b += 2.0
        d = an * d + b
        d = 1.0 / d if abs(d) > tiny else 1.0 / tiny
        c = b + an / c
        c = c if abs(c) > tiny else tiny
        cd = c * d
        h *= cd
        i += 1
        if abs(cd - 1.0) < eps or i > 1000:
            break
    return 1.0 - math.exp(-x + s * math.log(x) - gln) * h


def gamma_p(s, x):
    """Regularized lower incomplete gamma P(s, x); = chi2 CDF for s=df/2, x=chi2/2."""
    if x <= 0:
        return 0.0
    if x < s + 1:
        return _gamma_p_series(s, x)
    return _gamma_p_cf(s, x)


# ---------- chi-square PoV attack ----------

def _pov_chi2_p(samples, first_pair=0):
    """P(embedded) for one channel's byte samples via PoV equalization.

    first_pair: skip pairs below this k (e.g. 1 to exclude the (0,1) pair
    when zeros/ones were never usable carriers).
    """
    hist = [0] * 256
    for v in samples:
        hist[v] += 1
    chi2, df = 0.0, 0
    for k in range(first_pair, 128):
        a, b = hist[2 * k], hist[2 * k + 1]
        e = (a + b) / 2.0
        if e > 0:
            chi2 += (a - e) ** 2 / e
            df += 1
    df -= 1
    if df <= 0:
        return 0.0
    return 1.0 - gamma_p(df / 2.0, chi2 / 2.0)


def chi_square_scan(flat, windows=(0.05, 0.1, 0.2, 0.4, 0.6, 0.8, 1.0)):
    """P(embedded) computed on growing prefixes of the channel stream.

    Sequential embedding: p ~ 1.0 for prefixes inside the payload region,
    then collapses once the window extends past it -> localizes payload end.
    """
    return [(w, _pov_chi2_p(flat[:max(256, int(len(flat) * w))])) for w in windows]


# ---------- RS analysis ----------

def _f1(v):
    return v ^ 1                       # 0<->1, 2<->3, ...


def _fm1(v):
    # F_{-1}: pairs (2i-1, 2i): even v -> v-1 (0 -> -1, fine for statistics),
    # odd v -> v+1. NOTE: earlier version had this backwards (= F_1 again).
    return v - 1 if v % 2 == 0 else v + 1


def _disc(group):
    return sum(abs(group[i + 1] - group[i]) for i in range(len(group) - 1))


def _rs_counts(seq, mask):
    """Fractions (R_M, S_M, R_-M, S_-M) over ALL groups (unusable in denominator)."""
    n = len(mask)
    groups = [seq[i:i + n] for i in range(0, len(seq) - n + 1, n)]
    total = len(groups)
    rm = sm = rmm = smm = 0
    neg_mask = [-x for x in mask]
    for g in groups:
        f0 = _disc(g)
        fm = _disc([(_f1(v) if m == 1 else v) for v, m in zip(g, mask)])
        fmm = _disc([(_fm1(v) if m == -1 else v) for v, m in zip(g, neg_mask)])
        if fm > f0:
            rm += 1
        elif fm < f0:
            sm += 1
        if fmm > f0:
            rmm += 1
        elif fmm < f0:
            smm += 1
    if total == 0:
        return 0, 0, 0, 0
    return rm / total, sm / total, rmm / total, smm / total


def _rs_estimate(seq):
    """Embedding-rate estimate for one channel via the RS quadratic."""
    mask = [0, 1, 1, 0]
    rm, sm, rmm, smm = _rs_counts(seq, mask)
    neg = [_f1(v) for v in seq]                    # LSB-flipped "dual"
    nrm, nsm, nrmm, nsmm = _rs_counts(neg, mask)
    # Patent US6831991B2 mapping (M = [0,1,1,0] mask):
    #   d0  = R_M  - S_M   on the suspect image      (point p/2)
    #   d1  = R_M  - S_M   on the flipped image      (point 1-p/2)
    #   d_0 = R_-M - S_-M  on the suspect image
    #   d_1 = R_-M - S_-M  on the flipped image
    # NOTE: an earlier version swapped d1 and d_0; the patent text settled it.
    d0, d1 = rm - sm, nrm - nsm
    dm0, dm1 = rmm - smm, nrmm - nsmm
    a = 2 * (d1 + d0)
    b = dm0 - dm1 - d1 - 3 * d0
    c = d0 - dm0
    if abs(a) < 1e-12:
        return 0.0, (rm, sm, rmm, smm)
    disc = b * b - 4 * a * c
    if disc < 0:
        return 0.0, (rm, sm, rmm, smm)
    roots = [(-b + math.sqrt(disc)) / (2 * a), (-b - math.sqrt(disc)) / (2 * a)]
    x = min(roots, key=abs)          # root with smaller ABSOLUTE value (patent)
    p = x / (x - 0.5) if abs(x - 0.5) > 1e-9 else 0.0
    p = max(0.0, min(1.0, p))
    return p, (rm, sm, rmm, smm)


def rs_analyze(flat):
    """RS embedding-rate estimate per channel (R, G, B separately)."""
    chans = [flat[i::3] for i in range(3)]
    return [_rs_estimate(c)[0] for c in chans]


# ---------- LSB-plane visual attack (quantified) ----------

def lsb_plane_stats(flat):
    """Fraction of 1-bits and local unpredictability of the LSB plane.

    Natural LSB planes keep scene structure (low local entropy); embedded
    random bits look like white noise (~50% ones, high local entropy).
    """
    bits = [v & 1 for v in flat]
    frac1 = sum(bits) / len(bits)
    # local entropy: unpredictability of each bit from its left neighbor
    agree = sum(1 for i in range(1, len(bits)) if bits[i] == bits[i - 1])
    return {"frac_ones": frac1, "neighbor_agreement": agree / (len(bits) - 1)}


def smooth_lsb_agreement(flat, w, h, var_thresh=6.0):
    """LSB neighbor-agreement restricted to per-channel low-variance 3x3
    neighborhoods. In smooth regions of a natural image, neighboring LSBs
    agree more often than chance; embedded random bits push this toward 0.5.
    Weak signal: cover-dependent, use only as supporting evidence."""
    import numpy as np
    arr = np.array(flat, dtype=float).reshape(h, w, 3)
    agree = n = 0
    for c in range(3):
        ch = arr[:, :, c]
        pad = np.pad(ch, 1, mode="edge")
        for y in range(h):
            for x in range(1, w):
                win = pad[y:y + 3, x - 1:x + 2]
                if win.var() < var_thresh:
                    if (int(ch[y, x]) & 1) == (int(ch[y, x - 1]) & 1):
                        agree += 1
                    n += 1
    return agree / n if n else 0.5
