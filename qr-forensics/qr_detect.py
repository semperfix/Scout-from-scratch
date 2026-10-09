"""QR detection: photograph/PNG -> module matrix.

Pipeline: grayscale -> Otsu threshold -> finder-pattern search via the
1:1:3:1:1 run-length signature (horizontal scan + vertical cross-check) ->
cluster into 3 finders -> order them -> estimate dimension -> locate the
bottom-right alignment pattern (v2+) or extrapolate (v1) -> 4-point
projective homography -> per-module sampling -> Otsu on samples.

Limitation: the run-length scan assumes a roughly upright code (rotation
within ~15 degrees; exact multiples of 90 degrees are fine). Heavy
perspective or curved surfaces are out of scope.
"""
import numpy as np
from PIL import Image

from qr_tables import VERSIONS


class QRDetectError(Exception):
    pass


# --------------------------------------------------------------------------
# basic image helpers
# --------------------------------------------------------------------------

def _grayscale(img):
    if isinstance(img, str):
        img = Image.open(img)
    return np.asarray(img.convert("L"), dtype=np.float64)


def _otsu_threshold(gray):
    hist, _ = np.histogram(gray, bins=256, range=(0, 256))
    hist = hist.astype(np.float64)
    total = gray.size
    sum_all = np.dot(np.arange(256), hist)
    sum_b = 0.0
    w_b = 0.0
    best_t, best_var = 0, -1.0
    for t in range(256):
        w_b += hist[t]
        if w_b == 0:
            continue
        w_f = total - w_b
        if w_f == 0:
            break
        sum_b += t * hist[t]
        m_b = sum_b / w_b
        m_f = (sum_all - sum_b) / w_f
        var = w_b * w_f * (m_b - m_f) ** 2
        if var > best_var:
            best_var, best_t = var, t
    return best_t


def _runs(line):
    """Run-length encode a 1-D binary array -> list of (start, length, value)."""
    runs = []
    start = 0
    cur = line[0]
    for i in range(1, len(line)):
        if line[i] != cur:
            runs.append((start, i - start, cur))
            start, cur = i, line[i]
    runs.append((start, len(line) - start, cur))
    return runs


def _ratio_match(lens, expected, tol=0.6):
    """Check run lengths against expected ratios (relative tolerance)."""
    total = sum(lens)
    unit = total / sum(expected)
    return all(abs(l - e * unit) <= e * unit * tol for l, e in zip(lens, expected))


# --------------------------------------------------------------------------
# finder-pattern search
# --------------------------------------------------------------------------

def _scan_finders_1d(line, expected=(1, 1, 3, 1, 1)):
    """Return [(center, module_size)] for 1:1:3:1:1 patterns along a line."""
    runs = _runs(line)
    out = []
    for i in range(len(runs) - 4):
        win = runs[i:i + 5]
        if [w[2] for w in win] != [1, 0, 1, 0, 1]:  # dark-light-dark-light-dark
            continue
        lens = [w[1] for w in win]
        if not _ratio_match(lens, expected):
            continue
        cx = win[0][0] + lens[0] + lens[1] + lens[2] / 2.0
        out.append((cx, sum(lens) / 7.0))
    return out


def _find_finder_candidates(bin_img):
    h, w = bin_img.shape
    cands = []
    for y in range(h):
        for cx, mod_h in _scan_finders_1d(bin_img[y]):
            x = int(round(cx))
            if x < 0 or x >= w:
                continue
            # a column can cross two finders (TL and BL share x); pair the
            # horizontal hit with the vertical hit nearest to this row
            vhits = _scan_finders_1d(bin_img[:, x])
            best = min(vhits, key=lambda hv: abs(hv[0] - y), default=None)
            if best is not None and abs(best[1] - mod_h) / mod_h < 0.3:
                cands.append((cx, best[0], (mod_h + best[1]) / 2))
    return cands


def _cluster(cands):
    clusters = []  # each: [sx, sy, ss, n]
    for x, y, s in cands:
        placed = False
        for cl in clusters:
            cx, cy, cs, n = cl[0] / cl[3], cl[1] / cl[3], cl[2] / cl[3], cl[3]
            if abs(x - cx) < cs * 2 and abs(y - cy) < cs * 2:
                cl[0] += x
                cl[1] += y
                cl[2] += s
                cl[3] += 1
                placed = True
                break
        if not placed:
            clusters.append([x, y, s, 1])
    clusters.sort(key=lambda cl: -cl[3])
    return [(c[0] / c[3], c[1] / c[3], c[2] / c[3], c[3]) for c in clusters]


def _pick_finder_triple(clusters):
    """Pick the 3 clusters that are the real finders.

    Random data modules can fake the 1:1:3:1:1 signature, and a tiny fake
    triple can out-score the true one on pure shape. So: keep triples with
    plausible right-isosceles geometry (legs equal, hyp = leg*sqrt(2)),
    then pick by cluster support (true finders collect far more scan hits
    than fakes). clusters are (x, y, module_size, n_hits).
    """
    import math
    import itertools
    scored = []
    for triple in itertools.combinations(clusters[:10], 3):
        pts = [np.array(t[:2]) for t in triple]
        d = sorted([math.dist(pts[0], pts[1]),
                    math.dist(pts[1], pts[2]),
                    math.dist(pts[0], pts[2])])
        if d[0] < 1e-9:
            continue
        err = abs(d[0] - d[1]) / d[0] + abs(d[2] / d[0] - math.sqrt(2))
        support = sum(t[3] for t in triple)
        scored.append((err, support, triple))
    good = [s for s in scored if s[0] <= 0.25]
    if not good:
        best = min(scored, key=lambda s: s[0], default=None)
        raise QRDetectError("no plausible finder triple (best shape error "
                            f"{best[0]:.2f}" if best else "no triples)")
    # real finders are the same physical size (up to mild perspective);
    # fake clusters vary. Weight size agreement strongly.
    def combined(s):
        err, support, triple = s
        sizes = [t[2] for t in triple]
        size_err = (max(sizes) - min(sizes)) / (sum(sizes) / 3)
        return err + 3.0 * size_err, -support
    good.sort(key=combined)
    return good[0][2]


def _order_finders(f):
    """Label (TL, TR, BL) from 3 finder centers using the diagonal rule."""
    import math
    d = [math.dist(f[0], f[1]), math.dist(f[1], f[2]), math.dist(f[0], f[2])]
    # the pair with max distance = TR/BL diagonal; the odd one out is TL
    k = max(range(3), key=lambda i: d[i])
    pairs = [(0, 1), (1, 2), (0, 2)]
    a, b = pairs[k]
    tl = 3 - a - b  # indices 0,1,2 sum to 3
    A, B = np.array(f[a]), np.array(f[b])
    TL = np.array(f[tl])
    cross = (A[0] - TL[0]) * (B[1] - TL[1]) - (A[1] - TL[1]) * (B[0] - TL[0])
    # image coords: y down. TL->TR=(+x,0), TL->BL=(0,+y): cross(TR,BL) > 0
    tr, bl = (a, b) if cross > 0 else (b, a)
    return np.array(f[tl]), np.array(f[tr]), np.array(f[bl])


# --------------------------------------------------------------------------
# alignment pattern search (5x5 -> 1:1:1:1:1 signature)
# --------------------------------------------------------------------------

def _scan_alignment_1d(line):
    """Find 5x5 alignment centers along a line.

    Unlike finders, alignment patterns have no white separator, so the
    outer dark runs can merge with neighboring data modules. Only the
    middle three runs must be ~1 module; the outer runs just need to be
    dark and at least half a module. Center = middle of the center run.
    """
    runs = _runs(line)
    out = []
    for i in range(len(runs) - 4):
        win = runs[i:i + 5]
        if [w[2] for w in win] != [1, 0, 1, 0, 1]:
            continue
        lens = [w[1] for w in win]
        unit = sum(lens[1:4]) / 3.0
        if not all(abs(l - unit) <= unit * 0.5 for l in lens[1:4]):
            continue
        if lens[0] < unit * 0.5 or lens[4] < unit * 0.5:
            continue
        out.append((win[2][0] + win[2][1] / 2.0, unit))
    return out


def _find_alignment(bin_img, px, py, module):
    """Search near (px,py) for an alignment pattern; return (x, y) or None."""
    h, w = bin_img.shape
    R = int(module * 4)
    x0, x1 = max(0, int(px - R)), min(w, int(px + R))
    y0, y1 = max(0, int(py - R)), min(h, int(py + R))
    best = None
    for y in range(y0, y1):
        for cx, mod in _scan_alignment_1d(bin_img[y, x0:x1]):
            if abs(mod - module) / module > 0.4:
                continue
            ax = x0 + cx
            col = bin_img[y0:y1, int(round(ax))]
            for cy, mod2 in _scan_alignment_1d(col):
                ay = y0 + cy
                dist = abs(ax - px) + abs(ay - py)
                if best is None or dist < best[0]:
                    best = (dist, ax, ay)
    return None if best is None else (best[1], best[2])


# --------------------------------------------------------------------------
# homography + sampling
# --------------------------------------------------------------------------

def _homography(src, dst):
    """Solve image->grid projective map (h22 = 1) via least squares."""
    A, b = [], []
    for (x, y), (u, v) in zip(src, dst):
        A.append([-x, -y, -1, 0, 0, 0, u * x, u * y])
        b.append(-u)
        A.append([0, 0, 0, -x, -y, -1, v * x, v * y])
        b.append(-v)
    h, *_ = np.linalg.lstsq(np.array(A), np.array(b), rcond=None)
    return np.array([[h[0], h[1], h[2]],
                     [h[3], h[4], h[5]],
                     [h[6], h[7], 1.0]])


def _sample_grid(gray, H_inv, dim):
    h, w = gray.shape
    samples = np.zeros((dim, dim))
    for r in range(dim):
        for c in range(dim):
            p = H_inv @ np.array([c + 0.5, r + 0.5, 1.0])
            x, y = p[0] / p[2], p[1] / p[2]
            x0, y0 = int(np.floor(x)), int(np.floor(y))
            fx, fy = x - x0, y - y0
            v = 0.0
            for dy in (0, 1):
                for dx in (0, 1):
                    xx = min(max(x0 + dx, 0), w - 1)
                    yy = min(max(y0 + dy, 0), h - 1)
                    v += gray[yy, xx] * ((1 - fx) if dx == 0 else fx) * ((1 - fy) if dy == 0 else fy)
            samples[r, c] = v
    return samples


# --------------------------------------------------------------------------
# main entry
# --------------------------------------------------------------------------

def detect(img):
    """Detect and sample a QR code -> (matrix, info dict)."""
    gray = _grayscale(img)
    t = _otsu_threshold(gray)
    binary = (gray <= t).astype(np.int32)  # 1 = dark

    cands = _find_finder_candidates(binary)
    if len(cands) < 3:
        raise QRDetectError(f"only {len(cands)} finder candidates")
    clusters = _cluster(cands)
    if len(clusters) < 3:
        raise QRDetectError(f"only {len(clusters)} finder clusters")
    triple = _pick_finder_triple(clusters)
    TL, TR, BL = _order_finders([c[:2] for c in triple])
    module = float(np.mean([c[2] for c in triple]))

    d1 = np.linalg.norm(TR - TL) / module
    d2 = np.linalg.norm(BL - TL) / module
    raw = (d1 + d2) / 2 + 7
    # true dimension is always 21 + 4k; snap the noisy estimate
    dim = int(round((raw - 17) / 4) * 4 + 17)
    if abs(raw - dim) > 1.5 or dim < 21 or dim > 177:
        raise QRDetectError(f"implausible dimension {raw:.1f}")
    version = (dim - 17) // 4

    # 4th correspondence: bottom-right alignment pattern (v2+) or
    # the affine-completed finder-equivalent point (v1)
    br_grid = (dim - 3.5, dim - 3.5)
    if version == 1:
        BR_img = TR + (BL - TL)
    else:
        # affine prediction from the 3 finders, then local search
        A = []
        b = []
        grid_pts = [(3.5, 3.5), (dim - 3.5, 3.5), (3.5, dim - 3.5)]
        for (u, v), (x, y) in zip(grid_pts, (TL, TR, BL)):
            A.append([u, v, 1, 0, 0, 0])
            A.append([0, 0, 0, u, v, 1])
            b += [x, y]
        coef, *_ = np.linalg.lstsq(np.array(A), np.array(b), rcond=None)
        ap = VERSIONS[version]["align"][-1] + 0.5
        px = coef[0] * ap + coef[1] * ap + coef[2]
        py = coef[3] * ap + coef[4] * ap + coef[5]
        found = _find_alignment(binary, px, py, module)
        if found is None:
            raise QRDetectError("bottom-right alignment pattern not found")
        BR_img = np.array(found)
        br_grid = (ap, ap)

    H = _homography([TL, TR, BL, BR_img],
                    [(3.5, 3.5), (dim - 3.5, 3.5), (3.5, dim - 3.5), br_grid])
    try:
        H_inv = np.linalg.inv(H)
    except np.linalg.LinAlgError:
        raise QRDetectError("singular homography")
    samples = _sample_grid(gray, H_inv, dim)
    st = _otsu_threshold(samples)
    matrix = (samples <= st).astype(int).tolist()
    return matrix, {
        "version": version, "dim": dim, "module_px": module,
        "finders": {"TL": TL.tolist(), "TR": TR.tolist(), "BL": BL.tolist()},
    }
