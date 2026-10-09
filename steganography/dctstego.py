"""DCT-domain steganography from scratch (the JPEG-stego math, without a JPEG codec).

Pipeline: grayscale pixels -> 8x8 orthonormal DCT-II (hand-rolled) ->
quantize with the standard IJG luminance table -> F5-style embedding on
non-zero AC coefficients -> dequantize -> IDCT.

F5 rule (simplified): walk coefficients in zigzag order; to embed bit b in
coefficient c (!= 0): if LSB(c) == b keep it, else decrement |c| by 1;
if that makes c == 0 ("shrinkage"), skip it and re-embed b at the next
coefficient. The receiver just reads LSBs of non-zero AC coefficients.
Framing: 32-bit length header, then payload bits (no CRC here — the
histogram attack demo doesn't need it; extract() reports raw bits).

Steganalysis: chi-square PoV attack works on the quantized-coefficient
histogram too (embedding equalizes (2k,2k+1) pairs of coefficient values).
"""
import math
import numpy as np

# Standard IJG luminance quantization table (zigzag order irrelevant here;
# we index it in natural 8x8 order via ZZ below).
QTABLE = np.array([
    [16, 11, 10, 16, 24, 40, 51, 61],
    [12, 12, 14, 19, 26, 58, 60, 55],
    [14, 13, 16, 24, 40, 57, 69, 56],
    [14, 17, 22, 29, 51, 87, 80, 62],
    [18, 22, 37, 56, 68, 109, 103, 77],
    [24, 35, 55, 64, 81, 104, 113, 92],
    [49, 64, 78, 87, 103, 121, 120, 101],
    [72, 92, 95, 98, 112, 100, 103, 99]], dtype=float)

# Zigzag scan order for an 8x8 block.
ZZ = []
for s in range(15):
    diag = [(y, s - y) for y in range(8) if 0 <= s - y < 8]
    ZZ += diag if s % 2 == 0 else diag[::-1]


def _dct_matrix():
    C = np.zeros((8, 8))
    for u in range(8):
        for x in range(8):
            C[u, x] = math.cos((2 * x + 1) * u * math.pi / 16)
    C[0, :] *= 1 / math.sqrt(8)
    C[1:, :] *= 1 / 2
    return C


_DCT = _dct_matrix()


def block_dct(block):
    return _DCT @ block @ _DCT.T


def block_idct(coef):
    return _DCT.T @ coef @ _DCT


def image_to_qcoefs(gray):
    """gray: (h, w) float array, h and w multiples of 8. -> int quantized coefs."""
    h, w = gray.shape
    assert h % 8 == 0 and w % 8 == 0
    q = np.zeros((h, w), dtype=int)
    for by in range(0, h, 8):
        for bx in range(0, w, 8):
            blk = gray[by:by + 8, bx:bx + 8] - 128.0
            q[by:by + 8, bx:bx + 8] = np.round(block_dct(blk) / QTABLE).astype(int)
    return q


def qcoefs_to_image(q):
    h, w = q.shape
    out = np.zeros((h, w))
    for by in range(0, h, 8):
        for bx in range(0, w, 8):
            out[by:by + 8, bx:bx + 8] = block_idct(q[by:by + 8, bx:bx + 8] * QTABLE) + 128.0
    return np.clip(out, 0, 255)


def _ac_positions(q):
    """Zigzag-ordered (y, x) of AC coefficients, block after block."""
    h, w = q.shape
    pos = []
    for by in range(0, h, 8):
        for bx in range(0, w, 8):
            for (zy, zx) in ZZ[1:]:       # skip DC
                pos.append((by + zy, bx + zx))
    return pos


def f5_embed(q, payload: bytes):
    """Returns modified quantized-coefficient array with payload embedded."""
    q = q.copy()
    bits = [(len(payload).to_bytes(4, "big")[i // 8] >> (7 - i % 8)) & 1
            for i in range(32)]
    for byte in payload:
        bits += [(byte >> (7 - i)) & 1 for i in range(8)]
    pos = _ac_positions(q)
    assert len(bits) <= sum(1 for (y, x) in pos if q[y, x] != 0), "payload too big"
    bi = 0
    for (y, x) in pos:
        if bi >= len(bits):
            break
        c = q[y, x]
        if c == 0:
            continue
        if (abs(c) & 1) != bits[bi]:
            c = c - 1 if c > 0 else c + 1     # decrement |c|
            if c == 0:                        # shrinkage -> skip, retry bit
                q[y, x] = c
                continue
            q[y, x] = c
        bi += 1
    assert bi == len(bits), "ran out of coefficients"
    return q


def f5_extract(q, max_bytes=65536):
    """Reads LSBs of non-zero AC coefficients; returns (length, payload)."""
    bits = []
    for (y, x) in _ac_positions(q):
        c = q[y, x]
        if c == 0:
            continue
        bits.append(abs(c) & 1)
        if len(bits) >= 32 + max_bytes * 8:
            break
    length = 0
    for b in bits[:32]:
        length = (length << 1) | b
    if length > max_bytes:
        raise ValueError(f"implausible length {length}")
    payload = bytearray()
    for i in range(length):
        byte = 0
        for b in bits[32 + i * 8:32 + (i + 1) * 8]:
            byte = (byte << 1) | b
        payload.append(byte)
    return length, bytes(payload)


def jsteg_embed(q, payload: bytes):
    """Naive LSB replacement on |AC| (Jsteg-style): no shrinkage handling.

    Like the real Jsteg, coefficients with |c| <= 1 are never touched
    (flipping 1 -> 0 would desync the decoder, which skips zeros).
    """
    q = q.copy()
    bits = [(len(payload).to_bytes(4, "big")[i // 8] >> (7 - i % 8)) & 1
            for i in range(32)]
    for byte in payload:
        bits += [(byte >> (7 - i)) & 1 for i in range(8)]
    pos = [p for p in _ac_positions(q) if abs(q[p]) > 1]
    assert len(bits) <= len(pos), "payload too big"
    for (y, x), b in zip(pos, bits):
        c = q[y, x]
        q[y, x] = abs(c) // 2 * 2 + b if c > 0 else -(abs(c) // 2 * 2 + b)
    return q


def jsteg_extract(q, max_bytes=65536):
    """Jsteg decoder: skips |c| <= 1, mirroring jsteg_embed."""
    bits = []
    for (y, x) in _ac_positions(q):
        c = q[y, x]
        if abs(c) <= 1:
            continue
        bits.append(abs(c) & 1)
        if len(bits) >= 32 + max_bytes * 8:
            break
    length = 0
    for b in bits[:32]:
        length = (length << 1) | b
    if length > max_bytes:
        raise ValueError(f"implausible length {length}")
    payload = bytearray()
    for i in range(length):
        byte = 0
        for b in bits[32 + i * 8:32 + (i + 1) * 8]:
            byte = (byte << 1) | b
        payload.append(byte)
    return length, bytes(payload)


def calibrated_f5_stat(q):
    """Lite version of Fridrich's 'Breaking F5' calibration attack.

    Estimate the cover's coefficient histogram by dequantizing, cropping 4 px
    (desyncs the 8x8 grid, killing the embedding's histogram trace), and
    re-quantizing. F5 shifts mass from odd |c| to even |c|; the calibrated
    image restores the natural odd/even balance. Returns the odd-count
    deficit ratio: 1 - odd_stego/odd_cal  (>> 0 means F5-like depletion).
    """
    import collections
    def odd_frac(qq):
        vals = [abs(int(qq[y, x])) for (y, x) in _ac_positions(qq) if qq[y, x] != 0]
        hist = collections.Counter(vals)
        odd = sum(v for k, v in hist.items() if k % 2 == 1 and k <= 20)
        even = sum(v for k, v in hist.items() if k % 2 == 0 and k <= 20)
        return odd / (odd + even) if odd + even else 0.5
    img = qcoefs_to_image(q)
    h, w = img.shape
    cropped = img[4:h - 4, 4:w - 4]
    ch, cw = cropped.shape
    ch, cw = ch // 8 * 8, cw // 8 * 8
    qcal = image_to_qcoefs(cropped[:ch, :cw])
    oc, os_ = odd_frac(qcal), odd_frac(q)
    return 1.0 - os_ / oc if oc else 0.0


def coef_chi_square(q):
    """Chi-square PoV P(embedded) over non-zero quantized AC coefficients."""
    from steganalysis import _pov_chi2_p
    vals = [abs(int(q[y, x])) for (y, x) in _ac_positions(q) if q[y, x] != 0]
    # fold sign: work on magnitudes; PoV pairs of |c|, skipping the (0,1)
    # pair (zeros/ones are never carriers, so it can never equalize)
    return _pov_chi2_p(vals, first_pair=1)
