"""Signal processing from scratch: FFT, Goertzel, DTMF, Morse, spectrograms, WAV.

Zero ML/framework DSP deps beyond numpy (used as a complex-number container and
for trig; the FFT butterfly math, Goertzel recurrence, detectors are all ours).
Validated against numpy.fft / scipy as oracles.

Public API:
  fft(x), ifft(x)          iterative radix-2 Cooley-Tukey (power-of-2 lengths)
  spectrum(x, fs)          real magnitude spectrum via fft
  freq_of(x, fs)           dominant frequency with parabolic interpolation
  goertzel(x, fs, f)       |X(f)|^2 at one target frequency
  hann(n)                  window
  spectrogram(x, fs, nfft, hop)
  dtmf_encode(digits, fs, tone_ms, gap_ms, snr_db) -> samples
  dtmf_decode(x, fs)       -> digit string
  morse_encode(text, fs, wpm, tone_hz) -> samples
  morse_decode(x, fs, tone_hz) -> text
  wav_write(path, x, fs), wav_read(path) -> (x, fs)
"""

import math
import struct

import numpy as np

# ---------------------------------------------------------------------------
# FFT: iterative radix-2 Cooley-Tukey (decimation in time)
# ---------------------------------------------------------------------------

def _is_pow2(n):
    return n > 0 and (n & (n - 1)) == 0


def fft(x):
    """Forward DFT via iterative radix-2 Cooley-Tukey. n must be a power of 2."""
    X = np.asarray(x, dtype=np.complex128).copy()
    n = len(X)
    if not _is_pow2(n):
        raise ValueError("fft: length %d is not a power of 2" % n)
    # bit-reversal permutation
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if i < j:
            X[i], X[j] = X[j], X[i]
    # butterfly stages
    m = 2
    while m <= n:
        w_m = np.exp(-2j * np.pi / m)
        for k in range(0, n, m):
            w = 1.0 + 0.0j
            for j2 in range(m // 2):
                t = w * X[k + j2 + m // 2]
                u = X[k + j2]
                X[k + j2] = u + t
                X[k + j2 + m // 2] = u - t
                w *= w_m
        m <<= 1
    return X


def ifft(X):
    """Inverse DFT via conjugation trick: ifft(X) = conj(fft(conj(X)))/n."""
    X = np.asarray(X, dtype=np.complex128)
    n = len(X)
    return np.conj(fft(np.conj(X))) / n


def rfft_mag(x):
    """One-sided magnitude spectrum of real x (n/2+1 bins), using our fft."""
    X = fft(np.asarray(x, dtype=float))
    n = len(X)
    mag = np.abs(X[: n // 2 + 1])
    mag[1:-1] *= 2.0          # fold negative-frequency energy back
    mag /= n                  # normalize: pure sine of amplitude A -> peak A
    return mag


def spectrum(x, fs):
    """(freqs, mag): one-sided amplitude spectrum of real signal x at rate fs."""
    x = np.asarray(x, dtype=float)
    n = len(x)
    mag = rfft_mag(x)
    freqs = np.arange(n // 2 + 1) * fs / n
    return freqs, mag


def hann(n):
    return 0.5 * (1.0 - np.cos(2.0 * np.pi * np.arange(n) / n))


def freq_of(x, fs):
    """Dominant frequency with parabolic interpolation around the peak bin."""
    x = np.asarray(x, dtype=float)
    n = len(x)
    w = hann(n)
    mag = rfft_mag(x * w)
    k = int(np.argmax(mag[1:])) + 1
    if k <= 0 or k >= len(mag) - 1:
        return k * fs / n
    a, b, c = mag[k - 1], mag[k], mag[k + 1]
    denom = a - 2 * b + c
    delta = 0.5 * (a - c) / denom if denom != 0 else 0.0
    delta = max(-1.0, min(1.0, delta))
    return (k + delta) * fs / n


# ---------------------------------------------------------------------------
# Goertzel: single-frequency power |X(f)|^2
# ---------------------------------------------------------------------------

def goertzel(x, fs, f):
    """Power at frequency f via the Goertzel recurrence (no full FFT needed)."""
    x = np.asarray(x, dtype=float)
    n = len(x)
    k = int(round(f * n / fs))           # nearest DFT bin
    omega = 2.0 * math.pi * k / n
    coeff = 2.0 * math.cos(omega)
    s1 = 0.0
    s2 = 0.0
    for s in x:
        s0 = s + coeff * s1 - s2
        s2 = s1
        s1 = s0
    return s1 * s1 + s2 * s2 - coeff * s1 * s2


# ---------------------------------------------------------------------------
# Spectrogram
# ---------------------------------------------------------------------------

def spectrogram(x, fs, nfft=1024, hop=256):
    """Magnitude spectrogram: rows = time frames, cols = freq bins."""
    x = np.asarray(x, dtype=float)
    w = hann(nfft)
    frames = []
    for start in range(0, len(x) - nfft + 1, hop):
        frames.append(rfft_mag(x[start:start + nfft] * w))
    S = np.array(frames)
    freqs = np.arange(nfft // 2 + 1) * fs / nfft
    times = np.arange(len(frames)) * hop / fs
    return times, freqs, S


# ---------------------------------------------------------------------------
# DTMF (phone keypad tones)
# ---------------------------------------------------------------------------

DTMF_ROWS = [697.0, 770.0, 852.0, 941.0]
DTMF_COLS = [1209.0, 1336.0, 1477.0, 1633.0]
DTMF_KEYS = [
    ['1', '2', '3', 'A'],
    ['4', '5', '6', 'B'],
    ['7', '8', '9', 'C'],
    ['*', '0', '#', 'D'],
]
_DTMF_OF = {DTMF_KEYS[r][c]: (DTMF_ROWS[r], DTMF_COLS[c])
            for r in range(4) for c in range(4)}


def dtmf_encode(digits, fs=8000, tone_ms=120, gap_ms=80, snr_db=None,
                freq_jitter=0.0, rng=None):
    """Synthesize DTMF audio. snr_db adds white noise; freq_jitter (fraction)
    shifts each tone pair to emulate real line tolerance."""
    rng = np.random.default_rng() if rng is None else rng
    tone_n = int(fs * tone_ms / 1000)
    gap_n = int(fs * gap_ms / 1000)
    t = np.arange(tone_n) / fs
    out = []
    for d in digits:
        fr, fc = _DTMF_OF[d]
        if freq_jitter:
            j = 1.0 + rng.uniform(-freq_jitter, freq_jitter)
            fr, fc = fr * j, fc * j
        sig = np.sin(2 * np.pi * fr * t) + np.sin(2 * np.pi * fc * t)
        sig *= 0.5
        out.append(sig)
        out.append(np.zeros(gap_n))
    x = np.concatenate(out) if out else np.zeros(0)
    if snr_db is not None and len(x):
        sig_p = np.mean(x ** 2)
        noise_p = sig_p / (10 ** (snr_db / 10))
        x = x + rng.normal(0, math.sqrt(noise_p), len(x))
    return x


def dtmf_decode(x, fs=8000, win_ms=25, hop_ms=10):
    """Decode DTMF digits from audio via sliding-window Goertzel.

    Each window is classified; consecutive same-digit windows collapse to one
    digit. A window must have a clear row+col winner and the pair must beat
    the noise floor (relative-margin checks) to count."""
    x = np.asarray(x, dtype=float)
    win = int(fs * win_ms / 1000)
    hop = int(fs * hop_ms / 1000)
    if len(x) < win:
        return ''
    freqs = DTMF_ROWS + DTMF_COLS
    raw = []  # (digit|None, pair_power)
    for start in range(0, len(x) - win + 1, hop):
        seg = x[start:start + win] * hann(win)
        p = [goertzel(seg, fs, f) for f in freqs]
        row_p, col_p = p[:4], p[4:]
        ri = int(np.argmax(row_p))
        ci = int(np.argmax(col_p))
        # margins: winner must clearly beat runner-up in its group
        row_sorted = sorted(row_p, reverse=True)
        col_sorted = sorted(col_p, reverse=True)
        pair = row_sorted[0] + col_sorted[0]
        if row_sorted[1] == 0 or col_sorted[1] == 0:
            raw.append((None, pair))
            continue
        row_margin = row_sorted[0] / row_sorted[1]
        col_margin = col_sorted[0] / col_sorted[1]
        # twist check: row/col levels within 8 dB of each other
        twist = 10 * math.log10(row_sorted[0] / col_sorted[0]) \
            if col_sorted[0] > 0 else 99
        # noise floor: pair power must beat total of all 8 bins' also-rans
        rest = sum(p) - pair
        if row_margin > 4.0 and col_margin > 4.0 and abs(twist) < 8.0 \
                and (rest == 0 or pair / rest > 1.5):
            raw.append((DTMF_KEYS[ri][ci], pair))
        else:
            raw.append((None, pair))
    # absolute power gate: kill noise-only windows that passed relative checks
    pmax = max((pp for _, pp in raw), default=0.0)
    gated = [d if pp >= 0.2 * pmax else None for d, pp in raw]
    # run-length encode
    runs = []
    for g in gated:
        if runs and runs[-1][0] == g:
            runs[-1][1] += 1
        else:
            runs.append([g, 1])
    # absorb short silence gaps flanked by the same digit (mid-tone dropout);
    # real inter-digit gaps are >= 40 ms = 4 windows, so < 3 is safe to merge
    merged = []
    i = 0
    while i < len(runs):
        g, length = runs[i]
        if (g is None and length < 3 and merged and i + 1 < len(runs)
                and merged[-1][0] is not None
                and merged[-1][0] == runs[i + 1][0]):
            merged[-1][1] += length + runs[i + 1][1]
            i += 2
        else:
            merged.append([g, length])
            i += 1
    # drop single-window flickers, then collapse
    digits = []
    for g, length in merged:
        if g is not None and length >= 2:
            digits.append(g)
    return ''.join(digits)


# ---------------------------------------------------------------------------
# Morse code via audio tones
# ---------------------------------------------------------------------------

MORSE = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..',
    '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
    '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
    '.': '.-.-.-', ',': '--..--', '?': '..--..', '/': '-..-.', '=': '-...-',
}
_MORSE_REV = {v: k for k, v in MORSE.items()}


def morse_encode(text, fs=8000, wpm=20, tone_hz=700.0, snr_db=None, rng=None):
    """Text -> audio. wpm sets unit length (PARIS standard: unit = 1.2/wpm s)."""
    rng = np.random.default_rng() if rng is None else rng
    unit = int(fs * 1.2 / wpm)
    t_tone = np.arange(unit * 3) / fs  # longest element needed is dash=3u
    out = []
    text = text.upper()
    for i, ch in enumerate(text):
        if ch == ' ':
            out.append(np.zeros(unit * 7))   # word gap
            continue
        code = MORSE.get(ch)
        if code is None:
            continue
        for j, sym in enumerate(code):
            n = unit if sym == '.' else unit * 3
            tt = np.arange(n) / fs
            out.append(0.5 * np.sin(2 * np.pi * tone_hz * tt))
            out.append(np.zeros(unit))        # intra-character gap
        out.append(np.zeros(unit * 2))        # +2u => 3u char gap total
    x = np.concatenate(out) if out else np.zeros(0)
    if snr_db is not None and len(x):
        sig_p = np.mean(x[x != 0] ** 2) if np.any(x != 0) else 1.0
        x = x + rng.normal(0, math.sqrt(sig_p / 10 ** (snr_db / 10)), len(x))
    return x


def morse_decode(x, fs=8000, wpm=20, tone_hz=700.0):
    """Audio -> text. Bandpass around tone_hz via Goertzel-free envelope:
    rectify the tone with a quadrature-free mixer then low-pass."""
    x = np.asarray(x, dtype=float)
    unit = int(fs * 1.2 / wpm)
    if len(x) < unit:
        return ''
    # coherent-ish envelope: mix down by tone, low-pass via moving average
    t = np.arange(len(x)) / fs
    mixed = x * np.sin(2 * np.pi * tone_hz * t)
    k = max(1, unit // 8)
    env = np.convolve(np.abs(mixed), np.ones(k) / k, mode='same')
    # threshold from 98th percentile (robust to noise spikes that inflate max),
    # Schmitt trigger (hysteresis) so noise can't chatter a dash into pieces.
    # KEY FIX: thresholds float above the measured noise floor (p20), not zero
    # — otherwise the noise floor itself holds the detector "on" through gaps.
    p98 = np.percentile(env, 98)
    noise = np.percentile(env, 20)
    span = p98 - noise
    thr_hi = noise + 0.60 * span
    thr_lo = noise + 0.35 * span
    hi = np.zeros(len(env), dtype=bool)
    state = False
    for i, e in enumerate(env):
        if e >= thr_hi:
            state = True
        elif e <= thr_lo:
            state = False
        hi[i] = state
    # run-length encode
    runs = []  # (is_high, length_in_units)
    cur, cnt = hi[0], 1
    for v in hi[1:]:
        if v == cur:
            cnt += 1
        else:
            runs.append((cur, cnt / unit))
            cur, cnt = v, 1
    runs.append((cur, cnt / unit))
    # strip leading/trailing silence
    while runs and not runs[0][0]:
        runs.pop(0)
    while runs and not runs[-1][0]:
        runs.pop()
    out = []
    cur_sym = ''
    for is_high, ulen in runs:
        if is_high:
            cur_sym += '.' if ulen < 2.0 else '-'
        else:
            if ulen < 2.0:
                pass                       # intra-character gap
            elif ulen < 5.0:
                out.append(_MORSE_REV.get(cur_sym, '?'))
                cur_sym = ''
            else:
                out.append(_MORSE_REV.get(cur_sym, '?'))
                out.append(' ')
                cur_sym = ''
    if cur_sym:
        out.append(_MORSE_REV.get(cur_sym, '?'))
    return ''.join(out).strip()


# ---------------------------------------------------------------------------
# Minimal WAV codec (16-bit PCM mono), hand-rolled with struct
# ---------------------------------------------------------------------------

def wav_write(path, x, fs=8000):
    x = np.asarray(x, dtype=float)
    peak = np.max(np.abs(x)) if len(x) else 0.0
    pcm = np.int16(np.clip(x / max(peak, 1e-12), -1, 1) * 32767)
    data = pcm.tobytes()
    with open(path, 'wb') as f:
        f.write(b'RIFF')
        f.write(struct.pack('<I', 36 + len(data)))
        f.write(b'WAVEfmt ')
        f.write(struct.pack('<IHHIIHH', 16, 1, 1, fs, fs * 2, 2, 16))
        f.write(b'data')
        f.write(struct.pack('<I', len(data)))
        f.write(data)


def wav_read(path):
    with open(path, 'rb') as f:
        blob = f.read()
    if blob[0:4] != b'RIFF' or blob[8:12] != b'WAVE':
        raise ValueError('not a RIFF/WAVE file')
    # walk chunks
    pos = 12
    fs = None
    pcm = None
    while pos + 8 <= len(blob):
        cid, size = struct.unpack('<4sI', blob[pos:pos + 8])
        body = blob[pos + 8:pos + 8 + size]
        if cid == b'fmt ':
            audio_fmt, nchan, fs, _, _, bits = struct.unpack('<HHIIHH', body[:16])
            if audio_fmt != 1 or bits != 16:
                raise ValueError('only 16-bit PCM supported')
        elif cid == b'data':
            pcm = np.frombuffer(body, dtype=np.int16).astype(float) / 32768.0
            if nchan == 2:
                pcm = pcm.reshape(-1, 2).mean(axis=1)
        pos += 8 + size + (size & 1)
    if pcm is None or fs is None:
        raise ValueError('WAV missing fmt/data chunk')
    return pcm, fs
