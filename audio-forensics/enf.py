#!/usr/bin/env python3
"""enf: electrical-network-frequency (mains hum) continuity analysis.

Mains-powered recordings carry a faint 50/60 Hz hum whose phase is
continuous in an unedited take. A splice (cut, insert, or join from another
take) almost always breaks the hum's phase or amplitude continuity at the
edit point. This module:

  * reads WAV via the stdlib `wave` module (any PCM width, mono/stereo),
  * runs a Goertzel detector at 50 and 60 Hz per 0.1 s window (auto-selects
    the stronger hum),
  * tracks phase continuity via the window-to-window cross product
    z[k]*conj(z[k-1]) -- for a continuous hum the cross-product phase is
    constant, so a splice shows up as a phase residual spike,
  * tracks amplitude continuity and hum SNR (hum power vs neighboring bins),
  * adds energy (RMS) and zero-crossing-rate jumps as supporting signals.

All DSP is hand-written: math, struct, wave only.
"""
import math
import struct
import wave

WIN_S = 0.10            # analysis window, seconds
PHASE_THRESH = 0.60     # radians of residual that counts as a break
AMP_RATIO_THRESH = 2.5  # amplitude jump factor that counts as a break
ENERGY_RATIO_THRESH = 2.0
SNR_FLOOR_DB = 3.0      # below this the hum is too weak to trust


def read_wav(path):
    """Returns dict: sr, channels, width, frames, duration, mono (float list)."""
    with wave.open(path, "rb") as w:
        nch, sw, sr, nframes = w.getnchannels(), w.getsampwidth(), \
            w.getframerate(), w.getnframes()
        raw = w.readframes(nframes)
    fmt = {1: "b", 2: "h", 4: "i"}[sw]
    scale = float(1 << (8 * sw - 1))
    vals = struct.unpack("<" + fmt * (len(raw) // sw), raw)
    mono = [sum(vals[i * nch:(i + 1) * nch]) / (nch * scale)
            for i in range(nframes)]
    return {"path": path, "sr": sr, "channels": nch, "width": sw,
            "frames": nframes, "duration": nframes / sr, "mono": mono}


def goertzel(samples, sr, freq):
    """Single-bin DFT at `freq` over `samples`. Returns complex amplitude."""
    n = len(samples)
    w = 2.0 * math.pi * freq / sr
    cw, sw = math.cos(w), math.sin(w)
    coeff = 2.0 * cw
    s1 = s2 = 0.0
    for x in samples:
        s0 = x + coeff * s1 - s2
        s2, s1 = s1, s0
    # X(k) = y[N-1] - y[N-2] * e^{-jw}
    return complex(s1 - s2 * cw, s2 * sw)


def _noise_bins(freq):
    """Bins for the noise-floor estimate: +/-10 and +/-20 Hz sit at exact
    nulls of the rectangular window's sidelobes for a stable hum, so they
    measure background -- not the hum itself. The alternate mains frequency
    is excluded (it may carry its own hum)."""
    cands = [freq - 20, freq - 10, freq + 10, freq + 20]
    other = 50.0 if freq > 55 else 60.0
    return [f for f in cands if f != other and f > 0]


def hum_track(mono, sr, freq, win_s=WIN_S):
    """Per-window (t, complex amplitude, snr_db) for the hum at `freq`."""
    n = int(win_s * sr)
    nbins = _noise_bins(freq)
    out = []
    for start in range(0, len(mono) - n + 1, n):
        seg = mono[start:start + n]
        z = goertzel(seg, sr, freq)
        p_hum = abs(z) ** 2
        p_noise = sum(abs(goertzel(seg, sr, f)) ** 2 for f in nbins) / len(nbins)
        snr = 10 * math.log10(p_hum / (p_noise + 1e-18))
        out.append((start / sr, z, snr))
    return out


def select_hum_freq(mono, sr):
    """Pick 50 or 60 Hz by median hum power. Returns (freq, track)."""
    cand = {}
    for f in (50.0, 60.0):
        tr = hum_track(mono, sr, f)
        med = sorted(abs(z) for _, z, _ in tr)[len(tr) // 2]
        cand[f] = (med, tr)
    f = max(cand, key=lambda k: cand[k][0])
    return f, cand[f][1]


def _wrap(a):
    while a > math.pi:
        a -= 2 * math.pi
    while a < -math.pi:
        a += 2 * math.pi
    return a


def enf_discontinuities(track):
    """Find splice candidates in a hum track.
    Returns list of (t, kind, detail) with kind in {'phase','amplitude'}."""
    # baseline cross-product phase from the median (robust to a few edits)
    crosses = []
    for (_, z0, _), (_, z1, _) in zip(track, track[1:]):
        crosses.append(_wrap(math.atan2((z1 * z0.conjugate()).imag,
                                        (z1 * z0.conjugate()).real)))
    base = sorted(crosses)[len(crosses) // 2] if crosses else 0.0
    events = []
    for i, ((t0, z0, snr0), (t1, z1, snr1)) in enumerate(zip(track, track[1:])):
        if snr0 < SNR_FLOOR_DB or snr1 < SNR_FLOOR_DB:
            continue  # hum too weak here to say anything
        res = abs(_wrap(crosses[i] - base))
        if res > PHASE_THRESH:
            events.append((t1, "phase",
                           f"residual {res:.2f} rad (baseline {base:.2f})"))
        a0, a1 = abs(z0), abs(z1)
        ratio = a1 / (a0 + 1e-18)
        if ratio > AMP_RATIO_THRESH or ratio < 1.0 / AMP_RATIO_THRESH:
            events.append((t1, "amplitude", f"hum amplitude {ratio:.2f}x"))
    return events


def frame_stats(mono, sr, win_s=WIN_S):
    """Per-window (t, rms, zcr)."""
    n = int(win_s * sr)
    out = []
    for start in range(0, len(mono) - n + 1, n):
        seg = mono[start:start + n]
        rms = math.sqrt(sum(x * x for x in seg) / n)
        zc = sum(1 for a, b in zip(seg, seg[1:]) if (a < 0) != (b < 0)) / n
        out.append((start / sr, rms, zc))
    return out


def energy_jumps(stats):
    """Supporting signal: large window-to-window RMS jumps."""
    events = []
    for (t0, r0, _), (t1, r1, _) in zip(stats, stats[1:]):
        if r0 < 1e-4:
            continue
        ratio = r1 / r0
        if ratio > ENERGY_RATIO_THRESH or ratio < 1.0 / ENERGY_RATIO_THRESH:
            events.append((t1, "energy", f"RMS {ratio:.2f}x"))
    return events


def zcr_shifts(stats):
    """Supporting signal: abrupt zero-crossing-rate changes (timbre cut)."""
    events = []
    for (t0, _, z0), (t1, _, z1) in zip(stats, stats[1:]):
        if z0 < 1e-4:
            continue
        ratio = z1 / z0
        if ratio > 2.0 or ratio < 0.5:
            events.append((t1, "zcr", f"ZCR {ratio:.2f}x"))
    return events
