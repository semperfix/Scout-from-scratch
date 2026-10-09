"""Validation for 43-dsp. Oracles: numpy.fft, scipy.signal (informational)."""
import math
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dsp import (fft, ifft, rfft_mag, spectrum, hann, freq_of, goertzel,
                 spectrogram, dtmf_encode, dtmf_decode, morse_encode,
                 morse_decode, wav_write, wav_read, DTMF_ROWS, DTMF_COLS)

PASS = []
FAIL = []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("ok   " if cond else "FAIL ") + name + ((" -- " + str(detail)) if detail and not cond else ""))


rng = np.random.default_rng(43)

# --- 1. FFT agreement with numpy.fft ---------------------------------------
for n in [2, 4, 8, 64, 256, 1024, 4096]:
    x = rng.standard_normal(n) + 1j * rng.standard_normal(n)
    err = np.max(np.abs(fft(x) - np.fft.fft(x)))
    check(f"fft matches numpy.fft n={n}", err < 1e-9, f"max err {err:.2e}")

# pure real input too
x = rng.standard_normal(512)
check("fft real input matches numpy.fft",
      np.max(np.abs(fft(x) - np.fft.fft(x))) < 1e-9)

# --- 2. ifft roundtrip ------------------------------------------------------
x = rng.standard_normal(256) + 1j * rng.standard_normal(256)
err = np.max(np.abs(ifft(fft(x)) - x))
check("ifft(fft(x)) == x", err < 1e-9, f"max err {err:.2e}")

# --- 3. Parseval: sum|x|^2 == sum|X|^2 / n ----------------------------------
x = rng.standard_normal(512)
X = fft(x)
check("Parseval holds", abs(np.sum(np.abs(x) ** 2) - np.sum(np.abs(X) ** 2) / 512) < 1e-9)

# --- 4. rfft_mag normalization: sine of amplitude A -> peak A ---------------
# NOTE: must use an exact on-bin frequency or leakage spreads the peak
fs = 8000
n = 4096
t = np.arange(n) / fs
A = 0.7
f0 = 226 * fs / n          # bin 226 exactly: 441.40625 Hz
x = A * np.sin(2 * np.pi * f0 * t)
mag = rfft_mag(x)
check("rfft_mag peak == amplitude", abs(mag[226] - A) < 1e-6, f"peak {mag[226]}")

# --- 5. freq_of with parabolic interpolation --------------------------------
err = abs(freq_of(x, fs) - f0)
check("freq_of exact-bin", err < 0.01, f"err {err:.4f} Hz")
f1 = 444.7  # off-bin: bin width = fs/n = 1.953 Hz
x1 = A * np.sin(2 * np.pi * f1 * t)
err = abs(freq_of(x1, fs) - f1)
# parabolic interpolation on a Hann window has up to ~0.1-bin systematic bias
check("freq_of off-bin interpolated", err < 0.2, f"err {err:.4f} Hz")

# --- 6. Goertzel == FFT bin power -------------------------------------------
seg = x1[:1024]
g = goertzel(seg, fs, f1)
Xf = np.fft.fft(seg)
k = int(round(f1 * 1024 / fs))
ref = abs(Xf[k]) ** 2
check("goertzel == |FFT bin|^2", abs(g - ref) / max(ref, 1e-300) < 1e-9,
      f"g {g:.3e} ref {ref:.3e}")
# Goertzel beats full FFT for sparse detection: same answer, O(n) not O(n log n)
check("goertzel rejects wrong freq", goertzel(seg, fs, 900.0) < g * 1e-3)

# --- 7. DTMF roundtrip, clean -----------------------------------------------
digits = "9126280064*#"
x = dtmf_encode(digits, fs=8000)
check("dtmf clean roundtrip", dtmf_decode(x) == digits, repr(dtmf_decode(x)))

# --- 8. DTMF under noise: 10 dB SNR ------------------------------------------
x = dtmf_encode(digits, fs=8000, snr_db=10.0)
check("dtmf 10dB SNR roundtrip", dtmf_decode(x) == digits, repr(dtmf_decode(x)))

# --- 9. DTMF with frequency jitter +/-1.5% (real line tolerance) ------------
x = dtmf_encode(digits, fs=8000, snr_db=15.0, freq_jitter=0.015)
check("dtmf freq-jitter roundtrip", dtmf_decode(x) == digits, repr(dtmf_decode(x)))

# --- 10. DTMF fast timing (40ms tone / 40ms gap, telephony minimum) ---------
x = dtmf_encode("5551234", fs=8000, tone_ms=40, gap_ms=40)
check("dtmf fast-timing roundtrip", dtmf_decode(x) == "5551234",
      repr(dtmf_decode(x)))

# --- 11. DTMF rejects silence ------------------------------------------------
check("dtmf silence -> ''", dtmf_decode(np.zeros(8000)) == "")

# --- 12. Morse roundtrip -----------------------------------------------------
msg = "SOS FOX 42"
x = morse_encode(msg, fs=8000, wpm=20)
check("morse clean roundtrip", morse_decode(x, fs=8000, wpm=20) == msg,
      repr(morse_decode(x, fs=8000, wpm=20)))

# --- 13. Morse under noise: 12 dB SNR ----------------------------------------
x = morse_encode("HELLO WORLD", fs=8000, wpm=15, snr_db=12.0)
check("morse 12dB SNR roundtrip",
      morse_decode(x, fs=8000, wpm=15) == "HELLO WORLD",
      repr(morse_decode(x, fs=8000, wpm=15)))

# --- 14. Morse at speed (30 wpm) ----------------------------------------------
x = morse_encode("QUICK 99", fs=8000, wpm=30)
check("morse 30wpm roundtrip", morse_decode(x, fs=8000, wpm=30) == "QUICK 99",
      repr(morse_decode(x, fs=8000, wpm=30)))

# --- 15. WAV roundtrip --------------------------------------------------------
xd = dtmf_encode("8675309", fs=8000)
p = "/tmp/dsp_test.wav"
wav_write(p, xd, fs=8000)
back, fs2 = wav_read(p)
check("wav_read fs", fs2 == 8000)
# correlation should be ~1 (16-bit quantization only)
corr = np.corrcoef(xd, back[:len(xd)])[0, 1]
check("wav roundtrip correlation", corr > 0.99999, f"corr {corr}")
check("dtmf decodes from wav file", dtmf_decode(back, fs2) == "8675309",
      repr(dtmf_decode(back, fs2)))
os.remove(p)

# --- 16. Spectrogram: two tones at different times ---------------------------
n = 8192
t = np.arange(n) / fs
xs = np.zeros(n)
xs[:4096] = 0.5 * np.sin(2 * np.pi * 440 * t[:4096])
xs[4096:] = 0.5 * np.sin(2 * np.pi * 880 * t[4096:])
times, freqs, S = spectrogram(xs, fs, nfft=1024, hop=512)
early = freqs[int(np.argmax(S[2]))]
late = freqs[int(np.argmax(S[-3]))]
check("spectrogram time-freq localization",
      abs(early - 440) < 10 and abs(late - 880) < 10, f"{early}, {late}")

# --- 17. hann window: coherent gain of hann is 0.5 ---------------------------
check("hann coherent gain 0.5", abs(np.mean(hann(4096)) - 0.5) < 1e-12)

# --- 18. fft rejects non-power-of-2 ------------------------------------------
try:
    fft(np.zeros(100))
    check("fft rejects non-pow2", False)
except ValueError:
    check("fft rejects non-pow2", True)

# --- 19. Known DFT: impulse -> flat spectrum ---------------------------------
d = np.zeros(8)
d[0] = 1.0
check("fft of impulse is flat", np.max(np.abs(fft(d) - 1.0)) < 1e-12)

# --- 20. DTMF all 16 keys -----------------------------------------------------
all16 = "123A456B789C*0#D"
x = dtmf_encode(all16, fs=8000, snr_db=12.0)
check("dtmf all 16 keys", dtmf_decode(x) == all16, repr(dtmf_decode(x)))

print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
sys.exit(1 if FAIL else 0)
