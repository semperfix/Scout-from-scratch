# 43. DSP & Telephony Tone Decoding — Learnings

## What was built
`dsp.py` (~430 lines, numpy only): iterative radix-2 Cooley-Tukey FFT + IFFT
(conjugation trick), one-sided amplitude spectrum, parabolic-interpolated peak
frequency estimation, Goertzel single-frequency detector, Hann-windowed
spectrogram, full DTMF encode/decode (all 16 keys), Morse encode/decode via
tone envelope, and a hand-rolled 16-bit PCM WAV codec (struct, chunk-walking).
`tonedec.py` CLI: `gen-dtmf` / `decode-dtmf` / `gen-morse` / `decode-morse` /
`tones`. `test_dsp.py`: 31/31.

## Earned insights (each paid for in debugging)
- **My test was wrong, not the FFT.** First run: `rfft_mag` peak read 0.613
  instead of 0.7 — because I tested at 440 Hz, which is *not* on a DFT bin
  (bin width 8000/4096 = 1.953 Hz). Spectral leakage is not a code bug; the
  fix was testing at an exact on-bin frequency (226·fs/n). Lesson: when the
  oracle disagrees, check whether the *test's assumptions* hold before the code.
- **Relative checks aren't enough against noise — you need an absolute floor.**
  DTMF decode passed all relative margins (winner/runner-up > 4×, twist < 8 dB,
  pair/rest > 1.5) on pure-noise gap windows and hallucinated digits
  ('91262808064*#' — a phantom 8 in a gap). The fix is an adaptive absolute
  gate: a window's tone-pair power must exceed 0.2× the global max pair power.
  Real detectors do exactly this (cf. ITU Q.24 signal-level requirements).
- **Mid-tone dropouts double-emit digits.** Once flicker was possible, one
  tone's window-run could split into two same-digit runs → "88". Fix:
  run-length encode, absorb None-gaps < 3 windows when flanked by the same
  digit (real inter-digit gaps are ≥ 4 windows), drop single-window digit runs.
  Two small state machines beat one clever threshold.
- **Thresholds must float above the *noise floor*, not above zero.**
  Morse decode failed at 12 dB SNR ('HELLO WORLD' → 'NELLO AOR?') because the
  gap noise envelope (~0.057) sat above my fixed low threshold (~0.037) — gaps
  never registered as "off", so dots merged into dashes and char gaps vanished.
  Fix: noise = p20(envelope), signal = p98, Schmitt thresholds at
  noise+0.35·span / noise+0.60·span. Percentile-based, so a noise spike can't
  drag the threshold the way max() did.
- **Goertzel window length is a jitter-vs-resolution tradeoff, not just
  "longer is better."** Longer windows narrow the bins, which *hurts* when the
  tone jitters off the nominal frequency (fractional-bin offset grows). 25 ms
  windows (40 Hz bins) tolerate the full ±1.5% line jitter from the spec.
- **Parabolic interpolation on a Hann window has ~0.1-bin systematic bias.**
  Pinned by test at 444.7 Hz (err 0.10 Hz vs 0.05 threshold I first set).
  Honest threshold: 0.2 Hz. Quinn's estimator would do better; documented gap.
- **DTMF is absurdly robust; envelope Morse is not.** Stress test (5 seeds
  each): DTMF decodes 5/5 even at **0 dB SNR** with 1% frequency jitter —
  narrowband dual-tone + relative margins is a fortress. Morse holds 5/5 to
  12 dB, 4/5 at 8 dB, 0/5 at 5 dB: once noise floor ≈ signal level, envelope
  timing dies. That's the honest operating envelope, measured not assumed.

## Validation summary
- FFT: max abs err vs numpy.fft < 1e-9 at n = 2..4096; IFFT roundtrip;
  Parseval; impulse → flat spectrum.
- Goertzel power == |FFT bin|² to 1e-9 relative.
- DTMF: all 16 keys @ 12 dB SNR; 40 ms telephony-minimum timing; silence → '';
  jitter ±1.5%; WAV file roundtrip decode.
- Morse: 15/20/30 wpm; 12 dB SNR; WAV roundtrip.
- `tones` CLI correctly reports the DTMF row/col frequencies in a dial WAV.

## What it's for
Phone-call forensics (what digits were dialed in a recording — DTMF is exactly
how keypad tones travel in audio), decoding beacon/morse-ish signals in
captured audio, frequency autopsy of any WAV (`tones`), and a real feel for
what lives inside every spectrogram. Pairs with #4 (audio forensics): ENF
says *when* a recording was made; this says *what tones it contains*.
