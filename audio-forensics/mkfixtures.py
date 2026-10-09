#!/usr/bin/env python3
"""mkfixtures: synthesize test WAVs for audiocheck (struct + math only).

  fixtures/clean.wav   - 4 s, 44.1 kHz mono: speech-like signal + continuous
                         60 Hz mains hum. Expect: CLEAN.
  fixtures/spliced.wav - same, but the second half (t >= 2.0 s) comes from a
                         different "take": the hum is time-shifted by 4.2 ms
                         (= 1.58 rad phase jump at the boundary) and the
                         speech content is louder/different. Expect:
                         SPLICE-LIKELY with a candidate near t=2.00 s.

Usage: python3 mkfixtures.py   (writes ./fixtures/)
"""
import math
import os
import random
import struct
import wave

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
SR = 44100
DUR = 4.0
HUM_F = 60.0
HUM_A = 0.12  # strong enough for ~12 dB SNR against the speech bed


def speech(t, rng, gain=1.0):
    """Speech-ish: harmonic stack with gentle vibrato, syllabic AM, noise.
    Kept clear of the 50-70 Hz ENF band so the hum phase stays measurable:
    fundamentals at 220+ Hz, and the 10 Hz vibrato completes exactly one
    cycle per 0.1 s analysis window (periodic in-window -> no DFT leakage
    into the hum bins)."""
    vib = 0.5 * math.sin(2 * math.pi * 10.0 * t)
    am = 0.5 + 0.5 * math.sin(2 * math.pi * 0.7 * t)
    s = (0.30 * math.sin(2 * math.pi * 220 * t + vib)
         + 0.18 * math.sin(2 * math.pi * 330 * t + 1.3 * vib)
         + 0.10 * math.sin(2 * math.pi * 440 * t + 0.7 * vib))
    return gain * am * s + 0.015 * rng.gauss(0, 1)


def render(spliced):
    n = int(SR * DUR)
    rng_a = random.Random(7)
    rng_b = random.Random(99)
    out = []
    for i in range(n):
        t = i / SR
        if not spliced or t < 2.0:
            hum = HUM_A * math.sin(2 * math.pi * HUM_F * t)
            s = speech(t, rng_a) + hum
        else:
            # second take: hum clock shifted 4.2 ms -> phase jump at t=2.0,
            # different speech content, louder
            hum = HUM_A * math.sin(2 * math.pi * HUM_F * (t - 0.0042))
            s = speech(t, rng_b, gain=2.2) + hum
        out.append(max(-1.0, min(1.0, s)))
    return out


def write_wav(path, samples):
    with wave.open(path, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(SR)
        w.writeframes(struct.pack("<" + "h" * len(samples),
                                  *(int(s * 32767) for s in samples)))


def main():
    os.makedirs(OUT, exist_ok=True)
    write_wav(f"{OUT}/clean.wav", render(spliced=False))
    write_wav(f"{OUT}/spliced.wav", render(spliced=True))
    for f in sorted(os.listdir(OUT)):
        print("wrote", os.path.join(OUT, f))


if __name__ == "__main__":
    main()
