#!/usr/bin/env python3
"""tonedec: telephony-tone forensics CLI. All DSP by hand (see dsp.py).

  gen-dtmf DIGITS OUT.wav [--snr DB]      synthesize keypad tones
  decode-dtmf IN.wav                      recover digits from audio
  gen-morse "TEXT" OUT.wav [--wpm N] [--snr DB]
  decode-morse IN.wav [--wpm N]
  tones IN.wav [-n 8]                     strongest frequency components
"""
import argparse
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dsp import (dtmf_encode, dtmf_decode, morse_encode, morse_decode,
                 wav_write, wav_read, spectrum, hann)


def cmd_gen_dtmf(a):
    x = dtmf_encode(a.digits, snr_db=a.snr)
    wav_write(a.out, x)
    print(f"wrote {a.out}: {len(a.digits)} digits @ 8 kHz")


def cmd_decode_dtmf(a):
    x, fs = wav_read(a.wav)
    print(dtmf_decode(x, fs))


def cmd_gen_morse(a):
    x = morse_encode(a.text, wpm=a.wpm, snr_db=a.snr)
    wav_write(a.out, x)
    print(f"wrote {a.out}: {a.wpm} wpm @ 8 kHz")


def cmd_decode_morse(a):
    x, fs = wav_read(a.wav)
    print(morse_decode(x, fs, wpm=a.wpm))


def cmd_tones(a):
    x, fs = wav_read(a.wav)
    n = 1
    while n * 2 <= len(x):
        n <<= 1
    x = x[:n] * hann(n)
    freqs, mag = spectrum(x, fs)
    order = np.argsort(mag)[::-1]
    seen = []
    for k in order:
        f = freqs[k]
        if all(abs(f - s) > 15 for s in seen):   # dedupe sidelobes
            seen.append(f)
            print(f"{f:8.1f} Hz  mag {mag[k]:.4f}")
            if len(seen) >= a.n:
                break


p = argparse.ArgumentParser(prog="tonedec")
sub = p.add_subparsers(dest="cmd", required=True)

s = sub.add_parser("gen-dtmf"); s.add_argument("digits"); s.add_argument("out")
s.add_argument("--snr", type=float, default=None); s.set_defaults(f=cmd_gen_dtmf)
s = sub.add_parser("decode-dtmf"); s.add_argument("wav"); s.set_defaults(f=cmd_decode_dtmf)
s = sub.add_parser("gen-morse"); s.add_argument("text"); s.add_argument("out")
s.add_argument("--wpm", type=int, default=20); s.add_argument("--snr", type=float, default=None)
s.set_defaults(f=cmd_gen_morse)
s = sub.add_parser("decode-morse"); s.add_argument("wav")
s.add_argument("--wpm", type=int, default=20); s.set_defaults(f=cmd_decode_morse)
s = sub.add_parser("tones"); s.add_argument("wav"); s.add_argument("-n", type=int, default=8)
s.set_defaults(f=cmd_tones)

a = p.parse_args()
a.f(a)
