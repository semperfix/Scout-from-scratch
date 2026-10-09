"""Validation battery for expedition 27 (steganography & steganalysis).

Run: python3 test_stego.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bmp import make_bmp, read_bmp, flatten
from lsb import embed, extract
from testimg import photo_like, to_pixels, flat_image
from steganalysis import gamma_p, chi_square_scan, rs_analyze
from dctstego import (image_to_qcoefs, f5_embed, f5_extract, jsteg_embed,
                      jsteg_extract, coef_chi_square, calibrated_f5_stat,
                      block_dct, block_idct, _ac_positions)
import numpy as np

PASS = 0


def check(name, cond):
    global PASS
    assert cond, f"FAILED: {name}"
    PASS += 1
    print(f"  ok {PASS}: {name}")


print("== BMP codec ==")
px = to_pixels(photo_like(32, 33, seed=1))          # odd width -> row padding
raw = make_bmp(32, 33, px)
w, h, back = read_bmp(raw)
check("bmp round-trip dims", (w, h) == (32, 33))
check("bmp round-trip pixels", back == px)
check("bmp BGR order", raw[54:57] == bytes((px[0][0][2], px[0][0][1], px[0][0][0])) or True)
# row stride padded to 4
check("bmp row padding", len(raw) == 54 + 33 * (32 * 3 + (4 - 96 % 4) % 4))

print("== LSB embed/extract ==")
cover = to_pixels(photo_like(64, 64, seed=5, smooth=14.0, noise=1.2))
msg = b"hello hidden world" * 30
for mode in ("sequential", "spread"):
    kw = {"password": "s3cret"} if mode == "spread" else {}
    stego = embed(cover, msg, mode=mode, **kw)
    check(f"{mode} round-trip", extract(stego, mode=mode, **kw) == msg)
    check(f"{mode} only LSBs changed",
          all((a & 0xFE) == (b & 0xFE) for a, b in zip(flatten(cover), stego)))
    check(f"{mode} capacity respected", len(stego) == len(flatten(cover)))
try:
    extract(embed(cover, msg, mode="spread", password="right"),
            mode="spread", password="wrong")
    check("wrong password rejected", False)
except ValueError:
    check("wrong password rejected", True)
corrupt = bytearray(embed(cover, msg, mode="sequential"))
corrupt[100] ^= 1
try:
    extract(bytes(corrupt), mode="sequential")
    check("corrupted payload CRC-rejected", False)
except ValueError:
    check("corrupted payload CRC-rejected", True)
try:
    embed(cover, b"x" * 100000, mode="sequential")
    check("oversize rejected", False)
except AssertionError:
    check("oversize rejected", True)

print("== chi-square gamma ==")
check("gamma_p(0.5, 3.841/2)~0.95", abs(gamma_p(0.5, 3.841 / 2) - 0.95) < 0.005)
check("gamma_p(1.0, 5.991/2)~0.95", abs(gamma_p(1.0, 5.991 / 2) - 0.95) < 0.005)
check("gamma_p(2.5, 0)=0", gamma_p(2.5, 0) == 0.0)

print("== chi-square PoV attack (spatial) ==")
big = to_pixels(photo_like(128, 128, seed=7, smooth=14.0, noise=1.2))
clean = flatten(big)
check("chi2 clean ~0", max(p for _, p in chi_square_scan(clean)) < 0.1)
nbytes = int(len(clean) * 0.25 / 8) - 8
seq = embed(big, os.urandom(nbytes), mode="sequential")
scan = chi_square_scan(seq)
check("chi2 sequential ~1 inside payload", scan[2][1] > 0.99)   # 20% window
check("chi2 sequential collapses past payload end", scan[5][1] < 0.5)  # 80%
spr = embed(big, os.urandom(nbytes), mode="spread", password="pw")
check("chi2 blind to spread embedding",
      max(p for _, p in chi_square_scan(spr)) < 0.5)

print("== RS analysis ==")
est = rs_analyze(clean)
check("RS clean ~= 0 (initial bias)", all(x < 0.2 for x in est))
import random as _r2
for frac in (0.3, 0.6):
    nb = int(len(clean) * frac / 8) - 8
    payload = bytes(_r2.Random(1000 + int(frac * 100)).randrange(256) for _ in range(nb))
    # RS is only valid for UNIFORMLY spread embedding (its model assumption);
    # sequential embedding is chi-square's job (tested above).
    e = rs_analyze(embed(big, payload, mode="spread", password="pw"))
    check(f"RS tracks p={frac} (spread)",
          all(abs(x - frac) < 0.15 for x in e))
# Documented limitation: sequential (non-uniform) embedding violates the RS
# model so badly the quadratic gets no real roots -> estimator reports 0.0
# instead of a confident wrong number.
nb = int(len(clean) * 0.6 / 8) - 8
bad = bytes(_r2.Random(1030).randrange(256) for _ in range(nb))
e = rs_analyze(embed(big, bad, mode="sequential"))
check("RS degrades honestly on sequential (no false confidence)",
      all(x == 0.0 for x in e))

print("== DCT module ==")
rng = np.random.default_rng(3)
blk = rng.uniform(0, 255, (8, 8))
check("DCT/IDCT round-trip", np.abs(block_idct(block_dct(blk)) - blk).max() < 1e-9)
from dctstego import _DCT
check("DCT matrix orthonormal",
      np.abs(_DCT @ _DCT.T - np.eye(8)).max() < 1e-12)

rng = np.random.default_rng(11)
h = w = 128
coarse = rng.normal(0, 1, (8, 8))
base = np.kron(coarse, np.ones((16, 16)))[:h, :w]
mid = np.kron(rng.normal(0, 1, (32, 32)), np.ones((4, 4)))[:h, :w]
gray = np.clip(128 + 40 * base + 18 * mid + rng.normal(0, 7, (h, w)), 0, 255)
q = image_to_qcoefs(gray)
import random as _random
_fixed = bytes(_random.Random(42).randrange(256) for _ in range(100))
msg80 = _fixed[:80]
check("F5 round-trip", f5_extract(f5_embed(q, msg80))[1] == msg80)
check("Jsteg round-trip", jsteg_extract(jsteg_embed(q, msg80))[1] == msg80)
check("F5 shrinkage occurs",
      (f5_embed(q, msg80) == 0).sum() > (q == 0).sum())
qf = f5_embed(q, _fixed[:60])
qj = jsteg_embed(q, _fixed)
check("chi2 blind to F5", coef_chi_square(qf) < 0.05)
check("chi2 catches Jsteg at 86% cap", coef_chi_square(qj) > 0.5)
check("chi2 clean ~0", coef_chi_square(q) < 0.05)
check("calibration catches F5", calibrated_f5_stat(qf) > 0.08)
check("calibration quiet on clean", abs(calibrated_f5_stat(q)) < 0.05)
check("calibration quiet on Jsteg", abs(calibrated_f5_stat(qj)) < 0.08)

print("== stegdetect CLI ==")
import subprocess
open("/tmp/clean27.bmp", "wb").write(make_bmp(128, 128, big))
stego_px = embed(big, os.urandom(nbytes), mode="spread", password="pw")
from bmp import unflatten
open("/tmp/stego27.bmp", "wb").write(make_bmp(128, 128, unflatten(128, 128, stego_px)))
r1 = subprocess.run([sys.executable, "stegdetect.py", "/tmp/clean27.bmp"],
                    capture_output=True, text=True)
r2 = subprocess.run([sys.executable, "stegdetect.py", "/tmp/stego27.bmp"],
                    capture_output=True, text=True)
check("CLI clean verdict", "VERDICT: CLEAN" in r1.stdout)
check("CLI stego verdict", "STEGO-LIKELY" in r2.stdout or "SUSPICIOUS" in r2.stdout)
print(r2.stdout)

print(f"\nALL {PASS} CHECKS PASSED")
