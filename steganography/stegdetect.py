#!/usr/bin/env python3
"""stegdetect: LSB-stego triage for 24-bit BMP files.

Runs three independent detectors and prints a verdict:
  * chi-square PoV scan  - catches SEQUENTIAL embedding, localizes payload end
  * RS analysis           - estimates embedding rate, works on SPREAD too
  * smooth-region LSB agreement - weak supporting signal

Usage: python3 stegdetect.py suspect.bmp
Exit 0 always; the VERDICT line is the machine-readable result.
"""
import sys
from bmp import read_bmp, flatten
from steganalysis import chi_square_scan, rs_analyze, lsb_plane_stats, smooth_lsb_agreement


def triage(path):
    with open(path, "rb") as f:
        data = f.read()
    w, h, px = read_bmp(data)
    flat = flatten(px)
    n = len(flat)

    scan = chi_square_scan(flat)
    rs = rs_analyze(flat)
    lsb = lsb_plane_stats(flat)

    max_chi = max(p for _, p in scan)
    # payload-end localization: last window with p > 0.9 before collapse
    end = None
    for (w_, p), (w2, p2) in zip(scan, scan[1:]):
        if p > 0.9 and p2 < 0.5:
            end = (w_, w2)
            break
    max_rs = max(rs)
    agree = smooth_lsb_agreement(flat, w, h)

    print(f"file: {path}  ({w}x{h}, {n} channel bytes)")
    print(f"chi-square scan (window -> P(embedded)):")
    for w_, p in scan:
        print(f"  {w_*100:5.1f}%  {p:.4f}")
    print(f"RS embedding-rate estimate R/G/B: {[round(x, 3) for x in rs]}")
    print(f"smooth-region LSB agreement: {agree:.3f} (clean ~0.70; embedded -> ~0.60)")

    signals = []
    if max_chi > 0.95:
        signals.append(f"chi-square P(embedded)={max_chi:.3f}"
                       + (f", payload ends ~{end[0]*100:.0f}-{end[1]*100:.0f}%" if end else ""))
    if max_rs > 0.15:
        signals.append(f"RS rate ~{max_rs:.2f} of capacity")
    if agree < 0.64:
        signals.append(f"LSB plane noisy in smooth regions ({agree:.2f})")

    if not signals:
        print("VERDICT: CLEAN (no detector fired)")
    elif max_chi > 0.95 or max_rs > 0.3:
        print("VERDICT: STEGO-LIKELY -- " + "; ".join(signals))
    else:
        print("VERDICT: SUSPICIOUS -- " + "; ".join(signals))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python3 stegdetect.py suspect.bmp")
    triage(sys.argv[1])
