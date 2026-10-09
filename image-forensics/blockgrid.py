#!/usr/bin/env python3
"""blockgrid: JPEG block-grid artifact analysis on uncompressed BMPs.

Why this exists instead of true ELA: classic error-level analysis re-saves the
image at a known JPEG quality and maps per-pixel differences. The stdlib has
no JPEG *encoder*, so true ELA is not honestly implementable here (see the
README's Limitations). What *is* implementable: JPEG compresses in 8x8 blocks,
so a pasted region with a different compression history usually shows a
different 8x8 block-boundary discontinuity pattern than its surroundings.
This module measures, per 8x8 block, the ratio of gradient strength *across*
block edges vs *inside* blocks, then flags blocks that are statistical
outliers -- the same signal ELA exploits, without needing an encoder.
"""
import struct


def read_bmp24(data):
    """Minimal 24-bit uncompressed BMP reader. Returns (w, h, rows top-first)."""
    if data[:2] != b"BM":
        raise ValueError("not a BMP")
    (off,) = struct.unpack("<I", data[10:14])
    (w,) = struct.unpack("<i", data[18:22])
    (h,) = struct.unpack("<i", data[22:26])
    (bpp,) = struct.unpack("<H", data[28:30])
    if bpp != 24:
        raise ValueError(f"only 24-bit BMP supported, got {bpp}-bit")
    stride = (w * 3 + 3) & ~3
    rows = []
    for y in range(h):
        row = data[off + y * stride:off + y * stride + w * 3]
        rows.append([(row[x + 2], row[x + 1], row[x])
                     for x in range(0, w * 3, 3)])
    rows.reverse()  # BMP stores bottom-up
    return w, h, rows


def to_gray(rows):
    return [[(r + g + b) // 3 for (r, g, b) in row] for row in rows]


def block_scores(gray):
    """Per-8x8-block edge/interior gradient ratio. High ratio => the 8x8
    grid is visible there (blocky); outliers suggest a foreign region."""
    h, w = len(gray), len(gray[0])
    scores = []
    for by in range(h // 8):
        for bx in range(w // 8):
            x0, y0 = bx * 8, by * 8
            edge, inner, ne, ni = 0, 0, 0, 0
            for dy in range(8):
                y = y0 + dy
                for dx in range(8):
                    x = x0 + dx
                    if dx > 0:      # horizontal pair inside the block
                        d = abs(gray[y][x] - gray[y][x - 1])
                        inner, ni = inner + d, ni + 1
                    elif bx > 0:    # pair straddles the block's left edge
                        d = abs(gray[y][x] - gray[y][x - 1])
                        edge, ne = edge + d, ne + 1
                    if dy > 0:      # vertical pair inside the block
                        d = abs(gray[y][x] - gray[y - 1][x])
                        inner, ni = inner + d, ni + 1
                    elif by > 0:    # pair straddles the block's top edge
                        d = abs(gray[y][x] - gray[y-1][x])
                        edge, ne = edge + d, ne + 1
            scores.append((bx, by,
                           (edge / ne) / (inner / ni + 1e-6) if ne and ni else 1.0))
    return scores


def analyze(gray):
    """Returns dict: median score, MAD, list of anomalous (bx,by,score)."""
    scores = block_scores(gray)
    vals = sorted(s for _, _, s in scores)
    med = vals[len(vals) // 2]
    mad = sorted(abs(v - med) for v in vals)[len(vals) // 2] or 1e-6
    anom = [(bx, by, s) for bx, by, s in scores
            if s > med + 4 * mad and s > med * 1.8]
    anom.sort(key=lambda t: -t[2])
    return {"median": med, "mad": mad, "blocks": len(scores),
            "anomalies": anom[:25], "n_anomalies": len(anom)}


def ascii_map(gray, anom_set, cols=64):
    """Downsampled ASCII map; '#' marks anomalous 8x8 blocks."""
    h, w = len(gray), len(gray[0])
    bw, bh = w // 8, h // 8
    sx = max(1, bw // cols)
    lines = []
    for by in range(0, bh, max(1, bh // 24)):
        line = "".join("#" if (bx, by) in anom_set else "."
                        for bx in range(0, bw, sx))
        lines.append(line)
    return "\n".join(lines)
