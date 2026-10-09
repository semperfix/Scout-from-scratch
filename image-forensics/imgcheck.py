#!/usr/bin/env python3
"""imgcheck: image-forensics triage for JPEG / WebP / BMP.

JPEG: hand-parsed markers, EXIF (both endiannesses, IFD0/EXIF/GPS), XMP,
      quantization-table fingerprints vs the known IJG standard tables.
WebP:  RIFF/VP8/VP8L/VP8X header parse, XMP scan for AI-generation markers.
BMP:   8x8 block-grid discontinuity analysis (stdlib can't JPEG-encode, so
       true ELA is out; this is the honest, encoder-free proxy).

Usage: python3 imgcheck.py image.jpg
Exit 0 always; the VERDICT line is the machine-readable result
(CLEAN / WORTH-A-LOOK / TAMPER-SUSPECT).
"""
import argparse
import sys

from jpegparse import parse_jpeg, KNOWN_DQT, gps_decimal
from webpparse import parse_webp, xmp_flags, AI_MARKERS, EDITOR_MARKERS
from blockgrid import read_bmp24, to_gray, analyze, ascii_map

# Software-tag strings that mean "this file passed through an editor".
_EDITOR_HITS = ["photoshop", "gimp", "lightroom", "paint.net", "canva",
                "pixlr", "affinity", "capture one", "snapseed"]
# Software-tag strings that mean "this image was synthesized".
_AI_HITS = ["dall", "midjourney", "stable diffusion", "firefly",
            "generative", "synthetic", "ai generated"]


def detect_kind(data):
    if data[:2] == b"\xff\xd8":
        return "JPEG"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "WebP"
    if data[:2] == b"BM":
        return "BMP"
    return "unknown"


def triage_jpeg(path, data):
    j = parse_jpeg(data)
    notes, flags = [], []
    sof = j["sof"]
    print(f"file: {path}  (JPEG"
          + (f", {sof['width']}x{sof['height']}, {sof['components']}ch, {sof['name']}" if sof else ", no SOF")
          + ")")
    segline = " ".join(s["name"] for s in j["segments"])
    print(f"markers: {segline}")

    exif = j.get("exif")
    if isinstance(exif, dict) and "ifd0" in exif:
        ifd0, ex, gps = exif["ifd0"], exif["exif"], exif["gps"]
        print(f"EXIF ({'little' if exif['endian'] == 'II' else 'big'}-endian TIFF):")
        for k in ("Make", "Model", "DateTime", "Software"):
            if k in ifd0:
                print(f"  {k}: {ifd0[k]}")
        for k in ("DateTimeOriginal", "DateTimeDigitized",
                  "PixelXDimension", "PixelYDimension"):
            if k in ex:
                print(f"  {k}: {ex[k]}")
        xy = j["sof"]
        if "PixelXDimension" in ex and xy and \
                (ex["PixelXDimension"] != xy["width"]
                 or ex["PixelYDimension"] != xy["height"]):
            flags.append("EXIF pixel dims disagree with SOF dims "
                         f"({ex['PixelXDimension']}x{ex['PixelYDimension']} vs "
                         f"{xy['width']}x{xy['height']})")
        dec = gps_decimal(gps)
        if dec:
            print(f"  GPS: {dec[0]:.6f}, {dec[1]:.6f}")
            notes.append("GPS coordinates present (location privacy)")
        sw = str(ifd0.get("Software", "")).lower()
        if any(h in sw for h in _AI_HITS):
            flags.append(f"AI-generator software tag: {ifd0['Software']!r}")
        elif any(h in sw for h in _EDITOR_HITS):
            flags.append(f"editor software tag: {ifd0['Software']!r}")
    else:
        notes.append("no EXIF (stripped, or never had any)")

    if j.get("xmp"):
        xf = xmp_flags(j["xmp"])
        print(f"XMP: present ({len(j['xmp'])} chars)")
        if xf["ai"]:
            flags.append("XMP AI-generation markers: " + ", ".join(xf["ai"]))
        if xf["editors"]:
            flags.append("XMP editor markers: " + ", ".join(xf["editors"]))
    for c in j.get("com", []):
        print(f"COM: {c[:80]}")

    if j["dqt"]:
        print("quantization tables:")
        for t in j["dqt"]:
            known = KNOWN_DQT.get(t["md5"])
            print(f"  table {t['id']}: {known or 'CUSTOM/NONSTANDARD'}"
                  f"  md5={t['md5'][:16]}...")
            if not known:
                flags.append(f"nonstandard DQT table {t['id']} "
                             "(re-encoded or custom pipeline)")
    else:
        notes.append("no DQT segments found")

    return notes, flags


def triage_webp(path, data):
    w = parse_webp(data)
    notes, flags = [], []
    dims = w["vp8x"] or w["vp8"] or w["vp8l"]
    print(f"file: {path}  (WebP"
          + (f", {dims['width']}x{dims['height']}" if dims and "width" in dims else "")
          + ")")
    print("chunks: " + " ".join(f"{f}({s})" for f, s in w["chunks"]))
    if w["vp8x"]:
        v = w["vp8x"]
        print(f"VP8X: canvas {v['width']}x{v['height']}, "
              f"alpha={v['alpha']} anim={v['animation']} "
              f"iccp={v['iccp']} exif-chunk={v['exif']} xmp-chunk={v['xmp']}")
    if w["vp8"]:
        v = w["vp8"]
        print(f"VP8: {v.get('frame_type', '?')} frame "
              f"{v.get('width', '?')}x{v.get('height', '?')}")
    if w["vp8l"]:
        v = w["vp8l"]
        print(f"VP8L: lossless {v['width']}x{v['height']}")
    exif = w.get("exif")
    if isinstance(exif, dict) and "ifd0" in exif:
        print("EXIF chunk:")
        for k, v in exif["ifd0"].items():
            print(f"  {k}: {v}")
        sw = str(exif["ifd0"].get("Software", "")).lower()
        if any(h in sw for h in _AI_HITS):
            flags.append(f"AI-generator software tag: {exif['ifd0']['Software']!r}")
    if w.get("xmp"):
        xf = xmp_flags(w["xmp"])
        print(f"XMP: present ({len(w['xmp'])} chars)")
        if xf["ai"]:
            flags.append("XMP AI-generation markers: " + ", ".join(xf["ai"]))
        if xf["editors"]:
            flags.append("XMP editor markers: " + ", ".join(xf["editors"]))
    else:
        notes.append("no XMP chunk")
    return notes, flags


def triage_bmp(path, data):
    w, h, rows = read_bmp24(data)
    notes, flags = [], []
    print(f"file: {path}  (BMP, {w}x{h})")
    print("block-grid analysis (8x8 JPEG-grid discontinuity proxy for ELA):")
    a = analyze(to_gray(rows))
    print(f"  {a['blocks']} blocks, median edge/interior ratio "
          f"{a['median']:.3f} (MAD {a['mad']:.3f})")
    if a["anomalies"]:
        print(f"  {a['n_anomalies']} anomalous blocks; hottest:")
        for bx, by, s in a["anomalies"][:10]:
            print(f"    block ({bx},{by}) px~({bx*8},{by*8}) score {s:.2f}")
        print(ascii_map(to_gray(rows),
                        {(bx, by) for bx, by, _ in a["anomalies"]}))
        flags.append(f"{a['n_anomalies']} blocks with anomalous 8x8-grid "
                     "discontinuity (possible pasted region)")
    else:
        notes.append("block grid uniform -- no localized anomalies")
    return notes, flags


def main():
    ap = argparse.ArgumentParser(
        description="Image forensics triage: EXIF/DQT fingerprinting (JPEG), "
                    "XMP AI-metadata scan (WebP), block-grid analysis (BMP).")
    ap.add_argument("image", help="JPEG, WebP, or BMP file to triage")
    args = ap.parse_args()
    data = open(args.image, "rb").read()
    kind = detect_kind(data)
    if kind == "JPEG":
        notes, flags = triage_jpeg(args.image, data)
    elif kind == "WebP":
        notes, flags = triage_webp(args.image, data)
    elif kind == "BMP":
        notes, flags = triage_bmp(args.image, data)
    else:
        sys.exit(f"unrecognized image format for {args.image}")

    ai_hit = any("AI-generation" in f or "AI-generator" in f for f in flags)
    if ai_hit:
        print("VERDICT: TAMPER-SUSPECT -- " + "; ".join(flags))
    elif flags:
        print("VERDICT: WORTH-A-LOOK -- " + "; ".join(flags))
    else:
        print("VERDICT: CLEAN" + (" (" + "; ".join(notes) + ")" if notes else ""))


if __name__ == "__main__":
    main()
