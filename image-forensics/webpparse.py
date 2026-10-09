#!/usr/bin/env python3
"""webpparse: hand-rolled RIFF/WebP container + VP8/VP8L/VP8X header parser.

Extracts canvas size, animation/alpha/EXIF/XMP presence, embedded XMP text
(for AI-generation metadata like iptcExt:DigitalSourceType), and any EXIF
chunk (parsed with jpegparse's TIFF reader -- WebP stores raw TIFF there).
"""
import struct
from jpegparse import parse_tiff

# Strings that indicate synthetic/AI-generated imagery in XMP metadata.
AI_MARKERS = [
    "trainedAlgorithmicMedia", "compositeWithTrainedAlgorithmicMedia",
    "DALL", "Midjourney", "Stable Diffusion", "Firefly",
    "generative", "artificial intelligence", "ai generated",
]

EDITOR_MARKERS = [
    "Photoshop", "Lightroom", "GIMP", "Paint.NET", "Canva", "Pixlr",
    "Affinity", "Capture One",
]


def parse_webp(data):
    """Parse a WebP file. Returns dict; raises ValueError on bad magic."""
    if data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        raise ValueError("not a WebP file (missing RIFF/WEBP)")
    (riff_size,) = struct.unpack("<I", data[4:8])
    chunks, pos, end = [], 12, min(12 + riff_size, len(data))
    first_fourcc = None
    while pos + 8 <= end:
        fourcc = data[pos:pos + 4].decode("ascii", "replace")
        (size,) = struct.unpack("<I", data[pos + 4:pos + 8])
        payload = data[pos + 8:pos + 8 + size]
        chunks.append({"fourcc": fourcc, "size": size, "payload": payload})
        if first_fourcc is None:
            first_fourcc = fourcc
        pos += 8 + size + (size & 1)  # chunks are 2-byte aligned
    out = {"chunks": [(c["fourcc"], c["size"]) for c in chunks],
           "vp8x": None, "vp8": None, "vp8l": None,
           "xmp": None, "exif": None, "iccp": False, "anim": None}
    for c in chunks:
        f, p = c["fourcc"], c["payload"]
        if f == "VP8X":
            out["vp8x"] = _parse_vp8x(p)
        elif f == "VP8":
            out["vp8"] = _parse_vp8_frame(p)
        elif f == "VP8L":
            out["vp8l"] = _parse_vp8l(p)
        elif f == "XMP ":
            out["xmp"] = p.decode("utf-8", "replace")
        elif f == "EXIF":
            try:
                out["exif"] = parse_tiff(p)
            except ValueError as e:
                out["exif"] = {"error": str(e)}
        elif f == "ICCP":
            out["iccp"] = True
        elif f == "ANIM":
            out["anim"] = {"bgcolor": p[:4].hex(), "loops": struct.unpack("<H", p[4:6])[0]}
    return out


def _parse_vp8x(p):
    if len(p) < 10:
        return {"error": "truncated VP8X"}
    flags = p[0]
    w = int.from_bytes(p[4:7], "little") + 1
    h = int.from_bytes(p[7:10], "little") + 1
    return {
        "width": w, "height": h,
        "iccp": bool(flags & 0x20), "alpha": bool(flags & 0x10),
        "exif": bool(flags & 0x08), "xmp": bool(flags & 0x04),
        "animation": bool(flags & 0x02),
    }


def _parse_vp8_frame(p):
    """VP8 lossy bitstream frame header: 3-byte tag, 0x9D012A, 14-bit dims."""
    if len(p) < 10 or p[3:6] != b"\x9d\x01\x2a":
        return {"error": "bad VP8 frame header"}
    tag = int.from_bytes(p[0:3], "little")
    w = struct.unpack("<H", p[6:8])[0] & 0x3FFF
    h = struct.unpack("<H", p[8:10])[0] & 0x3FFF
    return {"frame_type": "key" if (tag & 1) == 0 else "inter",
            "width": w, "height": h}


def _parse_vp8l(p):
    """VP8L lossless header: 0x2F then 14-bit w-1, 14-bit h-1, alpha, version."""
    if len(p) < 5 or p[0] != 0x2F:
        return {"error": "bad VP8L signature"}
    bits = int.from_bytes(p[1:5], "little")
    return {"width": (bits & 0x3FFF) + 1,
            "height": ((bits >> 14) & 0x3FFF) + 1,
            "alpha_used": bool((bits >> 28) & 1),
            "version": (bits >> 29) & 7}


def xmp_flags(xmp_text):
    """Scan XMP XML text for AI-generation and editor markers."""
    if not xmp_text:
        return {"ai": [], "editors": []}
    low = xmp_text.lower()
    return {
        "ai": [m for m in AI_MARKERS if m.lower() in low],
        "editors": [m for m in EDITOR_MARKERS if m.lower() in low],
    }
