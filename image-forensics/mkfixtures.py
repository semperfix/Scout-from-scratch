#!/usr/bin/env python3
"""mkfixtures: hand-craft test images for imgcheck (no PIL, no encoders).

Builds, byte by byte:
  fixtures/cam.jpg    - JPEG with APP1 Exif (Canon, DateTime, GPS), standard
                        IJG quantization tables, SOF0 640x480 grayscale
  fixtures/edited.jpg - JPEG with Software="Adobe Photoshop", CUSTOM
                        quantization tables, no GPS
  fixtures/ai.webp    - WebP (VP8X+XMP) carrying iptcExt:DigitalSourceType
                        trainedAlgorithmicMedia and a DALL-E CreatorTool
  fixtures/ela.bmp    - 160x160 BMP with a synthetic "pasted" block region
                        (blocks 5..8,5..8) for the block-grid analysis

Usage: python3 mkfixtures.py   (writes ./fixtures/)
"""
import os
import random
import struct

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

_ZIGZAG = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5,
    12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6, 7, 14, 21, 28,
    35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51,
    58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
]

IJG_LUMA = [
    16, 11, 10, 16, 24, 40, 51, 61,
    12, 12, 14, 19, 26, 58, 60, 55,
    14, 13, 16, 24, 40, 57, 69, 56,
    14, 17, 22, 29, 51, 87, 80, 62,
    18, 22, 37, 56, 68, 109, 103, 77,
    24, 35, 55, 64, 81, 104, 113, 92,
    49, 64, 78, 87, 103, 121, 120, 101,
    72, 92, 95, 98, 112, 100, 103, 99,
]
IJG_CHROMA = [
    17, 18, 24, 47, 99, 99, 99, 99,
    18, 21, 26, 66, 99, 99, 99, 99,
    24, 26, 56, 99, 99, 99, 99, 99,
    47, 66, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
]


def _ascii(s):
    return s.encode("ascii") + b"\x00"


def build_tiff(ifds, bo="<"):
    """ifds: list of entry-lists; entry = (tag, type, count, value_bytes).
    Returns TIFF bytes. Offsets for nested IFDs must be precomputed by the
    caller (see gps offset math below)."""
    n = len(ifds)
    sizes = [2 + 12 * len(e) + 4 for e in ifds]
    ifd_off = []
    p = 8
    for s in sizes:
        ifd_off.append(p)
        p += s
    data_off, blobs, cur = [], [], p
    for entries in ifds:
        offs = []
        for (_, _, _, vb) in entries:
            if len(vb) > 4:
                offs.append(cur)
                blobs.append(vb)
                cur += len(vb)
            else:
                offs.append(None)
        data_off.append(offs)
    out = bytearray()
    out += b"II" + struct.pack(bo + "H", 42) + struct.pack(bo + "I", ifd_off[0])
    for entries, offs in zip(ifds, data_off):
        out += struct.pack(bo + "H", len(entries))
        for (tag, typ, cnt, vb), doff in zip(entries, offs):
            out += struct.pack(bo + "HHI", tag, typ, cnt)
            out += vb + b"\x00" * (4 - len(vb)) if doff is None \
                else struct.pack(bo + "I", doff)
        out += struct.pack(bo + "I", 0)
    for b in blobs:
        out += b
    return bytes(out)


def _rat(vals):
    return b"".join(struct.pack("<2I", n, d) for n, d in vals)


def exif_cam():
    gps_ifd = [
        (1, 2, 2, _ascii("N")),
        (2, 5, 3, _rat([(33, 1), (45, 1), (0, 1)])),
        (3, 2, 2, _ascii("W")),
        (4, 5, 3, _rat([(84, 1), (23, 1), (0, 1)])),
    ]
    ifd0 = [
        (0x010F, 2, 6, _ascii("Canon")),
        (0x0110, 2, 21, _ascii("Canon EOS 5D Mark IV")),
        (0x0132, 2, 20, _ascii("2024:05:01 12:00:00")),
    ]
    gps_off = 8 + (2 + 12 * (len(ifd0) + 1) + 4)  # +1: the GPS ptr entry itself
    ifd0.append((0x8825, 4, 1, struct.pack("<I", gps_off)))
    return build_tiff([ifd0, gps_ifd])


def exif_edited():
    ifd0 = [
        (0x010F, 2, 6, _ascii("Canon")),
        (0x0110, 2, 21, _ascii("Canon EOS 5D Mark IV")),
        (0x0131, 2, 26, _ascii("Adobe Photoshop 25.0")),
        (0x0132, 2, 20, _ascii("2024:05:01 12:00:00")),
    ]
    return build_tiff([ifd0])


def dqt_segment(tables):
    """tables: list of (table_id, 64 natural-order values)."""
    payload = bytearray()
    for tid, nat in tables:
        payload.append(tid)  # 8-bit precision, table id
        payload += bytes(nat[_ZIGZAG[i]] for i in range(64))
    seg = b"\xff\xdb" + struct.pack(">H", 2 + len(payload)) + bytes(payload)
    return seg


def _seg(marker, payload):
    return bytes([0xFF, marker]) + struct.pack(">H", 2 + len(payload)) + payload


def make_jpeg(path, exif, tables):
    out = bytearray(b"\xff\xd8")  # SOI
    out += _seg(0xE0, b"JFIF\x00\x01\x02\x00\x00\x01\x00\x01\x00\x00")  # APP0
    out += _seg(0xE1, b"Exif\x00\x00" + exif)  # APP1
    out += dqt_segment(tables)
    out += _seg(0xC0, struct.pack(">BHHB", 8, 480, 640, 1))  # SOF0 gray
    # minimal DHT: one 1-bit DC code (symbol 0), one 1-bit AC code (EOB)
    dht = bytes([0x00, 0, 1] + [0] * 14 + [0])          # DC table 0
    dht += bytes([0x10, 0, 1] + [0] * 14 + [0x00])       # AC table 0
    out += _seg(0xC4, dht)
    sos = bytes([1, 0x00, 0x00, 0x00, 0x3F, 0x00])  # 1 comp, DC0/AC0
    out += _seg(0xDA, sos) + b"\x00\x00\x00\x00" + b"\xff\xd9"  # scan + EOI
    open(path, "wb").write(bytes(out))


def make_webp(path):
    def chunk(fourcc, payload):
        pad = b"\x00" if len(payload) & 1 else b""
        return fourcc + struct.pack("<I", len(payload)) + payload + pad

    vp8x = bytes([0x0C]) + b"\x00\x00\x00"          # flags: EXIF + XMP present
    vp8x += (511).to_bytes(3, "little") + (511).to_bytes(3, "little")
    xmp = (b'<x:xmpmeta xmlns:x="adobe:ns:meta/">'
           b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
           b'<rdf:Description xmp:CreatorTool="DALL-E 3" '
           b'xmlns:xmp="http://ns.adobe.com/xap/1.0/" '
           b'xmlns:iptcExt="http://iptc.org/std/Iptc4xmpExt/2008-02-29/">'
           b'<iptcExt:DigitalSourceType>'
           b'http://cv.iptc.org/newscodes/c2pa/trainedAlgorithmicMedia'
           b'</iptcExt:DigitalSourceType></rdf:Description>'
           b'</rdf:RDF></x:xmpmeta>')
    # minimal VP8 keyframe header: tag, 0x9D012A, 512x512
    vp8 = bytes([0x10, 0x00, 0x00]) + b"\x9d\x01\x2a"
    vp8 += struct.pack("<H", 512) + struct.pack("<H", 512) + b"\x00" * 8
    exif = build_tiff([[(0x010F, 2, 7, _ascii("OpenAI")),
                        (0x0131, 2, 8, _ascii("DALL-E"))]])
    body = chunk(b"VP8X", vp8x) + chunk(b"VP8 ", vp8) \
        + chunk(b"XMP ", xmp) + chunk(b"EXIF", exif)
    open(path, "wb").write(b"RIFF" + struct.pack("<I", 4 + len(body))
                           + b"WEBP" + body)


def make_bmp(path):
    w = h = 160
    rng = random.Random(42)
    rows = []
    for y in range(h):
        row = []
        for x in range(w):
            v = 110 + (x * 40) // w + rng.randint(-6, 6)  # gradient + noise
            # synthetic "pasted" region: blocks 5..8,5..8 get per-block
            # mean shifts + coarse quantization (different pipeline history)
            bx, by = x // 8, y // 8
            if 5 <= bx <= 8 and 5 <= by <= 8:
                v = ((v + (bx * 37 + by * 53)) // 10) * 10
            row.append(max(0, min(255, v)))
        rows.append(row)
    stride = (w * 3 + 3) & ~3
    px = bytearray()
    for row in reversed(rows):  # bottom-up
        for v in row:
            px += bytes([v, v, v])
        px += b"\x00" * (stride - w * 3)
    hdr = b"BM" + struct.pack("<IHHI", 14 + 40 + len(px), 0, 0, 54)
    dib = struct.pack("<IiiHHIIiiII", 40, w, h, 1, 24, 0, len(px), 0, 0, 0, 0)
    open(path, "wb").write(hdr + dib + bytes(px))


def main():
    os.makedirs(OUT, exist_ok=True)
    custom = [(0, [max(1, v // 2) for v in IJG_LUMA]),
              (1, [max(1, v // 2) for v in IJG_CHROMA])]
    make_jpeg(f"{OUT}/cam.jpg", exif_cam(),
              [(0, IJG_LUMA), (1, IJG_CHROMA)])
    make_jpeg(f"{OUT}/edited.jpg", exif_edited(), custom)
    make_webp(f"{OUT}/ai.webp")
    make_bmp(f"{OUT}/ela.bmp")
    for f in sorted(os.listdir(OUT)):
        print("wrote", os.path.join(OUT, f))


if __name__ == "__main__":
    main()
