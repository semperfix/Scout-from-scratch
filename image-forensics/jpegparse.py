#!/usr/bin/env python3
"""jpegparse: hand-rolled JPEG marker walk, DQT extraction, EXIF/TIFF parser.

No PIL, no piexif -- every byte is walked by hand. Exposes:
  parse_jpeg(data)   -> dict with segments, sof, dqt tables, exif, xmp
  parse_tiff(tiff)   -> (endian, tags) with nested EXIF/GPS IFDs resolved
  dqt_fingerprints(dqt) -> per-table md5 + match against known IJG tables
"""
import hashlib
import struct

# Markers that carry no length field
_NO_LEN = {0xD8, 0xD9, 0x01} | set(range(0xD0, 0xD8))

_MARKER_NAMES = {
    0xD8: "SOI", 0xD9: "EOI", 0xDA: "SOS", 0xDB: "DQT", 0xC4: "DHT",
    0xC0: "SOF0", 0xC1: "SOF1", 0xC2: "SOF2", 0xC3: "SOF3",
    0xDD: "DRI", 0xFE: "COM",
}
for _n in range(16):
    _MARKER_NAMES[0xE0 + _n] = f"APP{_n}"
for _n in range(0xD0, 0xD8):
    _MARKER_NAMES[_n] = f"RST{_n - 0xD0}"


def marker_name(code):
    return _MARKER_NAMES.get(code, f"0x{code:02X}")


def parse_jpeg(data):
    """Walk JPEG markers. Returns dict; raises ValueError on bad SOI."""
    if data[:2] != b"\xff\xd8":
        raise ValueError("not a JPEG (missing SOI)")
    segs, pos, n = [], 2, len(data)
    while pos < n:
        if data[pos] != 0xFF:
            raise ValueError(f"expected marker at offset {pos}")
        # skip fill bytes
        while pos < n and data[pos] == 0xFF:
            pos += 1
        if pos >= n:
            break
        code = data[pos]
        pos += 1
        if code == 0x00:  # stuffed byte inside scan data, not a marker
            continue
        if code in _NO_LEN:
            segs.append({"marker": code, "name": marker_name(code),
                         "offset": pos - 2, "length": 0, "payload": b""})
            if code == 0xD9:  # EOI
                break
            continue
        if pos + 2 > n:
            raise ValueError("truncated marker length")
        (length,) = struct.unpack(">H", data[pos:pos + 2])
        payload = data[pos + 2:pos + length]
        segs.append({"marker": code, "name": marker_name(code),
                     "offset": pos - 2, "length": length, "payload": payload})
        pos += length
        if code == 0xDA:  # SOS: scan data runs to next marker; skip it
            while pos + 1 < n:
                if data[pos] == 0xFF and data[pos + 1] != 0x00 \
                        and data[pos + 1] != 0xFF:
                    break
                pos += 1
    return _enrich(segs)


def _enrich(segs):
    out = {"segments": segs, "sof": None, "dqt": [], "app0": None,
           "exif": None, "xmp": None, "com": []}
    for s in segs:
        code, p = s["marker"], s["payload"]
        if code in (0xC0, 0xC1, 0xC2, 0xC3) and len(p) >= 6 and out["sof"] is None:
            prec, h, w, ncomp = struct.unpack(">BHHB", p[:6])
            out["sof"] = {"name": s["name"], "precision": prec,
                          "width": w, "height": h, "components": ncomp}
        elif code == 0xDB:
            out["dqt"].extend(_parse_dqt(p))
        elif code == 0xE0 and p[:5] == b"JFIF\x00":
            out["app0"] = {"kind": "JFIF", "version": f"{p[5]}.{p[6]:02d}",
                           "density": struct.unpack(">HH", p[8:12]),
                           "units": p[7]}
        elif code == 0xE1:
            if p[:6] == b"Exif\x00\x00":
                try:
                    out["exif"] = parse_tiff(p[6:])
                except ValueError as e:
                    out["exif"] = {"error": str(e)}
            elif p.startswith(b"http://ns.adobe.com/xap/1.0/\x00"):
                out["xmp"] = p[29:].decode("utf-8", "replace")
        elif code == 0xFE:
            out["com"].append(p.decode("utf-8", "replace"))
    return out


def _parse_dqt(payload):
    """DQT payload -> list of (table_id, precision_bits, 64 natural-order bytes)."""
    tables, pos = [], 0
    while pos < len(payload):
        info = payload[pos]
        pos += 1
        prec = 8 if (info >> 4) == 0 else 16
        tid = info & 0x0F
        nbytes = 64 * (prec // 8)
        raw = payload[pos:pos + nbytes]
        pos += nbytes
        if len(raw) < nbytes:
            break
        if prec == 8:
            natural = bytes(raw[_ZIGZAG_INV[i]] for i in range(64))
        else:
            vals = struct.unpack(">64H", raw)
            natural = struct.pack(">64H", *(vals[_ZIGZAG_INV[i]] for i in range(64)))
        tables.append({"id": tid, "precision": prec, "natural": natural,
                       "md5": hashlib.md5(natural).hexdigest()})
    return tables


# Zig-zag scan order: DQT stores coefficients in zigzag; index i of the
# natural (row-major) table lives at zigzag position ZIGZAG[i].
_ZIGZAG = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5,
    12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6, 7, 14, 21, 28,
    35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51,
    58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
]

# Inverse of the zig-zag scan: segment byte i holds natural[ZIGZAG[i]], so
# natural[j] = segment[ZIGZAG_INV[j]].
_ZIGZAG_INV = [0] * 64
for _i, _z in enumerate(_ZIGZAG):
    _ZIGZAG_INV[_z] = _i
del _i, _z

# IJG standard quantization tables (natural order), from the JPEG spec annex K.
_IJG_LUMA = bytes([
    16, 11, 10, 16, 24, 40, 51, 61,
    12, 12, 14, 19, 26, 58, 60, 55,
    14, 13, 16, 24, 40, 57, 69, 56,
    14, 17, 22, 29, 51, 87, 80, 62,
    18, 22, 37, 56, 68, 109, 103, 77,
    24, 35, 55, 64, 81, 104, 113, 92,
    49, 64, 78, 87, 103, 121, 120, 101,
    72, 92, 95, 98, 112, 100, 103, 99,
])
_IJG_CHROMA = bytes([
    17, 18, 24, 47, 99, 99, 99, 99,
    18, 21, 26, 66, 99, 99, 99, 99,
    24, 26, 56, 99, 99, 99, 99, 99,
    47, 66, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
])
KNOWN_DQT = {
    hashlib.md5(_IJG_LUMA).hexdigest(): "IJG standard luminance",
    hashlib.md5(_IJG_CHROMA).hexdigest(): "IJG standard chrominance",
}

# TIFF tag ids we care about
_TAGS_IFD0 = {0x010F: "Make", 0x0110: "Model", 0x0131: "Software",
              0x0132: "DateTime", 0x8769: "ExifIFD", 0x8825: "GPSIFD",
              0x9286: "UserComment"}
_TAGS_EXIF = {0x9003: "DateTimeOriginal", 0x9004: "DateTimeDigitized",
              0xA002: "PixelXDimension", 0xA003: "PixelYDimension"}
_TAGS_GPS = {0: "GPSVersionID", 1: "GPSLatitudeRef", 2: "GPSLatitude",
             3: "GPSLongitudeRef", 4: "GPSLongitude", 5: "GPSAltitudeRef",
             6: "GPSAltitude", 29: "GPSDateStamp"}
_TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}


def parse_tiff(tiff):
    """Parse a TIFF header (as found after 'Exif\\0\\0'). Returns
    {'endian': 'II'/'MM', 'ifd0': {...}, 'exif': {...}, 'gps': {...}}."""
    if tiff[:2] == b"II":
        endian, bo = "II", "<"
    elif tiff[:2] == b"MM":
        endian, bo = "MM", ">"
    else:
        raise ValueError("bad TIFF byte order")
    if struct.unpack(bo + "H", tiff[2:4])[0] != 42:
        raise ValueError("bad TIFF magic")
    (ifd0_off,) = struct.unpack(bo + "I", tiff[4:8])

    def read_ifd(off, names):
        (count,) = struct.unpack(bo + "H", tiff[off:off + 2])
        tags = {}
        for i in range(count):
            e = off + 2 + i * 12
            tag, typ, cnt = struct.unpack(bo + "HHI", tiff[e:e + 8])
            size = _TYPE_SIZE.get(typ, 0) * cnt
            raw = tiff[e + 8:e + 12]
            if size > 4:
                (voff,) = struct.unpack(bo + "I", raw)
                raw = tiff[voff:voff + size]
            else:
                raw = raw[:size]
            tags[names.get(tag, f"0x{tag:04X}")] = _decode_value(typ, cnt, raw, bo)
        return tags

    ifd0 = read_ifd(ifd0_off, _TAGS_IFD0)
    out = {"endian": endian, "ifd0": ifd0, "exif": {}, "gps": {}}
    if isinstance(ifd0.get("ExifIFD"), int):
        out["exif"] = read_ifd(ifd0["ExifIFD"], _TAGS_EXIF)
    if isinstance(ifd0.get("GPSIFD"), int):
        out["gps"] = read_ifd(ifd0["GPSIFD"], _TAGS_GPS)
    return out


def _decode_value(typ, cnt, raw, bo):
    if typ == 2:  # ASCII
        return raw.split(b"\x00")[0].decode("utf-8", "replace")
    if typ == 1 or typ == 7:
        return bytes(raw)
    if typ == 3:
        return list(struct.unpack(bo + f"{cnt}H", raw))
    if typ == 4:
        vals = list(struct.unpack(bo + f"{cnt}I", raw))
        return vals[0] if cnt == 1 else vals
    if typ == 5:  # RATIONAL
        out = []
        for i in range(cnt):
            num, den = struct.unpack(bo + "2I", raw[i * 8:i * 8 + 8])
            out.append(num / den if den else 0.0)
        return out[0] if cnt == 1 else out
    if typ == 10:  # SRATIONAL
        out = []
        for i in range(cnt):
            num, den = struct.unpack(bo + "2i", raw[i * 8:i * 8 + 8])
            out.append(num / den if den else 0.0)
        return out[0] if cnt == 1 else out
    return raw


def gps_decimal(gps):
    """GPS IFD dict -> (lat, lon) decimal degrees, or None."""
    try:
        lat = gps["GPSLatitude"]
        lon = gps["GPSLongitude"]
        lat_d = lat[0] + lat[1] / 60 + lat[2] / 3600
        lon_d = lon[0] + lon[1] / 60 + lon[2] / 3600
        if str(gps.get("GPSLatitudeRef", "N")).upper().startswith("S"):
            lat_d = -lat_d
        if str(gps.get("GPSLongitudeRef", "E")).upper().startswith("W"):
            lon_d = -lon_d
        return lat_d, lon_d
    except (KeyError, TypeError, IndexError):
        return None
