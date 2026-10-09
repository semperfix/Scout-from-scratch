#!/usr/bin/env python3
"""mp4parse: hand-rolled MP4 (ISO BMFF) box parser.

Walks ftyp/moov/trak/mdia/minf/stbl by hand and extracts the sample-table
boxes that matter for forensics: stts (decode timestamps), stsc, stsz, stco,
plus mvhd/mdhd durations and edts edit lists. The timeline-surgery tell is
comparing the durations the container *claims* (mvhd/mdhd) against the
duration the sample table *proves* (sum of stts entries).
"""
import struct

_CONTAINERS = {b"moov", b"trak", b"mdia", b"minf", b"stbl", b"edts",
               b"dinf", b"mvex", b"moof", b"traf", b"udta"}


def parse_boxes(data, start=0, end=None):
    """Returns list of box dicts: type, size, offset, header, children/payload."""
    if end is None:
        end = len(data)
    boxes, pos = [], start
    while pos + 8 <= end:
        (size,) = struct.unpack(">I", data[pos:pos + 4])
        ftype = data[pos + 4:pos + 8]
        hdr = 8
        if size == 1:
            (size,) = struct.unpack(">Q", data[pos + 8:pos + 16])
            hdr = 16
        elif size == 0:
            size = end - pos
        if size < hdr or pos + size > end:
            break
        payload = data[pos + hdr:pos + size]
        children = parse_boxes(data, pos + hdr, pos + size) \
            if ftype in _CONTAINERS else []
        boxes.append({"type": ftype, "size": size, "offset": pos,
                      "payload": payload, "children": children})
        pos += size
    return boxes


def find(box, ftype):
    """First direct child with the given type, or None."""
    for c in box["children"]:
        if c["type"] == ftype:
            return c
    return None


def find_path(box, *types):
    cur = box
    for t in types:
        cur = find(cur, t) if cur else None
    return cur


def _full(payload):
    return payload[0], int.from_bytes(payload[1:4], "big")  # version, flags


def parse_ftyp(box):
    p = box["payload"]
    return {"major": p[0:4].decode("ascii", "replace"),
            "minor": struct.unpack(">I", p[4:8])[0],
            "compat": [p[i:i + 4].decode("ascii", "replace")
                       for i in range(8, len(p), 4)]}


def parse_mvhd(box):
    p, (ver, _) = box["payload"], _full(box["payload"])
    if ver == 1:
        ts, dur = struct.unpack(">IQ", p[20:32])[0], struct.unpack(">Q", p[24:32])[0]
    else:
        ts, dur = struct.unpack(">II", p[12:20])
    return {"timescale": ts, "duration": dur,
            "seconds": dur / ts if ts else 0.0}


def parse_tkhd(box):
    p, (ver, _) = box["payload"], _full(box["payload"])
    if ver == 1:
        tid, dur = struct.unpack(">I", p[20:24])[0], struct.unpack(">Q", p[28:36])[0]
    else:
        tid, dur = struct.unpack(">I", p[12:16])[0], struct.unpack(">I", p[20:24])[0]
    return {"id": tid, "duration": dur}


def parse_mdhd(box):
    p, (ver, _) = box["payload"], _full(box["payload"])
    if ver == 1:
        ts, dur = struct.unpack(">I", p[20:24])[0], struct.unpack(">Q", p[24:32])[0]
        lang_off = 32
    else:
        ts, dur = struct.unpack(">II", p[12:20])
        lang_off = 20
    lang = struct.unpack(">H", p[lang_off:lang_off + 2])[0]
    lang_s = "".join(chr(0x60 + ((lang >> s) & 0x1F)) for s in (10, 5, 0))
    return {"timescale": ts, "duration": dur, "language": lang_s,
            "seconds": dur / ts if ts else 0.0}


def parse_hdlr(box):
    p = box["payload"]
    handler = p[8:12].decode("ascii", "replace")
    name = p[24:].split(b"\x00")[0].decode("utf-8", "replace")
    return {"handler": handler, "name": name}


def parse_stsd(box):
    p = box["payload"]
    (count,) = struct.unpack(">I", p[4:8])
    entries, pos = [], 8
    for _ in range(count):
        (size,) = struct.unpack(">I", p[pos:pos + 4])
        entries.append({"fourcc": p[pos + 4:pos + 8].decode("ascii", "replace"),
                        "size": size})
        pos += size
    return entries


def _entry_list(box, entry_size, fmts):
    p = box["payload"]
    (count,) = struct.unpack(">I", p[4:8])
    out, pos = [], 8
    for _ in range(count):
        out.append(struct.unpack(">" + "".join(fmts), p[pos:pos + entry_size]))
        pos += entry_size
    return out


def parse_stts(box):
    return [{"count": c, "delta": d}
            for c, d in _entry_list(box, 8, "II")]


def parse_stsc(box):
    return [{"first_chunk": a, "samples_per_chunk": b, "desc": c}
            for a, b, c in _entry_list(box, 12, "III")]


def parse_stsz(box):
    p = box["payload"]
    sample_size, count = struct.unpack(">II", p[4:12])
    table = list(struct.unpack(">" + "I" * count, p[12:12 + 4 * count])) \
        if sample_size == 0 else []
    return {"sample_size": sample_size, "count": count, "table": table}


def parse_stco(box):
    p = box["payload"]
    (count,) = struct.unpack(">I", p[4:8])
    return list(struct.unpack(">" + "I" * count, p[8:8 + 4 * count]))


def parse_elst(box):
    p, (ver, _) = box["payload"], _full(box["payload"])
    if ver == 1:
        (count,) = struct.unpack(">I", p[4:8])
        return [struct.unpack(">Qqhh", p[8 + i * 20:28 + i * 20])
                for i in range(count)]
    (count,) = struct.unpack(">I", p[4:8])
    return [struct.unpack(">Ii hh", p[8 + i * 12:20 + i * 12])
            for i in range(count)]


def analyze_mp4(data):
    """Full container analysis. Returns dict with tree, tracks, surgery flags."""
    top = parse_boxes(data)
    ftyp_b = next((b for b in top if b["type"] == b"ftyp"), None)
    moov = next((b for b in top if b["type"] == b"moov"), None)
    if moov is None:
        raise ValueError("no moov box found")
    mvhd = parse_mvhd(find(moov, b"mvhd"))
    tracks = []
    for trak in [c for c in moov["children"] if c["type"] == b"trak"]:
        tkhd = parse_tkhd(find(trak, b"tkhd"))
        mdia = find(trak, b"mdia")
        mdhd = parse_mdhd(find(mdia, b"mdhd"))
        hdlr = parse_hdlr(find(mdia, b"hdlr"))
        stbl = find_path(mdia, b"minf", b"stbl")
        stsd = parse_stsd(find(stbl, b"stsd")) if find(stbl, b"stsd") else []
        stts = parse_stts(find(stbl, b"stts")) if find(stbl, b"stts") else []
        stsc = parse_stsc(find(stbl, b"stsc")) if find(stbl, b"stsc") else []
        stsz = parse_stsz(find(stbl, b"stsz")) if find(stbl, b"stsz") else {}
        stco_b = find(stbl, b"stco") or find(stbl, b"co64")
        stco = parse_stco(stco_b) if stco_b else []
        elst_b = find_path(trak, b"edts", b"elst")
        elst = parse_elst(elst_b) if elst_b else []
        stts_ticks = sum(e["count"] * e["delta"] for e in stts)
        stts_sec = stts_ticks / mdhd["timescale"] if mdhd["timescale"] else 0
        tracks.append({
            "id": tkhd["id"], "handler": hdlr["handler"], "name": hdlr["name"],
            "codecs": [e["fourcc"] for e in stsd],
            "mdhd_timescale": mdhd["timescale"], "mdhd_sec": mdhd["seconds"],
            "tkhd_sec": tkhd["duration"] / mvhd["timescale"] if mvhd["timescale"] else 0,
            "stts": stts, "stts_ticks": stts_ticks, "stts_sec": stts_sec,
            "samples": stsz.get("count", 0) if isinstance(stsz, dict) else 0,
            "chunks": len(stco), "edit_list": elst,
        })
    flags = []
    for t in tracks:
        if t["mdhd_sec"] > 0 and abs(t["stts_sec"] - t["mdhd_sec"]) / t["mdhd_sec"] > 0.01:
            flags.append(f"track {t['id']}: stts duration {t['stts_sec']:.3f}s "
                         f"!= mdhd duration {t['mdhd_sec']:.3f}s "
                         "(timeline surgery: samples removed/added)")
        if t["edit_list"]:
            # A single identity entry (media_time=0, rate=1) is what most
            # encoders write by default -- benign. Anything else re-times
            # the track and is worth flagging.
            el = t["edit_list"]
            identity = (len(el) == 1 and el[0][1] == 0
                        and el[0][2] == 1 and el[0][3] == 0)
            if not identity:
                flags.append(f"track {t['id']}: non-trivial edit list "
                             f"({len(el)} entries -- timeline was re-cut)")
    return {"boxes": top, "ftyp": parse_ftyp(ftyp_b) if ftyp_b else None,
            "mvhd": mvhd, "tracks": tracks, "flags": flags}
