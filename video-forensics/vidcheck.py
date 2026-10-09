#!/usr/bin/env python3
"""vidcheck: video-forensics triage for MP4 containers and H.264 streams.

MP4: hand-parsed box tree (ftyp/moov/trak/mdia/minf/stbl), track list with
     codec fourccs, mvhd/mdhd durations vs stts-computed duration (the
     timeline-surgery tell), edit lists.
H.264 Annex-B: NAL split, Exp-Golomb SPS decode (profile/level/resolution),
     slice-header I/P/B classification, GOP analysis with IDR-spacing
     anomaly detection (the splice tell).

ELA heatmaps for pasted regions are NOT implemented: they need decoded
frames, and the stdlib has no H.264 decoder. The IDR/GOP timeline is the
honest encoder-free proxy (see README Limitations).

Usage: python3 vidcheck.py clip.mp4
       python3 vidcheck.py stream.264
Exit 0 always; the VERDICT line is the machine-readable result
(CLEAN / TIMELINE-SUSPECT / SPLICE-LIKELY).
"""
import argparse
import sys

from mp4parse import analyze_mp4
from h264parse import analyze_stream

_INDENT = "  "


def detect_kind(data):
    if len(data) >= 8 and data[4:8] == b"ftyp":
        return "MP4"
    if data[:4] == b"\x00\x00\x00\x01" or data[:3] == b"\x00\x00\x01":
        return "H264"
    return "unknown"


def _tree(boxes, depth=0):
    for b in boxes:
        t = b["type"].decode("ascii", "replace")
        print(f"{_INDENT * depth}{t} @{b['offset']} ({b['size']} bytes)")
        _tree(b["children"], depth + 1)


def triage_mp4(path, data):
    a = analyze_mp4(data)
    print(f"file: {path}  (MP4)")
    print("box tree:")
    _tree(a["boxes"])
    f = a["ftyp"]
    if f:
        print(f"ftyp: major={f['major']} compat={','.join(f['compat'])}")
    mv = a["mvhd"]
    print(f"mvhd: timescale={mv['timescale']} duration={mv['duration']} "
          f"({mv['seconds']:.3f}s)")
    for t in a["tracks"]:
        print(f"track {t['id']}: {t['handler']} ({t['name']}) "
              f"codecs={','.join(t['codecs']) or '?'}")
        print(f"  mdhd: {t['mdhd_sec']:.3f}s (timescale {t['mdhd_timescale']}), "
              f"tkhd: {t['tkhd_sec']:.3f}s, "
              f"stts: {t['samples']} samples -> {t['stts_sec']:.3f}s, "
              f"{t['chunks']} chunks")
        if t["stts"] and len(t["stts"]) <= 6:
            print("  stts entries: " + ", ".join(
                f"({e['count']}x{e['delta']})" for e in t["stts"]))
        for e in t["edit_list"]:
            print(f"  edit list: segment_dur={e[0]} media_time={e[1]}")
    return a["flags"]


def triage_h264(path, data):
    a = analyze_stream(data)
    print(f"file: {path}  (H.264 Annex-B, {len(a['nals'])} NAL units)")
    if a["sps"] and "error" not in a["sps"]:
        s = a["sps"]
        print(f"SPS: profile {s['profile_idc']} level {s['level']} "
              f"{s['width']}x{s['height']}")
    kinds = {}
    for e in a["nals"]:
        kinds[e["name"]] = kinds.get(e["name"], 0) + 1
    print("NAL census: " + ", ".join(f"{k}x{v}" for k, v in kinds.items()))
    fc = a["frame_counts"]
    if fc:
        print("frames: " + ", ".join(f"{k}:{v}" for k, v in sorted(fc.items()))
              + f"  (IDR at frame idx {a['idr_positions']})")
    if len(a["idr_intervals"]) > 1:
        print("IDR intervals: " + ", ".join(map(str, a["idr_intervals"])))
    return a["flags"]


def main():
    ap = argparse.ArgumentParser(
        description="Video forensics triage: MP4 box/timeline analysis and "
                    "H.264 SPS/GOP analysis.")
    ap.add_argument("video", help="MP4 file or H.264 Annex-B stream")
    args = ap.parse_args()
    data = open(args.video, "rb").read()
    kind = detect_kind(data)
    if kind == "MP4":
        flags = triage_mp4(args.video, data)
    elif kind == "H264":
        flags = triage_h264(args.video, data)
    else:
        sys.exit(f"unrecognized video format for {args.video}")

    splice = [f for f in flags if "IDR" in f or "no IDR" in f]
    surgery = [f for f in flags if "IDR" not in f and "no IDR" not in f]
    if splice:
        print("VERDICT: SPLICE-LIKELY -- " + "; ".join(splice))
    elif surgery:
        print("VERDICT: TIMELINE-SUSPECT -- " + "; ".join(surgery))
    else:
        print("VERDICT: CLEAN (container and GOP structure consistent)")


if __name__ == "__main__":
    main()
