#!/usr/bin/env python3
"""h264parse: hand-rolled H.264 Annex-B NAL parser.

Splits NAL units on start codes, strips emulation-prevention bytes, decodes
SPS with a from-scratch Exp-Golomb bit reader (resolution, profile, level),
classifies slice NALs into I/P/B frame types from their slice headers, and
runs GOP analysis: IDR positions and spacing anomalies (a splice usually
shows up as an IDR interval that breaks the established GOP rhythm).
"""
import struct

NAL_NAMES = {1: "slice(non-IDR)", 2: "slice(partition A)", 3: "slice(partition B)",
             4: "slice(partition C)", 5: "slice(IDR)", 6: "SEI", 7: "SPS",
             8: "PPS", 9: "AUD", 10: "EOSeq", 11: "EOStream", 12: "filler"}

FRAME_TYPES = {0: "P", 1: "B", 2: "I", 3: "SP", 4: "SI"}


def split_annexb(data):
    """Split an Annex-B stream into NAL units (start codes stripped)."""
    starts = []
    i = 0
    while True:
        j = data.find(b"\x00\x00\x01", i)
        if j < 0:
            break
        starts.append(j - 1 if j > 0 and data[j - 1] == 0 else j)
        i = j + 3
    units = []
    for k, s in enumerate(starts):
        e = starts[k + 1] if k + 1 < len(starts) else len(data)
        sc = 4 if data[s:s + 4] == b"\x00\x00\x00\x01" else 3
        nal = data[s + sc:e]
        if nal:
            units.append(nal)
    return units


def ebsp_to_rbsp(ebsp):
    """Strip emulation-prevention bytes (00 00 03 -> 00 00)."""
    out = bytearray()
    i, n = 0, len(ebsp)
    while i < n:
        if i + 2 < n and ebsp[i] == 0 and ebsp[i + 1] == 0 and ebsp[i + 2] == 3:
            out += b"\x00\x00"
            i += 3
        else:
            out.append(ebsp[i])
            i += 1
    return bytes(out)


class BitReader:
    def __init__(self, data):
        self.data, self.pos = data, 0  # pos in bits

    def u(self, n):
        v = 0
        for _ in range(n):
            byte = self.data[self.pos >> 3]
            v = (v << 1) | ((byte >> (7 - (self.pos & 7))) & 1)
            self.pos += 1
        return v

    def ue(self):
        zeros = 0
        while self.u(1) == 0:
            zeros += 1
        return (1 << zeros) - 1 + (self.u(zeros) if zeros else 0)

    def se(self):
        v = self.ue()
        return (v + 1) // 2 if v & 1 else -(v // 2)


def parse_sps(nal):
    """Decode an SPS NAL (type 7). Returns dict with profile/level/resolution."""
    br = BitReader(ebsp_to_rbsp(nal[1:]))
    profile, _, level = br.u(8), br.u(8), br.u(8)
    br.ue()  # sps_id
    if profile in (100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 144):
        cf = br.ue()
        if cf == 3:
            br.u(1)
        br.ue(), br.ue()  # bit depths
        br.u(1)
        if br.u(1):  # scaling matrix
            for _ in range(8 if cf != 3 else 12):
                if br.u(1):
                    last, nxt = 8, 8
                    for _ in range(16 if _ < 6 else 64):
                        d = br.se()
                        nxt = (last + d + 256) % 256
                        last = 0 if nxt == 0 else nxt
                        if nxt == 0:
                            break
    br.ue()  # log2_max_frame_num_minus4
    poc_type = br.ue()
    if poc_type == 0:
        br.ue()
    elif poc_type == 1:
        br.u(1)   # delta_pic_order_always_zero_flag
        br.se()   # offset_for_non_ref_pic
        br.se()   # offset_for_top_to_bottom_field
        for _ in range(br.ue()):  # num_ref_frames_in_pic_order_cnt_cycle
            br.se()  # offset_for_ref_frame
    br.ue()  # num_ref_frames
    br.u(1)  # gaps flag
    w_mbs = br.ue() + 1
    h_map = br.ue() + 1
    frame_mbs_only = br.u(1)
    if not frame_mbs_only:
        br.u(1)
    br.u(1)  # direct_8x8
    crop = [0, 0, 0, 0]
    if br.u(1):
        crop = [br.ue(), br.ue(), br.ue(), br.ue()]
    width = w_mbs * 16 - (crop[0] + crop[1]) * 2
    height = (2 - frame_mbs_only) * h_map * 16 - (crop[2] + crop[3]) * 2
    return {"profile_idc": profile, "level_idc": level,
            "level": f"{level / 10:.1f}",
            "width": width, "height": height}


def parse_slice_header(nal):
    """Classify a slice NAL (types 1-5) from its header. Returns frame type."""
    nal_type = nal[0] & 0x1F
    if nal_type == 5:
        return "I", True  # IDR is always intra
    br = BitReader(ebsp_to_rbsp(nal[1:]))
    br.ue()  # first_mb_in_slice
    slice_type = br.ue() % 5
    br.ue()  # pic_parameter_set_id
    return FRAME_TYPES.get(slice_type, "?"), False


def analyze_stream(data):
    """Parse an Annex-B stream. Returns NAL list, SPS info, GOP analysis."""
    nals = []
    sps_info = None
    for nal in split_annexb(data):
        ntype = nal[0] & 0x1F
        entry = {"type": ntype, "name": NAL_NAMES.get(ntype, f"reserved({ntype})"),
                 "size": len(nal), "ref_idc": (nal[0] >> 5) & 3}
        if ntype in (1, 2, 3, 4, 5):
            try:
                ft, is_idr = parse_slice_header(nal)
            except IndexError:
                ft, is_idr = "?", ntype == 5
            entry["frame"] = ft
            entry["idr"] = is_idr or ntype == 5
        elif ntype == 7 and sps_info is None:
            try:
                sps_info = parse_sps(nal)
            except IndexError:
                sps_info = {"error": "truncated SPS"}
            entry["sps"] = sps_info
        nals.append(entry)

    frames = [e for e in nals if "frame" in e]
    idr_idx = [i for i, e in enumerate(frames) if e["idr"]]
    intervals = [b - a for a, b in zip(idr_idx, idr_idx[1:])]
    flags = []
    if frames and not idr_idx:
        flags.append("no IDR frames at all (open-GOP fragment or stream cut)")
    if len(intervals) >= 2:
        med = sorted(intervals)[len(intervals) // 2]
        for (a, b), iv in zip(zip(idr_idx, idr_idx[1:]), intervals):
            if med and (iv > 2 * med or iv * 2 < med):
                flags.append(f"IDR spacing anomaly: frames {a}->{b} "
                             f"interval {iv} vs typical {med}")
    counts = {}
    for e in frames:
        counts[e["frame"]] = counts.get(e["frame"], 0) + 1
    return {"nals": nals, "sps": sps_info, "frames": frames,
            "idr_positions": idr_idx, "idr_intervals": intervals,
            "frame_counts": counts, "flags": flags}
