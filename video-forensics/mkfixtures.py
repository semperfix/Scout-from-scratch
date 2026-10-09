#!/usr/bin/env python3
"""mkfixtures: hand-craft test videos for vidcheck (struct only, no encoder).

MP4 (ISO BMFF, structural -- no mdat media, boxes only):
  fixtures/tiny.mp4    - ftyp + moov, one AVC track; mvhd says 4.0 s and the
                         stts sample table agrees. Expect: CLEAN.
  fixtures/surgery.mp4 - same, but the stts table only accounts for 2.0 s of
                         the claimed 4.0 s. Expect: TIMELINE-SUSPECT.

H.264 Annex-B (real parseable parameter sets + slice headers):
  fixtures/tiny.264    - SPS(1280x720 baseline) + PPS + regular GOP-30
                         (IDR at 0, 30, 60). Expect: CLEAN.
  fixtures/anomaly.264 - IDR at 0, 30, then a rogue IDR at 35 (interval 5
                         vs typical 30). Expect: SPLICE-LIKELY.

Usage: python3 mkfixtures.py   (writes ./fixtures/)
"""
import os
import struct

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def box(ftype, payload):
    return struct.pack(">I", 8 + len(payload)) + ftype + payload


# ---------------- MP4 ----------------

def _mvhd(timescale, duration):
    p = struct.pack(">I", 0)            # version/flags
    p += struct.pack(">II", 0, 0)       # creation, modification
    p += struct.pack(">II", timescale, duration)
    p += struct.pack(">I", 0x00010000)  # rate
    p += struct.pack(">H", 0x0100) + b"\x00\x00"  # volume, reserved
    p += b"\x00" * 8                    # reserved
    p += struct.pack(">9I", 0x00010000, 0, 0, 0, 0x00010000, 0,
                     0, 0, 0x40000000)  # matrix
    p += b"\x00" * 24                   # pre_defined
    p += struct.pack(">I", 2)           # next_track_ID
    return box(b"mvhd", p)


def _tkhd(track_id, duration):
    p = struct.pack(">I", 0x000007)     # version/flags: enabled|in_movie|preview
    p += struct.pack(">II", 0, 0)
    p += struct.pack(">I", track_id) + b"\x00" * 4
    p += struct.pack(">I", duration) + b"\x00" * 8
    p += struct.pack(">HHH", 0, 0, 0x0100) + b"\x00\x00"
    p += struct.pack(">9I", 0x00010000, 0, 0, 0, 0x00010000, 0,
                     0, 0, 0x40000000)
    p += struct.pack(">II", 1280 << 16, 720 << 16)  # width/height 16.16
    return box(b"tkhd", p)


def _mdhd(timescale, duration):
    p = struct.pack(">I", 0)
    p += struct.pack(">II", 0, 0)
    p += struct.pack(">II", timescale, duration)
    p += struct.pack(">HH", 0x55C4, 0)  # language 'und', quality
    return box(b"mdhd", p)


def _hdlr(handler, name):
    p = struct.pack(">I", 0) + b"\x00" * 4 + handler + b"\x00" * 12
    p += name.encode() + b"\x00"
    return box(b"hdlr", p)


def _stsd():
    e = b"\x00" * 6 + struct.pack(">H", 1) + b"\x00" * 16
    e += struct.pack(">HH", 1280, 720)
    e += struct.pack(">II", 0x00480000, 0x00480000) + b"\x00" * 4
    e += struct.pack(">H", 1) + b"\x00" * 32
    e += struct.pack(">HH", 0x0018, 0xFFFF)
    entry = struct.pack(">I", 8 + len(e)) + b"avc1" + e
    return box(b"stsd", struct.pack(">II", 0, 1) + entry)


def _stts(entries):
    p = struct.pack(">II", 0, len(entries))
    for c, d in entries:
        p += struct.pack(">II", c, d)
    return box(b"stts", p)


def _stsc():
    return box(b"stsc", struct.pack(">IIIIII", 0, 1, 1, 1, 1, 1))


def _stsz(count):
    return box(b"stsz", struct.pack(">III", 0, 0, count) + b"\x00" * 4 * count)


def _stco():
    # structural fixture: no mdat, so the chunk offset is a placeholder
    return box(b"stco", struct.pack(">III", 0, 1, 0xFFFFFFFF))


def _minf(stbl):
    vmhd = box(b"vmhd", struct.pack(">IHHH", 1, 0, 0, 0))
    url = box(b"url ", struct.pack(">I", 1))
    dref = box(b"dref", struct.pack(">II", 0, 1) + url)
    dinf = box(b"dinf", dref)
    return box(b"minf", vmhd + dinf + stbl)


def _trak(track_id, mdhd_ts, mdhd_dur, stts_entries, mvhd_ts):
    tkhd_dur = mdhd_dur * mvhd_ts // mdhd_ts
    stbl = _stsd() + _stts(stts_entries) + _stsc() + \
        _stsz(sum(c for c, _ in stts_entries)) + _stco()
    mdia = _mdhd(mdhd_ts, mdhd_dur) + _hdlr(b"vide", "VideoHandler") + \
        _minf(box(b"stbl", stbl))
    elst = box(b"elst", struct.pack(">II", 0, 1)
               + struct.pack(">Ii hh", tkhd_dur, 0, 1, 0))
    edts = box(b"edts", elst)
    return box(b"trak", _tkhd(track_id, tkhd_dur) + edts + box(b"mdia", mdia))


def make_mp4(path, stts_entries):
    ftyp = box(b"ftyp", b"isom" + struct.pack(">I", 0) + b"isomiso2")
    moov = box(b"moov", _mvhd(1000, 4000)
               + _trak(1, 90000, 360000, stts_entries, 1000))
    open(path, "wb").write(ftyp + moov)


# ---------------- H.264 ----------------

class BitWriter:
    def __init__(self):
        self.bits = []

    def u(self, n, v):
        for i in range(n - 1, -1, -1):
            self.bits.append((v >> i) & 1)

    def ue(self, v):
        code = v + 1
        nb = code.bit_length()
        self.u(nb - 1, 0)
        self.u(nb, code)

    def se(self, v):
        self.ue(2 * v - 1 if v > 0 else -2 * v)

    def rbsp(self):
        self.bits.append(1)  # rbsp_stop_one_bit
        while len(self.bits) % 8:
            self.bits.append(0)
        out = bytearray()
        for i in range(0, len(self.bits), 8):
            b = 0
            for bit in self.bits[i:i + 8]:
                b = (b << 1) | bit
            out.append(b)
        return bytes(out)


def _ebsp(rbsp):
    out, zeros = bytearray(), 0
    for byte in rbsp:
        if zeros >= 2 and byte <= 0x03:
            out.append(0x03)
            zeros = 0
        out.append(byte)
        zeros = zeros + 1 if byte == 0 else 0
    return bytes(out)


def _nal(nal_type, rbsp, ref_idc=3):
    return b"\x00\x00\x00\x01" + bytes([(ref_idc << 5) | nal_type]) + _ebsp(rbsp)


def make_sps(width=1280, height=720):
    w = BitWriter()
    w.u(8, 66)   # profile_idc: baseline
    w.u(8, 0)    # constraints
    w.u(8, 30)   # level_idc: 3.0
    w.ue(0)      # sps_id
    w.ue(0)      # log2_max_frame_num_minus4 (max 16)
    w.ue(0)      # pic_order_cnt_type
    w.ue(0)      # log2_max_pic_order_cnt_lsb_minus4
    w.ue(1)      # num_ref_frames
    w.u(1, 0)    # gaps flag
    w.ue(width // 16 - 1)
    w.ue(height // 16 - 1)
    w.u(1, 1)    # frame_mbs_only_flag
    w.u(1, 1)    # direct_8x8_inference_flag
    w.u(1, 0)    # frame_cropping_flag
    w.u(1, 0)    # vui_parameters_present_flag
    return _nal(7, w.rbsp())


def make_pps():
    w = BitWriter()
    w.ue(0)      # pps_id
    w.ue(0)      # sps_id
    w.u(1, 0)    # entropy_coding_mode_flag
    w.u(1, 0)    # pic_order_cnt_present_flag
    w.ue(0)      # num_slice_groups_minus1
    w.ue(0)      # num_ref_idx_l0_active_minus1
    w.ue(0)      # num_ref_idx_l1_active_minus1
    w.u(1, 0)    # weighted_pred_flag
    w.u(2, 0)    # weighted_bipred_idc
    w.se(0)      # pic_init_qp_minus26
    w.se(0)      # pic_init_qs_minus26
    w.se(0)      # chroma_qp_index_offset
    w.u(1, 1)    # deblocking_filter_control_present_flag
    w.u(1, 0)    # constrained_intra_pred_flag
    w.u(1, 0)    # redundant_pic_cnt_present_flag
    return _nal(8, w.rbsp())


def make_slice(idr, frame_num, poc):
    w = BitWriter()
    w.ue(0)              # first_mb_in_slice
    w.ue(2 if idr else 0)  # slice_type: 2=I, 0=P
    w.ue(0)              # pps_id
    w.u(4, frame_num % 16)  # frame_num (log2_max_frame_num = 4)
    if idr:
        w.ue(0)          # idr_pic_id
    w.u(4, poc % 16)     # pic_order_cnt_lsb
    return _nal(5 if idr else 1, w.rbsp(), ref_idc=3 if idr else 2)


def make_264(path, idr_positions, total_frames=61):
    out = bytearray(make_sps() + make_pps())
    for f in range(total_frames):
        out += make_slice(f in idr_positions, f, f)
    open(path, "wb").write(bytes(out))


def main():
    os.makedirs(OUT, exist_ok=True)
    make_mp4(f"{OUT}/tiny.mp4", [(120, 3000)])     # 120*3000 = 360000 = 4.0 s
    make_mp4(f"{OUT}/surgery.mp4", [(60, 3000)])   # 180000 ticks = 2.0 s != 4 s
    make_264(f"{OUT}/tiny.264", {0, 30, 60})
    make_264(f"{OUT}/anomaly.264", {0, 30, 35, 65}, total_frames=66)
    for f in sorted(os.listdir(OUT)):
        print("wrote", os.path.join(OUT, f))


if __name__ == "__main__":
    main()
