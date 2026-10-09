#!/usr/bin/env python3
"""Minimal NTFS formatter, from scratch. Zero dependencies.

Creates a valid-enough NTFS volume for forensic study:
  boot sector, $MFT (16 records), $MFTMirr, root dir (record 5),
  $Bitmap (record 6), $Volume (record 3, label).

The Surgeon (surgery.py) then injects files into it. The from-scratch
parser (ntfs.py) reads it back. If ntfs-3g/pytsk3 is available they act
as independent oracles.
"""

import struct
import sys
import datetime

from ntfs import dt_to_filetime, make_fixup
from surgery import build_si, build_fn, build_attr, build_index_root

SECTOR = 512
CLUSTER = 4096
NCLUSTERS = 16384          # 64 MB
MFT_LCN = 4
MFT_RECORDS = 16
MFTMIRR_LCN = 9
BITMAP_LCN = 8
BASE_TIME = datetime.datetime(2026, 10, 1, 12, 0, 0,
                              tzinfo=datetime.timezone.utc)


def boot_sector():
    b = bytearray(SECTOR)
    b[0:3] = b"\xeb\x52\x90"
    b[3:11] = b"NTFS    "
    struct.pack_into("<H", b, 0x0B, SECTOR)
    b[0x0D] = CLUSTER // SECTOR
    b[0x15] = 0xF8
    struct.pack_into("<Q", b, 0x28, NCLUSTERS * (CLUSTER // SECTOR))
    struct.pack_into("<q", b, 0x30, MFT_LCN)
    struct.pack_into("<q", b, 0x38, MFTMIRR_LCN)
    struct.pack_into("<b", b, 0x40, -10)   # 2^10 = 1024 byte MFT records
    struct.pack_into("<b", b, 0x44, -12)   # 2^12 = 4096 byte index blocks
    struct.pack_into("<Q", b, 0x48, 0x123456789ABCDEF0)
    b[0x1FE:0x200] = b"\x55\xaa"
    return bytes(b)


def mft_record(number, is_dir, attrs, seq=1):
    rec = bytearray(1024)
    rec[0:4] = b"FILE"
    struct.pack_into("<HHHH", rec, 0x10, seq, 1, 0x30,
                     0x01 | (0x02 if is_dir else 0x00))
    aid = len(attrs)
    struct.pack_into("<H", rec, 0x28, aid)
    pos = 0x30
    for atype, body, name, aid_, *rest in attrs:
        nr = rest[0] if rest else None
        a = build_attr(atype, body, name, aid_, nr)
        rec[pos:pos + len(a)] = a
        pos += len(a)
    struct.pack_into("<I", rec, pos, 0xFFFFFFFF)
    pos += 8
    struct.pack_into("<II", rec, 0x18, pos, 1024)
    return make_fixup(bytes(rec))


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "foxfs.img"
    img = bytearray(NCLUSTERS * CLUSTER)

    def w(lcn, data):
        img[lcn * CLUSTER:lcn * CLUSTER + len(data)] = data

    w(0, boot_sector())

    mft_clusters = (MFT_RECORDS * 1024 + CLUSTER - 1) // CLUSTER  # 4
    si = build_si(BASE_TIME)

    def nr_runs(runs, real):
        vcn = sum(l for _, l in runs)
        return {"start_vcn": 0, "end_vcn": vcn, "runs": runs,
                "alloc": vcn * CLUSTER, "real": real, "init": real}

    recs = {}
    # 0 $MFT
    recs[0] = mft_record(0, False, [
        (0x10, si, "", 0),
        (0x30, build_fn(5 | (1 << 48), "$MFT", mft_clusters * CLUSTER,
                        mft_clusters * CLUSTER), "", 1),
        (0x80, None, "", 2,
         nr_runs([(MFT_LCN, mft_clusters)], mft_clusters * CLUSTER)),
        (0xB0, b"\x0f\x00\x00\x00\x00\x00\x00\x00", "", 3),  # recs 0-3 used
    ])
    # 1 $MFTMirr
    recs[1] = mft_record(1, False, [
        (0x10, si, "", 0),
        (0x30, build_fn(5 | (1 << 48), "$MFTMirr", CLUSTER, CLUSTER), "", 1),
        (0x80, None, "", 2, nr_runs([(MFTMIRR_LCN, 1)], CLUSTER)),
    ])
    # 3 $Volume
    recs[3] = mft_record(3, False, [
        (0x10, si, "", 0),
        (0x30, build_fn(5 | (1 << 48), "$Volume", 0, 0), "", 1),
        (0x60, "FOXFS".encode("utf-16-le"), "", 2),
        # $VOLUME_INFORMATION: 8 reserved + major + minor + flags (NTFS 3.1)
        (0x70, b"\x00" * 8 + bytes([3, 1]) + struct.pack("<H", 0), "", 3),
    ])
    # 5 root
    recs[5] = mft_record(5, True, [
        (0x10, si, "", 0),
        (0x30, build_fn(5 | (1 << 48), ".", 0, 0, is_dir=True), "", 1),
        (0x90, build_index_root(4096), "$I30", 2),
    ])
    # 6 $Bitmap
    bm_size = (NCLUSTERS + 7) // 8
    bm = bytearray((bm_size + CLUSTER - 1) // CLUSTER * CLUSTER)
    for c in range(0, MFTMIRR_LCN + 1):  # clusters 0..9 used
        bm[c // 8] |= 1 << (c % 8)
    recs[6] = mft_record(6, False, [
        (0x10, si, "", 0),
        (0x30, build_fn(5 | (1 << 48), "$Bitmap", bm_size, bm_size), "", 1),
        (0x80, None, "", 2, nr_runs([(BITMAP_LCN, 1)], bm_size)),
    ])
    w(BITMAP_LCN, bytes(bm))

    # lay MFT records into MFT clusters
    for num, rec in recs.items():
        off = MFT_LCN * CLUSTER + num * 1024
        img[off:off + 1024] = rec
    # $MFTMirr = first 4 records
    mirr = bytearray(CLUSTER)
    for num in range(4):
        r = recs.get(num, b"\x00" * 1024)
        mirr[num * 1024:(num + 1) * 1024] = r
    w(MFTMIRR_LCN, bytes(mirr))

    with open(path, "wb") as f:
        f.write(bytes(img))
    print("[*] formatted %s: %d MB NTFS, label FOXFS" %
          (path, NCLUSTERS * CLUSTER // 1024 // 1024))


if __name__ == "__main__":
    main()
