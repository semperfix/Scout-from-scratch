#!/usr/bin/env python3
"""Validation suite for the from-scratch NTFS stack.

Runs against fixture.img built by make_fixtures.py (formatter mkfs_ntfs.py
+ surgical injector surgery.py). Every check asserts a concrete,
independently-computable fact.
"""
import os
import struct
import sys
import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ntfs import (Volume, BootSector, NTFSError, apply_fixup, make_fixup,
                  decode_runlist, encode_runlist, filetime_to_dt,
                  dt_to_filetime, parse_filename_key, EPOCH)
from ntfscheck import carve_verdict, resolve, split_stream

IMG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixture.img")
PASS = []
FAIL = []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name +
          ("  [%s]" % detail if detail and not cond else ""))


def expect_raise(name, fn):
    try:
        fn()
    except NTFSError:
        check(name, True)
    except Exception as e:  # noqa - wrong exception type is a failure
        check(name, False, "raised %r not NTFSError" % e)
    else:
        check(name, False, "no exception raised")


# ---------- pure codec tests (no image needed) ----------
def test_runlist():
    runs = [(10, 1), (14, 1), (17, 1)]
    check("runlist round-trip fragmented", decode_runlist(encode_runlist(runs)) == runs)
    runs2 = [(100, 5), (95, 3), (200, 1)]  # backward delta (signed!)
    check("runlist round-trip negative delta",
          decode_runlist(encode_runlist(runs2)) == runs2)
    runs3 = [(50, 2), (None, 4), (60, 1)]  # sparse
    check("runlist round-trip sparse",
          decode_runlist(encode_runlist(runs3)) == runs3)
    # hand-verify the byte layout of a known runlist:
    # run (lcn=10,len=1): header 0x11, len 0x01, off 0x0A
    enc = encode_runlist([(10, 1)])
    check("runlist byte layout", enc == b"\x11\x01\x0a\x00", enc.hex())


def test_fixup():
    rec = bytearray(1024)
    rec[0:4] = b"FILE"
    rec[510:512] = b"\xab\xcd"
    rec[1022:1024] = b"\x12\x34"
    stamped = make_fixup(bytes(rec), usn=0x55)
    # sector ends now carry the USN
    check("fixup stamps USN", stamped[510:512] == b"\x55\x00" and
          stamped[1022:1024] == b"\x55\x00")
    restored = apply_fixup(stamped)
    check("fixup round-trip", restored[510:512] == b"\xab\xcd" and
          restored[1022:1024] == b"\x12\x34")
    # tamper with a sector end -> must raise, not silently parse
    bad = bytearray(stamped)
    bad[510] ^= 0xFF
    expect_raise("fixup tamper detected", lambda: apply_fixup(bytes(bad)))
    # bad magic
    bad2 = bytearray(stamped)
    bad2[0:4] = b"XXXX"
    expect_raise("fixup bad magic", lambda: apply_fixup(bytes(bad2)))


def test_filetime():
    # 2026-10-01 12:00 UTC hand-computed: days since 1601-01-01 = 155434
    dt = datetime.datetime(2026, 10, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
    ft = dt_to_filetime(dt)
    check("filetime round-trip", filetime_to_dt(ft) == dt)
    check("filetime zero -> None", filetime_to_dt(0) is None)
    # known anchor: 1970-01-01 UTC = 11644473600 seconds after 1601
    unix_epoch = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
    check("filetime unix anchor",
          dt_to_filetime(unix_epoch) == 11644473600 * 10_000_000)


# ---------- image tests ----------
def test_boot(v):
    b = v.boot
    check("boot bytes/sector", b.bytes_per_sector == 512)
    check("boot cluster size", v.cs == 4096)
    check("boot MFT LCN", b.mft_lcn == 4)
    check("boot MFT record size", v.mft_rec_size == 1024)
    check("boot index block size", b.index_block_size == 4096)
    check("boot total sectors", b.total_sectors == 131072)


def test_mft_basics(v):
    r0 = v.mft_record(0)
    check("MFT0 in-use", r0.in_use and not r0.is_dir)
    da = r0.first(0x80)
    check("MFT0 $DATA non-resident", da is not None and da.nonresident)
    runs = da.data_runs()
    check("MFT0 runs", runs == [(4, 4)], str(runs))
    # $MFTMirr holds fixup-stamped copies of records 0..3, kept in sync
    # by the surgeon exactly like real NTFS.
    from ntfs import apply_fixup as _af
    mirr = v.mft_record(1)
    mdata = mirr.read_stream()
    for n in (0, 1, 3):  # records defined by this minimal format
        stamped = mdata[n * 1024:(n + 1) * 1024]
        check("MFTMirr record %d in sync" % n,
              _af(stamped) == v.mft_record_raw(n))


def test_files(v):
    entries = sorted((n.lower(), r, d) for n, r, d, k in v.list_dir(5))
    names = [n for n, r, d in entries]
    check("root listing exact",
          names == ["big.bin", "hello.txt", "notes.txt", "subdir",
                    "timestomp.exe"],
          str(names))
    byname = {n: (r, d) for n, r, d in entries}
    check("subdir is dir", byname["subdir"][1] is True)
    check("hello.txt resident content",
          v.mft_record(byname["hello.txt"][0]).read_stream() ==
          b"Hello NTFS forensics!\n")
    # fragmented file reassembles byte-identical
    big = v.mft_record(byname["big.bin"][0])
    expected = bytes((i * 7) & 0xFF for i in range(3 * 4096))
    check("big.bin byte-identical", big.read_stream() == expected)
    check("big.bin 3 runs", len(big.first(0x80).data_runs()) == 3)
    # subdir walk
    sub = sorted(n.lower() for n, r, d, k in v.list_dir(byname["subdir"][0]))
    check("subdir listing", sub == ["inner.txt"], str(sub))
    inner = v.mft_record(resolve(v, "/subdir/inner.txt"))
    check("inner.txt content",
          inner.read_stream() == b"inside the subdir\n")
    check("full_path", v.full_path(byname["big.bin"][0]) == "\\big.bin")
    check("full_path nested",
          v.full_path(resolve(v, "subdir/inner.txt")) ==
          "\\subdir\\inner.txt")


def test_ads(v):
    n = resolve(v, "/hello.txt")
    rec = v.mft_record(n)
    check("ADS present", "secret" in rec.data_streams())
    check("ADS content",
          rec.read_stream("secret") == b"you never saw this stream\n")
    # main stream untouched by ADS surgery
    check("main stream intact",
          rec.read_stream() == b"Hello NTFS forensics!\n")
    p, s = split_stream("/hello.txt:secret")
    check("split_stream", (p, s) == ("/hello.txt", "secret"))
    p2, s2 = split_stream("C:\\x")
    check("split_stream drive prefix", (p2, s2) == ("C:\\x", ""))


def test_bitmap(v):
    # clusters 10,14,17 (big.bin) allocated; gap clusters 11,12,13,15,16 free
    # (deleted.txt took 11-12 then freed them)
    for c in (10, 14, 17):
        check("cluster %d allocated" % c, v.cluster_allocated(c))
    for c in (11, 12, 13, 15, 16):
        check("cluster %d free" % c, not v.cluster_allocated(c))
    # MFT record bits: 7..13 used
    r0 = v.mft_record(0)
    bm = r0.first(0xB0).body
    for n in range(7, 14):
        check("MFT bit %d set" % n, bool(bm[n // 8] & (1 << (n % 8))))


def test_deleted(v):
    found = {r.file_names()[0]["name"]: r for r in v.scan_deleted()}
    check("deleted.txt found", "deleted.txt" in found)
    check("deleted flag clear", not found["deleted.txt"].in_use)
    check("deleted absent from listing",
          "deleted.txt" not in [n for n, _, _, _ in v.list_dir(5)])
    verdict, data = carve_verdict(v, found["deleted.txt"])
    expected = b"this file was deleted but its clusters survive\n" * 100
    check("deleted verdict OK", verdict == "OK", verdict)
    check("deleted carve byte-identical", data == expected)


def test_timestomp(v):
    hits = []

    mft0 = v.mft_record(0)
    total = mft0.first(0x80).body["real_size"] // v.mft_rec_size
    for num in range(total):
        try:
            rec = v.mft_record(num)
        except NTFSError:
            continue
        if not (rec.in_use and rec.is_base and not rec.is_dir):
            continue
        si, fns = rec.standard_info(), rec.file_names()
        if si and fns and abs((si["created"] -
                              fns[0]["times"][0]).total_seconds()) > 1:
            hits.append(num)
    check("timestomp flags exactly MFT 13", hits == [13], str(hits))


def test_partial_carve():
    # delete big.bin, reallocate one of its clusters, carve -> PARTIAL
    import shutil
    import tempfile
    from surgery import Surgeon
    tmp = tempfile.mktemp(suffix=".img")
    shutil.copy(IMG, tmp)
    try:
        s = Surgeon(tmp)
        s.delete_file(5, 9, "big.bin")
        runs = s.alloc_clusters(1)  # reuses cluster 10
        s.create_file(5, "overwrite.txt", data=b"X" * 100, runs=runs)
        s.close()
        v = Volume(tmp)
        try:
            verdict, data = carve_verdict(v, v.mft_record(9))
            check("partial verdict on reallocated cluster",
                  verdict == "PARTIAL", verdict)
            check("reallocated cluster zero-filled",
                  data[:4096] == b"\x00" * 4096)
            check("unreallocated clusters intact",
                  data[4096:8192] ==
                  bytes((i * 7) & 0xFF for i in range(4096, 8192)))
        finally:
            v.close()
    finally:
        os.unlink(tmp)


def test_hostile():
    # garbage image -> clean NTFSError, never a raw traceback type
    with open("/tmp/notntfs.img", "wb") as f:
        f.write(os.urandom(4096))
    expect_raise("garbage boot sector",
                 lambda: Volume("/tmp/notntfs.img"))
    # fixup with lying USA count
    rec = bytearray(1024)
    rec[0:4] = b"FILE"
    struct.pack_into("<HH", rec, 4, 0x2A, 99)  # usa_count=99, record too short
    expect_raise("lying USA count", lambda: apply_fixup(bytes(rec)))


def main():
    test_runlist()
    test_fixup()
    test_filetime()
    if not os.path.exists(IMG):
        print("fixture image missing; run make_fixtures.py first")
        sys.exit(2)
    v = Volume(IMG)
    try:
        test_boot(v)
        test_mft_basics(v)
        test_files(v)
        test_ads(v)
        test_bitmap(v)
        test_deleted(v)
        test_timestomp(v)
    finally:
        v.close()
    test_hostile()
    test_partial_carve()
    print("\n%d passed, %d failed" % (len(PASS), len(FAIL)))
    if FAIL:
        print("FAILURES:", FAIL)
        sys.exit(1)


if __name__ == "__main__":
    main()
