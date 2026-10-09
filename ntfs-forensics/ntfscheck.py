#!/usr/bin/env python3
"""ntfscheck — NTFS forensic triage CLI (from-scratch parser).

  ntfscheck.py summary <image>
  ntfscheck.py ls <image> [path]
  ntfscheck.py cat <image> <path>[:stream]
  ntfscheck.py istat <image> <mft#>
  ntfscheck.py deleted <image>        # deleted-file scan + carve verdicts
  ntfscheck.py timestomp <image>      # $SI vs $FN timestamp skew
  ntfscheck.py ads <image>            # alternate data streams
  ntfscheck.py timeline <image>       # created-time ordered listing
"""

import sys
import struct
import datetime

from ntfs import (Volume, NTFSError, filetime_to_dt, SYS_FILES,
                  FILE_FLAG_IN_USE)


def resolve(vol, path):
    """Walk a \\- or /-separated path from root. Returns MFT record number."""
    parts = [p for p in path.replace("\\", "/").split("/") if p]
    cur = 5
    for p in parts:
        hit = None
        for name, ref, is_dir, key in vol.list_dir(cur):
            if name.lower() == p.lower():
                hit = (ref, is_dir)
                break
        if hit is None:
            raise NTFSError("path not found: %s (at %r)" % (path, p))
        cur = hit[0]
    return cur


def fmt_dt(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "?"


def cmd_summary(vol):
    b = vol.boot
    print("volume serial : %016x" % b.serial)
    print("bytes/sector  : %d" % b.bytes_per_sector)
    print("cluster size  : %d" % vol.cs)
    print("total sectors : %d (%.1f MB)" %
          (b.total_sectors, b.total_sectors * 512 / 1e6))
    print("MFT at LCN    : %d (file offset %d)" % (b.mft_lcn, b.mft_offset))
    print("MFT record    : %d bytes" % vol.mft_rec_size)
    print("index block   : %d bytes" % b.index_block_size)
    mft0 = vol.mft_record(0)
    da = mft0.first(0x80)
    nrecs = da.body["real_size"] // vol.mft_rec_size
    print("MFT records   : %d (%.1f MB MFT)" %
          (nrecs, da.body["real_size"] / 1e6))
    # count in-use
    inuse = 0
    for n in range(nrecs):
        try:
            r = vol.mft_record(n)
        except NTFSError:
            continue
        if r.in_use and r.is_base:
            inuse += 1
    print("in-use records: %d" % inuse)
    # volume label
    try:
        vrec = vol.mft_record(3)
        vn = vrec.first(0x60)
        if vn and not vn.nonresident:
            print("label         : %s" %
                  vn.body.decode("utf-16-le", errors="replace"))
    except NTFSError:
        pass


def cmd_ls(vol, path):
    num = resolve(vol, path) if path else 5
    print("%-28s %6s %8s  %s" % ("name", "mft", "size", "modified"))
    for name, ref, is_dir, key in sorted(vol.list_dir(num),
                                         key=lambda e: e[0].lower()):
        rec = vol.mft_record(ref)
        fns = rec.file_names()
        size = fns[0]["real_size"] if fns else 0
        si = rec.standard_info()
        mod = fmt_dt(si["modified"]) if si else "?"
        flag = "<DIR>" if is_dir else ""
        print("%-28s %6d %8d  %s %s" % (name, ref, size, mod, flag))


def split_stream(spec):
    """Split 'path:stream' ADS syntax; a 'C:'-style drive prefix is not ADS."""
    idx = spec.rfind(":")
    if idx <= 1:
        return spec, ""
    path, stream = spec[:idx], spec[idx + 1:]
    if "/" in stream or "\\" in stream or not stream:
        return spec, ""
    return path, stream


def cmd_cat(vol, pathspec):
    path, stream = split_stream(pathspec)
    num = resolve(vol, path)
    rec = vol.mft_record(num)
    data = rec.read_stream(stream)
    sys.stdout.buffer.write(data)


def cmd_istat(vol, number):
    number = int(number)
    rec = vol.mft_record(number)
    print("MFT record %d  seq=%d  %s %s  links=%d" %
          (number, rec.seq,
           "in-use" if rec.in_use else "NOT-in-use",
           "dir" if rec.is_dir else "file", rec.links))
    print("path: %s" % vol.full_path(number))
    si = rec.standard_info()
    if si:
        print("  $SI  created=%s modified=%s mftmod=%s accessed=%s" %
              (fmt_dt(si["created"]), fmt_dt(si["modified"]),
               fmt_dt(si["mft_modified"]), fmt_dt(si["accessed"])))
    for fn in rec.file_names():
        print("  $FN  parent=%d name=%r ns=%d size=%d" %
              (fn["parent"], fn["name"], fn["namespace"], fn["real_size"]))
        print("       created=%s modified=%s" %
              (fmt_dt(fn["times"][0]), fmt_dt(fn["times"][1])))
    for a in rec.attrs:
        if a.nonresident:
            runs = a.data_runs()
            allocd = sum(1 for lcn, ln in runs if lcn is not None
                         and all(vol.cluster_allocated(c)
                                 for c in range(lcn, lcn + ln)))
            print("  attr %-22s name=%r NON-RESIDENT runs=%d "
                  "real=%d alloc=%d" %
                  (a.type_name, a.name, len(runs), a.body["real_size"],
                   a.body["alloc_size"]))
            for lcn, ln in runs:
                tag = ("LCN %d" % lcn) if lcn is not None else "SPARSE"
                print("       %s len %d clusters" % (tag, ln))
        else:
            print("  attr %-22s name=%r resident %d bytes" %
                  (a.type_name, a.name, len(a.body)))


def carve_verdict(vol, rec):
    """Attempt recovery of a deleted record's unnamed $DATA stream.

    Returns (verdict, bytes): OK / PARTIAL / GONE."""
    da = rec.first(0x80)
    if da is None:
        return "NO-DATA", b""
    if not da.nonresident:
        return "OK", da.body
    runs = da.data_runs()
    real = da.body["real_size"]
    out = bytearray()
    partial = False
    for lcn, ln in runs:
        if lcn is None:
            out += b"\x00" * ln * vol.cs
            continue
        for c in range(lcn, lcn + ln):
            if vol.cluster_allocated(c):
                partial = True  # reallocated: content gone
                out += b"\x00" * vol.cs
            else:
                out += vol.read_clusters(c, 1)
    data = bytes(out[:real])
    if partial:
        return "PARTIAL", data
    return "OK", data


def cmd_deleted(vol):
    print("%-6s %-28s %8s  %s  %s" %
          ("mft", "name", "size", "verdict", "deleted?"))
    n = 0
    for rec in vol.scan_deleted():
        fns = rec.file_names()
        name = fns[0]["name"] if fns else "?"
        size = fns[0]["real_size"] if fns else 0
        verdict, _ = carve_verdict(vol, rec)
        print("%-6d %-28s %8d  %-7s  in-use-flag=%s" %
              (rec.number, name, size, verdict, rec.in_use))
        n += 1
    if not n:
        print("(no deleted records found)")


def cmd_timestomp(vol):
    """Flag files whose $SI timestamps disagree with $FN timestamps.

    Anti-forensics tools usually only rewrite $STANDARD_INFORMATION,
    leaving $FILE_NAME (maintained by the filesystem) telling the truth.
    """
    print("%-6s %-28s %s" % ("mft", "name", "skew"))
    mft0 = vol.mft_record(0)
    da = mft0.first(0x80)
    total = da.body["real_size"] // vol.mft_rec_size
    for num in range(total):
        try:
            rec = vol.mft_record(num)
        except NTFSError:
            continue
        if not (rec.in_use and rec.is_base and not rec.is_dir):
            continue
        si = rec.standard_info()
        fns = rec.file_names()
        if not si or not fns:
            continue
        fn = fns[0]
        for label, si_t, fn_t in (("created", si["created"], fn["times"][0]),
                                  ("modified", si["modified"], fn["times"][1])):
            if si_t and fn_t and abs((si_t - fn_t).total_seconds()) > 1:
                print("%-6d %-28s $SI.%s=%s $FN.%s=%s  <-- SKEW" %
                      (num, fn["name"], label, fmt_dt(si_t),
                       label, fmt_dt(fn_t)))
                break


def cmd_ads(vol):
    print("%-40s %8s" % ("path:stream", "size"))
    mft0 = vol.mft_record(0)
    da = mft0.first(0x80)
    total = da.body["real_size"] // vol.mft_rec_size
    for num in range(total):
        try:
            rec = vol.mft_record(num)
        except NTFSError:
            continue
        if not (rec.in_use and rec.is_base):
            continue
        for name in rec.data_streams():
            if name:
                print("%-40s %8d" %
                      (vol.full_path(num) + ":" + name,
                       len(rec.read_stream(name))))


def cmd_timeline(vol):
    rows = []
    mft0 = vol.mft_record(0)
    da = mft0.first(0x80)
    total = da.body["real_size"] // vol.mft_rec_size
    for num in range(total):
        try:
            rec = vol.mft_record(num)
        except NTFSError:
            continue
        if not (rec.in_use and rec.is_base):
            continue
        si = rec.standard_info()
        if si and si["created"]:
            rows.append((si["created"], num, vol.full_path(num)))
    for dt, num, path in sorted(rows):
        print("%s  %6d  %s" % (fmt_dt(dt), num, path))


COMMANDS = {"summary": (cmd_summary, 0), "ls": (cmd_ls, 1),
            "cat": (cmd_cat, 1), "istat": (cmd_istat, 1),
            "deleted": (cmd_deleted, 0), "timestomp": (cmd_timestomp, 0),
            "ads": (cmd_ads, 0), "timeline": (cmd_timeline, 0)}


def main():
    if len(sys.argv) < 3 or sys.argv[1] not in COMMANDS:
        print(__doc__)
        sys.exit(2)
    cmd, nargs = COMMANDS[sys.argv[1]]
    vol = Volume(sys.argv[2])
    try:
        cmd(vol, *sys.argv[3:3 + nargs])
    finally:
        vol.close()


if __name__ == "__main__":
    main()
