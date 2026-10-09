#!/usr/bin/env python3
"""Differential test: my from-scratch NTFS parser vs The Sleuth Kit.

pytsk3 is the independent oracle — it never saw my code or my fixtures.
Agreement here means the on-disk bytes are genuinely valid NTFS, not
just self-consistent.

TSK behavior notes (learned while writing this):
- TSK's open_dir lists unallocated (deleted) names too — so the
  directory comparison is a subset check, plus a separate check that
  TSK flags deleted.txt as unallocated.
- TSK errors (not EOF) when reading past end-of-attribute, so reads
  must request exactly meta.size bytes.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pytsk3

from ntfs import Volume, NTFSError
from ntfscheck import resolve, carve_verdict

IMG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixture.img")
PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name +
          ("  [%s]" % detail if detail and not cond else ""))


def tsk_ls(fs, path):
    d = fs.open_dir(path)
    out = []
    for e in d:
        name = e.info.name.name.decode("utf-8", "replace")
        if name in (".", ".."):
            continue
        meta = e.info.meta
        # unallocated names have meta=None; the flag lives on the name
        unalloc = bool(e.info.name.flags & 0x02)  # TSK_FS_NAME_FLAG_UNALLOC
        out.append((name, unalloc))
    return out


def tsk_cat(fs, path):
    f = fs.open(path)
    size = f.info.meta.size
    # read in chunks, never past EOF (TSK errors instead of returning b"")
    chunks, off = [], 0
    while off < size:
        b = f.read_random(off, min(65536, size - off))
        if not b:
            break
        chunks.append(b)
        off += len(b)
    return b"".join(chunks)


def main():
    img = pytsk3.Img_Info(IMG)
    fs = pytsk3.FS_Info(img)
    v = Volume(IMG)
    try:
        # 1. root listing: every live file I see, TSK sees too
        mine = set(n.lower() for n, r, d, k in v.list_dir(5))
        tsk_entries = tsk_ls(fs, "/")
        theirs = set(n.lower() for n, u in tsk_entries)
        check("every live file in TSK listing", mine <= theirs,
              "mine=%s tsk=%s" % (sorted(mine), sorted(theirs)))
        # TSK additionally sees system files + the deleted name (as unalloc)
        tsk_unalloc = set(n.lower() for n, u in tsk_entries if u)
        check("TSK flags deleted.txt unallocated",
              "deleted.txt" in tsk_unalloc, str(sorted(tsk_unalloc)))
        check("my listing omits deleted.txt", "deleted.txt" not in mine)

        # 2. file content agreement (resident + fragmented non-resident)
        for path in ["/hello.txt", "/notes.txt", "/big.bin",
                     "/subdir/inner.txt"]:
            tdata = tsk_cat(fs, path)
            mdata = v.mft_record(resolve(v, path)).read_stream()
            check("content agrees %s (%d bytes)" % (path, len(mdata)),
                  mdata == tdata)

        # 3. subdir listing (subset check; no deleted files here)
        ms = set(n.lower() for n, r, d, k in v.list_dir(resolve(v, "/subdir")))
        ts = set(n.lower() for n, u in tsk_ls(fs, "/subdir"))
        check("subdir listing agrees", ms <= ts and not
              any(u for _, u in tsk_ls(fs, "/subdir")),
              "mine=%s tsk=%s" % (sorted(ms), sorted(ts)))

        # 4. ADS: TSK sees the named $DATA stream; compare bytes via icat
        #    of the attribute (pytsk3 has no attr read, so use fs.open_meta
        #    on the file and walk — instead, verify via TSK's attr walk size
        #    and my byte-identical read already proven in test_ntfs.py).
        f = fs.open("/hello.txt")
        streams = []
        for attr in f:
            try:
                aname = attr.info.name.decode("utf-8", "replace") \
                    if attr.info.name else ""
            except Exception:
                aname = ""
            if attr.info.type == 128:  # $DATA
                streams.append((aname, attr.info.size))
        check("TSK sees ADS 'secret' with size 26",
              ("secret", 26) in streams, str(streams))
        mdata = v.mft_record(resolve(v, "/hello.txt")).read_stream("secret")
        check("ADS size agrees", len(mdata) == 26)

        # 5. deleted file: TSK icat of MFT 12 == my carve
        tdel = fs.open_meta(12)
        # open_meta gives default attr; read its full size
        size = tdel.info.meta.size
        chunks, off = [], 0
        while off < size:
            b = tdel.read_random(off, min(65536, size - off))
            if not b:
                break
            chunks.append(b)
            off += len(b)
        tdata = b"".join(chunks)
        expected = b"this file was deleted but its clusters survive\n" * 100
        check("TSK icat MFT 12 == expected", tdata == expected,
              "len=%d" % len(tdata))
        verdict, mdata = carve_verdict(v, v.mft_record(12))
        check("my carve == TSK icat", mdata == tdata,
              "verdict=%s" % verdict)

        # 6. $MFT readable via TSK
        mft = fs.open("/$MFT")
        check("$MFT readable via TSK", mft.info.meta.size > 0)
    finally:
        v.close()
        img.close()
    print("\n%d passed, %d failed" % (len(PASS), len(FAIL)))
    if FAIL:
        print("FAILURES:", FAIL)
        sys.exit(1)


if __name__ == "__main__":
    main()
