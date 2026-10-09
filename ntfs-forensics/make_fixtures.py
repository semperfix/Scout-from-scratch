#!/usr/bin/env python3
"""Build the NTFS forensic fixture volume.

Usage: make_fixtures.py <image>
  1. mkntfs formats a 64MB volume (needs ntfs-3g installed)
  2. Surgeon injects:
       /hello.txt            resident "Hello NTFS forensics"
       /hello.txt:secret     ADS (alternate data stream)
       /notes.txt            resident notes
       /big.bin              non-resident, FRAGMENTED runlist (~3 clusters)
       /subdir/              directory
       /subdir/inner.txt     file inside subdir
       /deleted.txt          created, then deleted (carve target)
       /timestomp.exe        $SI timestamps != $FN timestamps
"""

import os
import subprocess
import sys
import datetime

from surgery import Surgeon, BASE_TIME
from ntfs import dt_to_filetime

SIZE_MB = 64


def main():
    img = sys.argv[1] if len(sys.argv) > 1 else "fixture.img"
    if not os.path.exists(img):
        import shutil
        if shutil.which("mkntfs"):
            print("[*] formatting %s with mkntfs ..." % img)
            subprocess.run(["mkntfs", "-F", "-f", "-L", "FORENSIC",
                            "-s", "512", "-c", "4096", img],
                           check=True, capture_output=True)
        else:
            print("[*] mkntfs not available; formatting with mkfs_ntfs.py")
            import mkfs_ntfs
            sys.argv = ["mkfs_ntfs.py", img]
            mkfs_ntfs.main()
    else:
        print("[*] using existing image %s" % img)

    s = Surgeon(img)
    print("[*] cluster size %d, MFT record size %d" %
          (s.cs, s.rec_size))

    # 1. resident file
    n1 = s.create_file(5, "hello.txt", data=b"Hello NTFS forensics!\n")
    print("[+] /hello.txt -> MFT %d" % n1)

    # 2. ADS on hello.txt: add a named $DATA stream surgically
    #    (rebuild hello.txt's record with an extra stream)
    from surgery import build_attr, build_si, build_fn
    from ntfs import make_fixup, parse_attributes
    raw = bytearray(s.read_mft_raw(n1))
    used = int.from_bytes(raw[0x18:0x1C], "little")
    raw = bytearray(raw[:used])
    attrs_off = int.from_bytes(raw[0x14:0x16], "little")
    # find end of attributes
    off = attrs_off
    while True:
        atype = int.from_bytes(raw[off:off + 4], "little")
        if atype == 0xFFFFFFFF:
            break
        alen = int.from_bytes(raw[off + 4:off + 8], "little")
        off += alen
    ads = build_attr(0x80, b"you never saw this stream\n", "secret", 5)
    assert used + len(ads) <= s.rec_size, "record overflow adding ADS"
    raw[off:off] = ads
    raw += b"\x00" * (s.rec_size - len(raw))
    # fix attr length bookkeeping: record used size grows
    raw[0x18:0x1C] = (used + len(ads)).to_bytes(4, "little")
    s.write_mft_raw(n1, bytes(raw))
    print("[+] /hello.txt:secret ADS added")

    # 3. another resident file
    n2 = s.create_file(5, "notes.txt",
                       data=b"buy milk\ncall abe about $420\n")
    print("[+] /notes.txt -> MFT %d" % n2)

    # 4. fragmented non-resident file (~3 clusters, forced multi-run)
    big = bytes((i * 7) & 0xFF for i in range(3 * 4096))
    runs = s.alloc_clusters(3, fragmented=True)
    n3 = s.create_file(5, "big.bin", data=big, runs=runs)
    print("[+] /big.bin -> MFT %d runs=%s" % (n3, runs))

    # 5. subdirectory with a file in it
    nd = s.create_file(5, "subdir", is_dir=True)
    ni = s.create_file(nd, "inner.txt", data=b"inside the subdir\n")
    print("[+] /subdir -> MFT %d, /subdir/inner.txt -> MFT %d" % (nd, ni))

    # 6. deleted file (carve target): non-resident so clusters matter
    ddata = b"this file was deleted but its clusters survive\n" * 100
    druns = s.alloc_clusters(2)
    ndel = s.create_file(5, "deleted.txt", data=ddata, runs=druns)
    s.delete_file(5, ndel, "deleted.txt")
    print("[+] /deleted.txt -> MFT %d created then deleted runs=%s"
          % (ndel, druns))

    # 7. timestomped file: $SI says 2020, $FN says real date
    old = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
    nts = s.create_file(5, "timestomp.exe", data=b"MZ\x90\x00fakestub",
                        si_times=old, fn_times=BASE_TIME)
    print("[+] /timestomp.exe -> MFT %d ($SI=2020, $FN=2026)" % nts)

    s.close()
    print("[*] fixtures complete: %s" % img)


if __name__ == "__main__":
    main()
