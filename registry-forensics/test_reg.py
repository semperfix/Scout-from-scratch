#!/usr/bin/env python3
"""test_reg.py — validation battery for the registry forensics expedition.

Builds the fixture hive, then asserts parser/triage behavior. Also asserts
malformed-input rejection and tamper detection.
"""
import os
import struct
import sys

import reghive_gen as gen
from regparse import Hive, HiveError
from regtriage import Triage

HIVE = "fakehive.dat"
fails = []

def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (f" — {extra}" if extra and not cond else ""))
    if not cond:
        fails.append(name)

def main():
    info = gen.build(HIVE)
    h = Hive(HIVE)

    # --- base block ---
    check("magic regf", h.data[:4] == b"regf")
    check("checksum verifies", h.checksum_ok)
    check("clean seq numbers", not h.dirty and h.seq1 == 1)
    check("version 1.4", (h.major, h.minor) == (1, 4))
    check("root offset matches builder", h.root_off == info["root"])
    check("bins_size matches file", h.bins_size == len(h.data) - 4096)
    check("3 bins walked", len(h.bins) == 3)

    # --- cell walk sanity: within each bin, cells are contiguous, 8-aligned, gapless ---
    ok = True
    for boff, bsize in h.bins:
        bcells = sorted(c for c in h.cells if boff <= c[0] < boff + bsize)
        ok &= bool(bcells) and bcells[0][0] == boff + 32
        ok &= all(c[0] + c[1] == bcells[i + 1][0] for i, c in enumerate(bcells[:-1]))
        ok &= bcells[-1][0] + bcells[-1][1] == boff + bsize
        ok &= all(c[1] % 8 == 0 for c in bcells)
    check("cells cover bins exactly", ok)

    # --- tree structure ---
    paths = [p for _, p in h.walk()]
    check("22 live keys", len(paths) == 22, str(len(paths)))
    for want in ["ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                 "ROOT\\System\\CurrentControlSet\\Enum\\USBSTOR\\Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00\\4C530001331122113321&0",
                 "ROOT\\Software\\Test\\Types"]:
        check(f"path present: ...{want[-30:]}", want in paths)

    # --- parent pointers round-trip (path reconstruction) ---
    for nk, p in h.walk():
        if nk["parent"] != 0xFFFFFFFF:
            par = h.nk(nk["parent"])
            check(f"parent link ok: {p[-20:]}", p == h.path(par) + "\\" + nk["name"])
            break

    # --- values: every type decodes ---
    vals = {}
    for nk, p in h.walk():
        for v in h.values(nk):
            vals[(p, v["name"])] = v
    TP = "ROOT\\Software\\Test\\Types"
    check("REG_SZ", vals[(TP, "TempDir")]["data"] == "%SystemRoot%\\Temp")
    check("REG_DWORD inline", vals[(TP, "Retries")]["data"] == 3 and vals[(TP, "Retries")]["inline"])
    check("REG_QWORD", vals[(TP, "BigCounter")]["data"] == 0x1122334455667788)
    check("REG_MULTI_SZ", vals[(TP, "Hosts")]["data"] == ["a", "b"])
    check("default value", vals[(TP, "(Default)")]["data"] == "default data")
    check("big value 20000B via db", vals[(TP, "blob")]["raw"] == info["big"])
    check("Run value", vals[("ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Updater")]["data"]
          == "C:\\Users\\kyle\\AppData\\Roaming\\updater.exe")

    # --- flags ---
    root = h.nk(h.root_off)
    check("root flags KEY_HIVE_ENTRY|NO_DELETE|COMP_NAME", root["flags"] == 0x2C)
    check("root flag names", "KEY_HIVE_ENTRY" in root["flag_names"])

    # --- deleted recovery ---
    d = h.scan_deleted()
    keys = [r for r in d if r["kind"] == "key"]
    rvals = [r for r in d if r["kind"] == "value"]
    check("deleted key recovered", any(r["name"] == "EvilPersistence" for r in keys))
    check("deleted key lastwrite", any(str(r["lastwrite"]).startswith("2025-10-04") for r in keys))
    check("deleted value payload recovered", any(r["name"] == "payload" and r["data"] == "C:\\Temp\\evil.exe" for r in rvals))
    check("deleted OldSecret recovered", any(r["name"] == "OldSecret" and r["data"] == b"supersecret" for r in rvals))
    check("exactly 3 remnant records", len(d) == 3, str(len(d)))
    check("deleted key + value share coalesced cell",
          len({r["cell_off"] for r in d if r["name"] in ("EvilPersistence", "payload")}) == 1)

    # --- triage ---
    t = Triage(h)
    rep = t.run("timeline.csv")
    check("verdict MALICIOUS", rep["verdict"] == "MALICIOUS", rep["verdict"])
    texts = [f[2] for f in rep["findings"]]
    check("deleted persistence flagged",
          any("EvilPersistence" in x and "payload=C:\\Temp\\evil.exe" in x for x in texts))
    check("UserAssist ROT13 decoded", any("UserAssist executed: C:\\Users\\kyle\\updater.exe" in x for x in texts))
    check("USB artifact", any("SanDisk Cruzer" in x for x in texts))
    check("timeline rows", rep["timeline_rows"] == 22 and os.path.exists("timeline.csv"))

    # --- tamper / malformed ---
    bad = bytearray(h.data)
    bad[0:4] = b"XXXX"
    open("bad.dat", "wb").write(bad)
    try:
        Hive("bad.dat"); check("bad magic rejected", False)
    except HiveError:
        check("bad magic rejected", True)

    tam = bytearray(h.data)
    tam[508] ^= 0xFF                      # corrupt checksum
    open("tam.dat", "wb").write(tam)
    check("checksum tamper detected", not Hive(tam and "tam.dat").checksum_ok)

    dty = bytearray(h.data)
    struct.pack_into("<I", dty, 4, 7)     # seq1 != seq2
    open("dty.dat", "wb").write(dty)
    hd = Hive("dty.dat")
    check("dirty hive detected", hd.dirty)

    trunc = h.data[:5000]
    open("trunc.dat", "wb").write(trunc)
    try:
        Hive("trunc.dat"); check("truncated hive rejected", False)
    except HiveError:
        check("truncated hive rejected", True)

    for f in ("bad.dat", "tam.dat", "dty.dat", "trunc.dat"):
        os.remove(f)

    print()
    if fails:
        print(f"{len(fails)} FAILURES: {fails}")
        sys.exit(1)
    print("ALL CHECKS PASSED")

if __name__ == "__main__":
    main()
