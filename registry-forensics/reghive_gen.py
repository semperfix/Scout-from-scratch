#!/usr/bin/env python3
"""reghive_gen.py — synthetic Windows registry hive WRITER.

Builds a forensically-flavored fake NTUSER/SOFTWARE-style hive from scratch,
byte-level, per the REGF primary-file format (base block + hive bins + cells).

Purpose: the parser/triage in this expedition is validated by round-tripping
against a hive whose every byte I placed deliberately — including two deleted
records (a freed persistence key and a freed value) that recovery must find.

All names/people/paths are fictional.
"""
import struct, os

EPOCH_DIFF = 116444736000000000          # FILETIME <-> Unix epoch delta (100ns units)
NULL = 0xFFFFFFFF

def filetime(unix_ts: float) -> int:
    return int(unix_ts * 10_000_000 + EPOCH_DIFF)

# fictional fixed timestamps (Oct 2026)
TS = {
    "base":   filetime(1759270000),   # 2026-09-30
    "run":    filetime(1759350000),   # 2026-10-01 autorun added
    "usb":    filetime(1759430000),   # 2026-10-02 USB plugged
    "recent": filetime(1759510000),   # 2026-10-03 docs opened
    "evil":   filetime(1759600000),   # 2026-10-04 persistence installed (then deleted)
    "types":  filetime(1759680000),   # 2026-10-05 test values
}

def align8(n: int) -> int:
    return (n + 7) // 8 * 8

# ---------------------------------------------------------------- builder
class HiveBuilder:
    BIN = 4096

    def __init__(self, filename="FAKEHIVE"):
        self.filename = filename
        self.bins = []          # list of bytearrays; file layout = concat
        self.bin_starts = []    # bins-relative start of each bin
        self.bin_sizes = []     # each bin size (multiple of 4096)
        self.cursors = []       # per-bin next-cell offset
        self.cur_bin = -1

    # -- low level -------------------------------------------------
    def _new_bin(self, first: bool, min_size: int = 4096):
        # room for header + the cell + the bin's trailing free cell
        size = ((32 + min_size + 8 + 4095) // 4096) * 4096
        b = bytearray(size)
        start = self.bin_starts[-1] + self.bin_sizes[-1] if self.bins else 0
        b[0:4] = b"hbin"
        struct.pack_into("<I", b, 4, start)      # offset rel. to bins start
        struct.pack_into("<I", b, 8, size)      # bin size
        if first:
            struct.pack_into("<Q", b, 20, TS["base"])
        self.bins.append(b)
        self.bin_starts.append(start)
        self.bin_sizes.append(size)
        self.cursors.append(32)
        self.cur_bin = len(self.bins) - 1

    def _locate(self, off: int):
        for i, s in enumerate(self.bin_starts):
            if s <= off < s + self.bin_sizes[i]:
                return i, off - s
        raise IndexError(f"offset {off:#x} outside hive bins")

    def _poke(self, off: int, fmt: str, *vals):
        """Write into bins-data at a bins-relative offset."""
        i, within = self._locate(off)
        struct.pack_into(fmt, self.bins[i], within, *vals)

    def _peek(self, off: int, fmt: str):
        i, within = self._locate(off)
        return struct.unpack_from(fmt, self.bins[i], within)

    def alloc(self, payload: bytes) -> int:
        """Allocate a cell; returns offset of the cell SIZE field, rel. to bins start."""
        size = align8(4 + len(payload))
        if (self.cur_bin < 0
                or self.cursors[self.cur_bin] + size + 8 > self.bin_sizes[self.cur_bin]):
            # +8 reserves room for the bin's trailing free cell
            self._new_bin(first=self.cur_bin < 0, min_size=size)
        within = self.cursors[self.cur_bin]
        b = self.bins[self.cur_bin]
        struct.pack_into("<i", b, within, -size)     # negative = allocated
        b[within + 4:within + 4 + len(payload)] = payload
        self.cursors[self.cur_bin] += size
        return self.bin_starts[self.cur_bin] + within

    # -- records ---------------------------------------------------
    def sk(self) -> int:
        rec = b"sk" + b"\x00\x00" + struct.pack("<II", 0, 0) + struct.pack("<II", 99, 0)
        off = self.alloc(rec)
        self._poke(off + 4 + 4, "<II", off, off)      # flink=blink=self
        return off

    def nk(self, name: str, flags: int, lastwrite: int, parent: int | None,
           subkeys: list, values: list, sk_off: int) -> int:
        nb = name.encode("ascii")
        rec = bytearray()
        rec += b"nk"
        rec += struct.pack("<H", flags)
        rec += struct.pack("<Q", lastwrite)
        rec += struct.pack("<I", 0)                    # access bits / spare
        rec += struct.pack("<I", NULL if parent is None else parent)
        rec += struct.pack("<II", len(subkeys), 0)    # subkey count, volatile count
        rec += struct.pack("<I", NULL)                # subkey list (patched)   @0x1C
        rec += struct.pack("<I", NULL)                # volatile subkey list    @0x20
        rec += struct.pack("<I", len(values))                                       # @0x24
        rec += struct.pack("<I", NULL)                # value list (patched)    @0x28
        rec += struct.pack("<I", sk_off)                                            # @0x2C
        rec += struct.pack("<I", NULL)                # class name              @0x30
        rec += struct.pack("<IIII", 0, 0, 0, 0)       # max lens                @0x34
        rec += struct.pack("<I", 0)                   # workvar                 @0x44
        rec += struct.pack("<HH", len(nb), 0)         # name len, class len     @0x48
        rec += nb                                                                   # @0x4C
        off = self.alloc(bytes(rec))
        if subkeys:
            entries = b"".join(
                struct.pack("<II", so, _hint(n)) for n, so in subkeys)
            lo = self.alloc(b"lf" + struct.pack("<H", len(subkeys)) + entries)
            self._poke(off + 4 + 0x1C, "<I", lo)
        if values:
            vo = self.alloc(struct.pack("<%dI" % len(values), *values))
            self._poke(off + 4 + 0x28, "<I", vo)
        return off

    def vk(self, name: str, vtype: int, data: bytes | None) -> int:
        nb = name.encode("ascii")
        if data is None:
            dsize, dfield = 0, NULL
        elif len(data) <= 4:
            dsize = len(data) | 0x80000000               # MSB = inline
            dfield = int.from_bytes(data.ljust(4, b"\x00"), "little")
        elif len(data) > 16344:
            dsize, dfield = len(data), self._bigdata(data)
        else:
            dsize = len(data)
            dfield = self.alloc(data)
        rec = (b"vk" + struct.pack("<H", len(nb)) + struct.pack("<I", dsize)
               + struct.pack("<I", dfield) + struct.pack("<I", vtype)
               + struct.pack("<HH", 0x0001, 0) + nb)     # 0x0001 = VALUE_COMP_NAME
        return self.alloc(rec)

    def _bigdata(self, data: bytes) -> int:
        segs = [self.alloc(data[i:i + 16344]) for i in range(0, len(data), 16344)]
        seglist = self.alloc(struct.pack("<%dI" % len(segs), *segs))
        return self.alloc(b"db" + struct.pack("<H", len(segs))
                          + struct.pack("<I", seglist))

    def set_parent(self, child_off: int, parent_off: int):
        self._poke(child_off + 4 + 0x10, "<I", parent_off)

    # -- deletion simulation ---------------------------------------
    def delete_cells(self, offs: list[int]):
        """Flip cells to free and coalesce adjacent ones (like real deletion)."""
        for off in sorted(offs):
            (sz,) = self._peek(off, "<i")
            assert sz < 0, "deleting a non-allocated cell"
            self._poke(off, "<i", -sz)
        # coalesce runs of adjacent free cells into single free cells
        offs = sorted(offs)
        runs = []
        for off in offs:
            (sz,) = self._peek(off, "<i")
            if runs and runs[-1][1] == off:
                runs[-1][1] = off + sz
            else:
                runs.append([off, off + sz])
        for start, end in runs:
            self._poke(start, "<i", end - start)

    # -- base block -------------------------------------------------
    def write_file(self, path: str, root_off: int):
        for i, b in enumerate(self.bins):              # trailing free cell per bin
            free = self.bin_sizes[i] - self.cursors[i]
            assert free >= 8, f"bin {i} overrun"
            struct.pack_into("<i", b, self.cursors[i], free)

        bb = bytearray(4096)
        bb[0:4] = b"regf"
        struct.pack_into("<II", bb, 4, 1, 1)          # seq1 == seq2 → clean
        struct.pack_into("<Q", bb, 12, TS["types"])  # hive last write
        struct.pack_into("<II", bb, 20, 1, 4)        # major 1, minor 4
        struct.pack_into("<II", bb, 28, 0, 1)        # type primary, format direct
        struct.pack_into("<I", bb, 36, root_off)
        struct.pack_into("<I", bb, 40, sum(self.bin_sizes))
        struct.pack_into("<I", bb, 44, 1)            # clustering factor
        bb[48:48 + 2 * len(self.filename)] = self.filename.encode("utf-16-le")
        c = 0                                        # XOR-32 checksum, first 508 B
        for i in range(0, 508, 4):
            c ^= struct.unpack_from("<I", bb, i)[0]
        if c == 0xFFFFFFFF:
            c = 0xFFFFFFFE
        elif c == 0:
            c = 1
        struct.pack_into("<I", bb, 508, c)
        with open(path, "wb") as f:
            f.write(bb)
            for b in self.bins:
                f.write(b)
        return path


def _hint(name: str) -> int:
    """lf 'name hint': first 4 bytes of the (ASCII) name, little-endian."""
    return struct.unpack("<I", name.encode("ascii")[:4].ljust(4, b"\x00"))[0]

def rot13(s: str) -> str:
    out = []
    for ch in s:
        o = ord(ch)
        if 65 <= o <= 90:
            out.append(chr((o - 65 + 13) % 26 + 65))
        elif 97 <= o <= 122:
            out.append(chr((o - 97 + 13) % 26 + 97))
        else:
            out.append(ch)
    return "".join(out)

# ---------------------------------------------------------------- tree
def build(path: str) -> dict:
    b = HiveBuilder("FAKEHIVE")
    sk = b.sk()

    # ---- deleted persistence key (allocated first → cells adjacent) ----
    evil_vk = b.vk("payload", 1, "C:\\Temp\\evil.exe\x00".encode("utf-16-le"))
    evil_vl = b.alloc(struct.pack("<I", evil_vk))
    evil_nk = b.nk("EvilPersistence", 0x20, TS["evil"], None, [], [], sk)
    b._poke(evil_nk + 4 + 0x24, "<I", 1)          # value count = 1
    b._poke(evil_nk + 4 + 0x28, "<I", evil_vl)   # value list

    # ---- Run key (live values only) ----
    v_upd = b.vk("Updater", 1, "C:\\Users\\kyle\\AppData\\Roaming\\updater.exe\x00".encode("utf-16-le"))
    v_steam = b.vk("Steam", 1, "C:\\Program Files\\Steam\\steam.exe\x00".encode("utf-16-le"))
    run_nk = b.nk("Run", 0x20, TS["run"], None, [], [v_upd, v_steam], sk)
    b.set_parent(evil_nk, run_nk)   # remnant: deleted key still points at Run

    v_clean = b.vk("Cleanup", 1, "C:\\Windows\\Temp\\cleanup.exe\x00".encode("utf-16-le"))
    runonce_nk = b.nk("RunOnce", 0x20, TS["run"], None, [], [v_clean], sk)

    curver_nk = b.nk("CurrentVersion", 0x20, TS["run"], None,
                     [("Run", run_nk), ("RunOnce", runonce_nk)], [], sk)
    b.set_parent(run_nk, curver_nk)
    b.set_parent(runonce_nk, curver_nk)

    # ---- Explorer: RecentDocs + UserAssist (ROT13-encoded value name) ----
    mru = b.vk("MRUListEx", 3, struct.pack("<5I", 0, 1, 2, 3, 0xFFFFFFFF))
    d0 = b.vk("0", 1, "budget_2026.xlsx\x00".encode("utf-16-le"))
    d1 = b.vk("1", 1, "oak_removal_quote.pdf\x00".encode("utf-16-le"))
    recent_nk = b.nk("RecentDocs", 0x20, TS["recent"], None, [], [mru, d0, d1], sk)

    ua_name = rot13("C:\\Users\\kyle\\updater.exe")     # stored ROT13, like real UserAssist
    ua_v = b.vk(ua_name, 3, struct.pack("<IIQ", 1, 7, 12))
    count_nk = b.nk("Count", 0x20, TS["recent"], None, [], [ua_v], sk)
    guid_nk = b.nk("{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}", 0x20, TS["recent"], None,
                   [("Count", count_nk)], [], sk)
    b.set_parent(count_nk, guid_nk)
    ua_nk = b.nk("UserAssist", 0x20, TS["recent"], None,
                 [("{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}", guid_nk)], [], sk)
    b.set_parent(guid_nk, ua_nk)

    explorer_nk = b.nk("Explorer", 0x20, TS["recent"], None,
                       [("RecentDocs", recent_nk), ("UserAssist", ua_nk)], [], sk)
    b.set_parent(recent_nk, explorer_nk)
    b.set_parent(ua_nk, explorer_nk)

    windows_nk = b.nk("Windows", 0x20, TS["run"], None,
                      [("CurrentVersion", curver_nk), ("Explorer", explorer_nk)], [], sk)
    b.set_parent(curver_nk, windows_nk)
    b.set_parent(explorer_nk, windows_nk)
    ms_nk = b.nk("Microsoft", 0x20, TS["run"], None, [("Windows", windows_nk)], [], sk)
    b.set_parent(windows_nk, ms_nk)
    sw_nk = b.nk("Software", 0x20, TS["run"], None, [("Microsoft", ms_nk)], [], sk)
    b.set_parent(ms_nk, sw_nk)

    # ---- value-type showcase + a big value + a deleted value ----
    big = bytes((i * 7) & 0xFF for i in range(20000))     # 20000 > 16344 → db record
    v_big = b.vk("blob", 3, big)
    v_dword = b.vk("Retries", 4, struct.pack("<I", 3))    # inline (<=4 bytes)
    v_qword = b.vk("BigCounter", 11, struct.pack("<Q", 0x1122334455667788))
    v_multi = b.vk("Hosts", 7, bytes([0x61,0x00,0x00,0x00,0x62,0x00,0x00,0x00,0x00,0x00]))  # ["a","b"] UTF-16LE
    v_exp = b.vk("TempDir", 2, "%SystemRoot%\\Temp\x00".encode("utf-16-le"))
    v_def = b.vk("", 1, "default data\x00".encode("utf-16-le"))
    v_secret = b.vk("OldSecret", 3, b"supersecret")       # deleted below
    types_nk = b.nk("Types", 0x20, TS["types"], None, [],
                    [v_big, v_dword, v_qword, v_multi, v_exp, v_def], sk)

    test_nk = b.nk("Test", 0x20, TS["types"], None, [("Types", types_nk)], [], sk)
    b.set_parent(types_nk, test_nk)
    # Software gains Test as second subkey: rebuild its lf in place
    lf2 = b.alloc(b"lf" + struct.pack("<H", 2)
                  + struct.pack("<II", ms_nk, _hint("Microsoft"))
                  + struct.pack("<II", test_nk, _hint("Test")))
    b._poke(sw_nk + 4 + 0x1C, "<I", lf2)
    b._poke(sw_nk + 4 + 0x14, "<I", 2)
    b.set_parent(test_nk, sw_nk)

    # ---- USBSTOR tree ----
    v_friendly = b.vk("FriendlyName", 1, "SanDisk Cruzer USB Device\x00".encode("utf-16-le"))
    v_desc = b.vk("DeviceDesc", 1, "Disk drive\x00".encode("utf-16-le"))
    dev_nk = b.nk("4C530001331122113321&0", 0x20, TS["usb"], None, [],
                  [v_friendly, v_desc], sk)
    prod_nk = b.nk("Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00", 0x20, TS["usb"], None,
                   [("4C530001331122113321&0", dev_nk)], [], sk)
    b.set_parent(dev_nk, prod_nk)
    usbstor_nk = b.nk("USBSTOR", 0x20, TS["usb"], None,
                      [("Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00", prod_nk)], [], sk)
    b.set_parent(prod_nk, usbstor_nk)
    enum_nk = b.nk("Enum", 0x20, TS["usb"], None, [("USBSTOR", usbstor_nk)], [], sk)
    b.set_parent(usbstor_nk, enum_nk)
    ccs_nk = b.nk("CurrentControlSet", 0x20, TS["usb"], None, [("Enum", enum_nk)], [], sk)
    b.set_parent(enum_nk, ccs_nk)

    v_img = b.vk("ImagePath", 2, "C:\\Windows\\Temp\\svc.exe\x00".encode("utf-16-le"))
    v_start = b.vk("Start", 4, struct.pack("<I", 2))
    svc_nk = b.nk("EvilSvc", 0x20, TS["evil"], None, [], [v_img, v_start], sk)
    services_nk = b.nk("Services", 0x20, TS["evil"], None, [("EvilSvc", svc_nk)], [], sk)
    b.set_parent(svc_nk, services_nk)
    lf3 = b.alloc(b"lf" + struct.pack("<H", 2)
                  + struct.pack("<II", enum_nk, _hint("Enum"))
                  + struct.pack("<II", services_nk, _hint("Services")))
    b._poke(ccs_nk + 4 + 0x1C, "<I", lf3)
    b._poke(ccs_nk + 4 + 0x14, "<I", 2)
    b.set_parent(services_nk, ccs_nk)
    system_nk = b.nk("System", 0x20, TS["usb"], None,
                     [("CurrentControlSet", ccs_nk)], [], sk)
    b.set_parent(ccs_nk, system_nk)

    # ---- root ----
    root_nk = b.nk("ROOT", 0x2C, TS["types"], None,
                   [("Software", sw_nk), ("System", system_nk)], [], sk)
    b.set_parent(sw_nk, root_nk)
    b.set_parent(system_nk, root_nk)

    # ---- deletions (after all live structure is final) ----
    b.delete_cells([evil_nk, evil_vl, evil_vk])  # coalesce → 1 free cell, 3 remnants
    b.delete_cells([v_secret])                   # single freed value

    b.write_file(path, root_nk)
    return {"root": root_nk, "evil_nk": evil_nk, "evil_vk": evil_vk,
            "secret_vk": v_secret, "big": big, "bins": len(b.bins)}


if __name__ == "__main__":
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else "fakehive.dat"
    info = build(out)
    print(f"wrote {out}: {os.path.getsize(out)} bytes, "
          f"{info['bins']} bins, root@{info['root']:#x}")
