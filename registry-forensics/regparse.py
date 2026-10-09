#!/usr/bin/env python3
"""regparse.py — hand-rolled Windows registry hive (REGF) parser. Zero deps.

Parses: base block (magic, sequence numbers, checksum), hive bins, cells
(signed-size allocation), NK key nodes, VK values (inline / data-cell /
big-data db segments), subkey lists (li/lf/lh/ri), and deleted-record
recovery from unallocated cells (Thomassen-style remnant scan).

Raises HiveError on malformed input.
"""
import struct
from datetime import datetime, timezone

NULL = 0xFFFFFFFF
EPOCH_DIFF = 116444736000000000

TYPES = {
    0x0: "REG_NONE", 0x1: "REG_SZ", 0x2: "REG_EXPAND_SZ", 0x3: "REG_BINARY",
    0x4: "REG_DWORD", 0x5: "REG_DWORD_BIG_ENDIAN", 0x6: "REG_LINK",
    0x7: "REG_MULTI_SZ", 0x8: "REG_RESOURCE_LIST", 0x9: "REG_FULL_RESOURCE_DESCRIPTOR",
    0xA: "REG_RESOURCE_REQUIREMENTS_LIST", 0xB: "REG_QWORD", 0x10: "REG_FILETIME",
}

NK_FLAGS = {0x0001: "KEY_VOLATILE", 0x0002: "KEY_HIVE_EXIT", 0x0004: "KEY_HIVE_ENTRY",
            0x0008: "KEY_NO_DELETE", 0x0010: "KEY_SYM_LINK", 0x0020: "KEY_COMP_NAME",
            0x0040: "KEY_PREDEF_HANDLE", 0x0080: "VirtualSource",
            0x0100: "VirtualTarget", 0x0200: "VirtualStore"}

class HiveError(Exception):
    pass

def filetime_to_dt(ft: int):
    if not ft:
        return None
    try:
        return datetime.fromtimestamp((ft - EPOCH_DIFF) / 10_000_000, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None

def decode_name(raw: bytes, ascii_name: bool) -> str:
    return raw.decode("latin-1") if ascii_name else raw.decode("utf-16-le", errors="replace")

def decode_value(vtype: int, data: bytes):
    try:
        if vtype in (1, 2, 6):
            return data.decode("utf-16-le", errors="replace").rstrip("\x00")
        if vtype == 4 and len(data) >= 4:
            return struct.unpack("<I", data[:4])[0]
        if vtype == 5 and len(data) >= 4:
            return struct.unpack(">I", data[:4])[0]
        if vtype == 11 and len(data) >= 8:
            return struct.unpack("<Q", data[:8])[0]
        if vtype == 7:
            s = data.decode("utf-16-le", errors="replace")
            return [p for p in s.split("\x00") if p]
        if vtype == 0x10 and len(data) >= 8:
            return filetime_to_dt(struct.unpack("<Q", data[:8])[0])
    except Exception:
        pass
    return data

class Hive:
    def __init__(self, path: str):
        with open(path, "rb") as f:
            self.data = f.read()
        d = self.data
        if len(d) < 4096 or d[0:4] != b"regf":
            raise HiveError("not a registry hive (bad magic)")
        self.seq1, self.seq2 = struct.unpack_from("<II", d, 4)
        self.lastwrite = filetime_to_dt(struct.unpack_from("<Q", d, 12)[0])
        self.major, self.minor = struct.unpack_from("<II", d, 20)
        self.root_off = struct.unpack_from("<I", d, 36)[0]
        self.bins_size = struct.unpack_from("<I", d, 40)[0]
        self.fname = d[48:112].decode("utf-16-le", errors="replace").rstrip("\x00")
        self.checksum_ok = self._verify_checksum()
        self.bins = []          # (bins_off, size)
        self.cells = []         # (off, size, allocated)
        self._walk_bins()

    # -- base block ----------------------------------------------
    def _verify_checksum(self) -> bool:
        c = 0
        for i in range(0, 508, 4):
            c ^= struct.unpack_from("<I", self.data, i)[0]
        if c == 0xFFFFFFFF:
            c = 0xFFFFFFFE
        elif c == 0:
            c = 1
        return c == struct.unpack_from("<I", self.data, 508)[0]

    @property
    def dirty(self) -> bool:
        return self.seq1 != self.seq2

    # -- bins & cells ---------------------------------------------
    def _walk_bins(self):
        pos, end = 4096, 4096 + self.bins_size
        if end > len(self.data):
            raise HiveError("bins size runs past end of file")
        while pos < end:
            if self.data[pos:pos + 4] != b"hbin":
                raise HiveError(f"bad hbin signature at file offset {pos:#x}")
            boff, bsize = struct.unpack_from("<II", self.data, pos + 4)
            if bsize % 4096 or bsize == 0:
                raise HiveError(f"bad bin size {bsize:#x}")
            self.bins.append((boff, bsize))
            cpos, cend = pos + 32, pos + bsize
            while cpos + 4 <= cend:
                (sz,) = struct.unpack_from("<i", self.data, cpos)
                if sz == 0 or abs(sz) % 8:
                    raise HiveError(f"bad cell size {sz} at {cpos:#x}")
                if cpos + abs(sz) > cend:
                    raise HiveError(f"cell at {cpos:#x} overruns its bin")
                self.cells.append((cpos - 4096, abs(sz), sz < 0))
                cpos += abs(sz)
            pos += bsize

    def _abs(self, off: int) -> int:
        """bins-relative offset → file offset."""
        if not 0 <= off < self.bins_size:
            raise HiveError(f"offset {off:#x} outside hive bins")
        return 4096 + off

    def _cell(self, off: int):
        a = self._abs(off)
        (sz,) = struct.unpack_from("<i", self.data, a)
        return a + 4, abs(sz) - 4, sz < 0     # payload pos, payload len, allocated

    def _rec(self, off: int, sig: bytes) -> bytes:
        a = self._abs(off)
        if self.data[a + 4:a + 6] != sig:
            raise HiveError(f"expected {sig!r} at {off:#x}")
        (_, plen, _) = self._cell(off)
        return self.data[a + 4:a + 4 + plen]

    # -- key nodes -------------------------------------------------
    def nk(self, off: int) -> dict:
        r = self._rec(off, b"nk")
        if len(r) < 0x4C:
            raise HiveError(f"truncated nk at {off:#x}")
        flags = struct.unpack_from("<H", r, 2)[0]
        lastwrite = struct.unpack_from("<Q", r, 4)[0]
        parent, nsub, nsubv = struct.unpack_from("<III", r, 0x10)
        sublist = struct.unpack_from("<I", r, 0x1C)[0]
        nval = struct.unpack_from("<I", r, 0x24)[0]
        vallist = struct.unpack_from("<I", r, 0x28)[0]
        namelen, classlen = struct.unpack_from("<HH", r, 0x48)
        name = decode_name(r[0x4C:0x4C + namelen], bool(flags & 0x20))
        if len(name) * (1 if flags & 0x20 else 2) != namelen:
            raise HiveError(f"nk name length mismatch at {off:#x}")
        if nsub > 100000 or nval > 100000:
            raise HiveError(f"implausible counts at {off:#x}")
        return {"off": off, "flags": flags,
                "flag_names": [n for m, n in NK_FLAGS.items() if flags & m],
                "lastwrite": filetime_to_dt(lastwrite), "lastwrite_raw": lastwrite,
                "parent": parent, "nsub": nsub, "sublist": sublist,
                "nval": nval, "vallist": vallist, "name": name}

    def subkey_offsets(self, nk: dict) -> list[int]:
        if nk["sublist"] == NULL or nk["nsub"] == 0:
            return []
        out, seen = [], set()
        def walk(lo):
            if lo in seen or lo == NULL:
                return
            seen.add(lo)
            r = self._rec(lo, self.data[self._abs(lo) + 4:self._abs(lo) + 6])
            sig = r[0:2]
            (cnt,) = struct.unpack_from("<H", r, 2)
            if sig in (b"lf", b"lh"):
                # entry = [4-byte key offset][4-byte name hint/hash]
                for i in range(cnt):
                    out.append(struct.unpack_from("<I", r, 4 + 8 * i)[0])
            elif sig == b"li":
                for i in range(cnt):
                    out.append(struct.unpack_from("<I", r, 4 + 4 * i)[0])
            elif sig == b"ri":
                for i in range(cnt):
                    walk(struct.unpack_from("<I", r, 4 + 4 * i)[0])
            else:
                raise HiveError(f"unknown subkey-list sig {sig!r} at {lo:#x}")
        walk(nk["sublist"])
        return out

    def subkeys(self, nk: dict):
        for so in self.subkey_offsets(nk):
            yield self.nk(so)

    # -- values ----------------------------------------------------
    def _value_data(self, dsize_raw: int, dfield: int) -> bytes:
        if dsize_raw & 0x80000000:                       # inline in the offset field
            n = dsize_raw & 0x7FFFFFFF
            return struct.pack("<I", dfield)[:n]
        n = dsize_raw
        if n == 0:
            return b""
        r = self._rec(dfield, self.data[self._abs(dfield) + 4:self._abs(dfield) + 6])
        if r[0:2] == b"db":                              # big data: concat segments
            (nseg,) = struct.unpack_from("<H", r, 2)
            seglist = struct.unpack_from("<I", r, 4)[0]
            lr = self._rec(seglist, self.data[self._abs(seglist) + 4:self._abs(seglist) + 6])
            parts = []
            for i in range(nseg):
                so = struct.unpack_from("<I", lr, 4 * i)[0]
                (_, plen, _) = self._cell(so)
                a = self._abs(so)
                seg = self.data[a + 4:a + 4 + plen]
                # segments are raw cell payloads: strip alignment padding —
                # every segment but the last is exactly 16344 bytes
                want = 16344 if i < nseg - 1 else n - 16344 * (nseg - 1)
                parts.append(seg[:want])
            return b"".join(parts)
        return r[:n]

    def vk(self, off: int) -> dict:
        r = self._rec(off, b"vk")
        namelen = struct.unpack_from("<H", r, 2)[0]
        dsize_raw, dfield = struct.unpack_from("<II", r, 4)
        vtype = struct.unpack_from("<I", r, 12)[0]
        flags = struct.unpack_from("<H", r, 16)[0]
        name = decode_name(r[0x14:0x14 + namelen], bool(flags & 0x0001))
        raw = self._value_data(dsize_raw, dfield)
        return {"off": off, "name": name or "(Default)",
                "raw_name": name, "type": TYPES.get(vtype, f"0x{vtype:x}"),
                "type_id": vtype, "size": dsize_raw & 0x7FFFFFFF,
                "inline": bool(dsize_raw & 0x80000000),
                "data": decode_value(vtype, raw), "raw": raw}

    def values(self, nk: dict):
        if nk["vallist"] == NULL or nk["nval"] == 0:
            return []
        a = self._abs(nk["vallist"]) + 4   # skip the list cell's own size field
        return [self.vk(struct.unpack_from("<I", self.data, a + 4 * i)[0])
                for i in range(nk["nval"])]

    # -- navigation -------------------------------------------------
    def path(self, nk: dict) -> str:
        parts, seen, cur = [], set(), nk
        while True:
            if cur["off"] in seen:
                parts.append("<cycle>")
                break
            seen.add(cur["off"])
            parts.append(cur["name"])
            if cur["parent"] == NULL:
                break
            try:
                cur = self.nk(cur["parent"])
            except HiveError:
                parts.append("<orphan>")
                break
        return "\\".join(reversed(parts))

    def walk(self, nk: dict = None):
        """Depth-first over live keys; yields (nk, path)."""
        nk = self.nk(self.root_off) if nk is None else nk
        stack = [(nk, None)]
        seen = set()
        while stack:
            node, parent_path = stack.pop()
            if node["off"] in seen:
                continue
            seen.add(node["off"])
            p = node["name"] if parent_path is None else parent_path + "\\" + node["name"]
            yield node, p
            for child in reversed(list(self.subkeys(node))):
                stack.append((child, p))

    # -- deleted-record recovery ------------------------------------
    @staticmethod
    def _plausible_ft(ft: int) -> bool:
        if ft == 0:
            return True
        lo = 1262304000  # 2010-01-01
        hi = 1893456000  # 2030-01-01
        return lo * 10_000_000 + EPOCH_DIFF <= ft <= hi * 10_000_000 + EPOCH_DIFF

    def _try_nk(self, payload: bytes) -> dict | None:
        try:
            if len(payload) < 0x4C or payload[0:2] != b"nk":
                return None
            flags = struct.unpack_from("<H", payload, 2)[0]
            ft = struct.unpack_from("<Q", payload, 4)[0]
            parent, nsub, nsubv = struct.unpack_from("<III", payload, 0x10)
            sublist = struct.unpack_from("<I", payload, 0x1C)[0]
            nval = struct.unpack_from("<I", payload, 0x24)[0]
            vallist = struct.unpack_from("<I", payload, 0x28)[0]
            namelen = struct.unpack_from("<H", payload, 0x48)[0]
            if not 1 <= namelen <= 256 or 0x4C + namelen > len(payload):
                return None
            if nsub > 100000 or nval > 100000:
                return None
            if not self._plausible_ft(ft):
                return None
            for o in (parent, sublist, vallist):
                if o != NULL and o >= self.bins_size:
                    return None
            name = decode_name(payload[0x4C:0x4C + namelen], bool(flags & 0x20))
            if not name or not name.isprintable():
                return None
            return {"kind": "key", "name": name, "flags": flags,
                    "lastwrite": filetime_to_dt(ft), "nsub": nsub, "nval": nval,
                    "parent": parent, "sublist": sublist, "vallist": vallist}
        except Exception:
            return None

    def _try_vk(self, payload: bytes) -> dict | None:
        try:
            if len(payload) < 0x14 or payload[0:2] != b"vk":
                return None
            namelen = struct.unpack_from("<H", payload, 2)[0]
            dsize_raw, dfield = struct.unpack_from("<II", payload, 4)
            vtype = struct.unpack_from("<I", payload, 12)[0]
            flags = struct.unpack_from("<H", payload, 16)[0]
            if not 0 <= namelen <= 256 or 0x14 + namelen > len(payload):
                return None
            if (dsize_raw & 0x7FFFFFFF) > self.bins_size + 2**20:
                return None
            if vtype not in TYPES:
                return None
            name = decode_name(payload[0x14:0x14 + namelen], bool(flags & 0x0001))
            if not name.isprintable():
                return None
            raw = self._value_data(dsize_raw, dfield)
            return {"kind": "value", "name": name or "(Default)",
                    "type": TYPES[vtype], "size": dsize_raw & 0x7FFFFFFF,
                    "data": decode_value(vtype, raw)}
        except Exception:
            return None

    def scan_deleted(self) -> list[dict]:
        """Scan unallocated cells for remnant nk/vk records (incl. coalesced)."""
        found = []
        for off, size, allocated in self.cells:
            if allocated:
                continue
            a = self._abs(off)
            payload = self.data[a + 4:a + size]
            for pos in range(0, len(payload) - 2, 8):
                sig = payload[pos:pos + 2]
                if sig == b"nk":
                    r = self._try_nk(payload[pos:])
                    if r:
                        r["cell_off"] = off
                        r["slack"] = size - 4 - pos
                        found.append(r)
                elif sig == b"vk":
                    r = self._try_vk(payload[pos:])
                    if r:
                        r["cell_off"] = off
                        found.append(r)
        # dedupe (same record reachable once)
        seen, uniq = set(), []
        for r in found:
            key = (r["kind"], r["name"], r.get("cell_off"))
            if key not in seen:
                seen.add(key)
                uniq.append(r)
        return uniq
