#!/usr/bin/env python3
"""NTFS filesystem forensics from scratch. Zero dependencies.

Reads a raw NTFS volume image (no mounting, no ntfs-3g):
  - boot sector / BPB
  - MFT records with Update Sequence (fixup) handling
  - resident + non-resident attributes, runlist decoding (signed LCN deltas)
  - $STANDARD_INFORMATION / $FILE_NAME timestamps (FILETIME)
  - $I30 directory indexes: INDEX_ROOT + INDEX_ALLOCATION (INDX blocks)
  - path reconstruction via parent MFT references
  - $Bitmap allocation cross-checks
  - deleted-file recovery (in-use flag clear, FILE magic intact)
  - timestomp detection ($SI vs $FN timestamp skew)
  - alternate data streams (named $DATA attributes)

Layout references are from the on-disk format; every offset below was
validated against real mkntfs images with the ntfs-3g tools as oracle.
"""

import struct
import datetime

EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)

ATTR_TYPES = {
    0x10: "$STANDARD_INFORMATION", 0x20: "$ATTRIBUTE_LIST",
    0x30: "$FILE_NAME", 0x40: "$OBJECT_ID",
    0x50: "$SECURITY_DESCRIPTOR", 0x60: "$VOLUME_NAME",
    0x70: "$VOLUME_INFORMATION", 0x80: "$DATA",
    0x90: "$INDEX_ROOT", 0xA0: "$INDEX_ALLOCATION",
    0xB0: "$BITMAP", 0xC0: "$REPARSE_POINT",
    0xD0: "$EA_INFORMATION", 0xE0: "$EA",
    0x100: "$LOGGED_UTILITY_STREAM",
}

SYS_FILES = {0: "$MFT", 1: "$MFTMirr", 2: "$LogFile", 3: "$Volume",
             4: "$AttrDef", 5: "\\", 6: "$Bitmap", 7: "$Boot",
             8: "$BadClus", 9: "$Secure", 10: "$UpCase", 11: "$Extend"}

FILE_FLAG_IN_USE = 0x01
FILE_FLAG_DIR = 0x02


class NTFSError(Exception):
    pass


def filetime_to_dt(ft):
    """Windows FILETIME (100ns ticks since 1601-01-01) -> aware datetime."""
    if ft == 0:
        return None
    try:
        return EPOCH + datetime.timedelta(microseconds=ft // 10)
    except OverflowError:
        return None


def dt_to_filetime(dt):
    delta = dt - EPOCH
    return int(delta.total_seconds() * 10_000_000)


class BootSector:
    def __init__(self, data):
        if len(data) < 512:
            raise NTFSError("truncated boot sector")
        if data[0x1FE:0x200] != b"\x55\xaa":
            raise NTFSError("bad boot signature")
        if data[3:11] != b"NTFS    ":
            raise NTFSError("not an NTFS OEM id: %r" % data[3:11])
        self.bytes_per_sector = struct.unpack_from("<H", data, 0x0B)[0]
        self.sectors_per_cluster = data[0x0D]
        self.total_sectors = struct.unpack_from("<Q", data, 0x28)[0]
        self.mft_lcn = struct.unpack_from("<q", data, 0x30)[0]
        self.mftmirr_lcn = struct.unpack_from("<q", data, 0x38)[0]
        c = struct.unpack_from("<b", data, 0x40)[0]
        self.mft_record_size = 2 ** -c if c < 0 else c * self.cluster_size
        c = struct.unpack_from("<b", data, 0x44)[0]
        self.index_block_size = 2 ** -c if c < 0 else c * self.cluster_size
        self.serial = struct.unpack_from("<Q", data, 0x48)[0]

    @property
    def cluster_size(self):
        return self.bytes_per_sector * self.sectors_per_cluster

    @property
    def mft_offset(self):
        return self.mft_lcn * self.cluster_size


def apply_fixup(record, sector_size=512):
    """Apply the Update Sequence Array to a raw MFT/INDX record.

    Returns the fixed-up bytes. Raises NTFSError on USN mismatch.
    The last 2 bytes of every sector must equal USN; they are then
    replaced with the stored replacement bytes.
    """
    if record[0:4] not in (b"FILE", b"INDX", b"BAAD", b"HOLE"):
        raise NTFSError("bad record magic %r" % record[0:4])
    usa_off, usa_count = struct.unpack_from("<HH", record, 4)
    if usa_off + usa_count * 2 > len(record):
        raise NTFSError("USA runs past record end")
    usa = struct.unpack_from("<%dH" % usa_count, record, usa_off)
    usn = usa[0]
    out = bytearray(record)
    nsectors = usa_count - 1
    for i in range(nsectors):
        off = (i + 1) * sector_size - 2
        if off + 2 > len(out):
            raise NTFSError("record shorter than USA claims")
        if struct.unpack_from("<H", out, off)[0] != usn:
            raise NTFSError("update sequence mismatch at sector %d "
                            "(expected %04x)" % (i, usn))
        struct.pack_into("<H", out, off, usa[i + 1])
    return bytes(out)


def make_fixup(record, sector_size=512, usn=1):
    """Inverse of apply_fixup: stamp USN on sector ends, store originals.

    Used when *writing* MFT records surgically. Returns new bytes."""
    if len(record) % sector_size:
        raise NTFSError("record length not a multiple of sector size")
    nsectors = len(record) // sector_size
    usa_off = 0x2A  # standard location, right after the 42-byte header
    usa = [usn]
    out = bytearray(record)
    for i in range(nsectors):
        off = (i + 1) * sector_size - 2
        usa.append(struct.unpack_from("<H", out, off)[0])
        struct.pack_into("<H", out, off, usn)
    struct.pack_into("<HH", out, 4, usa_off, nsectors + 1)
    struct.pack_into("<%dH" % len(usa), out, usa_off, *usa)
    return bytes(out)


class Attribute:
    def __init__(self, atype, alen, nonres, name, flags, aid, body, raw):
        self.type = atype
        self.len = alen
        self.nonresident = nonres
        self.name = name          # decoded str or ""
        self.flags = flags
        self.id = aid
        self.body = body          # resident value bytes, or NR header dict
        self.raw = raw

    @property
    def type_name(self):
        return ATTR_TYPES.get(self.type, "UNKNOWN_%x" % self.type)

    def value(self, vol):
        """Return resident bytes, or full non-resident stream bytes."""
        if not self.nonresident:
            return self.body
        return vol.read_nonresident(self.body)

    def data_runs(self):
        assert self.nonresident
        return decode_runlist(self.body["runlist"])


def decode_runlist(buf):
    """Decode an NTFS runlist. Returns [(lcn, length), ...]; lcn=None => sparse."""
    runs = []
    prev_lcn = 0
    i = 0
    while i < len(buf):
        header = buf[i]
        i += 1
        if header == 0:
            break
        len_size = header & 0x0F
        off_size = (header >> 4) & 0x0F
        if i + len_size + off_size > len(buf):
            raise NTFSError("runlist overruns buffer")
        length = int.from_bytes(buf[i:i + len_size], "little", signed=False)
        i += len_size
        if off_size == 0:
            runs.append((None, length))  # sparse run
        else:
            delta = int.from_bytes(buf[i:i + off_size], "little", signed=True)
            i += off_size
            prev_lcn += delta
            runs.append((prev_lcn, length))
    return runs


def encode_runlist(runs):
    """Inverse of decode_runlist. runs: [(lcn|None, length), ...] -> bytes."""
    out = bytearray()
    prev = 0
    for lcn, length in runs:
        lb = length.to_bytes((length.bit_length() + 7) // 8 or 1, "little")
        if lcn is None:
            out.append(len(lb))
            out += lb
        else:
            delta = lcn - prev
            prev = lcn
            # minimal signed encoding
            for n in range(1, 9):
                lo = -(1 << (8 * n - 1))
                hi = (1 << (8 * n - 1))
                if lo <= delta < hi:
                    break
            db = delta.to_bytes(n, "little", signed=True)
            out.append((len(db) << 4) | len(lb))
            out += lb
            out += db
    out.append(0)
    return bytes(out)


def parse_attributes(record):
    """Parse attribute TLVs from a fixup-applied MFT record. Returns [Attribute]."""
    attrs_off = struct.unpack_from("<H", record, 0x14)[0]
    attrs = []
    off = attrs_off
    while off + 8 <= len(record):
        atype, alen = struct.unpack_from("<II", record, off)
        if atype == 0xFFFFFFFF:
            break
        if alen < 16 or off + alen > len(record):
            raise NTFSError("bad attribute length %d at %d" % (alen, off))
        nonres = record[off + 8]
        name_len = record[off + 9]
        name_off = struct.unpack_from("<H", record, off + 10)[0]
        flags, aid = struct.unpack_from("<HH", record, off + 12)
        name = ""
        if name_len:
            name = record[off + name_off:off + name_off + name_len * 2
                          ].decode("utf-16-le", errors="replace")
        if nonres == 0:
            vlen, voff = struct.unpack_from("<IH", record, off + 16)
            body = record[off + voff:off + voff + vlen]
            if len(body) != vlen:
                raise NTFSError("resident value overruns attribute")
        elif nonres == 1:
            start_vcn, end_vcn = struct.unpack_from("<QQ", record, off + 16)
            run_off = struct.unpack_from("<H", record, off + 32)[0]
            alloc_size, real_size, init_size = struct.unpack_from(
                "<QQQ", record, off + 40)
            body = {"start_vcn": start_vcn, "end_vcn": end_vcn,
                    "runlist": record[off + run_off:off + alen],
                    "alloc_size": alloc_size, "real_size": real_size,
                    "init_size": init_size}
        else:
            raise NTFSError("bad nonresident flag %d" % nonres)
        attrs.append(Attribute(atype, alen, nonres == 1, name, flags, aid,
                               body, record[off:off + alen]))
        off += alen
    return attrs


class MFTRecord:
    def __init__(self, vol, number, raw_fixed):
        self.vol = vol
        self.number = number
        self.raw = raw_fixed
        self.magic = raw_fixed[0:4]
        self.seq = struct.unpack_from("<H", raw_fixed, 0x10)[0]
        self.links = struct.unpack_from("<H", raw_fixed, 0x12)[0]
        self.flags = struct.unpack_from("<H", raw_fixed, 0x16)[0]
        self.used_size = struct.unpack_from("<I", raw_fixed, 0x18)[0]
        self.base_ref = struct.unpack_from("<Q", raw_fixed, 0x20)[0]
        self.attrs = parse_attributes(raw_fixed)

    @property
    def in_use(self):
        return bool(self.flags & FILE_FLAG_IN_USE)

    @property
    def is_dir(self):
        return bool(self.flags & FILE_FLAG_DIR)

    @property
    def is_base(self):
        return self.base_ref == 0

    def find(self, atype, name=""):
        return [a for a in self.attrs
                if a.type == atype and a.name == name]

    def first(self, atype, name=""):
        r = self.find(atype, name)
        return r[0] if r else None

    def standard_info(self):
        a = self.first(0x10)
        if not a or a.nonresident:
            return None
        v = a.body
        keys = ("created", "modified", "mft_modified", "accessed")
        times = {k: filetime_to_dt(struct.unpack_from("<Q", v, i * 8)[0])
                 for i, k in enumerate(keys)}
        times["dos_perms"] = struct.unpack_from("<I", v, 32)[0]
        return times

    def file_names(self):
        """All $FILE_NAME attributes: (parent_ref, parent_seq, times, size, flags, name, ns)."""
        out = []
        for a in self.find(0x30):
            v = a.body
            pref = struct.unpack_from("<Q", v, 0)[0]
            parent, pseq = pref & 0xFFFFFFFFFFFF, pref >> 48
            times = [filetime_to_dt(struct.unpack_from("<Q", v, 8 + i * 8)[0])
                     for i in range(4)]
            alloc, real = struct.unpack_from("<QQ", v, 40)
            flags = struct.unpack_from("<I", v, 56)[0]
            nlen, ns = v[64], v[65]
            name = v[66:66 + nlen * 2].decode("utf-16-le", errors="replace")
            out.append({"parent": parent, "parent_seq": pseq,
                        "times": times, "alloc_size": alloc,
                        "real_size": real, "flags": flags,
                        "name": name, "namespace": ns})
        return out

    def data_streams(self):
        """All $DATA attributes: {name: Attribute} ('' == unnamed/main)."""
        return {a.name: a for a in self.attrs if a.type == 0x80}

    def read_stream(self, name=""):
        a = self.first(0x80, name)
        if a is None:
            raise NTFSError("no $DATA stream %r" % name)
        data = a.value(self.vol)
        if a.nonresident:
            data = data[:a.body["real_size"]]
        return data


def parse_index_entries(node, off):
    """Parse index entries from an INDEX node body. Yields dicts."""
    first, total, alloced = struct.unpack_from("<III", node, off)
    if total > alloced:
        raise NTFSError("index node corrupt: total %d > allocated %d" %
                        (total, alloced))
    # flags at off+12: 0x01 => large index (has subnodes somewhere)
    pos = off + 16 + first
    end = off + 16 + total
    while pos + 16 <= end:
        ref, elen, klen, eflags = struct.unpack_from("<QHHH", node, pos)
        if elen < 16 or pos + elen > len(node):
            break
        entry = {"ref": ref & 0xFFFFFFFFFFFF, "seq": ref >> 48,
                 "flags": eflags, "key": node[pos + 16:pos + 16 + klen]}
        if eflags & 0x01:  # has subnode: VCN lives in last 8 bytes
            entry["subnode_vcn"] = struct.unpack_from(
                "<Q", node, pos + elen - 8)[0]
        yield entry
        if eflags & 0x02:  # last entry
            break
        pos += elen


def parse_filename_key(key):
    """Unpack a $FILE_NAME index key -> (parent, name, is_dir)."""
    pref = struct.unpack_from("<Q", key, 0)[0]
    nlen = key[64]
    name = key[66:66 + nlen * 2].decode("utf-16-le", errors="replace")
    flags = struct.unpack_from("<I", key, 56)[0]
    return pref & 0xFFFFFFFFFFFF, name, bool(flags & 0x10000000)


class Volume:
    def __init__(self, path):
        self.path = path
        self.f = open(path, "rb")
        self.boot = BootSector(self._pread(0, 512))
        self.cs = self.boot.cluster_size
        self.mft_rec_size = self.boot.mft_record_size
        self._mft_cache = {}
        self._mft_data_runs = None
        self._bitmap_cache = None

    def _pread(self, off, n):
        self.f.seek(off)
        return self.f.read(n)

    def close(self):
        self.f.close()

    # ---- cluster I/O ----
    def read_clusters(self, lcn, count):
        return self._pread(lcn * self.cs, count * self.cs)

    def mft_runs(self):
        if self._mft_data_runs is None:
            raw = self._pread(self.boot.mft_offset, self.mft_rec_size)
            rec = MFTRecord(self, 0, apply_fixup(raw))
            da = rec.first(0x80)
            if da is None or not da.nonresident:
                raise NTFSError("$MFT has no non-resident $DATA")
            self._mft_data_runs = da.data_runs()
        return self._mft_data_runs

    def read_nonresident(self, nr):
        """Read a full non-resident attribute stream (sparse runs => zeroes)."""
        runs = decode_runlist(nr["runlist"])
        out = bytearray()
        for lcn, length in runs:
            nbytes = length * self.cs
            if lcn is None:
                out += b"\x00" * nbytes
            else:
                out += self.read_clusters(lcn, length)
        return bytes(out)

    def mft_record(self, number):
        if number in self._mft_cache:
            return self._mft_cache[number]
        # locate record via $MFT runlist (walk runs in VCN space)
        target = number * self.mft_rec_size
        vcn = target // self.cs
        vbase = 0
        for lcn, length in self.mft_runs():
            if lcn is None:
                vbase += length
                continue
            if vbase <= vcn < vbase + length:
                off = (lcn + (vcn - vbase)) * self.cs + (target % self.cs)
                raw = self._pread(off, self.mft_rec_size)
                rec = MFTRecord(self, number, apply_fixup(raw))
                self._mft_cache[number] = rec
                return rec
            vbase += length
        raise NTFSError("MFT record %d beyond $MFT runs" % number)

    def mft_record_raw(self, number):
        """Raw (fixup-applied) bytes of an MFT record without parsing."""
        target = number * self.mft_rec_size
        vcn = target // self.cs
        vbase = 0
        for lcn, length in self.mft_runs():
            if lcn is None:
                vbase += length
                continue
            if vbase <= vcn < vbase + length:
                off = (lcn + (vcn - vbase)) * self.cs + (target % self.cs)
                return apply_fixup(self._pread(off, self.mft_rec_size))
            vbase += length
        raise NTFSError("MFT record %d beyond $MFT runs" % number)

    # ---- volume bitmap ----
    def volume_bitmap(self):
        if self._bitmap_cache is None:
            rec = self.mft_record(6)  # $Bitmap
            da = rec.first(0x80)
            self._bitmap_cache = da.value(self)
        return self._bitmap_cache

    def cluster_allocated(self, lcn):
        bm = self.volume_bitmap()
        byte, bit = lcn // 8, lcn % 8
        if byte >= len(bm):
            return False
        return bool(bm[byte] & (1 << bit))

    # ---- directory enumeration ----
    def list_dir(self, number):
        """Yield (name, ref, is_dir, raw_key) for a directory's $I30."""
        rec = self.mft_record(number)
        if not rec.is_dir:
            raise NTFSError("MFT %d is not a directory" % number)
        ir = rec.first(0x90, "$I30")
        if ir is None or ir.nonresident:
            raise NTFSError("no resident $INDEX_ROOT/$I30")
        v = ir.body
        # INDEX_ROOT header: type, collation, index_block_size, clusters/index
        entries = list(parse_index_entries(v, 16))
        ia = rec.first(0xA0, "$I30")
        if ia is not None:
            # walk subnodes for entries with the subnode flag, recursively
            runs = ia.data_runs()
            # map VCN -> file offset of index block
            vcn_to_off = {}
            vbase = 0
            for lcn, length in runs:
                if lcn is not None:
                    for i in range(length):
                        vcn_to_off[vbase + i] = (lcn + i) * self.cs
                vbase += length

            def read_indx(vcn):
                off = vcn_to_off.get(vcn)
                if off is None:
                    raise NTFSError("subnode VCN %d not in runs" % vcn)
                blk = self._pread(off, self.boot.index_block_size)
                if blk[0:4] != b"INDX":
                    raise NTFSError("bad INDX magic at VCN %d" % vcn)
                return apply_fixup(blk)

            def walk(node_entries):
                for e in node_entries:
                    if "subnode_vcn" in e:
                        sub = read_indx(e["subnode_vcn"])
                        # INDX node header starts after 24-byte INDX header
                        yield from walk(parse_index_entries(sub, 24))
                    if not (e["flags"] & 0x02):  # skip end-marker entries
                        parent, name, is_dir = parse_filename_key(e["key"])
                        yield name, e["ref"], is_dir, e["key"]
                # note: entries WITH subnode flag still carry their own key

            # root entries that have subnodes need the walk; plain ones first
            for e in entries:
                if "subnode_vcn" in e:
                    yield from walk([e])
                elif not (e["flags"] & 0x02):
                    parent, name, is_dir = parse_filename_key(e["key"])
                    yield name, e["ref"], is_dir, e["key"]
        else:
            for e in entries:
                if e["flags"] & 0x02:
                    continue
                parent, name, is_dir = parse_filename_key(e["key"])
                yield name, e["ref"], is_dir, e["key"]

    # ---- path resolution ----
    def full_path(self, number, _seen=None):
        # NOTE: no SYS_FILES shortcut — the parent walk is authoritative.
        # (Minimal/toy formats don't have $Secure at 9 etc.)
        if _seen is None:
            _seen = set()
        if number in _seen:
            return "<loop>/%d" % number
        _seen.add(number)
        rec = self.mft_record(number)
        fns = rec.file_names()
        if not fns:
            return "<no-name>/%d" % number
        fn = fns[0]
        if fn["parent"] == number or fn["parent"] == 5 and number == 5:
            return "\\" + fn["name"] if number != 5 else "\\"
        if number == 5:
            return "\\"
        parent_path = self.full_path(fn["parent"], _seen)
        return parent_path.rstrip("\\") + "\\" + fn["name"]

    # ---- deleted scan ----
    def scan_deleted(self, max_records=None):
        """Yield MFTRecords that look like deleted files (flag clear, FILE magic)."""
        # find $MFT size in records from its $DATA real size
        mft0 = self.mft_record(0)
        da = mft0.first(0x80)
        total = da.body["real_size"] // self.mft_rec_size
        if max_records is not None:
            total = min(total, max_records)
        for n in range(total):
            try:
                raw = self.mft_record_raw(n)
            except NTFSError:
                continue
            if raw[0:4] != b"FILE":
                continue
            flags = struct.unpack_from("<H", raw, 0x16)[0]
            if flags & FILE_FLAG_IN_USE:
                continue
            try:
                rec = MFTRecord(self, n, raw)
            except NTFSError:
                continue
            if rec.is_base and rec.file_names():
                yield rec
