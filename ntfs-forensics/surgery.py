#!/usr/bin/env python3
"""NTFS surgical file injector — hand-crafts MFT records into a real image.

Takes a volume created by mkntfs and adds files/directories/ADS/deleted
entries by writing raw MFT records, updating bitmaps, and inserting
$I30 index entries — all with the from-scratch codec in ntfs.py.

This is the fixture factory for the forensic parser: every byte the
parser reads was placed by this tool (or by mkntfs), and the ntfs-3g
tools act as the independent oracle.
"""

import struct
import datetime
import sys

from ntfs import (Volume, BootSector, NTFSError, apply_fixup, make_fixup,
                  decode_runlist, encode_runlist, dt_to_filetime,
                  filetime_to_dt, parse_index_entries, parse_filename_key,
                  EPOCH)

BASE_TIME = datetime.datetime(2026, 10, 1, 12, 0, 0,
                              tzinfo=datetime.timezone.utc)


def build_si(times=None, dos_perms=0x20):
    ft = dt_to_filetime(times or BASE_TIME)
    return struct.pack("<4QIIIIIIQQ", ft, ft, ft, ft, dos_perms,
                       0, 0, 0, 0, 0, 0, 0)


def build_fn(parent_ref, name, real_size, alloc_size, is_dir=False,
             times=None, namespace=3):
    ft = dt_to_filetime(times or BASE_TIME)
    flags = 0x10000000 if is_dir else 0x20
    nb = name.encode("utf-16-le")
    return (struct.pack("<Q4QQQIIBB", parent_ref, ft, ft, ft, ft,
                        alloc_size, real_size, flags, 0,
                        len(name), namespace) + nb)


def build_attr(atype, body, name="", aid=0, nonres_body=None):
    """Build a complete attribute (resident or non-resident)."""
    nb = name.encode("utf-16-le")
    if nonres_body is None:
        # resident: name goes between header and value
        total = 24 + len(nb) + len(body)
        hdr = struct.pack("<IIBBHHHIHBB", atype, total, 0, len(name),
                          24, 0, aid, len(body), 24 + len(nb), 0, 0)
        return hdr + nb + body
    else:
        nr = nonres_body  # dict(start_vcn, end_vcn, runs, alloc, real, init)
        runlist = encode_runlist(nr["runs"])
        total = 64 + len(nb) + len(runlist)
        hdr = struct.pack("<IIBBHHHQQHHIQQQ", atype, total, 1, len(name),
                          64, 0, aid,
                          nr["start_vcn"], nr["end_vcn"],
                          64 + len(nb), 0, 0,
                          nr["alloc"], nr["real"], nr["init"])
        return hdr + nb + runlist


def build_index_root_entry(mft_number, seq, fn_body):
    ref = (mft_number & 0xFFFFFFFFFFFF) | (seq << 48)
    klen = len(fn_body)
    elen = 16 + klen
    elen = (elen + 7) & ~7  # 8-byte align
    return (struct.pack("<QHHH", ref, elen, klen, 0x00) + b"\x00\x00" +
            fn_body + b"\x00" * (elen - 16 - klen))


def build_index_root(index_block_size=4096, entries=()):
    body = struct.pack("<IIIB3s", 0x30, 0x01, index_block_size, 1, b"\x00\x00\x00")
    node = bytearray()
    # reserve node header (16 bytes); entries appended after
    node += b"\x00" * 16
    for e in entries:
        node += e
    # end marker
    node += struct.pack("<QHHH", 0, 16, 0, 0x02) + b"\x00\x00"
    first, total = 0, len(node) - 16
    struct.pack_into("<III", node, 0, first, total, total)
    node[12] = 0x00  # leaf: no subnodes
    return body + bytes(node)


def collation_key(name):
    # COLLATION_FILENAME ~ case-insensitive; ASCII test names: upper() suffices
    return name.upper()


class Surgeon:
    """Raw read/write handle on an NTFS image for fixture construction."""

    def __init__(self, path):
        self.path = path
        self.f = open(path, "r+b")
        self.boot = BootSector(self.pread(0, 512))
        self.cs = self.boot.cluster_size
        self.rec_size = self.boot.mft_record_size

    def pread(self, off, n):
        self.f.seek(off)
        return self.f.read(n)

    def pwrite(self, off, data):
        self.f.seek(off)
        self.f.write(data)
        self.f.flush()

    def close(self):
        self.f.close()

    # ---- $MFT navigation (no fixup cache; direct) ----
    def mft_offset_of(self, number):
        # read $MFT record 0's runlist directly from the boot-known location
        raw = apply_fixup(self.pread(self.boot.mft_offset, self.rec_size))
        from ntfs import parse_attributes
        for a in parse_attributes(raw):
            if a.type == 0x80 and a.nonresident:
                runs = decode_runlist(a.body["runlist"])
                break
        else:
            raise NTFSError("no $MFT data runs")
        target = number * self.rec_size
        vcn = target // self.cs
        vbase = 0
        for lcn, length in runs:
            if lcn is None:
                vbase += length
                continue
            if vbase <= vcn < vbase + length:
                return (lcn + (vcn - vbase)) * self.cs + (target % self.cs)
            vbase += length
        raise NTFSError("MFT record %d out of range" % number)

    def read_mft_raw(self, number):
        return apply_fixup(self.pread(self.mft_offset_of(number),
                                      self.rec_size))

    def _mirror_offset(self, number):
        """File offset of record <number> inside $MFTMirr (None if >= 4)."""
        if number >= 4:
            return None
        if not hasattr(self, "_mirror_runs"):
            from ntfs import parse_attributes
            raw = apply_fixup(self.pread(self.mft_offset_of(1),
                                         self.rec_size))
            self._mirror_runs = None
            for a in parse_attributes(raw):
                if a.type == 0x80 and a.nonresident:
                    self._mirror_runs = decode_runlist(a.body["runlist"])
            if self._mirror_runs is None:
                raise NTFSError("no $MFTMirr data runs")
        target = number * self.rec_size
        vcn = target // self.cs
        vbase = 0
        for lcn, length in self._mirror_runs:
            if lcn is None:
                vbase += length
                continue
            if vbase <= vcn < vbase + length:
                return (lcn + (vcn - vbase)) * self.cs + (target % self.cs)
            vbase += length
        raise NTFSError("mirror record %d out of range" % number)

    def write_mft_raw(self, number, fixed_record):
        """Write a fixup-applied record: re-stamp fixup and write."""
        stamped = make_fixup(fixed_record)
        self.pwrite(self.mft_offset_of(number), stamped)
        # real NTFS keeps $MFTMirr in sync for the first 4 records
        moff = self._mirror_offset(number)
        if moff is not None:
            self.pwrite(moff, stamped)

    def mft_bitmap(self):
        """Return (bytearray bitmap, absolute file offset of bitmap data)."""
        raw = self.read_mft_raw(0)
        from ntfs import parse_attributes
        for a in parse_attributes(raw):
            if a.type == 0xB0 and not a.nonresident:
                bm = bytearray(a.body)
                # bitmap attr is resident in $MFT record 0
                return bm, None  # resident: must rewrite whole record
        raise NTFSError("no resident $BITMAP in $MFT")

    def set_mft_bit(self, number, used):
        raw = bytearray(self.read_mft_raw(0))
        from ntfs import parse_attributes
        attrs_off = struct.unpack_from("<H", raw, 0x14)[0]
        off = attrs_off
        while True:
            atype, alen = struct.unpack_from("<II", raw, off)
            if atype == 0xFFFFFFFF:
                raise NTFSError("no $BITMAP found")
            if atype == 0xB0:
                vlen, voff = struct.unpack_from("<IH", raw, off + 16)
                i = off + voff + number // 8
                if used:
                    raw[i] |= (1 << (number % 8))
                else:
                    raw[i] &= ~(1 << (number % 8))
                self.write_mft_raw(0, bytes(raw))
                return
            off += alen

    def alloc_mft_record(self):
        """Find a free MFT record number, mark it used, return it."""
        raw = self.read_mft_raw(0)
        from ntfs import parse_attributes
        for a in parse_attributes(raw):
            if a.type == 0xB0 and not a.nonresident:
                bm = a.body
                break
        else:
            raise NTFSError("no $BITMAP")
        total = len(bm) * 8
        # real NTFS reserves 0-15 for system files; this minimal format only
        # defines 0,1,3,5,6, so allocation starts at 7.
        for n in range(7, total):
            if not (bm[n // 8] & (1 << (n % 8))):
                self.set_mft_bit(n, True)
                return n
        raise NTFSError("MFT full")

    # ---- volume bitmap ----
    def _vol_bitmap_runs(self):
        raw = self.read_mft_raw(6)
        from ntfs import parse_attributes
        for a in parse_attributes(raw):
            if a.type == 0x80 and a.nonresident:
                return decode_runlist(a.body["runlist"])
        raise NTFSError("no $Bitmap runs")

    def _vol_bitmap_abs(self, byte_index):
        vcn = byte_index // self.cs
        vbase = 0
        for lcn, length in self._vol_bitmap_runs():
            if lcn is None:
                vbase += length
                continue
            if vbase <= vcn < vbase + length:
                return (lcn + (vcn - vbase)) * self.cs + (byte_index % self.cs)
            vbase += length
        raise NTFSError("bitmap byte out of range")

    def set_cluster_bit(self, lcn, used):
        off = self._vol_bitmap_abs(lcn // 8)
        b = self.pread(off, 1)[0]
        if used:
            b |= (1 << (lcn % 8))
        else:
            b &= ~(1 << (lcn % 8))
        self.pwrite(off, bytes([b]))

    def cluster_is_free(self, lcn):
        off = self._vol_bitmap_abs(lcn // 8)
        return not (self.pread(off, 1)[0] & (1 << (lcn % 8)))

    def alloc_clusters(self, count, fragmented=False):
        """Allocate clusters; fragmented=True forces >=2 runs."""
        total_clusters = (self.boot.total_sectors //
                          self.boot.sectors_per_cluster)
        found = []
        got = 0
        lcn = 0
        while got < count:
            # scan for free clusters
            while lcn < total_clusters and not self.cluster_is_free(lcn):
                lcn += 1
            if lcn >= total_clusters:
                raise NTFSError("disk full")
            start = lcn
            while (lcn < total_clusters and self.cluster_is_free(lcn)
                   and got + (lcn - start) < count):
                lcn += 1
            run_len = lcn - start
            if fragmented:
                run_len = min(run_len, 1)  # force single-cluster runs
                lcn += 1  # skip a cluster to guarantee a gap
            if run_len:
                found.append((start, run_len))
                got += run_len
            for c in range(start, start + run_len):
                self.set_cluster_bit(c, True)
        # merge adjacent runs
        merged = []
        for s, ln in found:
            if merged and merged[-1][0] + merged[-1][1] == s:
                merged[-1] = (merged[-1][0], merged[-1][1] + ln)
            else:
                merged.append((s, ln))
        return merged

    def free_clusters(self, runs):
        for lcn, length in runs:
            if lcn is None:
                continue
            for c in range(lcn, lcn + length):
                self.set_cluster_bit(c, False)

    def write_clusters(self, runs, data):
        pos = 0
        for lcn, length in runs:
            if lcn is None:
                pos += length * self.cs
                continue
            chunk = data[pos:pos + length * self.cs]
            if len(chunk) < length * self.cs:
                chunk += b"\x00" * (length * self.cs - len(chunk))
            self.pwrite(lcn * self.cs, chunk)
            pos += length * self.cs

    # ---- $I30 index surgery ----
    def insert_index_entry(self, dir_number, entry):
        """Insert a pre-built index entry into dir's resident $I30 INDEX_ROOT,
        keeping collation order. dir must have a leaf INDEX_ROOT."""
        raw = bytearray(self.read_mft_raw(dir_number))
        from ntfs import parse_attributes
        attrs_off = struct.unpack_from("<H", raw, 0x14)[0]
        off = attrs_off
        while True:
            atype, alen = struct.unpack_from("<II", raw, off)
            if atype == 0xFFFFFFFF:
                raise NTFSError("no $INDEX_ROOT")
            if atype == 0x90:
                break
            off += alen
        vlen, voff = struct.unpack_from("<IH", raw, off + 16)
        body_off = off + voff
        node_off = body_off + 16
        first, total, alloced = struct.unpack_from("<III", raw, node_off)
        flags = raw[node_off + 12]
        if flags & 0x01:
            raise NTFSError("large index: not implemented in surgeon")
        # find insertion point (collation order), before end marker
        klen = struct.unpack_from("<H", entry, 10)[0]
        new_name = parse_filename_key(entry[16:16 + klen])[1]
        pos = node_off + 16 + first
        end = node_off + 16 + total
        ins = None
        while pos < end:
            elen, klen, eflags = struct.unpack_from("<HHH", raw, pos + 8)
            if eflags & 0x02:
                ins = pos  # insert before end marker
                break
            key = bytes(raw[pos + 16:pos + 16 + klen])
            _, name, _ = parse_filename_key(key)
            if collation_key(new_name) < collation_key(name):
                ins = pos
                break
            pos += elen
        if ins is None:
            raise NTFSError("no end marker found")
        # MFT records are fixed-size: insert inside the used region,
        # consuming zero slack at the end (real NTFS does exactly this).
        used = struct.unpack_from("<I", raw, 0x18)[0]
        new_used = used + len(entry)
        if new_used > self.rec_size:
            raise NTFSError("MFT record overflow inserting index entry")
        new_raw = bytearray(raw[:used])
        new_raw[ins:ins] = entry
        new_raw += b"\x00" * (self.rec_size - len(new_raw))
        # fix sizes: attr length, record used size, value length, node total
        struct.pack_into("<I", new_raw, off + 4, alen + len(entry))
        struct.pack_into("<I", new_raw, 0x18, new_used)
        struct.pack_into("<I", new_raw, off + 16,
                         struct.unpack_from("<I", raw, off + 16)[0] + len(entry))
        # node total size AND allocated size (TSK validates total <= alloc)
        struct.pack_into("<I", new_raw, node_off + 4, total + len(entry))
        struct.pack_into("<I", new_raw, node_off + 8, total + len(entry))
        self.write_mft_raw(dir_number, bytes(new_raw))

    def remove_index_entry(self, dir_number, name):
        """Remove an index entry by name (for the 'deleted file' fixture)."""
        raw = bytearray(self.read_mft_raw(dir_number))
        from ntfs import parse_attributes
        attrs_off = struct.unpack_from("<H", raw, 0x14)[0]
        off = attrs_off
        while True:
            atype, alen = struct.unpack_from("<II", raw, off)
            if atype == 0xFFFFFFFF:
                raise NTFSError("no $INDEX_ROOT")
            if atype == 0x90:
                break
            off += alen
        vlen, voff = struct.unpack_from("<IH", raw, off + 16)
        node_off = off + voff + 16
        first, total, alloced = struct.unpack_from("<III", raw, node_off)
        pos = node_off + 16 + first
        end = node_off + 16 + total
        while pos < end:
            elen, klen, eflags = struct.unpack_from("<HHH", raw, pos + 8)
            if eflags & 0x02:
                raise NTFSError("entry %r not found" % name)
            key = bytes(raw[pos + 16:pos + 16 + klen])
            _, ename, _ = parse_filename_key(key)
            if ename == name:
                used = struct.unpack_from("<I", raw, 0x18)[0]
                del raw[pos:pos + elen]
                raw += b"\x00" * elen  # keep fixed record size
                struct.pack_into("<I", raw, off + 4, alen - elen)
                struct.pack_into("<I", raw, 0x18, used - elen)
                struct.pack_into("<I", raw, off + 16,
                                 struct.unpack_from("<I", raw, off + 16)[0] - elen)
                struct.pack_into("<I", raw, node_off + 4, total - elen)
                self.write_mft_raw(dir_number, bytes(raw))
                return
            pos += elen

    # ---- high-level file creation ----
    def create_file(self, parent, name, data=None, runs=None, ads=None,
                    is_dir=False, si_times=None, fn_times=None):
        """Create a file or directory. data->resident; runs->non-resident
        (list of (lcn,length)); ads->{stream_name: bytes}."""
        number = self.alloc_mft_record()
        seq = 1
        ref = (number & 0xFFFFFFFFFFFF) | (seq << 48)
        attrs = []
        aid = 0
        attrs.append((0x10, build_si(si_times), "", aid)); aid += 1
        alloc_sz = 0 if data is None else len(data)
        fn = build_fn((parent & 0xFFFFFFFFFFFF) | (1 << 48), name,
                      alloc_sz, alloc_sz, is_dir, fn_times)
        attrs.append((0x30, fn, "", aid)); aid += 1
        if is_dir:
            attrs.append((0x90, build_index_root(
                self.boot.index_block_size), "$I30", aid)); aid += 1
        else:
            if runs is not None:
                vcn_len = sum(l for _, l in runs)
                nr = {"start_vcn": 0, "end_vcn": vcn_len,
                      "runs": runs,
                      "alloc": vcn_len * self.cs,
                      "real": len(data or b""),
                      "init": len(data or b"")}
                attrs.append((0x80, None, "", aid, nr)); aid += 1
                self.write_clusters(runs, data or b"")
            else:
                attrs.append((0x80, data or b"", "", aid)); aid += 1
        for sname, sdata in (ads or {}).items():
            attrs.append((0x80, sdata, sname, aid)); aid += 1
        # assemble record
        rec = bytearray(self.rec_size)
        rec[0:4] = b"FILE"
        # 0x10 seq, 0x12 link count, 0x14 attrs offset, 0x16 flags
        struct.pack_into("<HHHH", rec, 0x10, seq, 1, 0x30,
                         0x01 | (0x02 if is_dir else 0x00))
        struct.pack_into("<H", rec, 0x28, aid)  # next attr id
        pos = 0x30
        for item in attrs:
            if len(item) == 4:
                atype, body, aname, aid_ = item
                a = build_attr(atype, body, aname, aid_)
            else:
                atype, body, aname, aid_, nr = item
                a = build_attr(atype, body, aname, aid_, nr)
            rec[pos:pos + len(a)] = a
            pos += len(a)
        struct.pack_into("<I", rec, pos, 0xFFFFFFFF)
        pos += 8
        struct.pack_into("<II", rec, 0x18, pos, self.rec_size)
        self.write_mft_raw(number, bytes(rec))
        # link into parent index
        entry = build_index_root_entry(number, seq, fn)
        self.insert_index_entry(parent, entry)
        return number

    def delete_file(self, parent, number, name):
        """Simulate deletion: unlink from index, clear in-use + bitmap bits,
        keep MFT record and data clusters intact (classic carve scenario)."""
        raw = bytearray(self.read_mft_raw(number))
        from ntfs import parse_attributes
        # free data clusters first (read runs before touching anything)
        rec_attrs = parse_attributes(bytes(raw))
        for a in rec_attrs:
            if a.type == 0x80 and a.nonresident:
                self.free_clusters(decode_runlist(a.body["runlist"]))
        # clear in-use flag
        flags = struct.unpack_from("<H", raw, 0x16)[0]
        struct.pack_into("<H", raw, 0x16, flags & ~0x01)
        self.write_mft_raw(number, bytes(raw))
        # unlink from parent index
        self.remove_index_entry(parent, name)
        # free the MFT record bit? Real NTFS frees it. But then alloc may
        # reuse it — for the fixture we keep it marked used so nothing
        # overwrites it, while the in-use flag says deleted. (Both states
        # occur in the wild; ntfsundelete handles either.)
