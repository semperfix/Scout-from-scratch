#!/usr/bin/env python3
"""zipread.py -- hand-rolled ZIP container reader (stdlib only).

Parses the end-of-central-directory (EOCD) by scanning backwards from the end
of file, walks the central directory, and extracts entries via their local
file headers. Supports stored (method 0) and deflated (method 8, via the
stdlib `zlib` raw inflate -- the container parsing itself is hand-rolled).

Validated byte-identical against stdlib `zipfile` on generated fixtures
(see test_apk.py).

Limitations: no ZIP64, no multi-disk archives, no encrypted entries, no data
descriptors (bit 3) -- sizes are taken from the central directory, which is
authoritative for reading.
"""
import struct
import zlib

EOCD_SIG = b"PK\x05\x06"
CD_SIG = b"PK\x01\x02"
LFH_SIG = b"PK\x03\x04"


class ZipError(Exception):
    pass


def _u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def find_eocd(data):
    """Scan backwards for the EOCD signature. Returns its offset."""
    # EOCD is >= 22 bytes; comment may be up to 65535 bytes, so in the worst
    # case scan the tail. Cap the scan at 66KB to stay sane.
    tail = data[max(0, len(data) - 66000):]
    idx = tail.rfind(EOCD_SIG)
    if idx < 0:
        raise ZipError("EOCD signature not found")
    return len(data) - len(tail) + idx


def parse_eocd(data):
    off = find_eocd(data)
    if len(data) - off < 22:
        raise ZipError("truncated EOCD")
    (disk_no, cd_disk, disk_entries, total_entries, cd_size, cd_off,
     comment_len) = struct.unpack_from("<HHHHIIH", data, off + 4)
    return {
        "eocd_offset": off,
        "total_entries": total_entries,
        "cd_size": cd_size,
        "cd_offset": cd_off,
        "comment_len": comment_len,
    }


class ZipEntry(object):
    def __init__(self, name, method, flags, crc32, comp_size, uncomp_size,
                 lfh_offset):
        self.name = name
        self.method = method            # 0 = stored, 8 = deflated
        self.flags = flags
        self.crc32 = crc32
        self.comp_size = comp_size
        self.uncomp_size = uncomp_size
        self.lfh_offset = lfh_offset

    def __repr__(self):
        return "ZipEntry(%r, method=%d, %d->%d bytes)" % (
            self.name, self.method, self.comp_size, self.uncomp_size)


def list_entries(data):
    """Walk the central directory. Returns [ZipEntry]."""
    eocd = parse_eocd(data)
    entries = []
    off = eocd["cd_offset"]
    for _ in range(eocd["total_entries"]):
        if data[off:off + 4] != CD_SIG:
            raise ZipError("bad central directory signature at %#x" % off)
        (ver_made, ver_need, flags, method, mod_time, mod_date, crc32,
         comp_size, uncomp_size, name_len, extra_len, comment_len,
         disk_start, int_attr, ext_attr,
         lfh_off) = struct.unpack_from("<HHHHHHIIIHHHHHII", data, off + 4)
        name = data[off + 46:off + 46 + name_len]
        try:
            name = name.decode("utf-8")
        except UnicodeDecodeError:
            name = name.decode("cp437")
        entries.append(ZipEntry(name, method, flags, crc32, comp_size,
                                uncomp_size, lfh_off))
        off += 46 + name_len + extra_len + comment_len
    return entries


def _data_offset(data, entry):
    """Offset of the entry's raw data via its local file header."""
    off = entry.lfh_offset
    if data[off:off + 4] != LFH_SIG:
        raise ZipError("bad local header for %r" % entry.name)
    name_len = _u16(data, off + 26)
    extra_len = _u16(data, off + 28)
    return off + 30 + name_len + extra_len


def read_entry(data, entry):
    """Return the decompressed bytes of a ZipEntry."""
    if entry.flags & 0x08:
        raise ZipError("data descriptors not supported (%r)" % entry.name)
    doff = _data_offset(data, entry)
    raw = data[doff:doff + entry.comp_size]
    if len(raw) < entry.comp_size:
        raise ZipError("truncated data for %r" % entry.name)
    if entry.method == 0:
        out = raw
    elif entry.method == 8:
        out = zlib.decompress(raw, -15)
    else:
        raise ZipError("unsupported method %d (%r)" % (entry.method, entry.name))
    if len(out) != entry.uncomp_size:
        raise ZipError("size mismatch for %r" % entry.name)
    if zlib.crc32(out) & 0xFFFFFFFF != entry.crc32:
        raise ZipError("CRC mismatch for %r" % entry.name)
    return out


def read_name(data, name):
    for e in list_entries(data):
        if e.name == name:
            return read_entry(data, e)
    raise ZipError("no such entry: %r" % name)


def names(data):
    return [e.name for e in list_entries(data)]
