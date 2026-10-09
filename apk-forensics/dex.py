#!/usr/bin/env python3
"""dex.py -- hand-rolled Dalvik DEX parser (stdlib only).

Parses the DEX header (magic, adler32 checksum, SHA-1 signature, table
offsets), the string_ids table (uleb128 length + MUTF-8), type_ids, and
method_ids. Extracts every string and every method reference
(class descriptor + method name) -- the two things triage needs.

Integrity: the adler32 (of everything after the magic+checksum) and the
SHA-1 signature (of everything after the 32-byte magic+checksum+signature
prefix) are verified; mismatches raise DexError.

Limitations: class_defs / code items are not parsed (triage works from
strings + method refs, which is where URLs, IPs and API references live);
MUTF-8 is decoded as UTF-8 with errors replaced (embedded NULs encoded as
C0 80 become U+FFFD -- acceptable for triage grepping).
"""
import hashlib
import struct
import zlib

DEX_MAGICS = (b"dex\n035\x00", b"dex\n037\x00", b"dex\n038\x00",
              b"dex\n039\x00")


class DexError(Exception):
    pass


def _u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def read_uleb128(buf, off):
    val, shift, i = 0, 0, 0
    while True:
        if off + i >= len(buf):
            raise DexError("uleb128 overruns buffer")
        b = buf[off + i]
        val |= (b & 0x7F) << shift
        i += 1
        if not (b & 0x80):
            return val, i
        shift += 7
        if shift > 35:
            raise DexError("uleb128 too long")


def parse_dex(data):
    """Returns dict: strings [...], types [...], methods [(class, name)]."""
    if len(data) < 0x70:
        raise DexError("too short for a DEX header")
    magic = data[0:8]
    if magic not in DEX_MAGICS:
        raise DexError("bad DEX magic %r" % magic)
    stored_adler = _u32(data, 8)
    if zlib.adler32(data[12:]) & 0xFFFFFFFF != stored_adler:
        raise DexError("DEX adler32 mismatch")
    stored_sig = data[12:32]
    if hashlib.sha1(data[32:]).digest() != stored_sig:
        raise DexError("DEX SHA-1 signature mismatch")
    file_size = _u32(data, 32)
    header_size = _u32(data, 36)
    endian_tag = _u32(data, 40)
    if endian_tag != 0x12345678:
        raise DexError("bad endian tag")
    if file_size != len(data):
        raise DexError("header file_size %d != actual %d"
                       % (file_size, len(data)))

    string_ids_size, string_ids_off = _u32(data, 56), _u32(data, 60)
    type_ids_size, type_ids_off = _u32(data, 64), _u32(data, 68)
    method_ids_size, method_ids_off = _u32(data, 88), _u32(data, 92)

    strings = []
    for i in range(string_ids_size):
        soff = _u32(data, string_ids_off + 4 * i)
        if soff >= len(data):
            raise DexError("string_ids[%d] out of range" % i)
        ulen, n = read_uleb128(data, soff)
        start = soff + n
        end = data.index(b"\x00", start)
        raw = data[start:end]
        strings.append(raw.decode("utf-8", errors="replace"))

    types = []
    for i in range(type_ids_size):
        didx = _u32(data, type_ids_off + 4 * i)
        if didx >= len(strings):
            raise DexError("type_ids[%d] descriptor out of range" % i)
        types.append(strings[didx])

    methods = []
    for i in range(method_ids_size):
        base = method_ids_off + 8 * i
        class_idx = _u16(data, base)
        name_idx = _u32(data, base + 4)
        if class_idx >= len(types) or name_idx >= len(strings):
            raise DexError("method_ids[%d] out of range" % i)
        methods.append((types[class_idx], strings[name_idx]))

    return {
        "magic": magic,
        "strings": strings,
        "types": types,
        "methods": methods,
        "n_strings": len(strings),
        "n_types": len(types),
        "n_methods": len(methods),
    }
