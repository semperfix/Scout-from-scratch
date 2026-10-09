#!/usr/bin/env python3
"""axml.py -- hand-rolled binary AndroidManifest.xml parser (stdlib only).

Parses the aapt2 binary XML wire format (little-endian ResChunk stream):
chunk headers, the string pool (UTF-8 and UTF-16), the resource map,
namespace decls, and start/end element chunks with their attributes.

Wire-format notes (empirically reverse-engineered from real aapt2 output,
and reflected in the fixture builder):
  * string-pool indices, attribute ns/name indices and rawValue are u32/i32
    -- the old AOSP docs that show u16 here are stale.
  * string-pool UTF-8 strings carry TWO length prefixes (char count, byte
    count), each 1-2 bytes with the high-bit-continuation scheme.
  * Res_value for attributes: u16 size (=8), u8 res0, u8 dataType, u32 data.
    TYPE_STRING (0x03) data = string-pool index; TYPE_INT_BOOLEAN (0x12)
    data is nonzero for true.
"""
import struct

# chunk types
RES_NULL_TYPE = 0x0000
RES_STRING_POOL_TYPE = 0x0001
RES_TABLE_TYPE = 0x0002
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
RES_XML_RESOURCE_MAP_TYPE = 0x0180

UTF8_FLAG = 1 << 8

# Res_value data types
TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

ANDROID_NS = "http://schemas.android.com/apk/res/android"


class AxmlError(Exception):
    pass


def _u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def _i32(b, o):
    return struct.unpack_from("<i", b, o)[0]


def _chunk(data, off):
    ctype, hsize, size = struct.unpack_from("<HHI", data, off)
    return ctype, hsize, size


def _utf8_len(data, off):
    """1-or-2-byte length prefix used by UTF-8 string-pool entries."""
    b0 = data[off]
    if b0 & 0x80:
        return ((b0 & 0x7F) << 8) | data[off + 1], 2
    return b0, 1


def parse_string_pool(data, off):
    """Parse a string-pool chunk at off. Returns [str]."""
    ctype, hsize, size = _chunk(data, off)
    if ctype != RES_STRING_POOL_TYPE:
        raise AxmlError("not a string pool at %#x" % off)
    scount, stcount, flags = struct.unpack_from("<III", data, off + 8)
    strings_start, styles_start = struct.unpack_from("<II", data, off + 20)
    utf8 = bool(flags & UTF8_FLAG)
    offsets = [_u32(data, off + 28 + 4 * i) for i in range(scount)]
    base = off + strings_start
    out = []
    for so in offsets:
        p = base + so
        if utf8:
            clen, n = _utf8_len(data, p)
            blen, m = _utf8_len(data, p + n)
            raw = data[p + n + m:p + n + m + blen]
            out.append(raw.decode("utf-8", errors="replace"))
        else:
            clen = _u16(data, p)
            n = 2
            if clen & 0x8000:      # extended length
                clen = ((clen & 0x7FFF) << 16) | _u16(data, p + 2)
                n = 4
            raw = data[p + n:p + n + 2 * clen]
            out.append(raw.decode("utf-16-le", errors="replace"))
    return out


def _attr_value(pool, raw_value, dtype, dval):
    if dtype == TYPE_STRING:
        if 0 <= dval < len(pool):
            return pool[dval]
        return ""
    if dtype == TYPE_INT_BOOLEAN:
        return "true" if dval != 0 else "false"
    if dtype == TYPE_INT_DEC:
        return str(_i32(struct.pack("<I", dval), 0))
    if dtype == TYPE_INT_HEX:
        return hex(dval)
    if raw_value not in (0xFFFFFFFF, -1) and 0 <= raw_value < len(pool):
        return pool[raw_value]
    return "@%08x" % dval


def parse_axml(data):
    """Parse a binary AndroidManifest.xml.

    Returns a dict: package, permissions [...], components [...],
    application_attrs {...}. Each component: kind, name, exported
    (True/False/None), intent_filters (count)."""
    ctype, hsize, size = _chunk(data, 0)
    if ctype != RES_XML_TYPE:
        raise AxmlError("not a binary XML document (type %#x)" % ctype)

    pool = []
    ns_stack = []          # [(prefix, uri)]
    el_stack = []          # [element dict]
    manifest = {
        "package": None,
        "permissions": [],
        "components": [],
        "application_attrs": {},
    }

    def pool_str(i):
        return pool[i] if 0 <= i < len(pool) else ""

    off = 8
    while off < size:
        ctype, hsize, csize = _chunk(data, off)
        if csize < 8:
            raise AxmlError("bad chunk size at %#x" % off)
        if ctype == RES_STRING_POOL_TYPE:
            pool = parse_string_pool(data, off)
        elif ctype == RES_XML_RESOURCE_MAP_TYPE:
            pass  # array of u32 resource ids; not needed for triage
        elif ctype in (RES_XML_START_NAMESPACE_TYPE,
                       RES_XML_END_NAMESPACE_TYPE):
            prefix = pool_str(_i32(data, off + 16))
            uri = pool_str(_i32(data, off + 20))
            if ctype == RES_XML_START_NAMESPACE_TYPE:
                ns_stack.append((prefix, uri))
            elif ns_stack:
                ns_stack.pop()
        elif ctype == RES_XML_START_ELEMENT_TYPE:
            ns_i = _i32(data, off + 16)
            name = pool_str(_i32(data, off + 20))
            # attrExt starts right after the 16-byte node header
            ax = off + 16
            a_start = _u16(data, ax + 8)
            a_size = _u16(data, ax + 10)
            a_count = _u16(data, ax + 12)
            attrs = {}
            abase = ax + a_start
            for i in range(a_count):
                ao = abase + i * a_size
                ans_i = _i32(data, ao)
                aname = pool_str(_i32(data, ao + 4))
                raw_v = _i32(data, ao + 8)
                dtype = data[ao + 15]
                dval = _u32(data, ao + 16)
                ans_uri = pool_str(ans_i) if ans_i >= 0 else None
                val = _attr_value(pool, raw_v, dtype, dval)
                attrs[(ans_uri, aname)] = val
                # also index by bare local name for convenience
                attrs.setdefault((None, aname), val)

            def attr(local, uri=ANDROID_NS):
                return attrs.get((uri, local), attrs.get((None, local)))

            el = {"name": name, "attrs": attrs, "intent_filters": 0,
                  "children": []}
            if el_stack:
                parent = el_stack[-1]
                parent["children"].append(el)
                if name == "intent-filter":
                    # bubble up: mark ancestor component
                    for anc in reversed(el_stack):
                        if anc["name"] in ("activity", "service",
                                           "receiver", "provider"):
                            anc["intent_filters"] += 1
                            break
            el_stack.append(el)

            if name == "uses-permission":
                perm = attr("name")
                if perm:
                    manifest["permissions"].append(perm)
            elif name == "manifest":
                manifest["package"] = attr("package", uri=None)
            elif name == "application":
                manifest["application_attrs"] = {
                    k[1]: v for k, v in attrs.items() if k[0] is not None}
        elif ctype == RES_XML_END_ELEMENT_TYPE:
            if el_stack:
                el = el_stack.pop()
                if el["name"] in ("activity", "service", "receiver",
                                  "provider"):
                    def _attr(local, uri=ANDROID_NS, _a=el["attrs"]):
                        return _a.get((uri, local), _a.get((None, local)))
                    exp = _attr("exported")
                    manifest["components"].append({
                        "kind": el["name"],
                        "name": _attr("name"),
                        "exported": (exp == "true" if exp in
                                     ("true", "false") else None),
                        "intent_filters": el["intent_filters"],
                    })
        off += csize
    return manifest
