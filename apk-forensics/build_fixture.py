#!/usr/bin/env python3
"""build_fixture.py -- build fake APK fixtures for testing the hand-rolled
parsers. FIXTURE ONLY: stdlib `zipfile` is used here purely as a convenient
ZIP *writer* so the test fixtures exist; zipread.py (the code under test)
never touches it.

Produces:
  fixtures/evil.apk  -- INTERNET+READ_SMS, exported activity w/ intent-filter,
                        DEX referencing DexClassLoader, Runtime.exec and a
                        hardcoded http:// URL + IP literal  => SUSPICIOUS
  fixtures/clean.apk -- no permissions, unexported activity, benign DEX
                        => CLEAN

The AndroidManifest.xml and classes.dex inside are NOT made with Android
tooling: the binary XML is assembled byte-by-byte in the aapt2 wire format
and the DEX is assembled from the header spec, so the parsers are validated
against independently-constructed bytes.
"""
import hashlib
import os
import struct
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
FIXDIR = os.path.join(HERE, "fixtures")

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Res_value data types
TYPE_STRING = 0x03
TYPE_INT_BOOLEAN = 0x12


def _enc_len(v):
    if v < 0x80:
        return bytes([v])
    return bytes([0x80 | (v >> 8), v & 0xFF])


def encode_uleb128(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


# --------------------------------------------------------------------------
# binary AXML builder
# --------------------------------------------------------------------------

class AxmlBuilder(object):
    def __init__(self):
        self.strings = []
        self._idx = {}

    def s(self, text):
        if text not in self._idx:
            self._idx[text] = len(self.strings)
            self.strings.append(text)
        return self._idx[text]

    def string_pool(self):
        n = len(self.strings)
        items, offsets, pos = [], [], 0
        for s in self.strings:
            b = s.encode("utf-8")
            it = _enc_len(len(s)) + _enc_len(len(b)) + b + b"\x00"
            items.append(it)
            offsets.append(pos)
            pos += len(it)
        body = struct.pack("<IIIII", n, 0, 1 << 8, 28 + 4 * n, 0)
        body += b"".join(struct.pack("<I", o) for o in offsets)
        body += b"".join(items)
        return struct.pack("<HHI", 0x0001, 28, 8 + len(body)) + body

    def ns(self, start, prefix, uri):
        ctype = 0x0100 if start else 0x0101
        return (struct.pack("<HHI", ctype, 24, 24) +
                struct.pack("<II", 0, 0) +
                struct.pack("<II", self.s(prefix), self.s(uri)))

    def start_el(self, name, attrs=()):
        """attrs: [(ns_uri_or_None, attr_name, dtype, data_u32, raw_str_or_None)]"""
        abody = b""
        for ns_uri, aname, dtype, dval, raw in attrs:
            ns_i = self.s(ns_uri) if ns_uri else -1
            raw_i = self.s(raw) if raw is not None else -1
            abody += struct.pack("<iii", ns_i, self.s(aname), raw_i)
            abody += struct.pack("<HBBI", 8, 0, dtype, dval)
        attr_ext = struct.pack("<iiHHHHHH", -1, self.s(name),
                               20, 20, len(attrs), 0xFFFF, 0xFFFF, 0xFFFF)
        return (struct.pack("<HHI", 0x0102, 36, 36 + len(abody)) +
                struct.pack("<II", 0, 0) + attr_ext + abody)

    def end_el(self, name):
        return (struct.pack("<HHI", 0x0103, 24, 24) +
                struct.pack("<II", 0, 0) +
                struct.pack("<ii", -1, self.s(name)))

    def res_map(self, ids):
        body = b"".join(struct.pack("<I", i) for i in ids)
        return struct.pack("<HHI", 0x0180, 8, 8 + len(body)) + body

    def document(self, chunks):
        body = self.string_pool() + b"".join(chunks)
        return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


def _str_attr(b, ns_uri, name, value):
    b.s(value)  # intern
    return (ns_uri, name, TYPE_STRING, b.s(value), value)


def build_manifest(package, permissions, app_label, activities):
    """activities: [(name, exported_bool, with_intent_filter)]"""
    b = AxmlBuilder()
    chunks = [b.ns(True, "android", ANDROID_NS)]
    mattrs = [(None, "package", TYPE_STRING, b.s(package), package)]
    chunks.append(b.start_el("manifest", mattrs))
    for perm in permissions:
        chunks.append(b.start_el("uses-permission",
                                 [_str_attr(b, ANDROID_NS, "name", perm)]))
        chunks.append(b.end_el("uses-permission"))
    chunks.append(b.start_el("application",
                             [_str_attr(b, ANDROID_NS, "label", app_label)]))
    for name, exported, intent_filter in activities:
        aattrs = [_str_attr(b, ANDROID_NS, "name", name),
                  (ANDROID_NS, "exported", TYPE_INT_BOOLEAN,
                   0xFFFFFFFF if exported else 0, None)]
        chunks.append(b.start_el("activity", aattrs))
        if intent_filter:
            chunks.append(b.start_el("intent-filter"))
            chunks.append(b.start_el(
                "action", [_str_attr(b, ANDROID_NS, "name",
                                     "android.intent.action.MAIN")]))
            chunks.append(b.end_el("action"))
            chunks.append(b.start_el(
                "category", [_str_attr(b, ANDROID_NS, "name",
                                       "android.intent.category.LAUNCHER")]))
            chunks.append(b.end_el("category"))
            chunks.append(b.end_el("intent-filter"))
        chunks.append(b.end_el("activity"))
    chunks.append(b.end_el("application"))
    chunks.append(b.end_el("manifest"))
    chunks.append(b.ns(False, "android", ANDROID_NS))
    # resource map chunk: a few dummy ids, exercises the parser's skip path
    chunks.insert(1, b.res_map([0x01010000, 0x01010001, 0x01010002]))
    return b.document(chunks)


# --------------------------------------------------------------------------
# DEX builder
# --------------------------------------------------------------------------

def build_dex(strings, type_str_idxs, methods):
    """strings: [str]; type_str_idxs: [str_idx]; methods: [(type_idx, name_str_idx)]"""
    sdata = []
    for s in strings:
        b = s.encode("utf-8")
        sdata.append(encode_uleb128(len(s)) + b + b"\x00")

    off = 0x70
    string_ids_off = off
    off += 4 * len(strings)
    type_ids_off = off
    off += 4 * len(type_str_idxs)
    method_ids_off = off
    off += 8 * len(methods)
    map_off = off
    map_items = [
        (0x0000, 1, 0),
        (0x0001, len(strings), string_ids_off),
        (0x0002, len(type_str_idxs), type_ids_off),
        (0x0008, len(methods), method_ids_off),
        (0x2002, len(strings), None),   # string_data_item offsets filled below
    ]
    off += 4 + 12 * len(map_items)
    sdata_off = off
    sdata_offsets = []
    for sd in sdata:
        sdata_offsets.append(off)
        off += len(sd)
    file_size = off
    map_items[4] = (0x2002, len(strings), sdata_off)

    buf = bytearray(file_size)
    for i, so in enumerate(sdata_offsets):
        struct.pack_into("<I", buf, string_ids_off + 4 * i, so)
    for i, si in enumerate(type_str_idxs):
        struct.pack_into("<I", buf, type_ids_off + 4 * i, si)
    for i, (ti, ni) in enumerate(methods):
        struct.pack_into("<HHI", buf, method_ids_off + 8 * i, ti, 0, ni)
    struct.pack_into("<I", buf, map_off, len(map_items))
    for i, (t, sz, mo) in enumerate(map_items):
        struct.pack_into("<HHII", buf, map_off + 4 + 12 * i, t, 0, sz, mo)
    for so, sd in zip(sdata_offsets, sdata):
        buf[so:so + len(sd)] = sd

    # header
    buf[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", buf, 32, file_size)
    struct.pack_into("<I", buf, 36, 0x70)
    struct.pack_into("<I", buf, 40, 0x12345678)
    struct.pack_into("<I", buf, 52, map_off)
    struct.pack_into("<I", buf, 56, len(strings))
    struct.pack_into("<I", buf, 60, string_ids_off)
    struct.pack_into("<I", buf, 64, len(type_str_idxs))
    struct.pack_into("<I", buf, 68, type_ids_off)
    struct.pack_into("<I", buf, 88, len(methods))
    struct.pack_into("<I", buf, 92, method_ids_off)
    data_size = file_size - map_off
    struct.pack_into("<I", buf, 104, data_size)
    struct.pack_into("<I", buf, 108, map_off)
    # signature covers everything past the first 32 bytes
    buf[12:32] = hashlib.sha1(bytes(buf[32:])).digest()
    # adler32 covers everything past the first 12 bytes
    struct.pack_into("<I", buf, 8, zlib.adler32(bytes(buf[12:])) & 0xFFFFFFFF)
    return bytes(buf)


# --------------------------------------------------------------------------
# APK assembly (stdlib zipfile = fixture writer only)
# --------------------------------------------------------------------------

EVIL_STRINGS = [
    "Lcom/evil/Flashlight;",
    "Lcom/evil/Loader;",
    "Ldalvik/system/DexClassLoader;",
    "Ljava/lang/Runtime;",
    "Ljavax/crypto/Cipher;",
    "Landroid/telephony/SmsManager;",
    "main",
    "onCreate",
    "exec",
    "loadDex",
    "http://evil.example.com/collect",
    "45.155.204.9",
]
EVIL_TYPES = [0, 1, 2, 3, 4, 5]
EVIL_METHODS = [(1, 9), (3, 8), (0, 7), (0, 6)]   # Loader.loadDex, Runtime.exec, ...

CLEAN_STRINGS = [
    "Lcom/clean/Flashlight;",
    "main",
    "onCreate",
]
CLEAN_TYPES = [0]
CLEAN_METHODS = [(0, 1), (0, 2)]


def write_apk(path, manifest_bytes, dex_bytes, arsc_bytes):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("AndroidManifest.xml", manifest_bytes,
                   compress_type=zipfile.ZIP_DEFLATED)
        z.writestr("classes.dex", dex_bytes,
                   compress_type=zipfile.ZIP_STORED)
        z.writestr("resources.arsc", arsc_bytes,
                   compress_type=zipfile.ZIP_DEFLATED)
        z.writestr("res/layout/main.xml", b"<dummy/>",
                   compress_type=zipfile.ZIP_DEFLATED)


def main():
    os.makedirs(FIXDIR, exist_ok=True)
    evil_manifest = build_manifest(
        "com.evil.flashlight",
        ["android.permission.INTERNET", "android.permission.READ_SMS"],
        "Fake Flashlight",
        [(".MainActivity", True, True)])
    evil_dex = build_dex(EVIL_STRINGS, EVIL_TYPES, EVIL_METHODS)
    write_apk(os.path.join(FIXDIR, "evil.apk"), evil_manifest, evil_dex,
              b"ARSC" + b"\x00" * 64)

    clean_manifest = build_manifest(
        "com.clean.flashlight", [], "Clean Flashlight",
        [(".MainActivity", False, False)])
    clean_dex = build_dex(CLEAN_STRINGS, CLEAN_TYPES, CLEAN_METHODS)
    write_apk(os.path.join(FIXDIR, "clean.apk"), clean_manifest, clean_dex,
              b"ARSC" + b"\x00" * 64)
    print("wrote fixtures to", FIXDIR)


if __name__ == "__main__":
    main()
