#!/usr/bin/env python3
"""Parser-level self-tests: codec round-trips, alternate-implementation
cross-check of dense-node decoding, header assertions."""

import sys

sys.path.insert(0, ".")
from pbf import (read_varint, zigzag_decode, parse_message, iter_blocks,
                 PBFReader, PBFError)  # noqa: E402


def enc_varint(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def enc_zigzag(v):
    return (v << 1) ^ (v >> 63)


# 1. varint round-trips incl. boundaries
for v in [0, 1, 127, 128, 300, 2**32 - 1, 2**63 - 1, 2**64 - 1]:
    got, pos = read_varint(enc_varint(v), 0)
    assert got == v and pos == len(enc_varint(v)), v
print("1. varint round-trip OK")

# 2. zigzag round-trips
for v in [0, 1, -1, -2, 2**31 - 1, -(2**31), 10**12, -(10**12)]:
    assert zigzag_decode(enc_zigzag(v)) == v, v
print("2. zigzag round-trip OK")

# 3. alternate dense-node decode cross-check on first data block
#    (independent code path: raw key loop, manual delta accumulation)
def alt_decode_dense(payload):
    blk = parse_message(payload)
    gran = blk.get_varint(17, 100)
    lato, lono = blk.get_varint(19, 0), blk.get_varint(20, 0)
    stab = [s for s in parse_message(blk.get(1)).get_all(1)]
    out = []
    for graw in blk.get_all(2):
        gmsg = parse_message(graw)
        drawn = gmsg.get(2)
        if drawn is None:
            continue
        dn = parse_message(drawn)
        def packed(b):
            r, p = [], 0
            while p < len(b):
                v, p = read_varint(b, p)
                r.append(v)
            return r
        ids, lats, lons = packed(dn.get(1, b"")), packed(dn.get(8, b"")), packed(dn.get(9, b""))
        ci = clat = clon = 0
        for i in range(len(ids)):
            ci += zigzag_decode(ids[i]); clat += zigzag_decode(lats[i]); clon += zigzag_decode(lons[i])
            out.append((ci, (lato + gran * clat) * 1e-9, (lono + gran * clon) * 1e-9))
    return out

got_main, got_alt = [], []
r = PBFReader()
for btype, payload in iter_blocks("georgia.osm.pbf"):
    if btype != "OSMData":
        continue
    r.decode_primitive_block(payload, node_cb=lambda n: got_main.append(
        (n["id"], n["lat"], n["lon"])))
    got_alt = alt_decode_dense(payload)
    break
assert len(got_main) == len(got_alt) > 0, (len(got_main), len(got_alt))
for m, a in zip(got_main, got_alt):
    assert m[0] == a[0] and abs(m[1] - a[1]) < 1e-12 and abs(m[2] - a[2]) < 1e-12
print(f"3. dense-node cross-check OK ({len(got_main)} nodes, two code paths agree)")

# 4. header assertions
for btype, payload in iter_blocks("georgia.osm.pbf"):
    if btype == "OSMHeader":
        r2 = PBFReader()
        r2.parse_header_block(payload)
        assert "OsmSchema-V0.6" in r2.header["required_features"]
        assert "DenseNodes" in r2.header["required_features"]
        assert r2.header["writingprogram"].startswith("osmium")
        print("4. header assertions OK:", r2.header["required_features"])
        break

# 5. malformed input is rejected, not silently accepted
try:
    parse_message(b"\x0a\xff")  # length-delimited field claiming 127 bytes
    raise SystemExit("5. FAIL: truncated field accepted")
except PBFError:
    print("5. truncation rejection OK")

print("ALL PARSER TESTS PASSED")
