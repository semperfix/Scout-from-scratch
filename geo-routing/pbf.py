#!/usr/bin/env python3
"""Hand-rolled OSM PBF parser. Zero protobuf dependencies.

Implements the full PBF container format from scratch:
  - FileBlock framing: 4-byte big-endian header length, BlobHeader protobuf,
    then Blob protobuf carrying zlib-compressed payload
  - Minimal protobuf codec: varint, zigzag sint, fixed32/64, length-delimited,
    packed repeated fields
  - OSMHeader block: bbox, required_features, writing program
  - OSMData PrimitiveBlock: stringtable, granularity/lat_offset/lon_offset,
    DenseNodes (delta-coded ids + delta-coded lat/lon), Ways (delta-coded refs),
    Relations (skipped)

Coordinate formula (per PBF spec):
    deg = (lat_offset + granularity * value) * 1e-9
"""

import struct
import zlib

NANO = 1e-9


class PBFError(Exception):
    pass


# ---------------------------------------------------------------- protobuf
def read_varint(buf, pos):
    """Read an unsigned varint; return (value, new_pos)."""
    result = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise PBFError("truncated varint")
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift >= 64:
            raise PBFError("varint too long")


def zigzag_decode(v):
    return (v >> 1) ^ -(v & 1)


class Message:
    """Parsed protobuf message: field_number -> list of (wire_type, value).

    wire_type 0 -> int, 1 -> 8 raw bytes, 2 -> bytes, 5 -> 4 raw bytes.
    """

    def __init__(self):
        self.fields = {}

    def add(self, num, wtype, value):
        self.fields.setdefault(num, []).append((wtype, value))

    def get(self, num, default=None):
        lst = self.fields.get(num)
        return lst[0][1] if lst else default

    def get_all(self, num):
        return [v for _, v in self.fields.get(num, [])]

    def get_varint(self, num, default=0):
        v = self.get(num, None)
        return v if v is not None else default

    def has(self, num):
        return num in self.fields


def parse_message(buf, end=None):
    if end is None:
        end = len(buf)
    msg = Message()
    pos = 0
    while pos < end:
        key, pos = read_varint(buf, pos)
        num, wtype = key >> 3, key & 0x7
        if wtype == 0:
            v, pos = read_varint(buf, pos)
            msg.add(num, wtype, v)
        elif wtype == 1:
            if pos + 8 > end:
                raise PBFError("truncated fixed64")
            msg.add(num, wtype, buf[pos:pos + 8])
            pos += 8
        elif wtype == 2:
            ln, pos = read_varint(buf, pos)
            if pos + ln > end:
                raise PBFError("truncated length-delimited field")
            msg.add(num, wtype, buf[pos:pos + ln])
            pos += ln
        elif wtype == 5:
            if pos + 4 > end:
                raise PBFError("truncated fixed32")
            msg.add(num, wtype, buf[pos:pos + 4])
            pos += 4
        else:
            raise PBFError(f"unsupported wire type {wtype} for field {num}")
    return msg


def packed_varints(buf):
    """Decode a packed repeated varint field."""
    out = []
    pos = 0
    while pos < len(buf):
        v, pos = read_varint(buf, pos)
        out.append(v)
    return out


# ---------------------------------------------------------------- FileBlock
def iter_blocks(path):
    """Yield (block_type, payload_bytes) for each FileBlock in the file."""
    with open(path, "rb") as f:
        while True:
            hdr_len_raw = f.read(4)
            if not hdr_len_raw:
                return
            if len(hdr_len_raw) < 4:
                raise PBFError("truncated fileblock header length")
            (hdr_len,) = struct.unpack(">I", hdr_len_raw)
            header = parse_message(f.read(hdr_len))
            btype = header.get(1).decode("utf-8")
            datasize = header.get_varint(3)  # BlobHeader.datasize = field 3
            _indexdata = header.get(2)  # optional, unused
            blob = parse_message(f.read(datasize))
            if blob.has(3):      # zlib_data
                payload = zlib.decompress(blob.get(3))
            elif blob.has(1):    # raw
                payload = blob.get(1)
                if blob.get_varint(2, len(payload)) != len(payload):
                    raise PBFError("raw blob size mismatch")
            elif blob.has(4):    # lzma_data
                import lzma
                payload = lzma.decompress(blob.get(4))
            else:
                raise PBFError("blob has no supported data field")
            yield btype, payload


# ---------------------------------------------------------------- OSM decode
class PBFReader:
    def __init__(self):
        self.header = {}
        self.n_nodes = 0
        self.n_ways = 0
        self.n_relations = 0

    def parse_header_block(self, payload):
        msg = parse_message(payload)
        self.header["required_features"] = [b.decode() for b in msg.get_all(4)]
        self.header["optional_features"] = [b.decode() for b in msg.get_all(5)]
        self.header["writingprogram"] = msg.get(16, b"").decode("utf-8", "replace")
        self.header["source"] = msg.get(17, b"").decode("utf-8", "replace")
        bbox = msg.get(1)
        if bbox is not None:
            bb = parse_message(bbox)
            # HeaderBBox: 1=left(*1e-9 deg), 2=right, 3=top, 4=bottom
            self.header["bbox"] = (
                bb.get_varint(4) * NANO, bb.get_varint(3) * NANO,
                bb.get_varint(1) * NANO, bb.get_varint(2) * NANO,
            )

    def decode_primitive_block(self, payload, node_cb=None, way_cb=None,
                               rel_cb=None):
        """Stream-decode one OSMData block. Callbacks receive dicts."""
        blk = parse_message(payload)
        granularity = blk.get_varint(17, 100)
        lat_offset = blk.get_varint(19, 0)
        lon_offset = blk.get_varint(20, 0)
        stab_raw = blk.get(1)
        if stab_raw is None:
            raise PBFError("primitive block without stringtable")
        stab_msg = parse_message(stab_raw)
        stab = [s for s in stab_msg.get_all(1)]

        def coord(off, gran, v):
            return (off + gran * v) * NANO

        for grp_raw in blk.get_all(2):
            grp = parse_message(grp_raw)

            for n_raw in grp.get_all(1):          # non-dense nodes (rare)
                n = parse_message(n_raw)
                self.n_nodes += 1
                if node_cb:
                    keys = packed_varints(n.get(2, b""))
                    vals = packed_varints(n.get(3, b""))
                    node_cb({
                        "id": n.get_varint(1),
                        "lat": coord(lat_offset, granularity,
                                     zigzag_decode(n.get_varint(8))),
                        "lon": coord(lon_offset, granularity,
                                     zigzag_decode(n.get_varint(9))),
                        "tags": {stab[k].decode("utf-8", "replace"):
                                 stab[v].decode("utf-8", "replace")
                                 for k, v in zip(keys, vals)},
                    })

            dn_raw = grp.get(2)                   # DenseNodes
            if dn_raw is not None and node_cb:
                dn = parse_message(dn_raw)
                ids = packed_varints(dn.get(1, b""))
                lats = packed_varints(dn.get(8, b""))
                lons = packed_varints(dn.get(9, b""))
                kvs = packed_varints(dn.get(10, b""))
                cur_id = cur_lat = cur_lon = 0
                kv_pos = 0
                for i in range(len(ids)):
                    cur_id += zigzag_decode(ids[i])
                    cur_lat += zigzag_decode(lats[i])
                    cur_lon += zigzag_decode(lons[i])
                    tags = {}
                    while kv_pos < len(kvs) and kvs[kv_pos] != 0:
                        k = kvs[kv_pos]
                        v = kvs[kv_pos + 1]
                        tags[stab[k].decode("utf-8", "replace")] = \
                            stab[v].decode("utf-8", "replace")
                        kv_pos += 2
                    kv_pos += 1  # skip the 0 delimiter
                    self.n_nodes += 1
                    node_cb({
                        "id": cur_id,
                        "lat": coord(lat_offset, granularity, cur_lat),
                        "lon": coord(lon_offset, granularity, cur_lon),
                        "tags": tags,
                    })

            for w_raw in grp.get_all(3):          # Ways
                w = parse_message(w_raw)
                keys = packed_varints(w.get(2, b""))
                vals = packed_varints(w.get(3, b""))
                refs = packed_varints(w.get(8, b""))
                cur = 0
                node_ids = []
                for r in refs:
                    cur += zigzag_decode(r)
                    node_ids.append(cur)
                self.n_ways += 1
                if way_cb:
                    way_cb({
                        "id": w.get_varint(1),
                        "refs": node_ids,
                        "tags": {stab[k].decode("utf-8", "replace"):
                                 stab[v].decode("utf-8", "replace")
                                 for k, v in zip(keys, vals)},
                    })

            for r_raw in grp.get_all(4):          # Relations: count only
                self.n_relations += 1
                if rel_cb:
                    r = parse_message(r_raw)
                    rel_cb({"id": r.get_varint(1)})

    def stream(self, path, node_cb=None, way_cb=None, rel_cb=None):
        """Full-file streaming decode."""
        self.header = {}
        self.n_nodes = self.n_ways = self.n_relations = 0
        for btype, payload in iter_blocks(path):
            if btype == "OSMHeader":
                self.parse_header_block(payload)
            elif btype == "OSMData":
                self.decode_primitive_block(payload, node_cb, way_cb, rel_cb)
            else:
                raise PBFError(f"unknown block type {btype!r}")
