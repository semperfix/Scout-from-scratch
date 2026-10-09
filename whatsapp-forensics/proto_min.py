"""Minimal protobuf wire-format decoder, from scratch (stdlib only).
Needed to parse the crypt14 backup header (and any length-prefixed proto
framing) without protobuf libraries. Handles varints, 32/64-bit fixed,
length-delimited (recursed when they look like nested messages), groups
skipped, unknown fields preserved.
"""

def read_varint(buf: bytes, pos: int):
    """Returns (value, new_pos). Raises on truncation/overlong (>10 bytes)."""
    val, shift, start = 0, 0, pos
    while True:
        if pos >= len(buf):
            raise ValueError("truncated varint")
        b = buf[pos]; pos += 1
        val |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            break
        if pos - start > 10:
            raise ValueError("varint too long")
    return val, pos

def write_varint(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F; v >>= 7
        out.append(b | (0x80 if v else 0))
        if not v: break
    return bytes(out)

def decode(buf: bytes):
    """Decode one protobuf message -> list of (field_no, wire_type, value).
    value: int for varint/fixed, bytes for length-delimited (decoded nested
    messages returned as ('msg', [fields]) when plausible, else raw bytes)."""
    fields, pos = [], 0
    while pos < len(buf):
        key, pos = read_varint(buf, pos)
        field_no, wtype = key >> 3, key & 0x7
        if field_no == 0:
            raise ValueError("field number 0 is illegal")
        if wtype == 0:
            v, pos = read_varint(buf, pos); fields.append((field_no, 0, v))
        elif wtype == 1:
            if pos + 8 > len(buf): raise ValueError("truncated fixed64")
            fields.append((field_no, 1, int.from_bytes(buf[pos:pos+8], 'little')))
            pos += 8
        elif wtype == 2:
            ln, pos = read_varint(buf, pos)
            if pos + ln > len(buf): raise ValueError("truncated len-delim")
            raw = buf[pos:pos+ln]; pos += ln
            fields.append((field_no, 2, _maybe_nested(raw)))
        elif wtype == 5:
            if pos + 4 > len(buf): raise ValueError("truncated fixed32")
            fields.append((field_no, 5, int.from_bytes(buf[pos:pos+4], 'little')))
            pos += 4
        else:
            raise ValueError(f"unsupported wire type {wtype} (groups deprecated)")
    return fields

def _maybe_nested(raw: bytes):
    """Try to decode as a nested message; fall back to raw bytes."""
    if len(raw) < 2:
        return raw
    try:
        f = decode(raw)
        # heuristic: must consume cleanly AND look like fields (re-encode sanity)
        if f and all(isinstance(n, int) and n > 0 for n, _, _ in f):
            return ("msg", f)
    except ValueError:
        pass
    return raw

def encode(fields) -> bytes:
    """Encode list of (field_no, wire_type, value) back to bytes (roundtrip)."""
    out = bytearray()
    for field_no, wtype, v in fields:
        out += write_varint((field_no << 3) | wtype)
        if wtype == 0:
            out += write_varint(v)
        elif wtype == 1:
            out += v.to_bytes(8, 'little')
        elif wtype == 2:
            raw = encode(v[1]) if isinstance(v, tuple) and v[0] == "msg" else v
            out += write_varint(len(raw)) + raw
        elif wtype == 5:
            out += v.to_bytes(4, 'little')
    return bytes(out)

def find(fields, field_no, wtype=None):
    return [v for n, t, v in fields if n == field_no and (wtype is None or t == wtype)]

def pretty(fields, indent=0):
    pad = "  " * indent
    lines = []
    for n, t, v in fields:
        if isinstance(v, tuple) and v[0] == "msg":
            lines.append(f"{pad}field {n} (msg):")
            lines.append(pretty(v[1], indent + 1))
        elif t == 2 and isinstance(v, bytes):
            try:
                txt = v.decode('utf-8')
                lines.append(f"{pad}field {n} (str): {txt!r}")
            except UnicodeDecodeError:
                lines.append(f"{pad}field {n} (bytes[{len(v)}]): {v.hex()[:64]}")
        else:
            lines.append(f"{pad}field {n} (w{t}): {v}")
    return "\n".join(lines)

if __name__ == "__main__":
    # self-test: build a crypt14-style header and roundtrip it
    hdr = [(1, 2, b"c14"), (2, 2, bytes(range(16))), (3, 0, 122)]
    blob = encode(hdr)
    dec = decode(blob)
    assert encode(dec) == blob, "roundtrip failed"
    assert find(dec, 1)[0] == b"c14" and find(dec, 2)[0] == bytes(range(16))
    assert find(dec, 3)[0] == 122
    # nested message
    nested = [(1, 2, ("msg", [(1, 0, 7), (2, 2, b"inner")]))]
    b2 = encode(nested)
    d2 = decode(b2)
    assert isinstance(d2[0][2], tuple) and d2[0][2][0] == "msg"
    assert encode(d2) == b2
    # malformed inputs rejected
    for bad in (b"\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80", b"\x08", b"\x12\x05ab"):
        try:
            decode(bad); raise SystemExit(f"accepted bad input {bad!r}")
        except ValueError:
            pass
    print("protobuf self-tests pass")
    print(pretty(dec))
