#!/usr/bin/env python3
"""HPACK: Header Compression for HTTP/2 (RFC 7541), from scratch, stdlib only.

Implements:
  - Section 5.1: integer representation with N-bit prefix
  - Section 5.2: string literals, raw or Huffman-coded
  - Appendix A: the 61-entry static table
  - Section 2.3.2 / 4: dynamic table with size accounting and FIFO eviction
  - Section 6: all five header-field representations
    (indexed; literal with incremental indexing / without indexing /
     never-indexed; dynamic table size update)
  - Encoder (with Huffman selection, dynamic-table indexing, never-indexed
    sensitive fields) and Decoder (with strict padding/EOS validation).

The Huffman code table below is the fixed table from RFC 7541 Appendix B.
Code Components extracted from IETF documents are provided under the
Simplified BSD License per the IETF Trust Legal Provisions (RFC 7541,
"Copyright Notice").

No third-party code is used here; the table was transcribed from the RFC
and is verified by test_http2.py via (a) the Kraft equality, (b) the
canonical-code sequentiality property, (c) all Appendix C decode vectors,
and (d) differential tests against the independent `hpack` package.
"""

# ---------------------------------------------------------------------------
# Section 5.1: integer representation
# ---------------------------------------------------------------------------

def encode_int(value: int, prefix_bits: int) -> bytes:
    """Encode `value` with an N-bit prefix. The caller ORs the representation
    pattern (e.g. 0x80 for indexed fields) into the first byte."""
    if value < 0:
        raise ValueError('HPACK integer must be non-negative')
    limit = (1 << prefix_bits) - 1
    if value < limit:
        return bytes([value])
    out = bytearray([limit])
    value -= limit
    while value >= 128:
        out.append((value & 0x7f) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def decode_int(buf: bytes, pos: int, prefix_bits: int):
    """Decode an integer; returns (value, new_pos)."""
    if pos >= len(buf):
        raise HPACKError('truncated integer')
    limit = (1 << prefix_bits) - 1
    value = buf[pos] & limit
    pos += 1
    if value < limit:
        return value, pos
    shift = 0
    while True:
        if pos >= len(buf):
            raise HPACKError('truncated integer continuation')
        b = buf[pos]
        pos += 1
        value += (b & 0x7f) << shift
        shift += 7
        if not b & 0x80:
            break
        if shift > 63:
            raise HPACKError('integer overflow')
    return value, pos


class HPACKError(Exception):
    pass


# ---------------------------------------------------------------------------
# Section 5.2 / Appendix B: Huffman codec
# ---------------------------------------------------------------------------
# Transcribed from RFC 7541 Appendix B: "sym:code_hex:nbits", symbols 0-255
# in order, then EOS as symbol 256. code_hex is the code aligned to the LSB.

_HUFFMAN_SRC = """
0:1ff8:13 1:7fffd8:23 2:fffffe2:28 3:fffffe3:28 4:fffffe4:28 5:fffffe5:28
6:fffffe6:28 7:fffffe7:28 8:fffffe8:28 9:ffffea:24 10:3ffffffc:30
11:fffffe9:28 12:fffffea:28 13:3ffffffd:30 14:fffffeb:28 15:fffffec:28
16:fffffed:28 17:fffffee:28 18:fffffef:28 19:ffffff0:28 20:ffffff1:28
21:ffffff2:28 22:3ffffffe:30 23:ffffff3:28 24:ffffff4:28 25:ffffff5:28
26:ffffff6:28 27:ffffff7:28 28:ffffff8:28 29:ffffff9:28 30:ffffffa:28
31:ffffffb:28 32:14:6 33:3f8:10 34:3f9:10 35:ffa:12 36:1ff9:13 37:15:6
38:f8:8 39:7fa:11 40:3fa:10 41:3fb:10 42:f9:8 43:7fb:11 44:fa:8 45:16:6
46:17:6 47:18:6 48:0:5 49:1:5 50:2:5 51:19:6 52:1a:6 53:1b:6 54:1c:6
55:1d:6 56:1e:6 57:1f:6 58:5c:7 59:fb:8 60:7ffc:15 61:20:6 62:ffb:12
63:3fc:10 64:1ffa:13 65:21:6 66:5d:7 67:5e:7 68:5f:7 69:60:7 70:61:7
71:62:7 72:63:7 73:64:7 74:65:7 75:66:7 76:67:7 77:68:7 78:69:7 79:6a:7
80:6b:7 81:6c:7 82:6d:7 83:6e:7 84:6f:7 85:70:7 86:71:7 87:72:7 88:fc:8
89:73:7 90:fd:8 91:1ffb:13 92:7fff0:19 93:1ffc:13 94:3ffc:14 95:22:6
96:7ffd:15 97:3:5 98:23:6 99:4:5 100:24:6 101:5:5 102:25:6 103:26:6
104:27:6 105:6:5 106:74:7 107:75:7 108:28:6 109:29:6 110:2a:6 111:7:5
112:2b:6 113:76:7 114:2c:6 115:8:5 116:9:5 117:2d:6 118:77:7 119:78:7
120:79:7 121:7a:7 122:7b:7 123:7ffe:15 124:7fc:11 125:3ffd:14 126:1ffd:13
127:ffffffc:28 128:fffe6:20 129:3fffd2:22 130:fffe7:20 131:fffe8:20
132:3fffd3:22 133:3fffd4:22 134:3fffd5:22 135:7fffd9:23 136:3fffd6:22
137:7fffda:23 138:7fffdb:23 139:7fffdc:23 140:7fffdd:23 141:7fffde:23
142:ffffeb:24 143:7fffdf:23 144:ffffec:24 145:ffffed:24 146:3fffd7:22
147:7fffe0:23 148:ffffee:24 149:7fffe1:23 150:7fffe2:23 151:7fffe3:23
152:7fffe4:23 153:1fffdc:21 154:3fffd8:22 155:7fffe5:23 156:3fffd9:22
157:7fffe6:23 158:7fffe7:23 159:ffffef:24 160:3fffda:22 161:1fffdd:21
162:fffe9:20 163:3fffdb:22 164:3fffdc:22 165:7fffe8:23 166:7fffe9:23
167:1fffde:21 168:7fffea:23 169:3fffdd:22 170:3fffde:22 171:fffff0:24
172:1fffdf:21 173:3fffdf:22 174:7fffeb:23 175:7fffec:23 176:1fffe0:21
177:1fffe1:21 178:3fffe0:22 179:1fffe2:21 180:7fffed:23 181:3fffe1:22
182:7fffee:23 183:7fffef:23 184:fffea:20 185:3fffe2:22 186:3fffe3:22
187:3fffe4:22 188:7ffff0:23 189:3fffe5:22 190:3fffe6:22 191:7ffff1:23
192:3ffffe0:26 193:3ffffe1:26 194:fffeb:20 195:7fff1:19 196:3fffe7:22
197:7ffff2:23 198:3fffe8:22 199:1ffffec:25 200:3ffffe2:26 201:3ffffe3:26
202:3ffffe4:26 203:7ffffde:27 204:7ffffdf:27 205:3ffffe5:26 206:fffff1:24
207:1ffffed:25 208:7fff2:19 209:1fffe3:21 210:3ffffe6:26 211:7ffffe0:27
212:7ffffe1:27 213:3ffffe7:26 214:7ffffe2:27 215:fffff2:24 216:1fffe4:21
217:1fffe5:21 218:3ffffe8:26 219:3ffffe9:26 220:ffffffd:28 221:7ffffe3:27
222:7ffffe4:27 223:7ffffe5:27 224:fffec:20 225:fffff3:24 226:fffed:20
227:1fffe6:21 228:3fffe9:22 229:1fffe7:21 230:1fffe8:21 231:7ffff3:23
232:3fffea:22 233:3fffeb:22 234:1ffffee:25 235:1ffffef:25 236:fffff4:24
237:fffff5:24 238:3ffffea:26 239:7ffff4:23 240:3ffffeb:26 241:7ffffe6:27
242:3ffffec:26 243:3ffffed:26 244:7ffffe7:27 245:7ffffe8:27 246:7ffffe9:27
247:7ffffea:27 248:7ffffeb:27 249:ffffffe:28 250:7ffffec:27 251:7ffffed:27
252:7ffffee:27 253:7ffffef:27 254:7fffff0:27 255:3ffffee:26 256:3fffffff:30
"""

# symbol -> (code, nbits); symbol 256 is EOS
HUFFMAN_TABLE = {}
for _tok in _HUFFMAN_SRC.split():
    _s, _c, _n = _tok.split(':')
    HUFFMAN_TABLE[int(_s)] = (int(_c, 16), int(_n))
assert len(HUFFMAN_TABLE) == 257
EOS_SYMBOL = 256

# reverse map for decoding: (nbits, code) -> symbol
_HUFFMAN_REV = {(nbits, code): sym for sym, (code, nbits) in HUFFMAN_TABLE.items()}


def huffman_encode(data: bytes) -> bytes:
    """Huffman-encode octets per RFC 7541 5.2 (EOS-bit padding to octet)."""
    acc, nbits = 0, 0
    out = bytearray()
    for byte in data:
        code, n = HUFFMAN_TABLE[byte]
        acc = (acc << n) | code
        nbits += n
        while nbits >= 8:
            nbits -= 8
            out.append((acc >> nbits) & 0xff)
            acc &= (1 << nbits) - 1
    if nbits:
        # pad with the most significant bits of EOS (all ones)
        out.append(((acc << (8 - nbits)) | ((1 << (8 - nbits)) - 1)) & 0xff)
    return bytes(out)


def huffman_decode(data: bytes) -> bytes:
    """Huffman-decode; rejects EOS mid-string and bad padding (RFC 7541 5.2)."""
    out = bytearray()
    code, nbits = 0, 0
    for byte in data:
        for i in range(7, -1, -1):
            code = (code << 1) | ((byte >> i) & 1)
            nbits += 1
            sym = _HUFFMAN_REV.get((nbits, code))
            if sym is not None:
                if sym == EOS_SYMBOL:
                    raise HPACKError('EOS symbol inside Huffman string')
                out.append(sym)
                code, nbits = 0, 0
    if nbits:
        # leftover bits: must be the EOS prefix (all ones), at most 7 bits
        if nbits > 7 or code != (1 << nbits) - 1:
            raise HPACKError('invalid Huffman padding')
    return bytes(out)


# ---------------------------------------------------------------------------
# Section 5.2: string literals
# ---------------------------------------------------------------------------

def encode_string(data: bytes, huffman: bool) -> bytes:
    flag = 0x80 if huffman else 0x00
    payload = huffman_encode(data) if huffman else data
    first = encode_int(len(payload), 7)
    return bytes([first[0] | flag]) + first[1:] + payload


def decode_string(buf: bytes, pos: int):
    if pos >= len(buf):
        raise HPACKError('truncated string')
    huffman = bool(buf[pos] & 0x80)
    length, pos = decode_int(buf, pos, 7)
    if pos + length > len(buf):
        raise HPACKError('truncated string data')
    raw = buf[pos:pos + length]
    pos += length
    return (huffman_decode(raw) if huffman else raw), pos


# ---------------------------------------------------------------------------
# Appendix A: static table (1-based; index 0 is invalid)
# ---------------------------------------------------------------------------

STATIC_TABLE = [None] + [
    (b':authority', b''),
    (b':method', b'GET'),
    (b':method', b'POST'),
    (b':path', b'/'),
    (b':path', b'/index.html'),
    (b':scheme', b'http'),
    (b':scheme', b'https'),
    (b':status', b'200'),
    (b':status', b'204'),
    (b':status', b'206'),
    (b':status', b'304'),
    (b':status', b'400'),
    (b':status', b'404'),
    (b':status', b'500'),
    (b'accept-charset', b''),
    (b'accept-encoding', b'gzip, deflate'),
    (b'accept-language', b''),
    (b'accept-ranges', b''),
    (b'accept', b''),
    (b'access-control-allow-origin', b''),
    (b'age', b''),
    (b'allow', b''),
    (b'authorization', b''),
    (b'cache-control', b''),
    (b'content-disposition', b''),
    (b'content-encoding', b''),
    (b'content-language', b''),
    (b'content-length', b''),
    (b'content-location', b''),
    (b'content-range', b''),
    (b'content-type', b''),
    (b'cookie', b''),
    (b'date', b''),
    (b'etag', b''),
    (b'expect', b''),
    (b'expires', b''),
    (b'from', b''),
    (b'host', b''),
    (b'if-match', b''),
    (b'if-modified-since', b''),
    (b'if-none-match', b''),
    (b'if-range', b''),
    (b'if-unmodified-since', b''),
    (b'last-modified', b''),
    (b'link', b''),
    (b'location', b''),
    (b'max-forwards', b''),
    (b'proxy-authenticate', b''),
    (b'proxy-authorization', b''),
    (b'range', b''),
    (b'referer', b''),
    (b'refresh', b''),
    (b'retry-after', b''),
    (b'server', b''),
    (b'set-cookie', b''),
    (b'strict-transport-security', b''),
    (b'transfer-encoding', b''),
    (b'user-agent', b''),
    (b'vary', b''),
    (b'via', b''),
    (b'www-authenticate', b''),
]
assert len(STATIC_TABLE) == 62  # index 0 unused + 61 entries

STATIC_INDEX = {}   # (name, value) -> index (first occurrence wins)
STATIC_NAME = {}    # name -> first index with that name
for _i in range(1, 62):
    _n, _v = STATIC_TABLE[_i]
    STATIC_INDEX.setdefault((_n, _v), _i)
    STATIC_NAME.setdefault(_n, _i)


# ---------------------------------------------------------------------------
# Section 2.3.2 / 4: dynamic table
# ---------------------------------------------------------------------------

def _entry_size(name: bytes, value: bytes) -> int:
    return 32 + len(name) + len(value)   # RFC 7541 4.1


class DynamicTable:
    """Newest entry first. `max_size` is the current limit; `max_allowed` is
    the protocol/peer ceiling a size update may not exceed."""

    def __init__(self, max_size: int = 4096, max_allowed: int = 4096):
        self.entries = []          # list of (name, value), newest first
        self.size = 0
        self.max_size = max_size
        self.max_allowed = max_allowed

    def _evict_to_fit(self):
        while self.entries and self.size > self.max_size:
            n, v = self.entries.pop()
            self.size -= _entry_size(n, v)

    def set_max_size(self, n: int):
        if n > self.max_allowed:
            raise HPACKError('dynamic table size update exceeds maximum')
        self.max_size = n
        self._evict_to_fit()

    def insert(self, name: bytes, value: bytes):
        esize = _entry_size(name, value)
        if esize > self.max_size:
            self.entries = []
            self.size = 0
            return
        self.entries.insert(0, (name, value))
        self.size += esize
        self._evict_to_fit()

    def get(self, dyn_index: int):
        """dyn_index 0 = newest entry."""
        if dyn_index >= len(self.entries):
            raise HPACKError('dynamic table index out of range')
        return self.entries[dyn_index]

    def find(self, name: bytes, value: bytes):
        """Return (full_index, name_index) in dynamic-table space (0-based)."""
        full, nm = None, None
        for i, (n, v) in enumerate(self.entries):
            if n == name and nm is None:
                nm = i
            if n == name and v == value:
                full = i
                break
        return full, nm


# ---------------------------------------------------------------------------
# Section 6: encoder / decoder
# ---------------------------------------------------------------------------

# Header fields that must never enter the dynamic table (RFC 7541 7.1.3).
NEVER_INDEX = {b'authorization', b'proxy-authorization'}

# Representation prefixes
_P_INDEXED = 0x80          # 1xxxxxxx  (7-bit prefix)
_P_LIT_INCR = 0x40        # 01xxxxxx  (6-bit prefix for name index... 4-bit)
_P_SIZE_UPDATE = 0x20     # 001xxxxx  (5-bit prefix)
_P_LIT_NOIDX = 0x00       # 0000xxxx  (4-bit prefix)
_P_LIT_NEVER = 0x10       # 0001xxxx  (4-bit prefix)


class Encoder:
    def __init__(self, max_size: int = 4096, use_huffman: bool = True):
        self.table = DynamicTable(max_size)
        self.use_huffman = use_huffman
        self._pending_size_update = None

    def set_max_size(self, n: int):
        """Queue a dynamic-table size update; emitted at the start of the
        next header block (RFC 7541 4.2)."""
        if n > self.table.max_allowed:
            raise HPACKError('size update exceeds maximum')
        self._pending_size_update = n

    def _enc_str(self, data: bytes) -> bytes:
        if self.use_huffman:
            h = huffman_encode(data)
            if len(h) < len(data):
                return encode_string(data, True)
        return encode_string(data, False)

    def encode(self, headers) -> bytes:
        """headers: iterable of (name, value) as bytes or str."""
        out = bytearray()
        if self._pending_size_update is not None:
            n = self._pending_size_update
            self._pending_size_update = None
            first = encode_int(n, 5)
            out += bytes([first[0] | _P_SIZE_UPDATE]) + first[1:]
            self.table.set_max_size(n)
        for name, value in headers:
            if isinstance(name, str):
                name = name.encode('latin-1')
            if isinstance(value, str):
                value = value.encode('latin-1')
            out += self._encode_field(name, value)
        return bytes(out)

    def _encode_field(self, name: bytes, value: bytes) -> bytes:
        never = name.lower() in NEVER_INDEX
        # 1. full match: static first, then dynamic (newest wins)
        if (name, value) in STATIC_INDEX and not never:
            idx = STATIC_INDEX[(name, value)]
            f = encode_int(idx, 7)
            return bytes([f[0] | _P_INDEXED]) + f[1:]
        if not never:
            full, nm = self.table.find(name, value)
            if full is not None:
                f = encode_int(62 + full, 7)
                return bytes([f[0] | _P_INDEXED]) + f[1:]
        else:
            _, nm = self.table.find(name, value)
        # 2. name-only match -> indexed name
        name_idx = 0
        if name in STATIC_NAME:
            name_idx = STATIC_NAME[name]
        elif nm is not None:
            name_idx = 62 + nm
        if never:
            prefix, pat = 4, _P_LIT_NEVER
        else:
            # incremental indexing (default): 6-bit prefix per RFC 7541 6.2.1
            prefix, pat = 6, _P_LIT_INCR
        f = encode_int(name_idx, prefix)
        out = bytearray(bytes([f[0] | pat]) + f[1:])
        if name_idx == 0:
            out += self._enc_str(name)
        out += self._enc_str(value)
        if not never:
            # literal without indexing also possible; we always index
            self.table.insert(name, value)
        return bytes(out)

    def encode_noindex(self, headers) -> bytes:
        """Encode with literal-without-indexing (for tests)."""
        out = bytearray()
        for name, value in headers:
            if isinstance(name, str):
                name = name.encode('latin-1')
            if isinstance(value, str):
                value = value.encode('latin-1')
            name_idx = STATIC_NAME.get(name, 0)
            f = encode_int(name_idx, 4)
            out += bytes([f[0] | _P_LIT_NOIDX]) + f[1:]
            if name_idx == 0:
                out += self._enc_str(name)
            out += self._enc_str(value)
        return bytes(out)


class Decoder:
    def __init__(self, max_size: int = 4096, max_allowed: int = 4096,
                 max_list_size: int | None = None):
        self.table = DynamicTable(max_size, max_allowed)
        self.max_list_size = max_list_size

    def set_max_allowed(self, n: int):
        """Apply the peer's SETTINGS_HEADER_TABLE_SIZE ceiling."""
        self.table.max_allowed = n
        if self.table.max_size > n:
            self.table.set_max_size(n)

    def decode(self, data: bytes):
        headers = []
        list_size = 0
        pos = 0
        while pos < len(data):
            b = data[pos]
            if b & 0x80:
                idx, pos = decode_int(data, pos, 7)
                name, value = self._lookup(idx)
            elif b & 0x40:
                idx, pos = decode_int(data, pos, 6)   # 6.2.1: 6-bit prefix
                name, value, pos = self._literal(data, pos, idx, index=True)
            elif b & 0x20:
                new_max, pos = decode_int(data, pos, 5)
                self.table.set_max_size(new_max)
                continue
            elif b & 0x10:
                idx, pos = decode_int(data, pos, 4)
                name, value, pos = self._literal(data, pos, idx, index=False)
            else:
                idx, pos = decode_int(data, pos, 4)
                name, value, pos = self._literal(data, pos, idx, index=False)
            headers.append((name, value))
            list_size += len(name) + len(value)
            if self.max_list_size is not None and list_size > self.max_list_size:
                raise HPACKError('header list too large')
        return headers

    def _lookup(self, idx: int):
        if idx == 0:
            raise HPACKError('indexed field with index 0')
        if idx <= 61:
            return STATIC_TABLE[idx]
        return self.table.get(idx - 62)

    def _literal(self, data: bytes, pos: int, idx: int, index: bool):
        if idx == 0:
            name, pos = decode_string(data, pos)
        else:
            name, _ = self._lookup(idx)
        value, pos = decode_string(data, pos)
        if index:
            self.table.insert(name, value)
        return name, value, pos
