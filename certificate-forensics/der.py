"""DER (Distinguished Encoding Rules) parser, from scratch. Zero dependencies.

DER is the binary wire format underneath every X.509 certificate: a strict
subset of BER using only definite-form lengths. Everything here is a
Tag-Length-Value triple; this module turns bytes into a navigable tree and
provides typed accessors for the ASN.1 types X.509 actually uses.
"""

import base64

# Universal class tag numbers we care about
TAG_BOOLEAN = 1
TAG_INTEGER = 2
TAG_BIT_STRING = 3
TAG_OCTET_STRING = 4
TAG_NULL = 5
TAG_OID = 6
TAG_UTF8STRING = 12
TAG_SEQUENCE = 16
TAG_SET = 17
TAG_PRINTABLESTRING = 19
TAG_T61STRING = 20
TAG_IA5STRING = 22
TAG_UTCTIME = 23
TAG_GENERALIZEDTIME = 24
TAG_BMPSTRING = 30

CLASS_UNIVERSAL = 0
CLASS_APPLICATION = 1
CLASS_CONTEXT = 2
CLASS_PRIVATE = 3

STRING_TAGS = {
    TAG_UTF8STRING: "utf-8",
    TAG_PRINTABLESTRING: "ascii",
    TAG_T61STRING: "latin-1",   # TeletexString: best-effort
    TAG_IA5STRING: "ascii",
    TAG_BMPSTRING: "utf-16-be",
}

TAG_NAMES = {
    1: "BOOLEAN", 2: "INTEGER", 3: "BIT STRING", 4: "OCTET STRING",
    5: "NULL", 6: "OBJECT IDENTIFIER", 12: "UTF8String", 16: "SEQUENCE",
    17: "SET", 19: "PrintableString", 20: "T61String", 22: "IA5String",
    23: "UTCTime", 24: "GeneralizedTime", 30: "BMPString",
}


class DERError(Exception):
    pass


class Node:
    """One parsed TLV triple."""

    __slots__ = ("cls", "constructed", "tag", "header_len", "value", "children")

    def __init__(self, cls, constructed, tag, header_len, value, children=None):
        self.cls = cls
        self.constructed = constructed
        self.tag = tag
        self.header_len = header_len  # bytes of tag+length octets
        self.value = value            # raw content bytes (primitive)
        self.children = children or []  # parsed children (constructed)

    # -- navigation -----------------------------------------------------
    def __len__(self):
        return len(self.children)

    def __getitem__(self, i):
        return self.children[i]

    def child(self, i):
        return self.children[i]

    def find(self, tag, cls=CLASS_UNIVERSAL):
        """First child with given tag/class, else None."""
        for c in self.children:
            if c.tag == tag and c.cls == cls:
                return c
        return None

    def expect(self, tag, cls=CLASS_UNIVERSAL):
        n = self.find(tag, cls)
        if n is None:
            raise DERError(f"expected tag {tag} class {cls}, not present")
        return n

    # -- typed accessors ------------------------------------------------
    def as_int(self):
        if self.tag != TAG_INTEGER or self.cls != CLASS_UNIVERSAL:
            raise DERError("as_int on non-INTEGER")
        b = self.value
        if not b:
            raise DERError("empty INTEGER")
        v = int.from_bytes(b, "big")
        if b[0] & 0x80:  # two's complement negative
            v -= 1 << (8 * len(b))
        return v

    def as_bytes(self):
        if self.tag not in (TAG_OCTET_STRING, TAG_BIT_STRING):
            raise DERError("as_bytes on non-string")
        return self.value

    def bitstring(self):
        """BIT STRING -> (unused_bits, payload_bytes)."""
        if self.tag != TAG_BIT_STRING:
            raise DERError("bitstring on non-BIT-STRING")
        if not self.value:
            raise DERError("empty BIT STRING")
        return self.value[0], self.value[1:]

    def as_oid(self):
        if self.tag != TAG_OID:
            raise DERError("as_oid on non-OID")
        return decode_oid(self.value)

    def as_str(self):
        enc = STRING_TAGS.get(self.tag)
        if enc is None:
            raise DERError(f"as_str on tag {self.tag}")
        return self.value.decode(enc, errors="replace")

    def as_time(self):
        """UTCTime/GeneralizedTime -> (year, month, day, hour, min, sec) tuple."""
        if self.tag == TAG_UTCTIME:
            s = self.value.decode("ascii")
            if len(s) < 11:
                raise DERError("short UTCTime")
            yy = int(s[0:2])
            year = 1900 + yy if yy >= 50 else 2000 + yy
            rest = s[2:]
        elif self.tag == TAG_GENERALIZEDTIME:
            s = self.value.decode("ascii")
            year = int(s[0:4])
            rest = s[4:]
        else:
            raise DERError("as_time on non-time tag")
        # rest: MMDDHHMMSS + optional Z or offset; we require Z for DER
        month, day = int(rest[0:2]), int(rest[2:4])
        hour, minute, sec = int(rest[4:6]), int(rest[6:8]), int(rest[8:10])
        return (year, month, day, hour, minute, sec)

    def as_bool(self):
        if self.tag != TAG_BOOLEAN:
            raise DERError("as_bool on non-BOOLEAN")
        return self.value != b"\x00"

    def tag_name(self):
        if self.cls == CLASS_UNIVERSAL:
            return TAG_NAMES.get(self.tag, f"UNIVERSAL-{self.tag}")
        cname = {1: "APPLICATION", 2: "CONTEXT", 3: "PRIVATE"}[self.cls]
        return f"[{self.tag}]({cname}{' constructed' if self.constructed else ''})"

    def pretty(self, indent=0):
        pad = "  " * indent
        extra = ""
        try:
            if self.tag == TAG_OID and self.cls == CLASS_UNIVERSAL:
                extra = f" = {self.as_oid()}"
            elif self.tag == TAG_INTEGER and self.cls == CLASS_UNIVERSAL:
                v = self.as_int()
                extra = f" = {v}" + (f" (0x{v:x})" if v >= 0 else "")
            elif self.tag in STRING_TAGS and self.cls == CLASS_UNIVERSAL:
                extra = f" = {self.as_str()!r}"
            elif self.tag in (TAG_UTCTIME, TAG_GENERALIZEDTIME):
                extra = f" = {'%04d-%02d-%02d %02d:%02d:%02d' % self.as_time()}"
            elif self.tag == TAG_BIT_STRING and self.cls == CLASS_UNIVERSAL:
                ub, _ = self.bitstring()
                extra = f" ({len(self.value) - 1} bytes, {ub} unused bits)"
            elif self.tag == TAG_OCTET_STRING and self.cls == CLASS_UNIVERSAL:
                extra = f" ({len(self.value)} bytes)"
            elif self.tag == TAG_NULL:
                extra = " = NULL"
            elif self.tag == TAG_BOOLEAN:
                extra = f" = {self.as_bool()}"
        except DERError:
            pass
        lines = [f"{pad}{self.tag_name()}{extra}"]
        for c in self.children:
            lines.append(c.pretty(indent + 1))
        return "\n".join(lines)


def decode_oid(content: bytes) -> str:
    """Decode OID content octets -> dotted string."""
    if not content:
        raise DERError("empty OID")
    first = content[0]
    arcs = [first // 40, first % 40]
    val = 0
    for byte in content[1:]:
        val = (val << 7) | (byte & 0x7F)
        if not (byte & 0x80):
            arcs.append(val)
            val = 0
    if val:
        raise DERError("truncated OID subidentifier")
    return ".".join(str(a) for a in arcs)


def encode_oid(dotted: str) -> bytes:
    """Dotted OID -> content octets (for building test fixtures)."""
    arcs = [int(a) for a in dotted.split(".")]
    out = bytes([40 * arcs[0] + arcs[1]])
    for a in arcs[2:]:
        stack = [a & 0x7F]
        a >>= 7
        while a:
            stack.append(0x80 | (a & 0x7F))
            a >>= 7
        out += bytes(reversed(stack))
    return out


def _parse_tlv(buf: bytes, off: int):
    """Parse one TLV at offset -> (Node, next_offset)."""
    start = off
    if off >= len(buf):
        raise DERError("truncated: expected tag")
    b0 = buf[off]
    off += 1
    cls = (b0 >> 6) & 0x03
    constructed = bool(b0 & 0x20)
    tag = b0 & 0x1F
    if tag == 0x1F:  # high-tag-number form
        tag = 0
        while True:
            if off >= len(buf):
                raise DERError("truncated high-tag-number")
            b = buf[off]
            off += 1
            tag = (tag << 7) | (b & 0x7F)
            if not (b & 0x80):
                break
    if off >= len(buf):
        raise DERError("truncated: expected length")
    lb = buf[off]
    off += 1
    if lb & 0x80 == 0:
        length = lb
    else:
        nbytes = lb & 0x7F
        if nbytes == 0:
            raise DERError("indefinite length: not DER")
        if nbytes > 4:
            raise DERError(f"absurd length octet count {nbytes}")
        if off + nbytes > len(buf):
            raise DERError("truncated length octets")
        length = int.from_bytes(buf[off:off + nbytes], "big")
        off += nbytes
        # DER: long form must be minimal (no leading zero octets) and only
        # when short form can't represent it
        if length < 128:
            raise DERError("non-minimal DER length encoding")
    if off + length > len(buf):
        raise DERError("truncated value")
    value = buf[off:off + length]
    off += length
    header_len = (off - length) - start
    children = []
    if constructed:
        coff = 0
        while coff < len(value):
            child, coff = _parse_tlv(value, coff)
            children.append(child)
        # constructed with primitive-only tag is legal (e.g. OCTET STRING
        # constructed form); children stay empty, value kept raw
    return Node(cls, constructed, tag, header_len, value, children), off


def parse_der(buf: bytes) -> Node:
    """Parse exactly one top-level DER value."""
    node, off = _parse_tlv(buf, 0)
    if off != len(buf):
        raise DERError(f"trailing garbage: {len(buf) - off} bytes after top-level value")
    return node


def pem_to_der(pem: str | bytes) -> bytes:
    """Extract DER bytes from a PEM block."""
    if isinstance(pem, bytes):
        pem = pem.decode("ascii", errors="ignore")
    lines = [l.strip() for l in pem.splitlines()
             if l.strip() and not l.startswith("-----")]
    return base64.b64decode("".join(lines))


def split_pems(text: str) -> list[str]:
    """Split a PEM bundle into individual PEM blocks."""
    blocks, cur = [], []
    for line in text.splitlines():
        if "BEGIN" in line:
            cur = [line]
        elif "END" in line:
            cur.append(line)
            blocks.append("\n".join(cur))
            cur = []
        elif cur:
            cur.append(line)
    return blocks
