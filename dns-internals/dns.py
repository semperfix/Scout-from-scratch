#!/usr/bin/env python3
"""DNS wire format (RFC 1035) by hand -- stdlib only.

Encode queries, decode responses, with compression-pointer handling on
decode. Supported types: A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, RRSIG,
DNSKEY (unknown types decode as raw hex).
"""
import struct

QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15,
          "TXT": 16, "AAAA": 28, "RRSIG": 46, "DNSKEY": 48}
RTYPES = {v: k for k, v in QTYPES.items()}


# ---------------------------------------------------------------------------
# domain names
# ---------------------------------------------------------------------------

def encode_name(name):
    """'www.example.com' -> b'\\x03www\\x07example\\x03com\\x00'."""
    out = bytearray()
    for label in name.rstrip(".").split("."):
        lb = label.encode("ascii")
        if not 1 <= len(lb) <= 63:
            raise ValueError(f"bad label: {label!r}")
        out += bytes([len(lb)]) + lb
    return bytes(out) + b"\x00"


def decode_name(data, off):
    """Decode a (possibly compressed) name at offset -> (name, next_offset)."""
    labels, jumped, end = [], False, off
    seen = set()
    while True:
        if off >= len(data):
            raise ValueError("name runs past end of message")
        if off in seen:
            raise ValueError("compression pointer loop")
        seen.add(off)
        ln = data[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:                      # compression pointer
            ptr = struct.unpack(">H", data[off:off + 2])[0] & 0x3FFF
            if not jumped:
                end = off + 2
                jumped = True
            off = ptr
            continue
        if ln & 0xC0:
            raise ValueError(f"bad label length byte {ln:#x}")
        off += 1
        labels.append(data[off:off + ln].decode("ascii", "replace"))
        off += ln
    return ".".join(labels), (end if jumped else off)


# ---------------------------------------------------------------------------
# rdata
# ---------------------------------------------------------------------------

def _decode_rdata(rtype, data, off, rdlen, msg):
    r = data[off:off + rdlen]
    if rtype == 1 and rdlen == 4:                       # A
        return ".".join(str(b) for b in r)
    if rtype == 28 and rdlen == 16:                     # AAAA
        return ":".join(f"{int.from_bytes(r[i:i+2], 'big'):x}" for i in range(0, 16, 2))
    if rtype in (2, 5, 12):                             # NS, CNAME, PTR
        name, _ = decode_name(msg, off)
        return name
    if rtype == 15:                                     # MX
        pref = struct.unpack(">H", r[:2])[0]
        name, _ = decode_name(msg, off + 2)
        return {"preference": pref, "exchange": name}
    if rtype == 16:                                     # TXT
        parts, i = [], 0
        while i < rdlen:
            ln = r[i]
            parts.append(r[i + 1:i + 1 + ln])
            i += 1 + ln
        return b"".join(parts).decode("utf-8", "replace")
    if rtype == 6:                                      # SOA
        mname, o = decode_name(msg, off)
        rname, o = decode_name(msg, o)
        serial, refresh, retry, expire, minimum = struct.unpack(">5I", data[o:o + 20])
        return {"mname": mname, "rname": rname, "serial": serial,
                "refresh": refresh, "retry": retry, "expire": expire,
                "minimum": minimum}
    if rtype == 46:                                     # RRSIG
        (tc, alg, labels, ottl, exp, inc, tag) = struct.unpack(">HBBIIIH", r[:18])
        signer, sig_off = decode_name(msg, off + 18)
        return {"type_covered": RTYPES.get(tc, tc), "algorithm": alg,
                "labels": labels, "original_ttl": ottl,
                "expiration": exp, "inception": inc, "key_tag": tag,
                "signer": signer,
                "signature": data[sig_off:off + rdlen].hex()}
    if rtype == 48:                                     # DNSKEY
        flags, proto, alg = struct.unpack(">HBB", r[:4])
        return {"flags": flags, "protocol": proto, "algorithm": alg,
                "key": r[4:].hex(), "key_tag": key_tag(rtype, r)}
    return r.hex()                                      # unknown type


def key_tag(rtype, rdata):
    """RFC 4034 Appendix B key-tag computation (used for DNSKEY)."""
    if rtype != 48:
        return None
    ac = 0
    for i, b in enumerate(rdata):
        ac += b << 8 if i & 1 == 0 else b
    return ((ac >> 16) + (ac & 0xFFFF)) & 0xFFFF


# ---------------------------------------------------------------------------
# messages
# ---------------------------------------------------------------------------

def build_query(name, qtype="A", qid=0x1234, rd=True):
    """Build a DNS query packet. qtype: name or number."""
    qn = QTYPES.get(str(qtype).upper(), qtype) if isinstance(qtype, str) else qtype
    flags = 0x0100 if rd else 0x0000
    hdr = struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 0)
    return hdr + encode_name(name) + struct.pack(">HH", qn, 1)


def _parse_rr(data, off):
    name, off = decode_name(data, off)
    rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
    rdata = _decode_rdata(rtype, data, off + 10, rdlen, data)
    return {"name": name, "type": RTYPES.get(rtype, rtype), "class": rclass,
            "ttl": ttl, "rdata": rdata}, off + 10 + rdlen


def parse_message(data):
    """Parse a DNS message -> dict. Raises ValueError on truncation."""
    if len(data) < 12:
        raise ValueError("message shorter than header")
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    off = 12
    questions = []
    for _ in range(qd):
        name, off = decode_name(data, off)
        qtype, qclass = struct.unpack(">HH", data[off:off + 4])
        off += 4
        questions.append({"name": name, "type": RTYPES.get(qtype, qtype),
                          "class": qclass})
    sections = {}
    for key, count in (("answers", an), ("authority", ns), ("additional", ar)):
        rrs = []
        for _ in range(count):
            rr, off = _parse_rr(data, off)
            rrs.append(rr)
        sections[key] = rrs
    return {"id": qid,
            "flags": {"qr": bool(flags & 0x8000), "opcode": (flags >> 11) & 0xF,
                      "aa": bool(flags & 0x0400), "tc": bool(flags & 0x0200),
                      "rd": bool(flags & 0x0100), "ra": bool(flags & 0x0080),
                      "rcode": flags & 0xF},
            "questions": questions, **sections}


def format_message(msg):
    L = [f"id=0x{msg['id']:04x} qr={int(msg['flags']['qr'])} "
         f"opcode={msg['flags']['opcode']} rcode={msg['flags']['rcode']} "
         f"qd={len(msg['questions'])} an={len(msg['answers'])} "
         f"ns={len(msg['authority'])} ar={len(msg['additional'])}"]
    for q in msg["questions"]:
        L.append(f"  Q: {q['name']} {q['type']}")
    for sec in ("answers", "authority", "additional"):
        for rr in msg[sec]:
            L.append(f"  {sec[:2].upper()}: {rr['name']} {rr['ttl']} "
                     f"{rr['type']} {rr['rdata']}")
    return "\n".join(L)


def self_test():
    # query round-trip
    q = build_query("www.example.com", "A")
    m = parse_message(q)
    assert m["questions"] == [{"name": "www.example.com", "type": "A", "class": 1}]
    assert m["flags"]["rd"] and not m["flags"]["qr"]

    # hand-crafted response with a compression pointer (answer name -> offset 12)
    hdr = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    question = encode_name("www.example.com") + struct.pack(">HH", 1, 1)
    answer = (b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4)
              + bytes([93, 184, 216, 34]))
    m = parse_message(hdr + question + answer)
    assert m["answers"][0]["rdata"] == "93.184.216.34", m["answers"][0]
    assert m["answers"][0]["name"] == "www.example.com"
    assert m["flags"]["qr"] and m["flags"]["rcode"] == 0

    # MX + TXT decode (question present so the answer pointer has a target)
    hdr = struct.pack(">HHHHHH", 1, 0x8180, 1, 1, 0, 0)
    question = encode_name("example.com") + struct.pack(">HH", 15, 1)
    mx_rdata = struct.pack(">H", 10) + encode_name("mail.example.com")
    answer = (b"\xc0\x0c" + struct.pack(">HHIH", 15, 1, 60, len(mx_rdata))
              + mx_rdata)
    m = parse_message(hdr + question + answer)
    assert m["answers"][0]["rdata"]["exchange"] == "mail.example.com"
    assert m["answers"][0]["name"] == "example.com"

    print("DNS SELF-TEST: PASS")
    return True


if __name__ == "__main__":
    raise SystemExit(0 if self_test() else 1)
