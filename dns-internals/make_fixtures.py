#!/usr/bin/env python3
"""Hand-craft DNS wire fixtures with struct (no dns.py on the build side --
the fixtures are *inputs* to the parser, so they must not depend on it).

Writes fixtures/query.bin (A query for www.example.com) and
fixtures/response.bin (matching response: 1 A answer + 1 NS authority,
answer name via compression pointer to the question).
"""
import os
import struct

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
os.makedirs(FIX, exist_ok=True)


def enc_name(name):
    out = bytearray()
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return bytes(out) + b"\x00"


QNAME = enc_name("www.example.com")          # starts at offset 12
query = (struct.pack(">HHHHHH", 0xABCD, 0x0100, 1, 0, 0, 0)
         + QNAME + struct.pack(">HH", 1, 1))

# response: same qid, flags QR|RD|RA, 1 question, 1 answer, 1 authority
answer = (b"\xc0\x0c"                                   # pointer -> offset 12
          + struct.pack(">HHIH", 1, 1, 300, 4)
          + bytes([93, 184, 216, 34]))
ns_rdata = enc_name("a.iana-servers.net")
authority = (enc_name("example.com")
             + struct.pack(">HHIH", 2, 1, 86400, len(ns_rdata)) + ns_rdata)
response = (struct.pack(">HHHHHH", 0xABCD, 0x8180, 1, 1, 1, 0)
            + QNAME + struct.pack(">HH", 1, 1) + answer + authority)

with open(os.path.join(FIX, "query.bin"), "wb") as f:
    f.write(query)
with open(os.path.join(FIX, "response.bin"), "wb") as f:
    f.write(response)
print(f"wrote fixtures/query.bin ({len(query)}B), fixtures/response.bin ({len(response)}B)")
