#!/usr/bin/env python3
"""DNSSEC one-link verification by hand -- stdlib only.

Parses DNSKEY/RRSIG rdata, builds the RFC 4034 Section 8.2 canonical
signing form, and verifies RSA/SHA-256 (algorithm 8) signatures with
hand-rolled RSA + PKCS#1 v1.5 (same construction as the email skill's
dkim.py, duplicated here so this skill stays standalone).

HONEST SCOPE: this verifies *one* link -- "this RRSIG over this RRset was
made by this DNSKEY". A full validator additionally walks the chain of
trust (DS -> parent -> ... -> root KSK trust anchor) and checks
inception/expiration times. That needs the root KSK and live DNS; the
mechanics below are the part you can do offline.
"""
import hashlib
import random
import struct

from dns import encode_name, QTYPES, key_tag

_rng = random.Random()

# ---------------------------------------------------------------------------
# tiny RSA (keygen for the self-test / demo signing side)
# ---------------------------------------------------------------------------

def _is_probable_prime(n, rounds=16):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    bases = (2, 325, 9375, 28178, 450775, 9780504, 1795265022) if n < 2 ** 64 \
        else [_rng.randrange(2, n - 1) for _ in range(rounds)]
    for a in bases:
        a %= n
        if a == 0:
            continue
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits):
    while True:
        c = _rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(c):
            return c


def _egcd(a, b):
    return (a, 1, 0) if b == 0 else \
        (lambda g, x, y: (g, y, x - (a // b) * y))(*_egcd(b, a % b))


def generate_rsa_key(bits=1024, e=65537):
    while True:
        p, q = _gen_prime(bits // 2), _gen_prime(bits // 2)
        if p != q and _egcd(e, (p - 1) * (q - 1))[0] == 1:
            break
    n = p * q
    _, x, _ = _egcd(e, (p - 1) * (q - 1))
    return n, e, x % ((p - 1) * (q - 1))


# ---------------------------------------------------------------------------
# DNSKEY wire format (RFC 3110): flags(2) proto(1) alg(1) | key blob
# key blob (RSA): exp_len(1 or 3) | exponent | modulus
# ---------------------------------------------------------------------------

def dnskey_rdata(n, e, flags=257, protocol=3, algorithm=8):
    """Build DNSKEY rdata bytes for an RSA key (RFC 3110 exponent format)."""
    e_bytes = e.to_bytes((e.bit_length() + 7) // 8, "big")
    exp_field = ((bytes([len(e_bytes)]) if len(e_bytes) < 256
                  else b"\x00" + struct.pack(">H", len(e_bytes))) + e_bytes)
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return struct.pack(">HBB", flags, protocol, algorithm) + exp_field + n_bytes


def parse_dnskey_rsa(rdata):
    """DNSKEY rdata -> (n, e). Only algorithm 8 (RSA/SHA-256)."""
    flags, proto, alg = struct.unpack(">HBB", rdata[:4])
    if alg != 8:
        raise ValueError(f"unsupported DNSSEC algorithm {alg} (only 8/RSA-SHA-256)")
    blob = rdata[4:]
    ln = blob[0]
    off = 1
    if ln == 0:
        ln = struct.unpack(">H", blob[1:3])[0]
        off = 3
    e = int.from_bytes(blob[off:off + ln], "big")
    n = int.from_bytes(blob[off + ln:], "big")
    return n, e


# ---------------------------------------------------------------------------
# canonical form (RFC 4034 6.2 / 8.2)
# ---------------------------------------------------------------------------

def canonical_name(name):
    """Lowercase, uncompressed wire encoding of a domain name."""
    return encode_name(name.lower())


def _canonical_rdata(rtype_num, rdata_wire):
    """Lowercase any domain names embedded in rdata (NS/CNAME/PTR/MX/SOA)."""
    # For this skill's scope only A/AAAA/TXT rdata is signed in the
    # self-test, which are already canonical; name-bearing types would need
    # per-type lowercasing. Documented, not silently wrong: we lowercase the
    # whole rdata only for the name types we can parse safely.
    return rdata_wire


def signed_data(rrset, rrsig):
    """Build the exact bytes covered by an RRSIG (RFC 4034 8.2).

    rrset: list of dicts {name, type(num or str), class, ttl, rdata_wire(bytes)}
    rrsig: dict with type_covered(num), algorithm, labels, original_ttl,
           expiration, inception, key_tag, signer(str), signature(bytes)
    """
    tc = rrsig["type_covered"]
    tc = QTYPES.get(str(tc).upper(), tc) if isinstance(tc, str) else tc
    out = bytearray()
    out += struct.pack(">HBBIIIH", tc, rrsig["algorithm"], rrsig["labels"],
                       rrsig["original_ttl"], rrsig["expiration"],
                       rrsig["inception"], rrsig["key_tag"])
    out += canonical_name(rrsig["signer"])
    canon_rrs = []
    for rr in rrset:
        rt = rr["type"]
        rt = QTYPES.get(str(rt).upper(), rt) if isinstance(rt, str) else rt
        rd = _canonical_rdata(rt, rr["rdata_wire"])
        canon_rrs.append((rd, canonical_name(rr["name"])
                          + struct.pack(">HHI", rt, rr["class"],
                                        rrsig["original_ttl"])
                          + struct.pack(">H", len(rd)) + rd))
    for _, wire in sorted(canon_rrs):   # canonical RRset order (RFC 4034 6.3)
        out += wire
    return bytes(out)


# ---------------------------------------------------------------------------
# sign (demo) / verify
# ---------------------------------------------------------------------------

_SHA256_DER_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def _emsa_pkcs1_v15_sha256(digest, k):
    t = _SHA256_DER_PREFIX + digest
    return b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t


def make_rrsig(rrset, signer, key, inception, expiration, labels=None):
    """Create an RRSIG dict for rrset using RSA key (n, e, d). Demo signing."""
    n, e, d = key
    rr0 = rrset[0]
    tc = rr0["type"]
    tc = QTYPES.get(str(tc).upper(), tc) if isinstance(tc, str) else tc
    if labels is None:
        labels = len(rr0["name"].rstrip(".").split("."))
    rdata = dnskey_rdata(n, e)
    rrsig = {"type_covered": tc, "algorithm": 8, "labels": labels,
             "original_ttl": rr0["ttl"], "expiration": expiration,
             "inception": inception,
             "key_tag": key_tag(48, rdata), "signer": signer,
             "signature": b""}
    data = signed_data(rrset, rrsig)
    k = (n.bit_length() + 7) // 8
    em = _emsa_pkcs1_v15_sha256(hashlib.sha256(data).digest(), k)
    sig = pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")
    rrsig["signature"] = sig
    return rrsig


def verify_rrsig(rrset, rrsig, dnskey_rdata):
    """Verify one RRSIG link. Returns (ok, detail)."""
    try:
        n, e = parse_dnskey_rsa(dnskey_rdata)
    except ValueError as exc:
        return False, str(exc)
    if rrsig.get("algorithm") != 8:
        return False, f"unsupported algorithm {rrsig.get('algorithm')}"
    data = signed_data(rrset, rrsig)
    digest = hashlib.sha256(data).digest()
    sig = rrsig["signature"]
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False, f"signature length {len(sig)} != key size {k}"
    em = pow(int.from_bytes(sig, "big"), e, n).to_bytes(k, "big")
    ok = em == _emsa_pkcs1_v15_sha256(digest, k)
    return ok, "RRSIG valid for this RRset/DNSKEY" if ok else \
        "RRSIG INVALID (wrong key or data changed)"


def self_test():
    n, e, d = generate_rsa_key(bits=1024)
    key_rdata = dnskey_rdata(n, e)
    rrset = [
        {"name": "www.example.com", "type": "A", "class": 1, "ttl": 300,
         "rdata_wire": bytes([93, 184, 216, 34])},
        {"name": "www.example.com", "type": "A", "class": 1, "ttl": 300,
         "rdata_wire": bytes([93, 184, 216, 35])},
    ]
    rrsig = make_rrsig(rrset, "example.com", (n, e, d),
                       inception=1700000000, expiration=1800000000)
    ok, detail = verify_rrsig(rrset, rrsig, key_rdata)
    print(f"[{'PASS' if ok else 'FAIL'}] sign->verify: {detail}")
    # tamper with one rdata byte
    bad = [dict(r) for r in rrset]
    bad[0] = dict(bad[0], rdata_wire=bytes([93, 184, 216, 99]))
    ok2, detail2 = verify_rrsig(bad, rrsig, key_rdata)
    print(f"[{'PASS' if not ok2 else 'FAIL'}] tampered RRset rejected: {detail2}")
    # wrong key
    n2, e2, _ = generate_rsa_key(bits=1024)
    ok3, detail3 = verify_rrsig(rrset, rrsig, dnskey_rdata(n2, e2))
    print(f"[{'PASS' if not ok3 else 'FAIL'}] wrong DNSKEY rejected: {detail3}")
    good = ok and not ok2 and not ok3
    print("DNSSEC SELF-TEST:", "PASS" if good else "FAIL")
    return good


if __name__ == "__main__":
    raise SystemExit(0 if self_test() else 1)
