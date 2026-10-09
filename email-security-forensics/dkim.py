#!/usr/bin/env python3
"""DKIM (RFC 6376) signer/verifier built from scratch -- stdlib only.

  * relaxed header canonicalization + simple body canonicalization
  * bh = base64(SHA-256(canonical body))
  * RSA-SHA256 with real RSASSA-PKCS1-v1.5 padding (hand-rolled RSA:
    Miller-Rabin keygen + modular exponentiation, no crypto libs)
  * minimal DER codec for the PKCS#1 RSAPublicKey in DNS TXT records
    (v=DKIM1; k=rsa; p=<base64 DER>)

DNS is injected as a callable (name -> TXT string or None) so verification
is fully offline-testable; emailauth.py wires it to a --dns-stub JSON file.
"""
import base64
import hashlib
import random
import re

_rng = random.Random()

# ---------------------------------------------------------------------------
# tiny RSA (keygen only; the math is pow() with PKCS#1 v1.5 padding)
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
    """Returns (n, e, d)."""
    while True:
        p, q = _gen_prime(bits // 2), _gen_prime(bits // 2)
        if p != q and _egcd(e, (p - 1) * (q - 1))[0] == 1:
            break
    n = p * q
    g, x, _ = _egcd(e, (p - 1) * (q - 1))
    return n, e, x % ((p - 1) * (q - 1))


# ---------------------------------------------------------------------------
# minimal DER codec (PKCS#1 RSAPublicKey ::= SEQUENCE { n INTEGER, e INTEGER })
# ---------------------------------------------------------------------------

def _der_len(n):
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der_int(x):
    b = x.to_bytes(max(1, (x.bit_length() + 7) // 8), "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + _der_len(len(b)) + b


def der_encode_rsa_pub(n, e):
    body = _der_int(n) + _der_int(e)
    return b"\x30" + _der_len(len(body)) + body


def _der_read_tlv(buf, off):
    tag = buf[off]
    first = buf[off + 1]
    if first < 128:
        ln, off2 = first, off + 2
    else:
        nbytes = first & 0x7F
        ln = int.from_bytes(buf[off + 2:off + 2 + nbytes], "big")
        off2 = off + 2 + nbytes
    return tag, buf[off2:off2 + ln], off2 + ln


def der_decode_rsa_pub(der):
    """Parse DER PKCS#1 RSAPublicKey -> (n, e)."""
    tag, body, end = _der_read_tlv(der, 0)
    if tag != 0x30 or end != len(der):
        raise ValueError("not a DER SEQUENCE")
    t1, v1, o = _der_read_tlv(body, 0)
    t2, v2, o2 = _der_read_tlv(body, o)
    if t1 != 2 or t2 != 2 or o2 != len(body):
        raise ValueError("not a DER (n, e) pair")
    return int.from_bytes(v1, "big"), int.from_bytes(v2, "big")


def dkim_dns_txt(n, e):
    """DNS TXT record content publishing this public key (RFC 6376 3.6.2.1)."""
    p64 = base64.b64encode(der_encode_rsa_pub(n, e)).decode()
    return f"v=DKIM1; k=rsa; p={p64}"


def parse_dkim_txt(txt):
    """Parse a DKIM DNS TXT record -> (n, e)."""
    tags = dict(p.split("=", 1) for p in txt.split(";") if "=" in p)
    tags = {k.strip().lower(): v.strip() for k, v in tags.items()}
    if tags.get("v", "").upper() != "DKIM1":
        raise ValueError("not a DKIM1 record")
    if tags.get("p", "") == "":
        raise ValueError("key revoked (empty p=)")
    return der_decode_rsa_pub(base64.b64decode(tags["p"]))


# ---------------------------------------------------------------------------
# canonicalization (RFC 6376 3.4)
# ---------------------------------------------------------------------------

def _normalize(raw: bytes) -> bytes:
    """Normalize line endings to CRLF (tolerates lone LF/CR input)."""
    return raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n").replace(b"\n", b"\r\n")


def split_email(raw: bytes):
    """-> (list[(name_bytes, unfolded_value_bytes)], body_bytes)."""
    raw = _normalize(raw)
    head, _, body = raw.partition(b"\r\n\r\n")
    headers = []
    for line in head.split(b"\r\n"):
        if line[:1] in b" \t" and headers:
            # continuation: unfolding = drop the CRLF, keep the WSP
            headers[-1] = (headers[-1][0], headers[-1][1] + line)
        elif b":" in line:
            name, _, value = line.partition(b":")
            headers.append((name, value))
    return headers, body


def relaxed_header(name: bytes, unfolded_value: bytes) -> bytes:
    """Relaxed header canonicalization -> b'lower-name:reduced value'."""
    v = re.sub(rb"[ \t]+", b" ", unfolded_value)
    v = v.strip(b" \t")
    return name.lower().strip(b" \t") + b":" + v


def simple_body(body: bytes) -> bytes:
    """'simple' body canonicalization: drop trailing empty lines."""
    body = _normalize(body)
    lines = body.split(b"\r\n")
    while lines and lines[-1] == b"":
        lines.pop()
    return b"\r\n".join(lines) + b"\r\n" if lines else b""


def body_hash_b64(body: bytes) -> str:
    return base64.b64encode(hashlib.sha256(simple_body(body)).digest()).decode()


# ---------------------------------------------------------------------------
# PKCS#1 v1.5 (RSASSA) sign/verify -- the real padding, hand-rolled
# ---------------------------------------------------------------------------

_SHA256_DER_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def _emsa_pkcs1_v15_sha256(digest: bytes, k: int) -> bytes:
    t = _SHA256_DER_PREFIX + digest
    if len(t) + 11 > k:
        raise ValueError("key too small for PKCS#1 v1.5")
    return b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t


def rsa_sign(n, d, digest: bytes) -> int:
    k = (n.bit_length() + 7) // 8
    em = _emsa_pkcs1_v15_sha256(digest, k)
    return pow(int.from_bytes(em, "big"), d, n)


def rsa_verify(n, e, digest: bytes, sig: int) -> bool:
    k = (n.bit_length() + 7) // 8
    if not 0 <= sig < n:
        return False
    em = pow(sig, e, n).to_bytes(k, "big")
    return em == _emsa_pkcs1_v15_sha256(digest, k)


# ---------------------------------------------------------------------------
# DKIM-Signature header handling
# ---------------------------------------------------------------------------

def parse_dkim_sig_header(name: bytes, value: bytes):
    """Parse an unfolded DKIM-Signature field value -> dict of tags."""
    if name.lower().strip() != b"dkim-signature":
        raise ValueError("not a DKIM-Signature header")
    tags = {}
    for part in value.split(b";"):
        if b"=" in part:
            k, _, v = part.partition(b"=")
            tags[k.strip().lower()] = v.strip()
    return tags


def _strip_b_value(unfolded_value: bytes) -> bytes:
    """Blank the b= signature value, keeping every other byte identical."""
    return re.sub(rb"\bb\s*=\s*[^;]*", b"b=", unfolded_value, count=1)


def _signing_data(headers, sig_unfolded_value, h_list):
    """Assemble the exact bytes that get RSA-signed (RFC 6376 3.7)."""
    # last occurrence of each named header, in h= order
    by_name = {}
    for name, value in headers:
        by_name[name.lower().strip()] = (name, value)
    out = bytearray()
    for h in h_list:
        h = h.strip().lower()
        if h in by_name:
            name, value = by_name[h]
            out += relaxed_header(name, value) + b"\r\n"
    out += relaxed_header(b"DKIM-Signature", _strip_b_value(sig_unfolded_value)) + b"\r\n"
    return bytes(out)


# ---------------------------------------------------------------------------
# high-level sign / verify
# ---------------------------------------------------------------------------

DEFAULT_SIGNED_HEADERS = [b"from", b"to", b"subject", b"date", b"message-id"]


def sign_raw_email(raw: bytes, domain: str, selector: str, key, sign_headers=None):
    """DKIM-sign a raw email. key = (n, e, d). Returns the signed raw email.

    The DKIM-Signature header is prepended to the header block.
    """
    n, e, d = key
    sign_headers = [h.lower() for h in (sign_headers or DEFAULT_SIGNED_HEADERS)]
    headers, body = split_email(raw)
    bh = body_hash_b64(body)
    h_tag = ":".join(h.decode() for h in sign_headers)
    sig_value = (f"v=1; a=rsa-sha256; d={domain}; s={selector}; c=relaxed/simple; "
                 f"q=dns/txt; h={h_tag}; bh={bh}; b=")
    data = _signing_data(headers, sig_value.encode(), sign_headers)
    sig = rsa_sign(n, d, hashlib.sha256(data).digest())
    k = (n.bit_length() + 7) // 8
    b64 = base64.b64encode(sig.to_bytes(k, "big")).decode()
    # fold the b= value at 64 chars for readability (unfolds back identically)
    folded = sig_value.encode() + b"\r\n ".join(
        b64[i:i + 64].encode() for i in range(0, len(b64), 64))
    head, _, _ = _normalize(raw).partition(b"\r\n\r\n")
    return b"DKIM-Signature: " + folded + b"\r\n" + head + b"\r\n\r\n" + _normalize(raw).partition(b"\r\n\r\n")[2]


def verify_raw_email(raw: bytes, dns_txt):
    """Verify all DKIM-Signature headers in a raw email.

    dns_txt: callable(name) -> TXT string or None (e.g. stub backed by JSON).
    Returns a list of per-signature report dicts.
    """
    headers, body = split_email(raw)
    reports = []
    for name, value in headers:
        if name.lower().strip() != b"dkim-signature":
            continue
        rep = {"header": "DKIM-Signature"}
        try:
            tags = parse_dkim_sig_header(name, value)
            rep.update({k.decode(): v.decode() for k, v in tags.items()})
        except Exception as exc:  # noqa: BLE001
            rep.update(status="error", detail=f"unparseable header: {exc}")
            reports.append(rep)
            continue
        domain = rep.get("d", "")
        selector = rep.get("s", "")
        # 1. body hash check
        want_bh = rep.get("bh", "")
        got_bh = body_hash_b64(body)
        rep["bh_match"] = (want_bh == got_bh)
        # 2. signature check (needs the public key from DNS)
        txt = dns_txt(f"{selector}._domainkey.{domain}") if domain and selector else None
        if not txt:
            rep.update(status="error",
                       detail=f"no DKIM TXT at {selector}._domainkey.{domain}")
            reports.append(rep)
            continue
        try:
            n, e = parse_dkim_txt(txt)
        except Exception as exc:  # noqa: BLE001
            rep.update(status="error", detail=f"bad DKIM TXT: {exc}")
            reports.append(rep)
            continue
        try:
            sig = int.from_bytes(base64.b64decode(rep.get("b", "")), "big")
        except Exception:
            rep.update(status="error", detail="bad b= base64")
            reports.append(rep)
            continue
        h_list = [h.strip() for h in rep.get("h", "").split(":") if h.strip()]
        data = _signing_data(headers, value, [h.encode() for h in h_list])
        digest = hashlib.sha256(data).digest()
        rep["sig_valid"] = rsa_verify(n, e, digest, sig)
        if rep["bh_match"] and rep["sig_valid"]:
            rep.update(status="pass", detail="body hash and RSA signature valid")
        elif rep["sig_valid"] and not rep["bh_match"]:
            rep.update(status="fail",
                       detail="signature valid but bh MISMATCH -- body was modified after signing")
        else:
            rep.update(status="fail", detail="RSA signature INVALID")
        reports.append(rep)
    return reports


if __name__ == "__main__":
    # quick self-test: keygen -> DER round-trip -> sign -> verify -> tamper
    n, e, d = generate_rsa_key(bits=1024)
    n2, e2 = der_decode_rsa_pub(der_encode_rsa_pub(n, e))
    assert (n2, e2) == (n, e), "DER round-trip failed"
    raw = (b"From: alice@example.com\r\nTo: bob@example.org\r\n"
           b"Subject: hello\r\nDate: Thu, 08 Oct 2026 12:00:00 -0400\r\n"
           b"Message-ID: <1@example.com>\r\n\r\nHello Bob,\r\n\r\n--Alice\r\n")
    dns = {f"sel1._domainkey.example.com": dkim_dns_txt(n, e)}
    signed = sign_raw_email(raw, "example.com", "sel1", (n, e, d))
    rep = verify_raw_email(signed, dns.get)[0]
    print("sign->verify:", rep["status"], "--", rep["detail"])
    tampered = signed.replace(b"Hello Bob,", b"Hello Mallory,")
    rep2 = verify_raw_email(tampered, dns.get)[0]
    print("tampered   :", rep2["status"], "--", rep2["detail"])
    assert rep["status"] == "pass" and rep2["status"] == "fail" and rep2["sig_valid"]
    print("DKIM SELF-TEST: PASS")
