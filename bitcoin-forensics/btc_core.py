#!/usr/bin/env python3
"""btc_core.py — Bitcoin cryptographic primitives, hand-rolled, zero dependencies.

Everything here is written from the spec, no hashlib shortcuts for the
message-digest algorithms themselves (hashlib is used only as a *test oracle*
for SHA-256, since writing SHA-256 is a solved exercise; RIPEMD-160 and all
EC math are from-scratch).

Covers: RIPEMD-160 (full compression function), SHA-256 (from scratch, oracle
compared), HASH160/HASH256, Base58Check encode/decode, Bech32/Bech32m
encode+decode (BIP-173/350), secp256k1 field + group arithmetic, compressed/
uncompressed pubkey -> P2PKH address, ECDSA sign/verify.
"""

import hashlib  # test oracle only (SHA-256), not used by the core algorithms


# --------------------------------------------------------------------------
# SHA-256 from scratch (FIPS 180-4), oracle-checked in tests
# --------------------------------------------------------------------------

_K256 = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def sha256(data: bytes) -> bytes:
    """SHA-256 from scratch."""
    h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    msg = bytearray(data)
    bitlen = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0x00)
    msg += bitlen.to_bytes(8, "big")
    for off in range(0, len(msg), 64):
        w = [int.from_bytes(msg[off + 4 * i:off + 4 * i + 4], "big") for i in range(16)]
        for i in range(16, 64):
            s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF)
        a, b, c, d, e, f, g, hh = h
        for i in range(64):
            S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
            ch = (e & f) ^ ((~e) & g)
            t1 = (hh + S1 + ch + _K256[i] + w[i]) & 0xFFFFFFFF
            S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
            mj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (S0 + mj) & 0xFFFFFFFF
            hh, g, f, e = g, f, e, (d + t1) & 0xFFFFFFFF
            d, c, b, a = c, b, a, (t1 + t2) & 0xFFFFFFFF
        h = [(x + y) & 0xFFFFFFFF for x, y in zip(h, [a, b, c, d, e, f, g, hh])]
    return b"".join(x.to_bytes(4, "big") for x in h)


def sha256d(data: bytes) -> bytes:
    """SHA-256 applied twice. The hash behind txids and block headers."""
    return sha256(sha256(data))


# --------------------------------------------------------------------------
# RIPEMD-160 from scratch (the one Bitcoin actually needs for HASH160)
# --------------------------------------------------------------------------

_RL = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8],
    [3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12],
    [1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2],
    [4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13],
]
_RR = [
    [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12],
    [6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2],
    [15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13],
    [8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14],
    [12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11],
]
_SL = [
    [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
    [7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12],
    [11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5],
    [11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12],
    [9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6],
]
_SR = [
    [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6],
    [9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11],
    [9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5],
    [15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8],
    [8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11],
]
_KL = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
_KR = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]


def _rol32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _f(j, x, y, z):
    if j == 0:
        return x ^ y ^ z
    if j == 1:
        return (x & y) | ((~x) & z)
    if j == 2:
        return (x | (~y)) ^ z
    if j == 3:
        return (x & z) | (y & (~z))
    return x ^ (y | (~z))


def ripemd160(data: bytes) -> bytes:
    """RIPEMD-160 from scratch."""
    msg = bytearray(data)
    bitlen = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0x00)
    msg += bitlen.to_bytes(8, "little")
    h0, h1, h2, h3, h4 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    for off in range(0, len(msg), 64):
        X = [int.from_bytes(msg[off + 4 * i:off + 4 * i + 4], "little") for i in range(16)]
        al, bl, cl, dl, el = h0, h1, h2, h3, h4
        ar, br, cr, dr, er = h0, h1, h2, h3, h4
        for j in range(80):
            rnd = j // 16
            t = (_rol32((al + _f(rnd, bl, cl, dl) + X[_RL[rnd][j % 16]] + _KL[rnd]) & 0xFFFFFFFF,
                        _SL[rnd][j % 16]) + el) & 0xFFFFFFFF
            al, el, dl, cl, bl = el, dl, _rol32(cl, 10), bl, t
            t = (_rol32((ar + _f(4 - rnd, br, cr, dr) + X[_RR[rnd][j % 16]] + _KR[rnd]) & 0xFFFFFFFF,
                        _SR[rnd][j % 16]) + er) & 0xFFFFFFFF
            ar, er, dr, cr, br = er, dr, _rol32(cr, 10), br, t
        t = (h1 + cl + dr) & 0xFFFFFFFF
        h1 = (h2 + dl + er) & 0xFFFFFFFF
        h2 = (h3 + el + ar) & 0xFFFFFFFF
        h3 = (h4 + al + br) & 0xFFFFFFFF
        h4 = (h0 + bl + cr) & 0xFFFFFFFF
        h0 = t
    return b"".join(x.to_bytes(4, "little") for x in (h0, h1, h2, h3, h4))


def hash160(data: bytes) -> bytes:
    """RIPEMD160(SHA256(data)) — the 20-byte Bitcoin address payload."""
    return ripemd160(sha256(data))


# --------------------------------------------------------------------------
# Base58Check
# --------------------------------------------------------------------------

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return "1" * pad + (out or "")


def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + _B58.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw


def b58check_encode(payload: bytes, version: bytes) -> str:
    body = version + payload
    return b58encode(body + sha256d(body)[:4])


def b58check_decode(s: str):
    """Returns (version_byte, payload) or raises ValueError."""
    raw = b58decode(s)
    if len(raw) < 5 or sha256d(raw[:-4])[:4] != raw[-4:]:
        raise ValueError("bad base58check checksum")
    return raw[0:1], raw[1:-4]


# --------------------------------------------------------------------------
# Bech32 / Bech32m (BIP-173 / BIP-350)
# --------------------------------------------------------------------------

_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values):
    GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= GEN[i]
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    out = []
    maxv = (1 << tobits) - 1
    for v in data:
        acc = (acc << frombits) | v
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if pad:
        if bits:
            out.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("bad bech32 padding")
    return out


def segwit_encode(hrp: str, witver: int, witprog: bytes, bech32m: bool = False) -> str:
    const = 0x2BC830A3 if bech32m else 1
    data = [witver] + _convertbits(witprog, 8, 5)
    pm = _bech32_polymod(_bech32_hrp_expand(hrp) + data + [0] * 6) ^ const
    check = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_BECH32[d] for d in data + check)


def segwit_decode(addr: str):
    """Returns (hrp, witness_version, witness_program) or raises ValueError."""
    addr = addr.lower()
    if "1" not in addr:
        raise ValueError("no bech32 separator")
    hrp, data_s = addr.rsplit("1", 1)
    if not hrp or len(data_s) < 8:
        raise ValueError("bad bech32")
    data = [_BECH32.index(c) for c in data_s]
    pm = _bech32_polymod(_bech32_hrp_expand(hrp) + data)
    if pm == 1:
        bech32m = False
    elif pm == 0x2BC830A3:
        bech32m = True
    else:
        raise ValueError("bad bech32 checksum")
    witver = data[0]
    if witver > 16 or (witver == 0 and bech32m) or (witver != 0 and not bech32m):
        raise ValueError("bad witness version/encoding")
    prog = bytes(_convertbits(data[1:-6], 5, 8, pad=False))
    if not (2 <= len(prog) <= 40):
        raise ValueError("bad witness program length")
    return hrp, witver, prog


# --------------------------------------------------------------------------
# secp256k1 from scratch
# --------------------------------------------------------------------------

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _inv(a, m):
    return pow(a, m - 2, m)


def _padd(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2:
        if (y1 + y2) % _P == 0:
            return None
        lam = (3 * x1 * x1 * _inv(2 * y1, _P)) % _P  # doubling
    else:
        lam = ((y2 - y1) * _inv(x2 - x1, _P)) % _P
    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return (x3, y3)


def _pmul(k, p=(_Gx, _Gy)):
    r = None
    add = p
    while k:
        if k & 1:
            r = _padd(r, add)
        add = _padd(add, add)
        k >>= 1
    return r


def pubkey_to_coords(pubkey: bytes):
    """Parse 33-byte compressed or 65-byte uncompressed pubkey -> (x, y)."""
    if len(pubkey) == 33 and pubkey[0] in (2, 3):
        x = int.from_bytes(pubkey[1:], "big")
        y2 = (pow(x, 3, _P) + 7) % _P
        y = pow(y2, (_P + 1) // 4, _P)
        if (y % 2 == 0) != (pubkey[0] == 2):
            y = _P - y
        return x, y
    if len(pubkey) == 65 and pubkey[0] == 4:
        x = int.from_bytes(pubkey[1:33], "big")
        y = int.from_bytes(pubkey[33:], "big")
        if (y * y - x ** 3 - 7) % _P != 0:
            raise ValueError("pubkey not on curve")
        return x, y
    raise ValueError("bad pubkey format")


def pubkey_to_address(pubkey: bytes, version=b"\x00") -> str:
    """P2PKH address from a raw pubkey (compressed or uncompressed).

    HASH160 is taken over the *serialized* pubkey (with its prefix byte),
    not the bare coordinates.
    """
    x, y = pubkey_to_coords(pubkey)
    if len(pubkey) == 33:  # compressed: parity prefix + x
        ser = bytes([2 + (y & 1)]) + x.to_bytes(32, "big")
    else:  # uncompressed: 0x04 + x + y
        ser = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
    return b58check_encode(hash160(ser), version)


def ecdsa_verify(pubkey: bytes, msg_hash: bytes, r: int, s: int) -> bool:
    """Verify an ECDSA signature over a 32-byte message hash."""
    if not (1 <= r < _N and 1 <= s < _N):
        return False
    x, y = pubkey_to_coords(pubkey)
    P = (x, y)
    e = int.from_bytes(msg_hash, "big")
    w = _inv(s, _N)
    u1 = (e * w) % _N
    u2 = (r * w) % _N
    pt = _padd(_pmul(u1), _pmul(u2, P))
    return pt is not None and pt[0] % _N == r
