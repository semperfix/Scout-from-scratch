"""Elliptic-curve signatures for X.509, from scratch. Zero dependencies.

Two families:
  * ECDSA over NIST P-256 / P-384 (the curves real web certs use).
  * Ed25519 (RFC 8032) verification.

The group arithmetic is the same short-Weierstrass ladder I built for
secp256k1 in the Bitcoin expedition, generalized to named parameters.
Ed25519 uses twisted-Edwards extended coordinates instead.
"""

import hashlib


# --------------------------------------------------------------------------
# Generic short-Weierstrass ECDSA
# --------------------------------------------------------------------------

class Curve:
    def __init__(self, name, p, a, b, gx, gy, n, h=1):
        self.name = name
        self.p = p
        self.a = a
        self.b = b
        self.G = (gx, gy)
        self.n = n
        self.h = h

    def _inv(self, x):
        return pow(x, self.p - 2, self.p)

    def add(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2:
            if (y1 + y2) % self.p == 0:
                return None
            lam = (3 * x1 * x1 + self.a) * self._inv(2 * y1) % self.p
        else:
            lam = (y2 - y1) * self._inv(x2 - x1) % self.p
        x3 = (lam * lam - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def mul(self, k, P=None):
        P = P or self.G
        k = k % self.n
        R = None
        while k:
            if k & 1:
                R = self.add(R, P)
            P = self.add(P, P)
            k >>= 1
        return R

    def on_curve(self, x, y):
        return (y * y - (x * x * x + self.a * x + self.b)) % self.p == 0


# Curve parameters verified against `openssl ecparam -param_enc explicit`
# (2026-10-08) -- never trust memorized constants; a single garbled digit
# silently breaks every signature. See README "the P-384 incident".
P256 = Curve(
    "secp256r1",
    p=0x00FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    a=0x00FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
    b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    n=0x00FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
)

P384 = Curve(
    "secp384r1",
    p=0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF,
    a=0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC,
    b=0x00B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
    gx=0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
    gy=0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F,
    n=0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
)


P521 = Curve(
    "secp521r1",
    p=0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
    a=0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC,
    b=0x51953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00,
    gx=0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66,
    gy=0x011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650,
    n=0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409,
)


CURVES = {"secp256r1": P256, "secp384r1": P384, "secp521r1": P521}


def parse_ec_point(key_bytes: bytes, curve: Curve):
    """Uncompressed 0x04||X||Y point -> (x, y), validated on curve."""
    if not key_bytes or key_bytes[0] != 0x04:
        raise ValueError("only uncompressed EC points supported")
    size = (len(key_bytes) - 1) // 2
    if 1 + 2 * size != len(key_bytes):
        raise ValueError("bad EC point length")
    x = int.from_bytes(key_bytes[1:1 + size], "big")
    y = int.from_bytes(key_bytes[1 + size:], "big")
    if not curve.on_curve(x, y):
        raise ValueError("EC public key not on curve")
    return (x, y)


def ecdsa_verify(curve: Curve, pub_xy, digest: bytes, r: int, s: int) -> bool:
    """ECDSA verify. digest is the hash output bytes (truncated to n bits)."""
    n = curve.n
    if not (1 <= r < n and 1 <= s < n):
        return False
    e = int.from_bytes(digest, "big")
    if len(digest) * 8 > n.bit_length():  # truncate leftmost excess bits
        e >>= len(digest) * 8 - n.bit_length()
    w = pow(s, -1, n)
    u1 = (e * w) % n
    u2 = (r * w) % n
    pt = curve.add(curve.mul(u1), curve.mul(u2, pub_xy))
    return pt is not None and pt[0] % n == r


# --------------------------------------------------------------------------
# Ed25519 (RFC 8032) -- verification only
# --------------------------------------------------------------------------

_Q = 2 ** 255 - 19
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)  # sqrt(-1) mod q


def _ed_inv(x):
    return pow(x, _Q - 2, _Q)


def _ed_decode_point(s: bytes):
    """Decode 32-byte compressed Edwards point -> (x, y)."""
    if len(s) != 32:
        raise ValueError("bad Ed25519 point length")
    y = int.from_bytes(s, "little") & ~(1 << 255)
    x_sign = (s[31] >> 7) & 1
    # x = sqrt((y^2 - 1) / (d*y^2 + 1))
    y2 = y * y % _Q
    x2 = (y2 - 1) * _ed_inv(_D * y2 + 1) % _Q
    x = pow(x2, (_Q + 3) // 8, _Q)
    if (x * x - x2) % _Q != 0:
        x = x * _I % _Q
    if x & 1 != x_sign:
        x = _Q - x
    return (x, y)


def _ed_encode_point(P) -> bytes:
    x, y = P
    return ((y | ((x & 1) << 255))).to_bytes(32, "little")


def _ed_add(P, Q):
    # Affine twisted-Edwards addition for a = -1 (Ed25519):
    #   x3 = (x1*y2 + x2*y1) / (1 + d*x1*x2*y1*y2)
    #   y3 = (y1*y2 - a*x1*x2) / (1 - d*x1*x2*y1*y2)  with a=-1 -> plus sign
    x1, y1 = P
    x2, y2 = Q
    den1 = (1 + _D * x1 * x2 * y1 * y2) % _Q
    den2 = (1 - _D * x1 * x2 * y1 * y2) % _Q
    x3 = (x1 * y2 + x2 * y1) * _ed_inv(den1) % _Q
    y3 = (y1 * y2 + x1 * x2) * _ed_inv(den2) % _Q
    return (x3, y3)


_IDENTITY = (0, 1)


def _ed_mul(P, k):
    R = _IDENTITY
    while k:
        if k & 1:
            R = _ed_add(R, P)
        P = _ed_add(P, P)
        k >>= 1
    return R


# Base point, RFC 8032 section 5.1 (y = 4/5, x odd)
_ED_G = _ed_decode_point(bytes.fromhex(
    "5866666666666666666666666666666666666666666666666666666666666666"))

_L = 2 ** 252 + 27742317777372353535851937790883648493  # group order


def ed25519_pubkey_from_seed(seed: bytes) -> bytes:
    """Derive public key from 32-byte seed (for self-tests)."""
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    # RFC 8032 clamping: clear bits 0,1,2 and 255, set bit 254
    a = (a & ~(1 | 2 | 4 | (1 << 255))) | (1 << 254)
    A = _ed_mul(_ED_G, a)
    return _ed_encode_point(A)


def ed25519_sign(seed: bytes, msg: bytes) -> bytes:
    """Deterministic RFC 8032 sign (for self-tests)."""
    h = hashlib.sha512(seed).digest()
    a = (int.from_bytes(h[:32], "little") & ~(1 | 2 | 4 | (1 << 255))) | (1 << 254)
    prefix = h[32:]
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % _L
    R = _ed_mul(_ED_G, r)
    Renc = _ed_encode_point(R)
    Aenc = ed25519_pubkey_from_seed(seed)
    k = int.from_bytes(hashlib.sha512(Renc + Aenc + msg).digest(), "little") % _L
    S = (r + k * a) % _L
    return Renc + S.to_bytes(32, "little")


def ed25519_verify(pubkey: bytes, msg: bytes, sig: bytes) -> bool:
    """RFC 8032 section 5.1.7 verification."""
    if len(sig) != 64 or len(pubkey) != 32:
        return False
    Renc, Senc = sig[:32], sig[32:]
    S = int.from_bytes(Senc, "little")
    if S >= _L:
        return False
    try:
        R = _ed_decode_point(Renc)
        A = _ed_decode_point(pubkey)
    except ValueError:
        return False
    # low-order check on A is skipped (acceptable for cert forensics)
    k = int.from_bytes(hashlib.sha512(Renc + pubkey + msg).digest(), "little") % _L
    lhs = _ed_mul(_ED_G, S)
    rhs = _ed_add(R, _ed_mul(A, k))
    return _ed_encode_point(lhs) == _ed_encode_point(rhs)
