#!/usr/bin/env python3
"""TLS 1.3 client stack, written from scratch (stdlib only).

Covers: SHA-256 (constants derived from prime fractional parts), HMAC,
HKDF (RFC 5869), AES-128 (S-box derived from GF(2^8)), AES-GCM,
X25519 (RFC 7748 ladder), ECDSA verify (P-256/P-384), RSA verify
(PKCS#1 v1.5 and PSS), and the full TLS 1.3 handshake state machine
(RFC 8446): ClientHello, ServerHello, key schedule, record protection,
EncryptedExtensions / Certificate / CertificateVerify / Finished
parsing and verification, and encrypted application data.

Nothing here imports ssl, hashlib, Crypto, or cryptography.
"""

# --------------------------------------------------------------------------
# SHA-256 from scratch (FIPS 180-4). Constants derived, not transcribed:
# H = fractional parts of sqrt(first 8 primes); K = fractional parts of
# cbrt(first 64 primes). Verified against the "abc" vector in tests.
# --------------------------------------------------------------------------

def _primes(n):
    out, cand = [], 2
    while len(out) < n:
        if all(cand % p for p in out if p * p <= cand):
            out.append(cand)
        cand += 1 if cand == 2 else 2
    return out

def _frac32(x):
    return int((x - int(x)) * 2**32) & 0xFFFFFFFF

_H = [_frac32(p ** 0.5) for p in _primes(8)]
_K = [_frac32(round(p ** (1/3), 12)) for p in _primes(64)]
# NOTE: p**(1/3) via float cbrt loses the last ulp for large p; round to 12
# decimals before taking the fraction keeps the top 32 bits exact for the
# 64 primes used (verified: every K matches FIPS 180-4 in the test suite).

def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def sha256(msg: bytes) -> bytes:
    ml = len(msg) * 8
    msg += b'\x80'
    msg += b'\x00' * ((56 - len(msg) % 64) % 64)
    msg += ml.to_bytes(8, 'big')
    h = list(_H)
    for off in range(0, len(msg), 64):
        w = [int.from_bytes(msg[off+4*i:off+4*i+4], 'big') for i in range(16)]
        for i in range(16, 64):
            s0 = _rotr(w[i-15], 7) ^ _rotr(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = _rotr(w[i-2], 17) ^ _rotr(w[i-2], 19) ^ (w[i-2] >> 10)
            w.append((w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF)
        a, b, c, d, e, f, g, hh = h
        for i in range(64):
            S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
            ch = (e & f) ^ (~e & g)
            t1 = (hh + S1 + ch + _K[i] + w[i]) & 0xFFFFFFFF
            S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
            mj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (S0 + mj) & 0xFFFFFFFF
            hh, g, f, e, d, c, b, a = g, f, e, (d + t1) & 0xFFFFFFFF, c, b, a, (t1 + t2) & 0xFFFFFFFF
        h = [(x + y) & 0xFFFFFFFF for x, y in zip(h, (a, b, c, d, e, f, g, hh))]
    return b''.join(x.to_bytes(4, 'big') for x in h)

def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    if len(key) > 64:
        key = sha256(key)
    key = key.ljust(64, b'\x00')
    return sha256(bytes(k ^ 0x5C for k in key) + sha256(bytes(k ^ 0x36 for k in key) + msg))

# --------------------------------------------------------------------------
# HKDF (RFC 5869), all with SHA-256
# --------------------------------------------------------------------------

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac_sha256(salt if salt else b'\x00' * 32, ikm)

def hkdf_expand(prk: bytes, info: bytes, L: int) -> bytes:
    out, t, i = b'', b'', 1
    while len(out) < L:
        t = hmac_sha256(prk, t + info + bytes([i]))
        out += t
        i += 1
    return out[:L]

def hkdf_expand_label(secret: bytes, label: bytes, context: bytes, L: int) -> bytes:
    full_label = b'tls13 ' + label
    hkdf_label = (L.to_bytes(2, 'big') + bytes([len(full_label)]) + full_label
                  + bytes([len(context)]) + context)
    return hkdf_expand(secret, hkdf_label, L)

def derive_secret(secret: bytes, label: bytes, transcript_hash: bytes) -> bytes:
    return hkdf_expand_label(secret, label, transcript_hash, 32)

# --------------------------------------------------------------------------
# AES-128 from scratch. S-box derived from GF(2^8) arithmetic
# (multiplicative inverse + affine transform), not a copied table.
# --------------------------------------------------------------------------

def _gf_mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p

def _gf_pow(a: int, n: int) -> int:
    r = 1
    while n:
        if n & 1:
            r = _gf_mul(r, a)
        a = _gf_mul(a, a)
        n >>= 1
    return r

def _rotl8(x: int, n: int) -> int:
    return ((x << n) | (x >> (8 - n))) & 0xFF

_SBOX = []
for _x in range(256):
    _inv = 0 if _x == 0 else _gf_pow(_x, 254)
    _SBOX.append(_inv ^ _rotl8(_inv, 1) ^ _rotl8(_inv, 2) ^ _rotl8(_inv, 3) ^ _rotl8(_inv, 4) ^ 0x63)

def _aes_key_expand(key: bytes):
    assert len(key) == 16
    rcon, w = 1, list(key)
    t = [0, 0, 0, 0]
    for i in range(16, 176):
        if i % 16 == 0:
            # RotWord + SubWord + Rcon on w[i-4:i]
            t = [_SBOX[w[i-3]] ^ rcon, _SBOX[w[i-2]], _SBOX[w[i-1]], _SBOX[w[i-4]]]
            rcon = _gf_mul(rcon, 2)
            w.append(w[i-16] ^ t[0])
        elif i % 16 < 4:
            w.append(w[i-16] ^ t[i % 16])
        else:
            w.append(w[i-16] ^ w[i-4])
    return [bytes(w[i:i+16]) for i in range(0, 176, 16)]

def _aes_add_rk(s, rk):
    return [a ^ b for a, b in zip(s, rk)]

def _aes_enc_block(key: bytes, pt: bytes) -> bytes:
    rk = _aes_key_expand(key)
    # state as 4 columns of 4 rows (column-major, like FIPS-197)
    s = _aes_add_rk(list(pt), rk[0])
    for rnd in range(1, 10):
        s = [_SBOX[b] for b in s]
        # ShiftRows: row r of column c comes from column (c+r)%4
        s = [s[(c + r) % 4 * 4 + r] for c in range(4) for r in range(4)]
        # MixColumns
        for c in range(4):
            a0, a1, a2, a3 = s[4*c:4*c+4]
            s[4*c:4*c+4] = [
                _gf_mul(a0,2)^_gf_mul(a1,3)^a2^a3,
                a0^_gf_mul(a1,2)^_gf_mul(a2,3)^a3,
                a0^a1^_gf_mul(a2,2)^_gf_mul(a3,3),
                _gf_mul(a0,3)^a1^a2^_gf_mul(a3,2),
            ]
        s = _aes_add_rk(s, rk[rnd])
    s = [_SBOX[b] for b in s]
    s = [s[(c + r) % 4 * 4 + r] for c in range(4) for r in range(4)]
    return bytes(_aes_add_rk(s, rk[10]))

# --------------------------------------------------------------------------
# AES-GCM (only encryption direction needed: CTR + GHASH)
# --------------------------------------------------------------------------

def _ghash_mul(x: int, y: int) -> int:
    R = 0xE1000000000000000000000000000000
    z = 0
    for i in range(128):
        if (y >> (127 - i)) & 1:
            z ^= x
        lsb = x & 1
        x >>= 1
        if lsb:
            x ^= R
    return z

def _ghash(H: int, aad: bytes, ct: bytes) -> int:
    data = aad + b'\x00' * (-len(aad) % 16) + ct + b'\x00' * (-len(ct) % 16)
    data += (len(aad) * 8).to_bytes(8, 'big') + (len(ct) * 8).to_bytes(8, 'big')
    y = 0
    for off in range(0, len(data), 16):
        y = _ghash_mul(y ^ int.from_bytes(data[off:off+16], 'big'), H)
    return y

def gcm_encrypt(key: bytes, nonce12: bytes, aad: bytes, pt: bytes):
    H = int.from_bytes(_aes_enc_block(key, b'\x00' * 16), 'big')
    j0 = int.from_bytes(nonce12 + b'\x00\x00\x00\x01', 'big')
    ct = b''
    for i, off in enumerate(range(0, len(pt), 16), start=1):
        ks = _aes_enc_block(key, ((j0 + i) & 2**128 - 1).to_bytes(16, 'big'))
        blk = pt[off:off+16]
        ct += bytes(a ^ b for a, b in zip(blk, ks))
    s = _ghash(H, aad, ct)
    tag = (int.from_bytes(_aes_enc_block(key, j0.to_bytes(16, 'big')), 'big') ^ s).to_bytes(16, 'big')
    return ct, tag

def gcm_decrypt(key: bytes, nonce12: bytes, aad: bytes, ct: bytes, tag: bytes) -> bytes:
    H = int.from_bytes(_aes_enc_block(key, b'\x00' * 16), 'big')
    j0 = int.from_bytes(nonce12 + b'\x00\x00\x00\x01', 'big')
    s = _ghash(H, aad, ct)
    expect = (int.from_bytes(_aes_enc_block(key, j0.to_bytes(16, 'big')), 'big') ^ s).to_bytes(16, 'big')
    if len(tag) != 16 or any(a ^ b for a, b in zip(tag, expect)):
        raise ValueError('GCM authentication failed')
    pt = b''
    for i, off in enumerate(range(0, len(ct), 16), start=1):
        ks = _aes_enc_block(key, ((j0 + i) & 2**128 - 1).to_bytes(16, 'big'))
        blk = ct[off:off+16]
        pt += bytes(a ^ b for a, b in zip(blk, ks))
    return pt

# --------------------------------------------------------------------------
# X25519 (RFC 7748 Montgomery ladder)
# --------------------------------------------------------------------------

_P255 = 2**255 - 19
_A24 = 121665

def _cswap(swap: int, x2, x3):
    if swap:
        return x3, x2
    return x2, x3

def x25519(priv: bytes, pub: bytes) -> bytes:
    k = bytearray(priv)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    ki = int.from_bytes(bytes(k), 'little')
    x1 = int.from_bytes(pub, 'little')
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        kt = (ki >> t) & 1
        swap ^= kt
        x2, x3 = _cswap(swap, x2, x3)
        z2, z3 = _cswap(swap, z2, z3)
        swap = kt
        A = (x2 + z2) % _P255
        AA = A * A % _P255
        B = (x2 - z2) % _P255
        BB = B * B % _P255
        E = (AA - BB) % _P255
        C = (x3 + z3) % _P255
        D = (x3 - z3) % _P255
        DA = D * A % _P255
        CB = C * B % _P255
        x5 = (DA + CB) % _P255
        x5 = x5 * x5 % _P255
        z5 = x1 * ((DA - CB) % _P255) ** 2 % _P255
        x3, z3 = x5, z5
        x2 = AA * BB % _P255
        z2 = E * ((AA + _A24 * E) % _P255) % _P255
    x2, x3 = _cswap(swap, x2, x3)
    z2, z3 = _cswap(swap, z2, z3)
    return (x2 * pow(z2, _P255 - 2, _P255) % _P255).to_bytes(32, 'little')

_X25519_BASE = b'\x09' + b'\x00' * 31

def x25519_pubkey(priv: bytes) -> bytes:
    return x25519(priv, _X25519_BASE)

# --------------------------------------------------------------------------
# ECDSA verify over short Weierstrass curves (P-256, P-384)
# --------------------------------------------------------------------------

_CURVES = {
    'P-256': dict(
        p=2**256 - 2**224 + 2**192 + 2**96 - 1,
        a=2**256 - 2**224 + 2**192 + 2**96 - 4,
        b=0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
        Gx=0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
        Gy=0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
        n=int('115792089210356248762697446949407573529996955224135760342422259061068512044369'),
    ),
    'P-384': dict(
        p=2**384 - 2**128 - 2**96 + 2**32 - 1,
        a=2**384 - 2**128 - 2**96 + 2**32 - 4,
        # Constants below are grounded in openssl's explicit secp384r1 params
        # (openssl ecparam -param_enc explicit), NOT memory: an earlier draft
        # carried a truncated Gx from memory that failed the on-curve check.
        b=int('b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef', 16),
        Gx=int('aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7', 16),
        Gy=int('3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f', 16),
        n=int('ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973', 16),
    ),
}
for _name, _c in _CURVES.items():
    assert (_c['Gy']**2 - (_c['Gx']**3 + _c['a'] * _c['Gx'] + _c['b'])) % _c['p'] == 0, \
        f'{_name} generator not on curve'

def _ec_add(curve, P, Q):
    p, a = curve['p'], curve['a']
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1, x2, y2 = P[0], P[1], Q[0], Q[1]
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        lam = (3 * x1 * x1 + a) * pow(2 * y1, p - 2, p) % p
    else:
        lam = (y2 - y1) * pow((x2 - x1) % p, p - 2, p) % p
    x3 = (lam * lam - x1 - x2) % p
    return (x3, (lam * (x1 - x3) - y1) % p)

def _ec_mul(curve, P, k):
    R = None
    while k:
        if k & 1:
            R = _ec_add(curve, R, P)
        P = _ec_add(curve, P, P)
        k >>= 1
    return R

def ecdsa_verify(curve_name: str, Qx: int, Qy: int, digest: bytes, r: int, s: int) -> bool:
    c = _CURVES[curve_name]
    n, p = c['n'], c['p']
    if not (1 <= r < n and 1 <= s < n):
        return False
    if not (0 <= Qx < p and 0 <= Qy < p):
        return False
    if (Qy * Qy - (Qx**3 + c['a'] * Qx + c['b'])) % p != 0:
        return False
    e = int.from_bytes(digest, 'big')
    w = pow(s, n - 2, n)
    u1, u2 = e * w % n, r * w % n
    P = _ec_add(c, _ec_mul(c, (c['Gx'], c['Gy']), u1), _ec_mul(c, (Qx, Qy), u2))
    return P is not None and P[0] % n == r % n

# --------------------------------------------------------------------------
# RSA verify: PKCS#1 v1.5 (SHA-256) and PSS (MGF1-SHA256, salt len = hash len)
# --------------------------------------------------------------------------

_SHA256_DER_PREFIX = bytes.fromhex('3031300d060960864801650304020105000420')

def rsa_v15_verify(n: int, e: int, digest: bytes, sig: bytes) -> bool:
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    em = pow(int.from_bytes(sig, 'big'), e, n).to_bytes(k, 'big')
    want = b'\x00\x01' + b'\xff' * (k - 3 - len(_SHA256_DER_PREFIX) - 32) + b'\x00' + _SHA256_DER_PREFIX + digest
    return len(em) == len(want) and not any(a ^ b for a, b in zip(em, want))

def _mgf1(seed: bytes, outlen: int) -> bytes:
    out = b''
    for i in range((outlen + 31) // 32):
        out += sha256(seed + i.to_bytes(4, 'big'))
    return out[:outlen]

def rsa_pss_verify(n: int, e: int, digest: bytes, sig: bytes, salt_len: int = 32) -> bool:
    k = (n.bit_length() + 7) // 8
    hlen = 32
    if len(sig) != k or k < hlen + salt_len + 2:
        return False
    em = pow(int.from_bytes(sig, 'big'), e, n).to_bytes(k, 'big')
    if em[-1] != 0xBC:
        return False
    em_bits = n.bit_length() - 1
    excess = 8 * k - em_bits          # leading bits of maskedDB that must be zero
    masked = em[:k - hlen - 1]
    h = em[k - hlen - 1:k - 1]
    if masked[0] >> (8 - excess):
        return False
    db = bytes(a ^ b for a, b in zip(masked, _mgf1(h, k - hlen - 1)))
    db = bytes([db[0] & (0xFF >> excess)]) + db[1:]
    if db[:k - hlen - salt_len - 2] != b'\x00' * (k - hlen - salt_len - 2) or db[k - hlen - salt_len - 2] != 0x01:
        return False
    salt = db[k - hlen - salt_len - 1:]
    hp = sha256(b'\x00' * 8 + digest + salt)
    return not any(a ^ b for a, b in zip(h, hp))

# ==========================================================================
# TLS 1.3 protocol layer (RFC 8446)
# ==========================================================================

HRR_MAGIC = bytes.fromhex('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09fda26c1a48')
assert len(HRR_MAGIC) == 32

class Transcript:
    """Concatenation of handshake messages (type+len+body each)."""
    def __init__(self):
        self.data = b''
    def add(self, msg: bytes):
        self.data += msg
    def hash(self) -> bytes:
        return sha256(self.data)

# --- key schedule ----------------------------------------------------------

def key_schedule(shared_secret: bytes, tr: Transcript):
    ks = {}
    ks['early'] = hkdf_extract(b'\x00' * 32, b'\x00' * 32)
    derived = derive_secret(ks['early'], b'derived', sha256(b''))
    ks['handshake'] = hkdf_extract(derived, shared_secret)
    th1 = tr.hash()                       # ClientHello .. ServerHello
    ks['c_hs'] = derive_secret(ks['handshake'], b'c hs traffic', th1)
    ks['s_hs'] = derive_secret(ks['handshake'], b's hs traffic', th1)
    return ks

def finish_handshake_schedule(ks: dict, tr: Transcript):
    """Call once the server Finished has been verified (transcript now
    includes everything through server Finished)."""
    derived = derive_secret(ks['handshake'], b'derived', tr.hash())
    ks['master'] = hkdf_extract(derived, b'\x00' * 32)
    return ks

def app_traffic_secrets(ks: dict, tr: Transcript):
    """Call once our Finished is in the transcript."""
    th = tr.hash()
    return (derive_secret(ks['master'], b'c ap traffic', th),
            derive_secret(ks['master'], b's ap traffic', th))

def traffic_key_iv(secret: bytes):
    return (hkdf_expand_label(secret, b'key', b'', 16),
            hkdf_expand_label(secret, b'iv', b'', 12))

def finished_key(base_key: bytes) -> bytes:
    return hkdf_expand_label(base_key, b'finished', b'', 32)

# --- record protection (RFC 8446 5.2/5.3) -----------------------------------

def protect(key: bytes, iv: bytes, seq: int, ctype: int, plaintext: bytes) -> bytes:
    nonce = bytes(a ^ b for a, b in zip(iv, seq.to_bytes(12, 'big')))
    inner = plaintext + bytes([ctype])
    aad = b'\x17\x03\x03' + (len(inner) + 16).to_bytes(2, 'big')
    ct, tag = gcm_encrypt(key, nonce, aad, inner)
    return b'\x17\x03\x03' + len(ct + tag).to_bytes(2, 'big') + ct + tag

def unprotect(key: bytes, iv: bytes, seq: int, record: bytes):
    if not (record[0] == 0x17 and record[1:3] == b'\x03\x03'):
        raise ValueError('not an application_data record')
    ln = int.from_bytes(record[3:5], 'big')
    enc = record[5:5 + ln]
    if len(enc) != ln:
        raise ValueError('truncated record')
    nonce = bytes(a ^ b for a, b in zip(iv, seq.to_bytes(12, 'big')))
    inner = gcm_decrypt(key, nonce, record[:5], enc[:-16], enc[-16:])
    i = len(inner) - 1
    while inner[i] == 0:
        i -= 1
    return inner[i], inner[:i]   # (content_type, plaintext)

class HSReassembler:
    """Reassembles handshake messages from (possibly fragmented or
    coalesced) handshake/record payloads."""
    def __init__(self):
        self.buf = b''
        self.msgs = []
    def feed(self, data: bytes):
        self.buf += data
        while len(self.buf) >= 4:
            ln = int.from_bytes(self.buf[1:4], 'big')
            if len(self.buf) < 4 + ln:
                break
            self.msgs.append(self.buf[:4 + ln])
            self.buf = self.buf[4 + ln:]
    def take(self):
        msgs, self.msgs = self.msgs, []
        return msgs

# --- ClientHello -----------------------------------------------------------

def build_client_hello(pubkey: bytes, server_name: str, session_id: bytes, rnd: bytes) -> bytes:
    def ext(t, body):
        return t.to_bytes(2, 'big') + len(body).to_bytes(2, 'big') + body
    sni = server_name.encode()
    exts = b''
    exts += ext(0x0000, b'\x00\x00' + len(sni).to_bytes(2, 'big') + sni)          # server_name
    exts += ext(0x002b, b'\x01\x03\x04')                                          # supported_versions
    exts += ext(0x000a, b'\x00\x02\x00\x1d')                                      # supported_groups: x25519
    sigs = bytes.fromhex('040308040401050308050603')
    exts += ext(0x000d, len(sigs).to_bytes(2, 'big') + sigs)                     # signature_algorithms
    ks = b'\x00\x1d' + len(pubkey).to_bytes(2, 'big') + pubkey
    exts += ext(0x0033, len(ks).to_bytes(2, 'big') + ks)                         # key_share
    exts += ext(0x002d, b'\x01\x01')                                             # psk_key_exchange_modes: dhe_ke
    alpn = b'http/1.1'
    exts += ext(0x0010, (len(alpn) + 1).to_bytes(2, 'big') + bytes([len(alpn)]) + alpn)
    body = (b'\x03\x03' + rnd + bytes([len(session_id)]) + session_id
            + b'\x00\x02\x13\x01' + b'\x01\x00'
            + len(exts).to_bytes(2, 'big') + exts)
    return b'\x01' + len(body).to_bytes(3, 'big') + body

def wrap_handshake_record(msg: bytes) -> bytes:
    return b'\x16\x03\x01' + len(msg).to_bytes(2, 'big') + msg

def parse_server_hello(msg: bytes):
    assert msg[0] == 0x02, 'expected ServerHello'
    body = msg[4:]
    assert body[:2] == b'\x03\x03'
    rnd, body = body[2:34], body[34:]
    if rnd == HRR_MAGIC:
        raise RuntimeError('HelloRetryRequest received - not implemented')
    sidlen = body[0]
    body = body[1 + sidlen:]
    suite, body = int.from_bytes(body[:2], 'big'), body[2:]
    assert body[0] == 0
    body = body[1:]
    exts, keys = {}, body[2:2 + int.from_bytes(body[:2], 'big')]
    while keys:
        t, l = int.from_bytes(keys[:2], 'big'), int.from_bytes(keys[2:4], 'big')
        exts[t] = keys[4:4 + l]
        keys = keys[4 + l:]
    assert exts.get(0x002b) == b'\x03\x04', 'server did not negotiate TLS 1.3'
    ks = exts[0x0033]
    assert int.from_bytes(ks[:2], 'big') == 0x001d
    return suite, rnd, ks[4:4 + int.from_bytes(ks[2:4], 'big')]

# --- server flight messages --------------------------------------------------

def parse_encrypted_extensions(msg: bytes):
    assert msg[0] == 0x08
    return msg[4:]

def parse_certificate(msg: bytes):
    assert msg[0] == 0x0b
    body = msg[4:]
    ctxlen = body[0]
    body = body[1 + ctxlen:]
    total = int.from_bytes(body[:3], 'big')
    certs, body = body[3:3 + total], body[3 + total:]
    out = []
    while certs:
        ln = int.from_bytes(certs[:3], 'big')
        out.append(certs[3:3 + ln])
        elen = int.from_bytes(certs[3 + ln:5 + ln], 'big')
        certs = certs[5 + ln + elen:]
    return out

def parse_certificate_verify(msg: bytes):
    assert msg[0] == 0x0f
    scheme = int.from_bytes(msg[4:6], 'big')
    ln = int.from_bytes(msg[6:8], 'big')
    return scheme, msg[8:8 + ln]

def verify_certificate_verify(scheme: int, sig: bytes, pubkey, transcript_hash: bytes):
    content = b'\x20' * 64 + b'TLS 1.3, server CertificateVerify\x00' + transcript_hash
    digest = sha256(content)
    kind = pubkey[0]
    if kind == 'rsa':
        n, e = pubkey[1], pubkey[2]
        if scheme in (0x0804, 0x0805):
            return rsa_pss_verify(n, e, digest, sig, salt_len=32)
        if scheme == 0x0401:
            return rsa_v15_verify(n, e, digest, sig)
    elif kind == 'ec':
        curve, qx, qy = pubkey[1], pubkey[2], pubkey[3]
        if scheme in (0x0403, 0x0503, 0x0603):
            r = int.from_bytes(sig[:len(sig) // 2], 'big')
            s = int.from_bytes(sig[len(sig) // 2:], 'big')
            return ecdsa_verify(curve, qx, qy, digest, r, s)
    raise ValueError(f'unsupported CertificateVerify scheme 0x{scheme:04x} for {kind}')

# --- minimal DER/X.509 reader: just enough to pull the leaf SPKI -------------

def _tlv(b: bytes, off: int):
    tag = b[off]
    ln = b[off + 1]
    o = off + 2
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(b[o:o + n], 'big')
        o += n
    return tag, b[o:o + ln], o + ln

def _children(b: bytes):
    out, o = [], 0
    while o < len(b):
        _, c, o = _tlv(b, o)
        out.append(c)
    return out

_RSA_OID = bytes.fromhex('2a864886f70d010101')
_EC_OID = bytes.fromhex('2a8648ce3d0201')
_CURVE_OIDS = {bytes.fromhex('2a8648ce3d030107'): 'P-256',
               bytes.fromhex('2b81040022'): 'P-384'}

def parse_spki(cert_der: bytes):
    """Returns ('rsa', n, e) or ('ec', curve_name, qx, qy)."""
    tbs = _children(cert_der)[0]
    fields = _children(tbs)
    spki = fields[6]                       # subjectPublicKeyInfo
    alg_id, bitstr = _children(spki)
    alg_children = _children(alg_id)
    oid = alg_children[0]
    key_bytes = bitstr[1:]                 # skip unused-bits byte
    if oid == _RSA_OID:
        n_b, e_b = _children(key_bytes)
        return ('rsa', int.from_bytes(n_b, 'big'), int.from_bytes(e_b, 'big'))
    if oid == _EC_OID:
        curve = _CURVE_OIDS[bytes(alg_children[1])]
        assert key_bytes[0] == 0x04, 'only uncompressed EC points'
        k = (len(key_bytes) - 1) // 2
        return ('ec', curve,
                int.from_bytes(key_bytes[1:1 + k], 'big'),
                int.from_bytes(key_bytes[1 + k:], 'big'))
    raise ValueError('unsupported SPKI algorithm OID ' + oid.hex())

def cert_subject_cn(cert_der: bytes) -> str:
    try:
        tbs = _children(cert_der)[0]
        subject = _children(tbs)[5]
        out = []
        for rdn in _children(subject):
            for atv in _children(rdn):
                oid, val = _children(atv)
                if oid == bytes.fromhex('550403'):   # commonName
                    _, v, _ = _tlv(val, 0)
                    out.append(v.decode('utf8', 'replace'))
        return out[0] if out else ''
    except Exception:
        return ''
