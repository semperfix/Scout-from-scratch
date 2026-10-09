"""AES-256 + GCM + HKDF, written from scratch (stdlib only).
New vs expedition #8 (AES-128 ECB/CBC): AES-256's 14-round key schedule,
GHASH in GF(2^128) + GCM authenticated encryption, and HKDF key expansion.
Used by the WhatsApp crypt14/crypt15 backup decryptor.
"""
import hashlib, hmac as hmac_mod, os

# ---------- AES ----------
def _gf_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi: a ^= 0x1B
        b >>= 1
    return p

# S-box built from the math, not a copied table: x -> affine(x^-1 in GF(2^8))
def _build_sbox():
    sbox, inv = [0]*256, [0]*256
    for x in range(256):
        if x == 0:
            inv_x = 0
        else:
            inv_x = next(y for y in range(256) if _gf_mul(x, y) == 1)
        # affine: inv ^ rotl(inv,1) ^ rotl(inv,2) ^ rotl(inv,3) ^ rotl(inv,4) ^ 0x63
        def rotl(b, n):
            return ((b << n) | (b >> (8 - n))) & 0xFF
        aff = inv_x ^ rotl(inv_x, 1) ^ rotl(inv_x, 2) ^ rotl(inv_x, 3) ^ rotl(inv_x, 4) ^ 0x63
        sbox[x] = aff
    for x in range(256):
        inv[sbox[x]] = x
    return sbox, inv

_SBOX, _INV_SBOX = _build_sbox()

def _rcon(i):
    r = 1
    for _ in range(i - 1):
        r = _gf_mul(r, 2)
    return r

def aes256_key_schedule(key: bytes):
    assert len(key) == 32
    Nk, Nb, Nr = 8, 4, 14
    w = [int.from_bytes(key[i*4:(i+1)*4], 'big') for i in range(Nk)]
    for i in range(Nk, Nb*(Nr+1)):
        temp = w[i-1]
        if i % Nk == 0:
            temp = (_SBOX[(temp >> 16) & 0xFF] << 24 | _SBOX[(temp >> 8) & 0xFF] << 16
                    | _SBOX[temp & 0xFF] << 8 | _SBOX[(temp >> 24) & 0xFF]) ^ (_rcon(i // Nk) << 24)
        elif Nk > 6 and i % Nk == 4:
            temp = (_SBOX[(temp >> 24) & 0xFF] << 24 | _SBOX[(temp >> 16) & 0xFF] << 16
                    | _SBOX[(temp >> 8) & 0xFF] << 8 | _SBOX[temp & 0xFF])
        w.append(w[i-Nk] ^ temp)
    rks = [b''.join(w[i*4+j].to_bytes(4, 'big') for j in range(4)) for i in range(Nr+1)]
    return rks

def _add_rk(s, rk):
    return bytes(a ^ b for a, b in zip(s, rk))

def aes256_encrypt_block(key: bytes, pt: bytes) -> bytes:
    assert len(pt) == 16
    rks = aes256_key_schedule(key)
    s = _add_rk(pt, rks[0])
    for r in range(1, 14):
        # SubBytes + ShiftRows (shift LEFT by row): t[r][c] = S(s[r][(c+r)%4])
        t = bytearray(16)
        for row in range(4):
            for col in range(4):
                t[row + 4*col] = _SBOX[s[row + 4*((col + row) % 4)]]
        # MixColumns
        u = bytearray(16)
        for col in range(4):
            a0, a1, a2, a3 = t[col*4], t[col*4+1], t[col*4+2], t[col*4+3]
            u[col*4]   = _gf_mul(a0,2) ^ _gf_mul(a1,3) ^ a2 ^ a3
            u[col*4+1] = a0 ^ _gf_mul(a1,2) ^ _gf_mul(a2,3) ^ a3
            u[col*4+2] = a0 ^ a1 ^ _gf_mul(a2,2) ^ _gf_mul(a3,3)
            u[col*4+3] = _gf_mul(a0,3) ^ a1 ^ a2 ^ _gf_mul(a3,2)
        s = _add_rk(bytes(u), rks[r])
    # final round: SubBytes + ShiftRows, no MixColumns
    t = bytearray(16)
    for row in range(4):
        for col in range(4):
            t[row + 4*col] = _SBOX[s[row + 4*((col + row) % 4)]]
    return _add_rk(bytes(t), rks[14])

def aes256_decrypt_block(key: bytes, ct: bytes) -> bytes:
    assert len(ct) == 16
    rks = aes256_key_schedule(key)
    s = _add_rk(ct, rks[14])
    for r in range(13, 0, -1):
        # InvShiftRows + InvSubBytes
        t = bytearray(16)
        for row in range(4):
            for col in range(4):
                t[row + 4*col] = _INV_SBOX[s[row + 4*((col - row) % 4)]]
        s = _add_rk(bytes(t), rks[r])
        # InvMixColumns
        u = bytearray(16)
        for col in range(4):
            a0, a1, a2, a3 = s[col*4], s[col*4+1], s[col*4+2], s[col*4+3]
            u[col*4]   = _gf_mul(a0,0x0e) ^ _gf_mul(a1,0x0b) ^ _gf_mul(a2,0x0d) ^ _gf_mul(a3,0x09)
            u[col*4+1] = _gf_mul(a0,0x09) ^ _gf_mul(a1,0x0e) ^ _gf_mul(a2,0x0b) ^ _gf_mul(a3,0x0d)
            u[col*4+2] = _gf_mul(a0,0x0d) ^ _gf_mul(a1,0x09) ^ _gf_mul(a2,0x0e) ^ _gf_mul(a3,0x0b)
            u[col*4+3] = _gf_mul(a0,0x0b) ^ _gf_mul(a1,0x0d) ^ _gf_mul(a2,0x09) ^ _gf_mul(a3,0x0e)
        s = bytes(u)
    t = bytearray(16)
    for row in range(4):
        for col in range(4):
            t[row + 4*col] = _INV_SBOX[s[row + 4*((col - row) % 4)]]
    return _add_rk(bytes(t), rks[0])

# ---------- GCM ----------
_R = 0xE1000000000000000000000000000000  # x^128 + x^7 + x^2 + x + 1 reflected

def _gf128_mul(x: int, y: int) -> int:
    z = 0
    for i in range(128):
        if (y >> (127 - i)) & 1:
            z ^= x
        # multiply x by x (i.e. shift right in the reflected representation)
        lsb = x & 1
        x >>= 1
        if lsb:
            x ^= _R
    return z

_H_CACHE = {}
def _ghash(H: int, aad: bytes, ct: bytes) -> int:
    y = 0
    def blocks(b):
        b = b + b'\x00' * ((-len(b)) % 16)
        for i in range(0, len(b), 16):
            yield int.from_bytes(b[i:i+16], 'big')
    for blk in blocks(aad):
        y = _gf128_mul(y ^ blk, H)
    for blk in blocks(ct):
        y = _gf128_mul(y ^ blk, H)
    y = _gf128_mul(y ^ ((len(aad)*8) << 64 | (len(ct)*8)), H)
    return y

def _gctr(key: bytes, icb: int, data: bytes) -> bytes:
    out = bytearray()
    cb = icb
    for i in range(0, len(data), 16):
        ks = aes256_encrypt_block(key, cb.to_bytes(16, 'big'))
        out += bytes(a ^ b for a, b in zip(data[i:i+16], ks))
        cb = (cb + 1) & ((1 << 128) - 1)
    return bytes(out)

def gcm_encrypt(key: bytes, nonce: bytes, pt: bytes, aad: bytes = b"") -> tuple:
    assert len(nonce) == 12, "only 96-bit nonces supported"
    H = int.from_bytes(aes256_encrypt_block(key, b'\x00'*16), 'big')
    J0 = int.from_bytes(nonce + b'\x00\x00\x00\x01', 'big')
    ct = _gctr(key, (J0 + 1) & ((1 << 128) - 1), pt)
    S = _ghash(H, aad, ct)
    tag = bytes(a ^ b for a, b in zip(
        aes256_encrypt_block(key, J0.to_bytes(16, 'big')),
        S.to_bytes(16, 'big')))
    return ct, tag

def gcm_decrypt(key: bytes, nonce: bytes, ct: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    assert len(nonce) == 12
    H = int.from_bytes(aes256_encrypt_block(key, b'\x00'*16), 'big')
    J0 = int.from_bytes(nonce + b'\x00\x00\x00\x01', 'big')
    S = _ghash(H, aad, ct)
    exp = bytes(a ^ b for a, b in zip(
        aes256_encrypt_block(key, J0.to_bytes(16, 'big')),
        S.to_bytes(16, 'big')))
    if not hmac_mod.compare_digest(exp, tag):
        raise ValueError("GCM tag mismatch — wrong key/nonce or tampered data")
    return _gctr(key, (J0 + 1) & ((1 << 128) - 1), ct)

# ---------- HKDF (RFC 5869) ----------
def hkdf_extract(salt: bytes, ikm: bytes, hashmod=hashlib.sha256) -> bytes:
    if not salt:
        salt = b'\x00' * hashmod().digest_size
    return hmac_mod.new(salt, ikm, hashmod).digest()

def hkdf_expand(prk: bytes, info: bytes, L: int, hashmod=hashlib.sha256) -> bytes:
    n = -(-L // hashmod().digest_size)
    okm, t = b'', b''
    for i in range(1, n + 1):
        t = hmac_mod.new(prk, t + info + bytes([i]), hashmod).digest()
        okm += t
    return okm[:L]

def hkdf(salt: bytes, ikm: bytes, info: bytes, L: int) -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm), info, L)
