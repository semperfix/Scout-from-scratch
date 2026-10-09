#!/usr/bin/env python3
"""AES-128 built entirely by hand -- no crypto libraries.

Implements the FIPS-197 cipher from the ground up:
  * S-box computed from the GF(2^8) multiplicative inverse + affine transform
    (not a hardcoded table -- the table is *derived* at import time)
  * Key expansion (44 words, RotWord/SubWord/Rcon)
  * SubBytes / ShiftRows / MixColumns / AddRoundKey and their inverses
  * PKCS#7 padding, ECB mode, CBC mode

State is a flat 16-byte list in column-major order: state[row + 4*col].
"""

# ---------------------------------------------------------------------------
# GF(2^8) arithmetic (irreducible polynomial x^8 + x^4 + x^3 + x + 1 = 0x11b)
# ---------------------------------------------------------------------------

def _gf_mul(a, b):
    """Multiply two bytes in GF(2^8) (Russian-peasant, reduction by 0x1b)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = ((a << 1) & 0xFF)
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _gf_pow(a, e):
    r = 1
    while e:
        if e & 1:
            r = _gf_mul(r, a)
        a = _gf_mul(a, a)
        e >>= 1
    return r


def _gf_inv(a):
    """Multiplicative inverse in GF(2^8); 0 maps to 0 (AES convention)."""
    return 0 if a == 0 else _gf_pow(a, 254)


# ---------------------------------------------------------------------------
# S-box: derived, not pasted.  s = affine(gf_inv(b)), c = 0x63
# ---------------------------------------------------------------------------

def _build_sbox():
    sbox, inv = [0] * 256, [0] * 256
    for b in range(256):
        x = _gf_inv(b)
        v = 0
        for i in range(8):
            bit = ((x >> i) & 1) ^ ((x >> ((i + 4) % 8)) & 1) \
                ^ ((x >> ((i + 5) % 8)) & 1) ^ ((x >> ((i + 6) % 8)) & 1) \
                ^ ((x >> ((i + 7) % 8)) & 1) ^ ((0x63 >> i) & 1)
            v |= bit << i
        sbox[b] = v
        inv[v] = b
    return sbox, inv


SBOX, INV_SBOX = _build_sbox()
assert SBOX[0x00] == 0x63 and SBOX[0x53] == 0xED and INV_SBOX[0x63] == 0x00, \
    "derived S-box does not match FIPS-197"  # sanity: known table entries

# Rcon[j] = x^(j-1) in GF(2^8), j = 1..10
RCON = [0x00]
_r = 0x01
for _ in range(10):
    RCON.append(_r)
    _r = _gf_mul(_r, 0x02)


# ---------------------------------------------------------------------------
# Key expansion: 16-byte key -> 11 round keys (each 16 bytes)
# ---------------------------------------------------------------------------

def key_expansion(key):
    assert len(key) == 16, "AES-128 needs a 16-byte key"
    w = [bytes(key[i:i + 4]) for i in range(0, 16, 4)]  # w[0..3]
    for i in range(4, 44):
        t = w[i - 1]
        if i % 4 == 0:
            t = bytes(SBOX[b] for b in t[1:] + t[:1])  # RotWord + SubWord
            t = bytes([t[0] ^ RCON[i // 4]]) + t[1:]
        w.append(bytes(a ^ b for a, b in zip(w[i - 4], t)))
    return [b"".join(w[4 * r:4 * r + 4]) for r in range(11)]


# ---------------------------------------------------------------------------
# Round functions (state = list of 16 ints, column-major)
# ---------------------------------------------------------------------------

def _add_round_key(s, rk):
    return [x ^ y for x, y in zip(s, rk)]


def _sub_bytes(s):
    return [SBOX[b] for b in s]


def _inv_sub_bytes(s):
    return [INV_SBOX[b] for b in s]


def _shift_rows(s):
    # row r: cyclic left shift by r. state[row + 4*col]
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[r + 4 * c] = s[r + 4 * ((c + r) % 4)]
    return out


def _inv_shift_rows(s):
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[r + 4 * c] = s[r + 4 * ((c - r) % 4)]
    return out


def _mix_columns(s):
    out = [0] * 16
    for c in range(4):
        a0, a1, a2, a3 = s[0 + 4 * c], s[1 + 4 * c], s[2 + 4 * c], s[3 + 4 * c]
        out[0 + 4 * c] = _gf_mul(a0, 2) ^ _gf_mul(a1, 3) ^ a2 ^ a3
        out[1 + 4 * c] = a0 ^ _gf_mul(a1, 2) ^ _gf_mul(a2, 3) ^ a3
        out[2 + 4 * c] = a0 ^ a1 ^ _gf_mul(a2, 2) ^ _gf_mul(a3, 3)
        out[3 + 4 * c] = _gf_mul(a0, 3) ^ a1 ^ a2 ^ _gf_mul(a3, 2)
    return out


def _inv_mix_columns(s):
    out = [0] * 16
    for c in range(4):
        a0, a1, a2, a3 = s[0 + 4 * c], s[1 + 4 * c], s[2 + 4 * c], s[3 + 4 * c]
        out[0 + 4 * c] = _gf_mul(a0, 0x0E) ^ _gf_mul(a1, 0x0B) ^ _gf_mul(a2, 0x0D) ^ _gf_mul(a3, 0x09)
        out[1 + 4 * c] = _gf_mul(a0, 0x09) ^ _gf_mul(a1, 0x0E) ^ _gf_mul(a2, 0x0B) ^ _gf_mul(a3, 0x0D)
        out[2 + 4 * c] = _gf_mul(a0, 0x0D) ^ _gf_mul(a1, 0x09) ^ _gf_mul(a2, 0x0E) ^ _gf_mul(a3, 0x0B)
        out[3 + 4 * c] = _gf_mul(a0, 0x0B) ^ _gf_mul(a1, 0x0D) ^ _gf_mul(a2, 0x09) ^ _gf_mul(a3, 0x0E)
    return out


# ---------------------------------------------------------------------------
# Block cipher
# ---------------------------------------------------------------------------

def encrypt_block(key, block16):
    """Encrypt one 16-byte block. Returns 16 bytes."""
    rk = key_expansion(bytes(key))
    s = _add_round_key(list(block16), rk[0])
    for rnd in range(1, 10):
        s = _sub_bytes(s)
        s = _shift_rows(s)
        s = _mix_columns(s)
        s = _add_round_key(s, rk[rnd])
    s = _sub_bytes(s)
    s = _shift_rows(s)
    s = _add_round_key(s, rk[10])
    return bytes(s)


def decrypt_block(key, block16):
    """Decrypt one 16-byte block. Returns 16 bytes."""
    rk = key_expansion(bytes(key))
    s = _add_round_key(list(block16), rk[10])
    for rnd in range(9, 0, -1):
        s = _inv_shift_rows(s)
        s = _inv_sub_bytes(s)
        s = _add_round_key(s, rk[rnd])
        s = _inv_mix_columns(s)
    s = _inv_shift_rows(s)
    s = _inv_sub_bytes(s)
    s = _add_round_key(s, rk[0])
    return bytes(s)


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------

def _pkcs7_pad(data):
    n = 16 - (len(data) % 16)
    return data + bytes([n]) * n


def _pkcs7_unpad(data):
    n = data[-1]
    if not 1 <= n <= 16 or data[-n:] != bytes([n]) * n:
        raise ValueError("bad PKCS#7 padding")
    return data[:-n]


def _xor16(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def ecb_encrypt(key, data):
    data = _pkcs7_pad(data)
    return b"".join(encrypt_block(key, data[i:i + 16]) for i in range(0, len(data), 16))


def ecb_decrypt(key, data):
    assert len(data) % 16 == 0
    pt = b"".join(decrypt_block(key, data[i:i + 16]) for i in range(0, len(data), 16))
    return _pkcs7_unpad(pt)


def cbc_encrypt(key, iv, data):
    assert len(iv) == 16
    data = _pkcs7_pad(data)
    out, prev = bytearray(), bytes(iv)
    for i in range(0, len(data), 16):
        prev = encrypt_block(key, _xor16(data[i:i + 16], prev))
        out += prev
    return bytes(out)


def cbc_decrypt(key, iv, data):
    assert len(iv) == 16 and len(data) % 16 == 0
    out, prev = bytearray(), bytes(iv)
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        out += _xor16(decrypt_block(key, blk), prev)
        prev = blk
    return _pkcs7_unpad(bytes(out))


# ---------------------------------------------------------------------------
# FIPS-197 Appendix B verification
# ---------------------------------------------------------------------------

FIPS_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
FIPS_PT = bytes.fromhex("00112233445566778899aabbccddeeff")
FIPS_CT = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")


def self_test():
    """Returns (ok, detail). Raises nothing -- reports."""
    ct = encrypt_block(FIPS_KEY, FIPS_PT)
    ok_ct = ct == FIPS_CT
    pt = decrypt_block(FIPS_KEY, ct)
    ok_rt = pt == FIPS_PT
    # mode round-trips
    msg = b"The quick brown fox jumps over the lazy dog. " * 7
    ok_modes = (ecb_decrypt(FIPS_KEY, ecb_encrypt(FIPS_KEY, msg)) == msg
                and cbc_decrypt(FIPS_KEY, b"\x00" * 16,
                                cbc_encrypt(FIPS_KEY, b"\x00" * 16, msg)) == msg)
    ok = ok_ct and ok_rt and ok_modes
    detail = (f"FIPS-197 App.B encrypt: {'PASS' if ok_ct else 'FAIL'} "
              f"(got {ct.hex()}, want {FIPS_CT.hex()}); "
              f"decrypt round-trip: {'PASS' if ok_rt else 'FAIL'}; "
              f"ECB/CBC+PKCS#7 round-trips: {'PASS' if ok_modes else 'FAIL'}")
    return ok, detail


if __name__ == "__main__":
    ok, detail = self_test()
    print(detail)
    raise SystemExit(0 if ok else 1)
