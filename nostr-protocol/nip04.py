"""NIP-04 encrypted direct messages, from scratch.

Key exchange: ECDH on secp256k1 — shared point = priv * lift_x(peer_xonly),
key = x(shared) used directly as the 32-byte AES key (matches nostr-tools).
Cipher: AES-256-CBC with PKCS#7 padding, random 16-byte IV.
Wire format: base64(ciphertext) + "?iv=" + base64(iv).

AES-256 block cipher vendored from expedition #17 (GF(2^8)-derived S-box,
14-round key schedule); CBC mode + padding are new here.
"""

import base64
import os

from secp import point_mul, lift_x


# --------------------------------------------------------------------------
# AES-256 block cipher (vendored from expedition #17, stdlib only)
# --------------------------------------------------------------------------

def _gf_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = ((a << 1) & 0xFF) ^ (0x1B if hi else 0)
        b >>= 1
    return p


def _build_sbox():
    sbox, inv = [0] * 256, [0] * 256
    for x in range(256):
        inv_x = 0 if x == 0 else next(y for y in range(256) if _gf_mul(x, y) == 1)

        def rotl(b, n):
            return ((b << n) | (b >> (8 - n))) & 0xFF

        sbox[x] = inv_x ^ rotl(inv_x, 1) ^ rotl(inv_x, 2) ^ rotl(inv_x, 3) ^ rotl(inv_x, 4) ^ 0x63
    for x in range(256):
        inv[sbox[x]] = x
    return sbox, inv


_SBOX, _INV_SBOX = _build_sbox()


def _rcon(i):
    r = 1
    for _ in range(i - 1):
        r = _gf_mul(r, 2)
    return r


def _key_schedule(key: bytes):
    assert len(key) == 32
    Nk, Nb, Nr = 8, 4, 14
    w = [int.from_bytes(key[i * 4:(i + 1) * 4], "big") for i in range(Nk)]
    for i in range(Nk, Nb * (Nr + 1)):
        temp = w[i - 1]
        if i % Nk == 0:
            temp = (_SBOX[(temp >> 16) & 0xFF] << 24 | _SBOX[(temp >> 8) & 0xFF] << 16
                    | _SBOX[temp & 0xFF] << 8 | _SBOX[(temp >> 24) & 0xFF]) ^ (_rcon(i // Nk) << 24)
        elif i % Nk == 4:
            temp = (_SBOX[(temp >> 24) & 0xFF] << 24 | _SBOX[(temp >> 16) & 0xFF] << 16
                    | _SBOX[(temp >> 8) & 0xFF] << 8 | _SBOX[temp & 0xFF])
        w.append(w[i - Nk] ^ temp)
    return [b"".join(w[i * 4 + j].to_bytes(4, "big") for j in range(4))
            for i in range(Nr + 1)]


def _sub_bytes(s):
    return [_SBOX[b] for b in s]


def _inv_sub_bytes(s):
    return [_INV_SBOX[b] for b in s]


def _shift_rows(s):
    return [s[0], s[5], s[10], s[15], s[4], s[9], s[14], s[3],
            s[8], s[13], s[2], s[7], s[12], s[1], s[6], s[11]]


def _inv_shift_rows(s):
    return [s[0], s[13], s[10], s[7], s[4], s[1], s[14], s[11],
            s[8], s[5], s[2], s[15], s[12], s[9], s[6], s[3]]


def _mix_columns(s):
    o = [0] * 16
    for c in range(4):
        a0, a1, a2, a3 = s[c * 4:(c + 1) * 4]
        o[c * 4] = _gf_mul(a0, 2) ^ _gf_mul(a1, 3) ^ a2 ^ a3
        o[c * 4 + 1] = a0 ^ _gf_mul(a1, 2) ^ _gf_mul(a2, 3) ^ a3
        o[c * 4 + 2] = a0 ^ a1 ^ _gf_mul(a2, 2) ^ _gf_mul(a3, 3)
        o[c * 4 + 3] = _gf_mul(a0, 3) ^ a1 ^ a2 ^ _gf_mul(a3, 2)
    return o


def _inv_mix_columns(s):
    o = [0] * 16
    for c in range(4):
        a0, a1, a2, a3 = s[c * 4:(c + 1) * 4]
        o[c * 4] = _gf_mul(a0, 14) ^ _gf_mul(a1, 11) ^ _gf_mul(a2, 13) ^ _gf_mul(a3, 9)
        o[c * 4 + 1] = _gf_mul(a0, 9) ^ _gf_mul(a1, 14) ^ _gf_mul(a2, 11) ^ _gf_mul(a3, 13)
        o[c * 4 + 2] = _gf_mul(a0, 13) ^ _gf_mul(a1, 9) ^ _gf_mul(a2, 14) ^ _gf_mul(a3, 11)
        o[c * 4 + 3] = _gf_mul(a0, 11) ^ _gf_mul(a1, 13) ^ _gf_mul(a2, 9) ^ _gf_mul(a3, 14)
    return o


def _enc_block(key, pt: bytes) -> bytes:
    rks = _key_schedule(key)
    s = [b ^ r for b, r in zip(pt, rks[0])]
    for rk in rks[1:-1]:
        s = _mix_columns(_shift_rows(_sub_bytes(s)))
        s = [b ^ r for b, r in zip(s, rk)]
    s = _shift_rows(_sub_bytes(s))
    return bytes(b ^ r for b, r in zip(s, rks[-1]))


def _dec_block(key, ct: bytes) -> bytes:
    rks = _key_schedule(key)
    s = [b ^ r for b, r in zip(ct, rks[-1])]
    for rk in reversed(rks[1:-1]):
        s = _inv_sub_bytes(_inv_shift_rows(s))
        s = [b ^ r for b, r in zip(s, rk)]
        s = _inv_mix_columns(s)
    s = _inv_sub_bytes(_inv_shift_rows(s))
    return bytes(b ^ r for b, r in zip(s, rks[0]))


def _cbc_encrypt(key: bytes, iv: bytes, pt: bytes) -> bytes:
    pad = 16 - len(pt) % 16
    pt = pt + bytes([pad]) * pad
    out, prev = b"", iv
    for i in range(0, len(pt), 16):
        blk = bytes(a ^ b for a, b in zip(pt[i:i + 16], prev))
        blk = _enc_block(key, blk)
        out += blk
        prev = blk
    return out


def _cbc_decrypt(key: bytes, iv: bytes, ct: bytes) -> bytes:
    if len(ct) % 16 or not ct:
        raise ValueError("bad ciphertext length")
    out, prev = b"", iv
    for i in range(0, len(ct), 16):
        blk = _dec_block(key, ct[i:i + 16])
        out += bytes(a ^ b for a, b in zip(blk, prev))
        prev = ct[i:i + 16]
    pad = out[-1]
    if not 1 <= pad <= 16 or out[-pad:] != bytes([pad]) * pad:
        raise ValueError("bad PKCS#7 padding")
    return out[:-pad]


# --------------------------------------------------------------------------
# NIP-04
# --------------------------------------------------------------------------

def shared_key(privkey_hex: str, peer_pubkey_hex: str) -> bytes:
    """ECDH shared secret: x(priv * lift_x(peer_xonly)), 32 bytes."""
    priv = int(privkey_hex, 16) if isinstance(privkey_hex, str) else int.from_bytes(privkey_hex, "big")
    peer = lift_x(bytes.fromhex(peer_pubkey_hex))
    if peer is None:
        raise ValueError("peer pubkey not on curve")
    shared = point_mul(priv, peer)
    if shared is None:
        raise ValueError("degenerate shared point")
    return shared[0].to_bytes(32, "big")


def nip04_encrypt(sender_privkey_hex: str, recipient_pubkey_hex: str, text: str) -> str:
    key = shared_key(sender_privkey_hex, recipient_pubkey_hex)
    iv = os.urandom(16)
    ct = _cbc_encrypt(key, iv, text.encode("utf-8"))
    return base64.b64encode(ct).decode() + "?iv=" + base64.b64encode(iv).decode()


def nip04_decrypt(recipient_privkey_hex: str, sender_pubkey_hex: str, payload: str) -> str:
    ct_b64, _, iv_b64 = payload.partition("?iv=")
    if not ct_b64 or not iv_b64:
        raise ValueError("not a NIP-04 payload")
    key = shared_key(recipient_privkey_hex, sender_pubkey_hex)
    pt = _cbc_decrypt(key, base64.b64decode(iv_b64), base64.b64decode(ct_b64))
    return pt.decode("utf-8")
