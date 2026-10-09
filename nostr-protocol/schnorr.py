"""BIP-340 Schnorr signatures over secp256k1, from scratch.

Reference: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
New signature scheme vs expedition #22 (which did ECDSA): linear in the
secret key, which is what makes it usable for multisig/MuSig-style protocols.
"""

from secp import sha256, P, N, G, point_add, point_mul, lift_x, has_even_y


def tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = sha256(tag.encode())
    return sha256(tag_hash + tag_hash + msg)


def sign(seckey: bytes, msg: bytes, aux_rand: bytes = None) -> bytes:
    """Sign a message (arbitrary bytes). Returns 64-byte (r, s)."""
    d = int.from_bytes(seckey, "big")
    if not 1 <= d < N:
        raise ValueError("secret key out of range")
    # BIP-340: negate secret if its public point has odd y
    if point_mul(d)[1] & 1:
        d = N - d
    pub = point_mul(d)[0].to_bytes(32, "big")
    if aux_rand is None:
        import os
        aux_rand = os.urandom(32)
    if len(aux_rand) != 32:
        raise ValueError("aux_rand must be 32 bytes")
    t = bytes(a ^ b for a, b in
              zip(d.to_bytes(32, "big"), tagged_hash("BIP0340/aux", aux_rand)))
    rand = tagged_hash("BIP0340/nonce", t + pub + msg)
    k0 = int.from_bytes(rand, "big") % N
    if k0 == 0:
        raise RuntimeError("k'=0, extremely unlikely")
    r_pt = point_mul(k0)
    k = N - k0 if (r_pt[1] & 1) else k0
    e = int.from_bytes(tagged_hash("BIP0340/challenge",
                                   r_pt[0].to_bytes(32, "big") + pub + msg), "big") % N
    s = (k + e * d) % N
    return r_pt[0].to_bytes(32, "big") + s.to_bytes(32, "big")


def verify(pubkey: bytes, msg: bytes, sig: bytes) -> bool:
    """Verify a 64-byte BIP-340 signature against a 32-byte x-only pubkey."""
    if len(pubkey) != 32 or len(sig) != 64:
        return False
    p = lift_x(pubkey)
    if p is None:
        return False
    r = int.from_bytes(sig[0:32], "big")
    s = int.from_bytes(sig[32:64], "big")
    if r >= P or s >= N:
        return False
    e = int.from_bytes(tagged_hash("BIP0340/challenge",
                                   sig[0:32] + pubkey + msg), "big") % N
    # R = s*G - e*P
    r_pt = point_add(point_mul(s), point_mul(N - e, p))
    if r_pt is None or (r_pt[1] & 1) or r_pt[0] != r:
        return False
    return True
