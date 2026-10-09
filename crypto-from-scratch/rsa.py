#!/usr/bin/env python3
"""Textbook RSA built by hand -- no crypto libraries.

  * Miller-Rabin primality test (deterministic bases for < 2^64, else rounds)
  * Key generation: random safe-ish primes, e=65537, d = e^-1 mod lcm(p-1,q-1)
  * Raw (textbook) encrypt/decrypt, PKCS#1-v1.5-style sign/verify for demos
    using hashlib digests + hand-rolled modular exponentiation
  * Attack demos:
      - multiplicative malleability: E(2)*E(3) == E(6) (mod n)
      - e=3 small-message cube-root attack: c = m^3, m = cbrt(c)

Keys here are textbook-sized by default for demo speed; pass bits=1024+
for anything you actually keep secret (and then don't -- use a real library).
"""
import hashlib
import os
import random

_rng = random.Random()


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
    # deterministic bases valid for n < 2^64 (Jaeschke/Sorenson-Webster)
    if n < 2 ** 64:
        bases = (2, 325, 9375, 28178, 450775, 9780504, 1795265022)
    else:
        bases = [_rng.randrange(2, n - 1) for _ in range(rounds)]
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
    if b == 0:
        return a, 1, 0
    g, x, y = _egcd(b, a % b)
    return g, y, x - (a // b) * y


def _modinv(a, m):
    g, x, _ = _egcd(a, m)
    if g != 1:
        raise ValueError("no modular inverse")
    return x % m


class RSAKey:
    """Textbook RSA keypair. All ops are raw modular exponentiation."""

    def __init__(self, n, e, d=None):
        self.n, self.e, self.d = n, e, d

    @classmethod
    def generate(cls, bits=1024, e=65537):
        # Regenerate primes until gcd(e, phi) == 1 so the *requested* e is kept
        # (bumping e instead would silently change the demo's e=3 to e=5/7/...).
        while True:
            p = _gen_prime(bits // 2)
            q = _gen_prime(bits // 2)
            if q == p:
                continue
            phi = (p - 1) * (q - 1)
            if _egcd(e, phi)[0] == 1:
                break
        return cls(p * q, e, _modinv(e, phi))

    # -- raw textbook ops ------------------------------------------------
    def encrypt(self, m):
        assert 0 <= m < self.n, "message must be < n (textbook RSA)"
        return pow(m, self.e, self.n)

    def decrypt(self, c):
        assert self.d is not None
        return pow(c, self.d, self.n)

    # -- sign/verify over a hashlib digest (demo-grade padding) -----------
    def sign(self, digest_bytes):
        """'Sign' by decrypting the digest int. Demo only -- no real padding."""
        assert self.d is not None
        m = int.from_bytes(digest_bytes, "big") % self.n
        return pow(m, self.d, self.n)

    def verify(self, digest_bytes, sig):
        m = int.from_bytes(digest_bytes, "big") % self.n
        return pow(sig, self.e, self.n) == m

    def pub(self):
        return RSAKey(self.n, self.e)


# ---------------------------------------------------------------------------
# Attack demos
# ---------------------------------------------------------------------------

def demo_malleability(key=None):
    """E(2) * E(3) mod n == E(6): textbook RSA is multiplicatively homomorphic.

    An attacker who sees E(m) can produce E(m*k) for any k of their choosing
    without ever learning m. This is why real RSA always uses padding (OAEP).
    """
    key = key or RSAKey.generate(bits=512)
    e2, e3 = key.encrypt(2), key.encrypt(3)
    forged = (e2 * e3) % key.n
    ok = forged == key.encrypt(6) and key.decrypt(forged) == 6
    return ok, (f"E(2)*E(3) mod n == E(2*3): forged ciphertext decrypts to "
                f"{key.decrypt(forged)} (expected 6)")


def _icbrt(n):
    """Integer cube root: largest x with x^3 <= n (Newton)."""
    x = 1 << ((n.bit_length() + 2) // 3)
    while True:
        y = (2 * x + n // (x * x)) // 3
        if y >= x:
            return x
        x = y


def demo_cube_root_attack(bits=512, e=3, msg=b"hi"):
    """e=3 + m^3 < n  =>  c = m^3 over the *integers*; m = cbrt(c), no key needed.

    Real-world version: Hastad's broadcast attack (same m, e=3, 3 different n).
    Defense: padding (OAEP) + e=65537.
    """
    key = RSAKey.generate(bits=bits, e=e)
    m = int.from_bytes(msg, "big")
    assert m ** key.e < key.n, "demo needs m^e < n so no modular wrap happens"
    c = key.encrypt(m)          # == m**3 exactly, since m^3 < n
    recovered = _icbrt(c)
    ok = recovered == m and recovered ** 3 == c
    return ok, (f"e={key.e}, n is {key.n.bit_length()} bits; intercepted c=m^3; "
                f"integer cube root -> {recovered.to_bytes((recovered.bit_length()+7)//8, 'big')!r}")


def demo_sign_verify(key=None):
    key = key or RSAKey.generate(bits=512)
    digest = hashlib.sha256(b"scout was here").digest()
    sig = key.sign(digest)
    ok = key.pub().verify(digest, sig)
    tampered = hashlib.sha256(b"scout was here!").digest()
    ok_tamper = not key.pub().verify(tampered, sig)
    return ok and ok_tamper, (f"valid signature verifies: {ok}; "
                              f"tampered message rejected: {ok_tamper}")


def run_demos(bits=512):
    results = []
    for name, fn in (("malleability", lambda: demo_malleability()),
                     ("cube-root", lambda: demo_cube_root_attack(bits=bits)),
                     ("sign/verify", lambda: demo_sign_verify())):
        try:
            ok, detail = fn()
        except Exception as exc:  # noqa: BLE001 -- demo harness
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        results.append((name, ok, detail))
    return results


if __name__ == "__main__":
    for name, ok, detail in run_demos():
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}")
    raise SystemExit(0)
