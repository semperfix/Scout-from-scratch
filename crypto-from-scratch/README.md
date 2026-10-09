# Crypto from Scratch

AES-128 built by hand and verified against the FIPS-197 test vector,
textbook RSA with working attack demos (multiplicative malleability,
e=3 cube-root), and a Diffie-Hellman key exchange running over a real
localhost TCP socket with the negotiated key driving an AES-CBC encrypted
echo channel. Zero dependencies — not even `hashlib` for the AES path
(`hashlib` is used only for the DH key-derivation step and RSA demo digests).

## Dependencies

- **Python 3** (3.10+ recommended)
- **stdlib only** — no third-party packages, no crypto libraries

## How to run

Entry point is `cryptodemo.py` (argparse, three subcommands):

```bash
python3 cryptodemo.py --help
python3 cryptodemo.py aes-test            # FIPS-197 Appendix B verification
python3 cryptodemo.py rsa-demo            # malleability + cube-root + sign/verify
python3 cryptodemo.py rsa-demo --bits 1024 # slower, bigger textbook keys
python3 cryptodemo.py dh-demo             # DH over localhost TCP + encrypted echo
python3 cryptodemo.py dh-demo --port 18322
```

Library use:

```python
from aes import encrypt_block, decrypt_block, cbc_encrypt, cbc_decrypt

key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
ct = encrypt_block(key, bytes.fromhex("00112233445566778899aabbccddeeff"))
assert ct.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"   # FIPS-197 App. B

from rsa import RSAKey
k = RSAKey.generate(bits=1024)
c = k.encrypt(42)
assert k.decrypt(c) == 42
```

## Example

```bash
$ python3 cryptodemo.py aes-test
FIPS-197 App.B encrypt: PASS (got 69c4e0d86a7b0430d8cdb78070b4c55a, want 69c4e0d86a7b0430d8cdb78070b4c55a); decrypt round-trip: PASS; ECB/CBC+PKCS#7 round-trips: PASS

$ python3 cryptodemo.py rsa-demo
[PASS] malleability: E(2)*E(3) mod n == E(2*3): forged ciphertext decrypts to 6 (expected 6)
[PASS] cube-root: e=3, n is 511 bits; intercepted c=m^3; integer cube root -> b'hi'
[PASS] sign/verify: valid signature verifies: True; tampered message rejected: True

$ python3 cryptodemo.py dh-demo
DH parameters: locally generated 512-bit safe prime (p=2q+1), g=3
client derived key: ebcd9d5daf3cdb283cb45ccbbff23269
server derived key: ebcd9d5daf3cdb283cb45ccbbff23269
keys match: True
  sent b'hello diffie' -> got b'echo: eiffid olleh'
  sent b'second message' -> got b'echo: egassem dnoces'
DH DEMO: PASS
```

## Key learnings

- **The S-box is derived, not pasted.** It is computed at import time from
  the GF(2^8) multiplicative inverse plus the FIPS affine transform, with an
  assertion on known entries (`SBOX[0x53] == 0xED`) so a broken field
  implementation fails fast instead of producing almost-right ciphertext.
- **The task's FIPS vector was corrupt** (`69c4e0d86a7b04315ae2b7f87` is only
  12 bytes and fails `bytes.fromhex`). Ground truth came from `openssl enc
  -aes-128-ecb` on this machine: `69c4e0d86a7b0430d8cdb78070b4c55a`. Never
  trust a test vector from memory — verify against an independent
  implementation.
- **Miller-Rabin determinism matters.** The deterministic bases
  (2, 325, 9375, ...) are valid only for n < 2^64; above that the code falls
  back to random bases. Keygen also *regenerates primes* until gcd(e, φ)=1
  instead of bumping e — bumping silently turned the e=3 demo into e=5 and
  made the cube-root "attack" recover garbage, a bug that looked like broken
  math but was really a violated precondition.
- **Cube-root attack needs m^e < n, strictly.** The demo asserts this; without
  the wrap-free precondition the integer cube root of c is meaningless.
- **A fabricated "RFC 3526 prime" is worse than no prime.** The first draft
  hardcoded a 2048-bit prime reconstructed from memory with visibly repeating
  blocks — pure fiction. Replaced with a locally generated 512-bit safe prime
  (p=2q+1, both verified prime, g of order q), cached in `dh_params.json`.
  Honest and checkable beats impressive-looking and wrong.

## Files

| File | What it does |
|---|---|
| `cryptodemo.py` | **Entry point**: argparse CLI — `aes-test`, `rsa-demo`, `dh-demo` |
| `aes.py` | AES-128 from FIPS-197: derived S-box, key expansion, cipher/inverse cipher, PKCS#7, ECB + CBC, `self_test()` vs Appendix B |
| `rsa.py` | Miller-Rabin, keygen, textbook encrypt/decrypt, digest sign/verify, demos: malleability `E(2)*E(3)==E(6)`, e=3 cube-root via Newton integer root |
| `dh_demo.py` | DH over localhost TCP (length-prefixed pubkey exchange), SHA-256 KDF, AES-CBC encrypted echo channel; generates/caches safe-prime params |
| `dh_params.json` | Cached DH parameters (generated once, ~10 s, then reused) |

## Limitations

- Textbook RSA has **no padding** — the malleability demo is the point, but
  nothing here should encrypt real data. Real RSA needs OAEP/PSS.
- The DH group is 512-bit (demo speed); production uses RFC 3526 2048-bit+.
- The DH exchange has **no authentication** — a MITM on localhost could swap
  public values. Real protocols sign the exchange (cf. Station-to-Station).
- AES side-channel resistance: none. This is a learning implementation with
  table lookups and Python-int timing; do not use where timing attacks matter.
