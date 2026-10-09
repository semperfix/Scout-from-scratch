# TLS 1.3 from Scratch (RFC 8446) — 🚧 IN PROGRESS 🚧

**This skill is under construction — the expedition is not finished.** What
exists today: every crypto primitive hand-rolled in stdlib-only Python
(`tls13.py`, ~620 lines), plus the full handshake *message machinery*:
ClientHello builder, ServerHello parser, the TLS 1.3 key schedule
(HKDF-based), record protection (AES-GCM encrypt/decrypt), EncryptedExtensions
/ Certificate / CertificateVerify / Finished parsing and verification, and a
minimal DER/X.509 reader that pulls the leaf SPKI.

## What's done vs. what's not

**Done (tested against published vectors, openssl CLI, and pycryptodome):**

- SHA-256 (constants derived from prime fractional parts, not transcribed)
- HMAC, HKDF (RFC 5869)
- AES-128 (S-box derived from GF(2⁸)), AES-GCM
- X25519 (RFC 7748 ladder), ECDSA verify (P-256/P-384), RSA verify (PKCS#1
  v1.5 and PSS)
- Handshake state machine pieces: key schedule, transcript hashing, record
  protection, message builders/parsers

**Not yet done:**

- No live socket driver — there is no `connect()`/`run_handshake()` that
  actually talks to a server over TCP
- `HelloRetryRequest` raises `RuntimeError('...not implemented')`
- The RFC 8448 fixtures (`rfc8448_fixtures.json`) are present but not yet wired
  into a full-transcript vector walkthrough test

## Dependencies

**Runtime:** stdlib only. **Tests:** pycryptodome + openssl CLI, used only as
test oracles (the library itself never imports them).

## How to run

```
python3 -c "import tls13; print(tls13.sha256(b'abc').hex())"   # smoke test
python3 test_tls13.py        # 35 checks (needs pycryptodome + openssl on PATH)
```

## Usage example (primitives)

```python
import tls13 as T

T.sha256(b"abc").hex()                      # hand-rolled SHA-256
T.hmac_sha256(b"key", b"msg")               # RFC 4231-compatible HMAC
T.x25519(priv, pub)                         # RFC 7748 shared secret
T.gcm_encrypt(key, nonce12, aad, pt)        # AES-GCM (record protection)
T.build_client_hello(pubkey, "example.com", session_id, rnd)  # handshake bytes
```

## Key learnings so far

- **Deriving constants beats transcribing them.** The SHA-256 K constants and
  the AES S-box are computed at import from first principles (prime fractional
  parts, GF(2⁸) inverse) — then spot-checked against published vectors. A
  hardcoded magic table can be wrong silently; a derivation is checkable.
- **Float precision bites even in constant derivation:** `p**(1/3)` via float
  cbrt loses the last ulp for large primes, so the K-constant code rounds to 12
  decimals before taking the fraction — keeping the top 32 bits exact for all
  64 primes (verified: every K matches FIPS 180-4).
- **Test against oracles, never transcribe vectors.** X25519 was validated by
  diffing against `openssl pkeyutl` on random keys; ECDSA/RSA by having openssl
  sign and the hand-rolled code verify. Published vectors confirm compatibility;
  random-key differential testing catches what vectors miss.

## Files

- `tls13.py` — the stack: primitives + handshake message machinery
- `test_tls13.py` — 35 checks (test-only deps: pycryptodome, openssl CLI)
- `rfc8448_fixtures.json` — RFC 8448 key-exchange/key-schedule test vectors
  (present; not yet wired into a full-transcript test)
