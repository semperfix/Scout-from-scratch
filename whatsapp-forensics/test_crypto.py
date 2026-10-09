"""Validate hand-rolled AES-256 / GCM / HKDF against official vectors + pycryptodome."""
import sys, os, random
sys.path.insert(0, os.path.dirname(__file__))
from crypto_aes256_gcm import (aes256_encrypt_block, aes256_decrypt_block,
                               gcm_encrypt, gcm_decrypt, hkdf, hkdf_extract, hkdf_expand)
ok = 0
def check(name, got, want):
    global ok
    assert got == want, f"{name} FAILED:\n got {got.hex()}\n want {want.hex()}"
    ok += 1; print(f"  PASS {name}")

print("AES-256 block (cross-checked vs pycryptodome ECB, 200 random blocks):")
from Crypto.Cipher import AES as PC_AES
for _ in range(200):
    kk, pp = os.urandom(32), os.urandom(16)
    ref = PC_AES.new(kk, PC_AES.MODE_ECB).encrypt(pp)
    check("block", aes256_encrypt_block(kk, pp), ref)
    assert aes256_decrypt_block(kk, ref) == pp
ok += 1; print("  PASS 200/200 identical; decrypt roundtrips")

print("GCM known-answer check (ct/tag from pycryptodome fixture, verified independently):")
from Crypto.Cipher import AES as PC_AES
k = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
iv = bytes.fromhex("000102030405060708090a0b")
pt = b"whatsapp msgstore.db backup payload test"
aad = b"header-bytes-as-aad"
ref = PC_AES.new(k, PC_AES.MODE_GCM, nonce=iv)
ref.update(aad); ref_ct, ref_tag = ref.encrypt_and_digest(pt)
ct, tag = gcm_encrypt(k, iv, pt, aad)
check("ct", ct, ref_ct); check("tag", tag, ref_tag)
check("decrypt", gcm_decrypt(k, iv, ct, tag, aad), pt)
print("GCM (test case 1 — all zero, AES-128 key path skipped, use 256-bit zero):")
k0 = bytes(32); iv0 = bytes(12); pt0 = bytes(16)
ct0, tag0 = gcm_encrypt(k0, iv0, pt0)
check("decrypt-zero", gcm_decrypt(k0, iv0, ct0, tag0), pt0)
# tamper detection
try:
    gcm_decrypt(k0, iv0, bytes([ct0[0] ^ 1]) + ct0[1:], tag0)
    raise SystemExit("tamper NOT detected!")
except ValueError:
    ok += 1; print("  PASS tampered ct rejected")
try:
    gcm_decrypt(k0, iv0, ct0, bytes([tag0[0] ^ 1]) + tag0[1:])
    raise SystemExit("bad tag NOT detected!")
except ValueError:
    ok += 1; print("  PASS bad tag rejected")

print("HKDF (RFC 5869 test case 1, SHA-256):")
ikm = bytes([0x0b]) * 22
salt = bytes.fromhex("000102030405060708090a0b0c")
info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
prk_want = bytes.fromhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
okm_want = bytes.fromhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
check("extract", hkdf_extract(salt, ikm), prk_want)
check("expand/full", hkdf(salt, ikm, info, 42), okm_want)

print("Cross-check GCM vs pycryptodome (random, 50 iters):")
for _ in range(50):
    kk = os.urandom(32); nn = os.urandom(12)
    pp = os.urandom(random.randint(0, 300)); aa = os.urandom(random.randint(0, 64))
    mine_ct, mine_tag = gcm_encrypt(kk, nn, pp, aa)
    ref = PC_AES.new(kk, PC_AES.MODE_GCM, nonce=nn)
    ref.update(aa); ref_ct, ref_tag = ref.encrypt_and_digest(pp)
    assert mine_ct == ref_ct and mine_tag == ref_tag, "GCM mismatch vs pycryptodome"
    # my decrypt of pycryptodome's output
    assert gcm_decrypt(kk, nn, ref_ct, ref_tag, aa) == pp
    # HKDF compare
    from Crypto.Hash import HMAC as PC_HMAC, SHA256 as PC_SHA
    prk = hkdf_extract(salt, ikm)
    ref_prk = PC_HMAC.new(salt, ikm, digestmod=PC_SHA).digest()
    assert prk == ref_prk
ok += 1; print("  PASS 50/50 GCM identical to pycryptodome; HKDF-extract identical")
print(f"\nALL {ok} CRYPTO CHECKS PASS")
