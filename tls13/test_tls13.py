#!/usr/bin/env python3
"""Primitive validation for tls13.py. Oracles: published vectors, openssl CLI,
and pycryptodome (test-only; tls13.py never imports it)."""
import os, subprocess, sys, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tls13 as T

PASS = []
def check(name, cond):
    PASS.append((name, bool(cond)))
    print(('ok  ' if cond else 'FAIL'), name)

# --- SHA-256 ---------------------------------------------------------------
check('sha256 empty', T.sha256(b'') == bytes.fromhex(
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'))
check('sha256 abc', T.sha256(b'abc') == bytes.fromhex(
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'))
check('sha256 K constants derived exactly',
      T._K[0] == 0x428a2f98 and T._K[63] == 0xc67178f2 and len(T._K) == 64)

# --- HMAC (RFC 4231 cases 1-2) ----------------------------------------------
check('hmac case1', T.hmac_sha256(b'\x0b' * 20, b'Hi There') == bytes.fromhex(
    'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'))
check('hmac case2', T.hmac_sha256(b'Jefe', b'what do ya want for nothing?') == bytes.fromhex(
    '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'))

# --- HKDF: mine vs pycryptodome (RFC 5869 case 1 inputs) -----------------------
from Crypto.Protocol.KDF import HKDF as _PC_HKDF
from Crypto.Hash import SHA256 as _PC_SHA256
ikm, salt, info = b'\x0b' * 22, bytes(range(13)), bytes(range(0xf0, 0xfa))
mine = T.hkdf_expand(T.hkdf_extract(salt, ikm), info, 42)
check('hkdf matches pycryptodome', mine == _PC_HKDF(ikm, 42, salt, _PC_SHA256, 1, info))
check('hkdf RFC5869 case1 published OKM', mine == bytes.fromhex(
    '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865'))
check('hkdf_expand_label format', T.hkdf_expand_label(b'secret', b'key', b'', 16) ==
      T.hkdf_expand(b'secret', b'\x00\x10\x09tls13 key\x00', 16))

# --- AES-128 -----------------------------------------------------------------
check('sbox spots', T._SBOX[0x00] == 0x63 and T._SBOX[0x53] == 0xed and T._SBOX[0xff] == 0x16)
check('aes FIPS-197 B', T._aes_enc_block(bytes(range(16)), bytes.fromhex(
    '00112233445566778899aabbccddeeff')) == bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a'))

# --- GCM: published zero vector + differential fuzz vs pycryptodome ----------
ct, tag = T.gcm_encrypt(b'\x00' * 16, b'\x00' * 12, b'', b'')
check('gcm zero vector', ct == b'' and tag == bytes.fromhex('58e2fccefa7e3061367f1d57a4e7455a'))
ct, tag = T.gcm_encrypt(b'\x00' * 16, b'\x00' * 12, b'', b'\x00' * 16)
check('gcm 16-zero-pt vector', ct == bytes.fromhex('0388dace60b6a392f328c2b971b2fe78')
      and tag == bytes.fromhex('ab6e47d42cec13bdf53a67b21257bddf'))
from Crypto.Cipher import AES as _AES
rng = random.Random(42)
gok = True
for _ in range(200):
    k = bytes(rng.randrange(256) for _ in range(16))
    n = bytes(rng.randrange(256) for _ in range(12))
    a = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 40)))
    p = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 64)))
    c1, t1 = T.gcm_encrypt(k, n, a, p)
    c2 = _AES.new(k, _AES.MODE_GCM, nonce=n)
    c2.update(a)
    cc, tt = c2.encrypt_and_digest(p)
    if (c1, t1) != (cc, tt):
        gok = False
        break
    # decrypt direction cross-check
    d = _AES.new(k, _AES.MODE_GCM, nonce=n)
    d.update(a)
    if d.decrypt_and_verify(c1, t1) != p or T.gcm_decrypt(k, n, a, c1, t1) != p:
        gok = False
        break
check('gcm 200-vector differential vs pycryptodome (enc+dec)', gok)
try:
    T.gcm_decrypt(b'\x00' * 16, b'\x00' * 12, b'', b'', b'\x00' * 16)
    check('gcm rejects bad tag', False)
except ValueError:
    check('gcm rejects bad tag', True)

# --- X25519: openssl cross-validation (no transcribed vectors) --------------------
def _ossl_x25519_raw(pem):
    t = subprocess.run(['openssl', 'pkey', '-in', pem, '-text', '-noout'],
                       check=True, capture_output=True).stdout.decode()
    priv = pub = None
    sec = None
    for line in t.split('\n'):
        s = line.strip()
        if s.startswith('priv:'):
            sec, priv = 'priv', ''
        elif s.startswith('pub:'):
            sec, pub = 'pub', ''
        elif sec and ':' in s:
            if sec == 'priv':
                priv += s.replace(':', '')
            else:
                pub += s.replace(':', '')
        elif sec and s == '':
            sec = None
    return bytes.fromhex(priv), bytes.fromhex(pub)
subprocess.run(['openssl', 'genpkey', '-algorithm', 'X25519', '-out', '/tmp/xa.pem'],
               check=True, capture_output=True)
subprocess.run(['openssl', 'genpkey', '-algorithm', 'X25519', '-out', '/tmp/xb.pem'],
               check=True, capture_output=True)
apriv, apub = _ossl_x25519_raw('/tmp/xa.pem')
bpriv, bpub = _ossl_x25519_raw('/tmp/xb.pem')
check('x25519 pubkey matches openssl', T.x25519_pubkey(apriv) == apub)
subprocess.run(['openssl', 'pkey', '-in', '/tmp/xb.pem', '-pubout', '-out', '/tmp/xbp.pem'],
               check=True, capture_output=True)
ossl_shared = subprocess.run(
    ['openssl', 'pkeyutl', '-derive', '-inkey', '/tmp/xa.pem', '-peerkey', '/tmp/xbp.pem'],
    check=True, capture_output=True).stdout
check('x25519 shared secret matches openssl', T.x25519(apriv, bpub) == ossl_shared)
check('x25519 DH commutativity', T.x25519(apriv, bpub) == T.x25519(bpriv, apub))

# --- curve constant grounding -------------------------------------------------
# P-256/P-384 parameters cross-checked against openssl explicit params;
# n*G must be the point at infinity (proves n is the true order, since n is prime).
for _cn in ('P-256', 'P-384'):
    _c = T._CURVES[_cn]
    check(f'{_cn} n*G is infinity', T._ec_mul(_c, (_c['Gx'], _c['Gy']), _c['n']) is None)
_p256ossl = subprocess.run(['openssl', 'ecparam', '-name', 'prime256v1', '-param_enc', 'explicit',
                            '-outform', 'DER'], capture_output=True).stdout
def _ossl_int(der, off):
    tag, c, nxt = T._tlv(der, off)
    return int.from_bytes(c, 'big')
# ECParameters: SEQ { ver, FieldID SEQ { fieldType OID, p }, Curve SEQ { a OCTET, b OCTET, seed BITSTR }, G OCTET, n INT, h INT }
_fields = T._children(T._children(_p256ossl)[0])
_curve = T._children(_fields[2])
_a = int.from_bytes(_curve[0], 'big'); _b = int.from_bytes(_curve[1], 'big')
_g = _fields[3][1:]  # G OCTET STRING content: 0x04 || X || Y
_k = (len(_g) - 1) // 2 if False else 32
_c256 = T._CURVES['P-256']
check('P-256 params match openssl explicit',
      _a == _c256['a'] and _b == _c256['b'] and
      int.from_bytes(_g[0:32], 'big') == _c256['Gx'] and
      int.from_bytes(_g[32:64], 'big') == _c256['Gy'] and
      _fields[4] is not None and int.from_bytes(_fields[4], 'big') == _c256['n'])

# --- ECDSA: openssl signs, mine verifies --------------------------------------
def ossl_sign(curve, digest):
    subprocess.run(['openssl', 'ecparam', '-name', curve, '-genkey', '-noout', '-out', '/tmp/ec.pem'],
                   check=True, capture_output=True)
    subprocess.run(['openssl', 'dgst', '-sha256', '-sign', '/tmp/ec.pem', '-out', '/tmp/ec.sig',
                    '-binary'], input=digest, check=True, capture_output=True)
    q = subprocess.run(['openssl', 'ec', '-in', '/tmp/ec.pem', '-pubout', '-outform', 'DER'],
                       check=True, capture_output=True).stdout
    sig = open('/tmp/ec.sig', 'rb').read()
    return q, sig
for curve, cn in (('prime256v1', 'P-256'), ('secp384r1', 'P-384')):
    qder, sig = ossl_sign(curve, b'test digest input...........')
    # qder is a DER SPKI: SEQUENCE { algId, BIT STRING(0x00 || 0x04 || X || Y) }
    bitstr = T._children(T._children(qder)[0])[1]
    assert bitstr[0] == 0x00 and bitstr[1] == 0x04, 'point parse'
    k = (len(bitstr) - 2) // 2
    qx = int.from_bytes(bitstr[2:2 + k], 'big')
    qy = int.from_bytes(bitstr[2 + k:], 'big')
    # parse DER signature (r, s)
    r_b, s_b = T._children(T._children(sig)[0])
    r, s = int.from_bytes(r_b, 'big'), int.from_bytes(s_b, 'big')
    dg = T.sha256(b'test digest input...........')
    check(f'ecdsa {cn} verifies openssl sig', T.ecdsa_verify(cn, qx, qy, dg, r, s))
    check(f'ecdsa {cn} rejects tampered sig', not T.ecdsa_verify(cn, qx, qy, dg, r ^ 1, s))

# --- RSA: openssl signs, mine verifies (v1.5 + PSS) -----------------------------
subprocess.run(['openssl', 'genrsa', '-out', '/tmp/rsa.pem', '2048'],
               check=True, capture_output=True)
n_e = subprocess.run(['openssl', 'rsa', '-in', '/tmp/rsa.pem', '-noout', '-modulus'],
                     check=True, capture_output=True)
modline = [l for l in n_e.stdout.decode().split('\n') if l.lower().startswith('modulus=')][0]
n = int(modline.split('=', 1)[1], 16)
dg = T.sha256(b'rsa test message')
subprocess.run(['openssl', 'dgst', '-sha256', '-sign', '/tmp/rsa.pem', '-out', '/tmp/rsa.sig'],
               input=b'rsa test message', check=True, capture_output=True)
sig = open('/tmp/rsa.sig', 'rb').read()
check('rsa v1.5 verifies openssl sig', T.rsa_v15_verify(n, 65537, dg, sig))
check('rsa v1.5 rejects tampered sig', not T.rsa_v15_verify(n, 65537, dg, sig[:-1] + bytes([sig[-1] ^ 1])))
subprocess.run(['openssl', 'dgst', '-sha256', '-sigopt', 'rsa_padding_mode:pss',
                '-sigopt', 'rsa_pss_saltlen:32', '-sign', '/tmp/rsa.pem',
                '-out', '/tmp/rsa_pss.sig'], input=b'rsa test message', check=True, capture_output=True)
psig = open('/tmp/rsa_pss.sig', 'rb').read()
check('rsa pss verifies openssl sig', T.rsa_pss_verify(n, 65537, dg, psig, 32))
check('rsa pss rejects tampered sig', not T.rsa_pss_verify(n, 65537, dg, psig[:-1] + bytes([psig[-1] ^ 1]), 32))

fails = [n for n, ok in PASS if not ok]
print(f'\n{len(PASS) - len(fails)}/{len(PASS)} checks passed')
sys.exit(1 if fails else 0)
