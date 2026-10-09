#!/usr/bin/env python3
"""tests/test_core.py — offline deterministic checks for the hand-rolled
Bitcoin stack. No network. Everything here is asserted, not printed."""
import sys, os, hashlib
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from btc_core import (sha256, sha256d, ripemd160, hash160,
                      b58encode, b58decode, b58check_encode, b58check_decode,
                      segwit_encode, segwit_decode,
                      _pmul, pubkey_to_coords, pubkey_to_address, ecdsa_verify,
                      _Gx, _Gy, _P, _N)
from btc_tx import (Cursor, encode_varint, disassemble, classify_scriptpubkey,
                    parse_tx, serialize_tx, txid, wtxid, parse_header,
                    merkle_root)

passed = []
def check(name, cond):
    assert cond, "FAILED: " + name
    passed.append(name)

# --- SHA-256 oracle (hashlib is the oracle, never the implementation) ---
for m in (b"", b"abc", b"x" * 1000, bytes(range(256))):
    check("sha256 oracle %r" % (m[:8],), sha256(m) == hashlib.sha256(m).digest())

# --- RIPEMD-160 official test vector ---
check("ripemd160 empty", ripemd160(b"").hex() ==
      "9c1185a5c5e9fc54612808977ee8f548b2258d31")

# --- HASH160 cross-validated against BIP-173's published example ---
# BIP-173 decodes bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 to program
# 751e76e8199196d454941c45d1b3a323f1433bd6, which is HASH160 of the
# compressed generator pubkey 0279be667e... — two independent sources agree.
G_COMP = bytes([0x02]) + _Gx.to_bytes(32, "big")
check("hash160(G comp) == BIP173 program",
      hash160(G_COMP).hex() == "751e76e8199196d454941c45d1b3a323f1433bd6")

# --- secp256k1: privkey 1 -> pubkey -> P2PKH address ---
x1, y1 = pubkey_to_coords(G_COMP)
check("decompressed G == generator coords", (x1, y1) == (_Gx, _Gy))
check("p2pkh comp", pubkey_to_address(G_COMP) == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
G_UNC = b"\x04" + _Gx.to_bytes(32, "big") + _Gy.to_bytes(32, "big")
check("p2pkh uncomp", pubkey_to_address(G_UNC) == "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm")
# scalar sanity: 2G via double-add equals generator doubling identity check
twoG = _pmul(2)
check("2G on curve", (twoG[1] * twoG[1] - twoG[0] ** 3 - 7) % _P == 0)
check("N*G is infinity", _pmul(_N) is None)

# --- Base58Check ---
v, p = b58check_decode("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
check("b58check decode", v == b"\x00" and p.hex() == "751e76e8199196d454941c45d1b3a323f1433bd6")
check("b58check roundtrip", b58check_decode(b58check_encode(bytes(20), b"\x00")) == (b"\x00", bytes(20)))
try:
    b58check_decode("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"[:-2] + "11")
    check("b58check tamper rejected", False)
except ValueError:
    check("b58check tamper rejected", True)

# --- Bech32 (BIP-173) and Bech32m (BIP-350) ---
h, ver, prog = segwit_decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
check("bech32 p2wpkh", (h, ver, prog.hex()) == ("bc", 0, "751e76e8199196d454941c45d1b3a323f1433bd6"))
check("bech32 re-encode", segwit_encode("bc", 0, prog) == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
# bech32m (BIP-350): round trip + encoding rules (cross-checked against a real
# mainnet bc1p address in the live validation step)
prog32 = bytes(range(32))
tr = segwit_encode("bc", 1, prog32, bech32m=True)
h2, ver2, prog2 = segwit_decode(tr)
check("bech32m p2tr roundtrip", (h2, ver2, prog2) == ("bc", 1, prog32))
try:
    segwit_decode(tr)  # sanity: re-decode works
    check("bech32m re-decode", True)
except ValueError:
    check("bech32m re-decode", False)
try:
    segwit_encode("bc", 1, prog32)  # v1 must use bech32m, not bech32
    v1b32 = segwit_encode("bc", 1, prog32)
    segwit_decode(v1b32)
    check("v1+bech32 rejected", False)
except ValueError:
    check("v1+bech32 rejected", True)
try:
    segwit_decode(tr[:-2] + "qq")  # tamper
    check("bech32 tamper rejected", False)
except ValueError:
    check("bech32 tamper rejected", True)

# --- varint round trips ---
for n in (0, 1, 252, 253, 0xFFFF, 0x10000, 0xFFFFFFFF, 2**64 - 1):
    check("varint %d" % n, Cursor(encode_varint(n)).varint() == n)

# --- script classification ---
P2PKH = bytes.fromhex("76a914751e76e8199196d454941c45d1b3a323f1433bd688ac")
check("classify p2pkh", classify_scriptpubkey(P2PKH) ==
      ("P2PKH", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"))
P2WPKH = bytes.fromhex("0014751e76e8199196d454941c45d1b3a323f1433bd6")
check("classify p2wpkh", classify_scriptpubkey(P2WPKH) ==
      ("P2WPKH", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"))
OPR = bytes.fromhex("6a0b68656c6c6f20776f726c64")
t, note = classify_scriptpubkey(OPR)
check("classify op_return", t == "OP_RETURN" and note == "68656c6c6f20776f726c64")
MSIG = bytes.fromhex("52" + "21" + G_COMP.hex() + "21" + G_COMP.hex() + "52ae")
check("classify multisig", classify_scriptpubkey(MSIG) == ("MULTISIG", "2-of-2"))
check("disassemble", disassemble(P2PKH) ==
      ["OP_DUP", "OP_HASH160", "<751e76e8199196d454941c45d1b3a323f1433bd6>",
       "OP_EQUALVERIFY", "OP_CHECKSIG"])

# --- genesis block header: hash must equal the famous value ---
GENESIS80 = bytes.fromhex(
    "01000000" + "00" * 32 +
    "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a" +
    "29ab5f49" + "ffff001d" + "1dac2b7c")
hdr = parse_header(GENESIS80)
check("genesis hash", hdr["hash"] == "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
check("genesis merkle", hdr["merkle"] == "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")

# --- merkle tree odd-duplication rule ---
a = sha256d(b"a")[::-1]; b = sha256d(b"b")[::-1]; c3 = sha256d(b"c")[::-1]
root3 = merkle_root([a, b, c3])
manual = sha256d(sha256d(a + b) + sha256d(c3 + c3))
check("merkle odd duplication", root3 == manual)
check("merkle single", merkle_root([a]) == a)

# --- ECDSA verify self-consistency (sign via raw k, verify) ---
import random
random.seed(42)
priv = random.randrange(1, _N)
pub = _pmul(priv)
pub_ser = bytes([2 + (pub[1] & 1)]) + pub[0].to_bytes(32, "big")
msg = sha256d(b"scout test message")
k = random.randrange(1, _N)
R = _pmul(k)
r = R[0] % _N
s = (pow(k, _N - 2, _N) * (int.from_bytes(msg, "big") + r * priv)) % _N
check("ecdsa verify valid", ecdsa_verify(pub_ser, msg, r, s))
# note: (r, N-s) is also a valid raw-ECDSA signature (malleability) — not tested
check("ecdsa verify bad r", not ecdsa_verify(pub_ser, msg, (r + 1) % _N, s))
check("ecdsa verify bad msg", not ecdsa_verify(pub_ser, sha256d(b"other"), r, s))

# --- synthetic legacy tx: parse -> serialize -> txid stability ---
raw_tx = bytes.fromhex(
    "01000000"            # version
    "01"                  # 1 input
    + "00" * 32 + "00000000"   # prev txid 0, vout 0
    + "00"                # empty scriptsig
    + "ffffffff"          # sequence
    + "01"                # 1 output
    + "00e1f50500000000"  # 1 BTC
    + "19" + P2PKH.hex()  # p2pkh script
    + "00000000")         # locktime
tx = parse_tx(raw_tx)
check("parse version", tx["version"] == 1 and len(tx["ins"]) == 1 and len(tx["outs"]) == 1)
check("txid stable", txid(tx) == sha256d(serialize_tx(tx, for_txid=True))[::-1].hex())
check("roundtrip bytes", serialize_tx(tx, for_txid=True) == raw_tx)
try:
    parse_tx(raw_tx + b"\x00")
    check("trailing bytes rejected", False)
except ValueError:
    check("trailing bytes rejected", True)

print("ALL %d OFFLINE CHECKS PASSED" % len(passed))
