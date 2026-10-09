#!/usr/bin/env python3
"""Validation suite for the from-scratch Nostr stack.

Oracles: official BIP-340 test vectors, the real nostr-tools JS library
(event hash/sign/verify + NIP-04 encrypt/decrypt), pycryptodome (AES-256),
and live events from relay.damus.io.
"""
import csv
import json
import os
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from secp import sha256, xonly_pubkey
from schnorr import sign, verify, tagged_hash
from event import (sign_event, verify_event, event_id, hex_to_npub,
                   npub_to_hex, hex_to_nsec, nsec_to_npub, bech32_encode,
                   bech32_decode, note_to_hex)
from ws import sha1, client_connect, server_accept, parse_ws_url
from relay import Relay
from client import NostrClient
from nip04 import (nip04_encrypt, nip04_decrypt, shared_key,
                   _enc_block, _cbc_encrypt, _cbc_decrypt)

HERE = os.path.dirname(os.path.abspath(__file__))
passed = failed = 0


def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
    else:
        failed += 1
        print("FAIL:", name)


def node_available():
    return (os.path.exists("/tmp/nostr-interop/node_modules/nostr-tools") and
            subprocess.run(["which", "node"], capture_output=True).returncode == 0)


# ---------------------------------------------------------------- 1. BIP-340
with open(os.path.join(HERE, "bip0340.csv")) as f:
    vectors = list(csv.DictReader(f))
for row in vectors:
    idx = int(row["index"])
    pk, msg = bytes.fromhex(row["public key"]), bytes.fromhex(row["message"])
    sig = bytes.fromhex(row["signature"])
    want = row["verification result"] == "TRUE"
    check(f"bip340 verify vector {idx} -> {want}", verify(pk, msg, sig) == want)
for row in vectors[:4]:  # signing vectors
    idx = int(row["index"])
    sk = bytes.fromhex(row["secret key"])
    check(f"bip340 sign vector {idx} byte-exact",
          sign(sk, bytes.fromhex(row["message"]),
               bytes.fromhex(row["aux_rand"])).hex() == row["signature"].lower())
    check(f"bip340 pubkey vector {idx}",
          xonly_pubkey(sk).hex() == row["public key"].lower())
# roundtrip + tamper
sk = os.urandom(32)
pk = xonly_pubkey(sk)
m = os.urandom(32)
sig = sign(sk, m)
check("schnorr roundtrip", verify(pk, m, sig))
bad = bytearray(sig)
bad[17] ^= 1
check("schnorr tamper rejected", not verify(pk, m, bytes(bad)))
check("schnorr wrong-key rejected",
      not verify(xonly_pubkey(os.urandom(32)), m, sig))

# ---------------------------------------------------------- 2. events/NIP-19
ev = sign_event(sk.hex(), 1, "hello nostr", tags=[["t", "test"]], created_at=1700000000)
check("event self-verifies", verify_event(ev)[0])
check("event id is sha256 of canonical json",
      ev["id"] == sha256(json.dumps(
          [0, ev["pubkey"], 1700000000, 1, [["t", "test"]], "hello nostr"],
          separators=(",", ":"), ensure_ascii=False).encode()).hex())
mut = dict(ev, content="forged")
ok, reason = verify_event(mut)
check("event tamper -> id mismatch", not ok and "id does not match" in reason)
mut2 = dict(ev, sig="00" * 64)
check("event sig tamper rejected", not verify_event(mut2)[0])
check("npub roundtrip", npub_to_hex(hex_to_npub(pk.hex())) == pk.hex())
check("nsec->npub", nsec_to_npub(hex_to_nsec(sk.hex())) == hex_to_npub(pk.hex()))
check("note id", note_to_hex(bech32_encode("note", bytes.fromhex(ev["id"]))) == ev["id"])
# NIP-01 interop with real nostr-tools (event hash + signature both directions)
if node_available():
    open("/tmp/nostr-interop/pyev.json", "w").write(json.dumps(
        {k: ev[k] for k in ("pubkey", "created_at", "kind", "tags", "content")}))
    js = subprocess.run(
        ["node", "--input-type=module", "-e", """
import { getEventHash, verifySignature, signEvent, getPublicKey } from 'nostr-tools';
import fs from 'fs';
const partial = JSON.parse(fs.readFileSync('/tmp/nostr-interop/pyev.json'));
const h = getEventHash(partial);                       // hash of MY unsigned event
const full = { ...partial, id: h, sig: process.argv[1] };
const v = verifySignature(full);                       // verify MY signature
const jsk = process.argv[2];
const jpub = getPublicKey(jsk);
const jev = { kind: 1, created_at: 1700000001, tags: [], content: 'js made', pubkey: jpub };
jev.id = getEventHash(jev); jev.sig = signEvent(jev, jsk);   // JS signs its own
fs.writeFileSync('/tmp/nostr-interop/jev.json', JSON.stringify(jev));
console.log(JSON.stringify({ hash: h, valid: v }));
""", ev["sig"], sk.hex()],
        capture_output=True, text=True, cwd="/tmp/nostr-interop")
    assert js.returncode == 0, js.stderr[-500:]
    r = json.loads(js.stdout)
    check("nostr-tools getEventHash == my event id", r["hash"] == ev["id"])
    check("nostr-tools verifySignature accepts my sig", r["valid"] is True)
    jev = json.load(open("/tmp/nostr-interop/jev.json"))
    ok, reason = verify_event(jev)
    check("my code verifies JS-signed event", ok)
else:
    print("SKIP: nostr-tools NIP-01 interop (node_modules absent)")

print(f"so far: {passed} passed, {failed} failed")

# ---------------------------------------------------------------- 3. websocket
import hashlib
for v in (b"", b"abc", b"The quick brown fox jumps over the lazy dog"):
    check(f"sha1 {v[:9]!r} matches hashlib", sha1(v) == hashlib.sha1(v).digest())
import socket as _socket
srv = _socket.socket()
srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(1)
port = srv.getsockname()[1]
got = {}


def _serve():
    c, _ = srv.accept()
    ws = server_accept(c)
    got["a"] = ws.recv_text()
    got["b"] = ws.recv_text()
    ws.send_text("ack")
    ws.close()


threading.Thread(target=_serve, daemon=False).start()
cli = client_connect("127.0.0.1", port)
cli.send_text("ping")
cli.send_text("z" * 70000)  # 64-bit extended length, masked
check("ws server reply", cli.recv_text() == "ack")
# the server only sends "ack" after receiving both frames, so got[] is stable
check("ws loopback small+70k frames", got.get("a") == "ping" and got.get("b") == "z" * 70000)
cli.close()
check("ws url parse", parse_ws_url("wss://relay.damus.io/") == ("relay.damus.io", 443, "/", True))

# -------------------------------------------------------------- 4. relay e2e
relay = Relay()
threading.Thread(target=relay.serve, kwargs={"port": 17791}, daemon=True).start()
time.sleep(0.4)
sk1, sk2 = os.urandom(32).hex(), os.urandom(32).hex()
pk1 = xonly_pubkey(bytes.fromhex(sk1)).hex()
pk2 = xonly_pubkey(bytes.fromhex(sk2)).hex()
c = NostrClient("ws://127.0.0.1:17791")
pub = [sign_event(sk1, 1, f"note {i}", created_at=1700000100 + i) for i in range(3)]
pub.append(sign_event(sk2, 1, "reply", tags=[["e", pub[0]["id"]], ["p", pk1]],
                             created_at=1700000110))
for e in pub:
    ok, _ = c.publish(e)
    check(f"relay accepts {e['id'][:8]}", ok)
check("relay query kinds", len(c.query({"kinds": [1]})) == 4)
check("relay author filter",
      len(c.query({"authors": [pk1]})) == 3)
check("relay limit", len(c.query({"kinds": [1], "limit": 2})) == 2)
check("relay since", len(c.query({"since": 1700000102})) == 2)
check("relay #e tag filter",
      [e["content"] for e in c.query({"#e": [pub[0]["id"]]})] == ["reply"])
check("relay #p tag filter",
      len(c.query({"#p": [pk1]})) == 1)
m1 = sign_event(sk1, 0, '{"name":"v1"}', created_at=1700000200)
m2 = sign_event(sk1, 0, '{"name":"v2"}', created_at=1700000210)
c.publish(m1)
c.publish(m2)
q = c.query({"kinds": [0], "authors": [pk1]})
check("replaceable: newest wins", len(q) == 1 and '"v2"' in q[0]["content"])
forged = dict(pub[0], content="forged")
ok, why = c.publish(forged)
check("relay rejects tampered event", not ok)
check("relay dedups", c.publish(pub[0])[0] is True)
c.close()

# ------------------------------------------------------------------ 5. NIP-04
from Crypto.Cipher import AES as _PAES
for _ in range(30):
    k, pt = os.urandom(32), os.urandom(16)
    check("aes256 block == pycryptodome (sampled)", _enc_block(k, pt) == _PAES.new(k, _PAES.MODE_ECB).encrypt(pt))
for ln in (0, 1, 15, 16, 17, 1000):
    k, iv = os.urandom(32), os.urandom(16)
    m = os.urandom(ln)
    check(f"cbc roundtrip len={ln}", _cbc_decrypt(k, iv, _cbc_encrypt(k, iv, m)) == m)
a_priv, b_priv = os.urandom(32).hex(), os.urandom(32).hex()
a_pub = xonly_pubkey(bytes.fromhex(a_priv)).hex()
b_pub = xonly_pubkey(bytes.fromhex(b_priv)).hex()
check("ecdh symmetric", shared_key(a_priv, b_pub) == shared_key(b_priv, a_pub))
for txt in ("", "hi", "x" * 16, "unicode 🦊 test " * 50):
    p = nip04_encrypt(a_priv, b_pub, txt)
    check(f"nip04 roundtrip len={len(txt)}", nip04_decrypt(b_priv, a_pub, p) == txt)
    check("nip04 wire format", "?iv=" in p)
if node_available():
    r = subprocess.run(
        ["node", "--input-type=module", "-e", """
import { generatePrivateKey, getPublicKey, nip04 } from 'nostr-tools';
const skA = generatePrivateKey(), pkA = getPublicKey(skA);
const skB = generatePrivateKey(), pkB = getPublicKey(skB);
const jsEnc = await nip04.encrypt(skA, pkB, 'js->py');
const pyEnc = process.argv[1];
const jsDec = (pyEnc && pyEnc !== 'NONE') ? await nip04.decrypt(skB, pkA, pyEnc) : null;
console.log(JSON.stringify({ skA, pkA, skB, pkB, jsEnc, jsDec }));
""", "NONE"], capture_output=True, text=True, cwd="/tmp/nostr-interop")
    assert r.returncode == 0, r.stderr[-500:]
    d = json.loads(r.stdout)
    check("py decrypts nostr-tools ciphertext",
          nip04_decrypt(d["skB"], d["pkA"], d["jsEnc"]) == "js->py")
    py_enc = nip04_encrypt(d["skA"], d["pkB"], "py->js")
    r2 = subprocess.run(
        ["node", "--input-type=module", "-e", """
import { nip04 } from 'nostr-tools';
const [skB, pkA, pyEnc] = process.argv.slice(1);
console.log(await nip04.decrypt(skB, pkA, pyEnc));
""", d["skB"], d["pkA"], py_enc],
        capture_output=True, text=True, cwd="/tmp/nostr-interop")
    check("nostr-tools decrypts py ciphertext", r2.stdout.strip() == "py->js")
else:
    print("SKIP: nostr-tools NIP-04 interop")

# ------------------------------------------------------- 6. live public relay
try:
    lc = NostrClient("wss://relay.damus.io/", timeout=25)
    evs = lc.query({"kinds": [1], "limit": 10}, timeout=40)
    lc.close()
    n_bad = sum(1 for e in evs if not verify_event(e)[0])
    check(f"live: {len(evs)} real events fetched", len(evs) > 0)
    check(f"live: all {len(evs)} pass my Schnorr+id verification", n_bad == 0)
except Exception as ex:
    print("SKIP live relay check:", type(ex).__name__, str(ex)[:120])

print(f"\nFINAL: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
