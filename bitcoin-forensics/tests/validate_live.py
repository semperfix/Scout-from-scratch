#!/usr/bin/env python3
"""tests/validate_live.py — validate the hand-rolled stack against real
mainnet data from blockstream.info (read-only GETs).

1. Fetch a full raw block, parse it, verify header hash + merkle root.
2. Parse several raw transactions; assert our txid == network txid.
3. Verify a real legacy P2PKH ECDSA signature (sighash rebuilt from scratch).
4. Verify a real BIP-143 P2WPKH ECDSA signature (sighash rebuilt from scratch).
5. Decode a real mainnet bc1p (taproot/bech32m) address.
"""
import sys, os, json, urllib.request
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from btc_tx import (parse_block, parse_tx, txid, verify_block_merkle,
                    verify_p2pkh_input, verify_p2wpkh_input,
                    classify_scriptpubkey, script_items)
from btc_core import segwit_decode

BASE = "https://blockstream.info/api"


def fetch(path):
    """GET -> (content_type, body)."""
    req = urllib.request.Request(BASE + path, headers={"User-Agent": "scout-forensics/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def api_json(path):
    return json.loads(fetch(path).decode())


passed = []
def check(name, cond, extra=""):
    assert cond, "FAILED: " + name + " " + str(extra)
    passed.append(name)
    print("ok -", name, extra)


# --- 1. full block parse + merkle verification ---
height = int(fetch("/blocks/tip/height").decode()) - 6
bhash = fetch("/block-height/%d" % height).decode().strip()
rawblock = fetch("/block/%s/raw" % bhash)
block = parse_block(rawblock)
hdr = block["header"]
check("block header hash == network id", hdr["hash"] == bhash, bhash[:20] + "...")
check("block merkle root verifies", verify_block_merkle(block),
      "ntx=%d" % len(block["txs"]))
check("tx count matches header list", len(api_json("/block/%s/txids" % bhash)) == len(block["txs"]))

# --- 2-5. transaction-level validation over block txs ---
txids = api_json("/block/%s/txids" % bhash)
p2pkh_done = p2wpkh_done = taproot_done = False
n_parsed = 0
for t in txids[1:]:  # skip coinbase
    if p2pkh_done and p2wpkh_done and taproot_done:
        break
    raw = bytes.fromhex(fetch("/tx/%s/hex" % t).decode().strip())
    tx = parse_tx(raw)
    check("txid(%s) matches" % t[:12], txid(tx) == t)
    n_parsed += 1
    if n_parsed > 40:
        break
    meta = api_json("/tx/%s" % t)

    for i, vin in enumerate(tx["ins"]):
        if p2pkh_done and p2wpkh_done:
            break
        prev = meta["vin"][i].get("prevout")
        if not prev:
            continue
        # legacy P2PKH: scriptsig of [sig, pubkey]
        if not p2pkh_done and not tx["segwit"]:
            pushes = [d for k, d in script_items(vin["scriptsig"]) if k == "data"]
            if len(pushes) == 2 and len(pushes[1]) in (33, 65):
                ok = verify_p2pkh_input(tx, i, bytes.fromhex(prev["scriptpubkey"]))
                check("real P2PKH signature verifies", ok, t[:16])
                p2pkh_done = True
        # segwit v0 P2WPKH: witness of [sig, pubkey]
        if not p2wpkh_done and tx["segwit"]:
            wit = tx["witness"][i]
            if len(wit) == 2 and len(wit[1]) == 33:
                ok = verify_p2wpkh_input(tx, i, prev["value"])
                check("real P2WPKH signature verifies", ok, t[:16])
                p2wpkh_done = True

    if not taproot_done:
        for v in meta["vout"]:
            if v["scriptpubkey_type"] == "v1_p2tr":
                hrp, ver, prog = segwit_decode(v["scriptpubkey_address"])
                check("real bc1p bech32m decodes", (hrp, ver, len(prog)) == ("bc", 1, 32),
                      v["scriptpubkey_address"][:24] + "...")
                taproot_done = True
                break

print("parsed %d txs; p2pkh=%s p2wpkh=%s taproot=%s" %
      (n_parsed, p2pkh_done, p2wpkh_done, taproot_done))
assert p2wpkh_done and taproot_done, "missing segwit/taproot samples (block too old?)"
print("LIVE CHECKS PASSED (%d)" % len(passed))
