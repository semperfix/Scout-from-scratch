#!/usr/bin/env python3
"""trace.py — Bitcoin transaction forensic triage.

Usage:
    python3 trace.py <txid> [--fetch]     # pull raw tx (+ prevouts) from blockstream
    python3 trace.py --hex <rawhex>        # analyze offline from raw hex

Report: structure, per-input/per-output decode, address classification,
value flow, fee, and scam-relevant heuristics (change detection, dust,
OP_RETURN data, RBF, multisig, round-number amounts, common-input cluster).
"""
import sys, os, json, urllib.request
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from btc_tx import (parse_tx, txid, wtxid, serialize_tx, disassemble,
                    classify_scriptpubkey, script_items, verify_p2pkh_input,
                    verify_p2wpkh_input)
from btc_core import hash160

DUST_SAT = 546
BASE = "https://blockstream.info/api"


def fetch(path):
    req = urllib.request.Request(BASE + path, headers={"User-Agent": "scout-forensics/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def btc(sat):
    return "%.8f" % (sat / 1e8)


def input_address(vin, witness):
    """Best-effort sender address from scriptSig/witness pubkey."""
    pushes = [d for k, d in script_items(vin["scriptsig"]) if k == "data"]
    if len(pushes) == 2 and len(pushes[1]) in (33, 65):  # P2PKH scriptSig
        from btc_core import b58check_encode
        return b58check_encode(hash160(pushes[1]), b"\x00") + " (from scriptSig pubkey)"
    if witness:
        for w in witness:
            if len(w) == 33 and w[0] in (2, 3):
                from btc_core import segwit_encode
                return segwit_encode("bc", 0, hash160(w)) + " (from witness pubkey)"
    return "?"


def opreturn_label(payload_hex):
    p = payload_hex.lower()
    if p.startswith("6f6d6e69"):
        return "OMNI layer"
    if p.startswith("00000000"):
        return "possible counterparty/stamp"
    try:
        txt = bytes.fromhex(p).decode("utf-8", "strict")
        if txt.isprintable():
            return "ascii: %r" % txt[:60]
    except Exception:
        pass
    return "raw %d bytes" % (len(p) // 2)


def analyze(tx, meta=None):
    L = []
    tid, wid = txid(tx), wtxid(tx)
    L.append("txid : %s" % tid)
    if tx["segwit"]:
        L.append("wtxid: %s" % wid)
    size = len(serialize_tx(tx))
    L.append("version=%d  size=%d vbytes  segwit=%s  locktime=%d%s" % (
        tx["version"], size, tx["segwit"], tx["locktime"],
        " (block height)" if tx["locktime"] < 500_000_000 and tx["locktime"] else
        (" (timestamp)" if tx["locktime"] else "")))
    rbf = any(v["sequence"] < 0xfffffffe for v in tx["ins"])
    L.append("RBF signaling: %s" % rbf)
    L.append("")
    L.append("== INPUTS (%d) ==" % len(tx["ins"]))
    in_total = 0
    in_addrs = set()
    for i, vin in enumerate(tx["ins"]):
        w = tx["witness"][i] if tx["segwit"] else None
        prev = meta["vin"][i].get("prevout") if meta else None
        val = prev["value"] if prev else None
        if val:
            in_total += val
        addr = prev.get("scriptpubkey_address") if prev else None
        if not addr:
            addr = input_address(vin, w)
        else:
            in_addrs.add(addr)
        L.append("[%d] %s:%d  %s BTC  <- %s" % (
            i, vin["prev_txid"][::-1].hex(), vin["vout"],
            btc(val) if val is not None else "?", addr))
        if not tx["segwit"]:
            L.append("     scriptsig: %s" % " ".join(disassemble(vin["scriptsig"]))[:160])
            if prev and not vin["prev_txid"] == bytes(32):
                try:
                    ok = verify_p2pkh_input(tx, i, bytes.fromhex(prev["scriptpubkey"]))
                    L.append("     signature: %s" % ("VALID" if ok else "INVALID"))
                except Exception as e:
                    L.append("     signature: could not verify (%s)" % e)
        else:
            tag = ""
            if w and len(w) >= 3 and len(w[0]) == 0:
                tag = "  [multisig-style witness: dummy + %d sigs + script]" % (len(w) - 2)
                try:
                    t2, note2 = classify_scriptpubkey(w[-1])
                    tag += "  policy=%s %s" % (t2, note2)
                except Exception:
                    pass
            L.append("     witness: %d items %s%s" % (
                len(w), str([len(x) for x in w]), tag))
            if prev and len(w) == 2 and len(w[1]) == 33:
                try:
                    ok = verify_p2wpkh_input(tx, i, prev["value"])
                    L.append("     signature: %s" % ("VALID" if ok else "INVALID"))
                except Exception as e:
                    L.append("     signature: could not verify (%s)" % e)
    L.append("")
    L.append("== OUTPUTS (%d) ==" % len(tx["outs"]))
    out_total = 0
    out_types = []
    for i, vout in enumerate(tx["outs"]):
        typ, addr = classify_scriptpubkey(vout["scriptpubkey"])
        out_types.append(typ)
        out_total += vout["value"]
        line = "[%d] %s BTC  %-10s %s" % (i, btc(vout["value"]), typ, addr)
        if typ == "OP_RETURN":
            line += "  [%s]" % opreturn_label(addr)
        if vout["value"] <= DUST_SAT and typ != "OP_RETURN":
            line += "  [DUST]"
        if vout["value"] % 100_000_000 == 0 and vout["value"]:
            line += "  [round BTC amount]"
        L.append(line)
    L.append("")
    L.append("== FLOW ==")
    L.append("in:  %s BTC%s" % (btc(in_total), "" if meta else " (prevouts unknown offline)"))
    L.append("out: %s BTC" % btc(out_total))
    if meta and in_total:
        fee = in_total - out_total
        L.append("fee: %s BTC  (%d sat/vbyte)" % (btc(fee), fee // size))
        if fee > 1_000_000:  # > 0.01 BTC
            L.append("  [HIGH FEE — possible fat-finger or urgent]")
        elif fee // size > 50:
            L.append("  [elevated fee rate for current network — urgent or overpaid]")
    L.append("")
    L.append("== HEURISTICS ==")
    h = []
    if len(tx["ins"]) > 1:
        h.append("common-input-ownership: %d inputs likely controlled by one wallet "
                 "(%d distinct prevout addresses seen)" % (len(tx["ins"]), len(in_addrs)))
    if len(tx["ins"]) == 1 and len(tx["outs"]) >= 5:
        h.append("payout batch shape: 1 input fanning out to %d outputs "
                 "(exchange/service payouts look like this)" % len(tx["outs"]))
    if len(tx["ins"]) == 1 and len(tx["outs"]) == 2:
        types = set(out_types)
        if len(types) == 1 and "OP_RETURN" not in types:
            h.append("possible change output: 1 in / 2 outs of same type — "
                     "the non-round, non-dust output is likely change back to sender")
    n_ret = sum(1 for t in out_types if t == "OP_RETURN")
    if n_ret:
        h.append("carries %d OP_RETURN data output(s) — check label above" % n_ret)
    if any(t == "MULTISIG" for t in out_types):
        h.append("multisig output present — escrow/pooling shape")
    if any("P2TR" == t for t in out_types):
        h.append("taproot output — modern wallet / possible ordinal inscription")
    dust_n = sum(1 for v in tx["outs"] if v["value"] <= DUST_SAT)
    if dust_n:
        h.append("%d dust output(s) — spam/airdrop-dusting pattern" % dust_n)
    if tx["locktime"]:
        h.append("nLockTime set (%d) — timelocked / replaceable" % tx["locktime"])
    if not h:
        h.append("no notable heuristics")
    L.extend("- " + x for x in h)
    return "\n".join(L)


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return
    meta = None
    if args[0] == "--hex":
        tx = parse_tx(bytes.fromhex(args[1]))
    else:
        t = args[0].strip().lower()
        raw = bytes.fromhex(fetch("/tx/%s/hex" % t).decode().strip())
        tx = parse_tx(raw)
        assert txid(tx) == t, "fetched txid mismatch"
        if "--fetch" in args:
            meta = json.loads(fetch("/tx/%s" % t).decode())
    print(analyze(tx, meta))


if __name__ == "__main__":
    main()
