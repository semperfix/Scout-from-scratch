#!/usr/bin/env python3
"""btc_tx.py — Bitcoin transaction / script / block parsing, hand-rolled.

Serialization is all manual: compactsize varints, little-endian fields,
legacy vs segwit (BIP-144) transaction layouts, Script disassembly with
opcode names, block headers, merkle-root computation, and scriptPubKey ->
human address classification (P2PKH, P2SH, P2WPKH, P2WSH, P2TR, OP_RETURN,
bare multisig).
"""

from btc_core import (
    sha256, sha256d, hash160, b58check_encode, segwit_encode, segwit_decode,
    pubkey_to_coords, ecdsa_verify,
)

# --------------------------------------------------------------------------
# Serialization primitives
# --------------------------------------------------------------------------


class Cursor:
    def __init__(self, data: bytes):
        self.d = data
        self.p = 0

    def read(self, n: int) -> bytes:
        if self.p + n > len(self.d):
            raise ValueError("truncated transaction")
        out = self.d[self.p:self.p + n]
        self.p += n
        return out

    def u8(self):
        return self.read(1)[0]

    def u16(self):
        return int.from_bytes(self.read(2), "little")

    def u32(self):
        return int.from_bytes(self.read(4), "little")

    def u64(self):
        return int.from_bytes(self.read(8), "little")

    def varint(self):
        b = self.u8()
        if b < 0xFD:
            return b
        if b == 0xFD:
            return self.u16()
        if b == 0xFE:
            return self.u32()
        return self.u64()

    def varbytes(self):
        n = self.varint()
        return self.read(n)

    def left(self):
        return len(self.d) - self.p


def encode_varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


# --------------------------------------------------------------------------
# Script
# --------------------------------------------------------------------------

_OPCODES = {
    0x00: "OP_0", 0x4c: "OP_PUSHDATA1", 0x4d: "OP_PUSHDATA2", 0x4e: "OP_PUSHDATA4",
    0x4f: "OP_1NEGATE", 0x50: "OP_RESERVED", 0x51: "OP_1", 0x52: "OP_2",
    0x53: "OP_3", 0x54: "OP_4", 0x55: "OP_5", 0x56: "OP_6", 0x57: "OP_7",
    0x58: "OP_8", 0x59: "OP_9", 0x5a: "OP_10", 0x5b: "OP_11", 0x5c: "OP_12",
    0x5d: "OP_13", 0x5e: "OP_14", 0x5f: "OP_15", 0x60: "OP_16", 0x61: "OP_NOP",
    0x62: "OP_VER", 0x63: "OP_IF", 0x64: "OP_NOTIF", 0x65: "OP_VERIF",
    0x66: "OP_VERNOTIF", 0x67: "OP_ELSE", 0x68: "OP_ENDIF", 0x69: "OP_VERIFY",
    0x6a: "OP_RETURN", 0x6b: "OP_TOALTSTACK", 0x6c: "OP_FROMALTSTACK",
    0x6d: "OP_2DROP", 0x6e: "OP_2DUP", 0x6f: "OP_3DUP", 0x70: "OP_2OVER",
    0x71: "OP_2ROT", 0x72: "OP_2SWAP", 0x73: "OP_IFDUP", 0x74: "OP_DEPTH",
    0x75: "OP_DROP", 0x76: "OP_DUP", 0x77: "OP_NIP", 0x78: "OP_OVER",
    0x79: "OP_PICK", 0x7a: "OP_ROLL", 0x7b: "OP_ROT", 0x7c: "OP_SWAP",
    0x7d: "OP_TUCK", 0x7e: "OP_CAT", 0x7f: "OP_SUBSTR", 0x80: "OP_LEFT",
    0x81: "OP_RIGHT", 0x82: "OP_SIZE", 0x83: "OP_INVERT", 0x84: "OP_AND",
    0x85: "OP_OR", 0x86: "OP_XOR", 0x87: "OP_EQUAL", 0x88: "OP_EQUALVERIFY",
    0x89: "OP_RESERVED1", 0x8a: "OP_RESERVED2", 0x8b: "OP_1ADD", 0x8c: "OP_1SUB",
    0x8d: "OP_2MUL", 0x8e: "OP_2DIV", 0x8f: "OP_NEGATE", 0x90: "OP_ABS",
    0x91: "OP_NOT", 0x92: "OP_0NOTEQUAL", 0x93: "OP_ADD", 0x94: "OP_SUB",
    0x95: "OP_MUL", 0x96: "OP_DIV", 0x97: "OP_MOD", 0x98: "OP_LSHIFT",
    0x99: "OP_RSHIFT", 0x9a: "OP_BOOLAND", 0x9b: "OP_BOOLOR",
    0x9c: "OP_NUMEQUAL", 0x9d: "OP_NUMEQUALVERIFY", 0x9e: "OP_NUMNOTEQUAL",
    0x9f: "OP_LESSTHAN", 0xa0: "OP_GREATERTHAN", 0xa1: "OP_LESSTHANOREQUAL",
    0xa2: "OP_GREATERTHANOREQUAL", 0xa3: "OP_MIN", 0xa4: "OP_MAX",
    0xa5: "OP_WITHIN", 0xa6: "OP_RIPEMD160", 0xa7: "OP_SHA1",
    0xa8: "OP_SHA256", 0xa9: "OP_HASH160", 0xaa: "OP_HASH256",
    0xab: "OP_CODESEPARATOR", 0xac: "OP_CHECKSIG",
    0xad: "OP_CHECKSIGVERIFY", 0xae: "OP_CHECKMULTISIG",
    0xaf: "OP_CHECKMULTISIGVERIFY", 0xb0: "OP_NOP1",
    0xb1: "OP_CHECKLOCKTIMEVERIFY", 0xb2: "OP_CHECKSEQUENCEVERIFY",
    0xb3: "OP_NOP4", 0xb4: "OP_NOP5", 0xb5: "OP_NOP6", 0xb6: "OP_NOP7",
    0xb7: "OP_NOP8", 0xb8: "OP_NOP9", 0xb9: "OP_NOP10", 0xba: "OP_CHECKSIGADD",
    0xff: "OP_INVALIDOPCODE",
}


def disassemble(script: bytes):
    """Script -> list of tokens: opcode names or '<hex>' data pushes."""
    out = []
    i = 0
    while i < len(script):
        op = script[i]
        i += 1
        if op == 0x00:
            out.append("OP_0")
        elif op <= 0x4B:
            out.append("<%s>" % script[i:i + op].hex())
            i += op
        elif op == 0x4C:
            n = script[i]; i += 1
            out.append("<%s>" % script[i:i + n].hex()); i += n
        elif op == 0x4D:
            n = int.from_bytes(script[i:i + 2], "little"); i += 2
            out.append("<%s>" % script[i:i + n].hex()); i += n
        elif op == 0x4E:
            n = int.from_bytes(script[i:i + 4], "little"); i += 4
            out.append("<%s>" % script[i:i + n].hex()); i += n
        else:
            out.append(_OPCODES.get(op, "OP_UNKNOWN_%02x" % op))
    return out


def script_items(script: bytes):
    """Script -> list of ('op', name) or ('data', bytes) items."""
    items = []
    i = 0
    while i < len(script):
        op = script[i]
        i += 1
        if op == 0x00:
            items.append(("op", 0x00))
        elif op <= 0x4B:
            items.append(("data", script[i:i + op])); i += op
        elif op == 0x4C:
            n = script[i]; i += 1
            items.append(("data", script[i:i + n])); i += n
        elif op == 0x4D:
            n = int.from_bytes(script[i:i + 2], "little"); i += 2
            items.append(("data", script[i:i + n])); i += n
        elif op == 0x4E:
            n = int.from_bytes(script[i:i + 4], "little"); i += 4
            items.append(("data", script[i:i + n])); i += n
        else:
            items.append(("op", op))
    return items


def classify_scriptpubkey(script: bytes):
    """Return (type, address_or_note). Address types decode to real strings."""
    it = script_items(script)
    ops = [x for x in it if x[0] == "op"]
    datas = [x[1] for x in it if x[0] == "data"]
    # P2PKH: DUP HASH160 <20> EQUALVERIFY CHECKSIG
    if (len(it) == 5 and it[0] == ("op", 0x76) and it[1] == ("op", 0xa9)
            and it[2][0] == "data" and len(it[2][1]) == 20
            and it[3] == ("op", 0x88) and it[4] == ("op", 0xac)):
        return "P2PKH", b58check_encode(it[2][1], b"\x00")
    # P2SH: HASH160 <20> EQUAL
    if (len(it) == 3 and it[0] == ("op", 0xa9) and it[1][0] == "data"
            and len(it[1][1]) == 20 and it[2] == ("op", 0x87)):
        return "P2SH", b58check_encode(it[1][1], b"\x05")
    # P2WPKH: 0 <20>
    if (len(it) == 2 and it[0] == ("op", 0x00) and it[1][0] == "data"
            and len(it[1][1]) == 20):
        return "P2WPKH", segwit_encode("bc", 0, it[1][1])
    # P2WSH: 0 <32>
    if (len(it) == 2 and it[0] == ("op", 0x00) and it[1][0] == "data"
            and len(it[1][1]) == 32):
        return "P2WSH", segwit_encode("bc", 0, it[1][1])
    # P2TR: 1 <32>
    if (len(it) == 2 and it[0] == ("op", 0x51) and it[1][0] == "data"
            and len(it[1][1]) == 32):
        return "P2TR", segwit_encode("bc", 1, it[1][1], bech32m=True)
    # OP_RETURN
    if it and it[0] == ("op", 0x6a):
        payload = "".join(d.hex() for t, d in it[1:] if t == "data")
        note = payload[:64] + ("..." if len(payload) > 64 else "")
        return "OP_RETURN", note or "(empty)"
    # bare multisig: <m> <pub>... <n> CHECKMULTISIG
    if (len(it) >= 4 and it[0][0] == "op" and 0x51 <= it[0][1] <= 0x60
            and it[-1] == ("op", 0xae) and it[-2][0] == "op"
            and 0x51 <= it[-2][1] <= 0x60):
        m = it[0][1] - 0x50
        n = it[-2][1] - 0x50
        pubs = [d for t, d in it[1:-2] if t == "data"]
        if len(pubs) == n and all(len(p) in (33, 65) for p in pubs):
            return "MULTISIG", "%d-of-%d" % (m, n)
    # P2PK: <pubkey> CHECKSIG
    if (len(it) == 2 and it[0][0] == "data" and len(it[0][1]) in (33, 65)
            and it[1] == ("op", 0xac)):
        return "P2PK", it[0][1].hex()[:40] + "..."
    return "NONSTANDARD", " ".join(disassemble(script))


# --------------------------------------------------------------------------
# Transactions
# --------------------------------------------------------------------------

def serialize_tx(tx: dict, for_txid: bool = False) -> bytes:
    """Canonical serialization. for_txid strips segwit witness data."""
    out = tx["version"].to_bytes(4, "little")
    wit = tx.get("witness") and not for_txid
    if wit:
        out += b"\x00\x01"  # marker, flag
    out += encode_varint(len(tx["ins"]))
    for vin in tx["ins"]:
        out += vin["prev_txid"][::-1]  # display order -> wire order
        out += vin["vout"].to_bytes(4, "little")
        out += encode_varint(len(vin["scriptsig"])) + vin["scriptsig"]
        out += vin["sequence"].to_bytes(4, "little")
    out += encode_varint(len(tx["outs"]))
    for vout in tx["outs"]:
        out += vout["value"].to_bytes(8, "little")
        out += encode_varint(len(vout["scriptpubkey"])) + vout["scriptpubkey"]
    if wit:
        for w in tx["witness"]:
            out += encode_varint(len(w))
            for item in w:
                out += encode_varint(len(item)) + item
    out += tx["locktime"].to_bytes(4, "little")
    return out


def _parse_tx_c(c: Cursor) -> dict:
    """Parse one transaction from a cursor (leaves position after locktime)."""
    tx = {"version": c.u32()}
    segwit = False
    if c.d[c.p:c.p + 2] == b"\x00\x01":
        segwit = True
        c.read(2)
    ins = []
    for _ in range(c.varint()):
        ins.append({
            "prev_txid": c.read(32)[::-1],  # wire -> display order
            "vout": c.u32(),
            "scriptsig": c.varbytes(),
            "sequence": c.u32(),
        })
    outs = []
    for _ in range(c.varint()):
        outs.append({
            "value": c.u64(),
            "scriptpubkey": c.varbytes(),
        })
    witness = None
    if segwit:
        witness = []
        for _ in range(len(ins)):
            witness.append([c.varbytes() for _ in range(c.varint())])
    locktime = c.u32()
    tx.update({"ins": ins, "outs": outs, "locktime": locktime,
               "witness": witness, "segwit": segwit})
    return tx


def parse_tx(raw: bytes) -> dict:
    """Parse raw transaction bytes (legacy or segwit)."""
    c = Cursor(raw)
    tx = _parse_tx_c(c)
    if c.left():
        raise ValueError("trailing bytes after locktime")
    tx["raw"] = raw
    return tx


def parse_block(raw: bytes) -> dict:
    """Parse a full serialized block: header + tx count + transactions."""
    c = Cursor(raw)
    header_raw = c.read(80)
    hdr = parse_header(header_raw)
    hdr["raw"] = header_raw
    ntx = c.varint()
    txs = [_parse_tx_c(c) for _ in range(ntx)]
    if c.left():
        raise ValueError("trailing bytes after last transaction")
    return {"header": hdr, "txs": txs}


def verify_block_merkle(block: dict) -> bool:
    """Recompute the merkle root from the block's txids; compare to header."""
    leaves = [bytes.fromhex(txid(t))[::-1] for t in block["txs"]]
    return merkle_root(leaves)[::-1].hex() == block["header"]["merkle"]


def txid(tx: dict) -> str:
    """Transaction id: display-order hex of sha256d over txid-serialization."""
    return sha256d(serialize_tx(tx, for_txid=True))[::-1].hex()


def wtxid(tx: dict) -> str:
    """Witness tx id (includes witness data)."""
    return sha256d(serialize_tx(tx))[::-1].hex()


# --------------------------------------------------------------------------
# Blocks
# --------------------------------------------------------------------------

def parse_header(raw80: bytes) -> dict:
    c = Cursor(raw80)
    return {
        "version": c.u32(),
        "prev": c.read(32)[::-1].hex(),
        "merkle": c.read(32)[::-1].hex(),
        "time": c.u32(),
        "bits": c.read(4).hex(),
        "nonce": c.u32(),
        "hash": sha256d(raw80)[::-1].hex(),
    }


def merkle_root(leaf_hashes_le: list) -> bytes:
    """Compute merkle root from txid byte strings (little-endian wire order).

    Bitcoin duplicates the last hash when a level has an odd count.
    """
    lvl = list(leaf_hashes_le)
    if not lvl:
        return b"\x00" * 32
    while len(lvl) > 1:
        if len(lvl) % 2:
            lvl.append(lvl[-1])
        lvl = [sha256d(lvl[i] + lvl[i + 1]) for i in range(0, len(lvl), 2)]
    return lvl[0]


# --------------------------------------------------------------------------
# Signature hash (sighash) — legacy (pre-segwit) and BIP-143 (segwit v0)
# --------------------------------------------------------------------------

def _ser_out(vout: dict) -> bytes:
    return (vout["value"].to_bytes(8, "little") + encode_varint(len(vout["scriptpubkey"]))
            + vout["scriptpubkey"])


def sighash_legacy(tx: dict, in_idx: int, prev_scriptpubkey: bytes,
                   sighash_type: int = 1) -> bytes:
    """Legacy SIGHASH_ALL preimage hash for input in_idx.

    Every input commits to the *prevout's* scriptPubKey for the input being
    signed and an empty script for all others; the sighash byte is appended
    as a 4-byte LE integer.
    """
    if sighash_type != 1:
        raise ValueError("only SIGHASH_ALL implemented")
    out = tx["version"].to_bytes(4, "little")
    out += encode_varint(len(tx["ins"]))
    for i, vin in enumerate(tx["ins"]):
        out += vin["prev_txid"][::-1]
        out += vin["vout"].to_bytes(4, "little")
        script = prev_scriptpubkey if i == in_idx else b""
        out += encode_varint(len(script)) + script
        out += vin["sequence"].to_bytes(4, "little")
    out += encode_varint(len(tx["outs"]))
    for vout in tx["outs"]:
        out += _ser_out(vout)
    out += tx["locktime"].to_bytes(4, "little")
    out += sighash_type.to_bytes(4, "little")
    return sha256d(out)


def sighash_segwit_v0(tx: dict, in_idx: int, script_code: bytes,
                      amount_sat: int, sighash_type: int = 1) -> bytes:
    """BIP-143 sighash for segwit v0 inputs (P2WPKH / P2WSH)."""
    if sighash_type != 1:
        raise ValueError("only SIGHASH_ALL implemented")
    out = tx["version"].to_bytes(4, "little")
    out += sha256d(b"".join(v["prev_txid"][::-1] + v["vout"].to_bytes(4, "little")
                            for v in tx["ins"]))
    out += sha256d(b"".join(v["sequence"].to_bytes(4, "little") for v in tx["ins"]))
    vin = tx["ins"][in_idx]
    out += vin["prev_txid"][::-1] + vin["vout"].to_bytes(4, "little")
    out += encode_varint(len(script_code)) + script_code
    out += amount_sat.to_bytes(8, "little")
    out += vin["sequence"].to_bytes(4, "little")
    out += sha256d(b"".join(_ser_out(v) for v in tx["outs"]))
    out += tx["locktime"].to_bytes(4, "little")
    out += sighash_type.to_bytes(4, "little")
    return sha256d(out)


def parse_der_sig(sig_with_hashtype: bytes):
    """Split a scriptSig/witness signature into (r, s, sighash_type)."""
    sighash_type = sig_with_hashtype[-1]
    der = sig_with_hashtype[:-1]
    if der[0] != 0x30:
        raise ValueError("not a DER sequence")
    if der[2] != 0x02:
        raise ValueError("bad DER integer marker (r)")
    rlen = der[3]
    r = int.from_bytes(der[4:4 + rlen], "big")
    s_off = 4 + rlen
    if der[s_off] != 0x02:
        raise ValueError("bad DER integer marker (s)")
    slen = der[s_off + 1]
    s = int.from_bytes(der[s_off + 2:s_off + 2 + slen], "big")
    return r, s, sighash_type


def verify_p2pkh_input(tx: dict, in_idx: int, prev_scriptpubkey: bytes) -> bool:
    """Full legacy P2PKH input validation: parse scriptSig, rebuild the
    SIGHASH_ALL preimage, and verify the ECDSA signature from scratch."""
    items = script_items(tx["ins"][in_idx]["scriptsig"])
    pushes = [d for t, d in items if t == "data"]
    if len(pushes) != 2:
        raise ValueError("not a standard P2PKH scriptSig")
    sig, pubkey = pushes
    r, s, stype = parse_der_sig(sig)
    msg = sighash_legacy(tx, in_idx, prev_scriptpubkey, stype)
    return ecdsa_verify(pubkey, msg, r, s)


def verify_p2wpkh_input(tx: dict, in_idx: int, amount_sat: int) -> bool:
    """Full BIP-143 P2WPKH input validation from scratch."""
    wit = tx["witness"][in_idx]
    if len(wit) != 2 or len(wit[1]) != 33:
        raise ValueError("not a standard P2WPKH witness")
    sig, pubkey = wit
    r, s, stype = parse_der_sig(sig)
    script_code = b"\x76\xa9\x14" + hash160(pubkey) + b"\x88\xac"
    msg = sighash_segwit_v0(tx, in_idx, script_code, amount_sat, stype)
    return ecdsa_verify(pubkey, msg, r, s)
