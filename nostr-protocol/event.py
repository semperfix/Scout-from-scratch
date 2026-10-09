"""NIP-01 events and NIP-19 bech32 identities, from scratch.

Event id = sha256(canonical JSON [0, pubkey, created_at, kind, tags, content]).
NIP-19: npub/nsec/note are plain bech32 (not bech32m) of the 32 raw bytes.
"""

import json
import time

from secp import sha256, xonly_pubkey
from schnorr import sign, verify


# --------------------------------------------------------------------------
# bech32 (BIP-173 reference algorithm, vendored from expedition #22)
# --------------------------------------------------------------------------

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values):
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3][i] \
                if ((b >> i) & 1) else 0
    return chk


def _hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("bad padding")
    return ret


def bech32_encode(hrp: str, data: bytes) -> str:
    vals = _convertbits(data, 8, 5)
    pm = _polymod(_hrp_expand(hrp) + vals + [0] * 6) ^ 1
    return hrp + "1" + "".join(_CHARSET[d] for d in vals) + \
        "".join(_CHARSET[(pm >> 5 * (5 - i)) & 31] for i in range(6))


def bech32_decode(s: str):
    if s.lower() != s and s.upper() != s:
        raise ValueError("mixed case")
    s = s.lower()
    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s):
        raise ValueError("bad bech32")
    hrp = s[:pos]
    vals = [_CHARSET.find(c) for c in s[pos + 1:]]
    if any(v < 0 for v in vals):
        raise ValueError("bad charset")
    if _polymod(_hrp_expand(hrp) + vals) != 1:
        raise ValueError("bad checksum")
    return hrp, bytes(_convertbits(vals[:-6], 5, 8, False))


# --------------------------------------------------------------------------
# NIP-19 identities
# --------------------------------------------------------------------------

def nsec_to_npub(nsec: str) -> str:
    hrp, raw = bech32_decode(nsec)
    if hrp != "nsec" or len(raw) != 32:
        raise ValueError("not an nsec")
    return bech32_encode("npub", xonly_pubkey(raw))


def npub_to_hex(npub: str) -> str:
    hrp, raw = bech32_decode(npub)
    if hrp != "npub" or len(raw) != 32:
        raise ValueError("not an npub")
    return raw.hex()


def hex_to_npub(hexpub: str) -> str:
    raw = bytes.fromhex(hexpub)
    if len(raw) != 32:
        raise ValueError("pubkey must be 32 bytes")
    return bech32_encode("npub", raw)


def hex_to_nsec(hexsec: str) -> str:
    raw = bytes.fromhex(hexsec)
    if len(raw) != 32:
        raise ValueError("secret must be 32 bytes")
    return bech32_encode("nsec", raw)


def note_to_hex(note: str) -> str:
    hrp, raw = bech32_decode(note)
    if hrp != "note" or len(raw) != 32:
        raise ValueError("not a note id")
    return raw.hex()


# --------------------------------------------------------------------------
# NIP-01 events
# --------------------------------------------------------------------------

def event_id(pubkey_hex: str, created_at: int, kind: int, tags: list, content: str) -> str:
    """The event id commits to every field via canonical JSON serialization."""
    canonical = json.dumps([0, pubkey_hex, created_at, kind, tags, content],
                           separators=(",", ":"), ensure_ascii=False)
    return sha256(canonical.encode("utf-8")).hex()


def sign_event(seckey_hex: str, kind: int, content: str, tags=None,
               created_at: int = None) -> dict:
    seckey = bytes.fromhex(seckey_hex)
    pubkey = xonly_pubkey(seckey).hex()
    created_at = int(time.time()) if created_at is None else created_at
    tags = tags or []
    eid = event_id(pubkey, created_at, kind, tags, content)
    sig = sign(seckey, bytes.fromhex(eid)).hex()
    return {"id": eid, "pubkey": pubkey, "created_at": created_at,
            "kind": kind, "tags": tags, "content": content, "sig": sig}


def verify_event(ev: dict) -> tuple:
    """Returns (ok: bool, reason: str). Checks id commitment AND signature."""
    try:
        for f in ("id", "pubkey", "created_at", "kind", "tags", "content", "sig"):
            if f not in ev:
                return False, f"missing field {f}"
        recomputed = event_id(ev["pubkey"], ev["created_at"], ev["kind"],
                              ev["tags"], ev["content"])
        if recomputed != ev["id"]:
            return False, "id does not match content (tampered or mis-serialized)"
        if not verify(bytes.fromhex(ev["pubkey"]), bytes.fromhex(ev["id"]),
                       bytes.fromhex(ev["sig"])):
            return False, "bad Schnorr signature"
        return True, "ok"
    except Exception as e:  # malformed hex etc.
        return False, f"malformed: {e}"


# Common kinds (NIP-01 + popular NIPs)
KINDS = {0: "metadata", 1: "text_note", 2: "recommend_relay", 3: "contacts",
         4: "encrypted_dm", 5: "deletion", 6: "repost", 7: "reaction",
         40: "channel_create", 41: "channel_metadata", 42: "channel_message",
         43: "channel_hide", 44: "channel_mute",
         10000: "mute_list", 10001: "pin_list", 10002: "relay_list",
         1984: "reporting", 9734: "zap_request", 9735: "zap_receipt",
         30023: "long_form", 30000: "parameterized_replaceable"}
